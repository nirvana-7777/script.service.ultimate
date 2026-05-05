# streaming_providers/providers/hrti/vod_manager.py
"""
HRTi VOD Manager - Handles all VOD catalogue operations.

This module contains all VOD-specific logic including:
- Catalogue structure navigation
- Series/season/episode hierarchy
- Special collections (Watch Later, Editor's Choice)
- VOD item parsing and conversion to VodCategory/VodItem

Field mapping notes (from real API responses):

  GetCatalogue item Type values:
    Type 2  → playable VOD  (VodData sub-object)
    Type 3  → series        (SeriesData sub-object)
    Type 5  → episode in a series listing (EpisodeData sub-object)
    absent  → navigable folder

  GetCatalogue vs GetVodDetails field names:
    Listing: Title, PosterLandscape, VodData.Duration (ms), VodData.ProductionYear,
             VodData.ContentRating, SeriesData.SeriesReferenceId, EpisodeData.*
    Details: Title, PosterLandscape, DurationInFrames (frames at ~25fps → /25 for sec),
             ProductionYear, ContentRating, SeriesReferenceId, SeasonNr, EpisodeNr,
             FileName (streaming URL), SVODVideostores, IsSVOD, Actors, Directors,
             Writers, Editors, Producers, ReferenceID (capital ID in details)
    GetSeries: Result.Items list; each item uses EpisodeData sub-object

  FileName URL parsing (e.g. https://cdn1oiv.akamaized.net/hrtvodorigin/REF.smil/manifest.mpd):
    path[0] = origin          (e.g. "hrtvodorigin")
    path[1] = ref.smil        (e.g. "1870699590_delin.smil")
    ContentReferenceId = path[1] without ".smil"
    ContentDrmId       = "{origin}_{ref}.smil"

  AuthorizeSession ContentType:
    SVODVideostores non-empty → "svod", pass VideostoreReferenceIds
    SVODVideostores empty     → "vod",  VideostoreReferenceIds = null

  Pagination: NumberOfItems (not TotalCount), no HasMore field.
  Token: _current_token.access_token (no get_access_token() method exists).
"""

import json
from typing import Dict, List, Optional, Union

from ...base.models.vod import VodCategory, VodItem
from ...base.utils.logger import logger
from .constants import HRTiDefaults

# GetCatalogue / GetSeries Type discriminator values
_TYPE_VOD = 2
_TYPE_SERIES = 3
_TYPE_EPISODE = 5  # episode within a series listing (GetSeries Result.Items)

# Frames-per-second assumed for DurationInFrames → seconds conversion
_ASSUMED_FPS = 25


class HRTiVodManager:
    """
    Manages HRTi VOD operations.

    Content ID encoding:
    - ""                               → root catalogue structure
    - "catalogue:{ref_id}"             → items in category (paginated)
    - "series:{series_ref_id}"         → seasons of a series
    - "season:{series_id}:{season_id}" → episodes of a season
    - "details:{ref_id}"               → single VOD item details
    - "special:watch_later"            → user's watch later list
    - "special:editors_choice"         → editor's picks
    """

    def __init__(self, provider):
        """
        Initialize VOD manager.

        Args:
            provider: HRTiProvider instance (for http_manager, authenticator, config)
        """
        self.provider = provider
        self._config = provider.hrti_config
        self._http_manager = provider.http_manager
        self._authenticator = provider.authenticator

    # --------------------------------------------------------------------------
    # Public API (called by provider.get_vod_category)
    # --------------------------------------------------------------------------

    def get_category(
        self,
        content_id: str = "",
        cursor: Optional[str] = None,
        page_size: int = 24,
    ) -> Union[List, Dict]:
        """
        Get VOD category children.

        Args:
            content_id: Opaque node identifier (see class docstring)
            cursor:     Pagination cursor (page number as string, 1-indexed)
            page_size:  Items per page

        Returns:
            Dict with ``entries``, ``next_cursor``, ``total`` for paginated endpoints;
            List of VodCategory/VodItem for non-paginated endpoints.
        """
        if not content_id:
            return self._fetch_catalogue_structure()

        if content_id.startswith("catalogue:"):
            ref_id = content_id[len("catalogue:"):]
            return self._fetch_catalogue_items(ref_id, cursor, page_size)

        if content_id.startswith("series:"):
            series_id = content_id[len("series:"):]
            return self._fetch_series_seasons(series_id)

        if content_id.startswith("season:"):
            # Format: season:{series_id}:{season_id}
            parts = content_id[len("season:"):].split(":", 1)
            if len(parts) == 2:
                series_id, season_id = parts
                return self._fetch_season_episodes(series_id, season_id)
            logger.warning(f"Malformed season content_id: {content_id}")
            return []

        if content_id.startswith("details:"):
            ref_id = content_id[len("details:"):]
            item = self._fetch_vod_details(ref_id)
            return [item] if item else []

        if content_id == "special:watch_later":
            return self._fetch_watch_later()

        if content_id == "special:editors_choice":
            return self._fetch_editors_choice()

        logger.warning(f"Unknown VOD content_id format: {content_id}")
        return []

    # --------------------------------------------------------------------------
    # HTTP helpers
    # --------------------------------------------------------------------------

    def _get_headers(self, referer_path: str = "/videostore") -> Dict[str, str]:
        """Build authenticated headers for VOD API calls."""
        headers = {
            "deviceid": self._authenticator.get_device_id(),
            "devicetypeid": self._config.device_reference_id,
            "ipaddress": self._authenticator.get_ip_address(),
            "operatorreferenceid": self._config.operator_reference_id,
            "origin": self._config.base_website,
            "referer": f"{self._config.base_website}{referer_path}",
            "User-Agent": self._config.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        token = (
            self._authenticator._current_token.access_token
            if self._authenticator._current_token
            else ""
        )
        if token:
            headers["authorization"] = f"Client {token}"

        return headers

    def _post(
        self,
        endpoint_key: str,
        payload: Dict,
        referer_path: str = "/videostore",
    ) -> Optional[Union[Dict, List]]:
        """
        Make an authenticated POST to a named HRTi endpoint.

        Returns:
            The ``Result`` field from the response JSON, or None on any error.
            Result may be a dict (GetCatalogue) or a list (GetCatalogueStructure,
            GetSeasons, GetEpisodes).
        """
        url = self._config.api_endpoints.get(endpoint_key)
        if not url:
            logger.error(f"Unknown endpoint key: {endpoint_key}")
            return None

        try:
            response = self._http_manager.post(
                url,
                operation="api",
                headers=self._get_headers(referer_path),
                data=json.dumps(payload),
            )
            response.raise_for_status()

            data = response.json()

            if data.get("ErrorCode", 0) != 0:
                logger.warning(
                    f"HRTi API error for {endpoint_key}: "
                    f"[{data.get('ErrorCode')}] {data.get('ErrorDescription')}"
                )
                return None

            result = data.get("Result")
            if result is None:
                logger.debug(f"No Result in response for {endpoint_key}")

            return result

        except Exception as e:
            logger.error(f"Error calling {endpoint_key}: {e}")
            return None

    # --------------------------------------------------------------------------
    # Root catalogue structure  (GetCatalogueStructure)
    # --------------------------------------------------------------------------

    def _fetch_catalogue_structure(self) -> List[VodCategory]:
        """
        Fetch top-level categories from GetCatalogueStructure.

        The Result is a list of folder nodes.  The field names here ARE
        ``Name`` and ``ReferenceId`` (confirmed from the root-level curl output).
        """
        result = self._post("catalogue_structure", {}, "/videostore")

        if not result or not isinstance(result, list):
            logger.warning("No catalogue structure returned from HRTi")
            return []

        categories = []
        for node in result:
            category = self._parse_catalogue_node(node)
            if category:
                categories.append(category)

        logger.info(f"Retrieved {len(categories)} root VOD categories from HRTi")
        return categories

    def _parse_catalogue_node(self, node: Dict) -> Optional[VodCategory]:
        """
        Parse a GetCatalogueStructure node.

        These nodes use ``Name`` / ``ReferenceId`` / ``ChildCount`` / ``Icon``
        (distinct from catalogue item nodes which use ``Title`` etc.).
        """
        try:
            ref_id = node.get("ReferenceId")
            name = (node.get("Name") or "").strip()

            if not ref_id or not name:
                logger.debug("Skipping catalogue node — missing ReferenceId or Name")
                return None

            return VodCategory(
                name=name,
                content_id=f"catalogue:{ref_id}",
                provider=self.provider.provider_name,
                logo_url=node.get("Icon"),
                description=node.get("Description"),
                child_count=node.get("ChildCount"),
            )

        except Exception as e:
            logger.error(f"Error parsing catalogue node: {e}")
            return None

    # --------------------------------------------------------------------------
    # Catalogue items  (GetCatalogue)
    # --------------------------------------------------------------------------

    def _fetch_catalogue_items(
        self,
        ref_id: str,
        cursor: Optional[str] = None,
        page_size: int = 24,
    ) -> Dict:
        """
        Fetch paginated items from GetCatalogue.

        The Result is a dict:
          {
            "Name": "...",
            "NumberOfItems": 22,
            "Items": [ ... ]
          }

        There is no ``HasMore`` or ``TotalCount`` field — pagination is derived
        from ``NumberOfItems``.
        """
        page = 1
        if cursor:
            try:
                page = max(1, int(cursor))
            except ValueError:
                logger.warning(f"Invalid cursor '{cursor}', using page 1")

        if page > HRTiDefaults.MAX_VOD_PAGES:
            logger.warning(f"Page {page} exceeds max {HRTiDefaults.MAX_VOD_PAGES}")
            return {"entries": [], "next_cursor": None, "total": None}

        payload = {
            "ReferenceId": ref_id,
            "ItemsPerPage": page_size,
            "PageNumber": page,
        }

        result = self._post("catalogue", payload, "/videostore")

        if not result or not isinstance(result, dict):
            return {"entries": [], "next_cursor": None, "total": None}

        raw_items = result.get("Items") or []
        total_count = result.get("NumberOfItems")  # actual field name

        entries = []
        for item in raw_items:
            parsed = self._parse_catalogue_item(item)
            if parsed:
                entries.append(parsed)

        # has_more: total known and we haven't exhausted it yet
        has_more = (
            total_count is not None
            and page * page_size < total_count
            and page < HRTiDefaults.MAX_VOD_PAGES
        )
        next_cursor = str(page + 1) if has_more else None

        logger.debug(
            f"catalogue {ref_id} page {page}: "
            f"{len(entries)} entries, total {total_count}, next_cursor {next_cursor}"
        )

        return {"entries": entries, "next_cursor": next_cursor, "total": total_count}

    def _parse_catalogue_item(self, item: Dict) -> Optional[Union[VodCategory, VodItem]]:
        """
        Parse one item from a GetCatalogue ``Items`` list.

        Discrimination is done via the ``Type`` field:
          Type 2  → playable VOD  (VodData present)
          Type 3  → series        (SeriesData present)
          other   → treat as navigable sub-category

        Field names in catalogue items:
          Title           ← display name
          ReferenceId     ← stable id
          PosterLandscape / PosterPortrait  ← artwork
          VodData.Duration        ← ms
          VodData.ProductionYear  ← int
          VodData.ContentRating   ← string
          SeriesData.SeriesReferenceId
        """
        try:
            item_type = item.get("Type")

            if item_type == _TYPE_SERIES:
                return self._parse_series_item(item)

            if item_type == _TYPE_VOD:
                return self._parse_vod_catalogue_item(item)

            # Anything without a known Type is a navigable folder
            return self._parse_folder_item(item)

        except Exception as e:
            logger.error(f"Error parsing catalogue item: {e}")
            return None

    def _parse_folder_item(self, item: Dict) -> Optional[VodCategory]:
        """Parse a navigable folder node found inside a GetCatalogue result."""
        ref_id = item.get("ReferenceId")
        name = (item.get("Title") or item.get("Name") or "").strip()

        if not ref_id or not name:
            logger.debug("Skipping folder item — missing ReferenceId or title")
            return None

        return VodCategory(
            name=name,
            content_id=f"catalogue:{ref_id}",
            provider=self.provider.provider_name,
            logo_url=item.get("PosterLandscape") or item.get("PosterPortrait"),
            description=item.get("Description"),
            child_count=item.get("ChildCount"),  # usually absent; that's fine
        )

    def _parse_series_item(self, item: Dict) -> Optional[VodCategory]:
        """Parse a Type-3 series item into a drillable VodCategory."""
        series_data = item.get("SeriesData") or {}
        series_ref_id = series_data.get("SeriesReferenceId") or item.get("ReferenceId")
        name = (item.get("Title") or "").strip()

        if not series_ref_id or not name:
            logger.debug("Skipping series item — missing SeriesReferenceId or Title")
            return None

        season_count = (
            series_data.get("LastSeasonNumber")  # best proxy available
        )

        return VodCategory(
            name=name,
            content_id=f"series:{series_ref_id}",
            provider=self.provider.provider_name,
            logo_url=item.get("PosterLandscape") or item.get("PosterPortrait"),
            description=item.get("Description"),
            child_count=season_count,
        )

    def _parse_vod_catalogue_item(self, item: Dict) -> Optional[VodItem]:
        """
        Parse a Type-2 (playable) item from a GetCatalogue listing.

        Metadata here is sparse — no StreamingURL, no genres list, etc.
        The ``content_id`` is the raw ReferenceId so callers can pass it to
        ``get_manifest()`` / ``get_drm()`` directly.
        """
        ref_id = item.get("ReferenceId")
        title = (item.get("Title") or "").strip()

        if not ref_id or not title:
            logger.debug("Skipping VOD catalogue item — missing ReferenceId or Title")
            return None

        vod_data = item.get("VodData") or {}

        # Duration in the catalogue listing is milliseconds
        duration_ms = vod_data.get("Duration")
        duration_sec = int(duration_ms / 1000) if duration_ms else None

        # Genre comes as a comma-separated category string in catalogue listings
        category_str = item.get("VodCategoryNames") or ""
        genres = [g.strip() for g in category_str.split(",") if g.strip()] or None

        return VodItem(
            name=title,
            content_id=ref_id,
            provider=self.provider.provider_name,
            logo_url=item.get("PosterLandscape") or item.get("PosterPortrait"),
            description=item.get("Description"),
            long_description=None,
            original_title=None,
            duration_seconds=duration_sec,
            release_year=vod_data.get("ProductionYear"),
            rating=vod_data.get("ContentRating"),
            genre=genres[0] if genres else None,
            genres=genres,
            cast=None,
            director=None,
            season_number=None,
            episode_number=None,
            series_id=None,
            series_title=None,
            trailer_url=None,
            is_highlight=False,
            content_type="MOVIE",
            manifest_script=None,  # not provided in listings — fetched on demand
        )

    # --------------------------------------------------------------------------
    # Series, Seasons, Episodes
    # --------------------------------------------------------------------------

    def _fetch_series_seasons(self, series_ref_id: str) -> List[VodCategory]:
        """
        Get seasons for a series from GetSeasons.

        Result is a list of season objects.
        """
        payload = {"SeriesReferenceId": series_ref_id}
        result = self._post("seasons", payload, "/videostore")

        if not result or not isinstance(result, list):
            logger.warning(f"No seasons returned for series {series_ref_id}")
            return []

        seasons = []
        for season in result:
            season_ref_id = season.get("ReferenceId")
            season_name = (season.get("Name") or "").strip()
            if not season_name:
                season_num = season.get("SeasonNumber")
                season_name = f"Season {season_num}" if season_num else "Unknown Season"

            seasons.append(VodCategory(
                name=season_name,
                content_id=f"season:{series_ref_id}:{season_ref_id}",
                provider=self.provider.provider_name,
                logo_url=season.get("PosterLandscape") or season.get("Icon"),
                description=season.get("Description"),
                child_count=season.get("EpisodeCount"),
            ))

        logger.info(f"Retrieved {len(seasons)} seasons for series {series_ref_id}")
        return seasons

    def _fetch_season_episodes(
        self,
        series_ref_id: str,
        season_ref_id: str,
    ) -> List[VodItem]:
        """
        Get episodes for a season from GetSeries.

        The endpoint is GetSeries (not GetEpisodes — that endpoint does not exist).
        Result is a dict: { "Items": [...], "LastWatchedEpisodeReferenceId": ..., ... }
        Each item uses EpisodeData sub-object (not VodData) and Type 5.
        """
        payload = {
            "SeriesReferenceId": series_ref_id,
            "SeasonReferenceId": season_ref_id,
        }
        result = self._post("episodes", payload, "/videostore")

        # Result is a dict with an Items list (not a bare list)
        if not result or not isinstance(result, dict):
            logger.warning(f"No episodes returned for season {season_ref_id}")
            return []

        raw_items = result.get("Items") or []
        episodes = []
        for ep in raw_items:
            vod_item = self._parse_series_episode_item(ep, series_ref_id)
            if vod_item:
                episodes.append(vod_item)

        logger.info(
            f"Retrieved {len(episodes)} episodes for season {season_ref_id} "
            f"of series {series_ref_id}"
        )
        return episodes

    def _parse_series_episode_item(self, item: Dict, series_ref_id: str) -> Optional[VodItem]:
        """
        Parse a Type-5 episode from a GetSeries Result.Items list.

        Schema differs from both catalogue items and vod_details:
          ReferenceId, Title, PosterLandscape, PosterPortrait, VodCategoryNames
          EpisodeData.EpisodeNr, EpisodeData.SeasonNr, EpisodeData.Duration (ms),
          EpisodeData.ContentRating
          SeriesData.SeriesReferenceId, SeriesData.SeriesName
        """
        ref_id = item.get("ReferenceId")
        title = (item.get("Title") or "").strip()
        if not ref_id or not title:
            return None

        ep_data = item.get("EpisodeData") or {}
        series_data = item.get("SeriesData") or {}

        duration_ms = ep_data.get("Duration")
        duration_sec = int(duration_ms / 1000) if duration_ms else None

        category_str = item.get("VodCategoryNames") or ""
        genres = [g.strip() for g in category_str.split(",") if g.strip()] or None

        return VodItem(
            name=title,
            content_id=ref_id,
            provider=self.provider.provider_name,
            logo_url=item.get("PosterLandscape") or item.get("PosterPortrait"),
            description=None,
            long_description=None,
            original_title=None,
            duration_seconds=duration_sec,
            release_year=None,
            rating=ep_data.get("ContentRating"),
            genre=genres[0] if genres else None,
            genres=genres,
            cast=None,
            director=None,
            season_number=ep_data.get("SeasonNr"),
            episode_number=ep_data.get("EpisodeNr"),
            series_id=series_data.get("SeriesReferenceId") or series_ref_id,
            series_title=series_data.get("SeriesName"),
            trailer_url=None,
            is_highlight=False,
            content_type="SERIES",
            manifest_script=None,  # only available via GetVodDetails
        )

    # --------------------------------------------------------------------------
    # VOD item details  (GetVodDetails)
    # --------------------------------------------------------------------------

    def _fetch_vod_details(self, ref_id: str) -> Optional[VodItem]:
        """
        Fetch full metadata for a single VOD item from GetVodDetails.

        This is also the only place StreamingURL is available.
        """
        result = self._post("vod_details", {"ReferenceId": ref_id}, "/videostore")

        if not result:
            logger.warning(f"No details returned for VOD item {ref_id}")
            return None

        return self._parse_vod_details_item(result)

    def _parse_vod_details_item(self, item: Dict) -> Optional[VodItem]:
        """
        Parse a rich VOD item as returned by GetVodDetails.

        Real field names (verified from API):
          ReferenceID (capital ID!), Title, OriginalTitle, Description,
          FileName (streaming URL — NOT StreamingURL),
          DurationInFrames (frames, divide by _ASSUMED_FPS for seconds),
          ProductionYear, ContentRating, SeriesReferenceId, SeriesName,
          SeasonNr, EpisodeNr, TrailerUrl, Type ("vod" / "episode"),
          PosterLandscape, PosterPortrait,
          Actors / Directors / Writers / Editors / Producers (strings or null),
          SVODVideostores (list of store ids, governs auth type),
          IsSVOD (bool — but SVODVideostores non-empty is the reliable signal).
        """
        try:
            # Details uses "ReferenceID" (capital ID), listings use "ReferenceId"
            ref_id = item.get("ReferenceID") or item.get("ReferenceId")
            title = (item.get("Title") or "").strip()

            if not ref_id or not title:
                logger.debug("Skipping VOD details item — missing ReferenceId or Title")
                return None

            # DurationInFrames at ~25fps → seconds
            frames = item.get("DurationInFrames")
            duration_sec = int(frames / _ASSUMED_FPS) if frames else None

            # Actors field is a string (comma-separated or null), not a list
            actors_str = item.get("Actors")
            cast = (
                [a.strip() for a in actors_str.split(",") if a.strip()]
                if actors_str else None
            )

            # Directors, Writers also strings
            directors_str = item.get("Directors") or ""
            genre_from_category = item.get("AssetCategory") or ""

            # Type field: "vod" or "episode"
            item_type_str = (item.get("Type") or "").lower()
            content_type = "SERIES" if item_type_str == "episode" else "MOVIE"

            # Streaming URL is in FileName, not StreamingURL
            filename = item.get("FileName") or ""

            # Store SVOD data on the item for use by get_vod_session_data
            svod_videostores = item.get("SVODVideostores") or []

            vod_item = VodItem(
                name=title,
                content_id=ref_id,
                provider=self.provider.provider_name,
                logo_url=item.get("PosterLandscape") or item.get("PosterPortrait"),
                description=item.get("Description"),
                long_description=None,
                original_title=item.get("OriginalTitle"),
                duration_seconds=duration_sec,
                release_year=item.get("ProductionYear"),
                rating=item.get("ContentRating"),
                genre=genre_from_category or None,
                genres=[genre_from_category] if genre_from_category else None,
                cast=cast,
                director=directors_str or None,
                season_number=item.get("SeasonNr"),
                episode_number=item.get("EpisodeNr"),
                series_id=item.get("SeriesReferenceId"),
                series_title=item.get("SeriesName"),
                trailer_url=item.get("TrailerUrl"),
                is_highlight=False,
                content_type=content_type,
                manifest_script=filename or None,
            )

            # Stash SVOD stores so get_vod_session_data can read them without
            # a second GetVodDetails call
            vod_item._svod_videostores = svod_videostores

            logger.debug(f"Parsed VOD details: {title} ({ref_id}), svod={bool(svod_videostores)}")
            return vod_item

        except Exception as e:
            logger.error(f"Error parsing VOD details item: {e}")
            return None

    # --------------------------------------------------------------------------
    # Special collections
    # --------------------------------------------------------------------------

    def _fetch_watch_later(self) -> List[VodItem]:
        """Get user's Watch Later list (requires user auth)."""
        result = self._post("watch_later", {}, "/watch_later")

        if not result or not isinstance(result, list):
            logger.debug("No watch later items returned (may require user auth)")
            return []

        items = [self._parse_vod_details_item(i) for i in result]
        items = [i for i in items if i]
        logger.info(f"Retrieved {len(items)} items from watch later")
        return items

    def _fetch_editors_choice(self) -> List[VodItem]:
        """Get Editor's Choice list."""
        result = self._post("editors_choice", {}, "/editors_choice")

        if not result or not isinstance(result, list):
            logger.debug("No editor's choice items returned")
            return []

        items = [self._parse_vod_details_item(i) for i in result]
        items = [i for i in items if i]
        logger.info(f"Retrieved {len(items)} items from editor's choice")
        return items

    # --------------------------------------------------------------------------
    # Provider-facing helpers
    # --------------------------------------------------------------------------

    def get_vod_streaming_url(self, content_id: str) -> Optional[str]:
        """
        Return the DASH manifest URL for a playable VOD item.

        The URL comes from the ``FileName`` field in GetVodDetails
        (stored as ``manifest_script`` on the VodItem).
        """
        details = self._fetch_vod_details(content_id)
        if details and details.manifest_script:
            return details.manifest_script

        logger.warning(f"No FileName/StreamingURL found for VOD item {content_id}")
        return None

    def get_vod_session_data(self, content_id: str) -> Optional[Dict]:
        """
        Authorize a VOD playback session and return the session dict.

        Derives all AuthorizeSession parameters from GetVodDetails:

          FileName = https://cdn1oiv.akamaized.net/hrtvodorigin/REF.smil/manifest.mpd
            → path[0] = "hrtvodorigin"   (origin)
            → path[1] = "REF.smil"       (ref with extension)
            → ContentReferenceId = "REF"              (stem without .smil)
            → ContentDrmId = "hrtvodorigin_REF.smil"  (origin_ref.smil)

          SVODVideostores non-empty → ContentType="svod", pass VideostoreReferenceIds
          SVODVideostores empty     → ContentType="vod",  VideostoreReferenceIds=null
        """
        try:
            details = self._fetch_vod_details(content_id)
            if not details or not details.manifest_script:
                logger.error(f"Cannot authorize VOD session — no FileName for {content_id}")
                return None

            filename = details.manifest_script  # e.g. https://.../hrtvodorigin/REF.smil/manifest.mpd
            svod_stores = getattr(details, "_svod_videostores", []) or []

            # Parse ContentReferenceId and ContentDrmId from FileName path
            from urllib.parse import urlparse
            path_parts = urlparse(filename).path.strip("/").split("/")
            # path_parts: ["hrtvodorigin", "REF.smil", "manifest.mpd"]
            if len(path_parts) < 2:
                logger.error(f"Cannot parse FileName path for {content_id}: {filename}")
                return None

            origin = path_parts[0]          # "hrtvodorigin"
            ref_with_ext = path_parts[1]    # "REF.smil"
            ref_id = ref_with_ext.removesuffix(".smil") if ref_with_ext.endswith(".smil") else ref_with_ext
            content_drm_id = f"{origin}_{ref_with_ext}"  # "hrtvodorigin_REF.smil"

            content_type = "svod" if svod_stores else "vod"
            video_store_ids = svod_stores if svod_stores else None

            logger.debug(
                f"Authorizing VOD session — content_id: {content_id}, "
                f"ref: {ref_id}, drm: {content_drm_id}, "
                f"type: {content_type}, stores: {video_store_ids}"
            )

            return self._authenticator.authorize_session(
                content_type=content_type,
                content_ref_id=ref_id,
                content_drm_id=content_drm_id,
                video_store_ids=video_store_ids,
                channel_id=None,
                start_time=None,
                end_time=None,
            )

        except Exception as e:
            logger.error(f"Error getting VOD session data for {content_id}: {e}")
            return None