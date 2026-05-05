# streaming_providers/providers/hrti/vod_manager.py
"""
HRTi VOD Manager - Handles all VOD catalogue operations.

Endpoints actually available (confirmed from API):
  GetCatalogueStructure  → full nested tree (Children arrays), root nav
  GetCatalogue           → paginated items for a catalogue node
  GetSeries              → episodes for a series season
  GetVodDetails          → full metadata + FileName for a single item
  GetEditorsChoice       → editor's picks
  GetWatchLater          → user watch later (requires user auth)

NOT available: GetSeasons, GetEpisodes — these do not exist on this API.

Navigation model
----------------
  GetCatalogueStructure returns the full tree with Children nesting.
  Every navigable node at every level uses ``catalogue:{ReferenceId}``.
  There is no separate seasons API — seasons appear as Children of a
  series node inside GetCatalogueStructure and are therefore already
  handled by the catalogue: routing.

  Type-3 series items in GetCatalogue listings link to GetSeries via:
    content_id = "series:{SeriesReferenceId}:{SeasonReferenceId}"
  The default SeasonReferenceId is "{SeriesReferenceId}_S01".

Content ID scheme
-----------------
  ""                                     root  (GetCatalogueStructure)
  "catalogue:{ref_id}"                   items (GetCatalogue, paginated)
  "series:{series_ref}:{season_ref}"     episodes (GetSeries)
  "special:watch_later"                  GetWatchLater
  "special:editors_choice"               GetEditorsChoice

Field mapping (verified from real API responses)
-------------------------------------------------
  GetCatalogueStructure nodes:
    Name, ReferenceId, Children (list), PosterLandscape, ParentReferenceId

  GetCatalogue items:
    Type 2 → playable VOD   (VodData.Duration ms, VodData.ProductionYear,
                              VodData.ContentRating)
    Type 3 → series         (SeriesData.SeriesReferenceId, SeriesData.SeriesName,
                              SeriesData.LastSeasonNumber)
    Type 5 → episode        (EpisodeData.EpisodeNr, EpisodeData.SeasonNr,
                              EpisodeData.Duration ms, EpisodeData.ContentRating)
    other  → navigable folder

  GetVodDetails:
    ReferenceID (capital), Title, FileName (streaming URL — NOT StreamingURL),
    DurationInFrames (frames / 25 ≈ seconds), ProductionYear, ContentRating,
    AssetCategory, Directors, Actors (plain strings, not lists),
    SeriesReferenceId, SeriesName, SeasonNr, EpisodeNr,
    SVODVideostores (list → "svod" auth when non-empty),
    PosterLandscape, PosterPortrait

  AuthorizeSession parameters derived from FileName:
    FileName = https://cdn1oiv.akamaized.net/hrtvodorigin/REF.smil/manifest.mpd
    ContentReferenceId = path[1] without ".smil"    e.g. "1870699590_delin"
    ContentDrmId       = "{path[0]}_{path[1]}"      e.g. "hrtvodorigin_1870699590_delin.smil"
    ContentType        = "svod" if SVODVideostores else "vod"
    VideostoreReferenceIds = SVODVideostores or null

  Token: _current_token.access_token (no get_access_token() method exists).
  Pagination: NumberOfItems field (not TotalCount); no HasMore field.
"""

import json
from typing import Dict, List, Optional, Union
from urllib.parse import urlparse

from ...base.models.vod import VodCategory, VodItem
from ...base.utils.logger import logger
from .constants import HRTiDefaults

# GetCatalogue / GetSeries Type discriminator values
_TYPE_VOD = 2
_TYPE_SERIES = 3
_TYPE_EPISODE = 5

# DurationInFrames in GetVodDetails is at ~25 fps
_ASSUMED_FPS = 25


class HRTiVodManager:
    """Manages HRTi VOD catalogue operations."""

    def __init__(self, provider):
        self.provider = provider
        self._config = provider.hrti_config
        self._http_manager = provider.http_manager
        self._authenticator = provider.authenticator

    # -------------------------------------------------------------------------
    # Public API (called by provider.get_vod_category)
    # -------------------------------------------------------------------------

    def get_category(
        self,
        content_id: str = "",
        cursor: Optional[str] = None,
        page_size: int = 24,
    ) -> Union[List, Dict]:
        """
        Return children for a VOD navigation node.

        Routing by content_id prefix:
          ""                    → GetCatalogueStructure (root, top-level categories)
          "catalogue:{ref_id}"  → GetCatalogue items (paginated)
          "series:{sid}:{ssid}" → GetSeries episodes
          "special:*"           → special collections
        """
        if not content_id:
            return self._fetch_catalogue_structure()

        if content_id.startswith("catalogue:"):
            ref_id = content_id[len("catalogue:"):]
            return self._fetch_catalogue_items(ref_id, cursor, page_size)

        if content_id.startswith("series:"):
            # Format: series:{series_ref_id}:{season_ref_id}
            parts = content_id[len("series:"):].split(":", 1)
            if len(parts) == 2:
                return self._fetch_series_episodes(parts[0], parts[1])
            logger.warning(f"Malformed series content_id (expected series:SID:SSID): {content_id}")
            return []

        if content_id == "special:watch_later":
            return self._fetch_watch_later()

        if content_id == "special:editors_choice":
            return self._fetch_editors_choice()

        logger.warning(f"Unknown VOD content_id format: {content_id}")
        return []

    # -------------------------------------------------------------------------
    # HTTP helpers
    # -------------------------------------------------------------------------

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
        POST to a named endpoint and return the Result field.

        Returns None on HTTP error, API error (ErrorCode != 0), or missing Result.
        Result type varies by endpoint:
          GetCatalogueStructure → list
          GetCatalogue          → dict with Items, NumberOfItems, Name
          GetSeries             → dict with Items, LastWatchedEpisodeReferenceId
          GetVodDetails         → dict (single item)
        """
        url = self._config.api_endpoints.get(endpoint_key)
        if not url:
            logger.error(f"Unknown endpoint key: {endpoint_key}")
            return None
        try:
            resp = self._http_manager.post(
                url,
                operation="api",
                headers=self._get_headers(referer_path),
                data=json.dumps(payload),
            )
            resp.raise_for_status()
            data = resp.json()
            if data.get("ErrorCode", 0) != 0:
                logger.warning(
                    f"HRTi API error for {endpoint_key}: "
                    f"[{data.get('ErrorCode')}] {data.get('ErrorDescription')}"
                )
                return None
            return data.get("Result")
        except Exception as e:
            logger.error(f"Error calling {endpoint_key}: {e}")
            return None

    # -------------------------------------------------------------------------
    # GetCatalogueStructure — root navigation tree
    # -------------------------------------------------------------------------

    def _fetch_catalogue_structure(self) -> List[VodCategory]:
        """
        Fetch top-level navigation categories from GetCatalogueStructure.

        The API returns a flat list of root nodes, each with a Children array
        containing the full subtree.  We parse only the top level here —
        children are lazy-loaded when the user navigates via their
        catalogue:{ReferenceId} content_id.

        child_count is set from len(Children) since the API provides no
        separate count field.  A non-zero child_count signals the UI that
        this node is drillable.
        """
        result = self._post("catalogue_structure", {}, "/videostore")

        if not result or not isinstance(result, list):
            logger.warning("No catalogue structure returned from HRTi")
            return []

        categories = []
        for node in result:
            cat = self._parse_structure_node(node)
            if cat:
                categories.append(cat)

        logger.info(f"Retrieved {len(categories)} root VOD categories from HRTi")
        return categories

    def _parse_structure_node(self, node: Dict) -> Optional[VodCategory]:
        """
        Parse one node from GetCatalogueStructure.

        Fields: Name, ReferenceId, Children (list), PosterLandscape,
                ParentReferenceId (ignored — content_id encodes the path).
        """
        try:
            ref_id = node.get("ReferenceId")
            name = (node.get("Name") or "").strip()
            if not ref_id or not name:
                logger.debug(f"Skipping structure node — missing id or name")
                return None

            children = node.get("Children") or []
            return VodCategory(
                name=name,
                content_id=f"catalogue:{ref_id}",
                provider=self.provider.provider_name,
                logo_url=node.get("PosterLandscape"),
                description=None,
                # child_count from Children length; None if empty (may still have
                # items via GetCatalogue even with no sub-categories)
                child_count=len(children) if children else None,
            )
        except Exception as e:
            logger.error(f"Error parsing structure node: {e}")
            return None

    # -------------------------------------------------------------------------
    # GetCatalogue — paginated items for a catalogue node
    # -------------------------------------------------------------------------

    def _fetch_catalogue_items(
        self,
        ref_id: str,
        cursor: Optional[str] = None,
        page_size: int = 24,
    ) -> Dict:
        """
        Fetch paginated items from GetCatalogue for a given ReferenceId.

        Response: { "Name": "...", "NumberOfItems": N, "Items": [...] }
        Pagination is derived from NumberOfItems — no HasMore field exists.
        """
        page = 1
        if cursor:
            try:
                page = max(1, int(cursor))
            except ValueError:
                logger.warning(f"Invalid cursor '{cursor}', using page 1")

        if page > HRTiDefaults.MAX_VOD_PAGES:
            return {"entries": [], "next_cursor": None, "total": None}

        result = self._post(
            "catalogue",
            {"ReferenceId": ref_id, "ItemsPerPage": page_size, "PageNumber": page},
        )

        if not result or not isinstance(result, dict):
            return {"entries": [], "next_cursor": None, "total": None}

        raw_items = result.get("Items") or []
        total_count = result.get("NumberOfItems")

        entries = []
        for item in raw_items:
            parsed = self._parse_catalogue_item(item)
            if parsed:
                entries.append(parsed)

        has_more = (
            total_count is not None
            and page * page_size < total_count
            and page < HRTiDefaults.MAX_VOD_PAGES
        )

        logger.debug(
            f"catalogue {ref_id} page {page}: {len(entries)} entries, "
            f"total {total_count}, next_cursor {page + 1 if has_more else None}"
        )
        return {
            "entries": entries,
            "next_cursor": str(page + 1) if has_more else None,
            "total": total_count,
        }

    def _parse_catalogue_item(self, item: Dict) -> Optional[Union[VodCategory, VodItem]]:
        """Dispatch catalogue item parsing by Type field."""
        try:
            item_type = item.get("Type")
            if item_type == _TYPE_VOD:
                return self._parse_vod_catalogue_item(item)
            if item_type == _TYPE_SERIES:
                return self._parse_series_catalogue_item(item)
            if item_type == _TYPE_EPISODE:
                return self._parse_episode_catalogue_item(item)
            return self._parse_folder_catalogue_item(item)
        except Exception as e:
            logger.error(f"Error parsing catalogue item: {e}")
            return None

    def _parse_folder_catalogue_item(self, item: Dict) -> Optional[VodCategory]:
        """No Type — navigable sub-folder node."""
        ref_id = item.get("ReferenceId")
        name = (item.get("Title") or item.get("Name") or "").strip()
        if not ref_id or not name:
            return None
        return VodCategory(
            name=name,
            content_id=f"catalogue:{ref_id}",
            provider=self.provider.provider_name,
            logo_url=item.get("PosterLandscape") or item.get("PosterPortrait"),
            description=None,
            child_count=item.get("ChildCount"),
        )

    def _parse_series_catalogue_item(self, item: Dict) -> Optional[VodCategory]:
        """
        Type-3 series item.

        Navigation goes to GetSeries which requires SeriesReferenceId and
        SeasonReferenceId.  We default to the _S01 suffix since there is no
        GetSeasons endpoint.  Multi-season series have their seasons listed as
        Children in GetCatalogueStructure, so they are browsed via catalogue:
        nodes and never reach this path.
        """
        series_data = item.get("SeriesData") or {}
        series_ref_id = series_data.get("SeriesReferenceId") or item.get("ReferenceId")
        name = (item.get("Title") or "").strip()
        if not series_ref_id or not name:
            return None

        default_season_ref = f"{series_ref_id}_S01"
        season_count = series_data.get("LastSeasonNumber")

        return VodCategory(
            name=name,
            content_id=f"series:{series_ref_id}:{default_season_ref}",
            provider=self.provider.provider_name,
            logo_url=item.get("PosterLandscape") or item.get("PosterPortrait"),
            description=None,
            child_count=season_count,
        )

    def _parse_vod_catalogue_item(self, item: Dict) -> Optional[VodItem]:
        """
        Type-2 playable item from a GetCatalogue listing.

        manifest_script is None — FileName only available via GetVodDetails.
        content_id is the raw ReferenceId (no prefix) so provider routing works.
        """
        ref_id = item.get("ReferenceId")
        title = (item.get("Title") or "").strip()
        if not ref_id or not title:
            return None

        vod_data = item.get("VodData") or {}
        duration_ms = vod_data.get("Duration")
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
            manifest_script=None,
        )

    def _parse_episode_catalogue_item(self, item: Dict) -> Optional[VodItem]:
        """
        Type-5 episode item from GetCatalogue or GetSeries.

        EpisodeData sub-object: EpisodeNr, SeasonNr, Duration (ms), ContentRating.
        SeriesData sub-object:  SeriesReferenceId, SeriesName.
        content_id is the raw ReferenceId.
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
            series_id=series_data.get("SeriesReferenceId"),
            series_title=series_data.get("SeriesName"),
            trailer_url=None,
            is_highlight=False,
            content_type="SERIES",
            manifest_script=None,
        )

    # -------------------------------------------------------------------------
    # GetSeries — episodes for a specific series season
    # -------------------------------------------------------------------------

    def _fetch_series_episodes(
        self,
        series_ref_id: str,
        season_ref_id: str,
    ) -> Dict:
        """
        Fetch all episodes from GetSeries for a given series + season.

        Payload: SeriesReferenceId, SeasonReferenceId, PageSize, PageNumber.
        Response: { "Items": [...], "LastWatchedEpisodeReferenceId": ..., ... }
        Each item uses Type 5 / EpisodeData schema.
        """
        result = self._post(
            "episodes",
            {
                "SeriesReferenceId": series_ref_id,
                "SeasonReferenceId": season_ref_id,
                "PageSize": 100,
                "PageNumber": 1,
            },
        )

        if not result or not isinstance(result, dict):
            logger.warning(
                f"No episodes returned for series {series_ref_id} "
                f"season {season_ref_id}"
            )
            return {"entries": [], "next_cursor": None, "total": None}

        raw_items = result.get("Items") or []
        episodes = []
        for ep in raw_items:
            parsed = self._parse_episode_catalogue_item(ep)
            if parsed:
                episodes.append(parsed)

        logger.info(
            f"Retrieved {len(episodes)} episodes for series {series_ref_id} "
            f"season {season_ref_id}"
        )
        return {"entries": episodes, "next_cursor": None, "total": len(episodes)}

    # -------------------------------------------------------------------------
    # GetVodDetails — full metadata for one item
    # -------------------------------------------------------------------------

    def _fetch_vod_details(self, ref_id: str) -> Optional[VodItem]:
        """Fetch full metadata for a single VOD item from GetVodDetails."""
        result = self._post("vod_details", {"ReferenceId": ref_id})
        if not result:
            logger.warning(f"No details returned for VOD item {ref_id}")
            return None
        return self._parse_vod_details_item(result)

    def _parse_vod_details_item(self, item: Dict) -> Optional[VodItem]:
        """
        Parse a rich VOD item from GetVodDetails.

        Key differences from catalogue listing schema:
          - ReferenceID (capital ID, not ReferenceId)
          - FileName (streaming URL, not StreamingURL)
          - DurationInFrames (divide by 25 for seconds)
          - Directors / Actors are plain strings, not lists
          - SVODVideostores list controls auth type
        """
        try:
            ref_id = item.get("ReferenceID") or item.get("ReferenceId")
            title = (item.get("Title") or "").strip()
            if not ref_id or not title:
                return None

            frames = item.get("DurationInFrames")
            duration_sec = int(frames / _ASSUMED_FPS) if frames else None

            actors_str = item.get("Actors")
            cast = (
                [a.strip() for a in actors_str.split(",") if a.strip()]
                if actors_str else None
            )

            item_type_str = (item.get("Type") or "").lower()
            content_type = "SERIES" if item_type_str == "episode" else "MOVIE"
            genre = item.get("AssetCategory") or None
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
                genre=genre,
                genres=[genre] if genre else None,
                cast=cast,
                director=item.get("Directors") or None,
                season_number=item.get("SeasonNr"),
                episode_number=item.get("EpisodeNr"),
                series_id=item.get("SeriesReferenceId"),
                series_title=item.get("SeriesName"),
                trailer_url=item.get("TrailerUrl"),
                is_highlight=False,
                content_type=content_type,
                manifest_script=item.get("FileName") or None,
            )
            vod_item._svod_videostores = svod_videostores
            logger.debug(f"Parsed VOD details: {title} ({ref_id}), svod={bool(svod_videostores)}")
            return vod_item

        except Exception as e:
            logger.error(f"Error parsing VOD details item: {e}")
            return None

    # -------------------------------------------------------------------------
    # Special collections
    # -------------------------------------------------------------------------

    def _fetch_watch_later(self) -> List[VodItem]:
        """User's Watch Later list (requires user auth)."""
        result = self._post("watch_later", {}, "/watch_later")
        if not result or not isinstance(result, list):
            return []
        items = [self._parse_vod_details_item(i) for i in result]
        return [i for i in items if i]

    def _fetch_editors_choice(self) -> List[VodItem]:
        """Editor's Choice list."""
        result = self._post("editors_choice", {}, "/editors_choice")
        if not result or not isinstance(result, list):
            return []
        items = [self._parse_vod_details_item(i) for i in result]
        return [i for i in items if i]

    # -------------------------------------------------------------------------
    # Provider-facing helpers (called by provider.py)
    # -------------------------------------------------------------------------

    def get_vod_streaming_url(self, content_id: str) -> Optional[str]:
        """
        Return the DASH manifest URL for a playable VOD item.

        Always calls GetVodDetails — FileName is only available there,
        never in catalogue listings.
        """
        details = self._fetch_vod_details(content_id)
        if details and details.manifest_script:
            return details.manifest_script
        logger.warning(f"No FileName found for VOD item {content_id}")
        return None

    def get_vod_session_data(self, content_id: str) -> Optional[Dict]:
        """
        Authorize a VOD playback session and return the session dict.

        Derives all AuthorizeSession parameters from the FileName in GetVodDetails:

          FileName = https://cdn1oiv.akamaized.net/hrtvodorigin/REF.smil/manifest.mpd
            path[0] = "hrtvodorigin"   (origin)
            path[1] = "REF.smil"

          ContentReferenceId = "REF"                        (stem without .smil)
          ContentDrmId       = "hrtvodorigin_REF.smil"
          ContentType        = "svod" if SVODVideostores non-empty else "vod"
          VideostoreReferenceIds = SVODVideostores or null
        """
        try:
            details = self._fetch_vod_details(content_id)
            if not details or not details.manifest_script:
                logger.error(f"Cannot authorize VOD session — no FileName for {content_id}")
                return None

            filename = details.manifest_script
            svod_stores = getattr(details, "_svod_videostores", []) or []

            path_parts = urlparse(filename).path.strip("/").split("/")
            if len(path_parts) < 2:
                logger.error(f"Cannot parse FileName path for {content_id}: {filename}")
                return None

            origin = path_parts[0]
            ref_with_ext = path_parts[1]
            ref_id = (
                ref_with_ext.removesuffix(".smil")
                if ref_with_ext.endswith(".smil")
                else ref_with_ext
            )
            content_drm_id = f"{origin}_{ref_with_ext}"
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