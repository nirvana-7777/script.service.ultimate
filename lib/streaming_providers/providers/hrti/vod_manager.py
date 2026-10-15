# streaming_providers/providers/hrti/vod_manager.py
"""
HRTi VOD manager -- catalogue navigation and VOD playback.

Endpoints (confirmed from the API): GetCatalogueStructure (root tree),
GetCatalogue (paged items), GetSeries (episodes of a season), GetVodDetails
(metadata + FileName), GetEditorsChoice, GetWatchLater (user auth).
There is NO GetSeasons / GetEpisodes.

content_id grammar (see ids.py):
  ""                          root          -> GetCatalogueStructure
  "catalogue_<ref>"           folder items  -> GetCatalogue (paged)
  "series_<sid>--<ssid>"      episodes      -> GetSeries
  "special_watch_later" / "special_editors_choice"
  "details_<ref>" | "<ref>"   one playable item (VodManager.handles_content_id)

Return conventions
------------------
Navigation always returns a VodPage. next_cursor (the next page number) is set
ONLY for GetCatalogue, which honours PageNumber/ItemsPerPage; every other
endpoint returns the full list (next_cursor None). Failures raise typed
errors; GetWatchLater / GetEditorsChoice are optional lists: an API error
there yields an empty page.

Manifest and DRM share one GetVodDetails through the provider-owned playout
cache (5 s TTL); the AuthorizeSession of the DRM call is cached the same way.
"""

import time
from typing import Any, Dict, List, Optional, Tuple, Union

from ...base.errors import BadRequestError, EntitlementError, NotFoundError
from ...base.managers import VodManager
from ...base.models import DRMConfig
from ...base.models.vod import VodCategory, VodItem
from ...base.utils.logger import logger
from ...base.vod import VodPage
from . import ids
from .api import api_post
from .constants import HRTiDefaults
from .drm import build_widevine, derive_vod_session_params
from .models import VodDetails

# GetCatalogue / GetSeries "Type" discriminator values
_TYPE_VOD = 2
_TYPE_SERIES = 3
_TYPE_EPISODE = 5

# DurationInFrames in GetVodDetails is ~25 fps
_ASSUMED_FPS = 25

_VOD_REFERER = "/videostore"
_PROVIDER = HRTiDefaults.PROVIDER_NAME
_PARSE_ERRORS = (KeyError, TypeError, AttributeError, ValueError)


class HRTiVodManager(VodManager):
    def __init__(
        self,
        *,
        http_manager: Any,
        auth: Any,
        country: str,
        config: Any,
        playout_cache: Optional[Dict[str, Tuple[Any, float]]] = None,
    ):
        super().__init__(
            http_manager=http_manager, auth=auth, country=country, config=config
        )
        # Provider-owned dict, borrowed by reference. Keys: "vod:<ref>" ->
        # (VodDetails, ts) and "vodsess:<ref>" -> (session dict, ts).
        self._playout_cache = playout_cache if playout_cache is not None else {}

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------
    def handles_content_id(self, content_id: str) -> bool:
        return ids.is_vod(content_id)

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------
    def get_vod_category(
        self,
        content_id: str = "",
        cursor: Optional[str] = None,
        page_size: int = HRTiDefaults.VOD_ITEMS_PER_PAGE,
        **kw: Any,
    ) -> VodPage:
        if not content_id:
            return self._fetch_catalogue_structure()
        if content_id.startswith("catalogue_"):
            return self._fetch_catalogue_items(content_id[len("catalogue_"):], cursor, page_size)
        if content_id.startswith("series_"):
            parts = content_id[len("series_"):].split("--", 1)
            if len(parts) != 2 or not all(parts):
                raise BadRequestError(
                    f"HRTi: malformed series id (expected series_SID--SSID): {content_id}"
                )
            return self._fetch_series_episodes(parts[0], parts[1])
        if content_id == "special_watch_later":
            return self._fetch_special("watch_later", "/watch_later")
        if content_id == "special_editors_choice":
            return self._fetch_special("editors_choice", "/editors_choice")
        raise BadRequestError(f"HRTi: unknown VOD content_id format: {content_id}")

    def _post(self, endpoint_key: str, payload: Dict, referer_path: str = _VOD_REFERER,
              required: bool = True) -> Optional[Union[Dict, List]]:
        return api_post(
            http_manager=self.http_manager,
            session=self.auth,
            config=self.config,
            endpoint_key=endpoint_key,
            payload=payload,
            referer_path=referer_path,
            required=required,
        )

    # --- GetCatalogueStructure: root tree -------------------------------
    def _fetch_catalogue_structure(self) -> VodPage:
        result = self._post("catalogue_structure", {})
        if not isinstance(result, list):
            logger.warning("HRTi: no catalogue structure returned")
            return VodPage()
        categories = [c for c in (self._parse_structure_node(n) for n in result) if c]
        logger.info(f"HRTi: {len(categories)} root VOD categories")
        return VodPage(entries=categories)

    def _parse_structure_node(self, node: Dict) -> Optional[VodCategory]:
        try:
            ref_id = node.get("ReferenceId")
            name = (node.get("Name") or "").strip()
            if not ref_id or not name:
                return None
            children = node.get("Children") or []
            return VodCategory(
                name=name,
                content_id=f"catalogue_{ref_id}",
                provider=_PROVIDER,
                logo_url=node.get("PosterLandscape"),
                description=None,
                child_count=len(children) if children else None,
            )
        except _PARSE_ERRORS as exc:
            logger.warning(f"HRTi: skipping malformed structure node: {exc!r}")
            return None

    # --- GetCatalogue: paged items ---------------------------------------
    def _fetch_catalogue_items(self, ref_id: str, cursor: Optional[str], page_size: int) -> VodPage:
        page = 1
        if cursor:
            try:
                page = max(1, int(cursor))
            except ValueError:
                logger.warning(f"HRTi: invalid cursor '{cursor}', using page 1")
        if page > HRTiDefaults.MAX_VOD_PAGES:
            return VodPage()

        result = self._post(
            "catalogue", {"ReferenceId": ref_id, "ItemsPerPage": page_size, "PageNumber": page}
        )
        if not isinstance(result, dict):
            return VodPage()

        entries = [e for e in (self._parse_catalogue_item(i) for i in result.get("Items") or []) if e]
        total = result.get("NumberOfItems")
        has_more = (
            total is not None
            and page * page_size < total
            and page < HRTiDefaults.MAX_VOD_PAGES
        )
        return VodPage(
            entries=entries,
            next_cursor=str(page + 1) if has_more else None,
            total=total,
        )

    def _parse_catalogue_item(self, item: Dict) -> Optional[Union[VodCategory, VodItem]]:
        try:
            item_type = item.get("Type")
            if item_type == _TYPE_VOD:
                return self._parse_vod_catalogue_item(item)
            if item_type == _TYPE_SERIES:
                return self._parse_series_catalogue_item(item)
            if item_type == _TYPE_EPISODE:
                return self._parse_episode_catalogue_item(item)
            return self._parse_folder_catalogue_item(item)
        except _PARSE_ERRORS as exc:
            logger.warning(f"HRTi: skipping malformed catalogue item: {exc!r}")
            return None

    def _parse_folder_catalogue_item(self, item: Dict) -> Optional[VodCategory]:
        """No Type: a navigable sub-folder."""
        ref_id = item.get("ReferenceId")
        name = (item.get("Title") or item.get("Name") or "").strip()
        if not ref_id or not name:
            return None
        return VodCategory(
            name=name,
            content_id=f"catalogue_{ref_id}",
            provider=_PROVIDER,
            logo_url=item.get("PosterLandscape") or item.get("PosterPortrait"),
            description=None,
            child_count=item.get("ChildCount"),
        )

    def _parse_series_catalogue_item(self, item: Dict) -> Optional[VodCategory]:
        """Type 3: navigation goes to GetSeries (needs series + season ids);
        there is no GetSeasons, so the default season is ``<series>_S01``."""
        series_data = item.get("SeriesData") or {}
        series_ref_id = series_data.get("SeriesReferenceId") or item.get("ReferenceId")
        name = (item.get("Title") or "").strip()
        if not series_ref_id or not name:
            return None
        return VodCategory(
            name=name,
            content_id=f"series_{series_ref_id}--{series_ref_id}_S01",
            provider=_PROVIDER,
            logo_url=item.get("PosterLandscape") or item.get("PosterPortrait"),
            description=None,
            child_count=series_data.get("LastSeasonNumber"),
        )

    def _parse_vod_catalogue_item(self, item: Dict) -> Optional[VodItem]:
        """Type 2: playable item. manifest_script stays None (FileName only
        comes from GetVodDetails); content_id is the raw ReferenceId."""
        ref_id = item.get("ReferenceId")
        title = (item.get("Title") or "").strip()
        if not ref_id or not title:
            return None
        vod_data = item.get("VodData") or {}
        duration_ms = vod_data.get("Duration")
        genres = [g.strip() for g in (item.get("VodCategoryNames") or "").split(",") if g.strip()] or None
        return VodItem(
            name=title,
            content_id=ref_id,
            provider=_PROVIDER,
            logo_url=item.get("PosterLandscape") or item.get("PosterPortrait"),
            description=None,
            long_description=None,
            original_title=None,
            duration_seconds=int(duration_ms / 1000) if duration_ms else None,
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
        """Type 5: episode (EpisodeData / SeriesData sub-objects)."""
        ref_id = item.get("ReferenceId")
        title = (item.get("Title") or "").strip()
        if not ref_id or not title:
            return None
        ep_data = item.get("EpisodeData") or {}
        series_data = item.get("SeriesData") or {}
        duration_ms = ep_data.get("Duration")
        genres = [g.strip() for g in (item.get("VodCategoryNames") or "").split(",") if g.strip()] or None
        return VodItem(
            name=title,
            content_id=ref_id,
            provider=_PROVIDER,
            logo_url=item.get("PosterLandscape") or item.get("PosterPortrait"),
            description=None,
            long_description=None,
            original_title=None,
            duration_seconds=int(duration_ms / 1000) if duration_ms else None,
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

    # --- GetSeries: episodes of one season --------------------------------
    def _fetch_series_episodes(self, series_ref_id: str, season_ref_id: str) -> VodPage:
        result = self._post(
            "episodes",
            {
                "SeriesReferenceId": series_ref_id,
                "SeasonReferenceId": season_ref_id,
                "PageSize": HRTiDefaults.SERIES_PAGE_SIZE,
                "PageNumber": 1,
            },
        )
        if not isinstance(result, dict):
            logger.warning(f"HRTi: no episodes for series {series_ref_id} season {season_ref_id}")
            return VodPage()
        episodes = [e for e in (self._parse_episode_catalogue_item(i) for i in result.get("Items") or []) if e]
        return VodPage(entries=episodes, total=len(episodes))

    # --- Special lists (optional endpoints) --------------------------------
    def _fetch_special(self, endpoint_key: str, referer_path: str) -> VodPage:
        result = self._post(endpoint_key, {}, referer_path, required=False)
        if not isinstance(result, list):
            return VodPage()
        items = [i for i in (self._parse_vod_details_item(r) for r in result) if i]
        return VodPage(entries=items)

    def _parse_vod_details_item(self, item: Dict) -> Optional[VodItem]:
        """Rich item as returned by GetVodDetails / the special lists: ReferenceID
        (capital ID), FileName (the stream URL), DurationInFrames (/25 = s),
        Directors / Actors are plain strings."""
        try:
            ref_id = item.get("ReferenceID") or item.get("ReferenceId")
            title = (item.get("Title") or "").strip()
            if not ref_id or not title:
                return None
            frames = item.get("DurationInFrames")
            actors = item.get("Actors")
            genre = item.get("AssetCategory") or None
            return VodItem(
                name=title,
                content_id=ref_id,
                provider=_PROVIDER,
                logo_url=item.get("PosterLandscape") or item.get("PosterPortrait"),
                description=item.get("Description"),
                long_description=None,
                original_title=item.get("OriginalTitle"),
                duration_seconds=int(frames / _ASSUMED_FPS) if frames else None,
                release_year=item.get("ProductionYear"),
                rating=item.get("ContentRating"),
                genre=genre,
                genres=[genre] if genre else None,
                cast=[a.strip() for a in actors.split(",") if a.strip()] if actors else None,
                director=item.get("Directors") or None,
                season_number=item.get("SeasonNr"),
                episode_number=item.get("EpisodeNr"),
                series_id=item.get("SeriesReferenceId"),
                series_title=item.get("SeriesName"),
                trailer_url=item.get("TrailerUrl"),
                is_highlight=False,
                content_type="SERIES" if (item.get("Type") or "").lower() == "episode" else "MOVIE",
                manifest_script=item.get("FileName") or None,
            )
        except _PARSE_ERRORS as exc:
            logger.warning(f"HRTi: skipping malformed VOD details item: {exc!r}")
            return None

    # ------------------------------------------------------------------
    # Playback: details + authorised session, cached per request
    # ------------------------------------------------------------------
    def _cached(self, key: str) -> Optional[Any]:
        entry = self._playout_cache.get(key)
        if entry and (time.time() - entry[1]) < HRTiDefaults.PLAYOUT_CACHE_TTL:
            return entry[0]
        return None

    def _details(self, ref_id: str) -> VodDetails:
        cached = self._cached(f"vod:{ref_id}")
        if cached is not None:
            return cached
        result = self._post("vod_details", {"ReferenceId": ref_id})
        if not isinstance(result, dict) or not result:
            raise NotFoundError(f"HRTi: VOD item {ref_id} not found")
        try:
            details = VodDetails.from_api_response(result)
        except (KeyError, TypeError, AttributeError, ValueError) as exc:
            raise NotFoundError(f"HRTi: VOD item {ref_id} has no usable details: {exc}") from exc
        self._playout_cache[f"vod:{ref_id}"] = (details, time.time())
        return details

    def _session(self, ref_id: str) -> Dict[str, Any]:
        cached = self._cached(f"vodsess:{ref_id}")
        if cached is not None:
            return cached
        details = self._details(ref_id)
        if not details.file_name:
            raise EntitlementError(f"HRTi: no FileName (not entitled?) for VOD item {ref_id}")
        params = derive_vod_session_params(details.file_name)
        stores = details.svod_stores
        session_data = self.auth.authorize_session(
            content_type="svod" if stores else "vod",
            content_ref_id=params.content_ref_id,
            content_drm_id=params.content_drm_id,
            video_store_ids=stores or None,
            channel_id=None,
            start_time=None,
            end_time=None,
        )
        if not session_data.get("Authorized", False):
            raise EntitlementError(f"HRTi: VOD session for {ref_id} was not authorised")
        self._playout_cache[f"vodsess:{ref_id}"] = (session_data, time.time())
        return session_data

    def get_vod_manifest(self, content_id: str, **kw: Any) -> Optional[str]:
        details = self._details(ids.vod_ref(content_id))
        if not details.file_name:
            logger.warning(f"HRTi: no FileName for VOD item {content_id}")
            return None
        return details.file_name

    def get_vod_drm(self, content_id: str, **kw: Any) -> List[DRMConfig]:
        ref_id = ids.vod_ref(content_id)
        return build_widevine(
            self.config,
            self.auth.user_id,
            self._session(ref_id),
            ref_id,
            referer_path=_VOD_REFERER,
        )
