# streaming_providers/providers/magentaeu/vod_manager.py
# -*- coding: utf-8 -*-
"""
VOD manager for MagentaEU (HR/AT/PL/HU/ME).

Changes vs. the original proposal (see inline comments tagged FIXED /
NEW for the specifics):

  FIXED  DRM licence pid: get_drm() previously built the Widevine
         licence URL from playinfo's title_id/program_id. Against the
         capture, the real `releasePid` the client sends is
         `video.pid` from the /media response -- a different value
         that only exists after resolving the manifest. get_manifest()
         and get_drm() now share one `_resolve_playback()` call so
         both use the correct pid and neither re-fetches playinfo/media
         redundantly.
  FIXED  401 retry: `retry_on_auth` was accepted but never acted on.
         `_request()` now actually catches VodAuthError, force-refreshes
         the token once, and retries.
  FIXED  X-Tv-Step values: root categories capture shows step=DECK
         (not CATEGORIES); series actions capture shows
         step=SERIES_WATCH_ACTION (not SERIES_ACTIONS).
  NEW    VodCatchupRequiredError: some catalogue entries that look like
         VOD (empty actions.watch/trailer) are actually catch-up-only
         items from a linear channel (populated actions.schedules /
         episode catchup_schedules[], a station_id). These now raise a
         distinct, data-carrying exception instead of being reported as
         a plain entitlement denial.
  NEW    get_program_metadata(): the real client fetches
         `details/program/{id}` (no /actions/v2 suffix,
         flow=SINGLE_PROGRAM_DETAIL, step=PROGRAM_METADATA) for
         description/cast/genre fields the actions/v2 endpoint doesn't
         carry. The response schema for this endpoint has not been
         captured yet (only headers were observed, not a body), so this
         returns the raw parsed JSON rather than a typed object -- do
         not assume field names without a capture.
  NEW    get_related_content(): `relatedcontent/feed` is called by the
         real client but was not implemented in the original proposal.
         Field shapes are captured for the "Movie"/"Program" asset
         entries seen so far; still un-captured shapes raise
         VodNotImplementedError via the same discipline as search().

Everything else (browse, search, pagination) is unchanged from the
original proposal, which matched the capture well.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Union

from ...base.models import ContentType, DRMConfig, StreamingMode
from ...base.models.vod import VodCategory, VodItem
from ...base.utils.logger import logger

from ..lib_theplatform import (
    build_licence_url,
    build_widevine_drm_config,
)
from .auth import MagentaAuthToken, MagentaAuthenticator
from .constants import (
    DEFAULT_REQUEST_TIMEOUT,
    STREAMING_FORMAT_DASH,
    USER_AGENT,
    WV_URL,
    build_auth_headers,
    get_app_key,
    get_base_url,
    get_bifrost_url,
    get_language,
    get_natco_key,
)
from .vod_errors import (
    VodAccountVodDisabledError,
    VodAuthError,
    VodBadRequestError,
    VodCatchupRequiredError,
    VodEntitlementError,
    VodError,
    VodGeoBlockError,
    VodNotFoundError,
    VodRateLimitError,
    VodServerError,
)


# ---------------------------------------------------------------------------
# Response wrappers
# ---------------------------------------------------------------------------

@dataclass
class VodPage:
    """A page of VOD results (see get_component_assets_page)."""
    entries: List[Union[VodCategory, VodItem]]
    next_offset: Optional[int]

    @property
    def has_more(self) -> bool:
        return self.next_offset is not None


@dataclass
class SearchResult:
    """A search response (see search())."""
    entries: List[Union[VodCategory, VodItem]]
    has_more_items: bool


@dataclass
class ResolvedPlayback:
    """
    Everything needed to play one VOD asset, resolved once.

    `media_id` is the trailer/watch service item id (input to /media).
    `release_pid` is /media's `video.pid` -- the value the real client
    sends as `releasePid` to the Widevine licence endpoint. This is
    NOT the same as playinfo's title_id/program_id; conflating those
    was the original proposal's DRM bug.
    """
    video_src: str
    release_pid: str
    content_type: str
    media_id: str


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class MagentaEUVodManager:
    """VOD browse / search / playback-info manager for MagentaEU."""

    DEFAULT_ASSET_PAGE_SIZE = 20
    DEFAULT_SEARCH_SIZE = 30

    # How long a resolved-playback result stays valid for reuse between
    # a get_manifest() call and the get_drm() call that typically
    # follows it for the same title within one playback attempt. This
    # is NOT a manifest-freshness guarantee -- it only avoids the
    # provider re-hitting playinfo/media twice for one play action.
    _PLAYBACK_CACHE_TTL_SECONDS = 60

    def __init__(
        self,
        country: str,
        http_manager,
        authenticator: MagentaAuthenticator,
    ) -> None:
        self._country = country
        self._http = http_manager
        self._auth = authenticator

        self._bifrost_url = get_bifrost_url(country)
        self._natco_key = get_natco_key(country)
        self._app_language = get_language(country)
        self._app_key = get_app_key(country)
        self._origin = get_base_url(country)

        # (program_id, video_id) -> (ResolvedPlayback, resolved_at_epoch)
        self._playback_cache: Dict[Tuple[str, str], Tuple[ResolvedPlayback, float]] = {}

        logger.info(f"[MagentaEUVodManager/{country}] initialised")

    # ==================================================================
    # Public API -- VOD enablement
    # ==================================================================

    def is_vod_enabled(self, force_refresh: bool = False) -> Optional[bool]:
        try:
            self._auth.get_user_account(force_refresh=force_refresh)
        except Exception as exc:
            logger.warning(f"[{self._country}] get_user_account failed: {exc}")
            return None
        return self._auth.current_token.vod_enabled

    def require_vod_enabled(self, force_refresh: bool = False) -> None:
        enabled = self.is_vod_enabled(force_refresh=force_refresh)
        if enabled is False:
            raw = self._auth.current_token.vod_enabled_raw
            raise VodAccountVodDisabledError(
                f"VOD is disabled for this account "
                f"(TVSOA-setting-VodEnabled={raw!r})"
            )

    # ==================================================================
    # Public API -- browse
    # ==================================================================

    def get_root_categories(self) -> List[VodCategory]:
        """Top-level VOD navigation (POČETNA, SERIJE, FILMOVI, ZA DJECU, SPORT)."""
        data = self._request(
            "home/root/categories",
            params={
                "device_type": "WEB",
                "app_language": self._app_language,
                "natco_code": self._country,
            },
            flow="HOME",
            step="DECK",  # FIXED: capture shows DECK, not CATEGORIES
        )

        categories: List[VodCategory] = []
        for raw in data.get("categories") or []:
            cat = self._parse_category_root(raw)
            if cat is not None:
                categories.append(cat)

        logger.debug(f"[{self._country}] root categories: {len(categories)} entries")
        return categories

    def get_category_children(self, content_id: str) -> List[Union[VodCategory, VodItem]]:
        if not content_id:
            return self.get_root_categories()

        # Rails come back as components; a page id returns the rails on
        # that page. We cannot tell from the id alone which one this is,
        # so we try page first and fall back to component.
        #
        # FIXED (production evidence, not capture): the wrong-guess
        # signal from bifrost is 400 Bad Request, NOT 404 as originally
        # assumed. A live call to /home/page/{component_id} for a real
        # rail id (e.g. "PREPORUKA UREDNIKA" -> 640f02fb55eb300001743795)
        # returned 400. Catching only VodNotFoundError here meant every
        # non-page content_id propagated a raw VodError instead of
        # falling through to _get_component_assets -- i.e. every rail
        # was unbrowsable. Both exception types are caught now.
        try:
            return self._get_page_rails(content_id)
        except (VodNotFoundError, VodBadRequestError) as exc:
            logger.debug(
                f"[{self._country}] {content_id} is not a page "
                f"({type(exc).__name__}), trying as a component instead"
            )

        return self._get_component_assets(content_id)

    def _get_page_rails(self, page_id: str) -> List[VodCategory]:
        data = self._request(
            f"home/page/{page_id}",
            params={
                "page_size": 10,
                "offset": 0,
                "component_type": "all",
                "is_opted_in": "true",
                "app_language": self._app_language,
                "natco_code": self._country,
            },
            flow="HOME",
            step="PAGE_COMPONENTS",  # confirmed by capture (doc 7)
        )

        rails: List[VodCategory] = []
        for raw in data.get("components") or []:
            template = raw.get("template_id")
            if template not in ("RAIL", "HIGHLIGHT"):
                continue
            cat = self._parse_rail(raw)
            if cat is not None:
                rails.append(cat)

        logger.debug(f"[{self._country}] page {page_id}: {len(rails)} rails")
        return rails

    def _get_component_assets(
        self,
        component_id: str,
        offset: int = 0,
        page_size: Optional[int] = None,
    ) -> List[Union[VodCategory, VodItem]]:
        # FIXED: previously filtered to `isinstance(e, VodItem)` only,
        # which silently dropped every VodCategory (series) now
        # returned by _parse_asset. A rail can legitimately mix
        # playable movies (VodItem) and drill-down series
        # (VodCategory); both need to reach the caller.
        page = self.get_component_assets_page(component_id, offset=offset, page_size=page_size)
        return page.entries

    def get_component_assets_page(
        self,
        component_id: str,
        offset: int = 0,
        page_size: Optional[int] = None,
    ) -> VodPage:
        size = page_size or self.DEFAULT_ASSET_PAGE_SIZE

        data = self._request(
            f"home/component/{component_id}/assets",
            params={
                "offset": offset,
                "page_size": size,
                "device_type": "WEB",
                "store_id": "MHR Production - Main",
                "app_language": self._app_language,
                "natco_code": self._country,
            },
            flow="HOME",
            step="RAIL",
        )

        entries: List[VodItem] = []
        for raw in data.get("assets") or []:
            item = self._parse_asset(raw)
            if item is not None:
                entries.append(item)

        next_offset = data.get("next_offset")
        normalised_next = None if next_offset in (None, -1) else int(next_offset)

        logger.debug(
            f"[{self._country}] component {component_id} offset={offset}: "
            f"{len(entries)} items, next={normalised_next}"
        )
        return VodPage(entries=entries, next_offset=normalised_next)

    # ==================================================================
    # Public API -- details
    # ==================================================================

    def get_series_detail(self, series_id: str) -> Dict[str, Any]:
        """Raw series-actions response."""
        data = self._request(
            f"details/series/{series_id}/actions/v2",
            params={
                "interacted_with_nPVR": "false",
                "app_language": self._app_language,
                "natco_code": self._country,
            },
            flow="SERIES_DETAIL",
            step="SERIES_WATCH_ACTION",  # FIXED: capture shows this, not SERIES_ACTIONS
        )
        return data

    def get_season_episodes(
        self,
        series_id: str,
        season_id: str,
        season_number: int,
    ) -> List[VodItem]:
        """
        Episodes of one season, as VodItems.

        KNOWN LIMITATION: `season_id` must already be known (it comes
        from the season list inside a series-actions response), but the
        shape of that seasons list has not been captured -- every
        series-actions capture so far has had exactly one season, so
        it's unclear whether seasons come back as a `seasons: [...]`
        array on the series-actions response, a separate endpoint, or
        something else for a multi-season show. Callers currently have
        no verified way to enumerate seasons for a series with more
        than one season; this only works if the season_id is already
        known some other way (e.g. surfaced elsewhere in the UI flow).
        """
        data = self._request(
            f"details/series/{series_id}/season/{season_id}/v2",
            params={
                "interacted_with_nPVR": "false",
                "season_number": season_number,
                "app_language": self._app_language,
                "natco_code": self._country,
            },
            flow="SERIES_DETAIL",
            step="SEASON_EPISODE_LIST",
        )

        episodes: List[VodItem] = []
        for raw in data.get("episodes") or []:
            item = self._parse_episode(raw, series_id=series_id)
            if item is not None:
                episodes.append(item)
        return episodes

    def get_program_detail(self, program_id: str) -> Dict[str, Any]:
        """Raw program-actions response (movies, one-off programmes)."""
        data = self._request(
            f"details/program/{program_id}/actions/v2",
            params={
                "interacted_with_nPVR": "false",
                "app_language": self._app_language,
                "natco_code": self._country,
            },
            flow="SERIES_DETAIL",
            step="PROGRAM_ACTIONS",  # NOTE: unconfirmed -- no headers were
            # captured for this specific call, only its response body.
            # Verify against a fresh capture before relying on this step
            # value for anything that inspects X-Tv-Step server-side.
        )
        return data

    def get_program_metadata(self, program_id: str) -> Dict[str, Any]:
        """
        NEW. Raw `details/program/{id}` response (no /actions/v2 suffix).

        The real client calls this ahead of the /actions/v2 call for
        single-program detail pages (flow=SINGLE_PROGRAM_DETAIL,
        step=PROGRAM_METADATA) to get description/cast/genre fields
        that /actions/v2 does not carry. Only the request (headers +
        URL) was captured, not a response body, so this deliberately
        returns the raw dict rather than a typed object -- do not
        assume specific field names here until a body capture confirms
        them. Callers that want description/genres for a program
        should call this and merge defensively (e.g. `.get("description")`,
        `.get("metadata")` following the same GENRES-tagged-list shape
        used elsewhere in this file) rather than assuming it 1:1
        matches get_program_detail() or the episode `details` shape.
        """
        return self._request(
            f"details/program/{program_id}",
            params={
                "interacted_with_nPVR": "false",
                "app_language": self._app_language,
                "natco_code": self._country,
            },
            flow="SINGLE_PROGRAM_DETAIL",
            step="PROGRAM_METADATA",
        )

    def get_related_content(
        self,
        program_id: str,
        is_series: bool,
        size: int = 16,
        offset: int = 0,
    ) -> List[VodItem]:
        """
        NEW. `relatedcontent/feed` -- "more like this" rail on a detail page.

        Confirmed asset shape from capture:
            {"id", "title", "type": "Movie", "content_type": "Program",
             "thumbnail", "cta": {"deeplink"}, "ratings", "release_year"?}
        `release_year` was present on some entries and absent on others
        in the capture -- treated as optional here.
        """
        data = self._request(
            "relatedcontent/feed",
            params={
                "program_id": program_id,
                "live": "false",
                "size": size,
                "offset": offset,
                "is_series": "true" if is_series else "false",
                "app_language": self._app_language,
                "natco_code": self._country,
            },
            flow="SERIES_DETAIL" if is_series else "SINGLE_PROGRAM_DETAIL",
            step="RELATED_CONTENT",
        )

        items: List[VodItem] = []
        for raw in data.get("assets") or []:
            content_id = raw.get("id")
            title = raw.get("title")
            if not content_id or not title:
                continue
            items.append(VodItem(
                name=title,
                content_id=content_id,
                provider="magentaeu",
                logo_url=raw.get("thumbnail"),
                mode=StreamingMode.VOD,
                content_type=ContentType.MOVIE,
                release_year=raw.get("release_year"),
                rating=raw.get("ratings"),
                streaming_format=STREAMING_FORMAT_DASH,
                country=self._country.upper(),
                language=self._app_language,
            ))
        return items

    def get_program_playinfo(self, program_id: str, video_id: str) -> Dict[str, Any]:
        """Raw playinfo response for a program (movie)."""
        data = self._request(
            "player/playinfo/program",
            params={
                "program_id": program_id,
                "video_id": video_id,
                "device_type": "WEB",
                "app_language": self._app_language,
                "natco_code": self._country,
            },
            flow="PLAYER",
            step="VOD_PLAYBACK",
        )
        return data

    # ==================================================================
    # Public API -- search
    # ==================================================================

    def search(
        self,
        query: str,
        item_type: Optional[str] = None,
        size: Optional[int] = None,
    ) -> SearchResult:
        if not query:
            return SearchResult(entries=[], has_more_items=False)

        params = {
            "device_type": "WEB",
            "text_search": query,
            "size": size or self.DEFAULT_SEARCH_SIZE,
            "app_language": self._app_language,
            "natco_code": self._country,
        }
        if item_type:
            params["item_type"] = item_type

        data = self._request(
            "search/items",
            params=params,
            flow="SEARCH",
            step="SEARCH_ALL",
        )

        entries: List[Union[VodCategory, VodItem]] = []

        for raw in data.get("tv_shows") or []:
            cat = self._parse_search_series(raw)
            if cat is not None:
                entries.append(cat)

        for raw in data.get("movies") or []:
            if raw.get("is_live"):
                continue
            item = self._parse_search_movie(raw)
            if item is not None:
                entries.append(item)

        streaming = data.get("streaming") or []
        if streaming:
            logger.warning(
                f"[{self._country}] search returned {len(streaming)} "
                f"streaming[] entries -- parser not yet implemented, dropped."
            )

        return SearchResult(
            entries=entries,
            has_more_items=bool(data.get("has_more_items")),
        )

    # ==================================================================
    # Public API -- playback
    # ==================================================================

    def _resolve_playback(self, content_id: str, **kwargs) -> ResolvedPlayback:
        """
        Resolve everything needed to play a VOD asset, exactly once per
        (program_id, video_id) within the cache TTL.

        This is the single source of truth for both get_manifest() and
        get_drm() -- previously each independently re-derived a video_id
        via get_program_detail() and re-called get_program_playinfo(),
        doubling the request count per playback and (for get_drm)
        building the licence URL from the wrong field entirely.

        Raises VodCatchupRequiredError if the resolved program has no
        playable watch/trailer action but does have schedule data,
        signalling this is a linear-catchup item, not VOD.
        """
        video_id = kwargs.get("video_id")
        program_id = kwargs.get("program_id") or content_id

        if not video_id:
            video_id = self._resolve_playable_video_id(program_id)

        cache_key = (program_id, video_id)
        cached = self._playback_cache.get(cache_key)
        if cached is not None:
            resolved, resolved_at = cached
            if time.time() - resolved_at < self._PLAYBACK_CACHE_TTL_SECONDS:
                return resolved

        playinfo = self.get_program_playinfo(program_id, video_id)

        services = (playinfo.get("playBackInfoResponse") or {}).get("service_items") or []
        chosen = None
        for item in services:
            if not item.get("is_trailer"):
                chosen = item
                break
        if chosen is None and services:
            chosen = services[0]

        if chosen is None:
            raise VodError(
                f"No service_items in playinfo response for {program_id}/{video_id}"
            )

        media_id = chosen["media_id"]
        content_type = (playinfo.get("playBackInfoResponse") or {}).get(
            "content_type", "tvod"
        )

        media = self._request(
            "media",
            params={
                "client_id": self._auth.current_token.device_id or "",
                "media_id": media_id,
                "src_format": "MPEG-DASH",
                "content_type": content_type,
                "app_language": self._app_language,
                "natco_code": self._country,
            },
            flow="PLAYER",
            step="MEDIA_CALL",
        )

        video = media.get("video") or {}
        src = video.get("video_src") or video.get("ref_src")
        if not src:
            raise VodError(f"No video_src in /media response for media_id={media_id}")

        # FIXED: this is the actual releasePid the real client sends to
        # the Widevine licence endpoint -- NOT playinfo's title_id or
        # program_id (that was the original proposal's DRM bug).
        release_pid = video.get("pid")
        if not release_pid:
            raise VodError(f"No pid in /media response for media_id={media_id}")

        resolved = ResolvedPlayback(
            video_src=src,
            release_pid=release_pid,
            content_type=content_type,
            media_id=media_id,
        )
        self._playback_cache[cache_key] = (resolved, time.time())
        return resolved

    def get_manifest(self, content_id: str, **kwargs) -> Optional[str]:
        resolved = self._resolve_playback(content_id, **kwargs)
        logger.debug(f"[{self._country}] manifest for {content_id}: {resolved.video_src}")
        return resolved.video_src

    def get_drm(self, content_id: str, **kwargs) -> List[DRMConfig]:
        resolved = self._resolve_playback(content_id, **kwargs)

        token = self._auth.current_token
        if not isinstance(token, MagentaAuthToken):
            raise VodAuthError("No MagentaAuthToken available for DRM")

        persona_jwt = token.persona_jwt
        account_uri = token.account_uri
        if not persona_jwt or not account_uri:
            self._auth.get_user_account(force_refresh=True)
            token = self._auth.current_token
            persona_jwt = token.persona_jwt
            account_uri = token.account_uri

        if not persona_jwt:
            raise VodAuthError("dc_cts_personaToken missing from access token")
        if not account_uri:
            raise VodAuthError("account_url missing from /user/account response")

        licence_url = build_licence_url(
            widevine_endpoint=WV_URL,
            release_pid=resolved.release_pid,  # FIXED: was title_id/program_id
            persona_jwt=persona_jwt,
            account_uri=account_uri,
        )

        drm = build_widevine_drm_config(
            licence_url=licence_url,
            user_agent=USER_AGENT,
            origin=self._origin,
        )
        return [drm]

    # ==================================================================
    # Internal -- HTTP
    # ==================================================================

    def _build_headers(self, flow: str, step: str) -> Dict[str, str]:
        device_id, session_id = self._auth.get_guest_session_ids()
        return build_auth_headers(
            country=self._country,
            device_id=device_id,
            session_id=session_id,
            flow=flow,
            step=step,
            call_type="AUTH_USER",
        )

    @staticmethod
    def _extract_status(exc: Exception) -> Optional[int]:
        """
        Best-effort extraction of an HTTP status code from an exception
        raised by http_manager.get() itself.

        FIXED (production evidence): confirmed via live logs that
        http_manager.get() raises directly on non-2xx responses (it
        logs "HTTP unknown error..." and raises) rather than returning
        a response object with .status_code for the caller to inspect.
        That meant _raise_for_status() was NEVER reached for any
        non-2xx status -- every 400/401/403/404/429/5xx fell into the
        generic "Transport error" catch-all below, and the 401-retry
        logic was consequently unreachable too, despite looking correct
        on inspection. This extracts the status from the exception
        (the common requests.HTTPError shape: exc.response.status_code)
        so the same classification logic can run regardless of whether
        the status arrived via a raised exception or a returned
        response object.
        """
        response_obj = getattr(exc, "response", None)
        status = getattr(response_obj, "status_code", None)
        return status if isinstance(status, int) else None

    def _request(
        self,
        path: str,
        params: Dict[str, Any],
        flow: str,
        step: str,
        *,
        retry_on_auth: bool = True,
        timeout: int = DEFAULT_REQUEST_TIMEOUT,
    ) -> Dict[str, Any]:
        """
        Single HTTP entry point for every VOD call.

        Status classification happens from TWO possible places, since
        http_manager.get() has been confirmed to raise on non-2xx
        rather than always returning a response object: (1) the
        exception path below, via _extract_status(); (2) the
        `status = getattr(response, "status_code", ...)` path further
        down, kept as a defensive fallback in case behavior ever
        differs by status code or client version. Both paths funnel
        into the same _raise_for_status() + 401-retry logic so there's
        exactly one place that owns the retry decision.
        """
        token = self._auth.get_bearer_token()
        if token.startswith("Bearer "):
            token = token[7:]

        url = f"{self._bifrost_url}/{path.lstrip('/')}"

        full_params = dict(params)
        full_params["natco_key"] = self._natco_key

        headers = self._build_headers(flow, step)
        headers["Bff_token"] = token
        headers["X-Account-Details"] = self._account_details_header()

        cmid = self._auth.current_token.channel_map_id
        if cmid:
            headers["X-Channel-Map-Id"] = str(cmid)

        try:
            response = self._http.get(
                url,
                operation=f"vod_{path.replace('/', '_')}",
                headers=headers,
                params=full_params,
                timeout=timeout,
            )
        except Exception as exc:
            status = self._extract_status(exc)
            if status is None:
                # Genuine transport failure (DNS, TLS, connection
                # refused, timeout) -- no status to classify.
                raise VodError(f"Transport error on {path}: {exc}", url=url) from exc
            return self._handle_status(
                status, getattr(exc, "response", None), url, path,
                params=params, flow=flow, step=step,
                retry_on_auth=retry_on_auth, timeout=timeout,
                transport_exc=exc,
            )

        status = getattr(response, "status_code", None)
        if status == 200:
            return response.json()

        return self._handle_status(
            status, response, url, path,
            params=params, flow=flow, step=step,
            retry_on_auth=retry_on_auth, timeout=timeout,
            transport_exc=None,
        )

    def _handle_status(
        self,
        status: Optional[int],
        response,
        url: str,
        path: str,
        *,
        params: Dict[str, Any],
        flow: str,
        step: str,
        retry_on_auth: bool,
        timeout: int,
        transport_exc: Optional[Exception],
    ) -> Dict[str, Any]:
        """Shared non-2xx handling for both call sites in _request()."""
        try:
            self._raise_for_status(status, response, url, path)
        except VodAuthError:
            if not retry_on_auth:
                raise
            logger.info(
                f"[{self._country}] 401 on {path}, refreshing token and retrying once"
            )
            self._auth.get_bearer_token(force_refresh=True)
            return self._request(
                path, params, flow, step,
                retry_on_auth=False, timeout=timeout,
            )

        # Defensive -- _raise_for_status always raises on non-200.
        if transport_exc is not None:
            raise VodError(
                f"Unreachable: status {status}", status=status, url=url
            ) from transport_exc
        raise VodError(f"Unreachable: status {status}", status=status, url=url)

    @staticmethod
    def _raise_for_status(status: int, response, url: str, path: str) -> None:
        body_snippet = ""
        try:
            body_snippet = (response.text or "")[:512]
        except Exception:
            pass

        message = f"{status} from {path}: {body_snippet}"

        if status == 401:
            raise VodAuthError(message, status=status, url=url)
        if status == 403:
            lower = body_snippet.lower()
            if "geo" in lower or "region" in lower:
                raise VodGeoBlockError(message, status=status, url=url)
            raise VodEntitlementError(message, status=status, url=url)
        if status == 404:
            raise VodNotFoundError(message, status=status, url=url)
        if status == 400:
            # FIXED (production evidence): a component id passed to
            # /home/page/{id} returns 400, not 404. get_category_children()
            # relies on this being raised as a distinguishable type to
            # know its page-vs-component guess was wrong.
            raise VodBadRequestError(message, status=status, url=url)
        if status == 429:
            raise VodRateLimitError(message, status=status, url=url)
        if 500 <= status < 600:
            raise VodServerError(message, status=status, url=url)
        raise VodError(message, status=status, url=url)

    def _account_details_header(self) -> str:
        token = self._auth.current_token
        info = token.account_info or {}

        account_type = info.get("account_type") or "MHR_default"
        user_id = info.get("tvAccountId") or info.get("user_id") or ""
        channel_map_id = info.get("channelMap_id") or token.channel_map_id or ""
        account_id = info.get("account_id") or ""
        vod_enabled = str(token.vod_enabled).lower() if token.vod_enabled is not None else "false"

        import json
        return json.dumps({
            "accountType": account_type,
            "userId": user_id,
            "recordingEnabledDVR": False,
            "channelMapId": channel_map_id,
            "rightsGroupIds": "",
            "releaseSlot": "",
            "accountId": account_id,
            "vodEnabled": vod_enabled,
        })

    # ==================================================================
    # Internal -- entitlement / catchup detection
    # ==================================================================

    def _resolve_playable_video_id(self, program_id: str) -> str:
        """
        Given a program id, return the media_id (video_id) of a
        playable action.

        Order of preference:
            1. actions.watch[0].video_id  (entitled -- UNVERIFIED, see
               module docstring: every capture so far has an account
               with vod_enabled=false, so this branch has never fired)
            2. actions.trailer[0].video_id (trailer -- confirmed working
               against the capture, "Tom i Jerry" case)
            3. SPECULATIVE, likely dead: if watch/trailer are both
               empty, check for schedules/catchup_schedules and raise
               VodCatchupRequiredError instead of a plain entitlement
               error. See the big comment at the check itself -- this
               field pair is confirmed to exist on the *series*-actions
               response (a different endpoint,
               details/series/{id}/actions/v2, called by
               get_series_detail()), but every *program*-actions
               response captured so far (details/program/{id}/actions/v2
               -- the endpoint this method actually calls) has neither
               key at all, whether for a movie or an episode. As
               written this branch is reachable but has never actually
               fired against real data. Left in as defensive coding
               with this caveat rather than removed outright -- but do
               not treat it as confirmed, and do not build further
               logic on top of it until a capture shows the fields
               present at THIS endpoint.
            4. raise VodEntitlementError
        """
        detail = self.get_program_detail(program_id)
        actions = detail.get("actions") or {}

        for key in ("watch", "trailer"):
            bucket = actions.get(key) or []
            if bucket:
                first = bucket[0]
                vid = (
                    first.get("video_id")
                    or (first.get("video") or {}).get("video_id")
                )
                if vid:
                    return vid

        # SPECULATIVE (see docstring point 3 above): schedules /
        # catchup_schedules are confirmed present on the *series*-level
        # actions response (get_series_detail()'s endpoint), not on the
        # *program*-level actions response this method calls. Kept as a
        # defensive no-op-in-practice check rather than removed, since
        # it's cheap and correct IF the fields ever do appear here --
        # but do not rely on it firing until a program/episode-actions
        # capture confirms it.
        schedules = actions.get("schedules") or []
        catchup_schedules = actions.get("catchup_schedules") or []
        if schedules or catchup_schedules:
            station_id = None
            if schedules:
                station_id = schedules[0].get("station_id")
            elif catchup_schedules:
                station_id = catchup_schedules[0].get("station_id")
            raise VodCatchupRequiredError(
                f"{program_id} has no watch/trailer action but has "
                f"schedule data -- this is a linear catch-up item, not "
                f"VOD. Route to provider.get_catchup_manifest() instead.",
                station_id=station_id,
                schedules=schedules,
                catchup_schedules=catchup_schedules,
            )

        msg = actions.get("svod_subscription_message")
        if msg:
            raise VodEntitlementError(f"No playable action for {program_id}: {msg}")
        raise VodEntitlementError(
            f"No playable action for {program_id} (actions.watch, "
            f"actions.trailer, and schedule data all empty)"
        )

    # ==================================================================
    # Internal -- parsers
    # ==================================================================

    @staticmethod
    def _parse_category_root(raw: Dict[str, Any]) -> Optional[VodCategory]:
        page_id = raw.get("page_id") or raw.get("id")
        title = raw.get("title") or raw.get("name")
        if not page_id or not title:
            return None
        return VodCategory(
            name=title.strip(),
            content_id=page_id,
            provider="magentaeu",
        )

    def _parse_rail(self, raw: Dict[str, Any]) -> Optional[VodCategory]:
        comp_id = raw.get("id")
        title = raw.get("title")
        if not comp_id or not title:
            return None

        content_details = raw.get("content_details") or {}
        end_point = content_details.get("end_point") or ""

        if end_point.startswith("recommendations/"):
            logger.debug(
                f"[{self._country}] rail {comp_id} is a recommendations "
                f"rail (end_point={end_point!r}); children not resolvable"
            )

        return VodCategory(
            name=title.strip(),
            content_id=comp_id,
            provider="magentaeu",
            child_count=None,
            details_url=end_point or None,
            fetch_url=None,
        )

    def _parse_asset(self, raw: Dict[str, Any]) -> Optional[Union[VodCategory, VodItem]]:
        content_id = raw.get("id")
        title = raw.get("title")
        if not content_id or not title:
            return None

        item_type = raw.get("type") or ""
        content_type = raw.get("content_type") or ""

        # FIXED: series assets on a rail were previously dropped
        # entirely (returned None). Against the capture, the entire
        # "SERIJE" page's rail assets are content_type=="Series" --
        # dropping them broke top-level series navigation completely.
        # Return a VodCategory drill-down node instead; the caller
        # (get_category_children) already knows how to descend into a
        # VodCategory via series_id.
        if item_type == "TVShow" or content_type == "Series":
            return VodCategory(
                name=title,
                content_id=content_id,
                provider="magentaeu",
                logo_url=raw.get("thumbnail"),
            )

        return VodItem(
            name=title,
            content_id=content_id,
            provider="magentaeu",
            logo_url=raw.get("thumbnail"),
            mode=StreamingMode.VOD,
            content_type=ContentType.MOVIE,
            release_year=raw.get("release_year"),
            rating=raw.get("ratings"),
            streaming_format=STREAMING_FORMAT_DASH,
            country=self._country.upper(),
            language=self._app_language,
        )

    def _parse_episode(
        self,
        raw: Dict[str, Any],
        series_id: Optional[str] = None,
    ) -> Optional[VodItem]:
        content_id = raw.get("id")
        if not content_id:
            return None

        episode_number: Optional[int] = None
        try:
            episode_number = int(raw.get("number"))
        except (TypeError, ValueError):
            pass

        details = raw.get("details") or {}
        description = details.get("description")

        genres = None
        for meta in details.get("metadata") or []:
            if meta.get("type") == "GENRES" and meta.get("value"):
                genres = [g.strip() for g in meta["value"].split(",") if g.strip()] or None
                break

        runtime = raw.get("runtime_seconds")
        try:
            runtime = int(runtime) if runtime is not None else None
        except (TypeError, ValueError):
            runtime = None

        return VodItem(
            name=raw.get("name") or f"Episode {raw.get('number')}",
            content_id=content_id,
            provider="magentaeu",
            logo_url=raw.get("poster_image_url"),
            mode=StreamingMode.VOD,
            content_type=ContentType.SERIES,
            description=description,
            release_year=raw.get("release_year"),
            rating=raw.get("ratings"),
            genres=genres,
            genre=genres[0] if genres else None,
            duration_seconds=runtime,
            episode_number=episode_number,
            series_id=series_id,
            streaming_format=STREAMING_FORMAT_DASH,
            country=self._country.upper(),
            language=self._app_language,
        )

    @staticmethod
    def _parse_search_series(raw: Dict[str, Any]) -> Optional[VodCategory]:
        series_id = raw.get("id")
        title = raw.get("name")
        if not series_id or not title:
            return None
        return VodCategory(
            name=title,
            content_id=series_id,
            provider="magentaeu",
            logo_url=raw.get("poster_image_url"),
        )

    def _parse_search_movie(self, raw: Dict[str, Any]) -> Optional[VodItem]:
        content_id = raw.get("id")
        title = raw.get("name")
        if not content_id or not title:
            return None

        runtime = raw.get("runtime_seconds")
        try:
            runtime = int(runtime) if runtime is not None else None
        except (TypeError, ValueError):
            runtime = None

        return VodItem(
            name=title,
            content_id=content_id,
            provider="magentaeu",
            logo_url=raw.get("poster_image_url"),
            mode=StreamingMode.VOD,
            content_type=ContentType.MOVIE,
            release_year=raw.get("release_year"),
            rating=raw.get("ratings"),
            duration_seconds=runtime,
            streaming_format=STREAMING_FORMAT_DASH,
            country=self._country.upper(),
            language=self._app_language,
        )

    # ==================================================================
    # Internal -- serialisation helper (for debugging)
    # ==================================================================

    @staticmethod
    def as_dict(entries: List[Union[VodCategory, VodItem]]) -> List[Dict]:
        return [e.to_dict() for e in entries]