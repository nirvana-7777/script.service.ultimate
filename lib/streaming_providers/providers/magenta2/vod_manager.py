# streaming_providers/providers/magenta2/vod_manager.py
"""
Magenta2 VOD Manager

Handles VOD catalogue browsing for the Magenta2 provider.

Browsing API hierarchy
-----------------------
    StructuredGrid/{VOD_FLEX_ID_HOME}                              → top-level lanes
    UnstructuredGrid/{flex_id}                                     → paginated lane items
    VodDetails/{VOD_FLEX_ID_DETAILS}/{gn_id}                      → series / movie / episode detail
    VodDetails/{VOD_FLEX_ID_DETAILS}/GN_SEASON_{id}_DE_{n}        → season detail

Playback chain  (implemented in provider.get_manifest)
-------------------------------------------------------
    1. VodDetails response  →  content.productInformationLink.href
          (wcps .../uspip/.../vodproductinformation/.../GN_...)
       Stored as VodItem.manifest_script at browse time.

    2. Fetch productInformationLink  →  buttons.primary[]
          Pick entry where rel=="player" AND instantUsable==true
          (skip rel=="launchApp" -- those are external apps, not streams)
          → href  = VodPlayer URL  (follow directly, do not construct)
          → partnerId already in the URL as a query param

    3. Fetch VodPlayer href  (append $redirect=false + sid from _base_params)
          → content.playbackUrls[].href
             (link.theplatform.eu/s/mdeprod/media/{mpx_id})
          That MPX selector URL is the manifest -- identical format to live channels.

    Bonus: buttons.secondary[] where rel=="trailer"
          → href = trailer URL  (populate VodItem.trailer_url if desired)

tvhubs base URL resolution order
---------------------------------
1. Manifest tv_hubs.base_urls  (via ProviderConfig.get_tvhubs_base_url)
2. TVHUBS_BASE_URL constant    (fallback)

Public interface
-----------------
    vod_manager.get_children(category_path, **kwargs)
        -> List[VodCategory | VodItem]
"""

import time
import uuid as _uuid_mod
from typing import Any, Dict, List, Optional, Union
from ...base.utils.logger import logger

from ...base.models.vod import VodCategory, VodItem

from .constants import (
    QUALITY_FALLBACK,
    SUBSCRIBER_TYPES,
    TVHUBS_BASE_URL,
    VOD_DEFAULT_PAGE_SIZE,
    VOD_FLEX_ID_DETAILS,
    VOD_FLEX_ID_HOME,
    VOD_PREFIX_EPISODE,
    VOD_PREFIX_SEASON,
    VOD_PREFIX_SERIES,
    VOD_STREAMING_TILE_TITLES,
)


class VodManager:
    """
    Manages Magenta2 VOD catalogue traversal.

    Args:
        http_manager:    An HTTPManager instance (from the parent provider).
        provider_name:   Provider identifier string (e.g. "magenta2").
        bootstrap:       BootstrapConfig obtained from discovery.  Supplies all
                         per-platform values (device_model, subscriber_type,
                         client_model, profile_name, theme_id, home_url) so
                         that platform identity does not need to be carried
                         through this class at all.
        provider_config: Optional ProviderConfig; when supplied the tvhubs base
                         URL is resolved from the manifest instead of the
                         TVHUBS_BASE_URL fallback constant.
    """

    def __init__(
        self,
        http_manager,
        provider_name: str,
        bootstrap=None,
        provider_config=None,
        session_id: Optional[str] = None,
        serial_number: Optional[str] = None,
        preferred_quality: str = "UHD",
        auth_headers_callback=None,
    ):
        self._http = http_manager
        self._provider = provider_name
        self._provider_config = provider_config
        self._session_id: str = session_id or ""
        # Stable serial number for the lifetime of this manager instance.
        # Passed in from the provider so it stays consistent across all
        # requests. Falls back to a fresh UUID only when not supplied (e.g. tests).
        self._serial_number: str = serial_number or str(_uuid_mod.uuid4())
        # Normalise to uppercase; fall back to "HD" for unknown values.
        _q = (preferred_quality or "HD").upper()
        self._preferred_quality: str = _q if _q in QUALITY_FALLBACK else "HD"
        # Optional callable() -> Dict[str, str] returning auth headers for
        # authenticated VOD endpoints (vodproductinformation, VodPlayer).
        # When None, requests are sent without auth (browsing/catalogue only).
        self._auth_headers_callback = auth_headers_callback

        # All content values resolved from BootstrapConfig -- no platform needed.
        self._home_url: Optional[str] = getattr(bootstrap, "home_url", None)
        self._client_model: str = getattr(bootstrap, "client_model", None) or "ftv-web"
        self._device_model: str = getattr(bootstrap, "device_model", None) or "WEB2_FTV"
        self._profile_name: str = getattr(bootstrap, "profile_name", None) or "stageExt"
        self._theme_id: str = getattr(bootstrap, "theme_id", None) or "hdr-ui2"
        # white_label_id scopes all tvhubs/wcps requests to the correct portal.
        # Comes from bootstrap (e.g. "megathek"); falls back to no param when absent
        # so existing behaviour is preserved for accounts that don't use white-labelling.
        self._white_label_id: Optional[str] = getattr(bootstrap, "white_label_id", None)
        # partner_map_id is the "partnerMap" theme string from the StructuredGrid
        # response (e.g. "wl_megathek").  It is discovered at browse time by
        # _parse_theme_strings() and then injected into every vodproductinformation
        # request via _playback_params().  Not available from bootstrap because it
        # is portal-specific metadata returned by the server, not a device identity.
        self._partner_map_id: Optional[str] = None
        # subscriber_type is not in bootstrap; derive from platform once at init.
        _platform = getattr(bootstrap, "platform", "")
        self._subscriber_type: str = SUBSCRIBER_TYPES.get(_platform, "FTV_OTT_DT")

        # Short-lived in-memory cache for VodDetails responses (content_id → data).
        # Prevents redundant network round-trips when the same content_id is
        # looked up multiple times within a single get_children() call chain
        # (e.g. _map_unstructured_item → _fetch_single_item for every lane movie,
        # then the provider calling get_children([gn_id]) directly to resolve
        # the MPX mediaId for playback).  Entries are keyed by the content_id
        # string and are not persisted across VodManager instances.
        self._vod_details_cache: Dict[str, Any] = {}

    # =========================================================================
    # Public API
    # =========================================================================

    def get_children(
        self,
        category_path: List[str],
        *,
        page_size: int = VOD_DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> List[Union[VodCategory, VodItem]]:
        """
        Return the children of a VOD tree node.

        Args:
            category_path: Ordered list of content_ids from root to the
                           requested node, matching the provider's contract:
                               []                       -> VOD home (top-level lanes)
                               ["GN_SERIES_123"]        -> series (seasons)
                               ["GN_SERIES_123",
                                "GN_SEASON_123_DE_2"]   -> season (episodes)
                               ["lane:326619"]           -> UnstructuredGrid lane
            page_size:  Number of items to fetch per page (UnstructuredGrid).
            offset:     Pagination offset (UnstructuredGrid).

        Returns:
            Mixed list of VodCategory and VodItem objects.
        """
        logger.debug(
            f"{self._provider}: get_children called with category_path={category_path!r}"
        )
        params = self._base_params()

        if not category_path:
            return self._fetch_home_lanes(params)

        # Reconstruct the full content_id from the path segments.
        # The caller splits on "/" so "UnstructuredGrid/357162" arrives as
        # ["UnstructuredGrid", "357162"] and "VodDetails/202887/GN_SERIES_9370385"
        # arrives as ["VodDetails", "202887", "GN_SERIES_9370385"].
        node_id = "/".join(category_path)

        if node_id.startswith("UnstructuredGrid/"):
            # The tail after "UnstructuredGrid/" may include query params
            # (e.g. "357162?whiteLabelId=megathek") that were preserved from
            # the original laneContentLink.  Split them out so _fetch_lane_items
            # can pass them as extra params rather than having them corrupt the
            # flex_id path segment.
            tail = node_id[len("UnstructuredGrid/"):]
            if "?" in tail:
                flex_id, qs_string = tail.split("?", 1)
                from urllib.parse import parse_qs
                extra = {k: v[0] for k, v in parse_qs(qs_string).items()}
            else:
                flex_id = tail
                extra = {}
            return self._fetch_lane_items(
                flex_id, params,
                page_size=page_size, offset=offset,
                extra_params=extra,
            )

        if node_id.startswith("VodDetails/"):
            # e.g. "VodDetails/202887/GN_SERIES_9370385" → extract the GN id
            node_id = node_id.split("/")[-1]

        if node_id.startswith(VOD_PREFIX_SEASON):
            return self._fetch_season_episodes(node_id, params)

        if node_id.startswith(VOD_PREFIX_SERIES):
            return self._fetch_series_seasons(node_id, params)

        if node_id.startswith(VOD_PREFIX_EPISODE):
            return self._fetch_single_episode(node_id, params)

        # Movies (GN_MV, GN_SH) and any other leaf ID
        return self._fetch_single_item(node_id, params)

    # =========================================================================
    # Private helpers – HTTP layer
    # =========================================================================

    def _get_vod_details(self, content_id: str, params: Dict) -> Optional[Dict]:
        """
        Fetch (and cache) a VodDetails response for *content_id*.

        The cache is keyed by content_id and lives for the lifetime of the
        VodManager instance.  This prevents duplicate network round-trips when
        the same content_id is resolved more than once within a single browsing
        session (e.g. lane enumeration followed by playback resolution).
        """
        if content_id in self._vod_details_cache:
            logger.debug(f"{self._provider}: VodDetails cache hit for {content_id}")
            return self._vod_details_cache[content_id]

        url = f"{self._base_url()}/VodDetails/{VOD_FLEX_ID_DETAILS}/{content_id}"
        data = self._get(url, params)
        if data:
            self._vod_details_cache[content_id] = data
        return data

    def _is_androidtv(self) -> bool:
        """Return True when the active client model is an Android TV variant."""
        return self._client_model.endswith("-androidtv")

    def _base_params(self) -> Dict[str, str]:
        """Build query parameters common to every tvhubs VOD API request.

        Session correlation follows the platform convention:
          - Android TV: ``$cid`` = ``<sessionId>::<callUUID>``  (no sid / t)
          - Web / other: ``sid`` + ``t``                        (no $cid)
        """
        params: Dict[str, str] = {
            "$deviceModel": self._device_model,
            "$profile": self._profile_name,
            "$subscriberType": self._subscriber_type,
            "$theme": self._theme_id,
            "$redirect": "false",
        }
        if self._is_androidtv():
            call_id = str(_uuid_mod.uuid4())
            params["$cid"] = f"{self._session_id}::{call_id}"
        else:
            params["sid"] = self._session_id
            params["t"] = str(int(time.time() * 1000))
        if self._white_label_id:
            params["whiteLabelId"] = self._white_label_id
        return params

    def _base_url(self) -> str:
        """
        Resolve the tvhubs root URL (https://host/v3/{clientModel}) with the
        client model already substituted.

        Resolution order:
          1. ProviderConfig.get_tvhubs_base_url() — derives the root from hub
             URLs already in the manifest, reusing data fetched for live TV.
          2. TVHUBS_BASE_URL constant — fallback when manifest is unavailable.
        """
        if self._provider_config is not None:
            resolved = self._provider_config.get_tvhubs_base_url(self._client_model)
            if resolved:
                return resolved

        return TVHUBS_BASE_URL.format(client_model=self._client_model)

    def _get(self, url: str, params: Dict) -> Optional[Dict]:
        """
        Perform a GET request and return the parsed JSON body, or None on error.

        Auth headers are injected automatically when auth_headers_callback is
        set — all tvhubs and wcps VOD endpoints require the same Bearer +
        x-mpx-authorization headers.
        """
        headers = None
        if self._auth_headers_callback:
            try:
                headers = self._auth_headers_callback()
            except Exception as exc:
                logger.warning(f"{self._provider}: auth_headers_callback failed: {exc}")
        try:
            response = self._http.get(url, params=params, headers=headers)
            if response and response.status_code == 200:
                return response.json()
            logger.warning(
                f"{self._provider}: VOD request failed "
                f"[{response.status_code if response else 'no response'}] {url}"
            )
        except Exception as exc:
            logger.error(f"{self._provider}: VOD request exception for {url}: {exc}")
        return None

    def _get_auth(self, url: str, params: Dict) -> Optional[Dict]:
        """Alias for _get — auth is now always injected when callback is set."""
        return self._get(url, params)

    def _get_no_auth(self, url: str, params: Dict) -> Optional[Dict]:
        """
        Perform a GET request *without* auth headers, regardless of whether
        auth_headers_callback is set.

        Used for unauthenticated endpoints such as PersonalBar discovery, where
        attaching Bearer / x-mpx-authorization headers causes the server to
        return a different or empty response.
        """
        try:
            response = self._http.get(url, params=params, headers=None)
            if response and response.status_code == 200:
                return response.json()
            logger.warning(
                f"{self._provider}: VOD request (no-auth) failed "
                f"[{response.status_code if response else 'no response'}] {url}"
            )
        except Exception as exc:
            logger.error(
                f"{self._provider}: VOD request (no-auth) exception for {url}: {exc}"
            )
        return None

    def _get_with_serial(
        self,
        url: str,
        params: Dict,
        serial_number: str,
        dt_session_id: str = "",
        dt_call_id: str = "",
    ) -> Optional[Dict]:
        """
        Perform an authenticated GET injecting the full set of device-identity
        headers required by the personal-bar endpoints:

            x-stbserialnumber   — device hardware serial (random UUID)
            dt-session-id       — stable across the discovery sequence
            dt-call-id          — fresh UUID per individual request

        These are sent in addition to the standard Bearer token from
        auth_headers_callback.  Omitting any of them causes the server to
        return an empty or unexpected response.
        """
        headers: Dict[str, str] = {}
        if self._auth_headers_callback:
            try:
                headers = dict(self._auth_headers_callback())
            except Exception as exc:
                logger.warning(f"{self._provider}: auth_headers_callback failed: {exc}")
        headers["x-stbserialnumber"] = serial_number
        if dt_session_id:
            headers["dt-session-id"] = dt_session_id
        if dt_call_id:
            headers["dt-call-id"] = dt_call_id
        try:
            response = self._http.get(url, params=params, headers=headers)
            if response and response.status_code == 200:
                return response.json()
            logger.warning(
                f"{self._provider}: VOD request (with serial) failed "
                f"[{response.status_code if response else 'no response'}] {url}"
            )
        except Exception as exc:
            logger.error(
                f"{self._provider}: VOD request (with serial) exception for {url}: {exc}"
            )
        return None

    # =========================================================================
    # Private helpers – Personal Bar Discovery
    # =========================================================================

    def _get_streaming_grid_url(self) -> Optional[str]:
        """
        Fetch the personal bar and extract the Streaming tile's StructuredGrid URL.

        Flow:
          1. Build the DocumentGroupRedirect URL using the platform's client model
             (e.g. ftv-androidtv for Android TV) substituted into home_url.
          2. Send an authenticated GET (Bearer + x-stbserialnumber + dt-session-id
             + dt-call-id) with params matching the real device call:
             $previewAutoMode, $deviceModel, $cid (dt-session-id::dt-call-id),
             $theme, $profile, $redirect.
          3. Follow the API-level redirect — the server returns
             {"$type":"redirect","redirectUrl":"..."} instead of an HTTP redirect.
          4. Fetch the redirectUrl authenticated with the same serial + session ID
             but a fresh dt-call-id (matching real device behaviour).
          5. Find the tile whose title matches VOD_STREAMING_TILE_TITLE and
             return its onFocus.screen.href.

        Falls back gracefully at each step so the hardcoded StructuredGrid URL
        is used when discovery fails.
        """
        import uuid as _uuid
        from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, quote

        if not self._home_url:
            logger.debug(
                f"{self._provider}: No homeUrl available; "
                "skipping personal-bar VOD discovery"
            )
            return None

        # Substitute the platform's actual client model into the home_url template
        # (e.g. ftv-androidtv for Android TV, ftv-web for web).
        resolved_home_url = self._home_url.replace("{clientModel}", self._client_model)

        # Use the provider's persistent session_id (same one used everywhere else)
        # rather than generating a random one — the server uses this to personalise
        # the bar, which is why the wrong session ID returns generic tiles instead
        # of the user's personalised view including the "Streaming" tile.
        dt_session_id = self._session_id
        dt_call_id_1 = str(_uuid.uuid4())
        cid = f"{dt_session_id}::{dt_call_id_1}"

        # Use the stable serial number set at construction time rather than
        # generating a fresh UUID on every call — the server uses it to
        # correlate requests within the same session.
        serial_number = self._serial_number

        # Params mirror the real Android TV DocumentGroupRedirect request exactly.
        # Note: $subscriberType and $reloadAfterChange are NOT sent by real devices;
        # $previewAutoMode and $cid are required instead.
        discovery_params = {
            "$previewAutoMode": "false",
            "$deviceModel": self._device_model,
            "$cid": cid,
            "$redirect": "false",
            "$theme": self._theme_id,
            "$profile": self._profile_name,
        }

        logger.debug(f"{self._provider}: home_url raw: {self._home_url}")
        logger.debug(f"{self._provider}: DocumentGroupRedirect URL: {resolved_home_url}")
        logger.debug(f"{self._provider}: DocumentGroupRedirect params: {discovery_params}")

        # Build and log the full header set for the first call so we can verify
        # the Bearer token, session ID, call ID and serial are all correct.
        _preview_headers: Dict[str, str] = {}
        if self._auth_headers_callback:
            try:
                _preview_headers = dict(self._auth_headers_callback())
            except Exception as exc:
                logger.warning(f"{self._provider}: auth_headers_callback failed (preview): {exc}")
        _preview_headers["x-stbserialnumber"] = serial_number
        _preview_headers["dt-session-id"] = dt_session_id
        _preview_headers["dt-call-id"] = dt_call_id_1
        logger.debug(
            f"{self._provider}: DocumentGroupRedirect headers: {_preview_headers}"
        )

        # The DocumentGroupRedirect endpoint requires authentication — real device
        # sends Bearer token + x-stbserialnumber + dt-session-id + dt-call-id.
        redirect_data = self._get_with_serial(
            resolved_home_url, discovery_params, serial_number,
            dt_session_id=dt_session_id, dt_call_id=dt_call_id_1,
        )
        if not redirect_data:
            logger.error(f"{self._provider}: Failed to fetch DocumentGroupRedirect")
            return None

        logger.debug(
            f"{self._provider}: DocumentGroupRedirect response: {redirect_data}"
        )

        # Step 2: follow the API-level redirect.
        # The server-built redirectUrl omits $cid — append it with a fresh call ID
        # so the PersonalBar endpoint can correlate the session and return the
        # correct personalised tile set (including "Streaming").
        if redirect_data.get("$type") == "redirect":
            redirect_url = redirect_data.get("redirectUrl")
            if not redirect_url:
                logger.error(f"{self._provider}: Redirect response missing redirectUrl")
                return None

            # Inject $cid into the redirectUrl (fresh call ID, same session ID).
            dt_call_id_2 = str(_uuid.uuid4())
            cid_2 = f"{dt_session_id}::{dt_call_id_2}"
            parsed = urlparse(redirect_url)
            qs = parse_qs(parsed.query, keep_blank_values=True)
            qs["$cid"] = [cid_2]
            # Use quote_via=quote with safe='$:' so that $ signs in
            # parameter names and :: in the cid value are NOT percent-
            # encoded (%24). The server requires literal $ characters.
            redirect_url_with_cid = urlunparse(
                parsed._replace(
                    query=urlencode(
                        {k: v[0] for k, v in qs.items()},
                        quote_via=quote,
                        safe="$:",
                    )
                )
            )

            logger.debug(
                f"{self._provider}: Following personal-bar redirect "
                f"(with $cid): {redirect_url_with_cid}"
            )
            bar_data = self._get_with_serial(
                redirect_url_with_cid, {}, serial_number,
                dt_session_id=dt_session_id, dt_call_id=dt_call_id_2,
            )
            if not bar_data:
                logger.error(f"{self._provider}: Failed to fetch PersonalBar from redirectUrl")
                return None
            logger.debug(
                f"{self._provider}: PersonalBar response keys: {list(bar_data.keys())}"
            )
        else:
            # Response was the bar itself (no redirect needed)
            bar_data = redirect_data

        tiles = bar_data.get("primary", {}).get("tiles", [])
        logger.debug(
            f"{self._provider}: Personal bar tiles: "
            f"{[t.get('title') for t in tiles]}"
        )
        # Build a lookup so we can find the first matching tile by title
        # regardless of which subscription/locale variant the user has.
        tile_by_title = {t.get("title"): t for t in tiles}
        for candidate in VOD_STREAMING_TILE_TITLES:
            tile = tile_by_title.get(candidate)
            if tile:
                href = tile.get("onFocus", {}).get("screen", {}).get("href")
                if href:
                    logger.debug(
                        f"{self._provider}: Found VOD grid tile '{candidate}': {href}"
                    )
                    return href

        logger.warning(
            f"{self._provider}: No VOD tile found in personal bar "
            f"(tried: {VOD_STREAMING_TILE_TITLES}); "
            f"available: {list(tile_by_title.keys())}"
        )
        return None

    def _parse_theme_strings(self, data: Dict) -> None:
        """
        Extract portal-scoping metadata from a StructuredGrid ``theme.strings``
        block and store the values for later use in playback requests.

        Keys consumed:
            whiteLabel  → self._white_label_id  (e.g. "megathek")
                          Only overwritten when not already set from bootstrap so
                          that an explicit bootstrap value always wins.
            partnerMap  → self._partner_map_id  (e.g. "wl_megathek")
                          Always updated; this value is only available from the
                          server response and is not present in bootstrap.

        The ``portal`` string ("MagentaTV") is logged for diagnostics but not
        stored — it is display-only and not needed as a request parameter.
        """
        strings: List[Dict] = (data.get("theme") or {}).get("strings") or []
        theme: Dict[str, str] = {
            entry["key"]: entry["value"]
            for entry in strings
            if "key" in entry and "value" in entry
        }

        if not theme:
            return

        white_label = theme.get("whiteLabel")
        partner_map = theme.get("partnerMap")
        portal      = theme.get("portal")

        logger.debug(
            f"{self._provider}: StructuredGrid theme strings — "
            f"whiteLabel={white_label!r}, portal={portal!r}, partnerMap={partner_map!r}"
        )

        # Bootstrap value takes precedence for whiteLabelId (it may have been
        # set from the manifest before this response was available).
        if white_label and not self._white_label_id:
            self._white_label_id = white_label
            logger.debug(
                f"{self._provider}: white_label_id set from theme strings: "
                f"{self._white_label_id!r}"
            )

        if partner_map:
            self._partner_map_id = partner_map
            logger.debug(
                f"{self._provider}: partner_map_id set from theme strings: "
                f"{self._partner_map_id!r}"
            )

    # =========================================================================
    # Private helpers – StructuredGrid (home)
    # =========================================================================

    def _fetch_home_lanes(self, params: Dict) -> List[VodCategory]:
        """
        Fetch the VOD home StructuredGrid and return each browsable lane as a
        VodCategory. External-partner lanes (Disney+, RTL+, …) are skipped.
        """
        streaming_grid_url = self._get_streaming_grid_url()

        if streaming_grid_url:
            url = streaming_grid_url
            logger.debug(f"{self._provider}: Using discovered VOD home URL: {url}")
        else:
            url = f"{self._base_url()}/StructuredGrid/{VOD_FLEX_ID_HOME}"
            logger.warning(f"{self._provider}: Falling back to hardcoded VOD home URL: {url}")

        data = self._get(url, params)
        if not data:
            return []

        # Extract portal-scoping values from the theme strings block.
        # These are used in all subsequent vodproductinformation requests.
        self._parse_theme_strings(data)

        lanes = data.get("content", {}).get("lanes", [])
        categories: List[VodCategory] = []

        for lane in lanes:
            lane_type = lane.get("type", "")
            title = lane.get("title", "").strip()
            flex_id = lane.get("flexId", "")

            # Skip external partner lanes (e.g. action == "ChannelTuneOpenApp")
            show_all = lane.get("showAllUrl", {})
            action = show_all.get("action", "") if isinstance(show_all, dict) else ""
            if action == "ChannelTuneOpenApp":
                logger.debug(f"{self._provider}: Skipping external partner lane '{title}'")
                continue

            if lane_type != "UnstructuredGrid" or not flex_id or not title:
                continue

            # Build the content_id that will be used to fetch this lane later.
            # Priority for sourcing the URL (highest to lowest):
            #   1. showAllUrl.href        — canonical "show all" deep-link
            #   2. laneContentLink.href   — always present, always has ?whiteLabelId=...
            #   3. constructed from flex_id — last resort, no portal scoping params
            #
            # Whichever source we use, we extract everything after /UnstructuredGrid/
            # (including any query string such as ?whiteLabelId=megathek) so that
            # portal-scoping parameters are preserved through to the actual fetch.
            show_all_href = (lane.get("showAllUrl") or {}).get("href") or None
            lane_content_href = (lane.get("laneContentLink") or {}).get("href") or None

            logger.debug(
                f"{self._provider}: Lane '{title}' (flexId={flex_id}) "
                f"showAllUrl={show_all_href!r} laneContentLink={lane_content_href!r}"
            )

            # Strategy:
            #   1. showAllUrl with /UnstructuredGrid/ → extract tail (id + query)
            #   2. laneContentLink with /UnstructuredGrid/ → same
            #   3. Either URL with ?whiteLabelId → use flex_id + carry whiteLabelId
            #   4. Nothing → bare flex_id, no portal scoping
            from urllib.parse import urlparse, parse_qs, urlencode

            def _qs_from_href(href):
                """Return URL query string params as a dict (first value only)."""
                if not href:
                    return {}
                return {k: v[0] for k, v in parse_qs(urlparse(href).query).items()}

            if show_all_href and "/UnstructuredGrid/" in show_all_href:
                tail = show_all_href.rstrip("/").split("/UnstructuredGrid/", 1)[1]
                content_id = f"UnstructuredGrid/{tail}"
            elif lane_content_href and "/UnstructuredGrid/" in lane_content_href:
                tail = lane_content_href.rstrip("/").split("/UnstructuredGrid/", 1)[1]
                content_id = f"UnstructuredGrid/{tail}"
            else:
                # laneContentLink uses a different path shape (e.g. UnstructuredGridLane/)
                # but may still carry ?whiteLabelId — extract it and append to flex_id.
                qs_params = _qs_from_href(lane_content_href) or _qs_from_href(show_all_href)
                scoping = {k: v for k, v in qs_params.items()
                           if k in ("whiteLabelId",)}
                if scoping:
                    content_id = f"UnstructuredGrid/{flex_id}?{urlencode(scoping)}"
                else:
                    content_id = f"UnstructuredGrid/{flex_id}"

            logger.debug(
                f"{self._provider}: Lane '{title}' → content_id={content_id!r}"
            )

            categories.append(
                VodCategory(
                    name=title,
                    content_id=content_id,
                    provider=self._provider,
                    child_count=lane.get("totalCount"),
                    details_url=show_all_href,
                )
            )

        logger.debug(f"{self._provider}: Found {len(categories)} VOD home lanes")
        return categories

    # =========================================================================
    # Private helpers – UnstructuredGrid (lane items)
    # =========================================================================

    def _fetch_lane_items(
        self,
        flex_id: str,
        params: Dict,
        page_size: int = VOD_DEFAULT_PAGE_SIZE,
        offset: int = 0,
        extra_params: Optional[Dict] = None,
    ) -> List[Union[VodCategory, VodItem]]:
        """
        Fetch items from an UnstructuredGrid lane.  Movies → VodItem,
        series → VodCategory (seasons/episodes require further drill-down).

        Args:
            extra_params: Additional query parameters extracted from the
                          content_id (e.g. {'whiteLabelId': 'megathek'}).
                          These originate from the server-supplied laneContentLink
                          and must be forwarded verbatim so the correct portal
                          scope is applied.
        """
        url = f"{self._base_url()}/UnstructuredGrid/{flex_id}"
        paged_params = dict(params)
        if extra_params:
            paged_params.update(extra_params)
        paged_params["$size"] = str(page_size)
        paged_params["$offset"] = str(offset)

        data = self._get(url, paged_params)
        if not data:
            return []

        content = data.get("content", {})
        results: List[Union[VodCategory, VodItem]] = []
        for item in content.get("items", []):
            node = self._map_unstructured_item(item, paged_params)
            if node is not None:
                results.append(node)

        total = content.get("page", {}).get("total", len(results))
        logger.debug(
            f"{self._provider}: Lane {flex_id} – fetched {len(results)}/{total} items "
            f"(offset={offset})"
        )
        return results

    def _map_unstructured_item(
        self, item: Dict, params: Dict
    ) -> Optional[Union[VodCategory, VodItem]]:
        """
        Map a single UnstructuredGrid item dict to a VodCategory or VodItem.

        Series → VodCategory (no playback needed, user navigates deeper).
        Movies → delegate to _fetch_single_item so the full playback chain
                 (VodDetails → productInformationLink → VodPlayer → playbackUrls)
                 is resolved and the correct MPX mediaId is stored as content_id.
        """
        content_id: str = item.get("id", "")
        title: str = (item.get("title") or "").strip()
        vod_type: str = item.get("vodType", "")
        image_url: Optional[str] = (item.get("image") or {}).get("href")
        description: Optional[str] = item.get("description")
        seasons_available: Optional[int] = item.get("seasonsAvailable")

        if not content_id or not title:
            return None

        if vod_type == "Series":
            details_href = (item.get("details") or {}).get("href") or None
            series_content_id = (
                details_href.split("/v3/")[1].split("?")[0].split("/", 1)[1]
                if details_href and "/v3/" in details_href
                else content_id
            )
            return VodCategory(
                name=title,
                content_id=series_content_id,
                provider=self._provider,
                logo_url=image_url,
                description=description,
                child_count=seasons_available,
                details_url=details_href,
            )

        # Movie (or unknown leaf): resolve via _fetch_single_item so we get
        # the correct MPX mediaId as content_id and a ready manifest_script.
        items = self._fetch_single_item(content_id, params)
        if items:
            return items[0]

        # _fetch_single_item failed — return a minimal unresolved VodItem so
        # the lane listing still shows the title/artwork, even if playback
        # will fail later.
        logger.warning(
            f"{self._provider}: Could not resolve playback for movie "
            f"'{title}' ({content_id}); returning unresolved item."
        )
        year_raw = item.get("yearOfProduction")
        try:
            release_year: Optional[int] = int(str(year_raw).split("-")[0]) if year_raw else None
        except (ValueError, TypeError):
            release_year = None
        duration_raw = item.get("duration")
        return VodItem.create_movie(
            name=title,
            content_id=content_id,
            provider=self._provider,
            logo_url=image_url,
            description=description,
            release_year=release_year,
            genre=item.get("mainGenre"),
            genres=item.get("genres") or None,
            duration_seconds=int(duration_raw) * 60 if duration_raw else None,
            rating=item.get("childProtectionId"),
        )

    # =========================================================================
    # Private helpers – VodDetails (series → seasons)
    # =========================================================================

    def _fetch_series_seasons(self, content_id: str, params: Dict) -> List[VodCategory]:
        """
        Fetch seasons for a series.

        Flow:
          1. Fetch VodDetails for the series.
          2. Follow productInformationLink to get the partner/button list.
          3. Pick the best primary button that has a subAssetLane (prefer
             'videoload', otherwise first with a laneContentLink href).
          4. Fetch that subAssetLane laneContentLink → items where
             vodType == "Season" become VodCategory entries.

        Fallback (old behaviour):
          If productInformationLink is absent or yields nothing, fall back to
          Season-typed lanes in the VodDetails response itself.
        """
        data = self._get_vod_details(content_id, params)
        if not data:
            return []

        content = data.get("content", {})
        info = content.get("contentInformation", {})
        series_title: str = info.get("seriesTitle") or info.get("title") or ""

        # ------------------------------------------------------------------
        # Primary path: productInformationLink → subAssetLane
        # ------------------------------------------------------------------
        product_url: Optional[str] = (
            content.get("productInformationLink") or {}
        ).get("href")

        if product_url:
            seasons = self._fetch_seasons_via_product_info(
                product_url, series_title, params
            )
            if seasons:
                logger.debug(
                    f"{self._provider}: Series {content_id} → "
                    f"{len(seasons)} seasons (via subAssetLane)"
                )
                return seasons

        # ------------------------------------------------------------------
        # Fallback: Season lanes embedded in the VodDetails response
        # ------------------------------------------------------------------
        series_num = content_id.replace(VOD_PREFIX_SERIES, "")
        seasons = []
        for lane in content.get("lanes", []):
            if lane.get("type") != "Season":
                continue
            season_num = lane.get("seasonNumber")
            if season_num is None:
                continue
            season_title = lane.get("title") or f"Staffel {season_num}"
            season_id = f"{VOD_PREFIX_SEASON}{series_num}_DE_{season_num}"
            seasons.append(
                VodCategory(
                    name=season_title,
                    content_id=season_id,
                    provider=self._provider,
                    description=f"{series_title} – {season_title}",
                    child_count=lane.get("episodeCount") or lane.get("totalCount"),
                )
            )

        logger.debug(
            f"{self._provider}: Series {content_id} → "
            f"{len(seasons)} seasons (via VodDetails lanes)"
        )
        return seasons

    def _fetch_seasons_via_product_info(
        self,
        product_url: str,
        series_title: str,
        params: Dict,
    ) -> List[VodCategory]:
        """
        Fetch the productInformation endpoint and resolve seasons from the
        first usable subAssetLane.

        Partner preference order:
          1. 'videoload'  (native Magenta VOD, always present)
          2. First primary button that has a subAssetLane with a
             laneContentLink href (regardless of instantUsable).
        """
        prod_data = self._get(product_url, params)
        if not prod_data:
            return []

        primary_buttons = (prod_data.get("buttons") or {}).get("primary", [])

        # Build an ordered candidate list: videoload first, then others
        candidates = []
        for btn in primary_buttons:
            lane_list = btn.get("subAssetLane") or []
            for lane in lane_list:
                href = (lane.get("laneContentLink") or {}).get("href")
                if not href:
                    continue
                if btn.get("partnerId") == "videoload":
                    candidates.insert(0, href)
                else:
                    candidates.append(href)

        for lane_href in candidates:
            lane_data = self._get(lane_href, params)
            if not lane_data:
                continue
            seasons = []
            for item in (lane_data.get("content") or {}).get("items", []):
                if item.get("vodType") != "Season":
                    continue
                season_id = item.get("id", "")
                title = (item.get("title") or item.get("seasonTitle") or "").strip()
                if not season_id or not title:
                    continue
                details_href: Optional[str] = (
                    item.get("details") or {}
                ).get("href")
                # content_id: strip base URL and query string from details href
                # e.g. "https://.../VodDetails/202887/GN_SEASON_184925_DE_1?..."
                # → "VodDetails/202887/GN_SEASON_184925_DE_1"
                if details_href and "/v3/" in details_href:
                    content_id = (
                        details_href.split("/v3/")[1]
                        .split("?")[0]
                        .split("/", 1)[1]
                    )
                else:
                    content_id = season_id

                image_url: Optional[str] = (item.get("image") or {}).get("href")
                description: Optional[str] = (
                    item.get("description") or item.get("longDescription")
                )
                episode_count: Optional[int] = item.get("episodesProduced")

                seasons.append(
                    VodCategory(
                        name=title,
                        content_id=content_id,
                        provider=self._provider,
                        logo_url=image_url,
                        description=description or f"{series_title} – {title}",
                        child_count=episode_count,
                        details_url=details_href,
                    )
                )
            if seasons:
                return seasons

        return []

    # =========================================================================
    # Private helpers – VodDetails (season → episodes)
    # =========================================================================

    def _fetch_season_episodes(self, season_id: str, params: Dict) -> List[VodItem]:
        """
        Fetch episodes for a season.

        Flow:
          1. Fetch the season VodDetails page.
          2. Follow productInformationLink → pick a primary button with a
             subAssetLane (prefer videoload).
          3. Fetch that subAssetLane → items where vodType == "Episode".

        Fallback:
          If productInformationLink is absent or yields nothing, fall back to
          Episode-typed lanes embedded in the VodDetails response.
        """
        episode_params = dict(params)
        episode_params["autofocus"] = "videoload"

        data = self._get_vod_details(season_id, episode_params)
        if not data:
            return []

        content = data.get("content", {})
        season_number: Optional[int] = self._extract_season_number(season_id)

        # ------------------------------------------------------------------
        # Primary path: productInformationLink → subAssetLane
        # ------------------------------------------------------------------
        product_url: Optional[str] = (
            content.get("productInformationLink") or {}
        ).get("href")

        if product_url:
            episodes = self._fetch_episodes_via_product_info(
                product_url, season_number, params
            )
            if episodes:
                logger.debug(
                    f"{self._provider}: Season {season_id} → "
                    f"{len(episodes)} episodes (via subAssetLane)"
                )
                return episodes

        # ------------------------------------------------------------------
        # Fallback: Episode lanes embedded in the VodDetails response
        # ------------------------------------------------------------------
        episodes = []
        for lane in content.get("lanes", []):
            if lane.get("type") != "Episode":
                continue
            lane_url = (lane.get("laneContentLink") or {}).get("href")
            if not lane_url:
                continue
            lane_data = self._get(lane_url, params)
            if not lane_data:
                continue
            for ep in lane_data.get("content", {}).get("items", []):
                node = self._map_episode_item(ep, season_number)
                if node is not None:
                    episodes.append(node)

        logger.debug(
            f"{self._provider}: Season {season_id} → "
            f"{len(episodes)} episodes (via VodDetails lanes)"
        )
        return episodes

    def _fetch_episodes_via_product_info(
        self,
        product_url: str,
        season_number: Optional[int],
        params: Dict,
    ) -> List[VodItem]:
        """
        Resolve the episode list from the productInformation subAssetLane.

        Partner preference: videoload first, then any other with a
        laneContentLink href.
        """
        prod_data = self._get(product_url, params)
        if not prod_data:
            return []

        primary_buttons = (prod_data.get("buttons") or {}).get("primary", [])

        candidates = []
        for btn in primary_buttons:
            lane_list = btn.get("subAssetLane") or []
            for lane in lane_list:
                href = (lane.get("laneContentLink") or {}).get("href")
                if not href:
                    continue
                if btn.get("partnerId") == "videoload":
                    candidates.insert(0, href)
                else:
                    candidates.append(href)

        for lane_href in candidates:
            lane_data = self._get(lane_href, params)
            if not lane_data:
                continue
            episodes = []
            for ep in (lane_data.get("content") or {}).get("items", []):
                if ep.get("vodType") != "Episode":
                    continue
                node = self._map_episode_item(ep, season_number)
                if node is not None:
                    episodes.append(node)
            if episodes:
                return episodes

        return []

    def _map_episode_item(
        self,
        ep: Dict,
        season_number: Optional[int],
    ) -> Optional[VodItem]:
        """
        Map an episode item from a season lane content response to a VodItem.

        manifest_script is not set here — lane listings do not include
        productInformationLink.  The provider's get_manifest(content_id) must
        fetch VodDetails for the episode to obtain it.
        """
        content_id: str = ep.get("id", "")
        if not content_id:
            return None
        ep_num: Optional[int] = ep.get("episodeNumber")
        title: str = (ep.get("title") or f"Episode {ep_num}").strip()
        image_url: Optional[str] = (ep.get("image") or {}).get("href")
        # Lane listings rarely include a description for episodes; try both
        # fields so we surface whatever the API returns.
        description: Optional[str] = ep.get("description") or ep.get("longDescription")
        duration_raw = ep.get("duration")
        duration_seconds: Optional[int] = int(duration_raw) * 60 if duration_raw else None
        genre: Optional[str] = ep.get("mainGenre")
        genres: Optional[List[str]] = ep.get("genres") or None
        rating: Optional[str] = ep.get("childProtectionId")

        return VodItem.create_episode(
            name=title,
            content_id=content_id,
            provider=self._provider,
            season_number=season_number or 0,
            episode_number=ep_num or 0,
            logo_url=image_url,
            description=description,
            duration_seconds=duration_seconds,
            genre=genre,
            genres=genres,
            rating=rating,
        )

    def _fetch_single_episode(self, content_id: str, params: Dict) -> List[VodItem]:
        """
        Fetch a single episode by content_id.

        The VodDetails response for an episode has the metadata directly in
        contentInformation — there are no inline episode items in the lanes.
        The lanes only contain Person and recommendation (UnstructuredGrid)
        rows, neither of which are relevant here.
        """
        episode_params = dict(params)
        episode_params["autofocus"] = "videoload"
        data = self._get_vod_details(content_id, episode_params)
        if not data:
            return []

        content_block = data.get("content", {})
        info = content_block.get("contentInformation", {})
        ep_num: Optional[int] = info.get("episodeNumber")
        title: str = (info.get("title") or f"Episode {ep_num}").strip()
        if not title:
            return []

        duration_seconds: Optional[int] = (
            int(info["runtime"]) * 60 if info.get("runtime") else None
        )
        product_url: Optional[str] = (
            content_block.get("productInformationLink") or {}
        ).get("href")

        # Walk the full playback chain to resolve a real MPX mediaId, just
        # like _fetch_single_item() does for movies.  Without this step the
        # content_id stays as a GN_EP* Gracenote id which the manifest/DRM
        # layer cannot use.
        playback_href: Optional[str] = None
        playback_media_id: Optional[str] = None
        if product_url:
            playback_href, playback_media_id = self._resolve_movie_playback_href(
                product_url, self._playback_params()
            )

        if playback_media_id:
            effective_content_id = playback_media_id
            manifest_script = playback_href
            session_manifest = True
            logger.debug(
                f"{self._provider}: Episode {content_id} → "
                f"resolved mediaId={playback_media_id}"
            )
        else:
            # Fallback: keep GN id + productInformationLink so the existing
            # session-manifest path still has a chance to work.
            effective_content_id = content_id
            manifest_script = product_url
            session_manifest = product_url is not None
            if product_url:
                logger.warning(
                    f"{self._provider}: Could not resolve MPX mediaId for "
                    f"episode {content_id}; falling back to GN id"
                )

        return [VodItem.create_episode(
            name=title,
            content_id=effective_content_id,
            provider=self._provider,
            season_number=info.get("seasonNumber") or 0,
            episode_number=ep_num or 0,
            logo_url=(info.get("image") or {}).get("href"),
            description=info.get("description"),
            long_description=info.get("longDescription"),
            original_title=info.get("originalTitle"),
            genre=info.get("mainGenre"),
            genres=info.get("genres") or None,
            duration_seconds=duration_seconds,
            rating=info.get("childProtectionId"),
            series_id=info.get("seriesId"),
            series_title=info.get("seriesTitle"),
            manifest_script=manifest_script,
            session_manifest=session_manifest,
        )]

    def _pick_playback_media_id(self, playback_urls: List[Dict]) -> Optional[str]:
        """
        Select the best mediaId from a VodPlayer ``content.playbackUrls`` list.

        The quality is chosen by walking ``QUALITY_FALLBACK[self._preferred_quality]``
        in order and returning the first ``mediaId`` whose ``quality`` matches.
        If no entry in the fallback chain matches, the first entry in the list is
        returned as a last resort (mirrors legacy behaviour).

        Args:
            playback_urls: List of dicts, each with at least ``quality`` and
                           ``mediaId`` keys, as found in the VodPlayer response.

        Returns:
            The selected ``mediaId`` string, or ``None`` if the list is empty.
        """
        if not playback_urls:
            return None

        # Build a quality → mediaId lookup from the response.
        quality_map: Dict[str, str] = {
            entry["quality"]: entry["mediaId"]
            for entry in playback_urls
            if entry.get("quality") and entry.get("mediaId")
        }

        for q in QUALITY_FALLBACK.get(self._preferred_quality, ["HD", "SD"]):
            if q in quality_map:
                logger.debug(
                    f"{self._provider}: Selected quality '{q}' "
                    f"(preferred: '{self._preferred_quality}'), "
                    f"mediaId={quality_map[q]}"
                )
                return quality_map[q]

        # Absolute fallback: first entry in the list.
        fallback_id: str = playback_urls[0].get("mediaId", "")
        logger.warning(
            f"{self._provider}: No matching quality for '{self._preferred_quality}'; "
            f"falling back to first entry mediaId={fallback_id}"
        )
        return fallback_id or None

    def _fetch_single_item(self, content_id: str, params: Dict) -> List[VodItem]:
        """
        Fetch a movie (or unknown leaf) by content_id.

        Metadata comes directly from contentInformation.  The lanes in the
        real API response only contain Person and recommendation rows — there
        are no playable child items to recurse into.

        Playback ID resolution
        ----------------------
        The VodPlayer response (step 3 of the playback chain) exposes
        ``content.playbackUrls`` — a list of quality-tagged theplatform hrefs
        and their MPX ``mediaId`` values.  We resolve the best mediaId here
        (using ``_pick_playback_media_id``) so that the provider's
        ``get_manifest`` receives the correct MPX ID, not the raw GN content ID.

        The resolved theplatform href is stored as ``manifest_script`` so that
        the existing playback chain in the provider needs no changes.
        """
        data = self._get_vod_details(content_id, params)
        if not data:
            return []

        content_block = data.get("content", {})
        info = content_block.get("contentInformation", {})
        title: str = (info.get("title") or "").strip()
        if not title:
            return []

        duration_seconds: Optional[int] = (
            int(info["runtime"]) * 60 if info.get("runtime") else None
        )
        year_raw = info.get("yearFrom")
        try:
            release_year_item: Optional[int] = int(str(year_raw).split("-")[0]) if year_raw else None
        except (ValueError, TypeError):
            release_year_item = None

        # ------------------------------------------------------------------
        # Resolve the VodPlayer URL and pick the correct theplatform href.
        #
        # Flow:
        #   productInformationLink → buttons.primary[rel=="player",
        #                            instantUsable==true] → VodPlayer URL
        #   VodPlayer response     → content.playbackUrls  → pick by quality
        #
        # When resolved:
        #   content_id      = MPX mediaId (e.g. "QflsaCy6P3Sc")
        #   manifest_script = full theplatform href (stored for reference)
        #   session_manifest = True  → provider._get_smil_content(content_id)
        #                              builds the correct SMIL URL automatically
        #
        # When resolution fails, fall back to GN content_id + productInformationLink
        # so the existing session-manifest path still has a chance to work.
        # ------------------------------------------------------------------
        product_url: Optional[str] = (
            content_block.get("productInformationLink") or {}
        ).get("href")

        playback_href: Optional[str] = None
        playback_media_id: Optional[str] = None
        if product_url:
            playback_href, playback_media_id = self._resolve_movie_playback_href(
                product_url, params
            )

        if playback_media_id:
            # Happy path: use the MPX mediaId so _get_smil_content builds the
            # right URL: selector_service + account_pid + "/media/" + mediaId
            effective_content_id = playback_media_id
            manifest_script = playback_href      # theplatform href for reference
            session_manifest = True
            logger.debug(
                f"{self._provider}: Movie {content_id} → "
                f"resolved mediaId={playback_media_id}"
            )
        else:
            # Fallback: keep GN id + productInformationLink
            effective_content_id = content_id
            manifest_script = product_url
            session_manifest = product_url is not None
            logger.warning(
                f"{self._provider}: Could not resolve MPX mediaId for {content_id}; "
                f"falling back to GN id + productInformationLink"
            )

        return [VodItem.create_movie(
            name=title,
            content_id=effective_content_id,
            provider=self._provider,
            logo_url=(info.get("image") or {}).get("href"),
            description=info.get("description"),
            long_description=info.get("longDescription"),
            original_title=info.get("originalTitle"),
            release_year=release_year_item,
            genre=info.get("mainGenre"),
            genres=info.get("genres") or None,
            duration_seconds=duration_seconds,
            rating=info.get("childProtectionId"),
            manifest_script=manifest_script,
            session_manifest=session_manifest,
        )]

    def _normalise_product_url(self, url: str) -> str:
        """
        Rewrite a productInformationLink URL to use the correct client model
        so that the response contains proper player buttons.

        The path segment (e.g. /ftv-androidtv/) is replaced with our actual
        client model.  The partnerMapId query parameter is intentionally left
        untouched — the server sets it to a portal-specific value such as
        "wl_megathek" that must be preserved for the correct button set to be
        returned.  Overwriting it with our client model would corrupt the
        partner scope and yield empty or wrong primary buttons.
        """
        from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

        for other in ("ftv-androidtv", "ftv-android", "ftv-ios", "ftv-web"):
            if other != self._client_model:
                url = url.replace(f"/{other}/", f"/{self._client_model}/")

        # Re-encode the query string without touching any of its values —
        # in particular partnerMapId, appMapId, channelMapId stay as-is.
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        new_query = urlencode({k: v[0] for k, v in qs.items()})
        return urlunparse(parsed._replace(query=new_query))

    def _playback_params(self) -> Dict:
        """Query parameters for vodproductinformation / VodPlayer requests.

        Session correlation follows the same platform convention as _base_params:
          - Android TV: ``$cid`` = ``<sessionId>::<callUUID>``  (no sid / t)
          - Web / other: ``sid`` + ``t``                        (no $cid)
        """
        params: Dict[str, str] = {
            "$deviceModel": self._device_model,
            "$profile": self._profile_name,
            "$subscriberType": self._subscriber_type,
            "$theme": self._theme_id,
            "$redirect": "false",
        }
        if self._is_androidtv():
            call_id = str(_uuid_mod.uuid4())
            params["$cid"] = f"{self._session_id}::{call_id}"
        else:
            params["sid"] = self._session_id
            params["t"] = str(int(time.time() * 1000))
        if self._white_label_id:
            params["whiteLabelId"] = self._white_label_id
        if self._partner_map_id:
            params["partnerMapId"] = self._partner_map_id
        return params

    def _resolve_movie_playback_href(
        self,
        product_url: str,
        params: Dict,
    ) -> tuple:
        """
        Walk the playback chain for a movie and return ``(href, media_id)``.

        Steps:
          1. Fetch productInformationLink.
          2. Pick buttons.primary[] where rel=="player" AND instantUsable==true.
          3. Fetch the VodPlayer URL ($redirect=false + sid already in params).
          4. Extract content.playbackUrls, pick by quality preference.

        Returns:
            (theplatform_href, media_id) on success, or (None, None) on any failure.
        """
        # Normalise URL to ftv-web so we get proper player buttons, and use
        # web-flavoured params (deviceModel, subscriberType) to match.
        web_url = self._normalise_product_url(product_url)
        web_params = self._playback_params()
        if web_url != product_url:
            logger.debug(
                f"{self._provider}: Normalised productInformation URL: {web_url}"
            )

        prod_data = self._get_auth(web_url, web_params)
        if not prod_data:
            return None, None

        # Log all primary buttons so we can diagnose auth / partner issues.
        primary_buttons = (prod_data.get("buttons") or {}).get("primary", [])
        logger.debug(
            f"{self._provider}: productInformation primary buttons: "
            + str([
                {
                    "rel": b.get("rel"),
                    "partnerId": b.get("partnerId"),
                    "instantUsable": b.get("instantUsable"),
                    "href_tail": (b.get("href") or "")[-60:],
                }
                for b in primary_buttons
            ])
        )

        vod_player_url: Optional[str] = None
        for btn in primary_buttons:
            if btn.get("rel") != "player":
                continue
            if not btn.get("instantUsable", False):
                continue
            href = btn.get("href")
            if href:
                vod_player_url = href
                break

        if not vod_player_url:
            logger.warning(
                f"{self._provider}: No instantUsable player button found "
                f"in productInformation for {product_url}. "
                f"Buttons present: {[b.get('rel') for b in primary_buttons]}"
            )
            return None, None

        vod_player_data = self._get_auth(vod_player_url, web_params)
        if not vod_player_data:
            return None, None

        playback_urls: List[Dict] = (
            (vod_player_data.get("content") or {}).get("playbackUrls") or []
        )
        media_id = self._pick_playback_media_id(playback_urls)
        if not media_id:
            return None, None

        for entry in playback_urls:
            if entry.get("mediaId") == media_id:
                href = entry.get("href")
                logger.debug(
                    f"{self._provider}: Resolved movie playback href "
                    f"(quality={entry.get('quality')}, mediaId={media_id}): {href}"
                )
                return href, media_id

        return None, None

    # =========================================================================
    # Utilities
    # =========================================================================

    @staticmethod
    def _extract_season_number(season_id: str) -> Optional[int]:
        """
        Parse the season number from a season content_id.

        e.g. "GN_SEASON_184925_DE_3" → 3
        """
        try:
            return int(season_id.rsplit("_DE_", 1)[-1])
        except (ValueError, IndexError):
            return None