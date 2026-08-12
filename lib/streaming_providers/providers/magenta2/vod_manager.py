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
          → href = trailer URL  (populates VodItem.trailer_url)

Pricing
-------
    VodDetails.content.contentInformation carries pricing in one of two shapes:
      1. Direct fields: buyPrice, rentPrice on contentInformation itself.
      2. partners[] array: each partner may carry its own buyPrice/rentPrice
         plus a validity window (partnerValidFrom/partnerValidTo).

    A single partner commonly exposes BOTH buyPrice and rentPrice at once
    (this is the normal case, not an edge case, e.g. the "videoload" partner).
    Both are captured as parallel PricePoint entries on one Pricing object,
    disambiguated via PricePoint.offer_type -- see base/models/pricing.py.

    Pricing.access_type is treated as the "default CTA": TVOD_RENTAL when a
    rental offer exists, TVOD_PURCHASE otherwise. Callers that need the other
    offer explicitly should use Pricing.primary_rental_price /
    Pricing.primary_purchase_price rather than relying on access_type alone.

tvhubs base URL resolution order
---------------------------------
1. Manifest tv_hubs.base_urls  (via ProviderConfig.get_tvhubs_base_url)
2. TVHUBS_BASE_URL constant    (fallback)

Public interface
-----------------
    vod_manager.get_children(content_id, *, cursor, page_size, **kwargs)
        -> Dict with keys: entries, next_cursor, total
"""

import time
import uuid as _uuid_mod
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union
from ...base.utils.logger import logger

from ...base.models.vod import VodCategory, VodItem
from ...base.models.pricing import AccessType, PricePoint, Pricing
from ...base.models.quality import Quality

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
)


# =============================================================================
# Pricing helpers (module-level, no instance state required)
# =============================================================================

# The API exposes "UHDHDR" as a distinct video-quality tier but the shared
# Quality enum has no HDR variant -- collapse it into UHD. Revisit if HDR
# badging is ever needed on price points.
_QUALITY_MAP: Dict[str, Quality] = {
    "UHDHDR": Quality.UHD,
    "UHD": Quality.UHD,
    "HD": Quality.HD,
    "SD": Quality.SD,
}

# Not present anywhere in the VodDetails response -- this is an unconfirmed
# guess. Replace with a real value if/when the API or app is found to expose
# the actual rental window.
_DEFAULT_RENTAL_HOURS = 48


def _map_quality(api_quality: Optional[str]) -> Optional[Quality]:
    """Map a raw API videoQualities string to the shared Quality enum."""
    if not api_quality:
        return None
    return _QUALITY_MAP.get(api_quality.upper())


def _parse_iso(dt_str: Optional[str]) -> Optional[datetime]:
    """Parse an ISO-8601 datetime string (e.g. partnerValidFrom/To), or None."""
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str)
    except (ValueError, TypeError):
        logger.debug(f"Could not parse ISO datetime: {dt_str!r}")
        return None


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

        # Node registry: opaque content_id → (fetch_url, extra_params)
        # Populated when lanes/series/seasons are discovered so that
        # get_children can look up the full fetch context without any
        # URL reconstruction or query-string manipulation.
        # Lives on the provider instance (long-lived) so it survives
        # across individual request-scoped calls.
        self._node_registry: Dict[str, Dict] = {}

        # Short-lived in-memory cache for VodDetails responses (content_id → data).
        # Prevents redundant network round-trips when the same content_id is
        # looked up multiple times within a single get_children() call chain.
        self._vod_details_cache: Dict[str, Any] = {}

    # =========================================================================
    # Public API
    # =========================================================================

    def _register_node(
            self,
            content_id: str,
            fetch_url: str,
            extra_params: Optional[Dict] = None,
    ) -> str:
        """
        Register a node in the registry and return its content_id.

        Args:
            content_id:   Opaque identifier (e.g. "lane:322341").
            fetch_url:    Full URL to use when fetching children.
            extra_params: Additional query params to merge (e.g. whiteLabelId).
        """
        self._node_registry[content_id] = {
            "fetch_url": fetch_url,
            "extra_params": extra_params or {},
        }
        return content_id

    def get_children(
            self,
            content_id: str,
            *,
            cursor: Optional[str] = None,
            page_size: int = VOD_DEFAULT_PAGE_SIZE,
            offset: int = 0,
    ) -> Dict:
        """
        Return the children of a VOD node identified by *content_id*.

        content_id is always a single opaque token — never split on "/" by
        the caller.  Dispatch is by prefix:

            ""              → VOD home (top-level lanes)
            "lane:<id>"     → UnstructuredGrid lane (via registry)
            "series:<id>"   → GN_SERIES_… seasons
            "season:<id>"   → GN_SEASON_… episodes
            "episode:<id>"  → single episode detail
            "movie:<id>"    → single movie detail
            legacy GN_*     → backwards-compat fallback

        Args:
            content_id: Opaque node identifier.
            cursor:     Opaque continuation token returned in a previous
                        response's next_cursor field.  For lane/UnstructuredGrid
                        nodes, VodManager encodes the next $offset as a plain
                        integer string (e.g. "24", "48").  None → first page.
                        For non-paginated nodes (home, series, seasons) the
                        cursor is ignored and next_cursor is always None.
            page_size:  Items per page for lane fetches.
            offset:     Direct offset override for internal callers that bypass
                        the cursor mechanism (e.g. _resolve_gn_id_to_media_id).
                        Ignored when cursor is supplied.

        Returns:
            {
                "entries":     List[VodCategory | VodItem],
                "next_cursor": Optional[str],   # None when no further pages exist
                "total":       Optional[int],   # total item count if known by API
            }
        """
        logger.debug(
            f"{self._provider}: get_children content_id={content_id!r} "
            f"cursor={cursor!r} page_size={page_size}"
        )

        # Decode cursor → offset.  cursor takes precedence over the legacy
        # offset kwarg so that route-layer callers always use cursor.
        if cursor is not None:
            try:
                offset = int(cursor)
            except (ValueError, TypeError):
                logger.warning(
                    f"{self._provider}: Invalid cursor value {cursor!r}, "
                    "ignoring and starting from offset 0"
                )
                offset = 0

        params = self._base_params()

        if not content_id:
            # Home lanes are not paginated — always return first page wrapped
            # in the standard dict so callers never need to branch on type.
            lanes = self._fetch_home_lanes(params)
            return {"entries": lanes, "next_cursor": None, "total": None}

        # ── Lane (UnstructuredGrid) ──────────────────────────────────────
        if content_id.startswith("lane:"):
            node = self._node_registry.get(content_id)
            if node:
                return self._fetch_lane_items(
                    content_id, params,
                    page_size=page_size, offset=offset,
                    fetch_url=node["fetch_url"],
                    extra_params=node["extra_params"],
                )
            # Fallback: extract bare id and construct URL
            bare = content_id[len("lane:"):]
            return self._fetch_lane_items(
                content_id, params,
                page_size=page_size, offset=offset,
                fetch_url=f"{self._base_url()}/UnstructuredGrid/{bare}",
            )

        # ── Series ──────────────────────────────────────────────────────
        if content_id.startswith("series:"):
            gn_id = content_id[len("series:"):]
            return self._fetch_series_seasons(gn_id, params, offset=offset, page_size=page_size)

        # ── Season ──────────────────────────────────────────────────────
        if content_id.startswith("season:"):
            gn_id = content_id[len("season:"):]
            return self._fetch_season_episodes(gn_id, params, offset=offset, page_size=page_size)

        # ── Episode / Movie ─────────────────────────────────────────────
        if content_id.startswith("episode:"):
            gn_id = content_id[len("episode:"):]
            items = self._fetch_single_episode(gn_id, params)
            return {"entries": items, "next_cursor": None, "total": None}

        if content_id.startswith("movie:"):
            gn_id = content_id[len("movie:"):]
            items = self._fetch_single_item(gn_id, params)
            return {"entries": items, "next_cursor": None, "total": None}

        # ── Legacy / backwards-compat ───────────────────────────────────
        # Support old-style content_ids (GN_SERIES_*, GN_SEASON_*, etc.)
        # and path-style IDs (UnstructuredGrid/*, VodDetails/*) so that
        # existing cached references keep working during transition.
        node_id = content_id
        if node_id.startswith("UnstructuredGrid/"):
            bare = node_id[len("UnstructuredGrid/"):].split("?")[0]
            return self._fetch_lane_items(
                f"lane:{bare}", params,
                page_size=page_size, offset=offset,
                fetch_url=f"{self._base_url()}/UnstructuredGrid/{bare}",
            )
        if node_id.startswith("VodDetails/"):
            node_id = node_id.split("/")[-1]
        if node_id.startswith(VOD_PREFIX_SEASON):
            return self._fetch_season_episodes(node_id, params, offset=offset, page_size=page_size)
        if node_id.startswith(VOD_PREFIX_SERIES):
            return self._fetch_series_seasons(node_id, params, offset=offset, page_size=page_size)
        if node_id.startswith(VOD_PREFIX_EPISODE):
            items = self._fetch_single_episode(node_id, params)
            return {"entries": items, "next_cursor": None, "total": None}
        items = self._fetch_single_item(node_id, params)
        return {"entries": items, "next_cursor": None, "total": None}

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

        Note: $subscriberType is intentionally omitted — the real Android TV
        device does NOT send it on tvhubs calls (StructuredGrid, VodDetails,
        PersonalBar, UnstructuredGrid etc.).  It is only sent on wcps calls
        (vodproductinformation, VodPlayer) via _playback_params().

        Session correlation follows the platform convention:
          - Android TV: ``$cid`` = ``<sessionId>::<callUUID>``  (no sid / t)
          - Web / other: ``sid`` + ``t``                        (no $cid)
        """
        params: Dict[str, str] = {
            "$deviceModel": self._device_model,
            "$profile": self._profile_name,
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

        Auth + device-identity headers are injected by auth_headers_callback
        (Bearer, x-mpx-authorization, x-stbserialnumber, dt-session-id,
        dt-call-id) — all tvhubs and wcps VOD endpoints require them.
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
        """Alias for _get — auth is always injected when callback is set."""
        return self._get(url, params)

    def _get_no_auth(self, url: str, params: Dict) -> Optional[Dict]:
        """
        Perform a GET request *without* any auth or device-identity headers.

        Used for unauthenticated endpoints where attaching headers causes the
        server to return a different or empty response.
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
        Perform an authenticated GET with explicit serial/session headers.

        Used by PersonalBar discovery which needs to supply its own
        dt-call-id and dt-session-id values per the discovery sequence.
        For all other calls, use _get() which injects these automatically.
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

    def _fetch_personal_bar(self) -> Optional[Dict]:
        """
        Fetch the personal bar data (single two-hop fetch).

        Returns the parsed PersonalBar JSON response, or None on failure.
        This method encapsulates the common discovery logic used by
        _discover_vod_tile_urls() and can be reused for other tile types.
        """
        import uuid as _uuid
        from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, quote

        if not self._home_url:
            logger.debug(f"{self._provider}: No homeUrl available; cannot fetch personal bar")
            return None

        # Substitute the platform's actual client model into the home_url template
        resolved_home_url = self._home_url.replace("{clientModel}", self._client_model)

        dt_session_id = self._session_id
        dt_call_id_1 = str(_uuid.uuid4())
        cid = f"{dt_session_id}::{dt_call_id_1}"
        serial_number = self._serial_number

        discovery_params = {
            "$previewAutoMode": "false",
            "$deviceModel": self._device_model,
            "$cid": cid,
            "$redirect": "false",
            "$theme": self._theme_id,
            "$profile": self._profile_name,
        }

        logger.debug(f"{self._provider}: DocumentGroupRedirect URL: {resolved_home_url}")

        # First hop: DocumentGroupRedirect
        redirect_data = self._get_with_serial(
            resolved_home_url, discovery_params, serial_number,
            dt_session_id=dt_session_id, dt_call_id=dt_call_id_1,
        )
        if not redirect_data:
            logger.error(f"{self._provider}: Failed to fetch DocumentGroupRedirect")
            return None

        # Follow API-level redirect
        if redirect_data.get("$type") != "redirect":
            logger.warning(
                f"{self._provider}: DocumentGroupRedirect response has unexpected $type: "
                f"{redirect_data.get('$type')!r}"
            )
            return None

        redirect_url = redirect_data.get("redirectUrl")
        if not redirect_url:
            logger.error(f"{self._provider}: Redirect response missing redirectUrl")
            return None

        # Inject $cid with fresh call ID
        dt_call_id_2 = str(_uuid.uuid4())
        cid_2 = f"{dt_session_id}::{dt_call_id_2}"
        parsed = urlparse(redirect_url)
        qs = parse_qs(parsed.query, keep_blank_values=True)
        qs["$cid"] = [cid_2]
        redirect_url_with_cid = str(urlunparse(
            parsed._replace(
                query=urlencode(
                    {k: v[0] for k, v in qs.items()},
                    quote_via=quote,
                    safe="$:",
                )
            )
        ))

        logger.debug(f"{self._provider}: Following personal-bar redirect: {redirect_url_with_cid}")

        # Second hop: PersonalBar
        bar_data = self._get_with_serial(
            redirect_url_with_cid, {}, serial_number,
            dt_session_id=dt_session_id, dt_call_id=dt_call_id_2,
        )
        if not bar_data:
            logger.error(f"{self._provider}: Failed to fetch PersonalBar from redirectUrl")
            return None

        logger.debug(f"{self._provider}: PersonalBar response received")
        return bar_data

    def _discover_vod_tile_urls(self) -> Dict[str, Optional[str]]:
        """
        Fetch the personal bar once and return ALL discovered VOD tile URLs.

        Returns a dict mapping tile title -> URL for all tiles that:
        - Point to a StructuredGrid (VOD content hub)
        - Are not external apps (onClick.href != "app")
        """
        bar_data = self._fetch_personal_bar()
        if not bar_data:
            return {}

        # Collect all tiles (primary + secondary)
        primary_tiles = bar_data.get("primary", {}).get("tiles", [])
        secondary_tiles = bar_data.get("secondary", {}).get("tiles", [])
        all_tiles = primary_tiles + secondary_tiles

        vod_tiles = {}

        for tile in all_tiles:
            title = tile.get("title", "")
            if not title:
                continue

            # Skip external app tiles
            onClick = tile.get("onClick", {})
            if onClick.get("href") == "app":
                logger.debug(f"{self._provider}: Skipping external app tile '{title}'")
                continue

            # Get the screen href
            screen = tile.get("onFocus", {}).get("screen", {})
            href = screen.get("href", "")

            # Only include tiles that point to DocumentGroupRedirect (which leads to StructuredGrid)
            # or directly to StructuredGrid
            if href and ("DocumentGroupRedirect" in href or "StructuredGrid" in href):
                vod_tiles[title] = href
                logger.debug(f"{self._provider}: Found VOD tile '{title}': {href}")
            else:
                logger.debug(f"{self._provider}: Skipping non-VOD tile '{title}' (href: {href})")

        return vod_tiles

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
        portal = theme.get("portal")

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
        Fetch VOD lanes from ALL discovered personal bar tiles.

        Returns a flat list of unique lanes from all VOD-capable tiles,
        deduplicated by flex_id.
        """
        tile_urls = self._discover_vod_tile_urls()

        if not tile_urls:
            fallback_url = f"{self._base_url()}/StructuredGrid/{VOD_FLEX_ID_HOME}"
            logger.warning(f"{self._provider}: No VOD tiles discovered, using fallback: {fallback_url}")
            tile_urls = {"VOD": fallback_url}

        categories: List[VodCategory] = []
        seen_flex_ids: set = set()
        theme_parsed = False

        for title, url in tile_urls.items():
            # Fetch the StructuredGrid (follow redirect if needed)
            data = self._get(url, params)
            if not data:
                logger.warning(f"{self._provider}: Failed to fetch StructuredGrid for '{title}' from {url}")
                continue

            # Handle redirect if necessary
            if data.get("$type") == "redirect":
                redirect_url = data.get("redirectUrl")
                if redirect_url:
                    data = self._get(redirect_url, params)

            if not data or data.get("$type") != "structuredgrid":
                continue

            # Parse theme strings only once
            if not theme_parsed:
                self._parse_theme_strings(data)
                theme_parsed = True

            # Extract lanes
            lanes = data.get("content", {}).get("lanes", [])
            logger.debug(f"{self._provider}: Processing {len(lanes)} lanes from tile '{title}'")

            for lane in lanes:
                lane_type = lane.get("type", "")
                lane_title = lane.get("title", "").strip()
                flex_id = lane.get("flexId", "")

                # Skip external partner lanes (e.g. action == "ChannelTuneOpenApp")
                show_all = lane.get("showAllUrl", {})
                action = show_all.get("action", "") if isinstance(show_all, dict) else ""
                if action == "ChannelTuneOpenApp":
                    logger.debug(f"{self._provider}: Skipping external partner lane '{lane_title}'")
                    continue

                # Skip non-VOD lane types (Special, ContinueWatching, etc.)
                # StageLane is a special case - it's an UnstructuredGrid that displays
                # as a hero/stage carousel, but still contains VOD content.
                if lane_type not in ("UnstructuredGrid", "StageLane"):
                    logger.debug(
                        f"{self._provider}: Skipping non-VOD lane type '{lane_type}': '{lane_title}'"
                    )
                    continue

                if not flex_id or not lane_title:
                    continue

                # Deduplicate by flex_id (same lane may appear in both grids)
                if flex_id in seen_flex_ids:
                    logger.debug(f"{self._provider}: Skipping duplicate lane '{lane_title}' (flex_id={flex_id})")
                    continue
                seen_flex_ids.add(flex_id)

                show_all_href = (lane.get("showAllUrl") or {}).get("href") or None
                lane_content_href = (lane.get("laneContentLink") or {}).get("href") or None

                # Best fetch URL: showAllUrl is the paginated full grid (preferred);
                # laneContentLink is the inline preview but always carries portal params.
                best_fetch_url = show_all_href or lane_content_href or None

                # Opaque content_id: "lane:<numeric_flex_id>" — router-safe, no slashes.
                # The full fetch context lives in the registry, not in the ID.
                opaque_id = f"lane:{flex_id}"
                if best_fetch_url:
                    self._register_node(opaque_id, best_fetch_url)

                logger.debug(
                    f"{self._provider}: Lane '{lane_title}' → content_id={opaque_id!r} "
                    f"fetch_url={best_fetch_url!r}"
                )

                categories.append(
                    VodCategory(
                        name=lane_title,
                        content_id=opaque_id,
                        provider=self._provider,
                        child_count=lane.get("totalCount"),
                        details_url=show_all_href,
                        fetch_url=best_fetch_url,
                    )
                )

        logger.info(
            f"{self._provider}: VOD root initialized with {len(categories)} lanes "
            f"(from {len(tile_urls)} tile(s))"
        )
        return categories

    # =========================================================================
    # Private helpers – UnstructuredGrid (lane items)
    # =========================================================================

    def _fetch_lane_items(
            self,
            content_id: str,
            params: Dict,
            page_size: int = VOD_DEFAULT_PAGE_SIZE,
            offset: int = 0,
            fetch_url: Optional[str] = None,
            extra_params: Optional[Dict] = None,
    ) -> Dict:
        """
        Fetch items from an UnstructuredGrid lane.

        Args:
            content_id:   Opaque lane identifier (e.g. "lane:322341").
            fetch_url:    Full URL from the registry, including portal-scoping
                          query params.  The URL's own query string is split out
                          and merged into paged_params so all params travel
                          together in one clean dict.
            extra_params: Additional params from the registry (merged after
                          fetch_url params so they take precedence).

        Returns:
            {
                "entries":     List[VodCategory | VodItem],
                "next_cursor": Optional[str],   # str(next_offset) or None
                "total":       Optional[int],   # total item count if returned by API
            }
        """
        from urllib.parse import urlparse, parse_qs, urlunparse

        if fetch_url:
            parsed = urlparse(fetch_url)
            url = urlunparse(parsed._replace(query=""))
            url_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        else:
            # Should not happen when registry is populated, but safe fallback.
            bare = content_id.split(":")[-1] if ":" in content_id else content_id
            url = f"{self._base_url()}/UnstructuredGrid/{bare}"
            url_params = {}

        paged_params = dict(params)
        if url_params:
            paged_params.update(url_params)
        if extra_params:
            paged_params.update(extra_params)
        paged_params["$size"] = str(page_size)
        paged_params["$offset"] = str(offset)

        logger.debug(
            f"{self._provider}: _fetch_lane_items {content_id!r} url={url!r} "
            f"url_params={url_params!r}"
        )
        data = self._get(url, paged_params)
        if not data:
            return {"entries": [], "next_cursor": None, "total": None}

        content = data.get("content", {})
        results: List[Union[VodCategory, VodItem]] = []
        for item in content.get("items", []):
            node = self._map_unstructured_item(item, paged_params)
            if node is not None:
                results.append(node)

        page_info = content.get("page", {})
        total: Optional[int] = page_info.get("total")

        # Compute next_cursor.  Use the API-reported total when available so
        # we never request a page beyond the end.  Fall back to the heuristic
        # that a full page means there are probably more items.
        next_offset = offset + len(results)
        if total is not None:
            next_cursor: Optional[str] = str(next_offset) if next_offset < total else None
        else:
            # No total from API: assume there are more pages if we received a
            # full page; stop if we received fewer items than requested.
            next_cursor = str(next_offset) if len(results) >= page_size else None

        logger.debug(
            f"{self._provider}: Lane {content_id} – fetched {len(results)}"
            + (f"/{total}" if total is not None else "")
            + f" items (offset={offset})"
            + (f" → next_cursor={next_cursor!r}" if next_cursor else " → end of lane")
        )
        return {"entries": results, "next_cursor": next_cursor, "total": total}

    def _map_unstructured_item(
            self, item: Dict, params: Dict
    ) -> Optional[Union[VodCategory, VodItem]]:
        """
        Map a single UnstructuredGrid item dict to a VodCategory or VodItem.

        Series → VodCategory (no playback needed, user navigates deeper).
        Movies → delegate to _fetch_single_item so the full playback chain
                 (VodDetails → productInformationLink → VodPlayer → playbackUrls)
                 is resolved and the correct MPX mediaId is stored as content_id.

        Note: pricing is intentionally NOT resolved here. Lane browsing can
        return dozens of items per page; fetching VodDetails per item just to
        populate pricing would multiply request volume for data the user may
        never look at. Pricing is resolved lazily in _fetch_single_item /
        _fetch_single_episode, i.e. when the user actually opens the detail
        view or triggers playback.
        """
        content_id: str = item.get("id", "")
        title: str = (item.get("title") or "").strip()
        vod_type: str = item.get("vodType", "")
        item_type: str = item.get("type", "")
        image_url: Optional[str] = (item.get("image") or {}).get("href")
        description: Optional[str] = item.get("description")
        seasons_available: Optional[int] = item.get("seasonsAvailable")

        if not content_id or not title:
            return None

        # Season items from UnstructuredGrid (e.g. "WIEDERHOLUNGEN" lane)
        if vod_type == "Season" or (vod_type == "Asset" and item_type == "Season"):
            details_href = (item.get("details") or {}).get("href") or None
            # content_id is already the GN_SEASON_* id from the lane
            opaque_season_id = f"season:{content_id}"
            if details_href:
                self._register_node(opaque_season_id, details_href)
            return VodCategory(
                name=title,
                content_id=opaque_season_id,
                provider=self._provider,
                logo_url=image_url,
                description=description,
            )

        if vod_type == "Series":
            details_href = (item.get("details") or {}).get("href") or None
            # Use opaque "series:<GN_SERIES_id>" — no slashes, router-safe.
            gn_series_id = content_id  # content_id from the lane item IS the GN id
            opaque_series_id = f"series:{gn_series_id}"
            if details_href:
                self._register_node(opaque_series_id, details_href)
            return VodCategory(
                name=title,
                content_id=opaque_series_id,
                provider=self._provider,
                logo_url=image_url,
                description=description,
                child_count=seasons_available,
                details_url=details_href,
                fetch_url=details_href,
            )

        # Movie (or unknown leaf): store opaque "movie:GN_MV..." id.
        # Playback resolution (VodDetails → productInformation → VodPlayer)
        # is deferred to get_manifest() / get_drm() — only triggered when the
        # user actually hits play, not during lane browsing.
        year_raw = item.get("yearOfProduction")
        try:
            release_year: Optional[int] = int(str(year_raw).split("-")[0]) if year_raw else None
        except (ValueError, TypeError):
            release_year = None
        duration_raw = item.get("duration")
        return VodItem.create_movie(
            name=title,
            content_id=f"movie:{content_id}",
            provider=self._provider,
            logo_url=image_url,
            description=description,
            release_year=release_year,
            genre=item.get("mainGenre"),
            genres=item.get("genres") or None,
            duration_seconds=int(duration_raw) * 60 if duration_raw else None,
            rating=item.get("childProtectionId"),
            # No pricing here — resolved lazily, see docstring above.
        )

    # =========================================================================
    # Private helpers – Pricing
    # =========================================================================

    def _parse_pricing_from_vod_details(self, data: Dict) -> Optional[Pricing]:
        """
        Extract pricing information from a VodDetails response.

        Pricing can appear in two shapes:
          1. Direct fields on contentInformation: buyPrice, rentPrice.
          2. A partners[] array, each partner carrying its own buyPrice/
             rentPrice and a validity window (partnerValidFrom/To).

        Both buy and rent can be present simultaneously on the same partner
        (this is the common case, not an edge case — see the "videoload"
        partner in the sample VodDetails response). Both are kept as
        parallel PricePoints on one Pricing object, distinguished by
        PricePoint.offer_type.

        Returns:
            Pricing object, or None if no pricing data is available.
        """
        content_info = data.get("content", {}).get("contentInformation", {})
        if not content_info:
            return None

        # Check for direct pricing fields first.
        buy_price = content_info.get("buyPrice")
        rent_price = content_info.get("rentPrice")
        if buy_price is not None or rent_price is not None:
            return self._create_pricing_from_direct_fields(
                buy_price=buy_price,
                rent_price=rent_price,
                currency="EUR",  # Not present in response; assumed from provider locale.
            )

        # Otherwise, check the partners array.
        partners = content_info.get("partners", [])
        if not partners:
            return None

        # Prefer "videoload" (native Magenta VOD partner) as the pricing source.
        for partner in partners:
            if partner.get("partnerId") == "videoload":
                pricing = self._create_pricing_from_partner(partner)
                if pricing:
                    return pricing

        # Fall back to the first partner that actually carries a price.
        # Partners such as Disney+ in the sample response have no buy/rentPrice
        # at all (SVOD-only access) and are naturally skipped here.
        for partner in partners:
            if partner.get("buyPrice") is not None or partner.get("rentPrice") is not None:
                pricing = self._create_pricing_from_partner(partner)
                if pricing:
                    return pricing

        return None

    def _create_pricing_from_partner(self, partner: Dict) -> Optional[Pricing]:
        """
        Create a Pricing object from a partners[] entry in the VodDetails response.

        Partner shape (see sample VodDetails response):
        {
            "partnerId": "videoload",
            "buyPrice": 13.99,
            "rentPrice": 4.99,
            "videoQualities": ["UHDHDR", "UHD", "HD", "SD"],
            "partnerValidFrom": "2026-06-30T00:01:00+02:00",
            "partnerValidTo": "2099-12-31T23:59:00+01:00",
            ...
        }

        The price itself is not quality-differentiated — one buyPrice/rentPrice
        covers every quality listed in videoQualities — so PricePoint.quality is
        left unset here rather than misleadingly tagged with only the top tier.
        """
        buy_price = partner.get("buyPrice")
        rent_price = partner.get("rentPrice")
        if buy_price is None and rent_price is None:
            return None

        valid_from = _parse_iso(partner.get("partnerValidFrom"))
        valid_until = _parse_iso(partner.get("partnerValidTo"))
        partner_label = partner.get("partnerName", partner.get("partnerId", "unknown"))

        price_points: List[PricePoint] = []
        has_rental = rent_price is not None and rent_price > 0
        has_purchase = buy_price is not None and buy_price > 0

        if has_rental:
            price_points.append(
                PricePoint(
                    amount=Decimal(str(rent_price)),
                    currency="EUR",
                    offer_type=AccessType.TVOD_RENTAL,
                    rental_duration_hours=_DEFAULT_RENTAL_HOURS,
                    valid_from=valid_from,
                    valid_until=valid_until,
                )
            )

        if has_purchase:
            price_points.append(
                PricePoint(
                    amount=Decimal(str(buy_price)),
                    currency="EUR",
                    offer_type=AccessType.TVOD_PURCHASE,
                    valid_from=valid_from,
                    valid_until=valid_until,
                )
            )

        if not price_points:
            return None

        return Pricing(
            access_type=AccessType.TVOD_RENTAL if has_rental else AccessType.TVOD_PURCHASE,
            price_points=price_points,
            rental_duration_hours=_DEFAULT_RENTAL_HOURS if has_rental else None,
            description=f"Available via {partner_label}",
        )

    def _create_pricing_from_direct_fields(
            self,
            buy_price: Optional[float],
            rent_price: Optional[float],
            currency: str = "EUR",
    ) -> Optional[Pricing]:
        """
        Create a Pricing object from direct price fields on contentInformation.

        Fields:
            buyPrice: float  - Purchase price
            rentPrice: float - Rental price

        Same parallel-offer handling as _create_pricing_from_partner — both
        buy and rent, when present, become separate PricePoints on one
        Pricing object rather than one being silently dropped.
        """
        if buy_price is None and rent_price is None:
            return None

        price_points: List[PricePoint] = []
        has_rental = rent_price is not None and rent_price > 0
        has_purchase = buy_price is not None and buy_price > 0

        if has_rental:
            price_points.append(
                PricePoint(
                    amount=Decimal(str(rent_price)),
                    currency=currency,
                    offer_type=AccessType.TVOD_RENTAL,
                    rental_duration_hours=_DEFAULT_RENTAL_HOURS,
                )
            )

        if has_purchase:
            price_points.append(
                PricePoint(
                    amount=Decimal(str(buy_price)),
                    currency=currency,
                    offer_type=AccessType.TVOD_PURCHASE,
                )
            )

        if not price_points:
            return None

        return Pricing(
            access_type=AccessType.TVOD_RENTAL if has_rental else AccessType.TVOD_PURCHASE,
            price_points=price_points,
            rental_duration_hours=_DEFAULT_RENTAL_HOURS if has_rental else None,
        )

    # =========================================================================
    # Private helpers – VodDetails (series → seasons)
    # =========================================================================

    def _fetch_series_seasons(
            self,
            content_id: str,
            params: Dict,
            offset: int = 0,
            page_size: int = VOD_DEFAULT_PAGE_SIZE,
    ) -> Dict:
        """
        Fetch seasons for a series with pagination support.

        Flow:
          1. Fetch VodDetails for the series.
          2. Follow productInformationLink to get the partner/button list.
          3. Pick the best primary button that has a subAssetLane (prefer
             'videoload', otherwise first with a laneContentLink href).
          4. Fetch that subAssetLane laneContentLink with $offset/$size →
             items where vodType == "Season" become VodCategory entries.

        Fallback:
          If productInformationLink is absent or yields nothing, fall back to
          Season-typed lanes embedded in the VodDetails response (no pagination).

        Returns:
            {
                "entries":     List[VodCategory],
                "next_cursor": Optional[str],   # None when no further pages
                "total":       Optional[int],   # total count if known by API
            }
        """
        data = self._get_vod_details(content_id, params)
        if not data:
            return {"entries": [], "next_cursor": None, "total": None}

        content = data.get("content", {})
        info = content.get("contentInformation", {})
        series_title: str = info.get("seriesTitle") or info.get("title") or ""

        # ------------------------------------------------------------------
        # Primary path: productInformationLink → subAssetLane with pagination
        # ------------------------------------------------------------------
        product_url: Optional[str] = (
                content.get("productInformationLink") or {}
        ).get("href")

        if product_url:
            seasons, next_offset, total = self._fetch_seasons_via_product_info(
                product_url, series_title, params, offset=offset, page_size=page_size
            )
            if seasons:
                logger.debug(
                    f"{self._provider}: Series {content_id} → "
                    f"{len(seasons)} seasons (via subAssetLane, offset={offset})"
                )
                next_cursor = str(next_offset) if next_offset is not None else None
                return {"entries": seasons, "next_cursor": next_cursor, "total": total}

        # ------------------------------------------------------------------
        # Fallback: Season lanes embedded in the VodDetails response.
        # These are not paginated by the API — return all seasons found.
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
            gn_season_id = f"{VOD_PREFIX_SEASON}{series_num}_DE_{season_num}"
            opaque_season_id = f"season:{gn_season_id}"
            seasons.append(
                VodCategory(
                    name=season_title,
                    content_id=opaque_season_id,
                    provider=self._provider,
                    description=f"{series_title} – {season_title}",
                    child_count=lane.get("episodeCount") or lane.get("totalCount"),
                )
            )

        logger.debug(
            f"{self._provider}: Series {content_id} → "
            f"{len(seasons)} seasons (via VodDetails lanes)"
        )
        return {"entries": seasons, "next_cursor": None, "total": None}

    def _fetch_seasons_via_product_info(
            self,
            product_url: str,
            series_title: str,
            params: Dict,
            offset: int = 0,
            page_size: int = VOD_DEFAULT_PAGE_SIZE,
    ) -> tuple:
        """
        Fetch the productInformation endpoint and resolve seasons from the
        first usable subAssetLane, with pagination support.

        Partner preference order:
          1. 'videoload'  (native Magenta VOD, always present)
          2. First primary button that has a subAssetLane with a
             laneContentLink href (regardless of instantUsable).

        Returns:
            (seasons_list, next_offset, total_count)
            next_offset is None when there are no further pages.

        Note: productInformation is fetched once per call to resolve the lane
        href. Callers that page through a series will re-fetch it on each page.
        This is acceptable given the low request frequency; a lane-href cache
        keyed on product_url could be added here if it proves noisy.
        """
        prod_data = self._get(product_url, params)
        if not prod_data:
            return [], None, None

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
            paged_params = dict(params)
            paged_params["$size"] = str(page_size)
            paged_params["$offset"] = str(offset)
            lane_data = self._get(lane_href, paged_params)
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
                # Opaque season ID — router-safe, no slashes.
                opaque_season_id = f"season:{season_id}"
                if details_href:
                    self._register_node(opaque_season_id, details_href)

                image_url: Optional[str] = (item.get("image") or {}).get("href")
                description: Optional[str] = (
                        item.get("description") or item.get("longDescription")
                )
                episode_count: Optional[int] = item.get("episodesProduced")

                seasons.append(
                    VodCategory(
                        name=title,
                        content_id=opaque_season_id,
                        provider=self._provider,
                        logo_url=image_url,
                        description=description or f"{series_title} – {title}",
                        child_count=episode_count,
                        details_url=details_href,
                        fetch_url=details_href,
                    )
                )
            if seasons:
                page_info = (lane_data.get("content") or {}).get("page") or {}
                total: Optional[int] = page_info.get("total")
                next_offset_val = offset + len(seasons)
                if total is not None:
                    next_offset: Optional[int] = (
                        next_offset_val if next_offset_val < total else None
                    )
                else:
                    # No total from API: assume more pages when a full page
                    # was returned; stop when a partial page is returned.
                    next_offset = next_offset_val if len(seasons) >= page_size else None
                return seasons, next_offset, total

        return [], None, None

    # =========================================================================
    # Private helpers – VodDetails (season → episodes)
    # =========================================================================

    def _fetch_season_episodes(
            self,
            season_id: str,
            params: Dict,
            offset: int = 0,
            page_size: int = VOD_DEFAULT_PAGE_SIZE,
    ) -> Dict:
        """
        Fetch episodes for a season with pagination support.

        Flow:
          1. PRIMARY: Episode/Asset lanes from VodDetails → SubAssetLane
             (handles e.g. "WIEDERHOLUNGEN" lane items where Season nodes
             come directly from an UnstructuredGrid lane rather than a
             series→season VodDetails page, and would otherwise be missing
             episode content entirely).
          2. FALLBACK 1: productInformationLink → subAssetLane (the
             previously-primary path; still works for series-rooted seasons).
          3. FALLBACK 2: Episode lanes embedded in the VodDetails response,
             fetched without pagination (last resort, take everything).

        Returns:
            {
                "entries":     List[VodItem],
                "next_cursor": Optional[str],   # None when no further pages
                "total":       Optional[int],   # total count if known by API
            }
        """
        episode_params = dict(params)
        episode_params["autofocus"] = "videoload"

        data = self._get_vod_details(season_id, episode_params)
        if not data:
            return {"entries": [], "next_cursor": None, "total": None}

        content = data.get("content", {})
        season_number: Optional[int] = self._extract_season_number(season_id)

        # ------------------------------------------------------------------
        # PRIMARY: Episode/Asset lanes from VodDetails → SubAssetLane
        # ------------------------------------------------------------------
        for lane in content.get("lanes", []):
            if lane.get("type") not in ("Episode", "Asset"):
                continue
            lane_url = (lane.get("laneContentLink") or {}).get("href")
            if not lane_url:
                continue
            episodes, next_offset, total = self._fetch_episodes_from_subasset_lane(
                lane_url, season_number, params, offset=offset, page_size=page_size
            )
            if episodes:
                logger.debug(
                    f"{self._provider}: Season {season_id} → "
                    f"{len(episodes)} episodes (via VodDetails Episode/Asset lane, offset={offset})"
                )
                next_cursor = str(next_offset) if next_offset is not None else None
                return {"entries": episodes, "next_cursor": next_cursor, "total": total}

        # ------------------------------------------------------------------
        # FALLBACK 1: productInformationLink → subAssetLane with pagination
        # ------------------------------------------------------------------
        product_url: Optional[str] = (
                content.get("productInformationLink") or {}
        ).get("href")

        if product_url:
            episodes, next_offset, total = self._fetch_episodes_via_product_info(
                product_url, season_number, params, offset=offset, page_size=page_size
            )
            if episodes:
                logger.debug(
                    f"{self._provider}: Season {season_id} → "
                    f"{len(episodes)} episodes (via subAssetLane, offset={offset})"
                )
                next_cursor = str(next_offset) if next_offset is not None else None
                return {"entries": episodes, "next_cursor": next_cursor, "total": total}

        # ------------------------------------------------------------------
        # FALLBACK 2: Episode lanes embedded in the VodDetails response.
        # These are not paginated by the API — return all episodes found.
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
            f"{len(episodes)} episodes (via VodDetails lanes, fallback)"
        )
        return {"entries": episodes, "next_cursor": None, "total": None}

    def _fetch_episodes_from_subasset_lane(
            self,
            lane_url: str,
            season_number: Optional[int],
            params: Dict,
            offset: int = 0,
            page_size: int = VOD_DEFAULT_PAGE_SIZE,
    ) -> tuple:
        """
        Fetch episodes from a SubAssetLane URL with pagination support.

        Used by the PRIMARY path in _fetch_season_episodes, where the
        SubAssetLane href comes directly from a VodDetails Episode/Asset
        lane rather than via productInformationLink.

        Args:
            lane_url:      Full SubAssetLane URL from laneContentLink.href
            season_number: Season number for episode metadata
            params:        Base query parameters
            offset:        Current page offset
            page_size:     Items per page

        Returns:
            (episodes_list, next_offset, total_count)
            next_offset is an int or None — caller is responsible for
            converting to a string cursor.
        """
        paged_params = dict(params)
        paged_params["$size"] = str(page_size)
        paged_params["$offset"] = str(offset)

        lane_data = self._get(lane_url, paged_params)
        if not lane_data:
            return [], None, None

        episodes = []
        for item in (lane_data.get("content") or {}).get("items", []):
            vod_type = item.get("vodType", "")
            item_type = item.get("type", "")
            # Accept both "Episode" vodType and Asset items where type == "Episode"
            if vod_type == "Episode" or (vod_type == "Asset" and item_type == "Episode"):
                node = self._map_episode_item(item, season_number)
                if node is not None:
                    episodes.append(node)

        if not episodes:
            return [], None, None

        page_info = (lane_data.get("content") or {}).get("page") or {}
        total: Optional[int] = page_info.get("total")
        next_offset_val = offset + len(episodes)
        if total is not None:
            next_offset: Optional[int] = (
                next_offset_val if next_offset_val < total else None
            )
        else:
            next_offset = next_offset_val if len(episodes) >= page_size else None

        return episodes, next_offset, total

    def _fetch_episodes_via_product_info(
            self,
            product_url: str,
            season_number: Optional[int],
            params: Dict,
            offset: int = 0,
            page_size: int = VOD_DEFAULT_PAGE_SIZE,
    ) -> tuple:
        """
        Resolve the episode list from the productInformation subAssetLane,
        with pagination support.

        Partner preference: videoload first, then any other with a
        laneContentLink href.

        Returns:
            (episodes_list, next_offset, total_count)
            next_offset is None when there are no further pages.

        Note: productInformation is fetched once per call to resolve the lane
        href. Callers that page through a season will re-fetch it on each page.
        This is acceptable given the low request frequency; a lane-href cache
        keyed on product_url could be added here if it proves noisy.
        """
        prod_data = self._get(product_url, params)
        if not prod_data:
            return [], None, None

        primary_buttons = (prod_data.get("buttons") or {}).get("primary", [])

        # Build an ordered candidate list: videoload first, then others.
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
            paged_params = dict(params)
            paged_params["$size"] = str(page_size)
            paged_params["$offset"] = str(offset)

            lane_data = self._get(lane_href, paged_params)
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
                page_info = (lane_data.get("content") or {}).get("page") or {}
                total: Optional[int] = page_info.get("total")
                next_offset_val = offset + len(episodes)
                if total is not None:
                    next_offset: Optional[int] = (
                        next_offset_val if next_offset_val < total else None
                    )
                else:
                    # No total from API: assume more pages when a full page
                    # was returned; stop when a partial page is returned.
                    next_offset = next_offset_val if len(episodes) >= page_size else None
                return episodes, next_offset, total

        return [], None, None

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

        Pricing is likewise not resolved here for the same reason it's skipped
        in _map_unstructured_item — lane/season listings can contain many
        items and pricing is only needed once the user opens the episode.
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
            content_id=f"episode:{content_id}",
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

        # Resolve pricing from the same VodDetails response.
        pricing = self._parse_pricing_from_vod_details(data)

        product_url: Optional[str] = (
                content_block.get("productInformationLink") or {}
        ).get("href")

        # Walk the full playback chain to resolve a real MPX mediaId, just
        # like _fetch_single_item() does for movies.  Without this step the
        # content_id stays as a GN_EP* Gracenote id which the manifest/DRM
        # layer cannot use.  Also picks up buttons.secondary[rel=="trailer"].
        playback_href: Optional[str] = None
        playback_media_id: Optional[str] = None
        trailer_href: Optional[str] = None
        if product_url:
            playback_href, playback_media_id, trailer_href = self._resolve_movie_playback_href(
                product_url, self._playback_params()
            )

        if playback_media_id:
            # Extract the alphanumeric guid from the theplatform href —
            # the SMIL selector requires the guid, not the numeric mediaId.
            # e.g. "https://link.theplatform.eu/s/mdeprod/media/zRPPGLNGgPa1"
            #      → guid = "zRPPGLNGgPa1"
            guid: Optional[str] = None
            if playback_href:
                tail = playback_href.rstrip("/").rsplit("/media/", 1)
                if len(tail) == 2:
                    guid = tail[1].split("?")[0] or None

            effective_content_id = guid if guid else playback_media_id
            manifest_script = playback_href
            session_manifest = True
            logger.debug(
                f"{self._provider}: Episode {content_id} → "
                f"mediaId={playback_media_id}, guid={guid or '(none, using mediaId)'}"
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
            pricing=pricing,
            trailer_url=trailer_href,
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

        Pricing resolution
        -------------------
        Resolved from the same VodDetails response via
        _parse_pricing_from_vod_details(); see that method's docstring for the
        direct-fields vs partners[] precedence and the parallel rent/buy
        PricePoint handling.

        Playback ID resolution
        ----------------------
        The VodPlayer response (step 3 of the playback chain) exposes
        ``content.playbackUrls`` — a list of quality-tagged theplatform hrefs
        and their MPX ``mediaId`` values.  We resolve the best mediaId here
        (using ``_pick_playback_media_id``) so that the provider's
        ``get_manifest`` receives the correct MPX ID, not the raw GN content ID.
        The same call also resolves buttons.secondary[rel=="trailer"], if present.

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

        # Resolve pricing from the same VodDetails response.
        pricing = self._parse_pricing_from_vod_details(data)

        # ------------------------------------------------------------------
        # Resolve the VodPlayer URL and pick the correct theplatform href.
        #
        # Flow:
        #   productInformationLink → buttons.primary[rel=="player",
        #                            instantUsable==true] → VodPlayer URL
        #   VodPlayer response     → content.playbackUrls  → pick by quality
        #   productInformation response also carries buttons.secondary
        #                            [rel=="trailer"] → trailer href
        #
        # When resolved:
        #   content_id      = MPX mediaId (e.g. "QflsaCy6P3Sc")
        #   manifest_script = full theplatform href (stored for reference)
        #   session_manifest = True  → provider._get_smil_content(content_id)
        #                              builds the correct SMIL URL automatically
        #
        # When resolution fails, fall back to GN content_id + productInformationLink
        # so the existing session-manifest path still has a chance to work.
        # Trailer resolution is independent of playback resolution succeeding.
        # ------------------------------------------------------------------
        product_url: Optional[str] = (
                content_block.get("productInformationLink") or {}
        ).get("href")

        playback_href: Optional[str] = None
        playback_media_id: Optional[str] = None
        trailer_href: Optional[str] = None
        if product_url:
            playback_href, playback_media_id, trailer_href = self._resolve_movie_playback_href(
                product_url, params
            )

        if playback_media_id:
            # Extract the alphanumeric guid from the theplatform href —
            # the SMIL selector requires the guid, not the numeric mediaId.
            # e.g. "https://link.theplatform.eu/s/mdeprod/media/zRPPGLNGgPa1"
            #      → guid = "zRPPGLNGgPa1"
            guid: Optional[str] = None
            if playback_href:
                tail = playback_href.rstrip("/").rsplit("/media/", 1)
                if len(tail) == 2:
                    guid = tail[1].split("?")[0] or None

            effective_content_id = guid if guid else playback_media_id
            manifest_script = playback_href
            session_manifest = True
            logger.debug(
                f"{self._provider}: Movie {content_id} → "
                f"mediaId={playback_media_id}, guid={guid or '(none, using mediaId)'}"
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
            pricing=pricing,
            trailer_url=trailer_href,
        )]

    def _normalise_product_url(self, url: str) -> str:
        """
        Rewrite a productInformationLink URL to use our client model
        so that the response contains proper player buttons.

        The partnerMapId, appMapId and channelMapId query parameters are left
        untouched — they are portal-specific values set by the server that must
        be preserved for the correct button set to be returned.
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
        return str(urlunparse(parsed._replace(query=new_query)))

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

    def _get_instant_usage_partners_url(self) -> str:
        """
        Resolve the instantusagepartners URL.

        Resolution order:
          1. ProviderConfig manifest tvHubUrls.instantUsagePartners with
             {clientModel} substituted — discovered dynamically, never hardcoded.
          2. Constructed from _base_url() — same host/path convention as all
             other tvhubs endpoints, flex ID 83856 is stable.
        """
        if self._provider_config is not None:
            url = self._provider_config.get_resolved_tvhub_url(
                "instantUsagePartners"
            )
            if url:
                return url
        return f"{self._base_url()}/instantusagepartners/83856"

    def _fetch_instant_usage_partners(self, params: Dict) -> None:
        """
        Preflight call to instantusagepartners — mirrors what the real app
        does before any vodproductinformation request.

        The server uses this to establish which partners the account can access
        instantly, and without it may return subscriptionMissing even for
        entitled content.  The response is not used directly; the side-effect
        on the server session is what matters.
        """
        if getattr(self, "_instant_usage_fetched", False):
            return  # Only needed once per VodManager instance
        # Params mirror the real device call exactly — $cid (AndroidTV style),
        # $reloadAfterChange, no whiteLabelId, no sid/t.
        # Serial + session headers are injected automatically by _get().
        iup_params: Dict[str, str] = {
            "$deviceModel": self._device_model,
            "$profile": self._profile_name,
            "$subscriberType": self._subscriber_type,
            "$theme": self._theme_id,
            "$redirect": "false",
            "$reloadAfterChange": "false",
        }
        if self._is_androidtv():
            iup_params["$cid"] = f"{self._session_id}::{str(_uuid_mod.uuid4())}"
        else:
            iup_params["sid"] = self._session_id
            iup_params["t"] = str(int(time.time() * 1000))
        url = self._get_instant_usage_partners_url()
        data = self._get(url, iup_params)
        if data:
            partners = data.get("partnerList", [])
            logger.debug(
                f"{self._provider}: instantusagepartners → "
                f"{len(partners)} partners available"
            )
        else:
            logger.warning(
                f"{self._provider}: instantusagepartners fetch failed"
            )
        self._instant_usage_fetched = True

    def _resolve_movie_playback_href(
            self,
            product_url: str,
            params: Dict,
    ) -> tuple:
        """
        Walk the playback chain for a movie/episode and return
        ``(href, media_id, trailer_href)``.

        Steps:
          1. Fetch productInformationLink.
          2. Extract buttons.secondary[rel=="trailer"] → trailer_href, if
             present. Captured independently of player-button resolution
             below, so a trailer can still be returned even when no
             instantUsable player button exists.
          3. Pick buttons.primary[] where rel=="player" AND instantUsable==true.
          4. Fetch the VodPlayer URL ($redirect=false + sid already in params).
          5. Extract content.playbackUrls, pick by quality preference.

        Returns:
            (theplatform_href, media_id, trailer_href).
            href/media_id are None on any playback-resolution failure;
            trailer_href is independently None/set based on whether
            buttons.secondary carried a trailer entry.
        """
        # Preflight: establish instant-usage partner session on the server
        # before the vodproductinformation call.
        self._fetch_instant_usage_partners(self._base_params())

        url = self._normalise_product_url(product_url)
        playback_params = self._playback_params()
        if url != product_url:
            logger.debug(
                f"{self._provider}: Normalised productInformation URL: {url}"
            )

        prod_data = self._get_auth(url, playback_params)
        if not prod_data:
            return None, None, None

        buttons = prod_data.get("buttons") or {}

        # Trailer — extracted up front so it survives even if no
        # instantUsable player button is found below.
        trailer_href: Optional[str] = None
        for btn in buttons.get("secondary", []):
            if btn.get("rel") == "trailer":
                trailer_href = btn.get("href")
                break

        # Log all primary buttons so we can diagnose auth / partner issues.
        primary_buttons = buttons.get("primary", [])
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
            return None, None, trailer_href

        vod_player_data = self._get_auth(vod_player_url, playback_params)
        if not vod_player_data:
            return None, None, trailer_href

        playback_urls: List[Dict] = (
                (vod_player_data.get("content") or {}).get("playbackUrls") or []
        )
        media_id = self._pick_playback_media_id(playback_urls)
        if not media_id:
            return None, None, trailer_href

        for entry in playback_urls:
            if entry.get("mediaId") == media_id:
                href = entry.get("href")
                logger.debug(
                    f"{self._provider}: Resolved movie playback href "
                    f"(quality={entry.get('quality')}, mediaId={media_id}): {href}"
                )
                return href, media_id, trailer_href

        return None, None, trailer_href

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

    # =========================================================================
    # Search
    # =========================================================================

    def search(
            self,
            query: str,
            cursor: Optional[str] = None,
            page_size: int = VOD_DEFAULT_PAGE_SIZE,
            **kwargs,
    ) -> Dict[str, Any]:
        """
        Search the VOD catalogue using Magenta2's two-step SearchGrid API.

        The API flow is:
          1. GET DocumentGroupRedirect?q={query}&...  → {"$type":"redirect","redirectUrl":"..."}
          2. GET redirectUrl                          → grouped SearchGrid results

        Based on actual API logs:
          First request: /DocumentGroupRedirect/TVHS_DG_SearchGrid?q=Geissens&...
          Response: {"$type": "redirect", "redirectUrl": "https://tvhubs.t-online.de/v3/ftv-web/SearchGrid/294240?q=Geissens&..."}
          Second request: GET redirectUrl
          Response: {"$type": "groupgrid", "content": {"groups": [...]}}

        Pagination notes:
          Only the first page is supported in this implementation. The API
          returns a fixed result set; full pagination via SearchUnstructuredGrid
          can be added later by following allItems.href with $offset/$size.

        Args:
            query:     Search string. Empty / whitespace-only → empty result.
            cursor:    Reserved for future pagination; ignored for now.
            page_size: Reserved for future pagination; ignored for now.

        Returns:
            {"entries": List[VodCategory | VodItem], "next_cursor": None, "total": int}
        """
        from urllib.parse import quote as _quote

        _empty: Dict[str, Any] = {"entries": [], "next_cursor": None, "total": 0}

        if not query or not query.strip():
            logger.debug(f"{self._provider}: Search called with empty query")
            return _empty

        # ── Resolve the search URL template ──────────────────────────────
        # Priority: 1. endpoint_manager (if available), 2. provider_config, 3. fallback
        search_template = self._get_search_url_template()
        if not search_template:
            logger.error(f"{self._provider}: No search URL template available")
            return _empty

        # The manifest template uses {clientModel} (camelCase) — same
        # convention as home_url / _get_streaming_grid_url().
        redirect_url = search_template.replace(
            "{clientModel}", self._client_model
        ).replace("{query}", _quote(query.strip(), safe=""))

        # ── Step 1: DocumentGroupRedirect → API-level redirect ────────────
        params = self._base_params()
        logger.debug(f"{self._provider}: Search redirect URL: {redirect_url}")
        logger.debug(f"{self._provider}: Search redirect params: {params}")

        redirect_data = self._get(redirect_url, params)

        if not redirect_data:
            logger.error(f"{self._provider}: Search redirect request failed - no response")
            return _empty

        if redirect_data.get("$type") != "redirect":
            logger.error(
                f"{self._provider}: Search redirect response has unexpected "
                f"$type={redirect_data.get('$type')!r}"
            )
            return _empty

        redirect_target = redirect_data.get("redirectUrl")
        if not redirect_target:
            logger.error(f"{self._provider}: Search redirect response missing redirectUrl")
            return _empty

        # ── Step 2: Fetch actual search results ───────────────────────────
        # The redirectUrl already carries all required query params baked in
        # by the server. Pass an empty params dict so we don't duplicate or
        # override them — this mirrors _get_streaming_grid_url()'s second call.
        logger.debug(f"{self._provider}: Search results URL: {redirect_target}")
        search_data = self._get(redirect_target, {})
        if not search_data:
            logger.error(f"{self._provider}: Search results request failed")
            return _empty

        # ── Step 3: Parse grouped results ────────────────────────────────
        entries = self._parse_search_groups(search_data)

        logger.info(
            f"{self._provider}: Search '{query}' returned {len(entries)} entries"
        )

        return {"entries": entries, "next_cursor": None, "total": len(entries)}

    def _get_search_url_template(self) -> Optional[str]:
        # Priority 1: Try endpoint manager (discovered via manifest)
        # This won't work because VodManager doesn't have endpoint_manager

        # Priority 2: Try provider config directly (THIS IS THE CORRECT PATH)
        if self._provider_config:
            template = self._provider_config.get_search_url_template()
            if template:
                logger.debug(f"{self._provider}: Found search template via provider_config")
                return template

        # Priority 3: Try manifest.tv_hubs.base_urls directly (fallback)
        if self._provider_config and hasattr(self._provider_config, 'manifest') and self._provider_config.manifest:
            template = self._provider_config.manifest.tv_hubs.base_urls.get("searchUrl")
            if template:
                logger.debug(f"{self._provider}: Found search template via manifest.tv_hubs")
                return template

        logger.warning(f"{self._provider}: Search URL template not found in any source.")
        return None

    def _parse_search_groups(self, data: Dict) -> List[Union[VodCategory, VodItem]]:
        """
        Parse a SearchGrid response into a flat list of VodCategory / VodItem.

        Response structure from actual API call:
        {
            "$type": "groupgrid",
            "content": {
                "groups": [
                    {
                        "title": "TV",
                        "items": [...],
                        "itemsCount": 213,
                        "allItems": {"href": "https://..."}
                    },
                    {
                        "title": "Streaming",
                        "items": [...],
                        "itemsCount": 213
                    }
                ]
            }
        }

        External / non-VOD groups (Podcasts, Music, …) are skipped: a group
        is included only when at least one of its items carries a recognisable
        VOD type (Series / Episode / Movie / Group).
        """
        _VOD_TYPES = {"Series", "Episode", "Movie"}

        entries: List[Union[VodCategory, VodItem]] = []
        groups: List[Dict] = (data.get("content") or {}).get("groups", [])

        for group in groups:
            group_title: str = group.get("title", "")
            items: List[Dict] = group.get("items", [])
            items_count: int = group.get("itemsCount", 0)

            # Skip groups that contain no recognisable VOD content so that
            # Podcasts, Music and other non-video groups are silently dropped.
            has_vod = any(
                i.get("vodType") in _VOD_TYPES or i.get("type") == "Group"
                for i in items
            )
            if not has_vod:
                logger.debug(
                    f"{self._provider}: Skipping non-VOD search group "
                    f"'{group_title}' ({items_count} items)"
                )
                continue

            logger.debug(
                f"{self._provider}: Processing search group '{group_title}' "
                f"with {len(items)} items"
            )

            for item in items:
                entry = self._map_search_item(item)
                if entry is not None:
                    entries.append(entry)

        return entries

    def _map_search_item(
            self, item: Dict
    ) -> Optional[Union[VodCategory, VodItem]]:
        """
        Dispatch a single search result item to the appropriate mapper.

        Based on actual API response for query "Geissens":

        Items can have:
            - type: "Group" (category folder, e.g., TV group items)
            - vodType: "Series" (browsable series)
            - vodType: "Episode" (playable episode)
            - vodType: "Movie" (playable movie)

        Examples from logs:
            - Group: {"id": "groupType16byGenreAdult__...", "type": "Group", "title": "Die Geissens - Eine schrecklich glamouröse Familie", "size": 11}
            - Series: {"id": "GN_SERIES_10862001", "vodType": "Series", "title": "Die Geissens - Eine schrecklich glamouröse Familie!", "seasonsAvailable": 24}
            - Episode: {"id": "GN_EP019441760098", "vodType": "Episode", "title": "Die Geissens campen wieder!", "seasonNumber": 4, "episodeNumber": 8}

        vodType / type → mapper
        -----------------------
        Group   → VodCategory  (category folder, e.g. a TV channel group)
        Series  → VodCategory  (browsable, navigates to seasons)
        Episode → VodItem      (playable)
        Movie   → VodItem      (playable)
        other   → None (logged and skipped)
        """
        vod_type: str = item.get("vodType", "")
        item_type: str = item.get("type", "")

        # Group items (category folders)
        if item_type == "Group":
            return self._map_search_group_item(item)

        # Series (browsable content)
        if vod_type == "Series":
            return self._map_search_series_item(item)

        # Episodes (playable)
        if vod_type == "Episode":
            season_number: Optional[int] = item.get("seasonNumber")
            return self._map_episode_item(item, season_number)

        # Movies (playable)
        if vod_type == "Movie":
            return self._map_search_movie_item(item)

        # Unknown type - log once per unique type for debugging
        logger.debug(
            f"{self._provider}: Unknown search item type: "
            f"vodType={vod_type!r} type={item_type!r} — skipping"
        )
        return None

    def _map_search_group_item(self, item: Dict) -> Optional[VodCategory]:
        """
        Map a Group-type search item to a VodCategory.

        Group items appear in the "TV" group and point to a category page
        (e.g., all episodes of a TV channel's output) identified by groupContentLink.

        Example from logs:
        {
            "id": "groupType16byGenreAdult__3cf311181b6a87f1aec3a3cc6abfbd62",
            "title": "Die Geissens - Eine schrecklich glamouröse Familie",
            "size": 11,
            "image": {"href": "http://ngiss.t-online.de/..."},
            "groupContentLink": {"href": "https://tvhubs.t-online.de/v3/ftv-web/SearchUnstructuredGrid/294240/0?$q=Geissens&$groupId=..."}
        }
        """
        content_id: str = item.get("id", "")
        if not content_id:
            logger.debug(f"{self._provider}: Search group item missing id")
            return None

        title: str = item.get("title", "")
        size: Optional[int] = item.get("size")

        # Extract image URL
        image: Optional[str] = None
        if item.get("image"):
            image = item["image"].get("href")

        group_content_link: str = (item.get("groupContentLink") or {}).get("href", "")

        # Create opaque ID for routing
        opaque_id = f"search_group:{content_id}"

        # Register the node for navigation if we have a fetch URL
        if group_content_link:
            self._register_node(opaque_id, group_content_link)
            logger.debug(
                f"{self._provider}: Registered search group '{title}' "
                f"with content_id={opaque_id}"
            )
        else:
            logger.warning(
                f"{self._provider}: Search group '{title}' has no groupContentLink"
            )

        return VodCategory(
            name=title,
            content_id=opaque_id,
            provider=self._provider,
            logo_url=image,
            child_count=size,
            fetch_url=group_content_link or None,
        )

    def _map_search_series_item(self, item: Dict) -> VodCategory:
        """
        Map a Series search result to a VodCategory.

        Reuses the same ``series:<GN_SERIES_id>`` prefix as lane browsing so
        that navigation into seasons works identically regardless of how the
        series was discovered.

        Example from logs:
        {
            "id": "GN_SERIES_10862001",
            "vodType": "Series",
            "title": "Die Geissens - Eine schrecklich glamouröse Familie!",
            "description": "Der Multimillionär Robert Geiss führt...",
            "seasonsAvailable": 24,
            "image": {"href": "http://ngiss.t-online.de/..."},
            "details": {"href": "https://tvhubs.t-online.de/v3/ftv-web/VodDetails/202887/GN_SERIES_10862001"}
        }
        """
        series_id: str = item.get("id", "")
        title: str = item.get("title", "")

        # Use longDescription if available, otherwise short description
        description: Optional[str] = item.get("longDescription") or item.get("description")

        # Extract image URL (prefer posterWide)
        image: Optional[str] = None
        if item.get("image"):
            image = item["image"].get("href")

        seasons_available: Optional[int] = item.get("seasonsAvailable")
        details_href: str = (item.get("details") or {}).get("href", "")

        opaque_id = f"series:{series_id}"

        if details_href:
            self._register_node(opaque_id, details_href)
            logger.debug(
                f"{self._provider}: Registered search series '{title}' "
                f"with content_id={opaque_id}"
            )

        return VodCategory(
            name=title,
            content_id=opaque_id,
            provider=self._provider,
            logo_url=image,
            description=description,
            child_count=seasons_available,
            details_url=details_href or None,
            fetch_url=details_href or None,
        )

    def _map_search_movie_item(self, item: Dict) -> VodItem:
        """
        Map a Movie search result to a VodItem.

        Playback resolution (VodDetails → productInformationLink → VodPlayer)
        AND pricing resolution are both deferred to when the user opens the
        detail view / hits play — not resolved here. Firing a VodDetails
        fetch per search result would multiply request volume for data most
        results will never need; this mirrors the same laziness convention
        used by _map_unstructured_item for lane browsing.

        Example from logs (movie variant - not in Geissens example but similar to series):
        {
            "id": "GN_MV_12345678",
            "vodType": "Movie",
            "title": "Movie Title",
            "description": "Movie description...",
            "duration": 90,
            "yearOfProduction": "2023",
            "image": {"href": "http://ngiss.t-online.de/..."},
            "details": {"href": "https://tvhubs.t-online.de/v3/ftv-web/VodDetails/202887/GN_MV_12345678"}
        }
        """
        movie_id: str = item.get("id", "")
        title: str = item.get("title", "")

        description: Optional[str] = item.get("longDescription") or item.get("description")

        # Extract image URL
        image: Optional[str] = None
        if item.get("image"):
            image = item["image"].get("href")

        # Duration in minutes from API → convert to seconds
        duration_raw = item.get("duration")
        try:
            duration_seconds: Optional[int] = int(duration_raw) * 60 if duration_raw else None
        except (ValueError, TypeError):
            duration_seconds = None
            logger.debug(f"{self._provider}: Invalid duration for movie {movie_id}: {duration_raw}")

        # Year from API (may be "2023" or "2023-01-01")
        year_raw = item.get("yearOfProduction")
        try:
            release_year: Optional[int] = (
                int(str(year_raw).split("-")[0]) if year_raw else None
            )
        except (ValueError, TypeError):
            release_year = None

        # Store details URL for manifest resolution (used by get_manifest)
        details_href: str = (item.get("details") or {}).get("href", "")

        vod_item = VodItem.create_movie(
            name=title,
            content_id=f"movie:{movie_id}",
            provider=self._provider,
            logo_url=image,
            description=description,
            release_year=release_year,
            duration_seconds=duration_seconds,
            genre=item.get("mainGenre"),
            genres=item.get("genres") or None,
            rating=item.get("childProtectionRating"),
            # No pricing here — resolved lazily, see docstring above.
        )

        # Store manifest script for later playback resolution
        if details_href:
            vod_item.manifest_script = details_href

        logger.debug(
            f"{self._provider}: Mapped search movie '{title}' "
            f"(id={movie_id}, year={release_year}, duration={duration_seconds}s)"
        )

        return vod_item