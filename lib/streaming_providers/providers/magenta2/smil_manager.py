# streaming_providers/providers/magenta2/smil_manager.py
"""
Magenta2 SMIL / Playback Manager

Handles all SMIL fetching, parsing, caching, and DRM resolution for the
Magenta2 provider.  This is the shared playback layer used by live channels,
VOD items, and recordings — content type does not affect the code path.

SMIL URL strategy
-----------------
VOD items and recordings already carry the full theplatform selector URL in
their ``manifest_script`` field (e.g.
``https://link.theplatform.eu/s/mdeprod/media/{guid}``).  That URL is used
directly; only the standard SMIL query params are appended.

Live channels have no pre-resolved URL.  The URL is constructed at request
time from the discovered selector endpoint + account PID + MPX GUID.

In both cases the query params are identical:
    ?format=SMIL&formats=MPEG-DASH&tracking=true&cid={session}::{call}

GN id resolution  (VOD only)
-----------------------------
When ``get_smil_data`` receives an opaque browse-time id (``movie:GN_MV…``,
``episode:GN_EP…``) or a legacy bare GN id, it resolves it to the full
theplatform URL via ``_resolve_gn_id_to_smil_url``.  This triggers the full
VodDetails -> productInformation -> VodPlayer chain and is the only place
where an extra network round-trip occurs at play time.

Public interface
----------------
    smil_manager.get_smil_data(content_id)  -> Optional[Dict]
    smil_manager.get_manifest(content_id)   -> Optional[str]
    smil_manager.get_catchup_manifest(channel_id, start_time, end_time) -> Optional[str]
    smil_manager.get_drm(content_id)        -> List[DRMConfig]
"""

import base64
import json
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from ...base.models import DRMConfig, DRMSystem, LicenseConfig
from ...base.utils.logger import logger

from .constants import (
    CONTENT_TYPE_LIVE,
    DEFAULT_REQUEST_TIMEOUT,
    MAGENTA2_FALLBACK_ACCOUNT_URI,
    SMIL_CACHE_DURATION,
    SMIL_CLIENT_ID,
    VOD_PREFIX_EPISODE,
    VOD_PREFIX_MOVIE_MV,
    VOD_PREFIX_MOVIE_SH,
)


class SmilManager:
    """
    Shared SMIL / playback layer for Magenta2.

    Args:
        http_manager:       HTTPManager instance from the parent provider.
        provider_name:      Provider identifier string (e.g. ``"magenta2"``).
        session_id:         Stable session UUID used in ``cid`` correlation header.
        call_id_callback:   Callable ``() -> str`` returning a fresh UUID per request.
        auth_callback:      Callable ``() -> str`` returning the current
                            Base64-encoded persona token.
        platform_config:    Platform dict from ``MAGENTA2_PLATFORMS`` — supplies
                            User-Agent and DRM request headers.
        endpoint_manager:   EndpointManager for selector / widevine endpoint lookup.
        provider_config:    ProviderConfig — account PID and account URI.
        vod_manager:        Optional VodManager — required only for GN id resolution.
        cache_ttl:          SMIL cache TTL in seconds (default: SMIL_CACHE_DURATION).
    """

    def __init__(
        self,
        http_manager,
        provider_name: str,
        session_id: str,
        call_id_callback,
        auth_callback,
        platform_config: Dict,
        endpoint_manager,
        provider_config,
        vod_manager=None,
        cache_ttl: int = SMIL_CACHE_DURATION,
    ):
        self._http = http_manager
        self._provider = provider_name
        self._session_id = session_id
        self._call_id = call_id_callback
        self._auth = auth_callback
        self._platform_config = platform_config
        self._endpoint_manager = endpoint_manager
        self._provider_config = provider_config
        self._vod_manager = vod_manager
        self._cache: Dict[str, Tuple[float, Dict]] = {}
        self._cache_ttl = cache_ttl

    # =========================================================================
    # Public API
    # =========================================================================

    def get_manifest(
        self, content_id: str, content_type: str = CONTENT_TYPE_LIVE, **kwargs
    ) -> Optional[str]:
        """Return the MPD URL for *content_id*, or None on failure."""
        smil_data = self.get_smil_data(content_id)
        return smil_data.get("mpd_url") if smil_data else None

    def get_catchup_manifest(
        self, channel_id: str, start_time: int, end_time: int, **kwargs
    ) -> Optional[str]:
        """
        Return a live manifest extended with catchup time-range parameters.

        Args:
            channel_id:  MPX GUID for the live channel.
            start_time:  Catchup start as Unix epoch seconds.
            end_time:    Catchup end as Unix epoch seconds.
        """
        from ...base.utils.timestamp_converter import TimestampConverter

        base_manifest = self.get_manifest(channel_id, **kwargs)
        if not base_manifest:
            logger.warning(
                f"{self._provider}: Channel {channel_id} has no manifest for catchup"
            )
            return None

        try:
            start_iso = TimestampConverter.epoch_to_iso(
                start_time, format_type="basic", as_utc=True
            )
            end_iso = TimestampConverter.epoch_to_iso(end_time, format_type="basic", as_utc=True)
            separator = "&" if "?" in base_manifest else "?"
            catchup_url = f"{base_manifest}{separator}begin={start_iso}&end={end_iso}"
            logger.debug(
                f"{self._provider}: Catchup manifest for {channel_id}: {catchup_url}"
            )
            return catchup_url
        except Exception as e:
            logger.error(
                f"{self._provider}: Error building catchup manifest for {channel_id}: {e}"
            )
            logger.warning(
                f"{self._provider}: Falling back to live manifest for {channel_id}"
            )
            return base_manifest

    def get_drm(
        self, content_id: str, content_type: str = CONTENT_TYPE_LIVE, **kwargs
    ) -> List[DRMConfig]:
        """
        Return a Widevine DRMConfig for *content_id*.

        Resolves the releasePid from cached SMIL data, extracts the persona JWT,
        and constructs the full Widevine licence URL.
        """
        try:
            smil_data = self.get_smil_data(content_id)
            if not smil_data:
                logger.error(f"{self._provider}: No SMIL data for {content_id}")
                return []

            release_pid = smil_data.get("release_pid")
            if not release_pid:
                logger.error(
                    f"{self._provider}: No releasePid in SMIL for {content_id}"
                )
                if smil_data.get("content"):
                    logger.debug(
                        f"{self._provider}: SMIL preview: {smil_data['content'][:500]}..."
                    )
                return []

            persona_token = self._auth()
            raw_jwt = self._extract_persona_jwt(persona_token)
            if not raw_jwt:
                logger.error(f"{self._provider}: Failed to extract persona JWT")
                return []

            widevine_endpoint = self._endpoint_manager.get_endpoint("widevine_license")
            if not widevine_endpoint:
                logger.error(
                    f"{self._provider}: No widevine_license endpoint available"
                )
                return []

            account_uri = self._get_account_uri()
            license_url = (
                f"{widevine_endpoint}?"
                f"schema=1.0&"
                f"releasePid={release_pid}&"
                f"token={raw_jwt}&"
                f"account={quote(account_uri, safe='')}"
            )

            drm_config = DRMConfig(
                system=DRMSystem.WIDEVINE,
                priority=1,
                license=LicenseConfig.create_with_req_data(
                    req_data_template="{CHA-RAW}",
                    server_url=license_url,
                    server_certificate=None,
                    req_headers=json.dumps(
                        {
                            "User-Agent": self._platform_config["user_agent"],
                            "Content-Type": "application/octet-stream",
                        }
                    ),
                    use_http_get_request=False,
                ),
            )
            logger.info(
                f"{self._provider}: DRM config for {content_id} "
                f"(releasePid: {release_pid})"
            )
            return [drm_config]

        except Exception as e:
            logger.error(f"{self._provider}: Error getting DRM for {content_id}: {e}")
            return []

    def get_smil_data(self, content_id: str) -> Optional[Dict[str, Any]]:
        """
        Resolve *content_id* to SMIL data (MPD URL + releasePid), with caching.

        Dispatch:
          - ``movie:…`` / ``episode:…``  -> GN id resolution via VodManager
          - bare ``GN_EP*`` / ``GN_MV*`` / ``GN_SH*`` -> same (legacy compat)
          - anything else -> treated as a raw MPX GUID (live channel)

        Cache key is always the bare MPX GUID so repeated calls for the same
        content under different prefixes share one entry.
        """
        smil_base_url: Optional[str] = None

        # ── Opaque VOD prefixes ──────────────────────────────────────────
        if content_id.startswith("movie:") or content_id.startswith("episode:"):
            gn_id = content_id.split(":", 1)[1]
            smil_base_url = self._resolve_gn_id_to_smil_url(gn_id)
            if not smil_base_url:
                logger.error(
                    f"{self._provider}: Cannot play {content_id}: "
                    "failed to resolve to SMIL URL"
                )
                return None

        # ── Legacy bare GN ids ───────────────────────────────────────────
        elif (
            content_id.startswith(VOD_PREFIX_EPISODE)
            or content_id.startswith(VOD_PREFIX_MOVIE_MV)
            or content_id.startswith(VOD_PREFIX_MOVIE_SH)
        ):
            smil_base_url = self._resolve_gn_id_to_smil_url(content_id)
            if not smil_base_url:
                logger.error(
                    f"{self._provider}: Cannot play {content_id}: "
                    "failed to resolve GN id to SMIL URL"
                )
                return None

        # ── Stable cache key (bare GUID) ─────────────────────────────────
        if smil_base_url:
            tail = smil_base_url.rstrip("/").rsplit("/media/", 1)
            cache_key = tail[1].split("?")[0] if len(tail) == 2 else content_id
        else:
            cache_key = content_id

        # ── Cache check ──────────────────────────────────────────────────
        now = time.time()
        if cache_key in self._cache:
            ts, cached = self._cache[cache_key]
            if now - ts < self._cache_ttl:
                logger.debug(f"{self._provider}: SMIL cache hit for {cache_key}")
                return cached
            del self._cache[cache_key]

        # ── Fetch ────────────────────────────────────────────────────────
        try:
            smil_content = self._fetch_smil(cache_key, smil_base_url=smil_base_url)
            if not smil_content:
                logger.error(f"{self._provider}: No SMIL content for {cache_key}")
                return None
            if not smil_content.strip():
                logger.error(f"{self._provider}: Empty SMIL content for {cache_key}")
                return None
            if "<smil" not in smil_content.lower():
                logger.error(
                    f"{self._provider}: Invalid SMIL for {cache_key}: "
                    f"{smil_content[:200]}..."
                )
                return None

            mpd_url = self._parse_mpd_url(smil_content, cache_key)
            release_pid = self._parse_release_pid(smil_content)

            smil_data: Dict[str, Any] = {
                "content": smil_content,
                "mpd_url": mpd_url,
                "release_pid": release_pid,
                "channel_id": cache_key,
            }

            if mpd_url or release_pid:
                self._cache[cache_key] = (now, smil_data)
                logger.debug(f"{self._provider}: Cached SMIL data for {cache_key}")
            else:
                logger.warning(
                    f"{self._provider}: No MPD URL or releasePid for "
                    f"{cache_key}, not caching"
                )

            return smil_data

        except Exception as e:
            logger.error(
                f"{self._provider}: Error getting SMIL data for {cache_key}: {e}"
            )
            return None

    # =========================================================================
    # Private – GN id resolution
    # =========================================================================

    def _resolve_gn_id_to_smil_url(self, gn_id: str) -> Optional[str]:
        """
        Resolve a Gracenote content id to the full theplatform selector URL.

        Returns manifest_script directly when available — it is already the
        correct URL and requires no further reconstruction.  Falls back to
        constructing a URL from selector + account_pid + content_id when
        manifest_script is absent but the guid was resolved via content_id.
        """
        if not self._vod_manager:
            logger.warning(
                f"{self._provider}: Cannot resolve GN id {gn_id}: "
                "VodManager not available"
            )
            return None
        try:
            if gn_id.startswith(VOD_PREFIX_EPISODE):
                result = self._vod_manager.get_children(f"episode:{gn_id}")
            elif (
                gn_id.startswith(VOD_PREFIX_MOVIE_MV)
                or gn_id.startswith(VOD_PREFIX_MOVIE_SH)
            ):
                result = self._vod_manager.get_children(f"movie:{gn_id}")
            else:
                result = self._vod_manager.get_children(gn_id)

            items = result.get("entries", []) if isinstance(result, dict) else result
            if not items:
                logger.warning(
                    f"{self._provider}: GN id {gn_id} resolution returned no items"
                )
                return None

            item = items[0]
            manifest_script: Optional[str] = getattr(item, "manifest_script", None)

            if manifest_script and "vodproductinformation" in manifest_script:
                logger.warning(
                    f"{self._provider}: {gn_id}: not entitled (subscriptionMissing)"
                )
                return None

            if manifest_script and "/media/" in manifest_script:
                logger.debug(f"{self._provider}: Resolved {gn_id} -> {manifest_script}")
                return manifest_script

            # Fallback: content_id is the guid — build URL from selector
            resolved_id: Optional[str] = getattr(item, "content_id", None)
            if resolved_id and resolved_id not in (
                gn_id, f"movie:{gn_id}", f"episode:{gn_id}"
            ):
                selector = self._endpoint_manager.get_endpoint("mpx_selector") or ""
                account_pid = (
                    self._provider_config.manifest.mpx.account_pid
                    if self._provider_config and self._provider_config.manifest
                    else ""
                )
                fallback_url = f"{selector}{account_pid}/media/{resolved_id}"
                logger.debug(
                    f"{self._provider}: Resolved {gn_id} -> {fallback_url} "
                    "(via content_id fallback)"
                )
                return fallback_url

            logger.warning(
                f"{self._provider}: GN id {gn_id} resolution returned no usable URL"
            )
        except Exception as exc:
            logger.warning(
                f"{self._provider}: GN id {gn_id} resolution failed: {exc}"
            )
        return None

    # =========================================================================
    # Private – HTTP
    # =========================================================================

    def _fetch_smil(
        self,
        channel_id: str,
        smil_base_url: Optional[str] = None,
    ) -> Optional[str]:
        """
        Fetch raw SMIL XML for any content type.

        Args:
            channel_id:    MPX GUID — used for logging and live channel URL
                           construction.
            smil_base_url: Pre-resolved theplatform URL for VOD / recordings.
                           When present, only the query params are appended.
                           When None the URL is built from selector + account_pid
                           + channel_id (live channel path).
        """
        logger.debug(f"{self._provider}: Fetching SMIL for {channel_id}")

        persona_token = self._auth()
        if not persona_token:
            logger.error(f"{self._provider}: No persona token for SMIL request")
            return None

        cid = f"{self._session_id}::{self._call_id()}"
        smil_params = f"?format=SMIL&formats=MPEG-DASH&tracking=true&cid={cid}"

        if smil_base_url:
            smil_url = f"{smil_base_url.split('?')[0]}{smil_params}"
        else:
            selector = self._endpoint_manager.get_endpoint("mpx_selector")
            if not selector:
                logger.error(f"{self._provider}: No mpx_selector endpoint")
                return None
            account_pid = (
                self._provider_config.manifest.mpx.account_pid
                if self._provider_config and self._provider_config.manifest
                else None
            )
            if not account_pid:
                logger.error(
                    f"{self._provider}: No account_pid for SMIL URL construction"
                )
                return None
            smil_url = f"{selector}{account_pid}/media/{channel_id}{smil_params}"

        headers = {
            "Authorization": f"Basic {persona_token}",
            "User-Agent": self._platform_config["user_agent"],
            "Accept": "application/smil+xml, application/xml;q=0.9, */*;q=0.8",
        }

        logger.debug(f"{self._provider}: SMIL URL: {smil_url}")
        try:
            decoded = base64.b64decode(persona_token).decode("utf-8")
            logger.debug(f"{self._provider}: Persona token preview: {decoded[:100]}...")
        except Exception:
            pass

        try:
            response = self._http.get(
                smil_url,
                operation="manifest_smil_drm",
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
        except Exception as e:
            logger.error(
                f"{self._provider}: SMIL request exception for {channel_id}: {e}"
            )
            return None

        if response.status_code != 200:
            logger.error(
                f"{self._provider}: SMIL request failed "
                f"[{response.status_code}] for {channel_id}"
            )
            return None

        smil_content = response.text
        if not smil_content:
            logger.error(f"{self._provider}: Empty SMIL response for {channel_id}")
            return None

        # Release concurrency lock immediately after receiving SMIL
        from .concurrency import extract_and_release_lock
        extract_and_release_lock(
            smil_content,
            self._http,
            client_id=SMIL_CLIENT_ID,
            user_agent=self._platform_config["user_agent"],
        )

        return smil_content

    # =========================================================================
    # Private – SMIL parsing
    # =========================================================================

    @staticmethod
    def _parse_mpd_url(smil_content: str, content_id: str) -> Optional[str]:
        """
        Extract the MPD URL from a SMIL response.

        Checks for real error signals first (unavailable content, invalid token,
        403).  A <ref> tag with title/abstract that does not match any error
        pattern is informational metadata (e.g. nPVR stream description) and
        is logged at DEBUG only.

        Resolution order:
          1. <video src="...">  (primary)
          2. <ref src="...">    (fallback)
        """
        try:
            logger.debug(f"Parsing SMIL for {content_id} ({len(smil_content)} chars)")

            error_match = re.search(
                r'<ref[^>]*title="([^"]*)"[^>]*abstract="([^"]*)"[^>]*>',
                smil_content,
            )
            if error_match:
                title = error_match.group(1)
                abstract = error_match.group(2)
                if "errorFiles/Unavailable.flv" in smil_content:
                    logger.error(
                        f"SMIL unavailable content for {content_id}: {title}"
                    )
                    return None
                if "Invalid Token" in title or "InvalidAuthToken" in smil_content:
                    logger.error(f"SMIL invalid token for {content_id}: {title}")
                    return None
                if "403" in smil_content:
                    logger.error(
                        f"SMIL access forbidden (403) for {content_id}: {title}"
                    )
                    return None
                # Not a real error — informational stream/nPVR metadata
                logger.debug(
                    f"SMIL stream info for {content_id}: {title} - {abstract}"
                )

            video_match = re.search(r'<video\s+src="([^"]+)"', smil_content)
            if video_match:
                mpd_url = video_match.group(1)
                logger.debug(f"Found MPD URL in <video> tag for {content_id}")
                ref_info = re.search(
                    r'<ref[^>]*src="([^"]*)"[^>]*title="([^"]*)"[^>]*abstract="([^"]*)"',
                    smil_content,
                )
                if ref_info and ref_info.group(1) == mpd_url:
                    logger.debug(
                        f"Stream info: {ref_info.group(2)} - {ref_info.group(3)}"
                    )
                return mpd_url

            ref_match = re.search(r'<ref\s+src="([^"]+)"', smil_content)
            if ref_match:
                mpd_url = ref_match.group(1)
                logger.debug(f"Found MPD URL in <ref> tag for {content_id}")
                full_ref = re.search(
                    r'<ref[^>]*src="%s"[^>]*title="([^"]*)"[^>]*abstract="([^"]*)"'
                    % re.escape(mpd_url),
                    smil_content,
                )
                if full_ref:
                    logger.debug(
                        f"Stream info: {full_ref.group(1)} - {full_ref.group(2)}"
                    )
                return mpd_url

            logger.warning(f"No MPD URL found in SMIL for {content_id}")
            if len(smil_content) < 1000:
                logger.debug(f"Full SMIL: {smil_content}")
            else:
                logger.debug(f"SMIL preview: {smil_content[:500]}...")
            return None

        except Exception as e:
            logger.error(f"Error parsing SMIL for {content_id}: {e}")
            return None

    @staticmethod
    def _parse_release_pid(smil_content: str) -> Optional[str]:
        """Extract releasePid from the SMIL trackingData parameter."""
        try:
            td_match = re.search(
                r'<param name="trackingData" value="([^"]*)"', smil_content
            )
            if not td_match:
                logger.warning("No trackingData found in SMIL")
                return None
            tracking_data = td_match.group(1)
            logger.debug(f"trackingData: {tracking_data}")
            pid_match = re.search(r"pid=([^|]+)", tracking_data)
            if pid_match:
                pid = pid_match.group(1)
                logger.debug(f"releasePid: {pid}")
                return pid
            logger.warning("No pid found in trackingData")
            return None
        except Exception as e:
            logger.error(f"Error extracting releasePid: {e}")
            return None

    # =========================================================================
    # Private – token / account helpers
    # =========================================================================

    @staticmethod
    def _extract_persona_jwt(persona_token: str) -> Optional[str]:
        """
        Extract the raw JWT from a Base64-encoded persona token.

        Persona token format:  Base64(account_uri + ":" + jwt)
        """
        try:
            decoded = base64.b64decode(persona_token).decode("utf-8")
            idx = decoded.rfind(":")
            if idx == -1:
                logger.error("No colon in decoded persona token")
                return None
            jwt = decoded[idx + 1:]
            if not jwt.startswith("eyJ"):
                logger.error("Extracted token is not a JWT")
                return None
            return jwt
        except Exception as e:
            logger.error(f"Error extracting persona JWT: {e}")
            return None

    def _get_account_uri(self) -> str:
        """Return the MPX account URI, falling back to the hardcoded constant."""
        if self._provider_config and self._provider_config.manifest:
            uri = self._provider_config.manifest.mpx.get_account_uri()
            if uri:
                return uri
        return MAGENTA2_FALLBACK_ACCOUNT_URI