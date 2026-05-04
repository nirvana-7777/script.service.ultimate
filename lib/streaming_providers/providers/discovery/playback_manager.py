# streaming_providers/providers/discovery/playback_manager.py
"""
Discovery+ Playback Manager

Handles all streaming/playback concerns:
- Fetching and caching playback info (tokens valid for 24 hours)
- Extracting manifest URLs and DRM details from playback responses
- Building DRMConfig objects
- Populating StreamingChannel objects with streaming data
"""
import base64
import secrets
import time
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from ...base.models import DRMConfig, DRMSystem, LicenseConfig, StreamingChannel
from ...base.utils.logger import logger

from .constants import (
    BLACKLISTED_CDN_PREFIXES,
    CDN_MAX_RETRIES,
    PlatformOS,
    get_default_capabilities,
    get_default_device_info,
    get_drm_request_headers,
)
from .exceptions import ManifestFetchError, PlaybackRestrictedException


class DiscoveryPlaybackManager:
    """
    Manages playback info fetching and streaming data population for Discovery+.

    Responsibilities:
    - Building the playback request payload (device capabilities, DRM, ads)
    - Fetching playback info from the Discovery+ playback endpoint
    - Caching playback tokens keyed on ``edit_id`` until DRM expiration
    - Extracting manifest URLs and DRM scheme details from playback responses
    - Building DRMConfig objects for Widevine / PlayReady
    - Populating a list of StreamingChannel objects (``populate_streaming_data``)

    The shared ``_channels_cache`` dict is owned by the provider and passed in
    so the manager can resolve ``edit_id`` values without extra API calls.
    """

    def __init__(
            self,
            provider,  # DiscoveryProvider — avoid circular import
            playback_cache: Dict[str, tuple],
    ):
        self._provider = provider
        # {edit_id: (expiry_timestamp, playback_data)}
        self._playback_cache = playback_cache

    # =========================================================================
    # Public interface
    # =========================================================================

    def populate_streaming_data(
            self,
            channels: List[StreamingChannel],
            max_retries: int = 3,
    ) -> List[StreamingChannel]:
        """
        Populate streaming data for a list of StreamingChannel objects.

        ``channel.channel_id`` is the ``edit_id`` (playback identifier), so
        it is passed directly to ``get_cached_playback_info`` — no cache
        indirection required.

        Args:
            channels: StreamingChannel objects to populate.
            max_retries: Maximum retry attempts per channel.

        Returns:
            List of successfully populated channels.
        """
        successful_channels = []

        for channel in channels:
            retries = 0
            success = False
            is_restricted = False

            while retries < max_retries and not success and not is_restricted:
                try:
                    edit_id = channel.channel_id
                    if not edit_id:
                        logger.warning(
                            f"No edit_id (channel_id) for {channel.name}, skipping"
                        )
                        break

                    logger.debug(
                        f"Getting playback info for: {channel.name} "
                        f"(edit_id: {edit_id}, attempt {retries + 1})"
                    )

                    playback_data = self.get_playback_info_with_cdn_check(
                        edit_id=edit_id
                    )
                    streaming_data = self.extract_streaming_data(playback_data)

                    if streaming_data["manifest_url"]:
                        channel.manifest = streaming_data["manifest_url"]
                        channel.streaming_format = streaming_data[
                            "streaming_format"
                        ]

                        if streaming_data["license_url"]:
                            drm_config = self.build_drm_config(streaming_data)
                            if drm_config:
                                channel.drm_config = drm_config
                            channel.license_url = streaming_data["license_url"]
                            channel.cdm_type = streaming_data["drm_system"]

                        logger.info(
                            f"Streaming data populated for: {channel.name}"
                        )
                        successful_channels.append(channel)
                        success = True
                    else:
                        raise ManifestFetchError("No manifest URL in response")

                except PlaybackRestrictedException as e:
                    logger.warning(
                        f"Playback restricted for {channel.name}: {e}"
                    )
                    is_restricted = True

                except Exception as e:
                    retries += 1
                    if retries < max_retries:
                        logger.debug(
                            f"Retry {retries}/{max_retries} for "
                            f"{channel.name}: {e}"
                        )
                        time.sleep(1)
                    else:
                        logger.error(
                            f"Failed to get streaming data for "
                            f"{channel.name}: {e}"
                        )

        logger.info(
            f"Streaming data population complete: "
            f"{len(successful_channels)}/{len(channels)}"
        )
        return successful_channels

    def get_playback_info(self, edit_id: str, **kwargs) -> Dict:
        """
        Fetch playback information for the given edit_id.

        Args:
            edit_id: Content edit ID.
            **kwargs: Additional parameters (unused, reserved for future use).

        Returns:
            Playback info dictionary from the Discovery+ playback endpoint.

        Raises:
            ValueError: If edit_id is not provided.
            PlaybackRestrictedException: If the server returns PLAYBACK_RESTRICTED.
            ManifestFetchError: On any other HTTP / parse error.
        """
        if not edit_id:
            raise ValueError("edit_id is required for playback")

        headers = self._provider.get_auth_headers()
        payload = self._build_playback_payload(edit_id)

        try:
            response = self._provider.http_manager.post(
                self._provider.authenticator.playback_endpoint,
                operation="playback",
                headers=headers,
                json=payload,
                timeout=30,
            )

            if response.status_code >= 400:
                error_text = response.text
                logger.error(f"Playback error response: {error_text}")
                if "PLAYBACK_RESTRICTED" in error_text:
                    raise PlaybackRestrictedException(
                        reason=f"Playback restricted for {edit_id}",
                        error_code="PLAYBACK_RESTRICTED",
                    )
                response.raise_for_status()

            response.raise_for_status()
            return response.json()

        except PlaybackRestrictedException:
            raise
        except Exception as e:
            raise ManifestFetchError(
                f"Error getting playback info for edit_id {edit_id}: {e}"
            )

    # =========================================================================
    # Playback cache
    # =========================================================================

    def get_cached_playback_info(self, edit_id: str) -> Dict:
        """
        Return playback info for edit_id, using a time-based cache.

        Tokens issued by Discovery+ are valid for 24 hours.  The cache entry
        is kept until the ``drm_expiration`` timestamp returned in the response
        (minus a 60-second safety margin).  If no expiration is present a
        fallback TTL of 23 hours is used.

        Args:
            edit_id: Content edit ID.

        Returns:
            Playback info dictionary (from cache or freshly fetched).
        """
        now = time.time()
        cached = self._playback_cache.get(edit_id)

        if cached:
            expiry, data = cached
            if now < expiry:
                logger.debug(
                    f"Playback cache hit for edit_id {edit_id} "
                    f"(expires in {int(expiry - now)}s)"
                )
                return data
            else:
                logger.debug(
                    f"Playback cache expired for edit_id {edit_id}, re-fetching"
                )

        # CDN check + cache write are both handled inside get_playback_info_with_cdn_check.
        return self.get_playback_info_with_cdn_check(edit_id=edit_id)

    def _store_playback_cache(self, edit_id: str, data: Dict) -> None:
        """
        Compute the expiry timestamp from playback data and write it to the cache.

        Args:
            edit_id: Content edit ID used as the cache key.
            data: Playback API response dict.
        """
        now = time.time()
        expiry = None
        try:
            drm_expiration_str = data.get("drm", {}).get("expirationDate")
            if drm_expiration_str:
                dt = datetime.fromisoformat(
                    drm_expiration_str.replace("Z", "+00:00")
                )
                expiry = dt.timestamp() - 60
        except Exception as e:
            logger.debug(f"Could not parse drm_expiration: {e}")

        if expiry is None or expiry <= now:
            expiry = now + 23 * 3600
            logger.debug(
                f"Using fallback 23h TTL for playback cache "
                f"(edit_id: {edit_id})"
            )

        self._playback_cache[edit_id] = (expiry, data)
        logger.debug(
            f"Playback cache stored for edit_id {edit_id} "
            f"(expires in {int(expiry - now)}s)"
        )

    # =========================================================================
    # Payload / streaming data helpers
    # =========================================================================

    def _build_playback_payload(self, edit_id: str) -> Dict[str, Any]:
        """
        Build the playback request payload for the Discovery+ playback API.

        Args:
            edit_id: Content edit ID.

        Returns:
            JSON-serialisable payload dict.
        """
        nonce = secrets.token_bytes(256)
        google_pal_nonce = base64.b64encode(nonce).decode("ascii")

        return {
            "appBundle": "dplus",
            "advertisingInfo": {
                "adBlockerDetection": False,
                "debug": {},
                "device": {},
                "googlePALNonce": google_pal_nonce,
                "server": {
                    "deviceId": "",
                    "iabTCFString": "",
                    "isLimitedAdTracking": 0,
                    "nielsenAppId": "",
                },
                "ssaiProvider": {"version": "2.2.0"},
            },
            "consumptionType": "streaming",
            "deviceInfo": get_default_device_info(
                self._provider.platform_os,
                device_id=self._provider.authenticator.device_id,
            ),
            "editId": edit_id,
            "capabilities": get_default_capabilities(
                self._provider.platform_os
            ),
            "gdpr": False,
            "firstPlay": False,
            "playbackSessionId": str(uuid.uuid4()),
            "applicationSessionId": str(uuid.uuid4()),
            "userPreferences": {
                "videoQuality": "best",
                "uiLanguage": f"{self._provider.country.lower()}-{self._provider.country.upper()}",
            },
            "features": ["mlp"],
        }

    @staticmethod
    def extract_streaming_data(playback_data: Dict) -> Dict[str, Any]:
        """
        Extract streaming URLs and DRM info from a playback response.

        Detects whichever DRM scheme is present — either ``widevine``
        (Linux/Chrome) or ``playready`` (Windows/Edge) — so callers can build
        the correct DRMConfig without knowing which platform produced the
        response.

        Args:
            playback_data: Playback API response dict.

        Returns:
            Dictionary with keys:
              manifest_url     – DASH manifest URL
              license_url      – DRM license server URL (or None)
              drm_system       – 'widevine' | 'playready' | None
              drm_auth         – JWT auth token from license URL (or None)
              streaming_format – 'dash' (always for Discovery+)
              drm_expiration   – ISO-8601 expiration string (or None)
              fallback_manifest – Fallback manifest URL (or None)
        """
        result: Dict[str, Any] = {
            "manifest_url": None,
            "license_url": None,
            "drm_system": None,
            "drm_auth": None,
            "streaming_format": "dash",
            "drm_expiration": None,
            "fallback_manifest": None,
        }

        try:
            manifest = playback_data.get("manifest", {})
            if manifest:
                result["manifest_url"] = manifest.get("url")
                result["streaming_format"] = manifest.get("format", "dash")

            fallback = playback_data.get("fallback", {})
            if fallback:
                fallback_manifest = fallback.get("manifest", {})
                if fallback_manifest:
                    result["fallback_manifest"] = fallback_manifest.get("url")

            drm = playback_data.get("drm", {})
            if drm:
                result["drm_expiration"] = drm.get("expirationDate")
                schemes = drm.get("schemes", {})

                for scheme_name in ("widevine", "playready"):
                    scheme = schemes.get(scheme_name, {})
                    if scheme and scheme.get("licenseUrl"):
                        result["license_url"] = scheme["licenseUrl"]
                        result["drm_system"] = scheme_name

                        if "auth=" in result["license_url"]:
                            import urllib.parse
                            parsed = urllib.parse.urlparse(
                                result["license_url"]
                            )
                            query = urllib.parse.parse_qs(parsed.query)
                            if "auth" in query:
                                result["drm_auth"] = query["auth"][0]
                        break

            cdn = playback_data.get("cdn", {})
            if cdn:
                result["cdn_provider"] = cdn.get("provider")

        except Exception as e:
            logger.error(f"Error extracting streaming data: {e}")

        return result

    # =========================================================================
    # CDN helpers
    # =========================================================================

    @staticmethod
    def _extract_cdn_prefix(url: str) -> Optional[str]:
        """
        Extract the CDN prefix from a manifest URL.

        The prefix is the first label of the hostname.
        Example: ``https://cf.dplus.eu.prd.media.max.com/...`` → ``"cf"``

        Args:
            url: Manifest URL string.

        Returns:
            Lowercase CDN prefix, or None if the URL cannot be parsed.
        """
        try:
            import urllib.parse
            hostname = urllib.parse.urlparse(url).hostname or ""
            prefix = hostname.split(".")[0]
            return prefix.lower() if prefix else None
        except Exception:
            return None

    @staticmethod
    def _is_blacklisted_cdn(url: str) -> bool:
        """
        Return True if the manifest URL's CDN prefix is blacklisted.

        Args:
            url: Manifest URL string.

        Returns:
            True when the CDN prefix appears in BLACKLISTED_CDN_PREFIXES.
        """
        prefix = DiscoveryPlaybackManager._extract_cdn_prefix(url)
        return prefix in BLACKLISTED_CDN_PREFIXES

    def get_playback_info_with_cdn_check(self, edit_id: str) -> Dict:
        """
        Fetch playback info, retrying up to CDN_MAX_RETRIES times if the
        resolved manifest URL lands on a blacklisted CDN.

        Each retry issues a completely fresh playback request (bypassing the
        cache) so Discovery+ may route us to a different CDN node.  After all
        retries are exhausted the last response is returned regardless of CDN.

        Args:
            edit_id: Content edit ID.

        Returns:
            Playback info dictionary — CDN-filtered when possible.
        """
        playback_data: Dict = {}
        cdn_prefix: Optional[str] = None

        for attempt in range(1, CDN_MAX_RETRIES + 1):
            # Always fetch fresh — we need a new request to get a new CDN assignment.
            playback_data = self.get_playback_info(edit_id=edit_id)

            manifest_url = playback_data.get("manifest", {}).get("url", "")
            cdn_prefix = self._extract_cdn_prefix(manifest_url)

            if not self._is_blacklisted_cdn(manifest_url):
                if attempt > 1:
                    logger.info(
                        f"CDN check passed on attempt {attempt}/{CDN_MAX_RETRIES} "
                        f"(cdn={cdn_prefix}, edit_id={edit_id})"
                    )
                self._store_playback_cache(edit_id, playback_data)
                return playback_data

            logger.warning(
                f"Blacklisted CDN '{cdn_prefix}' on attempt {attempt}/{CDN_MAX_RETRIES} "
                f"for edit_id={edit_id} — retrying"
            )

        # All retries exhausted — accept whatever CDN we got last.
        logger.warning(
            f"All {CDN_MAX_RETRIES} CDN retries exhausted for edit_id={edit_id}; "
            f"accepting blacklisted CDN '{cdn_prefix}'"
        )
        self._store_playback_cache(edit_id, playback_data)
        return playback_data

    def build_drm_config(
            self, streaming_data: Dict[str, Any]
    ) -> Optional[DRMConfig]:
        """
        Build a DRMConfig from extracted streaming data.

        Selects the correct DRMSystem based on the scheme returned by the
        server (``streaming_data["drm_system"]``).  Falls back to the active
        ``platform_os`` when the scheme is absent.

        Supported schemes:
          'widevine'  → DRMSystem.WIDEVINE  (Linux/Chrome path)
          'playready' → DRMSystem.PLAYREADY (Windows/Edge path)

        Args:
            streaming_data: Dict returned by ``extract_streaming_data()``.

        Returns:
            DRMConfig instance, or None if no license URL is available.
        """
        license_url = streaming_data.get("license_url")
        if not license_url:
            return None

        drm_system_str = streaming_data.get("drm_system")
        if drm_system_str == "playready":
            drm_system = DRMSystem.PLAYREADY
        elif drm_system_str == "widevine":
            drm_system = DRMSystem.WIDEVINE
        else:
            drm_system = (
                DRMSystem.PLAYREADY
                if self._provider.platform_os == PlatformOS.WINDOWS
                else DRMSystem.WIDEVINE
            )
            logger.debug(
                f"drm_system not in streaming_data, inferred from platform_os "
                f"({self._provider.platform_os.value}): {drm_system.name}"
            )

        license_headers = get_drm_request_headers(self._provider.platform_os)

        return DRMConfig(
            system=drm_system,
            priority=1,
            license=LicenseConfig(
                server_url=license_url,
                req_headers=license_headers,
                req_data="{CHA-RAW}",
                use_http_get_request=False,
            ),
        )