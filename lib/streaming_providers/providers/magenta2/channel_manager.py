# streaming_providers/providers/magenta2/channel_manager.py
# -*- coding: utf-8 -*-
"""
Manages channel discovery, metadata enrichment, entitlement, and streaming-data
population for the Magenta2 provider.
"""
import json
import re
import time
from typing import Callable, Dict, List, Optional

from ...base.models import StreamingChannel
from ...base.utils.logger import logger
from .constants import (
    CONTENT_TYPE_LIVE,
    DEFAULT_EPG_WINDOW_HOURS,
    DEFAULT_MAX_RETRIES,
    DEFAULT_REQUEST_TIMEOUT,
    DISTRIBUTION_PACKAGE_NAMES,
    DRM_SYSTEM_WIDEVINE,
    ERROR_CODES,
    MODE_LIVE,
    QUALITY_RANK,
)
from .endpoint_manager import EndpointManager
from .config_models import ProviderConfig
from .models import Magenta2Channel, Magenta2PlaybackRestrictedException
from ..lib_theplatform import (
    TheplatformChannel,
    fetch_distribution_rights,
    fetch_entitled_channels_feed,
)


class ChannelManager:
    """
    Handles all channel-related operations for Magenta2.

    ID Model (matches MagentaEU pattern):
    - content_id = station_id (numeric ID from stationId URI)
    - playback_id = opaque PID from era$mediaPids["urn:theplatform:tv:location:any"]
    - Both IDs are stored in manifest_script for later reference
    """

    # Pattern to extract numeric station ID from stationId URI
    _STATION_ID_PATTERN = re.compile(r"/Station/(\d+)$")

    def __init__(
        self,
        http_manager,
        provider_name: str,
        country: str,
        platform_config: Dict,
        session_id: str,
        serial_number: str,
        endpoint_manager: Optional[EndpointManager],
        provider_config: Optional[ProviderConfig],
        auth_callback: Callable[[], str],
        build_scaled_image_url_callback: Callable[[str], Optional[str]],
        catchup_window: int = 4,
    ):
        self._http = http_manager
        self._provider_name = provider_name
        self._country = country
        self._platform_config = platform_config
        self._session_id = session_id
        self._serial_number = serial_number
        self._endpoint_manager = endpoint_manager
        self._provider_config = provider_config
        self._ensure_authenticated = auth_callback
        self._build_scaled_image_url = build_scaled_image_url_callback
        self.catchup_window = catchup_window

        # Populated on first get_channels() call
        self._cached_channels: Optional[List[StreamingChannel]] = None

        # station_id (numeric) -> playback_id (opaque PID)
        self._station_to_playback_id: Dict[str, str] = {}

        # release_pid -> mpd_url (for fast manifest lookup)
        self._live_manifest_cache: Dict[str, str] = {}

        # release_pid -> release_pid (fast membership test for PlaybackManager)
        self._live_pid_cache: Dict[str, str] = {}

        # Pre-fetched station metadata (unauthenticated)
        self.station_metadata: Dict[str, Dict] = self._fetch_station_metadata()

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def get_channels(
        self,
        time_window_hours: int = DEFAULT_EPG_WINDOW_HOURS,
        fetch_manifests: bool = False,
        populate_streaming: bool = True,
        prefer_highest_quality: bool = True,
        **kwargs,
    ) -> List[StreamingChannel]:
        if self._cached_channels:
            logger.debug("get_channels: returning from cache")
            return list(self._cached_channels)

        try:
            import uuid
            cid = f"{self._session_id}::{str(uuid.uuid4())}"
            user_agent = self._platform_config["user_agent"]

            # ── Step 1: distribution rights ──────────────────────────────────
            rights_url = (
                self._provider_config.manifest.mpx.license_service_url
                if self._provider_config and self._provider_config.manifest
                else None
            )
            if not rights_url:
                raise RuntimeError("No license_service_url available")

            persona_token = self._ensure_authenticated()
            auth_headers = {
                "Authorization": f"Basic {persona_token}",
                "Origin": "https://www.magenta.tv",
                "Referer": "https://www.magenta.tv/",
            }

            distribution_rights = fetch_distribution_rights(
                http_manager=self._http,
                rights_url=rights_url,
                cid=cid,
                user_agent=user_agent,
                timeout=DEFAULT_REQUEST_TIMEOUT,
                extra_headers=auth_headers,
            )

            def _dist_uri_to_int(uri) -> Optional[int]:
                try:
                    return int(str(uri).rstrip("/").rsplit("/", 1)[-1])
                except (ValueError, AttributeError):
                    return None

            package_names = [
                DISTRIBUTION_PACKAGE_NAMES.get(numeric_id, f"Unknown package ({dist_id})")
                for dist_id in distribution_rights
                if (numeric_id := _dist_uri_to_int(dist_id)) is not None
            ]
            logger.info(f"Active subscription packages ({len(package_names)}):")
            for pkg in package_names:
                logger.info(f"  · {pkg}")

            # ── Step 2: entitled-channels feed ───────────────────────────────
            feed_url = (
                self._endpoint_manager.get_endpoint("mpx_feed_entitledChannelsFeed")
                if self._endpoint_manager
                else None
            ) or "https://feed.entertainment.tv.theplatform.eu/f/mdeprod/mdeprod-entitled-channels"

            tp_channels: List[TheplatformChannel] = fetch_entitled_channels_feed(
                http_manager=self._http,
                feed_url=feed_url,
                distribution_rights=distribution_rights,
                cid=cid,
                user_agent=user_agent,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )

            # ── Step 3: merge with station metadata and build channels ──────
            channels: List[StreamingChannel] = []
            for tp_ch in tp_channels:
                try:
                    station_id = self._extract_station_id(tp_ch.station_id)
                    meta = self.station_metadata.get(station_id, {})
                    name = meta.get("title") or tp_ch.station_id
                    logo_url = meta.get("logo_url")
                    quality = meta.get("quality")
                    channel_number = (
                        meta["channel_number"]
                        if meta.get("channel_number") is not None
                        else tp_ch.channel_number
                    )
                    playback_id = meta.get("playback_id") or tp_ch.release_pid

                    if not station_id or not playback_id:
                        logger.warning(
                            f"Skipping channel {name}: missing station_id={station_id}, "
                            f"playback_id={playback_id}"
                        )
                        continue

                    catchup_hours = getattr(tp_ch, 'catchup_hours', None) or self.catchup_window

                    # Build manifest_script with both IDs (like MagentaEU)
                    manifest_script_parts = []
                    if channel_number:
                        manifest_script_parts.append(f"chno={channel_number}")
                    if station_id:
                        manifest_script_parts.append(f"station={station_id}")
                    if playback_id:
                        manifest_script_parts.append(f"pid={playback_id}")
                    manifest_script = " ".join(manifest_script_parts) if manifest_script_parts else ""

                    # Store mapping for DRM lookup
                    self._station_to_playback_id[station_id] = playback_id

                    magenta2_channel = Magenta2Channel(
                        name=name,
                        channel_id=station_id,  # content_id = station_id (matches MagentaEU)
                        logo_url=logo_url,
                        mode=MODE_LIVE,
                        content_type=CONTENT_TYPE_LIVE,
                        country=self._country,
                        raw_data=tp_ch.extra,
                    )
                    streaming_channel = magenta2_channel.to_streaming_channel(
                        provider_name=self._provider_name
                    )
                    streaming_channel.channel_number = channel_number
                    streaming_channel.quality = quality
                    streaming_channel.manifest = tp_ch.mpd_url
                    streaming_channel.manifest_script = manifest_script
                    streaming_channel.cdm_type = DRM_SYSTEM_WIDEVINE
                    streaming_channel.cdm = f"pid={playback_id}"
                    streaming_channel.cdm_mode = "external"
                    streaming_channel.catchup_hours = catchup_hours

                    if tp_ch.hls_url:
                        streaming_channel.hls_url = tp_ch.hls_url

                    self._live_manifest_cache[playback_id] = tp_ch.mpd_url
                    self._live_pid_cache[playback_id] = playback_id  # For PlaybackManager fast-path

                    channels.append(streaming_channel)
                except Exception as exc:
                    logger.warning(f"get_channels: skipping channel {tp_ch.station_id}: {exc}")

            logger.info(
                f"Successfully fetched {len(channels)} entitled channels "
                f"for country {self._country} "
                f"({len(self.station_metadata)} stations with metadata)"
            )
            channels.sort(key=lambda ch: (ch.channel_number is None, ch.channel_number or 0))
            self._cached_channels = channels
            return channels

        except Exception as e:
            raise Exception(f"Error fetching channels from Magenta2 API: {e}")

    def get_playback_id_for_station(self, station_id: str) -> Optional[str]:
        """Get the playback ID (opaque PID) for a station ID."""
        return self._station_to_playback_id.get(station_id)

    def get_station_id_for_channel(self, channel: StreamingChannel) -> Optional[str]:
        """Get the station ID from a channel's manifest_script."""
        if not channel.manifest_script:
            return None
        # Parse "station=123456" from manifest_script
        for part in channel.manifest_script.split():
            if part.startswith("station="):
                return part.split("=", 1)[1]
        return None

    def get_playback_id_from_channel(self, channel: StreamingChannel) -> Optional[str]:
        """Get the playback ID from a channel's manifest_script or cdm field."""
        # Try cdm field first
        if channel.cdm and channel.cdm.startswith("pid="):
            return channel.cdm.split("=", 1)[1]
        # Fall back to manifest_script
        if channel.manifest_script:
            for part in channel.manifest_script.split():
                if part.startswith("pid="):
                    return part.split("=", 1)[1]
        return None

    def get_entitlement_token(
        self, content_id: str, content_type: str = CONTENT_TYPE_LIVE
    ) -> str:
        """
        Request an entitlement token for *content_id*.

        Note: content_id here is the station_id (numeric). We need to map
        it to playback_id for the entitlement request.
        """
        self._ensure_authenticated()

        # Map station_id -> playback_id
        playback_id = self._station_to_playback_id.get(content_id)
        if not playback_id:
            raise ValueError(f"No playback ID found for station {content_id}")

        headers = self._get_api_headers(require_auth=True)
        payload = {"content_id": playback_id, "content_type": content_type}

        url = (
            self._endpoint_manager.get_endpoint("entitlement")
            if self._endpoint_manager
            else "https://entitlement.p7s1.io/api/user/entitlement-token"
        )

        try:
            logger.debug(f"Requesting entitlement token for: {content_id} (playback: {playback_id})")
            response = self._http.post(
                url,
                operation="auth",
                headers=headers,
                json_data=payload,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )

            if response.status_code == 400:
                try:
                    error_data = response.json()
                    error_list = error_data if isinstance(error_data, list) else [error_data]
                    if error_list:
                        error = error_list[0]
                        code = error.get("code", error.get("errorCode", "UNKNOWN"))
                        msg = error.get("msg", error.get("message", "No error message provided"))
                        if code == ERROR_CODES["PLAYBACK_RESTRICTED"]:
                            raise Magenta2PlaybackRestrictedException(
                                f"Playback restricted for {content_id}: {msg}"
                            )
                        else:
                            raise Exception(f"Entitlement error for {content_id} ({code}): {msg}")
                except (json.JSONDecodeError, KeyError, IndexError) as e:
                    raise Exception(
                        f"Bad response for {content_id} (400), failed to parse error: {e}"
                    )

            response.raise_for_status()
            data = response.json()

            if "entitlement_token" in data:
                return data["entitlement_token"]
            elif "entitlementToken" in data:
                return data["entitlementToken"]
            elif "token" in data:
                return data["token"]
            else:
                raise KeyError("No entitlement token found in response")

        except Magenta2PlaybackRestrictedException:
            raise
        except KeyError as e:
            logger.error(f"No entitlement token in response for {content_id}: {e}")
            raise Exception(f"No entitlement token in response for {content_id}: {e}")
        except Exception as e:
            logger.error(f"Error getting entitlement token for {content_id}: {e}")
            raise Exception(f"Error getting entitlement token for {content_id}: {e}")

    def get_channel_playlist(self, channel_id: str, entitlement_token: str) -> Dict:
        """Fetch playlist data (manifest URL, licence URL, format) for a channel."""
        # channel_id here is the station_id, but the API expects playback_id
        playback_id = self._station_to_playback_id.get(channel_id)
        if not playback_id:
            raise ValueError(f"No playback ID found for station {channel_id}")

        if self._endpoint_manager and self._endpoint_manager.has_endpoint("channel_playlist"):
            url = self._endpoint_manager.get_endpoint("channel_playlist").format(
                channel_id=playback_id
            )
        else:
            url = f"https://api.magentatv.de/v1/channel/{playback_id}/playlist"

        headers = {
            "Authorization": f"Bearer {entitlement_token}",
            "User-Agent": self._platform_config["user_agent"],
            "Accept": "application/json",
        }

        try:
            response = self._http.get(
                url,
                operation="manifest",
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise Exception(f"Error getting playlist for {channel_id}: {e}")

    def populate_streaming_data(
        self,
        channels: List[StreamingChannel],
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> List[StreamingChannel]:
        self._ensure_authenticated()
        successful_channels = []

        for channel in channels:
            retries = 0
            success = False
            is_restricted = False

            while retries < max_retries and not success and not is_restricted:
                try:
                    # Use channel.channel_id (station_id) for entitlement
                    logger.debug(
                        f"Getting entitlement token for: {channel.name} (attempt {retries + 1})"
                    )
                    entitlement_token = self.get_entitlement_token(
                        content_id=channel.channel_id, content_type=channel.content_type
                    )
                    logger.debug(f"Getting playlist data for: {channel.name}")
                    playlist_data = self.get_channel_playlist(
                        channel.channel_id, entitlement_token
                    )

                    manifest_url = playlist_data.get(
                        "manifestUrl", playlist_data.get("manifest")
                    )
                    license_url = playlist_data.get(
                        "licenseUrl", playlist_data.get("license")
                    )
                    certificate_url = playlist_data.get(
                        "certificateUrl", playlist_data.get("certificate")
                    )
                    streaming_format = playlist_data.get(
                        "streamingFormat", playlist_data.get("format", "dash")
                    )

                    if manifest_url:
                        channel.manifest = manifest_url
                        channel.license_url = license_url
                        channel.certificate_url = certificate_url
                        channel.streaming_format = streaming_format

                        # Update manifest cache
                        playback_id = self.get_playback_id_from_channel(channel)
                        if playback_id:
                            self._live_manifest_cache[playback_id] = manifest_url
                            self._live_pid_cache[playback_id] = playback_id  # For PlaybackManager

                        logger.info(f"Streaming data populated for: {channel.name}")
                        successful_channels.append(channel)
                        success = True
                    else:
                        raise Exception("No manifest URL in response")

                except Magenta2PlaybackRestrictedException as e:
                    logger.warning(f"Playback restricted for {channel.name}: {e}")
                    is_restricted = True

                except Exception as e:
                    retries += 1
                    if retries < max_retries:
                        logger.debug(f"Retry {retries}/{max_retries} for {channel.name}: {e}")
                        time.sleep(1)
                    else:
                        logger.error(f"Failed to get streaming data for {channel.name}: {e}")

        logger.info(
            f"Streaming data population complete: "
            f"{len(successful_channels)} successful, "
            f"{len(channels) - len(successful_channels)} failed/restricted, "
            f"{len(channels)} total"
        )
        return successful_channels

    def invalidate_cache(self) -> None:
        self._cached_channels = None
        self._live_manifest_cache.clear()
        self._live_pid_cache.clear()
        logger.debug("ChannelManager: caches cleared")

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _extract_station_id(station_uri: str) -> Optional[str]:
        """Extract numeric station ID from a stationId URI."""
        if not station_uri:
            return None
        match = ChannelManager._STATION_ID_PATTERN.search(station_uri)
        return match.group(1) if match else None

    @staticmethod
    def _extract_channel_id_from_entry(entry: Dict) -> Optional[str]:
        """Extract the opaque playback PID from era$mediaPids."""
        try:
            stations = entry.get("stations", {})
            if not stations:
                return None
            station_id = next(iter(stations.keys()))
            station_info = stations[station_id]
            era_media_pids = station_info.get("era$mediaPids", {})
            channel_id = era_media_pids.get("urn:theplatform:tv:location:any")
            if channel_id:
                logger.debug(f"Extracted playback ID from era$mediaPids: {channel_id}")
                return channel_id
            return None
        except Exception as e:
            logger.warning(f"Error extracting playback ID from entry: {e}")
            return None

    def _fetch_station_metadata(self) -> Dict[str, Dict]:
        """
        Fetch the unauthenticated channel-stations feed and build metadata.

        Returns a dict keyed by station_id (numeric), each value containing:
            title, logo_url, quality, channel_number, playback_id
        """
        metadata: Dict[str, Dict] = {}
        self._station_to_playback_id.clear()

        try:
            url = None
            if self._endpoint_manager:
                url = (
                    self._endpoint_manager.get_endpoint("channel_stations")
                    or self._endpoint_manager.get_endpoint("channel_list")
                )
            url = (
                url
                or "https://feed.entertainment.tv.theplatform.eu/f/mdeprod/mdeprod-channel-stations-main"
            )
            url += "?lang=short-de&sort=dt%24displayChannelNumber&range=1-1000"

            headers = self._get_api_headers(require_auth=False)
            response = self._http.get(
                url, operation="api", headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()

            for entry in data.get("entries", []):
                try:
                    stations = entry.get("stations", {})
                    if not stations:
                        continue
                    station_uri = next(iter(stations.keys()))
                    station_info = stations[station_uri]

                    station_id = self._extract_station_id(station_uri)
                    if not station_id:
                        continue

                    playback_id = self._extract_channel_id_from_entry(entry)
                    if playback_id:
                        self._station_to_playback_id[station_id] = playback_id

                    title = (
                        station_info.get("title") or entry.get("title", "")
                    ).replace(" - Main", "")
                    quality = station_info.get("dt$quality", "SD")

                    logo_url = None
                    thumbnails = station_info.get("thumbnails", {})
                    for logo_type in ["stationLogo", "stationLogoColored"]:
                        if logo_type in thumbnails:
                            original_url = thumbnails[logo_type].get("url")
                            if original_url:
                                logo_url = self._build_scaled_image_url(original_url)
                                break

                    channel_number = entry.get("dt$displayChannelNumber")

                    existing = metadata.get(station_id)
                    if not existing or QUALITY_RANK.get(quality, 1) > QUALITY_RANK.get(
                        existing["quality"], 1
                    ):
                        metadata[station_id] = {
                            "title": title,
                            "logo_url": logo_url,
                            "quality": quality,
                            "channel_number": channel_number,
                            "playback_id": playback_id,
                        }
                except Exception as exc:
                    logger.debug(f"_fetch_station_metadata: skipping entry: {exc}")

            logger.debug(
                f"_fetch_station_metadata: built metadata for {len(metadata)} stations, "
                f"{len(self._station_to_playback_id)} playback mappings"
            )
        except Exception as exc:
            logger.warning(
                f"_fetch_station_metadata: failed, channels will have no names: {exc}"
            )

        return metadata

    def _get_api_headers(self, require_auth: bool = False) -> Dict[str, str]:
        headers = {
            "User-Agent": self._platform_config["user_agent"],
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if require_auth:
            persona_token = self._ensure_authenticated()
            headers["Authorization"] = f"Basic {persona_token}"
        return headers