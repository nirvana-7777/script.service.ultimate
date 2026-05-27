# streaming_providers/providers/magenta2/channel_manager.py
# -*- coding: utf-8 -*-
"""
Manages channel discovery, metadata enrichment, entitlement, and streaming-data
population for the Magenta2 provider.

Responsibilities
----------------
- Fetch and cache the unauthenticated channel-stations feed (_fetch_station_metadata)
- Build StreamingChannel objects from theplatform feed entries
- Fetch the entitled-channels feed and merge it with station metadata (get_channels)
- Request entitlement tokens and playlist data per channel
- Populate streaming data (manifest URL, DRM) for a set of channels

The live-manifest / live-pid caches live here because they are produced by
get_channels() and consumed by PlaybackManager via the provider's cache
attributes (_live_manifest_cache, _live_pid_cache).
"""
import json
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

    Parameters
    ----------
    http_manager:
        Shared HTTP manager (created by the provider).
    provider_name:
        Provider name string used when building StreamingChannel objects.
    country:
        Two-letter country code.
    platform_config:
        Platform-specific dict from MAGENTA2_PLATFORMS (user_agent, etc.).
    session_id:
        Session UUID shared with the provider instance.
    serial_number:
        Device serial UUID shared with the provider instance.
    endpoint_manager:
        Populated EndpointManager after discovery.
    provider_config:
        ProviderConfig after discovery.
    auth_callback:
        Callable[[], str] — returns a valid persona token (Basic-auth value).
        Provided by the provider as ``self._ensure_authenticated``.
    build_scaled_image_url_callback:
        Callable[[str], Optional[str]] — scales a logo URL.
        Provided by the provider.
    """

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

        # Populated on first get_channels() call; returned directly on subsequent calls.
        self._cached_channels: Optional[List[StreamingChannel]] = None

        # release_pid → mpd_url, keyed by release_pid (= channel_id after get_channels).
        self._live_manifest_cache: Dict[str, str] = {}
        # release_pid → release_pid (used as a fast membership test by PlaybackManager).
        self._live_pid_cache: Dict[str, str] = {}

        # Populated eagerly at provider init (unauthenticated call).
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
        """
        Fetch available channels via the entitled-channels flow.

        Uses lib_theplatform to:
          1. Call getApplicableDistributionRights (license_service_url from manifest).
          2. Fetch the entitled-channels feed filtered by those rights.
          3. Merge with station metadata pre-fetched at init time (unauthenticated).
          4. Convert each TheplatformChannel to a StreamingChannel.

        Results are cached after the first successful call; subsequent calls
        return from cache without hitting the network.
        """
        if self._cached_channels:
            logger.debug("get_channels: returning from cache (no network calls)")
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
                raise RuntimeError(
                    "No license_service_url available – configuration discovery may have failed"
                )

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

            # ── Step 3: merge with station metadata (pre-fetched at init) ────
            channels: List[StreamingChannel] = []
            for tp_ch in tp_channels:
                try:
                    meta = self.station_metadata.get(tp_ch.station_id, {})
                    name = meta.get("title") or tp_ch.station_id
                    logo_url = meta.get("logo_url")
                    quality = meta.get("quality")
                    channel_number = (
                        meta["channel_number"]
                        if meta.get("channel_number") is not None
                        else tp_ch.channel_number
                    )

                    magenta2_channel = Magenta2Channel(
                        name=name,
                        channel_id=tp_ch.release_pid,
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
                    if tp_ch.hls_url:
                        streaming_channel.hls_url = tp_ch.hls_url

                    self._live_manifest_cache[tp_ch.release_pid] = tp_ch.mpd_url
                    self._live_pid_cache[tp_ch.release_pid] = tp_ch.release_pid

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

    def get_entitlement_token(
        self, content_id: str, content_type: str = CONTENT_TYPE_LIVE
    ) -> str:
        """
        Request an entitlement token for *content_id* using the persona token
        (Basic auth).
        """
        self._ensure_authenticated()
        headers = self._get_api_headers(require_auth=True)
        payload = {"content_id": content_id, "content_type": content_type}

        url = (
            self._endpoint_manager.get_endpoint("entitlement")
            if self._endpoint_manager
            else "https://entitlement.p7s1.io/api/user/entitlement-token"
        )

        try:
            logger.debug(f"Requesting entitlement token for: {content_id}")
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
        if self._endpoint_manager and self._endpoint_manager.has_endpoint("channel_playlist"):
            url = self._endpoint_manager.get_endpoint("channel_playlist").format(
                channel_id=channel_id
            )
        else:
            url = f"https://api.magentatv.de/v1/channel/{channel_id}/playlist"

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
        """
        Populate manifest URL, DRM config, and streaming format for each channel
        by fetching an entitlement token and playlist.

        Channels that are restricted or repeatedly fail are silently dropped from
        the returned list.
        """
        self._ensure_authenticated()
        successful_channels = []

        for channel in channels:
            retries = 0
            success = False
            is_restricted = False

            while retries < max_retries and not success and not is_restricted:
                try:
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
                        channel.cdm_type = DRM_SYSTEM_WIDEVINE
                        channel.cdm = f"pid={channel.channel_id}"
                        channel.license_url = license_url
                        channel.certificate_url = certificate_url
                        channel.streaming_format = streaming_format
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
        """Clear the in-memory channel and live-manifest caches."""
        self._cached_channels = None
        self._live_manifest_cache.clear()
        self._live_pid_cache.clear()
        logger.debug("ChannelManager: caches cleared")

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _fetch_station_metadata(self) -> Dict[str, Dict]:
        """
        Fetch the unauthenticated channel-stations feed and return a lookup map
        keyed by the theplatform Station URI.

        The URI is the key of the ``stations`` dict in each feed entry, e.g.
        ``http://data.entertainment.tv.theplatform.eu/…/Station/265808936224``.
        This matches ``listings[0].stationId`` in the entitled-channels feed,
        which is what ``TheplatformChannel.station_id`` contains after parsing.

        Note: ``era$mediaPids["urn:theplatform:tv:location:any"]`` is a short
        opaque PID used for other purposes — it is NOT the mapping key.

        Each value dict contains:
            title        – display name (" - Main" suffix stripped)
            logo_url     – scaled logo URL or None
            quality      – "HD", "SD", etc.
            channel_number – display channel number or None
        """
        metadata: Dict[str, Dict] = {}
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

                    existing = metadata.get(station_uri)
                    if not existing or QUALITY_RANK.get(quality, 1) > QUALITY_RANK.get(
                        existing["quality"], 1
                    ):
                        metadata[station_uri] = {
                            "title": title,
                            "logo_url": logo_url,
                            "quality": quality,
                            "channel_number": channel_number,
                        }
                except Exception as exc:
                    logger.debug(f"_fetch_station_metadata: skipping entry: {exc}")

            logger.debug(
                f"_fetch_station_metadata: built metadata for {len(metadata)} stations"
            )
        except Exception as exc:
            logger.warning(
                f"_fetch_station_metadata: failed, channels will have no names: {exc}"
            )

        return metadata

    @staticmethod
    def _extract_channel_id_from_entry(entry: Dict) -> Optional[str]:
        """Extract the correct channel ID from ``era$mediaPids``."""
        try:
            stations = entry.get("stations", {})
            if not stations:
                return None
            station_id = next(iter(stations.keys()))
            station_info = stations[station_id]
            era_media_pids = station_info.get("era$mediaPids", {})
            channel_id = era_media_pids.get("urn:theplatform:tv:location:any")
            if channel_id:
                logger.debug(f"Extracted channel ID from era$mediaPids: {channel_id}")
                return channel_id
            fallback_id = entry.get("guid")
            if fallback_id:
                logger.warning(f"Using fallback channel ID from guid: {fallback_id}")
                return fallback_id
            logger.warning("No channel ID found in entry")
            return None
        except Exception as e:
            logger.warning(f"Error extracting channel ID from entry: {e}")
            return None

    def _create_channel_from_entry(
        self, entry: Dict, station_info: Dict, display_number
    ) -> Optional[StreamingChannel]:
        """Build a StreamingChannel from a raw feed entry."""
        try:
            title = station_info.get("title") or entry.get("title", "Unknown Channel")
            title = title.replace(" - Main", "")

            channel_id = self._extract_channel_id_from_entry(entry)
            if not channel_id:
                return None

            logo_url = None
            thumbnails = station_info.get("thumbnails", {})
            for logo_type in ["stationLogo", "stationLogoColored"]:
                if logo_type in thumbnails:
                    original_url = thumbnails[logo_type].get("url")
                    if original_url:
                        logo_url = self._build_scaled_image_url(original_url)
                        break

            magenta2_channel = Magenta2Channel(
                name=title,
                channel_id=channel_id,
                logo_url=logo_url,
                mode=MODE_LIVE,
                content_type=CONTENT_TYPE_LIVE,
                country=self._country,
                raw_data=entry,
            )
            streaming_channel = magenta2_channel.to_streaming_channel(
                provider_name=self._provider_name
            )
            streaming_channel.channel_number = display_number
            streaming_channel.quality = station_info.get("dt$quality", "SD")
            return streaming_channel

        except Exception as e:
            logger.warning(f"Error creating channel from entry: {e}")
            return None

    def _process_channel_stations_response_optimized(
        self, response_data: Dict, prefer_highest_quality: bool = True
    ) -> List[StreamingChannel]:
        """Single-pass deduplication and channel construction from a raw feed response."""
        if "entries" not in response_data:
            return []

        best_entries: Dict = {}
        channels: List[StreamingChannel] = []

        for entry in response_data["entries"]:
            try:
                stations = entry.get("stations", {})
                if not stations:
                    continue
                station_info = next(iter(stations.values()))
                display_number = entry.get("dt$displayChannelNumber")

                if display_number is None:
                    channel = self._create_channel_from_entry(
                        entry, station_info, display_number
                    )
                    if channel:
                        channels.append(channel)
                    continue

                quality = station_info.get("dt$quality", "SD")
                current_rank = QUALITY_RANK.get(quality, 1)

                existing = best_entries.get(display_number)
                if not existing:
                    best_entries[display_number] = (entry, station_info, current_rank)
                else:
                    _, _, existing_rank = existing
                    if (prefer_highest_quality and current_rank > existing_rank) or (
                        not prefer_highest_quality and current_rank < existing_rank
                    ):
                        best_entries[display_number] = (entry, station_info, current_rank)

            except Exception:
                continue

        for display_number, (entry, station_info, _) in best_entries.items():
            channel = self._create_channel_from_entry(entry, station_info, display_number)
            if channel:
                channels.append(channel)

        return channels

    def _get_api_headers(self, require_auth: bool = False) -> Dict[str, str]:
        """Build standard API request headers."""
        headers = {
            "User-Agent": self._platform_config["user_agent"],
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if require_auth:
            persona_token = self._ensure_authenticated()
            headers["Authorization"] = f"Basic {persona_token}"
        return headers