# streaming_providers/providers/magenta2/channel_manager.py
# -*- coding: utf-8 -*-
"""
Manages channel discovery, metadata enrichment, entitlement, and streaming-data
population for the Magenta2 provider.
"""
import json
import re
import threading
import time
import uuid
from typing import Callable, Dict, List, Optional, Tuple

from ...base.errors import AuthPendingError, ProviderError
from ...base.models import StreamingChannel
from ...base.utils.logger import logger
from ..lib_theplatform import paginate_feed, PaginationError
from .constants import (
    CONTENT_TYPE_LIVE,
    DEFAULT_EPG_WINDOW_HOURS,
    DEFAULT_MAX_RETRIES,
    DEFAULT_REQUEST_TIMEOUT,
    DISTRIBUTION_PACKAGE_NAMES,
    DRM_SYSTEM_WIDEVINE,
    ENTITLED_FEED_FALLBACK_MIN_INTERVAL,
    ERROR_CODES,
    MODE_LIVE,
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
        user_agent_plain: str,
        user_agent_subscriber: str,
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
        self._ua_plain = user_agent_plain
        self._ua_subscriber = user_agent_subscriber
        self.catchup_window = catchup_window

        # Special-rights rules (e.g. "uhd" -> liveTvOption False) from the
        # manifest, used by _is_station_playable() to filter stations a
        # non-managed device/account isn't allowed to play live.
        self._special_rights = (
            provider_config.manifest.special_rights_profiles
            if provider_config and provider_config.manifest
            else {}
        )

        # Populated on first get_channels() call
        self._cached_channels: Optional[List[StreamingChannel]] = None

        # station_id (numeric) -> playback_id (opaque PID)
        self._station_to_playback_id: Dict[str, str] = {}

        # release_pid -> mpd_url (for fast manifest lookup)
        self._live_manifest_cache: Dict[str, str] = {}

        # release_pid -> release_pid (fast membership test for PlaybackManager)
        self._live_pid_cache: Dict[str, str] = {}

        # release_pid -> hls_url (feed-delivered HLS variant, if any).
        # Written by the same writers as _live_manifest_cache.
        self._live_hls_cache: Dict[str, str] = {}

        # Playback-time feed fallback (resolve_release_pid_via_feed):
        # serialises concurrent fallback fetches and rate-limits how often
        # an unvouched pid may trigger an entitled-channels feed refetch.
        self._feed_fallback_lock = threading.Lock()
        self._feed_fallback_last_run: float = 0.0

        # True once get_channels() has COMPLETED and overwritten the
        # station->pid map with feed-sourced release pids. Until then the
        # map holds only station-metadata MEDIA pids (from
        # _fetch_station_metadata, which runs once in __init__).
        #
        # Deliberately NOT reset by invalidate_cache(): the entries a
        # completed feed load wrote remain release pids afterwards, and
        # refusing to resolve through them would degrade playback to raw
        # station ids for no benefit. Pids gone stale after a feed change
        # are handled by the rate-limited re-fetch on pid miss
        # (PlaybackManager._prepare_live_pid).
        #
        # resolve_release_pid_via_feed() is a SECOND feed-loading writer:
        # at playback time it re-fetches the entitled-channels feed and
        # overwrites the map with release pids under the same provenance
        # argument (see that method for why: the SMIL/selector path can be
        # unusable for a live pid — e.g. UserAgentBlocked — while the feed
        # still carries both the release pid and the direct streamingUrl).
        #
        # Note the live manifest/pid caches above are a DIFFERENT signal:
        # populate_streaming_data() also fills them (channel-playlist
        # endpoint) without ever touching the station map, so their
        # non-emptiness must not be used to vouch for the map — see
        # has_release_pid_map() vs has_entitled_live_channels().
        self._station_pids_are_release: bool = False

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
            # ── Steps 1+2: distribution rights + entitled-channels feed ──
            # Shared with the playback-time fallback
            # (resolve_release_pid_via_feed) so both paths issue
            # byte-identical requests.
            distribution_rights, tp_channels = self._fetch_entitled_feed_data()

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

            # ── Step 3: merge with station metadata and build channels ──────
            channels: List[StreamingChannel] = []
            for tp_ch in tp_channels:
                try:
                    station_id = self._extract_station_id(tp_ch.station_id)
                    meta = self.station_metadata.get(station_id, {})

                    if not self._is_station_playable(meta.get("special_rights_profile")):
                        logger.debug(
                            f"Skipping {station_id} — special-rights blocked "
                            f"(profile={meta.get('special_rights_profile')})"
                        )
                        continue

                    name = meta.get("title") or tp_ch.station_id
                    logo_url = meta.get("logo_url")
                    quality = meta.get("quality")
                    channel_number = (
                        meta["channel_number"]
                        if meta.get("channel_number") is not None
                        else tp_ch.channel_number
                    )
                    playback_id = tp_ch.release_pid or meta.get("playback_id")

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

                    # Store mapping for DRM lookup + feed the live caches
                    # (shared writer with resolve_release_pid_via_feed so
                    # both feed-loading paths record identical semantics)
                    self._cache_live_pid(
                        station_id=station_id,
                        playback_id=playback_id,
                        mpd_url=tp_ch.mpd_url,
                        hls_url=tp_ch.hls_url,
                    )

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

                    channels.append(streaming_channel)
                except Exception as exc:
                    logger.warning(f"get_channels: skipping channel {tp_ch.station_id}: {exc}")

            logger.info(
                f"Successfully fetched {len(channels)} entitled channels "
                f"for country {self._country} "
                f"({len(self.station_metadata)} stations with metadata)"
            )
            channels.sort(key=lambda ch: (ch.channel_number is None, ch.channel_number or 0))
            # A feed load completed: every map entry written above is a
            # release pid, so station-id resolution may trust the map from
            # here on (see has_release_pid_map). Set even when some (or
            # all) channels were skipped — the flag vouches for the
            # PROVENANCE of the entries written, not for completeness;
            # stations the feed skipped keep their constructor-era media
            # pids and fail entitlement downstream, which is the honest
            # outcome for a non-entitled station.
            self._station_pids_are_release = True
            self._cached_channels = channels
            return channels

        except ProviderError:
            # Typed errors (AuthPendingError, AuthError, RateLimitError, ...)
            # must reach the route unchanged so it can pick the right status;
            # wrapping them in a bare Exception turned every one into a 500.
            raise
        except Exception as e:
            raise Exception(f"Error fetching channels from Magenta2 API: {e}") from e

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

    def get_live_manifest_url(self, playback_id: str) -> Optional[str]:
        """
        MPD URL for a live channel, as delivered by the entitled-channels
        feed (get_channels / resolve_release_pid_via_feed) or the
        channel-playlist endpoint — known before any SMIL call is ever
        made.

        Returns None for non-live / unknown ids.
        """
        return self._live_manifest_cache.get(playback_id)

    def get_live_hls_manifest_url(self, playback_id: str) -> Optional[str]:
        """
        HLS (M3U/CMAF) URL for a live channel, as delivered by the
        entitled-channels feed alongside the DASH MPD — None when the feed
        carried no HLS variant for this pid.
        """
        return self._live_hls_cache.get(playback_id)

    def is_entitled_live_pid(self, playback_id: str) -> bool:
        """
        True if *playback_id* is a release pid delivered by the
        entitled-channels feed.

        Membership is the entitlement verification for PlaybackManager's
        live fast paths (manifest cache hit / direct licence build): a pid
        in this cache came from the entitled feed; a pid outside it may be
        a station-metadata media pid, a stale post-refresh pid, or an
        unentitled one, and must not be promoted to a releasePid without
        the SMIL round-trip.
        """
        return playback_id in self._live_pid_cache

    def has_entitled_live_channels(self) -> bool:
        """
        True once the live manifest cache has been populated by an
        entitled source — the entitled-channels feed (get_channels or the
        playback-time fallback resolve_release_pid_via_feed) or the
        channel-playlist endpoint (populate_streaming_data). All are
        legitimately "entitled" sources: the playlist endpoint requires
        an entitlement token and restricted channels are skipped.

        NOTE: this does NOT imply the station-to-pid map holds release
        pids — populate_streaming_data() fills this cache without ever
        touching that map. Whether resolving a numeric station id through
        the map is safe is signalled by has_release_pid_map() instead.
        """
        return bool(self._live_manifest_cache)

    def has_release_pid_map(self) -> bool:
        """
        True once a full entitled-feed load has completed and overwritten
        the station-to-pid map with feed-sourced RELEASE pids — via
        get_channels() or the playback-time fallback
        resolve_release_pid_via_feed() — the signal that resolving a
        numeric station id through the map is safe.

        This, not has_entitled_live_channels(), is the guard
        PlaybackManager._resolve_station_id keys on: the live manifest/pid
        caches are also populated by populate_streaming_data()
        (channel-playlist endpoint), which never updates the station map,
        so keying on those caches would let a playlist-only population
        vouch for a map that still holds station-metadata MEDIA pids —
        the "error SMIL for a live channel" bug re-entered through the
        playlist door.

        Once True it stays True for the instance's lifetime: the only
        writer of media pids is _fetch_station_metadata(), which runs once
        in __init__. invalidate_cache() deliberately does not reset it —
        map entries written by a completed feed load remain release pids,
        and ones gone stale after a feed change are refreshed by the
        rate-limited re-fetch on pid miss.
        """
        return self._station_pids_are_release

    def resolve_release_pid_via_feed(
        self, station_id: str, force: bool = False
    ) -> Optional[str]:
        """
        Playback-time fallback: (re)resolve *station_id*'s RELEASE pid from
        the entitled-channels feed, bypassing the SMIL/selector round trip.

        Why this exists: a live channel can reach SMIL with a pid the
        platform refuses to resolve — a station-metadata MEDIA pid left in
        the map when the feed never (re)ran, a stale pid after a feed
        change, or content whose selector is user-agent-gated (observed:
        ``UserAgentBlocked`` / "User Agent Restriction" error-SMIL, HTTP
        200 + 539-byte error body, for a Sky Sport UHD station). The
        entitled-channels feed carries BOTH the release pid and the direct
        CDN streamingUrl (DASH MPD + HLS), so manifest AND DRM can be
        served without SMIL at all:

            pid      = channel_manager.resolve_release_pid_via_feed(sid)
            manifest = channel_manager.get_live_manifest_url(pid)
            drm      = live fast-path construction with release_pid=pid

        Behaviour:
          * Vouched fast path: if the station already maps to a pid that is
            in the entitled pid cache, it is returned WITHOUT a fetch.
          * Rate limit: at most one feed refetch per
            ENTITLED_FEED_FALLBACK_MIN_INTERVAL seconds per instance, so a
            genuinely unentitled station cannot hammer the feed on every
            playback attempt. force=True bypasses (user-initiated retry,
            admin refresh). Concurrent callers serialise on a lock; the
            loser profits from the winner's refreshed maps.
          * On the rate-limited path the current map entry is returned ONLY
            if it is vouched; a media/stale pid yields None (returning it
            would recreate the exact failure this method exists to fix).

        Side effects on a completed refetch: station->pid map and the live
        manifest/pid/hls caches are rewritten for EVERY feed entry (not
        just *station_id*), `_station_pids_are_release` is set, and a
        cached channel list is dropped so the next get_channels() rebuilds
        with the fresh pids.

        Returns the release pid, or None if the station is not in the feed
        (not entitled on this account) or the feed could not be fetched.
        Never raises.
        """
        vouched = self._vouched_pid_for_station(station_id)
        if vouched:
            return vouched

        if not force and (time.time() - self._feed_fallback_last_run) < (
            ENTITLED_FEED_FALLBACK_MIN_INTERVAL
        ):
            logger.debug(
                f"resolve_release_pid_via_feed: rate-limited — no feed refetch "
                f"for station {station_id}"
            )
            return None

        with self._feed_fallback_lock:
            # Re-check under the lock: a concurrent caller may have just
            # refreshed the maps (and the rate-limit timestamp).
            vouched = self._vouched_pid_for_station(station_id)
            if vouched:
                return vouched
            if not force and (time.time() - self._feed_fallback_last_run) < (
                ENTITLED_FEED_FALLBACK_MIN_INTERVAL
            ):
                return None

            logger.info(
                f"resolve_release_pid_via_feed: re-resolving station {station_id} "
                f"from the entitled-channels feed (pid not vouched or SMIL "
                f"path unusable)"
            )
            try:
                _, tp_channels = self._fetch_entitled_feed_data()
                applied = 0
                for tp_ch in tp_channels:
                    sid = self._extract_station_id(tp_ch.station_id)
                    if not sid or not tp_ch.release_pid:
                        continue
                    self._cache_live_pid(
                        station_id=sid,
                        playback_id=tp_ch.release_pid,
                        mpd_url=tp_ch.mpd_url,
                        hls_url=tp_ch.hls_url,
                    )
                    applied += 1
            except Exception as exc:
                logger.warning(
                    f"resolve_release_pid_via_feed: entitled-feed refetch failed "
                    f"for station {station_id}: {exc}"
                )
                return None
            finally:
                self._feed_fallback_last_run = time.time()

            if applied:
                # Same provenance argument as a completed get_channels()
                # feed load: every entry written above is a feed-sourced
                # release pid.
                self._station_pids_are_release = True
                # Cached StreamingChannels embed the old pids (cdm /
                # manifest_script); force a rebuild on next get_channels().
                self._cached_channels = None

            pid = self._vouched_pid_for_station(station_id)
            if pid:
                logger.info(
                    f"resolve_release_pid_via_feed: station {station_id} -> "
                    f"release pid {pid}"
                )
                return pid

            logger.warning(
                f"resolve_release_pid_via_feed: station {station_id} is not in "
                f"the entitled-channels feed (not entitled on this account?)"
            )
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
        except ProviderError:
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
            "User-Agent": self._ua_subscriber,
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

                except AuthPendingError:
                    # Retrying 3x per channel while waiting for the user would
                    # just burn time; surface it immediately.
                    raise

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
        # _station_pids_are_release is deliberately NOT reset here: it
        # tracks the PROVENANCE of the station->pid map (feed-written
        # release pids), which invalidation does not undo — only a fresh
        # instance (whose map holds constructor-era media pids) starts
        # False again. See has_release_pid_map().
        self._cached_channels = None
        self._live_manifest_cache.clear()
        self._live_pid_cache.clear()
        self._live_hls_cache.clear()
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
#                logger.debug(f"Extracted playback ID from era$mediaPids: {channel_id}")
                return channel_id
            return None
        except Exception as e:
            logger.warning(f"Error extracting playback ID from entry: {e}")
            return None

    def _vouched_pid_for_station(self, station_id: str) -> Optional[str]:
        """
        The station's map pid ONLY if it is a vouched release pid (member
        of the entitled pid cache — see is_entitled_live_pid). Media and
        stale pids yield None: playback must not be built on them.
        """
        pid = self._station_to_playback_id.get(station_id)
        if pid and pid in self._live_pid_cache:
            return pid
        return None

    def _cache_live_pid(
        self,
        station_id: str,
        playback_id: str,
        mpd_url: Optional[str],
        hls_url: Optional[str],
    ) -> None:
        """
        Single writer for the live mappings: station -> playback pid plus
        the pid-keyed live caches (DASH MPD, HLS, entitled-pid set).

        Shared by get_channels() and resolve_release_pid_via_feed() so the
        two feed-loading paths can never diverge on what a recorded entry
        means. mpd_url/hls_url are stored only when truthy: the entitled
        feed always carries streamingUrl, but skipping falsy values keeps
        cache-miss semantics clean (a stored None would be indistinguishable
        from "known to have no URL").
        """
        self._station_to_playback_id[station_id] = playback_id
        if mpd_url:
            self._live_manifest_cache[playback_id] = mpd_url
        if hls_url:
            self._live_hls_cache[playback_id] = hls_url
        self._live_pid_cache[playback_id] = playback_id

    def _fetch_entitled_feed_data(
        self,
    ) -> Tuple[List[str], List[TheplatformChannel]]:
        """
        Steps 1-2 shared by get_channels() and the playback-time feed
        fallback (resolve_release_pid_via_feed):

          1. getApplicableDistributionRights — license_service_url with
             Basic persona auth (cid correlation header).
          2. mdeprod-entitled-channels feed — filtered by the account's
             distribution rights, paginated by fetch_entitled_channels_feed.

        Returns (distribution_rights, tp_channels); raises on failure so
        callers choose their own degradation (get_channels wraps it into a
        ProviderError-preserving exception chain, the fallback logs and
        returns None).
        """
        rights_url = (
            self._provider_config.manifest.mpx.license_service_url
            if self._provider_config and self._provider_config.manifest
            else None
        )
        if not rights_url:
            raise RuntimeError("No license_service_url available")

        cid = f"{self._session_id}::{uuid.uuid4()}"
        user_agent = self._ua_subscriber

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
        return distribution_rights, tp_channels

    def _fetch_station_metadata(self) -> Dict[str, Dict]:
        metadata: Dict[str, Dict] = {}
        self._station_to_playback_id.clear()

        try:
            url = None
            if self._endpoint_manager:
                url = (
                        self._endpoint_manager.get_endpoint("channel_stations")
                        or self._endpoint_manager.get_endpoint("channel_list")
                )
            base_url = (
                    url
                    or "https://feed.entertainment.tv.theplatform.eu/f/mdeprod/mdeprod-channel-stations-main"
            )
            headers = self._get_api_headers(require_auth=False)

            def _fetch_page(start_index: int, page_size: int) -> Optional[Dict]:
                page_url = (
                    f"{base_url}?lang=short-de&sort=dt%24displayChannelNumber"
                    f"&range={start_index}-{start_index + page_size - 1}"
                )
                try:
                    response = self._http.get(
                        page_url, operation="api", headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT
                    )
                    response.raise_for_status()
                    return response.json()
                except Exception as exc:
                    logger.warning(f"_fetch_station_metadata: page fetch failed: {exc}")
                    return None

            try:
                entries = paginate_feed(
                    _fetch_page, items_per_page=1000, max_pages=10, feed_name="channel_stations"
                )
            except PaginationError as exc:
                logger.warning(
                    f"_fetch_station_metadata: {exc} — using "
                    f"{len(exc.partial_entries)} entries fetched before failure"
                )
                entries = exc.partial_entries

            for entry in entries:
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
                    special_rights_profile = (
                        station_info.get("dt$clientData", {}) or {}
                    ).get("specialRightsProfile")

                    if station_id in metadata:
                        logger.debug(f"Duplicate station entry: {station_id}")
                    else:
                        metadata[station_id] = {
                            "title": title,
                            "logo_url": logo_url,
                            "quality": quality,
                            "channel_number": channel_number,
                            "playback_id": playback_id,
                            "special_rights_profile": special_rights_profile,
                        }
                except Exception as exc:
                    logger.debug(f"_fetch_station_metadata: skipping entry: {exc}")

            logger.debug(
                f"_fetch_station_metadata: built metadata for {len(metadata)} stations, "
                f"{len(self._station_to_playback_id)} playback mappings"
            )
        except Exception as exc:
            logger.warning(f"_fetch_station_metadata: failed, channels will have no names: {exc}")

        return metadata

    def _is_station_playable(self, profile: Optional[str]) -> bool:
        """
        Return True if the manifest allows live playback of a station
        carrying this specialRightsProfile tag (e.g. "uhd").

        `profile` comes from station_metadata[station_id]["special_rights_profile"],
        which _fetch_station_metadata reads from the station feed's
        dt$clientData.specialRightsProfile. It is NOT read from the
        entitled-channels feed's tp_ch.extra — parse_entitled_channels_feed
        only carries distributionRightIds into `extra`, never dt$clientData,
        so reading it from there would always fail open (nothing filtered).

        A station is blocked only if:
          1. It carries a specialRightsProfile tag, AND
          2. The manifest has a rule for that tag, AND
          3. The rule says liveTvOption == False.

        No rule for a given tag means unrestricted (e.g. this is the case
        for UHD/Sky/DAZN on the MagentaTV One manifest).
        """
        if not profile:
            return True
        rule = self._special_rights.get(profile)
        if rule is None:
            return True
        return rule.live_tv_option

    def _get_api_headers(self, require_auth: bool = False) -> Dict[str, str]:
        headers = {
            "User-Agent": self._ua_subscriber if require_auth else self._ua_plain,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if require_auth:
            persona_token = self._ensure_authenticated()
            headers["Authorization"] = f"Basic {persona_token}"
        return headers