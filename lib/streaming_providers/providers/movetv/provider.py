# streaming_providers/providers/movetv/provider.py
import re
import time
import threading
import requests
from collections import OrderedDict
from datetime import datetime, timezone
from typing import ClassVar, Dict, List, Optional, Any, Tuple

from ...base.models import DRMConfig, StreamingChannel
from ...base.models.proxy_models import ProxyConfig
from ...base.models.epg_models import EPGEntry
from ...base.provider import StreamingProvider
from ...base.utils.logger import logger
from .auth import MoveTVAuthenticator
from .constants import MoveTVConfig

from .vod_manager import (
    MoveTvVodManager,
    VodFilters,
    VodPage,
)

from .epg_manager import MoveTvEpgManager


class _SourceCache:
    """Thread-safe LRU-like cache for source URLs and Play-Auth headers."""

    def __init__(self, max_size: int = 100):
        self._cache: OrderedDict[str, tuple] = OrderedDict()
        self._lock = threading.Lock()
        self._max_size = max_size

    def get(self, key: str) -> Optional[tuple]:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
            return None

    def set(self, key: str, value: tuple) -> None:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = value
            if len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

    def pop(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._cache.pop(key, default)


class MoveTVChannel(StreamingChannel):
    """
    Extends StreamingChannel with move.tv-specific fields.
    """
    _PLAY_AUTH_EARLY_EXPIRY_BUFFER: int = 60

    def __init__(self, *args, live_id: int = 0, catchup_hours: int = 0,
                 stream_uid: str = "", play_auth_header: str = "",
                 play_auth_expires_at: float = 0.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.live_id: int = live_id
        self.catchup_hours: int = catchup_hours
        self.stream_uid: str = stream_uid
        self.play_auth_header: str = play_auth_header
        self.play_auth_expires_at: float = play_auth_expires_at

    def is_play_auth_valid(self) -> bool:
        if not self.play_auth_header or self.play_auth_expires_at == 0.0:
            return False
        return time.time() < (self.play_auth_expires_at - self._PLAY_AUTH_EARLY_EXPIRY_BUFFER)

    def to_dict(self) -> Dict:
        result = super().to_dict()
        result["LiveId"] = self.live_id
        result["CatchupHours"] = self.catchup_hours
        result["StreamUid"] = self.stream_uid
        result["PlayAuthHeader"] = self.play_auth_header
        result["PlayAuthExpiresAt"] = self.play_auth_expires_at
        return result


class MoveTVProvider(StreamingProvider):
    """
    Streaming provider for move.tv (MTS-SI platform).
    """

    PROVIDER_LABEL: ClassVar[str] = "move.tv"
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["user_credentials"]

    _PLAY_AUTH_EXPIRY_RE = re.compile(r"expires-(\d+)")

    def __init__(
            self,
            country: str = "SI",
            config: Optional[Dict] = None,
            proxy_config: Optional[ProxyConfig] = None,
            settings_manager=None,
    ):
        super().__init__(country)

        self.http_manager = self._setup_http_manager(
            provider_name="movetv",
            proxy_config=proxy_config,
            user_agent=MoveTVConfig.USER_AGENT,
            timeout=MoveTVConfig.TIMEOUT,
        )

        self.authenticator = MoveTVAuthenticator(
            proxy_config=proxy_config,
            http_manager=self.http_manager,
            settings_manager=settings_manager,
        )

        self._vod = MoveTvVodManager(self)
        self._epg = MoveTvEpgManager(self.authenticator)

        self.http_manager = self._share_http_manager_with_authenticator(self.authenticator)

        # Unified thread-safe LRU cache for both Live and Catchup sources.
        # Keyed by content_id (live) or content_id:epg_id (catchup).
        # Also stores entries keyed by the content_url itself so segment/manifest
        # header requests can look them up safely.
        self._source_cache = _SourceCache(max_size=200)

        # EPG response cache to prevent hammering the API on rapid manifest polls
        self._epg_cache: Dict[str, Tuple[List[EPGEntry], float]] = {}
        self._epg_lock = threading.Lock()

        try:
            self.authenticator.authenticate()
            logger.info("move.tv: Authentication successful during initialisation")
        except Exception as exc:
            logger.warning(f"move.tv: Could not authenticate during initialisation: {exc}")

    # ------------------------------------------------------------------
    # StreamingProvider identity properties
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return "movetv"

    @property
    def provider_label(self) -> str:
        return self.PROVIDER_LABEL

    @property
    def provider_logo(self) -> str:
        return MoveTVConfig.PROVIDER_LOGO

    @property
    def uses_dynamic_manifests(self) -> bool:
        return True

    @property
    def supported_auth_types(self) -> List[str]:
        return self.SUPPORTED_AUTH_TYPES

    @property
    def requires_manifest_context(self) -> bool:
        return True

    @property
    def catchup_window(self) -> int:
        return 168  # 7 days

    @property
    def supports_catchup(self) -> bool:
        return True

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _authenticated_headers(self) -> Dict[str, str]:
        auth_token = self.authenticator.get_auth_token()
        return MoveTVConfig.get_api_headers(auth_token=auth_token)

    def _channel_by_id(self, content_id: str) -> Optional[MoveTVChannel]:
        for ch in (self.channels or []):
            if isinstance(ch, MoveTVChannel) and ch.content_id == content_id:
                return ch
        return None

    def _get_channel_with_rebuild(self, content_id: str) -> Optional[MoveTVChannel]:
        channel = self._channel_by_id(content_id)
        if channel is None:
            logger.info(f"move.tv: Channel not found for {content_id}; rebuilding cache...")
            self.get_channels()
            channel = self._channel_by_id(content_id)
        return channel

    def _fetch_source_endpoint(
            self, url: str, payload: Dict[str, Any], content_id: str, cache_key: str, operation: str = "manifest"
    ) -> Optional[Dict[str, Any]]:
        """
        Unified POST method for fetching live or catchup source manifests.
        Handles caching, 401 retries, and Play-Auth extraction.
        """
        # 1. Check Cache
        cached = self._source_cache.get(cache_key)
        if cached:
            content_url, header_value, expires_at = cached
            if expires_at and time.time() < (expires_at - MoveTVChannel._PLAY_AUTH_EARLY_EXPIRY_BUFFER):
                logger.debug(f"move.tv: Cache hit for {operation} (key={cache_key})")
                return {"content_url": content_url, "protection": {"headerValue": header_value}}
            else:
                logger.debug(f"move.tv: Cache expired for {operation} (key={cache_key})")

        # 2. Get Session
        session = self.authenticator.get_session_info()
        if not session:
            logger.info(f"move.tv: No session info; re-authenticating before {operation} fetch")
            self.authenticator.authenticate(force_refresh=True)
            session = self.authenticator.get_session_info()

        if not session:
            logger.error(f"move.tv: Unable to obtain session info for {operation} fetch")
            return None

        # 3. Prepare Payload
        payload["customerId"] = session["customer_id"]
        payload["customerProfileId"] = session["customer_profile_id"]
        payload["appVersion"] = MoveTVConfig.APP_VERSION
        payload["dtype"] = MoveTVConfig.DTYPE_DASH

        headers = MoveTVConfig.get_api_headers(auth_token=session["auth_token"])

        # 4. Execute POST with 401 Retry
        try:
            response = self.http_manager.post(url, operation=operation, json=payload, headers=headers)
            is_401 = response.status_code == 401
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 401:
                is_401 = True
                response = exc.response
            else:
                logger.error(f"move.tv: HTTP error during {operation} fetch: {exc}")
                raise

        if is_401:
            logger.info(f"move.tv: 401 on {operation} fetch — attempting token refresh …")
            token = self.authenticator.get_current_token()
            refreshed = self.authenticator.refresh_token(token) if token else None
            if not refreshed:
                logger.info("move.tv: Refresh failed, falling back to full login")
                self.authenticator.authenticate(force_refresh=True)

            session = self.authenticator.get_session_info()
            if not session:
                logger.error("move.tv: Unable to obtain session after token refresh")
                return None

            payload["customerId"] = session["customer_id"]
            payload["customerProfileId"] = session["customer_profile_id"]
            headers = MoveTVConfig.get_api_headers(auth_token=session["auth_token"])

            try:
                response = self.http_manager.post(url, operation=operation, json=payload, headers=headers)
            except requests.HTTPError as exc:
                logger.error(f"move.tv: HTTP error during {operation} fetch retry: {exc}")
                raise

        # 5. Parse Response
        try:
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            logger.error(f"move.tv: Failed to parse {operation} response: {exc}")
            return None

        if not data.get("success"):
            logger.warning(f"move.tv: {operation} source endpoint returned success=false")
            return None

        # 6. Cache and Return
        content_url = data.get("content_url")
        protection = data.get("protection", {})
        header_value = protection.get("headerValue", "")

        expires_at = 0.0
        if header_value:
            match = self._PLAY_AUTH_EXPIRY_RE.search(header_value)
            if match:
                expires_at = float(match.group(1))
            else:
                logger.warning(f"move.tv: Could not parse expiry from X-Play-Auth for {cache_key}")

        # Cache by the primary key (e.g. content_id or content_id:epg_id)
        self._source_cache.set(cache_key, (content_url, header_value, expires_at))

        # CRITICAL: Also cache by the content_url itself. This allows stateless
        # proxy/segment header lookups if they pass the URL back to get_manifest_headers.
        if content_url:
            self._source_cache.set(content_url, (content_url, header_value, expires_at))

        logger.info(f"move.tv: Fetched and cached {operation} for {cache_key}: {content_url}")

        # Update channel object if it exists in memory
        channel = self._channel_by_id(content_id)
        if isinstance(channel, MoveTVChannel):
            channel.play_auth_header = header_value
            channel.play_auth_expires_at = expires_at

        return data

    # ------------------------------------------------------------------
    # get_channels
    # ------------------------------------------------------------------

    def get_channels(self, **kwargs) -> List[MoveTVChannel]:
        try:
            channels = self._fetch_channels()
            self.channels = channels
            logger.info(f"move.tv: Loaded {len(channels)} subscribed channels")
            return channels
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 401:
                logger.info("move.tv: 401 on channel fetch — attempting token refresh …")
                try:
                    token = self.authenticator.get_current_token()
                    if token and self.authenticator.refresh_token(token):
                        channels = self._fetch_channels()
                        self.channels = channels
                        return channels
                except Exception:
                    pass
                logger.info("move.tv: Refresh failed, retrying channel fetch after full login …")
            else:
                logger.error(f"move.tv: HTTP error fetching channels: {exc}")
            try:
                self.authenticator.authenticate(force_refresh=True)
                channels = self._fetch_channels()
                self.channels = channels
                return channels
            except Exception as retry_exc:
                logger.error(f"move.tv: Channel fetch retry failed: {retry_exc}")
                return []
        except requests.RequestException as exc:
            logger.error(f"move.tv: HTTP error fetching channels: {exc}")
            return []
        except Exception as exc:
            logger.error(f"move.tv: Unexpected error fetching channels: {exc}")
            return []

    def _fetch_channels(self) -> List[MoveTVChannel]:
        session = self.authenticator.get_session_info()
        if not session:
            self.authenticator.authenticate(force_refresh=True)
            session = self.authenticator.get_session_info()
        if not session:
            raise RuntimeError("move.tv: Unable to obtain session info for channel fetch")

        payload = {
            "customerId": session["customer_id"],
            "customerProfileId": session["customer_profile_id"],
            "lang": MoveTVConfig.DEFAULT_LANG,
            "appVersion": MoveTVConfig.APP_VERSION,
        }
        response = self.http_manager.post(
            MoveTVConfig.channels_url(),
            operation="api",
            json=payload,
            headers=self._authenticated_headers(),
        )
        response.raise_for_status()
        data = response.json()

        if not data.get("success"):
            raise RuntimeError("move.tv: channels endpoint returned success=false")

        channels: List[MoveTVChannel] = []
        for item in data.get("content", []):
            channel = self._parse_channel_item(item)
            if channel:
                channels.append(channel)
        return channels

    def _parse_channel_item(self, item: Dict[str, Any]) -> Optional[MoveTVChannel]:
        try:
            if not item.get("subscribed", False):
                return None

            catalog_id = item.get("contentId")
            live_id = item.get("liveId")
            name = item.get("contentName", "")
            stream_uid = item.get("streamUid", "")

            if not live_id or not catalog_id or not name:
                return None

            picture = item.get("picture", {})
            logo_url = MoveTVConfig.build_logo_url(picture.get("icon"))

            catchup: Dict = item.get("catchup", {})
            catchup_hours: int = int(catchup.get("duration", 0)) if catchup else 0

            is_audio = bool(item.get("audioOnly", False))

            channel = MoveTVChannel(
                name=name,
                content_id=str(catalog_id),
                provider=self.provider_name,
                logo_url=logo_url,
                mode="live",
                session_manifest=True,
                manifest=None,
                content_type="RADIO" if is_audio else "LIVE",
                quality="AUDIO" if is_audio else None,
                is_radio=is_audio,
                language="sr",
                country=self.country,
                live_id=int(live_id),
                catchup_hours=catchup_hours,
                stream_uid=stream_uid,
            )
            channel.channel_number = item.get("contentPosition")
            return channel

        except Exception as exc:
            logger.warning(f"move.tv: Error parsing channel item: {exc} — {item}")
            return None

    # ------------------------------------------------------------------
    # Live Manifest
    # ------------------------------------------------------------------

    def get_manifest_with_headers(self, content_id: str, **kwargs) -> Tuple[Optional[str], Dict[str, str]]:
        """Unified method to fetch both URL and headers in one go, avoiding redundant API calls."""
        try:
            channel = self._get_channel_with_rebuild(content_id)
            if not channel:
                return None, {"User-Agent": MoveTVConfig.USER_AGENT}

            payload = {"liveId": channel.live_id}
            source_data = self._fetch_source_endpoint(
                MoveTVConfig.live_source_url(),
                payload=payload,
                content_id=content_id,
                cache_key=content_id,
                operation="live_manifest"
            )

            if source_data:
                content_url = source_data.get("content_url")
                header_value = source_data.get("protection", {}).get("headerValue", "")
                return content_url, {"User-Agent": MoveTVConfig.USER_AGENT, "X-Play-Auth": header_value}

            return None, {"User-Agent": MoveTVConfig.USER_AGENT}
        except Exception as exc:
            logger.error(f"move.tv: Unexpected error fetching live manifest: {exc}")
            return None, {"User-Agent": MoveTVConfig.USER_AGENT}

    def get_manifest(self, content_id: str, **kwargs) -> Optional[str]:
        url, _ = self.get_manifest_with_headers(content_id, **kwargs)
        return url

    def get_manifest_headers(self, content_id: str, **kwargs) -> Dict[str, str]:
        # 1. Check if URL is provided in kwargs (common for segment/manifest proxy requests)
        url = kwargs.get("url") or kwargs.get("manifest_url") or kwargs.get("segment_url")
        if url:
            cached = self._source_cache.get(url)
            if cached:
                content_url, header_value, expires_at = cached
                if expires_at and time.time() < (expires_at - MoveTVChannel._PLAY_AUTH_EARLY_EXPIRY_BUFFER):
                    return {"User-Agent": MoveTVConfig.USER_AGENT, "X-Play-Auth": header_value}

        start_time = kwargs.get("start_time")
        end_time = kwargs.get("end_time")
        epg_id = kwargs.get("epg_id")

        # 2. If start_time and end_time are present, this is a catchup manifest/segment request
        if start_time is not None and end_time is not None:
            try:
                # FIX: Strip start_time, end_time, and epg_id from kwargs before forwarding
                # to prevent Python TypeError (multiple values for argument).
                forward_kwargs = {
                    k: v for k, v in kwargs.items()
                    if k not in ("start_time", "end_time", "epg_id")
                }

                if epg_id:
                    logger.debug(f"move.tv: Fetching catchup headers with provided epg_id={epg_id}")
                else:
                    logger.debug(f"move.tv: epg_id missing in kwargs, will re-resolve for catchup headers")

                return self.get_catchup_manifest_headers(
                    content_id, int(start_time), int(end_time), epg_id, **forward_kwargs
                )
            except ValueError:
                logger.warning(f"move.tv: ValueError parsing catchup times for {content_id}")
            except Exception as exc:
                # Don't silently swallow TypeErrors or other exceptions here
                logger.error(f"move.tv: Error getting catchup manifest headers: {exc}")

            # SAFETY NET: If catchup resolution failed for any reason, do NOT fall back
            # to live headers. Return an empty auth header so the CDN rejects it
            # loudly (401/403) rather than silently applying the wrong token.
            logger.error(f"move.tv: Catchup header resolution failed for {content_id}. Returning safe empty headers.")
            return {"User-Agent": MoveTVConfig.USER_AGENT}

        # 3. Fallback to live manifest headers (only if NOT a catchup request)
        _, headers = self.get_manifest_with_headers(content_id, **kwargs)
        return headers

    def get_segment_headers(self, content_id: str, **kwargs) -> Dict[str, str]:
        return self.get_manifest_headers(content_id, **kwargs)

    def get_drm(self, content_id: str, **kwargs) -> List[DRMConfig]:
        return []

    # ------------------------------------------------------------------
    # Catchup Manifest
    # ------------------------------------------------------------------

    def get_catchup_manifest_with_headers(
            self, content_id: str, start_time: int, end_time: int, epg_id: Optional[str] = None, **kwargs
    ) -> Tuple[Optional[str], Dict[str, str]]:
        """Unified method to fetch both catchup URL and headers in one go."""
        try:
            # 1. Resolve EPG ID
            resolved_epg_id = epg_id
            if not resolved_epg_id:
                # Check EPG cache first to avoid hammering the API on repeated manifest polls
                epg_entries = None
                with self._epg_lock:
                    cached_epg = self._epg_cache.get(content_id)
                    if cached_epg:
                        entries, expires_at = cached_epg
                        if time.time() < expires_at and entries:
                            # Validate that start_time actually falls within the cached entries' covered range
                            min_start = min(e.start for e in entries)
                            max_end = max(e.end for e in entries)
                            # Add a 1-hour buffer to handle edge cases gracefully
                            if min_start - 3600 <= start_time <= max_end + 3600:
                                epg_entries = entries
                                logger.debug(
                                    f"move.tv: EPG cache hit for {content_id} covering [{min_start}, {max_end}]")

                if epg_entries is None:
                    logger.debug(f"move.tv: EPG cache miss for {content_id} at {start_time}")
                    # A fixed 6-hour backward window anchored at start_time covers long-running
                    # programs (like films or sports) without pulling massive EPG ranges.
                    epg_entries = self._epg.get_channel_epg(
                        channel_id=content_id,
                        backwards=6,
                        forwards=2,
                        start_time=datetime.fromtimestamp(start_time, tz=timezone.utc),
                    )
                    # Cache the EPG response for 60 seconds to handle rapid manifest polls
                    if epg_entries is not None:
                        with self._epg_lock:
                            self._epg_cache[content_id] = (epg_entries, time.time() + 60)

                if not epg_entries:
                    return None, {"User-Agent": MoveTVConfig.USER_AGENT}

                target_entry = None
                closest_entry = None
                closest_diff = float('inf')

                for entry in epg_entries:
                    if entry.start <= start_time < entry.end:
                        target_entry = entry
                        break
                    diff = abs(entry.start - start_time)
                    if diff < closest_diff:
                        closest_diff = diff
                        closest_entry = entry

                if target_entry:
                    resolved_epg_id = str(target_entry.program_id)
                elif closest_entry and closest_diff < 3600:
                    resolved_epg_id = str(closest_entry.program_id)
                else:
                    logger.warning(f"move.tv: No suitable EPG entry found for {content_id} at {start_time}")
                    return None, {"User-Agent": MoveTVConfig.USER_AGENT}

            # 2. Fetch Source
            cache_key = f"{content_id}:{resolved_epg_id}"

            channel = self._get_channel_with_rebuild(content_id)
            if not channel:
                return None, {"User-Agent": MoveTVConfig.USER_AGENT}

            try:
                epg_id_int = int(resolved_epg_id)
                content_id_int = int(content_id)
            except ValueError:
                logger.error(f"move.tv: Invalid ID format. epg_id={resolved_epg_id}, content_id={content_id}")
                return None, {"User-Agent": MoveTVConfig.USER_AGENT}

            payload = {"epgId": epg_id_int, "contentId": content_id_int}
            source_data = self._fetch_source_endpoint(
                MoveTVConfig.epg_source_url(),
                payload=payload,
                content_id=content_id,
                cache_key=cache_key,
                operation="catchup_manifest"
            )

            if source_data:
                content_url = source_data.get("content_url")
                header_value = source_data.get("protection", {}).get("headerValue", "")
                return content_url, {"User-Agent": MoveTVConfig.USER_AGENT, "X-Play-Auth": header_value}

            return None, {"User-Agent": MoveTVConfig.USER_AGENT}

        except Exception as exc:
            logger.error(f"move.tv: Unexpected error in get_catchup_manifest_with_headers: {exc}")
            return None, {"User-Agent": MoveTVConfig.USER_AGENT}

    def get_catchup_manifest(self, content_id: str, start_time: int, end_time: int, epg_id: Optional[str] = None,
                             **kwargs) -> Optional[str]:
        url, _ = self.get_catchup_manifest_with_headers(content_id, start_time, end_time, epg_id, **kwargs)
        return url

    def get_catchup_manifest_headers(self, content_id: str, start_time: int, end_time: int,
                                     epg_id: Optional[str] = None, **kwargs) -> Dict[str, str]:
        _, headers = self.get_catchup_manifest_with_headers(content_id, start_time, end_time, epg_id, **kwargs)
        return headers

    def get_catchup_drm(
            self, content_id: str, start_time: int, end_time: int, epg_id: Optional[str] = None,
            drm_variant: Optional[str] = None, **kwargs
    ) -> List[DRMConfig]:
        return []

    def get_catchup_window_for_channel(self, content_id: str) -> int:
        channel = self._channel_by_id(content_id)
        if channel and hasattr(channel, 'catchup_hours'):
            return channel.catchup_hours
        return self.catchup_window

    # ------------------------------------------------------------------
    # VOD & EPG Delegations
    # ------------------------------------------------------------------

    def get_vod_filters(self) -> VodFilters:
        return self._vod.get_vod_filters()

    def get_vod_items(self, page: int = 1, sort: str = "newest", tag_id=None, category_id=None, catalog_id=None,
                      content_type_id=None, search_query=None) -> VodPage:
        return self._vod.get_vod_items(page=page, sort=sort, tag_id=tag_id, category_id=category_id,
                                       catalog_id=catalog_id, content_type_id=content_type_id,
                                       search_query=search_query)

    def get_all_vod_items(self, sort: str = "newest", tag_id=None, category_id=None, catalog_id=None,
                          content_type_id=None, max_pages=None):
        return self._vod.get_all_vod_items(sort=sort, tag_id=tag_id, category_id=category_id, catalog_id=catalog_id,
                                           content_type_id=content_type_id, max_pages=max_pages)

    def get_page_components(self, page_id: int):
        return self._vod.get_page_components(page_id)

    def get_component_items(self, component_id: int):
        return self._vod.get_component_items(component_id)

    def get_epg(self, channel_id: str, backwards: int = 2, forwards: int = 2, **kwargs) -> List[EPGEntry]:
        return self._epg.get_channel_epg(
            channel_id,
            backwards=kwargs.get("backwards", backwards),
            forwards=kwargs.get("forwards", forwards),
            **{k: v for k, v in kwargs.items() if k not in ("backwards", "forwards")},
        )

    @property
    def epg_window(self) -> Tuple[int, int]:
        return 3, 3