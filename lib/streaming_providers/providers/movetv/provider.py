# streaming_providers/providers/movetv/provider.py
import re
import time
import requests
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


class MoveTVChannel(StreamingChannel):
    """
    Extends StreamingChannel with move.tv-specific fields.

    content_id  stores the *contentId* so that get_epg(content_id) can pass
    it directly to the EPG endpoint without any mapping lookup.

    Extra fields
    ------------
    live_id         : int   – the liveId used by the live-source / manifest
                              endpoint (required for get_manifest mapping)
    catchup_hours   : int   – how many hours of catch-up are available (0 = none)
    stream_uid      : str   – the streamUid used by the CDN (e.g. "rts1")
    play_auth_header: str   – the X-Play-Auth value delivered with the manifest
                              source response; callers must inject this when
                              requesting the actual .mpd / .m3u8 from the CDN
    """

    # How many seconds before the stated expiry we treat the token as stale.
    # 60 s gives enough runway to start playback before the CDN rejects it.
    _PLAY_AUTH_EARLY_EXPIRY_BUFFER: int = 60

    def __init__(self, *args, live_id: int = 0, catchup_hours: int = 0,
                 stream_uid: str = "", play_auth_header: str = "",
                 play_auth_expires_at: float = 0.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.live_id: int = live_id
        self.catchup_hours: int = catchup_hours
        self.stream_uid: str = stream_uid
        self.play_auth_header: str = play_auth_header
        # Unix timestamp after which play_auth_header must be treated as stale.
        # 0.0 means "no expiry parsed / never cached".
        self.play_auth_expires_at: float = play_auth_expires_at

    def is_play_auth_valid(self) -> bool:
        """Return True only when a header is cached and has not yet expired."""
        if not self.play_auth_header:
            return False
        if self.play_auth_expires_at == 0.0:
            # No expiry was parsed — treat as already invalid so a fresh fetch
            # is triggered.
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

    Authentication
    --------------
    Token-based: login returns an auth_token used as X-Auth-Token on all
    subsequent requests.  No anonymous / client-credentials fallback exists.

    Channel list
    ------------
    GET /api/v2/content/live/all – only subscribed channels are kept.
    catchup_hours comes from catchup.duration (already in hours).

    content_id convention
    ---------------------
    contentId is stored as content_id so get_epg(content_id) can pass it
    directly to the EPG endpoint with no mapping lookup.  liveId is kept in
    live_id and looked up when get_manifest() needs to call the source endpoint.

    Manifest
    --------
    POST /api/v2/content/live/source/get – requires customer_id,
    customer_profile_id, liveId (= content_id) and dtype.  Returns a
    content_url (.mpd) and an X-Play-Auth protection header.  This provider
    returns the content_url only; the caller injects X-Play-Auth.

    DRM
    ---
    The AES-128 / token-based protection is handled via X-Play-Auth (see
    above).  Widevine/PlayReady are not active in observed traffic; get_drm()
    returns an empty list.
    """

    PROVIDER_LABEL: ClassVar[str] = "move.tv"
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["user_credentials"]

    def __init__(
        self,
        country: str = "SI",
        config: Optional[Dict] = None,
        proxy_config: Optional[ProxyConfig] = None,
        settings_manager=None,
    ):
        super().__init__(country)

        # HTTP manager (shared with authenticator)
        self.http_manager = self._setup_http_manager(
            provider_name="movetv",
            proxy_config=proxy_config,
            user_agent=MoveTVConfig.USER_AGENT,
            timeout=MoveTVConfig.TIMEOUT,
        )

        # Authenticator
        self.authenticator = MoveTVAuthenticator(
            proxy_config=proxy_config,
            http_manager=self.http_manager,
            settings_manager=settings_manager,
        )

        self._vod = MoveTvVodManager(self)
        self._epg = MoveTvEpgManager(self.authenticator)

        # Share the same http_manager session with the authenticator
        self.http_manager = self._share_http_manager_with_authenticator(self.authenticator)

        # Standalone play-auth cache: content_id -> (header_value, expires_at)
        # Used by _store_play_auth / _get_play_auth_header so they never depend
        # on self.channels being populated (get_channels may not have been called).
        self._play_auth_cache: Dict[str, tuple] = {}
        self._manifest_url_cache: Dict[str, str] = {}
        self._last_content_id: Optional[str] = None

        # Attempt authentication at startup; non-fatal if it fails
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
        # Manifests are fetched per-play via the source endpoint
        return True

    @property
    def supported_auth_types(self) -> List[str]:
        return self.SUPPORTED_AUTH_TYPES

    @property
    def requires_manifest_context(self) -> bool:
        # Manifests need http_manager context
        return True

    # ------------------------------------------------------------------
    # Header helpers
    # ------------------------------------------------------------------

    def _authenticated_headers(self) -> Dict[str, str]:
        """Return API headers with the current X-Auth-Token injected."""
        auth_token = self.authenticator.get_auth_token()
        return MoveTVConfig.get_api_headers(auth_token=auth_token)

    # ------------------------------------------------------------------
    # get_channels
    # ------------------------------------------------------------------

    def get_channels(self, **kwargs) -> List[MoveTVChannel]:
        """
        Fetch the live channel list and return only subscribed channels.

        POST /api/v2/content/live/all with customerId and appVersion.
        Only subscribed channels are kept; liveId is used as content_id.
        """
        try:
            channels = self._fetch_channels()
            self.channels = channels  # type: ignore[assignment]
            logger.info(f"move.tv: Loaded {len(channels)} subscribed channels")
            return channels

        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 401:
                logger.info("move.tv: 401 on channel fetch — attempting token refresh …")
                try:
                    token = self.authenticator.get_current_token()
                    if token and self.authenticator.refresh_token(token):
                        channels = self._fetch_channels()
                        self.channels = channels  # type: ignore[assignment]
                        return channels
                except Exception:
                    pass
                logger.info("move.tv: Refresh failed, retrying channel fetch after full login …")
            else:
                logger.error(f"move.tv: HTTP error fetching channels: {exc}")
            try:
                self.authenticator.authenticate(force_refresh=True)
                channels = self._fetch_channels()
                self.channels = channels  # type: ignore[assignment]
                return channels
            except Exception as retry_exc:
                logger.error(f"move.tv: Channel fetch retry failed: {retry_exc}")
                return []
        except requests.RequestException as exc:
            logger.error(f"move.tv: HTTP error fetching channels: {exc}")
            try:
                logger.info("move.tv: Retrying channel fetch after token refresh …")
                self.authenticator.invalidate_token()
                channels = self._fetch_channels()
                self.channels = channels  # type: ignore[assignment]
                return channels
            except Exception as retry_exc:
                logger.error(f"move.tv: Channel fetch retry failed: {retry_exc}")
                return []
        except Exception as exc:
            logger.error(f"move.tv: Unexpected error fetching channels: {exc}")
            return []

    def _fetch_channels(self) -> List[MoveTVChannel]:
        """POST the channel list endpoint and parse the response."""
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
        """
        Parse a single item from the /api/v2/content/live/all content array.

        Returns None for:
          - unsubscribed channels
          - items missing required identifiers
        """
        try:
            # Drop unsubscribed channels
            if not item.get("subscribed", False):
                return None

            catalog_id = item.get("contentId")
            live_id = item.get("liveId")
            name = item.get("contentName", "")
            stream_uid = item.get("streamUid", "")

            # Both identifiers are required
            if not live_id or not catalog_id or not name:
                logger.debug(f"move.tv: Skipping channel item with missing ids/name: {item}")
                return None

            # Logo
            picture = item.get("picture", {})
            logo_url = MoveTVConfig.build_logo_url(picture.get("icon"))

            # Catch-up duration — the API field is already in hours
            catchup: Dict = item.get("catchup", {})
            catchup_hours: int = int(catchup.get("duration", 0)) if catchup else 0

            # Audio-only channels
            is_audio = bool(item.get("audioOnly", False))

            # contentId stored as content_id so get_epg() needs no mapping;
            # liveId stored in live_id for use by get_manifest()
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
                # move.tv specifics
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
    # get_manifest
    # ------------------------------------------------------------------

    def get_manifest(self, content_id: str, **kwargs) -> Optional[str]:
        if content_id != self._last_content_id:
            logger.debug(
                f"move.tv: Channel switch detected "
                f"({self._last_content_id!r} → {content_id!r}), "
                f"invalidating play-auth and manifest URL cache"
            )
            self._play_auth_cache.pop(content_id, None)
            self._manifest_url_cache.pop(content_id, None)
            self._last_content_id = content_id

        channel = self._channel_by_id(content_id)
        if channel is None:
            logger.info(
                f"move.tv: Channel not found in cache for content_id={content_id!r}; "
                "attempting to rebuild channel cache before manifest fetch"
            )
            self.get_channels()
            channel = self._channel_by_id(content_id)
        if channel is None:
            logger.error(
                f"move.tv: Channel still not found after cache rebuild for "
                f"content_id={content_id!r}; cannot resolve liveId for manifest fetch"
            )
            return None

        live_id = channel.live_id

        # If we have both a valid play-auth token and a cached manifest URL,
        # skip the source endpoint entirely — the MPD TTL is server-driven at 0
        # but the token (~24h) and URL are both stable.
        cached_token = self._play_auth_cache.get(content_id)
        cached_url = self._manifest_url_cache.get(content_id)
        if cached_token and cached_url:
            header_value, expires_at = cached_token
            buffer = MoveTVChannel._PLAY_AUTH_EARLY_EXPIRY_BUFFER
            if expires_at and time.time() < (expires_at - buffer):
                logger.debug(
                    f"move.tv: Reusing cached manifest URL and X-Play-Auth for "
                    f"content_id={content_id} (token expires in "
                    f"{expires_at - time.time():.0f}s)"
                )
                return cached_url

        # Cache miss or expired token — hit the source endpoint.
        source_data = self._fetch_live_source(live_id)
        if source_data is None:
            return None

        self._store_play_auth(content_id, source_data)

        content_url: Optional[str] = source_data.get("content_url")
        if not content_url:
            logger.warning(
                f"move.tv: No content_url in source response for liveId={live_id}"
            )
            return None

        self._manifest_url_cache[content_id] = content_url
        logger.info(f"move.tv: Manifest URL for liveId={live_id}: {content_url}")
        return content_url

    def _get_play_auth_header(self, content_id: str) -> Optional[str]:
        """
        Return the X-Play-Auth header value for a channel.

        Checks the standalone _play_auth_cache first (populated by every
        _store_play_auth call, regardless of whether self.channels exists).
        A cached value is only returned when it has not expired (with a
        60-second early-expiry buffer).  A stale or absent entry triggers a
        fresh _fetch_live_source call.
        """
        cached = self._play_auth_cache.get(content_id)
        if cached:
            header_value, expires_at = cached
            buffer = MoveTVChannel._PLAY_AUTH_EARLY_EXPIRY_BUFFER
            if expires_at and time.time() < (expires_at - buffer):
                return header_value

        # Cache miss or expired — fetch a fresh source and re-cache.
        try:
            channel = self._channel_by_id(content_id)
            if channel is None:
                logger.info(
                    f"move.tv: Channel not found for content_id={content_id!r}; "
                    "attempting to rebuild channel cache before play-auth fetch"
                )
                self.get_channels()
                channel = self._channel_by_id(content_id)
            if channel is None:
                logger.error(
                    f"move.tv: Channel still not found after cache rebuild for "
                    f"content_id={content_id!r}; cannot resolve liveId for play-auth fetch"
                )
                return None
            live_id = channel.live_id
            source_data = self._fetch_live_source(live_id)
            if source_data:
                self._store_play_auth(content_id, source_data)
                cached = self._play_auth_cache.get(content_id)
                return cached[0] if cached else None
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 401:
                logger.info(
                    f"move.tv: 401 fetching play-auth for liveId={content_id} "
                    "— attempting token refresh …"
                )
                try:
                    token = self.authenticator.get_current_token()
                    refreshed = self.authenticator.refresh_token(token) if token else None
                    if not refreshed:
                        logger.info(
                            "move.tv: Refresh failed, falling back to full login "
                            "for play-auth fetch"
                        )
                        self.authenticator.authenticate(force_refresh=True)
                    # Retry once with the new token.
                    live_id = channel.live_id
                    source_data = self._fetch_live_source(live_id)
                    if source_data:
                        self._store_play_auth(content_id, source_data)
                        cached = self._play_auth_cache.get(content_id)
                        return cached[0] if cached else None
                except Exception as retry_exc:
                    logger.error(
                        f"move.tv: Failed to fetch play auth header after re-auth: {retry_exc}"
                    )
            else:
                logger.error(f"move.tv: Failed to fetch play auth header: {exc}")
        except Exception as exc:
            logger.error(f"move.tv: Failed to fetch play auth header: {exc}")

        return None

    def get_manifest_headers(self, content_id: str, **kwargs) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "User-Agent": MoveTVConfig.USER_AGENT,
            "X-Play-Auth": self._get_play_auth_header(content_id),
        }
        logger.debug(f"move.tv: Manifest headers: {headers}")
        return headers

    # ------------------------------------------------------------------
    # get_drm  (stub – AES-128/token auth, no active Widevine/PlayReady)
    # ------------------------------------------------------------------

    def get_drm(self, content_id: str, **kwargs) -> List[DRMConfig]:
        """
        move.tv uses AES-128 token-based stream protection via X-Play-Auth.
        No Widevine or PlayReady DRM is active in observed traffic.
        """
        return []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_live_source(self, live_id: int) -> Optional[Dict[str, Any]]:
        """
        POST /api/v2/content/live/source/get and return the parsed JSON.

        Requires an active authenticated session; the customer_id,
        customer_profile_id and device_id are read from the auth token via
        get_session_info().
        """
        session = self.authenticator.get_session_info()
        if not session:
            # Force re-authentication and retry once
            logger.info("move.tv: No session info; re-authenticating before manifest fetch")
            self.authenticator.authenticate(force_refresh=True)
            session = self.authenticator.get_session_info()

        if not session:
            logger.error("move.tv: Unable to obtain session info for manifest fetch")
            return None

        payload = {
            "customerId": session["customer_id"],
            "customerProfileId": session["customer_profile_id"],
            "liveId": live_id,
            "dtype": MoveTVConfig.DTYPE_DASH,
            "appVersion": MoveTVConfig.APP_VERSION,
        }

        headers = MoveTVConfig.get_api_headers(auth_token=session["auth_token"])

        logger.debug(f"move.tv: POST {MoveTVConfig.live_source_url()} liveId={live_id}")

        try:
            response = self.http_manager.post(
                MoveTVConfig.live_source_url(),
                operation="manifest",
                json=payload,
                headers=headers,
            )
            # http_manager returned a response object — check status before raise_for_status().
            is_401 = response.status_code == 401
        except requests.HTTPError as exc:
            # http_manager raised before returning (e.g. it calls raise_for_status internally).
            # Extract the 401 from the exception's attached response instead.
            if exc.response is not None and exc.response.status_code == 401:
                is_401 = True
                response = exc.response
            else:
                raise

        # On 401, attempt a token refresh and retry once before giving up.
        if is_401:
            logger.info(f"move.tv: 401 on manifest fetch for liveId={live_id} — attempting token refresh …")
            token = self.authenticator.get_current_token()
            refreshed = self.authenticator.refresh_token(token) if token else None
            if not refreshed:
                logger.info("move.tv: Refresh failed, falling back to full login for manifest fetch")
                self.authenticator.authenticate(force_refresh=True)
            # Rebuild session and headers with the new token.
            session = self.authenticator.get_session_info()
            if not session:
                logger.error("move.tv: Unable to obtain session after token refresh for manifest fetch")
                return None
            payload["customerId"] = session["customer_id"]
            payload["customerProfileId"] = session["customer_profile_id"]
            headers = MoveTVConfig.get_api_headers(auth_token=session["auth_token"])
            response = self.http_manager.post(
                MoveTVConfig.live_source_url(),
                operation="manifest",
                json=payload,
                headers=headers,
            )

        response.raise_for_status()
        data = response.json()

        if not data.get("success"):
            logger.warning(
                f"move.tv: live source endpoint returned success=false for liveId={live_id}"
            )
            return None

        return data

    def _channel_by_id(self, content_id: str) -> Optional[MoveTVChannel]:
        """Return the cached MoveTVChannel whose content_id matches, or None."""
        for ch in (self.channels or []):
            if isinstance(ch, MoveTVChannel) and ch.content_id == content_id:
                return ch
        return None

    # Regex to extract the Unix expiry from the X-Play-Auth token value.
    # The token format embeds it as "expires-<unix_ts>" e.g.:
    #   hash-…-expires-1774465909-cusid-…
    _PLAY_AUTH_EXPIRY_RE = re.compile(r"expires-(\d+)")

    def _store_play_auth(self, content_id: str, source_data: Dict[str, Any]) -> None:
        """
        Cache the X-Play-Auth header value and its expiry.

        Written to both the standalone _play_auth_cache dict (always) and to
        the matching MoveTVChannel object (when the channel list has been
        loaded).  Using the dict means the header is available even when
        get_channels() has not yet been called.
        """
        protection: Dict = source_data.get("protection", {})
        header_value: str = protection.get("headerValue", "")
        if not header_value:
            return

        # Parse the expiry timestamp from the token itself.
        expires_at: float = 0.0
        match = self._PLAY_AUTH_EXPIRY_RE.search(header_value)
        if match:
            expires_at = float(match.group(1))
        else:
            logger.warning(
                f"move.tv: Could not parse expiry from X-Play-Auth for "
                f"liveId={content_id}; token will not be reused."
            )

        # Always populate the standalone cache so _get_play_auth_header works
        # regardless of whether self.channels has been populated.
        self._play_auth_cache[content_id] = (header_value, expires_at)

        # Also mirror onto the channel object when available.
        channel = self._channel_by_id(content_id)
        if channel:
            channel.play_auth_header = header_value
            channel.play_auth_expires_at = expires_at

        logger.debug(
            f"move.tv: Cached X-Play-Auth for liveId={content_id} "
            f"expires_at={expires_at}: {header_value[:60]}…"
        )

    # ------------------------------------------------------------------ #
    # VOD — catalogue                                                      #
    # ------------------------------------------------------------------ #

    def get_vod_filters(self) -> VodFilters:
        """Return available VOD content types, categories, catalogs, tags, and sort options."""
        return self._vod.get_vod_filters()

    def get_vod_items(
            self,
            page: int = 1,
            sort: str = "newest",
            tag_id=None,
            category_id=None,
            catalog_id=None,
            content_type_id=None,
            search_query=None,
    ) -> VodPage:
        """Return a paginated VOD catalogue with optional filtering."""
        return self._vod.get_vod_items(
            page=page,
            sort=sort,
            tag_id=tag_id,
            category_id=category_id,
            catalog_id=catalog_id,
            content_type_id=content_type_id,
            search_query=search_query,
        )

    def get_all_vod_items(
            self,
            sort: str = "newest",
            tag_id=None,
            category_id=None,
            catalog_id=None,
            content_type_id=None,
            max_pages=None,
    ):
        """Fetch every VOD page and return a flat list of VodItems."""
        return self._vod.get_all_vod_items(
            sort=sort,
            tag_id=tag_id,
            category_id=category_id,
            catalog_id=catalog_id,
            content_type_id=content_type_id,
            max_pages=max_pages,
        )

    # ------------------------------------------------------------------ #
    # VOD — homepage / page layout                                         #
    # ------------------------------------------------------------------ #

    def get_page_components(self, page_id: int):
        """
        Return the ordered list of component descriptors for a UI page.

        Pass the returned component IDs to get_component_items() to load
        the actual content cards.
        """
        return self._vod.get_page_components(page_id)

    def get_component_items(self, component_id: int):
        """
        Return the content cards for a single carousel / banner component.

        Richer than get_vod_items() cards: includes description, age rating,
        release year, duration, and per-item subscription status.
        """
        return self._vod.get_component_items(component_id)

    def get_epg(
            self,
            channel_id: str,
            backwards: int = 2,
            forwards: int = 2,
            **kwargs,
    ) -> List[EPGEntry]:
        """
        Return the EPG schedule for *channel_id*.

        Parameters
        ----------
        channel_id:
            The channel's contentId (stored as ``MoveTVChannel.content_id``).
            Passed directly to the EPG API with no mapping required.
        backwards:
            Hours of past programming to include (default 2).
        forwards:
            Hours of future programming to include (default 2).

        Returns
        -------
        List of EPGEntry objects from ``MoveTvEpgManager`` (see
        epg_manager.py for the field mapping and known lossy fields).
        """
        # content_id IS the contentId the EPG endpoint expects — no mapping needed.
        return self._epg.get_channel_epg(
            channel_id,
            backwards=kwargs.get("backwards", backwards),
            forwards=kwargs.get("forwards", forwards),
            **{k: v for k, v in kwargs.items() if k not in ("backwards", "forwards")},
        )

    @property
    def epg_window(self) -> Tuple[int, int]:
        return 3, 3