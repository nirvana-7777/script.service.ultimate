# streaming_providers/providers/movetv/provider.py
import re
import time
import requests
from typing import ClassVar, Dict, List, Optional, Any, cast

from ...base.models import DRMConfig, StreamingChannel
from ...base.models.proxy_models import ProxyConfig
from ...base.provider import StreamingProvider
from ...base.utils.logger import logger
from .auth import MoveTVAuthenticator, MoveTVAuthToken
from .constants import MoveTVConfig


class MoveTVChannel(StreamingChannel):
    """
    Extends StreamingChannel with move.tv-specific fields.

    content_id  stores the *liveId* so that get_manifest(content_id) can post
    it directly to the source endpoint without any mapping lookup.

    Extra fields
    ------------
    catalog_id      : int   – the original contentId from the channel list
                              (retained for EPG / catch-up use)
    catchup_hours   : int   – how many hours of catch-up are available (0 = none)
    stream_uid      : str   – the streamUid used by the CDN (e.g. "rts1")
    play_auth_header: str   – the X-Play-Auth value delivered with the manifest
                              source response; callers must inject this when
                              requesting the actual .mpd / .m3u8 from the CDN
    """

    # How many seconds before the stated expiry we treat the token as stale.
    # 60 s gives enough runway to start playback before the CDN rejects it.
    _PLAY_AUTH_EARLY_EXPIRY_BUFFER: int = 60

    def __init__(self, *args, catalog_id: int = 0, catchup_hours: int = 0,
                 stream_uid: str = "", play_auth_header: str = "",
                 play_auth_expires_at: float = 0.0, **kwargs):
        super().__init__(*args, **kwargs)
        self.catalog_id: int = catalog_id
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
        result["CatalogId"] = self.catalog_id
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
    liveId is stored as content_id; the original contentId is kept in
    catalog_id.  This means get_manifest(content_id) can post liveId directly
    with no mapping lookup.

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

        # Share the same http_manager session with the authenticator
        self.http_manager = self._share_http_manager_with_authenticator(self.authenticator)

        # Standalone play-auth cache: content_id -> (header_value, expires_at)
        # Used by _store_play_auth / _get_play_auth_header so they never depend
        # on self.channels being populated (get_channels may not have been called).
        self._play_auth_cache: Dict[str, tuple] = {}

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
        return ""  # No hosted logo URL known at this time

    @property
    def uses_dynamic_manifests(self) -> bool:
        # Manifests are fetched per-play via the source endpoint
        return True

    @property
    def implements_epg(self) -> bool:
        return False

    @property
    def supported_auth_types(self) -> List[str]:
        return self.SUPPORTED_AUTH_TYPES

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
                    token = cast(MoveTVAuthToken, self.authenticator._current_token)
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

            # liveId stored as content_id so get_manifest() needs no mapping
            channel = MoveTVChannel(
                name=name,
                content_id=str(live_id),
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
                catalog_id=int(catalog_id),
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
        """
        Fetch the streaming manifest URL for a channel.

        The caller is responsible for injecting the X-Play-Auth header when
        requesting the returned .mpd / .m3u8 URL from the CDN.  The header
        value can be retrieved via get_play_auth_header().

        ``content_id`` is the liveId stored on MoveTVChannel.content_id.
        It is posted directly to the source endpoint with no mapping required.
        """
        try:
            # content_id IS the liveId — cast directly, no mapping needed
            try:
                live_id = int(content_id)
            except (ValueError, TypeError):
                logger.error(f"move.tv: content_id is not a valid liveId: {content_id!r}")
                return None

            source_data = self._fetch_live_source(live_id)
            if source_data is None:
                return None

            # ✅ STORE PLAY AUTH FIRST - before checking content_url
            # This ensures the header is cached even if content_url is missing
            self._store_play_auth(content_id, source_data)

            content_url: Optional[str] = source_data.get("content_url")
            if not content_url:
                logger.warning(
                    f"move.tv: No content_url in source response for liveId={live_id}"
                )
                return None

            logger.info(f"move.tv: Manifest URL for liveId={live_id}: {content_url}")
            return content_url

        except requests.RequestException as exc:
            logger.error(f"move.tv: HTTP error fetching manifest for {content_id}: {exc}")
            return None
        except Exception as exc:
            logger.error(f"move.tv: Unexpected error fetching manifest for {content_id}: {exc}")
            return None

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
            live_id = int(content_id)
            source_data = self._fetch_live_source(live_id)
            if source_data:
                self._store_play_auth(content_id, source_data)
                cached = self._play_auth_cache.get(content_id)
                return cached[0] if cached else None
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

        response = self.http_manager.post(
            MoveTVConfig.live_source_url(),
            operation="manifest",
            json=payload,
            headers=headers,
        )

        # On 401, attempt a token refresh and retry once before giving up.
        if response.status_code == 401:
            logger.info(f"move.tv: 401 on manifest fetch for liveId={live_id} — attempting token refresh …")
            token = cast(MoveTVAuthToken, self.authenticator._current_token)
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