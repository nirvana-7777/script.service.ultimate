# streaming_providers/providers/allente/constants.py
"""
Allente provider constants and default configurations.

Allente is a Nordic DTH/streaming provider. The streaming stack has two
layers:
  1. SSO  (logon.allente.tv)                     -> login, returns authCode
  2. Zulu (w-sgprod-zulu.api-canaldigital.com)   -> tokens, channels, DRM

v1 supports Sweden (SE) only.

This module is the SINGLE SOURCE OF TRUTH for every URL, header value,
and default used anywhere in the provider (including drm.py). Never
duplicate these values in other files.
"""

from typing import Optional

from ...base.utils.logger import logger
from ..globals import get_user_agent


class AllenteDefaults:
    """Default values for the Allente provider."""

    # Registry key / directory name / credential + session key.
    PROVIDER_NAME = "allente"

    ALLENTE_LOGO = "https://imgix-images-cdn.3ready.cc/e2dbff8f-a707-4d34-b7f5-856e45193f3c/logo_white_big.png"

    # ------------------------------------------------------------------
    # Identity / device
    # ------------------------------------------------------------------
    DEVICE_TYPE_WEB = "WEB"
    APP_VARIANT = "ALLENTE"
    CLIENT_VERSION = "5.1.6-0"          # update when the web player updates

    USER_AGENT = get_user_agent("macos", "chrome")
    ACCEPT_LANGUAGE_DEFAULT = "en-US,en;q=0.9"

    # Web-player origin/referer sent on Zulu calls. SE-only in v1 —
    # derive per-country when NO/DK/FI are added.
    TV_WEB_ORIGIN = "https://tv.allente.se"
    TV_WEB_REFERER = f"{TV_WEB_ORIGIN}/"

    # ------------------------------------------------------------------
    # SSO layer (login)
    # ------------------------------------------------------------------
    SSO_BASE = "https://logon.allente.tv"
    SSO_CLIENT_ID_TV = "go-web-cdse"     # THE ONLY CLIENT ID WE USE
    SSO_REDIRECT_URI_TV = "https://tv.allente.se/play/live"

    SSO_REST_AUTHORIZE = f"{SSO_BASE}/sso/rest/v1/oauth/authorize"
    SSO_REST_CONTINUE = f"{SSO_BASE}/sso/rest/v1/oauth/continue"
    SSO_REST_USER_STATUS = f"{SSO_BASE}/sso/rest/v1/user/status"
    SSO_REST_USER_LOGIN = f"{SSO_BASE}/sso/rest/v1/user/login"

    # ------------------------------------------------------------------
    # Zulu layer (streaming backend)
    # ------------------------------------------------------------------
    ZULU_BASE = "https://w-sgprod-zulu.api-canaldigital.com"
    ZULU_AUTH_LOGIN = f"{ZULU_BASE}/v1/authentication/login"
    ZULU_USER_PROFILES = f"{ZULU_BASE}/v1/user/profiles"
    ZULU_USER_ENTITLEMENTS = f"{ZULU_BASE}/v1/user/entitlements"
    ZULU_CHANNELS = f"{ZULU_BASE}/v1/channels"
    ZULU_PLAYOUT_CHANNEL = f"{ZULU_BASE}/v1/playout/channel"
    ZULU_DRM_WIDEVINE = f"{ZULU_BASE}/v1/drm/widevine"

    # Stream-session keep-alive: NOT used in v1. Captured logs suggest
    # direct streaming works without it. If long-playback testing fails,
    # re-enable in v2 (and reintroduce a persistent deviceId:
    # "www-" + uuid4, generated once and persisted per install).
    # ZULU_STREAM_SESSION = f"{ZULU_BASE}/v1/stream/session"

    # ------------------------------------------------------------------
    # Streaming preferences
    # ------------------------------------------------------------------
    DEFAULT_STREAM_TYPE = "DASH"         # v1 supports DASH only (see AllenteConfig)
    DEFAULT_WIDEVINE_LEVEL = "L3"        # L3 = software DRM (correct for web/Kodi)
    DEFAULT_TIMEOUT = 30

    # NOTE: token refresh buffer is FIXED at 300s inside BaseAuthToken.is_expired /
    # needs_refresh() (base_auth.py). Do not introduce a second value here.

    # Playout cache TTL (seconds) — get_manifest + get_drm share one call.
    PLAYOUT_CACHE_TTL = 5.0

    # ------------------------------------------------------------------
    # Auth retry policy (used by AllenteProvider._ensure_authenticated)
    #
    # After a TRANSIENT auth failure (network, 5xx, WAF) the provider waits
    # BASE * 2^(n-1) seconds (capped at MAX) before the next login attempt.
    # After a PERMANENT failure (wrong credentials, OTP, unsupported
    # account) it does not retry until the credentials change. This stops
    # every get_channels/get_manifest/get_drm call from hammering the SSO
    # (which risks account lockout / WAF bans).
    # ------------------------------------------------------------------
    AUTH_BACKOFF_BASE_SECONDS = 30
    AUTH_BACKOFF_MAX_SECONDS = 900

    # v1 supports SE only. Do NOT expand without testing the other domains.
    SUPPORTED_COUNTRIES = ("SE",)
    CONTENT_DOMAIN_BY_COUNTRY = {"se": "DTH-SE"}


class AllenteHeaders:
    """Static header builders for Allente API calls.

    Every builder accepts optional overrides so a user-configured
    user-agent / accept-language applies to ALL layers (SSO, Zulu, DRM) —
    no fingerprint drift between login and data calls.
    """

    @staticmethod
    def sso_login_headers(
        user_agent: Optional[str] = None,
        accept_language: Optional[str] = None,
    ) -> dict:
        """Headers for the SSO credential POST (logon.allente.tv)."""
        return {
            "Accept": "application/json,text/html;q=0.9,*/*;q=0.8",
            "Accept-Language": accept_language or AllenteDefaults.ACCEPT_LANGUAGE_DEFAULT,
            "Content-Type": "application/json; charset=UTF-8",
            "Origin": AllenteDefaults.SSO_BASE,
            "Referer": f"{AllenteDefaults.SSO_BASE}/static/sso/login-username",
            "User-Agent": user_agent or AllenteDefaults.USER_AGENT,
        }

    @staticmethod
    def sso_oauth_headers(
        user_agent: Optional[str] = None,
        accept_language: Optional[str] = None,
    ) -> dict:
        """Headers for SSO OAuth authorize/continue (browser-like)."""
        return {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": accept_language or AllenteDefaults.ACCEPT_LANGUAGE_DEFAULT,
            "User-Agent": user_agent or AllenteDefaults.USER_AGENT,
        }

    @staticmethod
    def zulu_headers(
        access_token: Optional[str] = None,
        client_version: Optional[str] = None,
        user_agent: Optional[str] = None,
        accept_language: Optional[str] = None,
    ) -> dict:
        """Headers for Zulu API calls."""
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": accept_language or AllenteDefaults.ACCEPT_LANGUAGE_DEFAULT,
            "Content-Type": "application/json",
            "Origin": AllenteDefaults.TV_WEB_ORIGIN,
            "Referer": AllenteDefaults.TV_WEB_REFERER,
            "User-Agent": user_agent or AllenteDefaults.USER_AGENT,
            "x-allente-appvariant": AllenteDefaults.APP_VARIANT,
            "x-allente-clientversion": client_version or AllenteDefaults.CLIENT_VERSION,
            "x-allente-devicetype": AllenteDefaults.DEVICE_TYPE_WEB,
        }
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        return headers


class AllenteConfig:
    """Per-instance configuration.

    ONE instance is constructed by the provider and SHARED with the
    authenticator, channel manager, and DRM builder. Never reconstruct
    a second config from a subset of values — that caused header drift.
    """

    def __init__(self, config_dict: Optional[dict] = None):
        config = config_dict or {}
        self.country = (config.get("country") or "se").lower()
        self.client_version = config.get("client_version", AllenteDefaults.CLIENT_VERSION)
        self.user_agent = config.get("user_agent", AllenteDefaults.USER_AGENT)
        self.accept_language = config.get(
            "accept_language", AllenteDefaults.ACCEPT_LANGUAGE_DEFAULT
        )

        # v1 is DASH-only: the channel list is requested as DASH and every
        # non-DASH channel is filtered out, so any other value here would
        # produce playout responses for a stream type we never list.
        requested_stream_type = str(
            config.get("stream_type") or AllenteDefaults.DEFAULT_STREAM_TYPE
        ).upper()
        if requested_stream_type != AllenteDefaults.DEFAULT_STREAM_TYPE:
            logger.warning(
                f"Allente: stream_type {requested_stream_type!r} is not supported "
                f"in v1 — using {AllenteDefaults.DEFAULT_STREAM_TYPE}"
            )
            requested_stream_type = AllenteDefaults.DEFAULT_STREAM_TYPE
        self.stream_type = requested_stream_type

        self.widevine_level = config.get(
            "widevine_level", AllenteDefaults.DEFAULT_WIDEVINE_LEVEL
        )
        self.timeout = config.get("timeout", AllenteDefaults.DEFAULT_TIMEOUT)

    @property
    def content_domain(self) -> str:
        # SE-only in v1; the fallback keeps old persisted configs working.
        return AllenteDefaults.CONTENT_DOMAIN_BY_COUNTRY.get(self.country, "DTH-SE")

    def stream_headers(self) -> dict:
        """
        Headers for the MPD and segment fetches (CDN, not Zulu).

        Akamai fronts stream-live-01.allente.tv and rejects requests
        without a whitelisted origin/referer (it answers with an "Access
        Denied" HTML page). The CDN advertises access-control-allow-origin: *
        for CORS, but that is a browser-level policy -- the actual gate is
        enforced at the edge based on these headers.
        """
        return {
            "origin": AllenteDefaults.TV_WEB_ORIGIN,
            "referer": AllenteDefaults.TV_WEB_REFERER,
            "user-agent": self.user_agent,
        }

    def zulu_headers(self, access_token: Optional[str] = None) -> dict:
        return AllenteHeaders.zulu_headers(
            access_token=access_token,
            client_version=self.client_version,
            user_agent=self.user_agent,
            accept_language=self.accept_language,
        )