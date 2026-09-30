# streaming_providers/providers/allente/models.py
"""
Allente-specific data models.

Plain data classes + from_api_response parsers. No business logic,
no network calls.
"""

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ...base.auth.base_auth import BaseAuthToken, TokenAuthLevel
from ...base.auth.credentials import UserPasswordCredentials
from ...base.models import StreamingChannel
from ...base.utils.logger import logger
from .constants import AllenteDefaults

# Fallback lifetime when the server gives no usable expiry. Deliberately
# conservative: too short only causes an extra refresh, too long causes
# requests with an expired token.
_DEFAULT_TOKEN_LIFETIME_SECONDS = 3600
# Upper clamp. Refreshing daily is cheap; trusting a mis-parsed expiry is not.
_MAX_TOKEN_LIFETIME_SECONDS = 86400


def _seconds_until_expiry(raw: Any, now: float) -> int:
    """
    Convert the Zulu `expirationTime` field to "seconds from now".

    The field is expected to be an epoch timestamp in MILLISECONDS, but the
    exact contract is not documented, so this is defensive:
      * > 1e11        -> epoch milliseconds
      * 1e9 .. 1e11   -> epoch seconds
      * 0 .. 1e9      -> relative lifetime in seconds
      * missing/invalid -> conservative default

    The chosen interpretation is logged at DEBUG so it can be verified
    during beta testing.
    """
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return _DEFAULT_TOKEN_LIFETIME_SECONDS
    if value <= 0:
        return _DEFAULT_TOKEN_LIFETIME_SECONDS

    if value > 1e11:
        kind, seconds = "epoch-ms", value / 1000.0 - now
    elif value >= 1e9:
        kind, seconds = "epoch-s", value - now
    else:
        kind, seconds = "relative-s", value

    result = int(max(0, min(seconds, _MAX_TOKEN_LIFETIME_SECONDS)))
    logger.debug(
        f"Allente: expirationTime={raw!r} interpreted as {kind} -> "
        f"expires in {result}s"
    )
    return result


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------
class AllenteUserCredentials(UserPasswordCredentials):
    """
    Username/password credentials.

    The client_id is always go-web-cdse for streaming (never mypage-cdse).
    """

    def __init__(
        self,
        username: str,
        password: str,
        client_id: Optional[str] = None,
        country: Optional[str] = None,
    ):
        super().__init__(
            username=username,
            password=password,
            client_id=client_id or AllenteDefaults.SSO_CLIENT_ID_TV,
            grant_type="password",
        )
        self.country = (country or "se").lower()

    def to_auth_payload(self) -> Dict[str, Any]:
        # NOTE: contains the plaintext password. NEVER log this dict, and
        # verify the HTTP layer does not log request bodies at DEBUG level.
        return {
            "username": self.username,
            "password": self.password,
            "isRegistrationRequired": False,
        }


# ---------------------------------------------------------------------------
# Token
# ---------------------------------------------------------------------------
class AllenteAuthToken(BaseAuthToken):
    """
    Zulu access token (from /v1/authentication/login).

    This is NOT the SSO cdsso cookie JWT. They serve different layers.

    auth_level is classified by the authenticator after fresh login/refresh
    and round-tripped through to_dict/from_dict — the framework reads it
    (SessionManager.clear_token strips it; the auth-status UI's token
    branch checks primary_token["auth_level"] == "user_authenticated").
    """

    # Identity fields a refresh response may omit; carried over from the
    # previous token by inherit_missing_from().
    _INHERITED_FIELDS = (
        "refresh_token",
        "entitlement_tag",
        "user_id",
        "user_name",
        "customer_no",
        "content_domain_id",
        "country_code",
    )

    def __init__(
        self,
        access_token: str,
        token_type: str,
        expires_in: int,
        issued_at: float,
        refresh_token: Optional[str] = None,
        entitlement_tag: Optional[str] = None,
        user_id: Optional[str] = None,
        user_name: Optional[str] = None,
        customer_no: Optional[str] = None,
        content_domain_id: Optional[str] = None,
        country_code: Optional[str] = None,
        geoblocked: bool = False,
    ):
        super().__init__(
            access_token=access_token,
            token_type=token_type,
            expires_in=expires_in,
            issued_at=issued_at,
            refresh_token=refresh_token,
        )
        self.entitlement_tag = entitlement_tag
        self.user_id = user_id
        self.user_name = user_name
        self.customer_no = customer_no
        self.content_domain_id = content_domain_id
        self.country_code = country_code
        self.geoblocked = geoblocked

    def inherit_missing_from(self, previous: Optional[BaseAuthToken]) -> "AllenteAuthToken":
        """
        Fill identity fields this token lacks from the previous token.

        A refresh response may omit entitlementTag/userId. Without this the
        refreshed token classifies as UNKNOWN and the provider would force a
        full SSO re-login on every refresh. `geoblocked` is deliberately NOT
        inherited: it must reflect the fresh server answer.
        """
        if previous is None:
            return self
        for attr in self._INHERITED_FIELDS:
            if not getattr(self, attr, None):
                value = getattr(previous, attr, None)
                if value:
                    setattr(self, attr, value)
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "issued_at": self.issued_at,
            "refresh_token": self.refresh_token,
            "auth_level": self.auth_level.value,   # e.g. "user_authenticated"
            "entitlement_tag": self.entitlement_tag,
            "user_id": self.user_id,
            "user_name": self.user_name,
            "customer_no": self.customer_no,
            "content_domain_id": self.content_domain_id,
            "country_code": self.country_code,
            "geoblocked": self.geoblocked,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AllenteAuthToken":
        """Restore a token from persisted storage (required for restart)."""
        auth_level = TokenAuthLevel.UNKNOWN
        raw_level = data.get("auth_level")
        if raw_level:
            try:
                auth_level = TokenAuthLevel(raw_level)
            except ValueError:
                pass  # unknown level string from a future schema — keep UNKNOWN

        token = cls(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_in=data["expires_in"],
            issued_at=data["issued_at"],
            refresh_token=data.get("refresh_token"),
            entitlement_tag=data.get("entitlement_tag"),
            user_id=data.get("user_id"),
            user_name=data.get("user_name"),
            customer_no=data.get("customer_no"),
            content_domain_id=data.get("content_domain_id"),
            country_code=data.get("country_code"),
            geoblocked=data.get("geoblocked", False),
        )
        token.auth_level = auth_level
        return token

    @classmethod
    def from_zulu_response(cls, data: Dict[str, Any]) -> "AllenteAuthToken":
        """
        Build from the Zulu /v1/authentication/login response (camelCase).

        auth_level is left at the dataclass default (UNKNOWN); the
        authenticator classifies via _classify_token() after construction.
        """
        now = time.time()
        expires_in = _seconds_until_expiry(data.get("expirationTime"), now)

        return cls(
            access_token=data["accessToken"],
            token_type=data.get("tokenType", "Bearer"),
            expires_in=expires_in,
            issued_at=now,
            refresh_token=data.get("refreshToken"),
            entitlement_tag=data.get("entitlementTag"),
            user_id=data.get("userId"),
            user_name=data.get("userName"),
            customer_no=data.get("customerNo"),
            content_domain_id=data.get("contentDomainId"),
            country_code=data.get("countryCode"),
            geoblocked=data.get("geoblocked", False),
        )


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------
@dataclass
class AllenteProfile:
    """A user profile from /v1/user/profiles."""

    id: str
    default: bool
    kids: bool
    parental_level: int
    audio_language: str
    subtitle_language: str
    app_language: str
    display_subtitles: bool
    deletable: bool
    name: Optional[str] = None
    avatar_id: Optional[str] = None

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "AllenteProfile":
        return cls(
            id=data["id"],
            default=data.get("default", False),
            kids=data.get("kids", False),
            parental_level=data.get("parentalLevel", 18),
            audio_language=data.get("audioLanguage", "sv"),
            subtitle_language=data.get("subtitleLanguage", "sv"),
            app_language=data.get("appLanguage", "sv"),
            display_subtitles=data.get("displaySubtitles", True),
            deletable=data.get("deletable", False),
            name=data.get("name"),
            avatar_id=data.get("avatarId"),
        )


# ---------------------------------------------------------------------------
# Entitlements
# ---------------------------------------------------------------------------
@dataclass
class AllenteEntitlements:
    """Response from /v1/user/entitlements."""

    entitlement_tag: str
    live_channels: List[str]
    catchup_channels: List[str]
    vod_libs: List[str]
    active_tvods: List[str]

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "AllenteEntitlements":
        return cls(
            entitlement_tag=data["entitlementTag"],
            live_channels=data.get("liveChannels", []),
            catchup_channels=data.get("catchupChannels", []),
            vod_libs=data.get("vodLibs", []),
            active_tvods=data.get("activeTvods", []),
        )


# ---------------------------------------------------------------------------
# Channel
# ---------------------------------------------------------------------------
@dataclass
class AllenteChannel:
    """A channel from /v1/channels.

    Parsing is strict on purpose (KeyError on missing required fields).
    The channel manager parses entry-by-entry and skips malformed entries,
    so one bad channel cannot take down the whole list.
    """

    id: str
    name: str
    position: int
    stream_id: str
    stream_url: str
    stream_type: str
    stream_drm_type: str
    content_provider_id: Optional[str] = None
    logo_url: Optional[str] = None
    is_catchup: bool = False
    is_start_over: bool = False
    start_over_window_length: Optional[int] = None
    has_epg: bool = True
    anti_ffw: bool = False
    dai_system: Optional[str] = None
    dai_channel_id: Optional[str] = None
    dai_stream_url: Optional[str] = None
    measurement_channel_id: Optional[str] = None
    dvb_triplet: Optional[str] = None
    is_fta: bool = False

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "AllenteChannel":
        dai = data.get("daiStream") or {}
        dth = data.get("dthChannel") or {}
        return cls(
            id=data["id"],
            name=data["name"],
            position=data.get("position", 0),
            stream_id=data["streamId"],
            stream_url=data["streamUrl"],
            stream_type=data.get("streamType", "DASH"),
            stream_drm_type=data.get("streamDrmType", "Widevine"),
            content_provider_id=data.get("contentProviderId"),
            logo_url=data.get("logoUrl"),
            is_catchup=data.get("isCatchup", False),
            is_start_over=data.get("isStartOver", False),
            start_over_window_length=data.get("startOverWindowLength"),
            has_epg=data.get("hasEpg", True),
            anti_ffw=data.get("antiFFW", False),
            dai_system=data.get("daiSystem"),
            dai_channel_id=data.get("daiChannelId"),
            dai_stream_url=dai.get("url"),
            measurement_channel_id=data.get("measurementChannelId"),
            dvb_triplet=dth.get("dvbTriplet"),
            is_fta=dth.get("isFta", False),
        )

    def to_streaming_channel(self, provider_name: str) -> StreamingChannel:
        """Convert to the base StreamingChannel model."""
        sc = StreamingChannel.create_live_channel(
            name=self.name,
            channel_id=self.id,
            provider=provider_name,
        )
        sc.logo_url = self.logo_url or ""
        sc.manifest = self.stream_url
        # Catch-up is out of scope for v1 — do not set catchup_hours.
        # (Note: start_over_window_length is start-over, not catch-up;
        # do not conflate them if catch-up is added later.)
        sc.catchup_hours = 0
        return sc


# ---------------------------------------------------------------------------
# Playout
# ---------------------------------------------------------------------------
@dataclass
class AllentePlayoutInfo:
    """Response from /v1/playout/channel/{id}."""

    stream_url: str
    stream_id: str
    stream_type: str
    drm_type: str

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "AllentePlayoutInfo":
        stream = data.get("stream") if isinstance(data, dict) else None
        if not isinstance(stream, dict) or not stream.get("url") or not stream.get("streamId"):
            raise ValueError(
                "Allente playout response is missing stream.url / stream.streamId"
            )
        return cls(
            stream_url=stream["url"],
            stream_id=stream["streamId"],
            stream_type=stream.get("streamType", "DASH"),
            drm_type=stream.get("drmType", "Widevine"),
        )