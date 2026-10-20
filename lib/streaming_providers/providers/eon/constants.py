# streaming_providers/providers/eon/constants.py
"""
Eon constants -- the SINGLE SOURCE OF TRUTH for every URL, header value,
identifier and default of this provider.

Identity rule: ONE id, used everywhere
    directory name == AVAILABLE_PROVIDERS key == provider_name
    == PROVIDER_NAME == credentials / session / enable-setting key
Never rename it after release.

Eon is a white-label platform (united.cloud): the same API serves several
operator brands. The brand selects the CDN/API host at runtime (see
bootstrap.EonEndpoints); the platform ("web" / "androidtv") selects the
client identity (OAuth client, device bodies, URL payload layout, UA).

Never log anything defined in PLATFORMS (client secrets) or any stream key.
"""

import base64
from dataclasses import dataclass
from typing import Dict, Optional

from ...base.errors import ConfigurationError


class EonDefaults:
    PROVIDER_NAME = "eon"
    PROVIDER_LABEL = "EON"
    PROVIDER_LOGO = "https://int.eon.tv/img/picture/eon-white-logo.png"

    # One entry pins the registry's construction country (UPPERCASE).
    # Brands are not 1:1 with countries; the default brand is Vivacom (BG).
    SUPPORTED_COUNTRIES = ("ba", "bg", "hr", "gr", "me", "si", "rs")

    DEFAULT_BRAND = "vivacom"
    DEFAULT_PLATFORM = "web"
    DEFAULT_LANGUAGE = "en"

    # --- Broker (brand / CDN discovery, generic client token) ------------
    BROKER_URL = "https://broker.global.united.cloud/"
    GLOBAL_HOST = "global.united.cloud/"
    PATH_BRANDS = "v2/brands"
    PATH_CDNINFO = "v1/cdninfo"
    PATH_OAUTH_TOKEN = "oauth/token"

    # --- API (relative to the resolved api base) -------------------------
    PATH_OTP = "v1/otp"
    PATH_DEVICES_V1 = "v1/devices"
    PATH_DEVICES_V2 = "v2/devices"
    PATH_SERVICE_PROVIDER = "v1/sp"
    PATH_PROFILES = "v1/rndprofiles"
    PATH_SERVERS = "v1/servers"
    PATH_TIME = "v1/time"
    PATH_CHANNELS = "v4/channels"
    PATH_EPG = "v2/events/epg"

    CHANNEL_TYPE_TV = "TV"
    CHANNEL_TYPE_RADIO = "RADIO"
    CHANNEL_SORT = "POSITION"

    # --- Stream URL ------------------------------------------------------
    PLAYER = "m3u8"
    CONN_TYPE_BROWSER = "BROWSER"
    CONN_TYPE_ETHERNET = "ETHERNET"
    SIG_LIVE = "live"
    SIG_CUTV = "cutv"
    SIG_RADIO = "radio"
    # The CDN rejects an encrypted URL whose ctime is older than ~20 s.
    URL_CACHE_TTL = 5.0
    # Position (1-based) in /v1/servers; the addon always took the 2nd
    # entry (3rd on Android TV). Positional on purpose -- see README of the
    # port; log when the list is shorter.
    SERVER_INDEX_WEB = 2
    SERVER_INDEX_ANDROIDTV = 3
    # video-bitrate floor sent as minvbr
    MIN_VIDEO_BITRATE = 100

    # --- Catalog cache ---------------------------------------------------
    CATALOG_TTL_SECONDS = 3600

    TIMEOUT = 30

    # --- EPG -------------------------------------------------------------
    # Rolling 7-day archive (older dates answer HTTP 400 invalid_input).
    # The future horizon is NOT verified against a real response.
    EPG_PAST_DAYS = 7
    EPG_FUTURE_DAYS = 7
    EPG_ICON_SIZE = "STB_XL"

    # --- Catchup ---------------------------------------------------------
    # Provider-wide maximum (the per-channel value is cutvDelay of v4/channels;
    # 604800000 ms = 168 h in every sample seen).
    CATCHUP_WINDOW_HOURS = 168


# brand key (config) -> CDN identifier as the broker knows it
BRAND_IDENTIFIERS: Dict[str, str] = {
    "sbb": "sbb-qa",
    "telemach": "telemach",
    "telemach-hr": "telemach-hr",
    "telemach-si": "telemach-si",
    "vivacom": "vivacom",
    "nova": "nova",
}


@dataclass(frozen=True)
class EonPlatform:
    key: str
    api_prefix: str
    api_selector: str
    device_type: str
    device_name: str
    device_model: str
    device_platform: str
    client_sw_version: str
    client_sw_build: str
    system_sw: str
    system_version: str
    user_agent: str
    client_id: str
    client_secret: str
    conn_type: str
    server_index: int

    @property
    def is_android_tv(self) -> bool:
        return self.key == "androidtv"


PLATFORMS: Dict[str, EonPlatform] = {
    "web": EonPlatform(
        key="web",
        api_prefix="web",
        api_selector="be",
        device_type="web_linux_chrome",
        device_name="",
        device_model="Chrome 150",
        device_platform="web",
        client_sw_version="",
        client_sw_build="",
        system_sw="Linux",
        system_version="x86_64",
        user_agent=(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
        ),
        client_id="b8d9ade4-1093-46a7-a4f7-0e47be463c10",
        client_secret="1w4dmww87x1e9l89essqvc81pidrqsa0li1rva23",
        conn_type=EonDefaults.CONN_TYPE_BROWSER,
        server_index=EonDefaults.SERVER_INDEX_WEB,
    ),
    "androidtv": EonPlatform(
        key="androidtv",
        api_prefix="android-tv",
        api_selector="af31",
        device_type="Android 11",
        device_name="Android TV 30",
        device_model="SHIELD Android TV",
        device_platform="android_tv",
        client_sw_version="8.1.3",
        client_sw_build="8.1.35906",
        system_sw="Android",
        system_version="11",
        user_agent=(
            "Mozilla/5.0 (Linux; Android 11; SHIELD Android TV "
            "Build/RQ1A.210105.003; wv) AppleWebKit/537.36 (KHTML, like Gecko) "
            "Version/4.0 Chrome/150.0.0.0 Mobile Safari/537.36; "
            "XDKAndroidWebView/3.0.1/XDKWebView NVIDIA NVIDIA/mdarcy/"
            "mdarcy:11/RQ1A.210105.003/7825230_3167.5736:user/release-keys "
            "NVIDIA AndroidTV 1.00A_ATV SHIELD Android TV Android/11 "
            "ExoPlayer ((1.00A_ATV::1.14.1::androidtv::)"
        ),
        client_id="5a3e24b8-70cd-4958-b716-af9ce053e594",
        client_secret="aazy6orsi9elhhs17e47lfb4palgszw6igf4y26z",
        conn_type=EonDefaults.CONN_TYPE_ETHERNET,
        server_index=EonDefaults.SERVER_INDEX_ANDROIDTV,
    ),
}


class EonConfig:
    """
    Per-instance configuration.

    ONE instance is created by the provider and SHARED with auth, api,
    bootstrap and managers. Never rebuild a second config from a subset.
    """

    def __init__(self, config_dict: Optional[dict] = None):
        c = config_dict or {}

        self.brand = str(c.get("brand", EonDefaults.DEFAULT_BRAND)).lower()
        if self.brand not in BRAND_IDENTIFIERS:
            raise ConfigurationError(
                f"{EonDefaults.PROVIDER_LABEL}: unknown brand {self.brand!r} "
                f"(known: {', '.join(sorted(BRAND_IDENTIFIERS))})"
            )
        self.brand_identifier = BRAND_IDENTIFIERS[self.brand]

        platform_key = str(c.get("platform", EonDefaults.DEFAULT_PLATFORM)).lower()
        if platform_key not in PLATFORMS:
            raise ConfigurationError(
                f"{EonDefaults.PROVIDER_LABEL}: unknown platform {platform_key!r} "
                f"(known: {', '.join(sorted(PLATFORMS))})"
            )
        self.platform = PLATFORMS[platform_key]

        self.user_agent = c.get("user_agent") or self.platform.user_agent
        self.timeout = c.get("timeout", EonDefaults.TIMEOUT)
        self.language = c.get("language", EonDefaults.DEFAULT_LANGUAGE)
        self.hide_unsubscribed = bool(c.get("hide_unsubscribed", False))
        self.include_radio = bool(c.get("include_radio", True))
        self.short_names = bool(c.get("short_names", False))
        self.channel_start_number = int(c.get("channel_start_number", 1))
        # `adaptive=true` in the URL payload. The addon sent it whenever
        # inputstream.adaptive plays (live AND replay); ffmpegdirect replay
        # rejects it. The backend feeds inputstream.adaptive.
        self.adaptive_hint = bool(c.get("adaptive_hint", True))
        self.server_index = int(c.get("server_index", self.platform.server_index))

    # ----- Header builders ---------------------------------------------
    def basic_auth_value(self) -> str:
        raw = f"{self.platform.client_id}:{self.platform.client_secret}"
        return "Basic " + base64.b64encode(raw.encode("ascii")).decode("ascii")

    def basic_headers(self) -> dict:
        """Client-credentials headers (broker calls, token endpoints)."""
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": self.basic_auth_value(),
        }

    def bearer_headers(self, access_token: str) -> dict:
        """Headers for the provider's JSON API (NOT for the CDN)."""
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"bearer {access_token}",
        }

    def epg_headers(self) -> dict:
        """Extra header the EPG endpoint wants (epoch times)."""
        return {"x-ucp-time-format": "timestamp"}

    def stream_headers(self) -> dict:
        """
        Headers for MPD / segment fetches by the player (CDN). The CDN blocks
        requests without a recognised browser / smart-TV UA; it must NOT get
        API headers (tokens).
        """
        return {"User-Agent": self.user_agent}