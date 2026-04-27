# streaming_providers/providers/rtlplus/constants.py
"""
RTL+ provider constants and default configurations
"""

from ..globals import get_user_agent

import json
import urllib.request
from typing import Optional
from ...base.utils.logger import logger


class RTLPlusDefaults:
    """Default values for RTL+ provider"""

    RTLPLUS_LOGO = "https://upload.wikimedia.org/wikipedia/commons/thumb/f/f4/RTL%2B_Logo_2021.svg/2560px-RTL%2B_Logo_2021.svg.png"

    # Device information
    DEVICE_ID = "8c3f37cc-13a3-4141-bd0f-e4b3673fe5e4"
    DEVICE_NAME = "Linux Chrome"
    PLAYREADY_DEVICE_NAME = "Windows Edge"

    # Device screen size (used in headers)
    DEVICE_PLAYER_SIZE_WIDTH = 3840
    DEVICE_PLAYER_SIZE_HEIGHT = 2160

    # User agents
    USER_AGENT = get_user_agent("windows", "chrome")
    PLAYREADY_USER_AGENT = get_user_agent("windows", "edge")

    # PlayReady SOAP action
    PLAYREADY_SOAP_ACTION = "http://schemas.microsoft.com/DRM/2007/03/protocols/AcquireLicense"

    # Supported platform identifiers
    PLATFORM_WEB = "web"
    PLATFORM_DEFAULT = PLATFORM_WEB

    # Client and version information
    CLIENT_VERSION_FALLBACK = "2025.6.26.0"
    CLIENT_ID = f"rtlplus-{PLATFORM_DEFAULT}"
    BEDROCK_CLIENT_ID = "bedrock-m6group_web"

    # API endpoints
    AUTH_BASE_URL = "https://auth.rtl.de/auth/realms/rtlplus/protocol/openid-connect"
    AUTH_ENDPOINT = f"{AUTH_BASE_URL}/token"
    AUTH_AUTHORIZE_ENDPOINT = f"{AUTH_BASE_URL}/auth"
    GRAPHQL_ENDPOINT = "https://cdn.gateway.now-plus-prod.aws-cbc.cloud/graphql"
    BASE_WEBSITE = "https://plus.rtl.de/"
    BETA_WEBSITE = "https://beta.plus.rtl.de/"
    CONFIG_ENDPOINT = "https://plus.rtl.de/assets/config/config.json"

    # Bedrock API endpoints (Linear TV)
    BEDROCK_AUTH_URL = "https://front-auth.rtlde.bedrock.tech/v2/rtlde/platforms/m6group_web/token"
    BEDROCK_LAYOUT_BASE = "https://layout.rtlde.bedrock.tech/front/v1/rtlde/m6group_web/main/token-web-31"
    BEDROCK_DRM_UPFRONT_BASE = "https://drm.rtlde.bedrock.tech/v1/customers/rtlde/platforms/m6group_web/services/rtlplus_root/users/{uid}/live"
    BEDROCK_HEARTBEAT_URL = "https://heartbeat-v2.rtlde.bedrock.tech/v2/platforms/m6group_web/notify/session_live"
    TIME_ENDPOINT = "https://time.rtlde.bedrock.tech/"
    USERS_ENDPOINT = "https://users.rtlde.bedrock.tech"
    PROFILES_PATH = "/v2/platforms/m6group_web/users/{user_id}/profiles"

    # DRM license server
    DRMTODAY_LICENSE_URL = "https://lic.drmtoday.com/license-proxy-widevine/cenc/"
    DRMTODAY_PLAYREADY_URL = "https://lic.drmtoday.com/license-proxy-headerauth/drmtoday/RightsManager.asmx"

    # DRM License Response Parsing
    DRM_LICENSE_UNWRAPPER = "json,base64"
    DRM_LICENSE_UNWRAPPER_PARAMS = {"path_data": "license"}

    # DRM Request Headers (common for all DRM types)
    DRM_COMMON_HEADERS = {
        "origin": BETA_WEBSITE.rstrip("/"),
        "referer": BETA_WEBSITE,
    }

    # Direct CDN
    ORIGIN_CDN_BASE = "https://origin.live.rtlde.bedrock.tech"

    # Anonymous credentials (fallback)
    ANONYMOUS_CLIENT_ID = "anonymous-user"
    ANONYMOUS_CLIENT_SECRET = "4bfeb73f-1c4a-4e9f-a7fa-96aa1ad3d94c"

    # HTTP settings
    DEFAULT_TIMEOUT = 30

    # Custom header carrying the signed profile JWT
    PROFILE_HEADER = "Rtlplus-Profile"

    # requiredPermission values returned by the events API
    PERMISSION_FREE_TV = "liveeventAccessToFreeTv"
    PERMISSION_PAY_TV = "liveeventAccessToPayTv"

    # GraphQL __typename values used during response parsing
    TYPENAME_LIVE_EVENT_WIDGET = "LiveEventWidget"
    TYPENAME_LIVE_EVENT = "LiveEvent"

    # Linear TV Quality Presets
    LINEAR_TV_PREFERRED_QUALITIES = ["hd", "sd"]
    LINEAR_TV_PREFERRED_FORMATS = ["dashcenc", "hlsfp"]
    LINEAR_TV_PREFERRED_DRM_TYPES = ["hardware", "software"]

    # ---------------------------------------------------------------------------
    # VOD — stream config endpoints
    # ---------------------------------------------------------------------------

    VOD_PREFERRED_VARIANTS = ["dashhd", "dashsd", "hlsfairplayhd", "hlsfairplaysd"]
    VOD_PLATFORM_GRAPHQL = PLATFORM_DEFAULT.upper()
    VOD_WURSTLAND_CONFIG_URL = "https://wurstland.plus.rtl.de/config/{rrn}/{platform}"
    VOD_WURSTLAND_PLATFORM = PLATFORM_DEFAULT.upper()

    # ---------------------------------------------------------------------------
    # VOD — root category definition
    # ---------------------------------------------------------------------------
    VOD_ROOT_SLUG = "topic-worlds"
    VOD_MOVIES_ROOT_WATCH_PATH = "/video-tv/filme"
    VOD_MOVIES_GENRE_WATCH_PATH = "/video-tv/filme/genre"
    VOD_MOVIES_ROOT_ID = "/video-tv/filme"

    VOD_MOVIE_GENRE_SLUGS = [
        "action", "abenteuer", "animation", "comedy", "dokumentation",
        "drama", "fantasy", "horror", "kinder", "krimi",
        "liebesfilm", "science-fiction", "thriller",
    ]

    VOD_SERIES_ROOT_WATCH_PATH = "/video-tv/serien"
    VOD_SERIES_GENRE_WATCH_PATH = "/video-tv/serien/genre"
    VOD_SERIES_ROOT_ID = "/video-tv/serien"

    VOD_SERIES_GENRE_SLUGS = [
        "action", "animation", "comedy", "crime", "dokumentation",
        "drama", "fantasy", "horror", "kinder", "reality",
        "romance", "science-fiction", "thriller",
    ]

    VOD_SHOWS_ROOT_WATCH_PATH = "/video-tv/shows"
    VOD_SHOWS_GENRE_WATCH_PATH = "/video-tv/shows/genre"
    VOD_SHOWS_ROOT_ID = "/video-tv/shows"

    VOD_SHOW_GENRE_SLUGS = [
        "action", "comedy", "crime", "dokumentation",
        "drama", "kinder", "reality", "romance", "thriller",
    ]

    VOD_ELEMENT_TYPE_MOVIE = "MOVIE"
    VOD_ELEMENT_TYPE_SERIES = "SERIES"
    VOD_ELEMENT_TYPE_SHOW = "SHOW"
    VOD_OVERVIEW_PAGE_LIMIT = 48


# Lazy-loaded client version
_CLIENT_VERSION_CACHE: Optional[str] = None


def _get_rtlplus_client_version() -> str:
    """Lazy fetch RTL+ client version from config endpoint."""
    global _CLIENT_VERSION_CACHE
    if _CLIENT_VERSION_CACHE is None:
        try:
            with urllib.request.urlopen(RTLPlusDefaults.CONFIG_ENDPOINT, timeout=4) as resp:
                data = json.loads(resp.read().decode())
                _CLIENT_VERSION_CACHE = data["version"]
            logger.debug(f"Fetched RTL+ client version: {_CLIENT_VERSION_CACHE}")
        except Exception as exc:
            logger.warning(
                f"Could not fetch RTL+ client version ({exc}); using fallback {RTLPlusDefaults.CLIENT_VERSION_FALLBACK}")
            _CLIENT_VERSION_CACHE = RTLPlusDefaults.CLIENT_VERSION_FALLBACK
    return _CLIENT_VERSION_CACHE


class RTLPlusGraphQL:
    """Persisted-query hashes and parameter builders for all RTL+ GraphQL operations."""

    HASHES: dict[str, str] = {
        "LiveTvStations": "845cf56a2a78110a0f978c1a2af2bc7f9a1c937d0f324ffaf852a9a4414c8485",
        "ExploreWidgetWatch": "724f21ab86aa3f8c57673a3b346cf119f6a155bf82bb0201fd3b18e28e44f1ed",
        "TopicWorlds": "3dbde4c45532f4bdb0a1d7c210db43f0888f8a82f4aab43f7a90f3c4762d8ff7",
        "Format": "d112638c0184ab5698af7b69532dfe2f12973f7af9cb137b9f70278130b1eafa",
        "MRE": "0c77404637570adff548e329a48654498c54ce1c36a459d72586ff18999bebaa",
        "Episode": "87dbde15a0d269b11606f5ff458d555e98eb493bb4fb6ddc150d812d5e9a9cf8",
        "WatchPlayerConfigV3": "fea0311fb572b6fded60c5a1a9d652f97f55d182bc4cedbdad676354a8d2797c",
        "SeoUrlData": "fcc4a812d6b93496f00c3068234db7722f553032bb760e09e5e6c74586c86f8d",
        "OverviewPage": "28aad4e992bb63330bfcd40a6906af3119d8a2612fa9fd28dae9c19127e247ca",
        "LiveEventsOverviewPage": "77a8f26d5de76daf801fcd7ae54bebd0ecabbeeb3ecb90889bc4a2e5590b7d20",
        "SeasonWithFormatAndEpisodes": "cc0fbbe17143f549a35efa6f8665ceb9b1cfae44b590f0b2381a9a304304c584",
    }

    @classmethod
    def _build(cls, operation: str, variables: str) -> dict:
        return {
            "operationName": operation,
            "variables": variables,
            "extensions": f'{{"persistedQuery":{{"version":1,"sha256Hash":"{cls.HASHES[operation]}"}}}}',
        }

    @classmethod
    def live_tv_stations(cls, epg_count: int = 4) -> dict:
        return cls._build("LiveTvStations",
                          f'{{"epgCount":{epg_count},"filter":{{"channelTypes":["BROADCAST","FAST"]}}}}')

    @classmethod
    def explore_widget_watch(cls, area: str = "home", offset: int = 0, take: int = 15) -> dict:
        return cls._build("ExploreWidgetWatch", f'{{"area":"{area}","offset":{offset},"take":{take}}}')

    @classmethod
    def season_with_episodes(cls, season_rrn: str, offset: int = 0, limit: int = 48) -> dict:
        return cls._build("SeasonWithFormatAndEpisodes",
                          f'{{"seasonId":"{season_rrn}","offset":{offset},"limit":{limit}}}')

    @classmethod
    def live_events_overview_page(cls) -> dict:
        return cls._build("LiveEventsOverviewPage", "{}")

    @classmethod
    def topic_worlds(cls, take: int = 100, offset: int = 0) -> dict:
        return cls._build("TopicWorlds", f'{{"take":{take},"offset":{offset},"filterForSearchGrid":true}}')

    @classmethod
    def format(cls, format_rrn: str) -> dict:
        return cls._build("Format", f'{{"id":"{format_rrn}"}}')

    @classmethod
    def mre(cls, format_rrn: str) -> dict:
        return cls._build("MRE", f'{{"id":"{format_rrn}"}}')

    @classmethod
    def episode(cls, episode_rrn: str) -> dict:
        return cls._build("Episode", f'{{"rrn":"{episode_rrn}"}}')

    @classmethod
    def watch_player_config(cls, rrn: str) -> dict:
        return cls._build("WatchPlayerConfigV3",
                          f'{{"platform":"{RTLPlusDefaults.VOD_PLATFORM_GRAPHQL}","id":"{rrn}"}}')

    @classmethod
    def seo_url_data(cls, watch_path: str) -> dict:
        return cls._build("SeoUrlData", f'{{"watchPath":"{watch_path}"}}')

    @classmethod
    def overview_page(cls, element_type: str, genres: list = None, offset: int = 0, limit: int = None) -> dict:
        if limit is None:
            limit = RTLPlusDefaults.VOD_OVERVIEW_PAGE_LIMIT

        filter_parts = [f'"elementType":"{element_type}"']
        if genres:
            genres_json = "[" + ",".join(f'"{g}"' for g in genres) + "]"
            filter_parts.append(f'"genres":{genres_json}')

        variables = f'{{"pagination":{{"offset":{offset},"limit":{limit}}},"filter":{{{",".join(filter_parts)}}}}}'
        return cls._build("OverviewPage", variables)


class RTLPlusHeaders:
    """Standard header configurations for RTL+ requests"""

    # Common headers shared across multiple request types
    _COMMON_HEADERS = {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "de-DE,de;q=0.9",
        "cache-control": "no-cache",
    }

    @staticmethod
    def get_base_headers(user_agent: str = None) -> dict:
        return {"User-Agent": user_agent or RTLPlusDefaults.USER_AGENT, "Accept": "application/json"}

    @staticmethod
    def get_auth_headers(user_agent: str = None) -> dict:
        headers = RTLPlusHeaders.get_base_headers(user_agent)
        headers.update({
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": RTLPlusDefaults.BASE_WEBSITE.rstrip("/"),
            "Referer": RTLPlusDefaults.BASE_WEBSITE,
        })
        return headers

    @staticmethod
    def get_api_headers(access_token: str = None, device_id: str = None, client_version: str = None,
                        user_agent: str = None) -> dict:
        headers = RTLPlusHeaders.get_base_headers(user_agent)
        headers.update({
            "Content-Type": "application/json",
            "Rtlplus-Client-Id": f"rci:rtlplus:{RTLPlusDefaults.PLATFORM_DEFAULT}",
            "Rtlplus-Referrer": "",
            "Rtlplus-Client-Version": client_version or _get_rtlplus_client_version(),
        })
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        if device_id:
            headers["X-Device-Id"] = device_id
        return headers

    @staticmethod
    def get_events_headers(access_token: str, profile_token: str = None, device_id: str = None,
                           client_version: str = None, user_agent: str = None) -> dict:
        headers = RTLPlusHeaders.get_api_headers(access_token=access_token, device_id=device_id,
                                                 client_version=client_version, user_agent=user_agent)
        if profile_token:
            headers[RTLPlusDefaults.PROFILE_HEADER] = profile_token
        return headers

    @staticmethod
    def get_bedrock_token_headers(
            oauth_token: str,
            device_id: str,
            client_version: str,
            user_agent: str,
            auth_token: str,
            timestamp: int,
            profile_id: str = None,
    ) -> dict:
        """Headers for obtaining Bedrock token."""
        headers = dict(RTLPlusHeaders._COMMON_HEADERS)
        headers.update({
            "authorization": f"Bearer {oauth_token}",
            "origin": RTLPlusDefaults.BETA_WEBSITE.rstrip("/"),
            "referer": RTLPlusDefaults.BETA_WEBSITE,
            "user-agent": user_agent,
            "x-auth-device-id": device_id,
            "x-auth-device-name": RTLPlusDefaults.DEVICE_NAME,
            "x-auth-device-player-size-width": str(RTLPlusDefaults.DEVICE_PLAYER_SIZE_WIDTH),
            "x-auth-device-player-size-height": str(RTLPlusDefaults.DEVICE_PLAYER_SIZE_HEIGHT),
            "x-auth-token": auth_token,
            "x-auth-token-timestamp": str(timestamp),
            "x-client-release": client_version,
            "x-customer-name": "rtlde",
        })
        if profile_id:
            headers["x-auth-profile-id"] = profile_id
        return headers

    @staticmethod
    def get_bedrock_layout_headers(
            oauth_token: str,
            bedrock_token: str,
            device_id: str,
            client_version: str,
            user_agent: str,
            location: str = None,
    ) -> dict:
        """Headers for Bedrock layout API calls."""
        headers = dict(RTLPlusHeaders._COMMON_HEADERS)
        headers.update({
            "authorization": f"Bearer {oauth_token}",
            "origin": RTLPlusDefaults.BETA_WEBSITE.rstrip("/"),
            "referer": RTLPlusDefaults.BETA_WEBSITE,
            "user-agent": user_agent,
            "x-bedrock-token": bedrock_token,
            "x-auth-device-id": device_id,
            "x-auth-device-name": RTLPlusDefaults.DEVICE_NAME,
            "x-client-release": client_version,
            "x-customer-name": "rtlde",
        })
        if location:
            headers["x-location"] = location
        return headers

    @staticmethod
    def get_upfront_token_headers(
            oauth_token: str,
            bedrock_token: str,
            device_id: str,
            client_version: str,
            user_agent: str,
    ) -> dict:
        """Headers for upfront token request."""
        headers = dict(RTLPlusHeaders._COMMON_HEADERS)
        headers.update({
            "authorization": f"Bearer {oauth_token}",
            "origin": RTLPlusDefaults.BETA_WEBSITE.rstrip("/"),
            "referer": RTLPlusDefaults.BETA_WEBSITE,
            "user-agent": user_agent,
            "x-bedrock-token": bedrock_token,
            "x-auth-device-id": device_id,
            "x-auth-device-name": RTLPlusDefaults.DEVICE_NAME,
            "x-client-release": client_version,
            "x-customer-name": "rtlde",
        })
        return headers

    @staticmethod
    def get_drm_license_headers(upfront_token: str, user_agent: str) -> dict:
        """Headers for DRM license request to DRMToday."""
        headers = {
            "content-type": "application/json",
            "user-agent": user_agent,
            "x-dt-auth-token": upfront_token,
        }
        # Add common DRM headers
        headers.update(RTLPlusDefaults.DRM_COMMON_HEADERS)
        return headers

    @staticmethod
    def get_playready_license_headers(upfront_token: str, user_agent: str = None) -> dict:
        """Get headers for PlayReady license request to DRMToday."""
        headers = {
            "Content-Type": "text/xml; charset=UTF-8",
            "SOAPAction": RTLPlusDefaults.PLAYREADY_SOAP_ACTION,
            "User-Agent": user_agent or RTLPlusDefaults.PLAYREADY_USER_AGENT,
            "X-Dt-Auth-Token": upfront_token,  # Note: Different case for PlayReady?
        }
        headers.update(RTLPlusDefaults.DRM_COMMON_HEADERS)
        return headers

    @staticmethod
    def get_drm_headers(access_token: str, device_id: str = None, user_agent: str = None) -> dict:
        return {
            "Origin": RTLPlusDefaults.BASE_WEBSITE.rstrip("/"),
            "Referer": RTLPlusDefaults.BASE_WEBSITE,
            "User-Agent": user_agent or RTLPlusDefaults.USER_AGENT,
            "X-Auth-Token": access_token,
            "X-Device-Id": device_id or RTLPlusDefaults.DEVICE_ID,
            "X-Device-Name": RTLPlusDefaults.DEVICE_NAME,
        }

    @staticmethod
    def get_playready_drm_headers(access_token: str, device_id: str = None) -> dict:
        return {
            "Content-Type": "text/xml; charset=UTF-8",
            "Origin": RTLPlusDefaults.BASE_WEBSITE.rstrip("/"),
            "Referer": RTLPlusDefaults.BASE_WEBSITE,
            "SOAPAction": RTLPlusDefaults.PLAYREADY_SOAP_ACTION,
            "User-Agent": RTLPlusDefaults.PLAYREADY_USER_AGENT,
            "X-Auth-Token": access_token,
            "X-Device-Id": device_id or RTLPlusDefaults.DEVICE_ID,
            "X-Device-Name": RTLPlusDefaults.PLAYREADY_DEVICE_NAME,
        }

    @staticmethod
    def get_profiles_headers(
            oauth_token: str,
            bedrock_token: str,
            client_version: str,
            user_agent: str,
    ) -> dict:
        """Headers for fetching user profiles."""
        headers = dict(RTLPlusHeaders._COMMON_HEADERS)
        headers.update({
            "authorization": f"Bearer {oauth_token}",
            "origin": RTLPlusDefaults.BETA_WEBSITE.rstrip("/"),
            "referer": RTLPlusDefaults.BETA_WEBSITE,
            "user-agent": user_agent,
            "x-bedrock-token": bedrock_token,
            "x-client-release": client_version,
            "x-customer-name": "rtlde",
        })
        return headers


class RTLPlusConfig:
    """Configuration class that can be customized per instance"""

    def __init__(self, config_dict: dict = None):
        config = config_dict or {}

        self.logo = config.get("logo", RTLPlusDefaults.RTLPLUS_LOGO)

        # Core settings
        self.client_version = config.get("client_version", _get_rtlplus_client_version())
        self.device_id = config.get("device_id", RTLPlusDefaults.DEVICE_ID)
        self.user_agent = config.get("user_agent", RTLPlusDefaults.USER_AGENT)
        self.platform = config.get("platform", RTLPlusDefaults.PLATFORM_DEFAULT)

        # Screen size
        self.screen_width = config.get("screen_width", RTLPlusDefaults.DEVICE_PLAYER_SIZE_WIDTH)
        self.screen_height = config.get("screen_height", RTLPlusDefaults.DEVICE_PLAYER_SIZE_HEIGHT)

        # API endpoints
        self.auth_endpoint = config.get("auth_endpoint", RTLPlusDefaults.AUTH_ENDPOINT)
        self.graphql_endpoint = config.get("graphql_endpoint", RTLPlusDefaults.GRAPHQL_ENDPOINT)
        self.base_website = config.get("base_website", RTLPlusDefaults.BASE_WEBSITE)
        self.beta_website = config.get("beta_website", RTLPlusDefaults.BETA_WEBSITE)
        self.config_endpoint = config.get("config_endpoint", RTLPlusDefaults.CONFIG_ENDPOINT)

        # Bedrock endpoints (Linear TV)
        self.bedrock_auth_url = config.get("bedrock_auth_url", RTLPlusDefaults.BEDROCK_AUTH_URL)
        self.bedrock_layout_base = config.get("bedrock_layout_base", RTLPlusDefaults.BEDROCK_LAYOUT_BASE)
        self.bedrock_drm_upfront_base = config.get("bedrock_drm_upfront_base", RTLPlusDefaults.BEDROCK_DRM_UPFRONT_BASE)
        self.bedrock_heartbeat_url = config.get("bedrock_heartbeat_url", RTLPlusDefaults.BEDROCK_HEARTBEAT_URL)
        self.time_endpoint = config.get("time_endpoint", RTLPlusDefaults.TIME_ENDPOINT)
        self.users_endpoint = config.get("users_endpoint", RTLPlusDefaults.USERS_ENDPOINT)
        self.profiles_path = config.get("profiles_path", RTLPlusDefaults.PROFILES_PATH)

        # DRM license server
        self.drmtoday_license_url = config.get("drmtoday_license_url", RTLPlusDefaults.DRMTODAY_LICENSE_URL)

        # Quality presets for linear TV
        self.preferred_qualities = config.get("preferred_qualities", RTLPlusDefaults.LINEAR_TV_PREFERRED_QUALITIES)
        self.preferred_formats = config.get("preferred_formats", RTLPlusDefaults.LINEAR_TV_PREFERRED_FORMATS)
        self.preferred_drm_types = config.get("preferred_drm_types", RTLPlusDefaults.LINEAR_TV_PREFERRED_DRM_TYPES)

        # HTTP settings
        self.timeout = config.get("timeout", RTLPlusDefaults.DEFAULT_TIMEOUT)

    def get_bedrock_layout_url(self, channel_seo: str) -> str:
        """Get Bedrock layout URL for a specific channel"""
        return f"{self.bedrock_layout_base}/live/{channel_seo}/layout"

    def get_profiles_url(self, user_id: str) -> str:
        """Get profiles URL for a specific user"""
        return f"{self.users_endpoint}{self.profiles_path.format(user_id=user_id)}"

    def get_epg_grid_url(self) -> str:
        """Get EPG grid URL for channel listing"""
        return f"{self.bedrock_layout_base}/epg_grid"

    def get_upfront_token_url(self, uid: str, content_id: str) -> str:
        """Get upfront token URL for DRM"""
        return f"{self.bedrock_drm_upfront_base.format(uid=uid)}/{content_id}/upfront-token"

    def get_base_headers(self) -> dict:
        return RTLPlusHeaders.get_base_headers(self.user_agent)

    def get_auth_headers(self) -> dict:
        return RTLPlusHeaders.get_auth_headers(self.user_agent)

    def get_api_headers(self, access_token: str = None) -> dict:
        return RTLPlusHeaders.get_api_headers(
            access_token=access_token,
            device_id=self.device_id,
            client_version=self.client_version,
            user_agent=self.user_agent,
        )

    def get_events_headers(self, access_token: str, profile_token: str = None) -> dict:
        return RTLPlusHeaders.get_events_headers(
            access_token=access_token,
            profile_token=profile_token,
            device_id=self.device_id,
            client_version=self.client_version,
            user_agent=self.user_agent,
        )

    def get_profiles_headers(self, oauth_token: str, bedrock_token: str) -> dict:
        """Get headers for profiles request."""
        return RTLPlusHeaders.get_profiles_headers(
            oauth_token=oauth_token,
            bedrock_token=bedrock_token,
            client_version=self.client_version,
            user_agent=self.user_agent,
        )

    def get_bedrock_token_headers(self, oauth_token: str, auth_token: str, timestamp: int,
                                  profile_id: str = None) -> dict:
        """Get headers for Bedrock token request."""
        return RTLPlusHeaders.get_bedrock_token_headers(
            oauth_token=oauth_token,
            device_id=self.device_id,
            client_version=self.client_version,
            user_agent=self.user_agent,
            auth_token=auth_token,
            timestamp=timestamp,
            profile_id=profile_id,
        )

    def get_bedrock_layout_headers(self, oauth_token: str, bedrock_token: str, location: str = None) -> dict:
        return RTLPlusHeaders.get_bedrock_layout_headers(
            oauth_token=oauth_token,
            bedrock_token=bedrock_token,
            device_id=self.device_id,
            client_version=self.client_version,
            user_agent=self.user_agent,
            location=location,
        )

    def get_upfront_token_headers(self, oauth_token: str, bedrock_token: str) -> dict:
        return RTLPlusHeaders.get_upfront_token_headers(
            oauth_token=oauth_token,
            bedrock_token=bedrock_token,
            device_id=self.device_id,
            client_version=self.client_version,
            user_agent=self.user_agent,
        )

    def get_drm_license_headers(self, upfront_token: str) -> dict:
        return RTLPlusHeaders.get_drm_license_headers(
            upfront_token=upfront_token,
            user_agent=self.user_agent,
        )

    def get_playready_license_headers(self, upfront_token: str) -> dict:
        return RTLPlusHeaders.get_playready_license_headers(
            upfront_token=upfront_token,
            user_agent=self.user_agent,
        )

    @staticmethod
    def get_drm_unwrapper_config() -> tuple:
        """Get unwrapper configuration for DRM license responses."""
        return (
            RTLPlusDefaults.DRM_LICENSE_UNWRAPPER,
            RTLPlusDefaults.DRM_LICENSE_UNWRAPPER_PARAMS,
        )
    def get_drm_headers(self, access_token: str) -> dict:
        return RTLPlusHeaders.get_drm_headers(
            access_token=access_token,
            device_id=self.device_id,
            user_agent=self.user_agent,
        )

    def get_playready_drm_headers(self, access_token: str) -> dict:
        return RTLPlusHeaders.get_playready_drm_headers(
            access_token=access_token,
            device_id=self.device_id,
        )
