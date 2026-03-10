# streaming_providers/providers/rtlplus/constants.py
"""
RTL+ provider constants and default configurations
"""

from ..globals import get_user_agent

import json
import urllib.request
from ...base.utils.logger import logger

# Fetch RTL+ client version once at import time.
_RTLPLUS_CONFIG_URL = "https://plus.rtl.de/assets/config/config.json"
_RTLPLUS_CLIENT_VERSION_FALLBACK = "2025.6.26.0"
try:
    with urllib.request.urlopen(_RTLPLUS_CONFIG_URL, timeout=4) as _resp:
        _RTLPLUS_CLIENT_VERSION = json.loads(_resp.read().decode())["version"]
    logger.debug(f"Fetched RTL+ client version: {_RTLPLUS_CLIENT_VERSION}")
except Exception as _exc:
    logger.warning(f"Could not fetch RTL+ client version ({_exc}); using fallback {_RTLPLUS_CLIENT_VERSION_FALLBACK}")
    _RTLPLUS_CLIENT_VERSION = _RTLPLUS_CLIENT_VERSION_FALLBACK

class RTLPlusDefaults:
    """Default values for RTL+ provider"""

    RTLPLUS_LOGO = "https://upload.wikimedia.org/wikipedia/commons/thumb/f/f4/RTL%2B_Logo_2021.svg/2560px-RTL%2B_Logo_2021.svg.png"

    # Device information
    DEVICE_ID = "8c3f37cc-13a3-4141-bd0f-e4b3673fe5e4"
    DEVICE_NAME = "Linux Chrome"
    PLAYREADY_DEVICE_NAME = "Windows Edge"

    # User agents — sourced from globals.get_user_agent() so versions stay current.
    # Windows Chrome is used for standard requests; Windows Edge for PlayReady
    # license acquisition (SOAP/XML), which requires an Edge UA.
    USER_AGENT = get_user_agent("windows", "chrome")
    PLAYREADY_USER_AGENT = get_user_agent("windows", "edge")

    # PlayReady SOAP action for license acquisition
    PLAYREADY_SOAP_ACTION = "http://schemas.microsoft.com/DRM/2007/03/protocols/AcquireLicense"

    # Supported platform identifiers
    PLATFORM_WEB = "web"
    PLATFORM_ANDROID = "android"
    PLATFORM_IOS = "ios"
    PLATFORM_SMART_TV = "smarttv"
    PLATFORM_DEFAULT = PLATFORM_WEB

    # Client and version information
    CLIENT_VERSION = _RTLPLUS_CLIENT_VERSION
    CLIENT_ID = f"rtlplus-{PLATFORM_DEFAULT}"

    # API endpoints
    AUTH_BASE_URL = "https://auth.rtl.de/auth/realms/rtlplus/protocol/openid-connect"
    AUTH_ENDPOINT = f"{AUTH_BASE_URL}/token"
    AUTH_AUTHORIZE_ENDPOINT = f"{AUTH_BASE_URL}/auth"
    GRAPHQL_ENDPOINT = "https://cdn.gateway.now-plus-prod.aws-cbc.cloud/graphql"
    MANIFEST_ENDPOINT = (
        "https://stus.player.streamingtech.de/livestream/linear/{channel_id}?platform={platform}"
    )
    EVENT_MANIFEST_ENDPOINT = (
        "https://stus.player.streamingtech.de/liveevent/{content_id}?platform={platform}"
    )
    VOD_PLAYOUT_ENDPOINT = (
        "https://stus.player.streamingtech.de/watch-playout-variants/{content_id}?platform={platform}"
    )
    BASE_WEBSITE = "https://plus.rtl.de/"
    CONFIG_ENDPOINT = "https://plus.rtl.de/assets/config/config.json"

    # Anonymous credentials (fallback)
    ANONYMOUS_CLIENT_ID = "anonymous-user"
    ANONYMOUS_CLIENT_SECRET = "4bfeb73f-1c4a-4e9f-a7fa-96aa1ad3d94c"

    # HTTP settings
    DEFAULT_TIMEOUT = 30

    # Custom header carrying the signed profile JWT (required by the events endpoint)
    PROFILE_HEADER = "Rtlplus-Profile"

    # requiredPermission values returned by the events API
    PERMISSION_FREE_TV = "liveeventAccessToFreeTv"
    PERMISSION_PAY_TV = "liveeventAccessToPayTv"

    # GraphQL __typename values used during response parsing
    TYPENAME_LIVE_EVENT_WIDGET = "LiveEventWidget"
    TYPENAME_LIVE_EVENT = "LiveEvent"

    # ---------------------------------------------------------------------------
    # VOD — stream config endpoints
    # ---------------------------------------------------------------------------

    # Preferred stream-variant order for VOD (first match wins)
    VOD_PREFERRED_VARIANTS = ["dashhd", "dashsd", "hlsfairplayhd", "hlsfairplaysd"]

    # WatchPlayerConfigV3 returns stream URLs + DRM config directly from GraphQL
    # (replaces the watch-playout-variants REST endpoint for VOD)
    VOD_PLATFORM_GRAPHQL = PLATFORM_DEFAULT.upper()

    # Wurstland — secondary stream resolver, returns DASH/HLS URLs
    # GET /config/{rrn}/{platform}
    VOD_WURSTLAND_CONFIG_URL = "https://wurstland.plus.rtl.de/config/{rrn}/{platform}"
    VOD_WURSTLAND_PLATFORM   = PLATFORM_DEFAULT.upper()

    # ---------------------------------------------------------------------------
    # VOD — root category definition
    # ---------------------------------------------------------------------------
    VOD_ROOT_SLUG = "topic-worlds"

    # Movies root / genre constants
    VOD_MOVIES_ROOT_WATCH_PATH  = "/video-tv/filme"
    VOD_MOVIES_GENRE_WATCH_PATH = "/video-tv/filme/genre"
    VOD_MOVIES_ROOT_ID          = "/video-tv/filme"

    VOD_MOVIE_GENRE_SLUGS = [
        "action", "abenteuer", "animation", "comedy", "dokumentation",
        "drama", "fantasy", "horror", "kinder", "krimi",
        "liebesfilm", "science-fiction", "thriller",
    ]

    # Series root / genre constants
    VOD_SERIES_ROOT_WATCH_PATH  = "/video-tv/serien"
    VOD_SERIES_GENRE_WATCH_PATH = "/video-tv/serien/genre"
    VOD_SERIES_ROOT_ID          = "/video-tv/serien"

    VOD_SERIES_GENRE_SLUGS = [
        "action", "animation", "comedy", "crime", "dokumentation",
        "drama", "fantasy", "horror", "kinder", "reality",
        "romance", "science-fiction", "thriller",
    ]

    # Shows root / genre constants
    VOD_SHOWS_ROOT_WATCH_PATH  = "/video-tv/shows"
    VOD_SHOWS_GENRE_WATCH_PATH = "/video-tv/shows/genre"
    VOD_SHOWS_ROOT_ID          = "/video-tv/shows"

    VOD_SHOW_GENRE_SLUGS = [
        "action", "comedy", "crime", "dokumentation",
        "drama", "kinder", "reality", "romance", "thriller",
    ]

    # OverviewPage elementType values and pagination
    VOD_ELEMENT_TYPE_MOVIE  = "MOVIE"
    VOD_ELEMENT_TYPE_SERIES = "SERIES"
    VOD_ELEMENT_TYPE_SHOW   = "SHOW"
    VOD_OVERVIEW_PAGE_LIMIT = 48


class RTLPlusGraphQL:
    """
    Persisted-query hashes and parameter builders for all RTL+ GraphQL operations.

    The HASHES dict maps each GraphQL operationName to its sha256 hash as
    captured from live browser network traffic.  Every builder method calls
    _build(), which assembles the standard persisted-query envelope so that
    the boilerplate never has to be repeated.
    """

    # sha256 hashes keyed by operationName (captured from browser network traffic)
    HASHES: dict[str, str] = {

        "LiveTvStations":     "845cf56a2a78110a0f978c1a2af2bc7f9a1c937d0f324ffaf852a9a4414c8485",
        "ExploreWidgetWatch": "724f21ab86aa3f8c57673a3b346cf119f6a155bf82bb0201fd3b18e28e44f1ed",
        "TopicWorlds":        "3dbde4c45532f4bdb0a1d7c210db43f0888f8a82f4aab43f7a90f3c4762d8ff7",
        "Format":             "d112638c0184ab5698af7b69532dfe2f12973f7af9cb137b9f70278130b1eafa",
        "MRE":                "0c77404637570adff548e329a48654498c54ce1c36a459d72586ff18999bebaa",
        "Episode":            "87dbde15a0d269b11606f5ff458d555e98eb493bb4fb6ddc150d812d5e9a9cf8",
        "WatchPlayerConfigV3":"fea0311fb572b6fded60c5a1a9d652f97f55d182bc4cedbdad676354a8d2797c",
        "SeoUrlData":             "fcc4a812d6b93496f00c3068234db7722f553032bb760e09e5e6c74586c86f8d",
        "OverviewPage":           "28aad4e992bb63330bfcd40a6906af3119d8a2612fa9fd28dae9c19127e247ca",
        "LiveEventsOverviewPage":       "77a8f26d5de76daf801fcd7ae54bebd0ecabbeeb3ecb90889bc4a2e5590b7d20",
        "SeasonWithFormatAndEpisodes":  "cc0fbbe17143f549a35efa6f8665ceb9b1cfae44b590f0b2381a9a304304c584",
    }

    @classmethod
    def _build(cls, operation: str, variables: str) -> dict:
        """Assemble a persisted-query parameter dict for *operation*."""
        return {
            "operationName": operation,
            "variables": variables,
            "extensions": (
                f'{{"persistedQuery":{{"version":1,"sha256Hash":"{cls.HASHES[operation]}"}}}}'
            ),
        }

    # --- Live TV / Events ---

    @classmethod
    def live_tv_stations(cls, epg_count: int = 4) -> dict:
        """LiveTvStations — all broadcast + FAST channels with EPG slots."""
        return cls._build(
            "LiveTvStations",
            f'{{"epgCount":{epg_count},"filter":{{"channelTypes":["BROADCAST","FAST"]}}}}',
        )

    @classmethod
    def explore_widget_watch(cls, area: str = "home", offset: int = 0, take: int = 15) -> dict:
        """ExploreWidgetWatch — editorial home view containing LiveEventWidget nodes."""
        return cls._build(
            "ExploreWidgetWatch",
            f'{{"area":"{area}","offset":{offset},"take":{take}}}',
        )

    @classmethod
    def season_with_episodes(cls, season_rrn: str, offset: int = 0, limit: int = 48) -> dict:
        """SeasonWithFormatAndEpisodes — episodes for a specific season RRN."""
        return cls._build(
            "SeasonWithFormatAndEpisodes",
            f'{{"seasonId":"{season_rrn}","offset":{offset},"limit":{limit}}}',
        )

    @classmethod
    def live_events_overview_page(cls) -> dict:
        """LiveEventsOverview — all upcoming/live events grouped by teaserRows."""
        return cls._build("LiveEventsOverviewPage", "{}")

    # --- VOD ---

    @classmethod
    def topic_worlds(cls, take: int = 100, offset: int = 0) -> dict:
        """TopicWorlds — browse all genre/topic worlds.

        Confirmed from live traffic:
          response key:  data.topicWorldsV2.elements[]   (NOT topicWorlds.items[])
          pagination:    data.topicWorldsV2.pageInfo.hasNextPage
        """
        return cls._build(
            "TopicWorlds",
            f'{{"take":{take},"offset":{offset},"filterForSearchGrid":true}}',
        )

    @classmethod
    def format(cls, format_rrn: str) -> dict:
        """Format — full format detail (seasons, metadata) by RRN."""
        return cls._build("Format", f'{{"id":"{format_rrn}"}}')

    @classmethod
    def mre(cls, format_rrn: str) -> dict:
        """MRE — seasons + related episodes for a Format."""
        return cls._build("MRE", f'{{"id":"{format_rrn}"}}')

    @classmethod
    def episode(cls, episode_rrn: str) -> dict:
        """Episode — full episode detail by RRN."""
        return cls._build("Episode", f'{{"rrn":"{episode_rrn}"}}')

    @classmethod
    def watch_player_config(cls, rrn: str) -> dict:
        """WatchPlayerConfigV3 — stream URL + DRM config for an episode or movie."""
        return cls._build(
            "WatchPlayerConfigV3",
            f'{{"platform":"{RTLPlusDefaults.VOD_PLATFORM_GRAPHQL}","id":"{rrn}"}}',
        )

    @classmethod
    def seo_url_data(cls, watch_path: str) -> dict:
        """SeoUrlData — resolve a watch-path to its content hierarchy."""
        return cls._build("SeoUrlData", f'{{"watchPath":"{watch_path}"}}')

    @classmethod
    def overview_page(
        cls,
        element_type: str,
        genres: list = None,
        offset: int = 0,
        limit: int = None,
    ) -> dict:
        """OverviewPage — paginated grid for MOVIE or SERIES with optional genre filter."""
        if limit is None:
            limit = RTLPlusDefaults.VOD_OVERVIEW_PAGE_LIMIT

        filter_parts = [f'"elementType":"{element_type}"']
        if genres:
            genres_json = "[" + ",".join(f'"{g}"' for g in genres) + "]"
            filter_parts.append(f'"genres":{genres_json}')

        variables = (
            f'{{"pagination":{{"offset":{offset},"limit":{limit}}},'
            f'"filter":{{{",".join(filter_parts)}}}}}'
        )
        return cls._build("OverviewPage", variables)


class RTLPlusHeaders:
    """Standard header configurations for RTL+ requests"""

    @staticmethod
    def get_base_headers(user_agent: str = None) -> dict:
        """Get base HTTP headers"""
        return {
            "User-Agent": user_agent or RTLPlusDefaults.USER_AGENT,
            "Accept": "application/json",
        }

    @staticmethod
    def get_auth_headers(user_agent: str = None) -> dict:
        """Get headers for authentication requests"""
        headers = RTLPlusHeaders.get_base_headers(user_agent)
        headers.update(
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": RTLPlusDefaults.BASE_WEBSITE.rstrip("/"),
                "Referer": RTLPlusDefaults.BASE_WEBSITE,
            }
        )
        return headers

    @staticmethod
    def get_api_headers(
        access_token: str = None,
        device_id: str = None,
        client_version: str = None,
        user_agent: str = None,
    ) -> dict:
        """Get headers for authenticated API requests"""
        headers = RTLPlusHeaders.get_base_headers(user_agent)
        headers.update(
            {
                "Content-Type": "application/json",
                "Rtlplus-Client-Id": f"rci:rtlplus:{RTLPlusDefaults.PLATFORM_DEFAULT}",
                "Rtlplus-Referrer": "",
                "Rtlplus-Client-Version": client_version or RTLPlusDefaults.CLIENT_VERSION,
            }
        )

        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"

        if device_id:
            headers["X-Device-Id"] = device_id

        return headers

    @staticmethod
    def get_events_headers(
        access_token: str,
        profile_token: str = None,
        device_id: str = None,
        client_version: str = None,
        user_agent: str = None,
    ) -> dict:
        """Get headers for the editorial GraphQL endpoint (events / ExploreWidgetWatch).

        Extends the standard API headers with the optional ``Rtlplus-Profile``
        JWT that the browser sends when a user profile is active.  The header
        is omitted when *profile_token* is ``None`` so that anonymous / client-
        credential sessions work without modification.

        Args:
            access_token:   Bearer token from the auth endpoint.
            profile_token:  Signed profile JWT (``Rtlplus-Profile`` header).
                            Pass ``None`` for anonymous / client-credential sessions.
            device_id:      Device UUID forwarded as ``X-Device-Id``.
            client_version: Client version string; falls back to the default.
            user_agent:     UA string; falls back to the default.

        Returns:
            dict of HTTP headers ready for use with the GraphQL endpoint.
        """
        headers = RTLPlusHeaders.get_api_headers(
            access_token=access_token,
            device_id=device_id,
            client_version=client_version,
            user_agent=user_agent,
        )

        if profile_token:
            headers[RTLPlusDefaults.PROFILE_HEADER] = profile_token

        return headers

    @staticmethod
    def get_drm_headers(access_token: str, device_id: str = None, user_agent: str = None) -> dict:
        return {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "de-DE,de;q=0.9",
            "Cache-Control": "no-cache",
            "Origin": RTLPlusDefaults.BASE_WEBSITE.rstrip("/"),
            "Referer": RTLPlusDefaults.BASE_WEBSITE,
            "User-Agent": user_agent or RTLPlusDefaults.USER_AGENT,
            "X-Auth-Token": access_token,
            "X-Device-Id": device_id or RTLPlusDefaults.DEVICE_ID,
            "X-Device-Name": RTLPlusDefaults.DEVICE_NAME,
        }

    @staticmethod
    def get_event_manifest_headers(access_token: str, user_agent: str = None) -> dict:
        """Get headers for the event manifest endpoint (stus.player.streamingtech.de/liveevent).
        Uses X-Auth-Token scheme as required by this endpoint."""
        return {
            "X-Auth-Token": access_token,
            "Content-Type": "application/json",
            "Origin": RTLPlusDefaults.BASE_WEBSITE.rstrip("/"),
            "Referer": RTLPlusDefaults.BASE_WEBSITE,
            "User-Agent": user_agent or RTLPlusDefaults.USER_AGENT,
        }

    @staticmethod
    def get_playready_drm_headers(access_token: str, device_id: str = None) -> dict:
        """Get headers for PlayReady DRM license acquisition (SOAP/XML)"""
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


class RTLPlusConfig:
    """Configuration class that can be customized per instance"""

    def __init__(self, config_dict: dict = None):
        """Initialize with optional configuration overrides"""
        config = config_dict or {}

        self.logo = config.get("logo", RTLPlusDefaults.RTLPLUS_LOGO)

        # Core settings (can be overridden)
        self.client_version = config.get("client_version", RTLPlusDefaults.CLIENT_VERSION)
        self.device_id = config.get("device_id", RTLPlusDefaults.DEVICE_ID)
        self.user_agent = config.get("user_agent", RTLPlusDefaults.USER_AGENT)
        self.platform = config.get("platform", RTLPlusDefaults.PLATFORM_DEFAULT)

        # API endpoints (can be overridden for testing)
        self.auth_endpoint = config.get("auth_endpoint", RTLPlusDefaults.AUTH_ENDPOINT)
        self.graphql_endpoint = config.get("graphql_endpoint", RTLPlusDefaults.GRAPHQL_ENDPOINT)
        self.manifest_endpoint = config.get("manifest_endpoint", RTLPlusDefaults.MANIFEST_ENDPOINT)
        self.event_manifest_endpoint = config.get("event_manifest_endpoint", RTLPlusDefaults.EVENT_MANIFEST_ENDPOINT)
        self.vod_playout_endpoint = config.get("vod_playout_endpoint", RTLPlusDefaults.VOD_PLAYOUT_ENDPOINT)
        self.base_website = config.get("base_website", RTLPlusDefaults.BASE_WEBSITE)
        self.config_endpoint = config.get("config_endpoint", RTLPlusDefaults.CONFIG_ENDPOINT)

        # HTTP settings
        self.timeout = config.get("timeout", RTLPlusDefaults.DEFAULT_TIMEOUT)

    def get_manifest_url(self, content_id: str) -> str:
        if "live-events" in content_id:
            return self.event_manifest_endpoint.format(
                content_id=content_id, platform=self.platform
            )
        if content_id.startswith("rrn:watch:videohub:station:"):
            return self.manifest_endpoint.format(
                channel_id=content_id, platform=self.platform
            )
        return self.vod_playout_endpoint.format(
            content_id=content_id, platform=self.platform
        )

    def get_base_headers(self) -> dict:
        """Get base headers with this config's user agent"""
        return RTLPlusHeaders.get_base_headers(self.user_agent)

    def get_auth_headers(self) -> dict:
        """Get auth headers with this config's settings"""
        return RTLPlusHeaders.get_auth_headers(self.user_agent)

    def get_api_headers(self, access_token: str = None) -> dict:
        """Get API headers with this config's settings"""
        return RTLPlusHeaders.get_api_headers(
            access_token=access_token,
            device_id=self.device_id,
            client_version=self.client_version,
            user_agent=self.user_agent,
        )

    def get_events_headers(self, access_token: str, profile_token: str = None) -> dict:
        """
        Get headers for the editorial GraphQL endpoint with this config's settings.

        Args:
            access_token:  Bearer token from the auth endpoint.
            profile_token: Optional signed profile JWT (``Rtlplus-Profile``).

        Returns:
            dict of HTTP headers.
        """
        return RTLPlusHeaders.get_events_headers(
            access_token=access_token,
            profile_token=profile_token,
            device_id=self.device_id,
            client_version=self.client_version,
            user_agent=self.user_agent,
        )

    def get_drm_headers(self, access_token: str) -> dict:
        """Get DRM headers with this config's settings"""
        return RTLPlusHeaders.get_drm_headers(
            access_token=access_token,
            device_id=self.device_id,
            user_agent=self.user_agent,
        )

    def get_event_manifest_headers(self, access_token: str) -> dict:
        """Get event manifest headers with this config's settings."""
        return RTLPlusHeaders.get_event_manifest_headers(
            access_token=access_token,
            user_agent=self.user_agent,
        )

    def get_playready_drm_headers(self, access_token: str) -> dict:
        """Get PlayReady-specific DRM headers (Edge UA, SOAP content-type)"""
        return RTLPlusHeaders.get_playready_drm_headers(
            access_token=access_token,
            device_id=self.device_id,
        )

    # ---------------------------------------------------------------------------
    # VOD helpers
    # ---------------------------------------------------------------------------

    @staticmethod
    def get_vod_wurstland_url(rrn: str) -> str:
        """Return the Wurstland config URL for a VOD RRN."""
        return RTLPlusDefaults.VOD_WURSTLAND_CONFIG_URL.format(
            rrn=rrn, platform=RTLPlusDefaults.VOD_WURSTLAND_PLATFORM
        )