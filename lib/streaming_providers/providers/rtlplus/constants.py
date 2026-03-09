# streaming_providers/providers/rtlplus/constants.py
"""
RTL+ provider constants and default configurations
"""


class RTLPlusDefaults:
    """Default values for RTL+ provider"""

    RTLPLUS_LOGO = "https://upload.wikimedia.org/wikipedia/commons/thumb/f/f4/RTL%2B_Logo_2021.svg/2560px-RTL%2B_Logo_2021.svg.png"

    # Client and version information
    CLIENT_VERSION = "2025.6.26.0"
    CHROME_VERSION = "121.0.0.0"
    CLIENT_ID = "rtlplus-web"

    # Device information
    DEVICE_ID = "8c3f37cc-13a3-4141-bd0f-e4b3673fe5e4"
    DEVICE_NAME = "Linux Chrome"
    PLAYREADY_DEVICE_NAME = "Windows Edge"

    # User Agent components
    USER_AGENT = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{CHROME_VERSION} Safari/537.36"

    # PlayReady-specific user agent (Edge/Windows as seen in license acquisition requests)
    PLAYREADY_EDGE_VERSION = "145.0.0.0"
    PLAYREADY_USER_AGENT = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{PLAYREADY_EDGE_VERSION} Safari/537.36 Edg/{PLAYREADY_EDGE_VERSION}"

    # PlayReady SOAP action for license acquisition
    PLAYREADY_SOAP_ACTION = "http://schemas.microsoft.com/DRM/2007/03/protocols/AcquireLicense"

    # Supported platform identifiers
    PLATFORM_WEB = "web"
    PLATFORM_ANDROID = "android"
    PLATFORM_IOS = "ios"
    PLATFORM_SMART_TV = "smarttv"
    PLATFORM_DEFAULT = PLATFORM_WEB

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

    # GraphQL query parameters — live TV channels
    CHANNELS_QUERY_PARAMS = {
        "operationName": "LiveTvStations",
        "variables": '{"epgCount":4,"filter":{"channelTypes":["BROADCAST","FAST"]}}',
        "extensions": '{"persistedQuery":{"version":1,"sha256Hash":"845cf56a2a78110a0f978c1a2af2bc7f9a1c937d0f324ffaf852a9a4414c8485"}}',
    }

    # GraphQL query parameters — editorial home view (contains LiveEventWidget nodes)
    EVENTS_QUERY_PARAMS = {
        "operationName": "ExploreWidgetWatch",
        "variables": '{"area":"home","offset":0,"take":15}',
        "extensions": '{"persistedQuery":{"version":1,"sha256Hash":"724f21ab86aa3f8c57673a3b346cf119f6a155bf82bb0201fd3b18e28e44f1ed"}}',
    }

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
    VOD_PLATFORM_GRAPHQL = "WEB"

    # Wurstland — secondary stream resolver, returns DASH/HLS URLs
    # GET /config/{rrn}/{platform}
    VOD_WURSTLAND_CONFIG_URL = "https://wurstland.plus.rtl.de/config/{rrn}/{platform}"
    VOD_WURSTLAND_PLATFORM   = "WEB"

    # ---------------------------------------------------------------------------
    # VOD — root category definition
    # ---------------------------------------------------------------------------

    # TopicWorlds is the series/show browse API — slug "topic-worlds" maps to the root
    VOD_ROOT_SLUG = "topic-worlds"

    # ---------------------------------------------------------------------------
    # VOD — persisted-query hashes (captured from browser network traffic)
    # ---------------------------------------------------------------------------

    # TopicWorlds — browse all genre/topic worlds; variables: { take, offset, filterForSearchGrid }
    VOD_HASH_TOPIC_WORLDS  = "3dbde4c45532f4bdb0a1d7c210db43f0888f8a82f4aab43f7a90f3c4762d8ff7"

    # Format — full format detail by RRN; variables: { id }
    VOD_HASH_FORMAT        = "d112638c0184ab5698af7b69532dfe2f12973f7af9cb137b9f70278130b1eafa"

    # MRE (More / Related Episodes) — seasons + episodes for a Format; variables: { id }
    VOD_HASH_MRE           = "0c77404637570adff548e329a48654498c54ce1c36a459d72586ff18999bebaa"

    # Episode — full episode detail by RRN; variables: { rrn }
    VOD_HASH_EPISODE       = "87dbde15a0d269b11606f5ff458d555e98eb493bb4fb6ddc150d812d5e9a9cf8"

    # WatchPlayerConfigV3 — stream URL + DRM config; variables: { platform, id }
    VOD_HASH_WATCH_PLAYER  = "fea0311fb572b6fded60c5a1a9d652f97f55d182bc4cedbdad676354a8d2797c"

    # SeoUrlData — resolve watch-path hierarchy (breadcrumbs + RRI page-type)
    # Used to enumerate genre slugs under /video-tv/filme/genre/* and
    # /video-tv/serien/genre/*
    # variables: { watchPath }
    VOD_HASH_SEO_URL_DATA  = "fcc4a812d6b93496f00c3068234db7722f553032bb760e09e5e6c74586c86f8d"

    # OverviewPage — paginated grid for both movies AND series, filtered by
    # elementType ("MOVIE" | "SERIES") and optional genres list.
    # variables: { pagination: { offset, limit }, filter: { elementType, genres? } }
    VOD_HASH_OVERVIEW_PAGE = "28aad4e992bb63330bfcd40a6906af3119d8a2612fa9fd28dae9c19127e247ca"

    # OverviewPage elementType values
    VOD_ELEMENT_TYPE_MOVIE  = "MOVIE"
    VOD_ELEMENT_TYPE_SERIES = "SERIES"

    # Default page size for OverviewPage pagination
    VOD_OVERVIEW_PAGE_LIMIT = 48

    # ---------------------------------------------------------------------------
    # VOD — Movies root / genre constants
    # ---------------------------------------------------------------------------
    VOD_MOVIES_ROOT_WATCH_PATH = "/video-tv/filme"
    VOD_MOVIES_GENRE_WATCH_PATH = "/video-tv/filme/genre"
    VOD_MOVIES_ROOT_ID = "movies-genre:/video-tv/filme"
    VOD_MOVIES_GENRE_PREFIX = "movies-genre:"

    # Known movie genre slugs (seed list; validated at runtime via SeoUrlData)
    VOD_MOVIE_GENRE_SLUGS = [
        "action",
        "abenteuer",
        "animation",
        "comedy",
        "dokumentation",
        "drama",
        "fantasy",
        "horror",
        "kinder",
        "krimi",
        "liebesfilm",
        "science-fiction",
        "thriller",
    ]

    # ---------------------------------------------------------------------------
    # VOD — Series root / genre constants
    # ---------------------------------------------------------------------------
    VOD_SERIES_ROOT_WATCH_PATH = "/video-tv/serien"
    VOD_SERIES_GENRE_WATCH_PATH = "/video-tv/serien/genre"
    VOD_SERIES_ROOT_ID = "series-genre:/video-tv/serien"
    VOD_SERIES_GENRE_PREFIX = "series-genre:"

    # Known series genre slugs (seed list; validated at runtime via SeoUrlData)
    VOD_SERIES_GENRE_SLUGS = [
        "action",
        "animation",
        "comedy",
        "crime",
        "dokumentation",
        "drama",
        "fantasy",
        "horror",
        "kinder",
        "reality",
        "romance",
        "science-fiction",
        "thriller",
    ]


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
                "Rtlplus-Client-Id": RTLPlusDefaults.CLIENT_ID,
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
        self.chrome_version = config.get("chrome_version", RTLPlusDefaults.CHROME_VERSION)
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
        if "live-events" in content_id:  # rrn:watch:live-events:*:{id}
            return self.event_manifest_endpoint.format(content_id=content_id, platform=self.platform)
        if content_id.startswith("rrn:watch:videohub:station:"):
            return self.manifest_endpoint.format(channel_id=content_id, platform=self.platform)
        # episode, movie, clip — full RRN passed directly
        return self.vod_playout_endpoint.format(content_id=content_id, platform=self.platform)

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

    def get_drm_headers(self, access_token: str) -> dict:
        return RTLPlusHeaders.get_drm_headers(
            access_token=access_token,
            device_id=self.device_id,
            user_agent=self.user_agent,
        )

    def get_event_manifest_headers(self, access_token: str) -> dict:
        return RTLPlusHeaders.get_event_manifest_headers(
            access_token=access_token,
            user_agent=self.user_agent,
        )

    def get_playready_drm_headers(self, access_token: str) -> dict:
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

    @staticmethod
    def get_vod_topic_worlds_params(take: int = 100, offset: int = 0) -> dict:
        return {
            "operationName": "TopicWorlds",
            "variables": f'{{"take":{take},"offset":{offset},"filterForSearchGrid":true}}',
            "extensions": (
                '{"persistedQuery":{"version":1,"sha256Hash":'
                f'"{RTLPlusDefaults.VOD_HASH_TOPIC_WORLDS}"}}'
            ),
        }

    @staticmethod
    def get_vod_format_params(format_rrn: str) -> dict:
        return {
            "operationName": "Format",
            "variables": f'{{"id":"{format_rrn}"}}',
            "extensions": (
                '{"persistedQuery":{"version":1,"sha256Hash":'
                f'"{RTLPlusDefaults.VOD_HASH_FORMAT}"}}'
            ),
        }

    @staticmethod
    def get_vod_mre_params(format_rrn: str) -> dict:
        return {
            "operationName": "MRE",
            "variables": f'{{"id":"{format_rrn}"}}',
            "extensions": (
                '{"persistedQuery":{"version":1,"sha256Hash":'
                f'"{RTLPlusDefaults.VOD_HASH_MRE}"}}'
            ),
        }

    @staticmethod
    def get_vod_episode_params(episode_rrn: str) -> dict:
        return {
            "operationName": "Episode",
            "variables": f'{{"rrn":"{episode_rrn}"}}',
            "extensions": (
                '{"persistedQuery":{"version":1,"sha256Hash":'
                f'"{RTLPlusDefaults.VOD_HASH_EPISODE}"}}'
            ),
        }

    @staticmethod
    def get_vod_watch_player_params(rrn: str) -> dict:
        """WatchPlayerConfigV3 — stream URL + DRM config for an episode or movie."""
        return {
            "operationName": "WatchPlayerConfigV3",
            "variables": (
                f'{{"platform":"{RTLPlusDefaults.VOD_PLATFORM_GRAPHQL}",'
                f'"id":"{rrn}"}}'
            ),
            "extensions": (
                '{"persistedQuery":{"version":1,"sha256Hash":'
                f'"{RTLPlusDefaults.VOD_HASH_WATCH_PLAYER}"}}'
            ),
        }

    @staticmethod
    def get_vod_seo_url_data_params(watch_path: str) -> dict:
        """
        SeoUrlData — resolve a watch-path to its hierarchy + RRI page-type.

        Works for any watch-path:
            /video-tv/filme
            /video-tv/filme/genre/action
            /video-tv/serien
            /video-tv/serien/genre/drama

        variables: { watchPath }
        """
        return {
            "operationName": "SeoUrlData",
            "variables": f'{{"watchPath":"{watch_path}"}}',
            "extensions": (
                '{"persistedQuery":{"version":1,"sha256Hash":'
                f'"{RTLPlusDefaults.VOD_HASH_SEO_URL_DATA}"}}'
            ),
        }

    @staticmethod
    def get_vod_overview_page_params(
        element_type: str,
        genres: list = None,
        offset: int = 0,
        limit: int = None,
    ) -> dict:
        """
        OverviewPage — paginated grid for movies or series with optional genre filter.

        This single query covers both the MovieGrid and SeriesGrid use-cases:
            element_type = RTLPlusDefaults.VOD_ELEMENT_TYPE_MOVIE   → movies
            element_type = RTLPlusDefaults.VOD_ELEMENT_TYPE_SERIES  → series

        Args:
            element_type: "MOVIE" or "SERIES"
            genres:       Optional list of genre slug strings, e.g. ["drama"].
                          Pass None / [] to fetch all genres.
            offset:       Pagination offset (0-based).
            limit:        Page size (defaults to VOD_OVERVIEW_PAGE_LIMIT).

        variables: { pagination: { offset, limit }, filter: { elementType, genres? } }
        """
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

        return {
            "operationName": "OverviewPage",
            "variables": variables,
            "extensions": (
                '{"persistedQuery":{"version":1,"sha256Hash":'
                f'"{RTLPlusDefaults.VOD_HASH_OVERVIEW_PAGE}"}}'
            ),
        }