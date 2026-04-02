# streaming_providers/providers/movetv/constants.py
from typing import Dict, Optional


class MoveTVConfig:
    """
    Central configuration for the move.tv / MTS-SI provider.

    All endpoint paths and fixed request parameters live here so that
    provider.py, auth.py, and vod_manager.py never contain raw strings
    or magic numbers.
    """

    # -------------------------------------------------------------------------
    # Base URLs
    # -------------------------------------------------------------------------
    API_BASE_URL: str = "https://api2.mts-si.tv"
    WEB_ORIGIN: str = "https://play.move.tv"
    WEB_REFERER: str = "https://play.move.tv/"

    # -------------------------------------------------------------------------
    # API endpoint paths  (relative to API_BASE_URL)
    # -------------------------------------------------------------------------

    # Auth
    PATH_LOGIN: str = "/api/v2/login"
    PATH_VALIDATE: str = "/api/v2/token/validate"
    PATH_TOKEN_STATUS: str = "/api/v2/token/status"

    # Live
    PATH_LIVE_CHANNELS: str = "/api/v2/content/live/all"
    PATH_LIVE_SOURCE: str = "/api/v2/content/live/source/get"

    # EPG
    PATH_EPG_ALL: str = "/api/v2/content/epg/all"

    # VOD — catalogue / filtering
    PATH_VOD_FILTERS: str = "/api/v2/content/vod/filters"
    PATH_VOD_GET_ALL: str = "/api/v2/content/vod/get/all"

    # VOD — homepage layout
    PATH_PAGE_GET: str = "/api/v2/content/page/get"
    PATH_COMPONENT_GET: str = "/api/v2/content/component/get"

    # -------------------------------------------------------------------------
    # Device / app constants sent in every login payload
    # -------------------------------------------------------------------------
    PARTNER_ID: int = 2
    DEVICE_MODEL_ID: int = 10
    DEVICE_NAME: str = "Chrome 146"
    APP_VERSION: str = "3.4.8"

    # -------------------------------------------------------------------------
    # Language / locale defaults
    # -------------------------------------------------------------------------
    DEFAULT_LANG: int = 1          # 1 = Serbian / local

    # -------------------------------------------------------------------------
    # HTTP / request defaults
    # -------------------------------------------------------------------------
    USER_AGENT: str = (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/146.0.0.0 Safari/537.36"
    )
    TIMEOUT: int = 30

    # -------------------------------------------------------------------------
    # Token sentinel: the API uses the literal string "null" for unauthenticated
    # requests instead of omitting the header entirely.
    # -------------------------------------------------------------------------
    UNAUTHENTICATED_TOKEN: str = "null"

    # -------------------------------------------------------------------------
    # Image / logo base URL (prepend to relative picture paths)
    # -------------------------------------------------------------------------
    IMAGE_BASE_URL: str = "https://api2.mts-si.tv"

    # -------------------------------------------------------------------------
    # Streaming type identifier used in the manifest source request
    # -------------------------------------------------------------------------
    DTYPE_DASH: int = 1

    # -------------------------------------------------------------------------
    # VOD: item-type IDs returned by /component/get and /vod/get/all
    # -------------------------------------------------------------------------
    # itemTypeId values observed in component responses
    ITEM_TYPE_LIVE: int = 1         # live channel card
    ITEM_TYPE_MOVIE: int = 2        # single movie / standalone VOD
    ITEM_TYPE_SERIES: int = 3       # series / show (has children / seasons)
    ITEM_TYPE_CATEGORY: int = 4     # browse category node (not playable)
    ITEM_TYPE_SERIES_CARD: int = 5  # series card as returned by /vod/get/all

    # contentSubTypeId values observed in /vod/get/all
    CONTENT_SUB_TYPE_MOVIE: int = 2
    CONTENT_SUB_TYPE_SERIES: int = 5

    # -------------------------------------------------------------------------
    # Header builders
    # -------------------------------------------------------------------------

    @classmethod
    def get_base_headers(cls, auth_token: Optional[str] = None) -> Dict[str, str]:
        """
        Returns headers shared by every request.

        When *auth_token* is None the unauthenticated sentinel value is used
        (as observed in the login request capture).
        """
        return {
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Content-Type": "application/json",
            "Origin": cls.WEB_ORIGIN,
            "Referer": cls.WEB_REFERER,
            "User-Agent": cls.USER_AGENT,
            "X-Auth-Token": auth_token if auth_token else cls.UNAUTHENTICATED_TOKEN,
        }

    @classmethod
    def get_api_headers(cls, auth_token: Optional[str] = None) -> Dict[str, str]:
        """Headers for authenticated JSON API calls (channels, manifest source, VOD)."""
        return cls.get_base_headers(auth_token)

    # -------------------------------------------------------------------------
    # Full endpoint URL helpers
    # -------------------------------------------------------------------------

    @classmethod
    def login_url(cls) -> str:
        return f"{cls.API_BASE_URL}{cls.PATH_LOGIN}"

    @classmethod
    def validate_url(cls) -> str:
        return f"{cls.API_BASE_URL}{cls.PATH_VALIDATE}"

    @classmethod
    def token_status_url(cls) -> str:
        return f"{cls.API_BASE_URL}{cls.PATH_TOKEN_STATUS}"

    @classmethod
    def channels_url(cls) -> str:
        return f"{cls.API_BASE_URL}{cls.PATH_LIVE_CHANNELS}"

    @classmethod
    def live_source_url(cls) -> str:
        return f"{cls.API_BASE_URL}{cls.PATH_LIVE_SOURCE}"

    @classmethod
    def epg_all_url(cls) -> str:
        """Full URL for fetching EPG data for a single channel."""
        return f"{cls.API_BASE_URL}{cls.PATH_EPG_ALL}"

    @classmethod
    def vod_filters_url(cls) -> str:
        return f"{cls.API_BASE_URL}{cls.PATH_VOD_FILTERS}"

    @classmethod
    def vod_get_all_url(cls) -> str:
        return f"{cls.API_BASE_URL}{cls.PATH_VOD_GET_ALL}"

    @classmethod
    def page_get_url(cls) -> str:
        return f"{cls.API_BASE_URL}{cls.PATH_PAGE_GET}"

    @classmethod
    def component_get_url(cls) -> str:
        return f"{cls.API_BASE_URL}{cls.PATH_COMPONENT_GET}"

    # -------------------------------------------------------------------------
    # Logo / image URL helper
    # -------------------------------------------------------------------------

    @classmethod
    def build_image_url(cls, path: Optional[str]) -> Optional[str]:
        """
        Turns a relative image path like '/images/tvshow_poster/…jpeg' into an
        absolute URL.  Returns None when *path* is falsy.
        """
        if not path:
            return None
        if path.startswith("http"):
            return path
        return f"{cls.IMAGE_BASE_URL}{path}"

    @classmethod
    def build_logo_url(cls, icon_path: Optional[str]) -> Optional[str]:
        """Alias kept for backward compatibility with existing channel code."""
        return cls.build_image_url(icon_path)