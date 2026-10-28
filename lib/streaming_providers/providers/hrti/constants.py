# streaming_providers/providers/hrti/constants.py
"""
HRTi constants -- the single source of truth for URLs, header values,
identifiers and defaults. Managers, session, drm.py and auth.py read from here.

Identity (ONE id everywhere): directory == registry key == provider_name ==
PROVIDER_NAME == credentials / session key == "hrti". PROVIDER_LABEL ("HRTi")
is only the UI label.

Dynamic endpoints
-----------------
The API hosts are NOT hardcoded: ``env.json`` and ``config.production.json``
on hrti.hrt.hr name them (``apiUrl``, ``webApiUrl``, merchant, ...). ONE
HRTiConfig instance is shared by authenticator, session and managers and
loads them lazily (``ensure_loaded``) -- independent of the login, so it also
works after a restart with a persisted session. If the bootstrap fails the
defaults below are used (they equal the live values).
"""

import threading
from typing import Any, ClassVar, Dict, Optional

from ...base.errors import ConfigurationError
from ...base.utils.logger import logger
from ..globals import get_identity


# One browser identity -> User-Agent AND client type, from the central
# registry (no drift between the two, and the Chrome version follows the
# live stable feed rather than a hardcoded literal).
_HRTI_IDENTITY = get_identity("linux", "chrome")


class HRTiDefaults:
    PROVIDER_NAME = "hrti"
    PROVIDER_LABEL = "HRTi"
    PROVIDER_LOGO = "https://upload.wikimedia.org/wikipedia/en/thumb/9/9e/Logo_of_the_HRT.svg/960px-Logo_of_the_HRT.svg.png"
    SUPPORTED_COUNTRIES = ("HR",)

    # Website / bootstrap
    BASE_WEBSITE = "https://hrti.hrt.hr"
    BASE_URL = "https://hrti.hrt.hr"
    ENV_ENDPOINT = f"{BASE_URL}/assets/config/env.json"
    CONFIG_ENDPOINT = f"{BASE_URL}/assets/config/config.production.json"

    # Fallbacks, used only when the bootstrap above fails
    FALLBACK_HSAPI_URL = "https://hsapi.aviion.tv/client.svc/json"
    FALLBACK_WEB_API_URL = "api/api/ott"
    FALLBACK_MERCHANT = "aviion2"

    # Endpoint path templates; base URLs come from the bootstrap
    API_ENDPOINT_PATHS: ClassVar[Dict[str, str]] = {
        "get_ip": "/getIPAddress",
        "grant_access": "/GrantAccess",
        "channels": "/GetChannels",
        "programme": "/GetProgramme",
        "epg_details": "/GetEpgDetails",
        "authorize_session": "/AuthorizeSession",
        "report_session": "/ReportSessionEvent",
        "register_device": "/RegisterDevice",
        "content_ratings": "/ContentRatingsGet",
        "profiles": "/ProfilesGet",
        "catalogue_structure": "/GetCatalogueStructure",
        "catalogue": "/GetCatalogue",
        "vod_details": "/GetVodDetails",
        "episodes": "/GetSeries",
        "watch_later": "/GetWatchLater",
        "editors_choice": "/GetEditorsChoice",
    }
    # served by the web API (webApiUrl) / by the HSAPI (apiUrl)
    WEB_API_ENDPOINTS = (
        "get_ip", "grant_access", "channels", "programme", "epg_details",
        "authorize_session", "report_session", "catalogue_structure",
        "catalogue", "vod_details", "episodes", "watch_later", "editors_choice",
    )
    HSAPI_ENDPOINTS = ("register_device", "content_ratings", "profiles")

    # Device information (overridable through the config dict)
    DEVICE_REFERENCE_ID = "6"          # string '6' as required by the headers
    OPERATOR_REFERENCE_ID = "hrt"
    CONNECTION_TYPE = "LAN/WiFi"
    APPLICATION_VERSION = "5.97.6"     # replaced by env.json's applicationVersion
    OS_VERSION = "Linux"

    # One browser identity -> User-Agent AND client type (no drift between
    # them). Both now follow the central Chrome registry. VERIFY: if the HRTi
    # backend cross-checks client_type against the User-Agent's Chrome version
    # on login, the two still match; if it expects a *fixed* historic version
    # (e.g. the production web app's pinned build), a login rejection will
    # appear on the first request after deploy — watch the login logs.
    CHROME_MAJOR = _HRTI_IDENTITY.chrome_major
    CLIENT_TYPE = f"Chrome {CHROME_MAJOR}"
    USER_AGENT = _HRTI_IDENTITY.user_agent

    # Anonymous (client-credentials) access -- the deliberate fallback
    ANONYMOUS_USERNAME = "anonymoushrt"
    ANONYMOUS_PASSWORD = "an0nPasshrt"

    # Auth / session
    TOKEN_LIFETIME_SECONDS = 86400     # GrantAccess carries no lifetime
    SESSION_BACKOFF_BASE = 2.0         # transient login failures: base * 2**(n-1) s
    SESSION_BACKOFF_CAP = 60.0

    # HTTP / VOD
    DEFAULT_TIMEOUT = 30
    VOD_ITEMS_PER_PAGE = 24
    MAX_VOD_PAGES = 100
    SERIES_PAGE_SIZE = 100

    # DRM (DRMToday, token travels in this header; priority was the lib default)
    DRM_AUTH_HEADER = "dt-custom-data"
    WIDEVINE_PRIORITY = 3

    # Caches
    PLAYOUT_CACHE_TTL = 5.0            # manifest + DRM share one authorised session


class HRTiConfig:
    """Per-instance configuration. ONE instance, shared by every layer."""

    def __init__(self, config_dict: Optional[dict] = None):
        config = config_dict or {}
        self.logo = config.get("logo", HRTiDefaults.PROVIDER_LOGO)
        self.base_website = config.get("base_website", HRTiDefaults.BASE_WEBSITE)
        self.base_url = config.get("base_url", HRTiDefaults.BASE_URL)

        # Dynamic values, filled by the bootstrap
        self.hsapi_base_url = config.get("hsapi_base_url")
        self.web_api_url = config.get("web_api_url")
        self.merchant = config.get("merchant")
        self.player_license_key = config.get("player_license_key")
        self.selfcare_url = None
        self.homepage_url = None

        self.env_endpoint = config.get("env_endpoint", HRTiDefaults.ENV_ENDPOINT)
        self.config_endpoint = config.get("config_endpoint", HRTiDefaults.CONFIG_ENDPOINT)
        self.api_endpoint_paths = config.get(
            "api_endpoint_paths", HRTiDefaults.API_ENDPOINT_PATHS.copy()
        )
        self.api_endpoints: Dict[str, str] = {}

        self.device_reference_id = config.get("device_reference_id", HRTiDefaults.DEVICE_REFERENCE_ID)
        self.operator_reference_id = config.get("operator_reference_id", HRTiDefaults.OPERATOR_REFERENCE_ID)
        self.connection_type = config.get("connection_type", HRTiDefaults.CONNECTION_TYPE)
        self.application_version = config.get("application_version", HRTiDefaults.APPLICATION_VERSION)
        self.os_version = config.get("os_version", HRTiDefaults.OS_VERSION)
        self.client_type = config.get("client_type", HRTiDefaults.CLIENT_TYPE)
        self.user_agent = config.get("user_agent", HRTiDefaults.USER_AGENT)
        self.timeout = config.get("timeout", HRTiDefaults.DEFAULT_TIMEOUT)
        self.vod_items_per_page = config.get("vod_items_per_page", HRTiDefaults.VOD_ITEMS_PER_PAGE)

        self._http: Any = None
        self._loaded = False
        self.loaded_from_fallback = False
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Lazy dynamic endpoints
    # ------------------------------------------------------------------
    def attach_http(self, http_manager: Any) -> None:
        """Give the config the HTTP manager used for the bootstrap fetch."""
        self._http = http_manager

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def ensure_loaded(self) -> None:
        """Fetch env.json + config.production.json once; fall back to defaults."""
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            if self._http is None:
                raise ConfigurationError(
                    "HRTi: HTTP manager not attached to the config (attach_http)"
                )
            try:
                env_resp = self._http.get(self.env_endpoint, operation="api")
                env_resp.raise_for_status()
                cfg_resp = self._http.get(self.config_endpoint, operation="api")
                cfg_resp.raise_for_status()
                self.update_from_api(env_resp.json(), cfg_resp.json())
                self.loaded_from_fallback = False
                if not self.hsapi_base_url or not self.web_api_url:
                    # Bootstrap answered but lacks apiUrl / webApiUrl: fill ONLY the
                    # gaps from the defaults (otherwise endpoint() raises a PERMANENT
                    # ConfigurationError for every later call).
                    logger.warning("HRTi: bootstrap config incomplete; filling gaps from defaults")
                    self._build_fallback_endpoints()
                    self.loaded_from_fallback = True
                logger.debug("HRTi environment configuration loaded")
            except Exception as exc:  # deliberate: bootstrap failure -> documented defaults
                logger.warning(f"HRTi: environment config unavailable ({exc}); using defaults")
                self._build_fallback_endpoints()
                self.loaded_from_fallback = True
            self._loaded = True

    def endpoint(self, key: str) -> str:
        """Full URL of a named endpoint (loads the dynamic config on first use)."""
        self.ensure_loaded()
        url = self.api_endpoints.get(key)
        if not url:
            raise ConfigurationError(f"HRTi: no endpoint configured for '{key}'")
        return url

    def get_merchant(self) -> str:
        self.ensure_loaded()
        return self.merchant or HRTiDefaults.FALLBACK_MERCHANT

    def update_from_api(self, env_data: dict, config_data: dict) -> None:
        if "applicationVersion" in env_data:
            self.application_version = env_data["applicationVersion"]
        if "apiUrl" in config_data:
            self.hsapi_base_url = config_data["apiUrl"]
        if "webApiUrl" in config_data:
            self.web_api_url = config_data["webApiUrl"]
        operators = config_data.get("operators") or []
        if operators:
            operator = operators[0]
            self.merchant = operator.get("playerMerchant", self.merchant)
            self.player_license_key = operator.get("playerLicenseKey", self.player_license_key)
            self.selfcare_url = operator.get("selfcareUrl", self.selfcare_url)
            self.homepage_url = operator.get("homepageUrl", self.homepage_url)
        self.api_endpoints = self._build_api_endpoints()

    def _build_fallback_endpoints(self) -> None:
        self.hsapi_base_url = self.hsapi_base_url or HRTiDefaults.FALLBACK_HSAPI_URL
        self.web_api_url = self.web_api_url or HRTiDefaults.FALLBACK_WEB_API_URL
        self.merchant = self.merchant or HRTiDefaults.FALLBACK_MERCHANT
        self.api_endpoints = self._build_api_endpoints()

    def _build_api_endpoints(self) -> Dict[str, str]:
        endpoints: Dict[str, str] = {}
        if self.web_api_url:
            base = f"{self.base_url}/{self.web_api_url}"
            for key in HRTiDefaults.WEB_API_ENDPOINTS:
                if key in self.api_endpoint_paths:
                    endpoints[key] = f"{base}{self.api_endpoint_paths[key]}"
        if self.hsapi_base_url:
            for key in HRTiDefaults.HSAPI_ENDPOINTS:
                if key in self.api_endpoint_paths:
                    endpoints[key] = f"{self.hsapi_base_url}{self.api_endpoint_paths[key]}"
        return endpoints

    # ------------------------------------------------------------------
    # Header builders
    # ------------------------------------------------------------------
    def api_headers(
        self,
        token: Optional[str] = None,
        device_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        referer_path: str = "/",
    ) -> Dict[str, str]:
        """Headers of the manager API calls (NOT for CDN / manifest requests)."""
        headers = {
            "deviceid": device_id or "",
            "devicetypeid": self.device_reference_id,
            "ipaddress": ip_address or "",
            "operatorreferenceid": self.operator_reference_id,
            "origin": self.base_website,
            "referer": f"{self.base_website}{referer_path}",
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if token:
            headers["authorization"] = f"Client {token}"
        return headers