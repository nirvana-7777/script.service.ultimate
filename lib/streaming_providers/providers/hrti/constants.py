# streaming_providers/providers/hrti/constants.py
"""
HRTi provider constants and default configurations
"""


class HRTiDefaults:
    """Default values for HRTi provider"""

    # Provider information
    PROVIDER_LOGO = "https://upload.wikimedia.org/wikipedia/en/thumb/9/9e/Logo_of_the_HRT.svg/960px-Logo_of_the_HRT.svg.png"
    PROVIDER_NAME = "HRTi"

    # Website and base URLs
    BASE_WEBSITE = "https://hrti.hrt.hr"
    BASE_URL = "https://hrti.hrt.hr"

    # Configuration endpoints
    ENV_ENDPOINT = f"{BASE_URL}/assets/config/env.json"
    CONFIG_ENDPOINT = f"{BASE_URL}/assets/config/config.production.json"

    # API endpoint path templates (will be combined with dynamic base URLs)
    # These are the path parts only - base URLs come from API config
    API_ENDPOINT_PATHS = {
        "get_ip": "/getIPAddress",
        "grant_access": "/GrantAccess",
        "channels": "/GetChannels",
        "programme": "/GetProgramme",
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

    # Device information (static defaults, may be overridden by config)
    DEVICE_REFERENCE_ID = "6"  # String '6' as required by headers
    OPERATOR_REFERENCE_ID = "hrt"
    CONNECTION_TYPE = "LAN/WiFi"
    APPLICATION_VERSION = "5.97.6"
    OS_VERSION = "Linux"
    CLIENT_TYPE = "Chrome 142"

    # User Agent
    USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"

    # HTTP settings
    DEFAULT_TIMEOUT = 30

    # VOD settings
    VOD_ITEMS_PER_PAGE = 24
    MAX_VOD_PAGES = 100


class HRTiConfig:
    """Configuration class for HRTi provider"""

    def __init__(self, config_dict: dict = None):
        """Initialize with optional configuration overrides"""
        config = config_dict or {}

        self.logo = config.get("logo", HRTiDefaults.PROVIDER_LOGO)

        # Website and base URLs
        self.base_website = config.get("base_website", HRTiDefaults.BASE_WEBSITE)
        self.base_url = config.get("base_url", HRTiDefaults.BASE_URL)

        # Dynamic URLs - will be populated from API
        self.hsapi_base_url = config.get("hsapi_base_url", None)
        self.web_api_url = config.get("web_api_url", None)

        # Configuration endpoints
        self.env_endpoint = config.get("env_endpoint", HRTiDefaults.ENV_ENDPOINT)
        self.config_endpoint = config.get("config_endpoint", HRTiDefaults.CONFIG_ENDPOINT)

        # API endpoints - start with paths only, build full URLs after API call
        self.api_endpoint_paths = config.get(
            "api_endpoint_paths", HRTiDefaults.API_ENDPOINT_PATHS.copy()
        )
        self.api_endpoints = {}  # Will be populated in update_from_api

        # Device configuration
        self.device_reference_id = config.get(
            "device_reference_id", HRTiDefaults.DEVICE_REFERENCE_ID
        )
        self.operator_reference_id = config.get(
            "operator_reference_id", HRTiDefaults.OPERATOR_REFERENCE_ID
        )
        self.merchant = config.get("merchant", None)  # Will be set from API
        self.player_license_key = config.get("player_license_key", None)  # Will be set from API
        self.connection_type = config.get("connection_type", HRTiDefaults.CONNECTION_TYPE)
        self.application_version = config.get(
            "application_version", HRTiDefaults.APPLICATION_VERSION
        )
        self.os_version = config.get("os_version", HRTiDefaults.OS_VERSION)
        self.client_type = config.get("client_type", HRTiDefaults.CLIENT_TYPE)

        # HTTP settings
        self.user_agent = config.get("user_agent", HRTiDefaults.USER_AGENT)
        self.timeout = config.get("timeout", HRTiDefaults.DEFAULT_TIMEOUT)

        # VOD settings
        self.vod_items_per_page = config.get("vod_items_per_page", HRTiDefaults.VOD_ITEMS_PER_PAGE)

    def _build_api_endpoints(self):
        """Build full API endpoints from dynamic base URLs and static paths"""
        endpoints = {}

        # Build endpoints using webApiUrl (for OTT endpoints)
        if self.web_api_url:
            base_api_url = f"{self.base_url}/{self.web_api_url}"
            ott_endpoints = [
                "get_ip", "grant_access", "channels", "programme",
                "authorize_session", "report_session", "catalogue_structure",
                "catalogue", "vod_details", "episodes", "watch_later",
                "editors_choice"
            ]
            for key in ott_endpoints:
                if key in self.api_endpoint_paths:
                    endpoints[key] = f"{base_api_url}{self.api_endpoint_paths[key]}"

        # Build endpoints using hsapi_base_url (for HSAPI endpoints)
        if self.hsapi_base_url:
            hsapi_endpoints = ["register_device", "content_ratings", "profiles"]
            for key in hsapi_endpoints:
                if key in self.api_endpoint_paths:
                    endpoints[key] = f"{self.hsapi_base_url}{self.api_endpoint_paths[key]}"

        return endpoints

    def update_from_api(self, env_data: dict, config_data: dict):
        """Update configuration from API responses"""
        try:
            # Update from env data
            if "applicationVersion" in env_data:
                self.application_version = env_data["applicationVersion"]

            # Update from config data
            if "apiUrl" in config_data:
                self.hsapi_base_url = config_data["apiUrl"]

            if "webApiUrl" in config_data:
                self.web_api_url = config_data["webApiUrl"]

            # Update operator-specific settings
            if "operators" in config_data and config_data["operators"]:
                operator = config_data["operators"][0]
                if "playerMerchant" in operator:
                    self.merchant = operator["playerMerchant"]
                if "playerLicenseKey" in operator:
                    self.player_license_key = operator["playerLicenseKey"]
                if "selfcareUrl" in operator:
                    self.selfcare_url = operator["selfcareUrl"]
                if "homepageUrl" in operator:
                    self.homepage_url = operator["homepageUrl"]

            # Build API endpoints from dynamic URLs
            self.api_endpoints = self._build_api_endpoints()

            # Log what we got from API (debug)
            import logging
            logging.debug(f"HRTi config updated from API - hsapi_url: {self.hsapi_base_url}, "
                          f"web_api_url: {self.web_api_url}, merchant: {self.merchant}")

        except Exception as e:
            import logging
            logging.debug(f"Error updating HRTi config from API: {e}")
            # Fallback to build endpoints with defaults if API update fails
            self._build_fallback_endpoints()

    def _build_fallback_endpoints(self):
        """Build fallback API endpoints if dynamic config fails"""
        # Use default hsapi URL if not set
        if not self.hsapi_base_url:
            self.hsapi_base_url = "https://hsapi.aviion.tv/client.svc/json"

        # Use default web API URL if not set
        if not self.web_api_url:
            self.web_api_url = "api/api/ott"

        # Use default merchant if not set
        if not self.merchant:
            self.merchant = "aviion2"

        self.api_endpoints = self._build_api_endpoints()

    def get_base_headers(self) -> dict:
        """Get base HTTP headers"""
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def get_auth_headers(
            self, device_id: str = None, ip_address: str = None, token: str = None
    ) -> dict:
        """Get authenticated headers for API requests"""
        headers = self.get_base_headers()

        if device_id:
            headers["deviceid"] = device_id
        if ip_address:
            headers["ipaddress"] = ip_address
        if token:
            headers["authorization"] = f"Client {token}"

        headers.update(
            {
                "devicetypeid": self.device_reference_id,
                "operatorreferenceid": self.operator_reference_id,
                "origin": self.base_website,
                "referer": self.base_website,
            }
        )

        return headers