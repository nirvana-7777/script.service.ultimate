# [file name]: constants.py
# [file content begin]
# streaming_providers/providers/hrti/constants.py
"""
HRTi provider constants and default configurations
"""


class HRTiDefaults:
    """Default values for HRTi provider"""

    # Provider information
    PROVIDER_LOGO = 'https://upload.wikimedia.org/wikipedia/en/thumb/9/9e/Logo_of_the_HRT.svg/2560px-Logo_of_the_HRT.svg.png'
    PROVIDER_NAME = 'HRTi'

    # Website and base URLs
    BASE_WEBSITE = 'https://hrti.hrt.hr'
    BASE_URL = 'https://hrti.hrt.hr'
    HSAPI_BASE_URL = 'https://hsapi.aviion.tv/client.svc/json'

    # Configuration endpoints
    ENV_ENDPOINT = f'{BASE_URL}/assets/config/env.json'
    CONFIG_ENDPOINT = f'{BASE_URL}/assets/config/config.production.json'

    # API endpoints
    API_ENDPOINTS = {
        'get_ip': f'{BASE_URL}/api/api/ott/getIPAddress',
        'grant_access': f'{BASE_URL}/api/api/ott/GrantAccess',
        'channels': f'{BASE_URL}/api/api/ott/GetChannels',
        'programme': f'{BASE_URL}/api/api/ott/GetProgramme',
        'authorize_session': f'{BASE_URL}/api/api/ott/AuthorizeSession',
        'report_session': f'{BASE_URL}/api/api/ott/ReportSessionEvent',
        'register_device': f'{HSAPI_BASE_URL}/RegisterDevice',
        'content_ratings': f'{HSAPI_BASE_URL}/ContentRatingsGet',
        'profiles': f'{HSAPI_BASE_URL}/ProfilesGet'
    }

    # DRM and License endpoints
    LICENSE_URL = 'https://lic.drmtoday.com/license-proxy-widevine/cenc/'

    # Device information
    DEVICE_REFERENCE_ID = '6'  # String '6' as required by headers
    OPERATOR_REFERENCE_ID = 'hrt'
    MERCHANT = 'aviion2'
    CONNECTION_TYPE = 'LAN/WiFi'
    APPLICATION_VERSION = '5.97.6'
    OS_VERSION = 'Linux'
    CLIENT_TYPE = 'Chrome 142'

    # User Agent
    USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36'

    # HTTP settings
    DEFAULT_TIMEOUT = 30


class HRTiConfig:
    """Configuration class for HRTi provider"""

    def __init__(self, config_dict: dict = None):
        """Initialize with optional configuration overrides"""
        config = config_dict or {}

        self.logo = config.get('logo', HRTiDefaults.PROVIDER_LOGO)

        # Website and base URLs
        self.base_website = config.get('base_website', HRTiDefaults.BASE_WEBSITE)
        self.base_url = config.get('base_url', HRTiDefaults.BASE_URL)
        self.hsapi_base_url = config.get('hsapi_base_url', HRTiDefaults.HSAPI_BASE_URL)
        self.env_endpoint = config.get('env_endpoint', HRTiDefaults.ENV_ENDPOINT)
        self.config_endpoint = config.get('config_endpoint', HRTiDefaults.CONFIG_ENDPOINT)

        # API endpoints configuration
        self.api_endpoints = config.get('api_endpoints', HRTiDefaults.API_ENDPOINTS.copy())

        # DRM and License
        self.license_url = config.get('license_url', HRTiDefaults.LICENSE_URL)

        # Device configuration
        self.device_reference_id = config.get('device_reference_id', HRTiDefaults.DEVICE_REFERENCE_ID)
        self.operator_reference_id = config.get('operator_reference_id', HRTiDefaults.OPERATOR_REFERENCE_ID)
        self.merchant = config.get('merchant', HRTiDefaults.MERCHANT)
        self.connection_type = config.get('connection_type', HRTiDefaults.CONNECTION_TYPE)
        self.application_version = config.get('application_version', HRTiDefaults.APPLICATION_VERSION)
        self.os_version = config.get('os_version', HRTiDefaults.OS_VERSION)
        self.client_type = config.get('client_type', HRTiDefaults.CLIENT_TYPE)

        # HTTP settings
        self.user_agent = config.get('user_agent', HRTiDefaults.USER_AGENT)
        self.timeout = config.get('timeout', HRTiDefaults.DEFAULT_TIMEOUT)

        # Web API URL (can be updated from config)
        self.web_api_url = config.get('web_api_url', 'api/api/ott')

    def update_from_api(self, env_data: dict, config_data: dict):
        """Update configuration from API responses"""
        try:
            # Update from env data
            if 'applicationVersion' in env_data:
                self.application_version = env_data['applicationVersion']

            # Update from config data
            if 'apiUrl' in config_data:
                self.hsapi_base_url = config_data['apiUrl']

            if 'webApiUrl' in config_data:
                self.web_api_url = config_data['webApiUrl']
                # Update API endpoints with new web API URL
                base_api_url = f"{self.base_url}/{self.web_api_url}"
                self.api_endpoints.update({
                    'get_ip': f"{base_api_url}/getIPAddress",
                    'grant_access': f"{base_api_url}/GrantAccess",
                    'channels': f"{base_api_url}/GetChannels",
                    'programme': f"{base_api_url}/GetProgramme",
                    'authorize_session': f"{base_api_url}/AuthorizeSession"
                })

            if 'operators' in config_data and config_data['operators']:
                operator = config_data['operators'][0]
                if 'playerMerchant' in operator:
                    self.merchant = operator['playerMerchant']
                if 'selfcareUrl' in operator:
                    # Store selfcare URL if needed
                    pass

        except Exception as e:
            # Log error but don't raise - use defaults if update fails
            import logging
            logging.debug(f"Error updating HRTi config from API: {e}")

    def get_base_headers(self) -> dict:
        """Get base HTTP headers"""
        return {
            'User-Agent': self.user_agent,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def get_auth_headers(self, device_id: str = None, ip_address: str = None, token: str = None) -> dict:
        """Get authenticated headers for API requests"""
        headers = self.get_base_headers()

        if device_id:
            headers['deviceid'] = device_id
        if ip_address:
            headers['ipaddress'] = ip_address
        if token:
            headers['authorization'] = f'Client {token}'

        headers.update({
            'devicetypeid': self.device_reference_id,  # Added devicetypeid
            'operatorreferenceid': self.operator_reference_id,
            'origin': self.base_website,
            'referer': self.base_website,
        })

        return headers
# [file content end]