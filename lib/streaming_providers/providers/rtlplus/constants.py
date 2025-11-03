# streaming_providers/providers/rtlplus/constants.py
"""
RTL+ provider constants and default configurations
"""


class RTLPlusDefaults:
    """Default values for RTL+ provider"""

    # Client and version information
    CLIENT_VERSION = '2025.6.26.0'
    CHROME_VERSION = '121.0.0.0'
    CLIENT_ID = 'rci:rtlplus:web'

    # Device information
    DEVICE_ID = '8c3f37cc-13a3-4141-bd0f-e4b3673fe5e4'
    DEVICE_NAME = 'Linux Chrome'

    # User Agent components
    USER_AGENT = f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{CHROME_VERSION} Safari/537.36'

    # API endpoints
    AUTH_BASE_URL = 'https://auth.rtl.de/auth/realms/rtlplus/protocol/openid-connect'
    AUTH_ENDPOINT = f'{AUTH_BASE_URL}/token'
    AUTH_AUTHORIZE_ENDPOINT = f'{AUTH_BASE_URL}/auth'
    GRAPHQL_ENDPOINT = 'https://cdn.gateway.now-plus-prod.aws-cbc.cloud/graphql'
    MANIFEST_ENDPOINT = 'https://stus.player.streamingtech.de/livestream/linear/{channel_id}?platform=web'
    BASE_WEBSITE = 'https://plus.rtl.de/'
    CONFIG_ENDPOINT = 'https://plus.rtl.de/assets/config/config.json'

    # Anonymous credentials (fallback)
    ANONYMOUS_CLIENT_ID = 'anonymous-user'
    ANONYMOUS_CLIENT_SECRET = '4bfeb73f-1c4a-4e9f-a7fa-96aa1ad3d94c'

    # HTTP settings
    DEFAULT_TIMEOUT = 30

    # GraphQL query parameters
    CHANNELS_QUERY_PARAMS = {
        "operationName": "LiveTvStations",
        "variables": '{"epgCount":4,"filter":{"channelTypes":["BROADCAST","FAST"]}}',
        "extensions": '{"persistedQuery":{"version":1,"sha256Hash":"845cf56a2a78110a0f978c1a2af2bc7f9a1c937d0f324ffaf852a9a4414c8485"}}'
    }


class RTLPlusHeaders:
    """Standard header configurations for RTL+ requests"""

    @staticmethod
    def get_base_headers(user_agent: str = None) -> dict:
        """Get base HTTP headers"""
        return {
            'User-Agent': user_agent or RTLPlusDefaults.USER_AGENT,
            'Accept': 'application/json',
#            'Accept-Language': 'de-DE,de;q=0.9,en;q=0.8',
#            'Accept-Encoding': 'gzip, deflate, br',
#            'DNT': '1',
#            'Connection': 'keep-alive',
 #           'Upgrade-Insecure-Requests': '1'
        }

    @staticmethod
    def get_auth_headers(user_agent: str = None) -> dict:
        """Get headers for authentication requests"""
        headers = RTLPlusHeaders.get_base_headers(user_agent)
        headers.update({
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': RTLPlusDefaults.BASE_WEBSITE.rstrip('/'),
            'Referer': RTLPlusDefaults.BASE_WEBSITE
        })
        return headers

    @staticmethod
    def get_api_headers(access_token: str = None, device_id: str = None,
                        client_version: str = None, user_agent: str = None) -> dict:
        """Get headers for authenticated API requests"""
        headers = RTLPlusHeaders.get_base_headers(user_agent)
        headers.update({
            'Content-Type': 'application/json',
            'Rtlplus-Client-Id': RTLPlusDefaults.CLIENT_ID,
            'Rtlplus-Referrer': '',
            'Rtlplus-Client-Version': client_version or RTLPlusDefaults.CLIENT_VERSION,
        })

        if access_token:
            headers['Authorization'] = f'Bearer {access_token}'

        if device_id:
            headers['X-Device-Id'] = device_id

        return headers

    @staticmethod
    def get_drm_headers(access_token: str, device_id: str = None, user_agent: str = None) -> dict:
        """Get headers for DRM license requests"""
        return {
            'X-Auth-Token': access_token,
            'X-Device-Id': device_id or RTLPlusDefaults.DEVICE_ID,
            'X-Device-Name': RTLPlusDefaults.DEVICE_NAME,
            'User-Agent': user_agent or RTLPlusDefaults.USER_AGENT,
            'Origin': RTLPlusDefaults.BASE_WEBSITE.rstrip('/'),
            'Referer': RTLPlusDefaults.BASE_WEBSITE
        }


class RTLPlusConfig:
    """Configuration class that can be customized per instance"""

    def __init__(self, config_dict: dict = None):
        """Initialize with optional configuration overrides"""
        config = config_dict or {}

        # Core settings (can be overridden)
        self.client_version = config.get('client_version', RTLPlusDefaults.CLIENT_VERSION)
        self.chrome_version = config.get('chrome_version', RTLPlusDefaults.CHROME_VERSION)
        self.device_id = config.get('device_id', RTLPlusDefaults.DEVICE_ID)
        self.user_agent = config.get('user_agent', RTLPlusDefaults.USER_AGENT)

        # API endpoints (can be overridden for testing)
        self.auth_endpoint = config.get('auth_endpoint', RTLPlusDefaults.AUTH_ENDPOINT)
        self.graphql_endpoint = config.get('graphql_endpoint', RTLPlusDefaults.GRAPHQL_ENDPOINT)
        self.manifest_endpoint = config.get('manifest_endpoint', RTLPlusDefaults.MANIFEST_ENDPOINT)
        self.base_website = config.get('base_website', RTLPlusDefaults.BASE_WEBSITE)
        self.config_endpoint = config.get('config_endpoint', RTLPlusDefaults.CONFIG_ENDPOINT)

        # HTTP settings
        self.timeout = config.get('timeout', RTLPlusDefaults.DEFAULT_TIMEOUT)

    def get_manifest_url(self, channel_id: str) -> str:
        """Get manifest URL for a specific channel"""
        return self.manifest_endpoint.format(channel_id=channel_id)

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
            user_agent=self.user_agent
        )

    def get_drm_headers(self, access_token: str) -> dict:
        """Get DRM headers with this config's settings"""
        return RTLPlusHeaders.get_drm_headers(
            access_token=access_token,
            device_id=self.device_id,
            user_agent=self.user_agent
        )
