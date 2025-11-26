# streaming_providers/providers/joyn/constants.py
# ============================================================================
# SSO Discovery Configuration
# ============================================================================

# SSO endpoints discovery URL
JOYN_SSO_DISCOVERY_URL = 'https://auth.joyn.de/sso/endpoints'

JOYN_LOGO = 'https://upload.wikimedia.org/wikipedia/de/thumb/7/74/Joyn_%28Streaminganbieter%29_logo.svg/2560px-Joyn_%28Streaminganbieter%29_logo.svg.png'

# Default client IDs for different platforms (fallback)
DEVICE_IDS = {
    'web': '709115c2-f87e-4bad-9b94-28ac08d72cd9',
    'android': '05f5f3df-1130-4707-a761-c04d0c50b7f2',
    'ios': '21218403-52ec-4a65-abf4-f36a0eadd631'
}

# OAuth2 Configuration
JOYN_OAUTH_SCOPE = "openid email profile offline_access"

# ============================================================================
# Authentication Configuration
# ============================================================================

# Base authentication URL
JOYN_AUTH_BASE_URL = 'https://auth.joyn.de/auth'

# Authentication endpoints
JOYN_AUTH_ENDPOINTS = {
    'ANONYMOUS': f'{JOYN_AUTH_BASE_URL}/anonymous',      # Client credentials flow
    'REFRESH': f'{JOYN_AUTH_BASE_URL}/refresh',          # Token refresh
    'LOGOUT': f'{JOYN_AUTH_BASE_URL}/logout',            # Logout
}

# ============================================================================
# Cidaas/7pass Configuration
# ============================================================================

# Cidaas base URL (7pass authentication service)
JOYN_CIDAAS_BASE_URL = 'https://auth.7pass.de'

# Cidaas API endpoints
JOYN_CIDAAS_ENDPOINTS = {
    'LOGIN': f'{JOYN_CIDAAS_BASE_URL}/login-srv/login',
    'VERIFICATION_INITIATE': f'{JOYN_CIDAAS_BASE_URL}/verification-srv/v2/authenticate/initiate/PASSWORD',
    'VERIFICATION_AUTHENTICATE': f'{JOYN_CIDAAS_BASE_URL}/verification-srv/v2/authenticate/authenticate/PASSWORD',
    'REGISTRATION_SETUP': f'{JOYN_CIDAAS_BASE_URL}/registration-setup-srv/public/list',
    'USER_CHECK_EXISTS': f'{JOYN_CIDAAS_BASE_URL}/users-srv/user/checkexists',
    'VERIFICATION_LIST': f'{JOYN_CIDAAS_BASE_URL}/verification-srv/v2/setup/public/configured/list',
    'CONSENT_ACCEPT': f'{JOYN_CIDAAS_BASE_URL}/consent-management-srv/consent/scope/accept',
    'LOGIN_CONTINUE': f'{JOYN_CIDAAS_BASE_URL}/login-srv/precheck/continue'
}

# Base URLs
JOYN_BASE_URLS = {
    'ORIGIN': 'https://www.joyn.de',
    'REFERER': 'https://www.joyn.de/',
    'SIGNIN_BASE': 'https://signin.7pass.de'
}

# ============================================================================
# API Configuration
# ============================================================================

# Client version used in API requests
JOYN_CLIENT_VERSION = '5.1261.0'

# Platform identifier
DEFAULT_PLATFORM = 'web'

# Default user agent for all requests
JOYN_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36'

# Base64 encoded secret key for signature generation
SIGNATURE_SECRET_KEY = 'MzU0MzM3MzgzMzM4MzMzNjM1NDMzNzM4MzYzNDM2MzYzNTQzMzczODM2MzYzMzM4MzIzNjM1NDMzNzM4MzMzMDM2MzQzNTM5MzU0MzM3MzgzMzM5MzMzNTMyMzQzNTQzMzczODM2MzUzMzM5MzU0MzM3MzgzMzM4MzMzMjMzNDYzNTQzMzczODM2MzYzMzMzMzM0NDMzNDIzNTQzMzczODMzMzgzNjM2MzMzNQ=='

JOYN_AUTH_HEADERS_BASE = {
    'User-Agent': JOYN_USER_AGENT,
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Origin': JOYN_BASE_URLS['ORIGIN'],
    'joyn-client-version': JOYN_CLIENT_VERSION,
    # Note: 'joyn-platform' is added dynamically in auth.py and provider.py
}

# Base API headers (without dynamic auth tokens)
JOYN_API_BASE_HEADERS = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'User-Agent': JOYN_USER_AGENT
}

# ============================================================================
# GraphQL Configuration
# ============================================================================

# GraphQL base URL
JOYN_GRAPHQL_BASE_URL = 'https://api.joyn.de/graphql'

# GraphQL persisted query hashes
GRAPHQL_QUERY_HASHES = {
    'LIVE_PLAYER': '52b37a3cf5bc75e56026aed7b0d234874eeabd2eccd369d0cd3d3a6ea15ef566',
    'LIVE_CHANNELS': 'b7703103ddd0516be6b49ed66186092a6c6f6d815ccc502a9f50800a8cc18dd2'
}

# GraphQL endpoints with full URLs
JOYN_GRAPHQL_ENDPOINTS = {
    'LIVE_PLAYER': f'{JOYN_GRAPHQL_BASE_URL}?operationName=PageLivePlayerClientSide&enable_user_location=true&watch_assistant_variant=true&extensions=%7B%22persistedQuery%22%3A%7B%22version%22%3A1%2C%22sha256Hash%22%3A%22{GRAPHQL_QUERY_HASHES["LIVE_PLAYER"]}%22%7D%7D',
    'LIVE_CHANNELS': f'{JOYN_GRAPHQL_BASE_URL}?operationName=LiveChannelsAndEpg&enable_user_location=true&watch_assistant_variant=true'
}

# Base GraphQL headers (without country-specific ones)
JOYN_GRAPHQL_BASE_HEADERS = {
    'X-Api-Key': '4f0fd9f18abbe3cf0e87fdb556bc39c8',
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'User-Agent': JOYN_USER_AGENT
}

# GraphQL persisted query version
GRAPHQL_PERSISTED_QUERY_VERSION = 1

# GraphQL query defaults
GRAPHQL_LIVE_CHANNELS_FILTER = "DEFAULT"
GRAPHQL_MAX_RESULTS = 5000
GRAPHQL_OFFSET = 0

# ============================================================================
# Streaming Configuration
# ============================================================================

# Streaming API endpoints
JOYN_STREAMING_ENDPOINTS = {
    'ENTITLEMENT': 'https://entitlement.p7s1.io/api/user/entitlement-token',
    'PLAYLIST': 'https://api.vod-prd.s.joyn.de/v1/channel/{channel_id}/playlist'
}

# Default video data payload configuration
"""
DEFAULT_VIDEO_CONFIG = {
    'manufacturer': 'unknown',
    'platform': 'browser',
    'maxSecurityLevel': 1,
    'model': 'unknown',
    'protectionSystem': 'widevine',
    'streamingFormat': 'dash',
    'enableSubtitles': True,
    'maxResolution': 1080,
    'version': 'v1',
}
"""
DEFAULT_VIDEO_CONFIG = {
    "enableDolbyAtmos": True,
    "enableSubtitles": True,
    "manufacturer": "",
    "maxResolution": 2160,
    "model": "",
    "platform": "android-tv",
    "protectionSystem": "widevine",
    "streamingFormat": "dash",
    "variantName": "",
    "version": "v1",
    "maxSecurityLevel": 5,
}

# ============================================================================
# Content Configuration
# ============================================================================

# Content types
CONTENT_TYPE_LIVE = 'LIVE'
CONTENT_TYPE_VOD = 'VOD'

# Stream types
STREAM_TYPE_LINEAR = 'LINEAR'
STREAM_TYPE_EVENT = 'EVENT'
STREAM_TYPE_ON_DEMAND = 'ON_DEMAND'

# Livestream types for GraphQL queries
DEFAULT_LIVESTREAM_TYPES = ['EVENT', 'LINEAR', 'ON_DEMAND']

# Stream modes
MODE_LIVE = 'live'
MODE_VOD = 'vod'

# ============================================================================
# Error Codes
# ============================================================================

# Known error codes from Joyn API
ERROR_CODES = {
    'PLAYBACK_RESTRICTED': 'ENT_RVOD_Playback_Restricted',
    'UNAUTHORIZED': 'ENT_Unauthorized',
    'NOT_FOUND': 'ENT_Not_Found',
    'GEOBLOCKED': 'ENT_Geoblocked',
    'VALIDATION_ERROR': 'VALIDATION_ERROR',  # Added for token refresh
    'INVALID_JWT': 'INVALID_JWT'             # Added for expired tokens
}

# ============================================================================
# Country/Region Configuration
# ============================================================================

# Country to distribution tenant mapping
COUNTRY_TENANT_MAPPING = {
    'de': 'JOYN',
    'at': 'JOYN_AT',
    'ch': 'JOYN_CH'
}

JOYN_DOMAINS = {
    'de': 'https://www.joyn.de',
    'at': 'https://www.joyn.at',
    'ch': 'https://www.joyn.ch'
}

def get_oauth_redirect_uri(country: str) -> str:
    """Get country-specific OAuth redirect URI"""
    return "https://www.joyn.de/oauth"

# Supported countries
SUPPORTED_COUNTRIES = list(COUNTRY_TENANT_MAPPING.keys())

# Default country
DEFAULT_COUNTRY = 'de'

# ============================================================================
# DRM Configuration
# ============================================================================

# DRM system
DRM_SYSTEM_WIDEVINE = 'widevine'

# DRM request headers
DRM_REQUEST_HEADERS = {
    'Content-Type': 'application/octet-stream',
    'User-Agent': JOYN_USER_AGENT
}

# DRM license request template (without bearer token)
DRM_LICENSE_HEADERS_BASE = {
    'Content-Type': 'application/octet-stream',
    'User-Agent': JOYN_USER_AGENT
}

# ============================================================================
# Request Configuration
# ============================================================================

# Default timeout for HTTP requests (seconds)
DEFAULT_REQUEST_TIMEOUT = 30

# Default maximum retries for failed requests
DEFAULT_MAX_RETRIES = 3

# Default time window for EPG queries (hours)
DEFAULT_EPG_WINDOW_HOURS = 3

# ============================================================================
# Channel Configuration
# ============================================================================

# Default channel settings
DEFAULT_CHANNEL_CONFIG = {
    'video': 'best',
    'on_demand': True,
    'speed_up': True,
    'use_cdm': True,
    'cdm_mode': 'external',
    'session_manifest': False
}

# Default language
DEFAULT_LANGUAGE = 'de'