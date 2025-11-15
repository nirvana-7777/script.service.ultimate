# streaming_providers/providers/magenta2/constants.py
# ============================================================================
# Magenta2 Configuration
# ============================================================================

# Supported countries (Magenta2 is Germany-specific)
SUPPORTED_COUNTRIES = ['de']

# Default country
DEFAULT_COUNTRY = 'de'

# Platform configuration
DEFAULT_PLATFORM = 'android-tv'
MAGENTA2_PLATFORMS = {
    'web': {
        'device_name': 'Web Browser',
        'firmware': 'Chrome 120',
        'user_agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'terminal_type': 'WEB',
        # TAA-specific device identification
        'taa_device_model': 'Web Browser',
        'taa_os': 'Chrome 120'
    },
    'android-tv': {
        'device_name': 'Android TV',
        'firmware': 'Android 11',
        'user_agent': 'Dalvik/2.1.0 (Linux; U; Android 11; SHIELD Android TV Build/RQ1A.210105.003) ((2.00T_ATV::3.134.4462::mdarcy::))',
        'terminal_type': 'ATV_ANDROIDTV',
        # TAA-specific device identification (API level format required)
        'taa_device_model': 'SHIELD Android TV',
        'taa_os': 'API level 30'
    },
    'atv-launcher': {
        'device_name': 'MagentaTV Stick',
        'firmware': 'Android 11',
        'user_agent': 'Mozilla/5.0 (Linux; Android 11; AFTS Build/PPR1.180610.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
        'terminal_type': 'ATV_LAUNCHER',
        # TAA-specific device identification
        'taa_device_model': 'MagentaTV Stick',
        'taa_os': 'API level 30'
    },
    'android-mobile': {
        'device_name': 'Android Mobile',
        'firmware': 'Android 13',
        'user_agent': 'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36',
        'terminal_type': 'ANDROID_MOBILE',
        # TAA-specific device identification
        'taa_device_model': 'Android Mobile',
        'taa_os': 'API level 33'
    },
    'ios': {
        'device_name': 'iPhone',
        'firmware': 'iOS 15',
        'user_agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1',
        'terminal_type': 'IOS',
        # TAA-specific device identification
        'taa_device_model': 'iPhone',
        'taa_os': 'iOS 15.0'
    }
}

# ============================================================================
# Manifest Request Configuration
# ============================================================================

# App identification for manifest requests
MAGENTA2_APP_NAME = 'MagentaTV'
MAGENTA2_APP_VERSION = '104180'
MAGENTA2_RUNTIME_VERSION = '1'

# Model names for manifest requests (different from device models!)
MANIFEST_MODEL_MAPPINGS = {
    'web': 'DT:WEB',
    'android-tv': 'DT:ATV-AndroidTV',
    'atv-launcher': 'DT:ATV-Launcher',
    'android-mobile': 'DT:Android-Mobile',
    'ios': 'DT:IOS'
}

# Firmware strings for manifest requests
MANIFEST_FIRMWARE_MAPPINGS = {
    'web': 'Chrome 120',
    'android-tv': 'API level 30',
    'atv-launcher': 'API level 30',
    'android-mobile': 'API level 33',
    'ios': 'iOS 15.0'
}

# Also update the fallback mappings:
CLIENT_MODEL_MAPPINGS = {
    'web': 'ftv-web',
    'android-tv': 'ftv-androidtv',
    'atv-launcher': 'ftv-androidtv',
    'android-mobile': 'ftv-android',
    'ios': 'ftv-ios'
}

DEVICE_MODEL_MAPPINGS = {
    'web': 'WebBrowser_FTV',
    'android-tv': 'AndroidTV_FTV',
    'atv-launcher': 'AndroidTV_FTV',
    'android-mobile': 'AndroidMobile_FTV',
    'ios': 'iOS_FTV'
}

# And update subscriber types if needed:
SUBSCRIBER_TYPES = {
    'web': 'WEB_OTT_DT',
    'android-tv': 'FTV_OTT_DT',
    'atv-launcher': 'FTV_OTT_DT',  # Same as android-tv
    'android-mobile': 'MOB_OTT_DT',  # Different for mobile
    'ios': 'IOS_OTT_DT'
}

# ============================================================================
# API Configuration - MINIMAL HARDCODING
# ============================================================================

# Only bootstrap endpoint is hardcoded - everything else discovered dynamically
MAGENTA2_BASE_URL = 'https://prod.dcm.telekom-dienste.de/v1'
MAGENTA2_BOOTSTRAP_URL = MAGENTA2_BASE_URL + '/settings/{terminal_type}/bootstrap'
MAGENTA2_MANIFEST_URL = MAGENTA2_BASE_URL + '/settings/{terminal_type}/manifest'

# Fallback endpoints if discovery fails
MAGENTA2_FALLBACK_ENDPOINTS = {
    'OPENID_CONFIG': 'https://accounts.login.idm.telekom.com/.well-known/openid-configuration',
    'TAA_AUTH': 'https://taa.p7s1.io/api/v1/taa',
    'ENTITLEMENT': 'https://entitlement.p7s1.io/api/user/entitlement-token',
}

# ============================================================================
# Application Configuration
# ============================================================================

# Application identifiers
IDM = "TDGIDM"
APPVERSION2 = "3.134.4462"

SSO_URL = "https://ssom.magentatv.de/login"
# SSO User Agent
SSO_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ============================================================================
# OAuth2 Configuration
# ============================================================================

# Client IDs for different platforms
MAGENTA2_CLIENT_IDS = {
    'web': '709115c2-f87e-4bad-9b94-28ac08d72cd9',
    'android-tv': '05f5f3df-1130-4707-a761-c04d0c50b7f2',
    'ios': '21218403-52ec-4a65-abf4-f36a0eadd631'
}

# OAuth2 scopes
MAGENTA2_OAUTH_SCOPE = "openid profile offline_access tvhubs"

# OAuth2 redirect URI
MAGENTA2_REDIRECT_URI = "https://web2.magentatv.de/authn/idm"

# ============================================================================
# Request Headers Configuration
# ============================================================================

# Headers for different API endpoints
MAGENTA2_HEADERS = {
    'DEFAULT': {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    },
    'SSO': {
        'User-Agent': SSO_USER_AGENT,
        'Content-Type': 'application/json',
        'origin': 'https://web2.magentatv.de',
        'referer': 'https://web2.magentatv.de/'
    },
    'DCM': {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    },
    'OAUTH2': {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
}

# ============================================================================
# Authentication Configuration
# ============================================================================

# Grant types
GRANT_TYPES = {
    'LINE_AUTH': 'urn:com:telekom:ott-app-services:access-auth',
    'AUTH_CODE': 'authorization_code',
    'PASSWORD': 'password',
    'REFRESH_TOKEN': 'refresh_token',
    'REMOTE_LOGIN': 'urn:telekom:com:grant-type:remote-login',
    'CLIENT_CREDENTIALS': 'client_credentials'
}

# ============================================================================
# Content Configuration
# ============================================================================

# Content types
CONTENT_TYPE_LIVE = 'LIVE'
CONTENT_TYPE_VOD = 'VOD'

# Stream modes
MODE_LIVE = 'live'
MODE_VOD = 'vod'

# ============================================================================
# DRM Configuration
# ============================================================================

# DRM system
DRM_SYSTEM_WIDEVINE = 'widevine'

# DRM request headers
DRM_REQUEST_HEADERS = {
    'Content-Type': 'application/octet-stream'
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

# Cache durations (seconds)
BOOTSTRAP_CACHE_DURATION = 3600  # 1 hour
OPENID_CONFIG_CACHE_DURATION = 86400  # 24 hours
MANIFEST_CACHE_DURATION = 7200  # 2 hours

# ============================================================================
# Error Codes
# ============================================================================

# Known error codes from Magenta2 API
ERROR_CODES = {
    'DEVICE_LIMIT_EXCEEDED': 'deviceLimitExceeded',
    'PLAYBACK_RESTRICTED': 'ENT_RVOD_Playback_Restricted',
    'UNAUTHORIZED': 'ENT_Unauthorized',
    'INVALID_TOKEN': 'INVALID_TOKEN',
    'SESSION_EXPIRED': 'SESSION_EXPIRED'
}

# ============================================================================
# TAA Configuration
# ============================================================================

# TAA request template
TAA_REQUEST_TEMPLATE = {
    "accessTokenSource": IDM,
    "appVersion": APPVERSION2,
    "channel": {
        "id": "Tv"
    },
    "natco": "DE",
    "type": "telekom"
}

# ============================================================================
# Bootstrap Configuration
# ============================================================================

# Bootstrap parameters
BOOTSTRAP_PARAMS = {
    '$redirect': 'false'
}

# REMOVED: Old BOOTSTRAP_KEYS - now handled in config_models.py