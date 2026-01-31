# streaming_providers/providers/bhtelecom/constants.py
# ============================================================================
# BH Telecom Configuration
# ============================================================================

# BH Telecom logo
BHTELECOM_LOGO = "https://upload.wikimedia.org/wikipedia/en/thumb/5/5c/BHTelecom_Logo.svg/1280px-BHTelecom_Logo.svg.png"

# ============================================================================
# API Configuration
# ============================================================================

# Base domain and host configuration
BHTELECOM_HOST = "webtvstream"
BHTELECOM_DOMAIN = ".bhtelecom.ba/"
BHTELECOM_CDN_PATH = "cdn/"
BHTELECOM_CHANNELS_PATH = "client/channels"
BHTELECOM_LOGO_PATH = "client/logos_dark/"

# Base URLs
BHTELECOM_BASE_URLS = {
    "INITIAL": f"https://{BHTELECOM_HOST}{BHTELECOM_DOMAIN}{BHTELECOM_CDN_PATH}",
    "CHANNELS": BHTELECOM_CHANNELS_PATH,
    "LOGOS": BHTELECOM_LOGO_PATH,
}

# Default user agent
BHTELECOM_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"

# Base headers for all requests
BHTELECOM_API_BASE_HEADERS = {
    "User-Agent": BHTELECOM_USER_AGENT,
    "Accept": "application/json",
}

# ============================================================================
# Streaming Configuration
# ============================================================================

# DRM system (default to Widevine for future compatibility)
DRM_SYSTEM_WIDEVINE = "widevine"

# Streaming format
DEFAULT_STREAMING_FORMAT = "dash"

# ============================================================================
# Content Configuration
# ============================================================================

# Content types
CONTENT_TYPE_LIVE = "LIVE"

# Stream modes
MODE_LIVE = "live"

# ============================================================================
# Request Configuration
# ============================================================================

# Default timeout for HTTP requests (seconds)
DEFAULT_REQUEST_TIMEOUT = 30

# Default maximum retries for failed requests
DEFAULT_MAX_RETRIES = 3

# ============================================================================
# Country/Region Configuration
# ============================================================================

# Supported countries
SUPPORTED_COUNTRIES = ["ba"]  # Bosnia and Herzegovina

# Default country
DEFAULT_COUNTRY = "ba"

# Default language
DEFAULT_LANGUAGE = "bs"  # Bosnian

# ============================================================================
# Channel Configuration
# ============================================================================

# Default channel settings
DEFAULT_CHANNEL_CONFIG = {
    "video": "best",
    "on_demand": True,
    "speed_up": True,
    "use_cdm": False,  # Currently no DRM
    "cdm_mode": "external",
    "session_manifest": False,
    "mode": MODE_LIVE,
    "content_type": CONTENT_TYPE_LIVE,
}

# ============================================================================
# Operating System and Browser Configuration
# ============================================================================

DEFAULT_OS = "Linux"
DEFAULT_BROWSER = "Chrome"
DEFAULT_BROWSER_VERSION = "132"