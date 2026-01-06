# streaming_providers/providers/magentaeu/constants.py
# ============================================================================
# Magenta TV Configuration
# ============================================================================

from typing import Dict

# Supported countries
SUPPORTED_COUNTRIES = ["hr", "pl", "me", "at", "hu"]

# Default country
DEFAULT_COUNTRY = "at"

MAX_TV_LOGO = "https://www.lyngsat.com/logo/corp/mm/max-tv-hr.png"
MAGENTA_TV_PL_LOGO = "https://magentatv.pl/client/assets/6700c91b4408a2abe2a4.webp"
MAGENTA_TV_AT_LOGO = "https://m.media-amazon.com/images/I/51XY6Cq3ANL.png"

# Country-specific configuration
COUNTRY_CONFIG = {
    "hr": {
        "base_url": "https://mojmaxtv.hrvatskitelekom.hr",
        "bifrost_url": "https://tv-hr-prod.yo-digital.com/hr-bifrost",
        "natco_key": "l2lyvGVbUm2EKJE96ImQgcc8PKMZWtbE",
        "app_key": "GWaBW4RTloLwpUgYVzOiW5zUxFLmoMj5",
        "language": "hr",
        "rsa_key": """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDMmKReuzuaCk10Wa6vv4ybcqjVN3cruj27IRp9YhdgEw9jcG728Aj9s60mY8B/czzW5ntKJQktyBRBZ98BKznRWBrVN/n9JR/m1UDc38PW4BPe4z5VtBe99dyFcJQ1VJij6HG0BFtw3isPR5NAUAAyGnXpNWKCat5TtBckqVatBQIDAQAB
-----END PUBLIC KEY-----""",
    },
    "pl": {
        "base_url": "https://magentatv.pl",
        "bifrost_url": "https://tv-pl-prod.yo-digital.com/pl-bifrost",
        "natco_key": "ovINYLVrQsLj8wPDQzNYotQMkFha9PFF",
        "app_key": "2zjAjpJ6dRfHR1nIwF47jz75g7Qf4F6z",
        "language": "pl",
        "rsa_key": """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxTkEaSufgfBKbzBAHRzSQreMYYCAg4wtjk44A31qVrt0/IaBNbAlvDNEWmB9kwZXK6s41XiPg1k/xsWNoug0nIU1eTEeTsRDwrMzxwYyn5ObO1jylBK0mEAmcl/cEk8A+DqW+raxoWSNq6IH4pciO3QVxeAzIP73FSBrcj81LEeDQsJY6ySbZ1mcDD1/axuCrUm2masJq3nifNOEZG7mAiy5pvoN54grldvXuc8nBne9tdMnCFRisRIO7f2KG5pQVqtLh41aeRTD0eg9c7SWYDhTcRb5MA+PqluZrtwQ3+J7kBGGlxkYHuQ10slR6YUqEELdd85CE7DtMx+PcGLxWwIDAQAB
-----END PUBLIC KEY-----""",
    },
    "me": {
        "base_url": "https://magentatv.me",
        "bifrost_url": "https://tv-me-prod.yo-digital.com/me-bifrost",
        "natco_key": "ANKB5xVVywklLUd9WtEOh8eyLnlAypTM",
        "app_key": "erYJuNj5fnVXtRgjkr4scxbr3oEkM4I4",
        "language": "me",
        "rsa_key": """-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApoovXHgusvwv7S0cdg+xQYuY3Kb/J50n3GKpW4UmH4xG8NCAD6PBHPKGlVYl6sAnLXofJeq0DsXZJ9xFGH1wTQdd3hxwhGrigstluu4PbpiVRjrFe9AuZto+/Hb0+Ljr5BKFgNMYhpZOaBWgjkqtYWFyMzB1v3VtgUURqxyzMhgiPoCcqYynnqK1weJLGEMSZNlHeWwX46VlK/JqIwPw2ajl5IwvQFzY6BEQvfwXVJxIcvQwkcmeR1A3ACE1E1tvrATb1EPNeKh/E6Kukb8EGTB1O3WJa4IrdX6HI3BJLXftLZ9Y55HuHa+GrGkJRJvchxYCugxgHKSqNOnsT8FWYm1gdZZ6/i/jPo7/tpEdd2U6FxG7/I4rcpk2FzSSd3LKEHGf5v1V982Idbrlm+1LfsjoTx5Go2M8+uBR92pV0qSQlB4YXgQQgqpDUq9f9TwN67nj2jfRECR2hBITkK3+sC9ZxSHYg4Cp3ycHqetxUJ21kVmO6jMG+JsBHLuDKCIc3yrHXHBwhZt4XOhH6K564pUKBOfbe9mZlGrttEla0FK9B/WM315QQ9WgHA5pFyDFmjsB4MvFqKrbsrVUxDZM1COHVC7QbyEte45BDDO/amaB1aa6st5mNIm22m0s0jW8flHarGuulCDNBt9jHI6MnYLb3wpVj00b62Vmx1FX9qkCAwEAAQ==
-----END PUBLIC KEY-----""",
    },
    "at": {
        "base_url": "https://tv.magenta.at",
        "bifrost_url": "https://tv-at-prod.yo-digital.com/at-bifrost",
        "natco_key": "NZu7aIg1vFTNLwHcb0Kjhqk54ql9RJj5",
        "app_key": "CTnKA63ruKM0JM1doxAXwwyQLLmQiEiy",
        "language": "de",
        "rsa_key": """-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA0EsuGonW8+y5Oq2Hopru5oFCaXEDMBrWPDkzIeY1Vvot3z/l9Q3/bcUQV3Yo6DvbhlARQnMeqiKJ5dutZmdxuj+nhZq9FcL20RUywqGnxTCHaGAEb05Qlovu7Rbld2GeJa4nFP1RY5glUlr/DYVB+tIHqPfZVUSc1PS+l5QkB9TJir57ALxERBJGjT5vhQixXGf6IqmLkxm1okIbuGJa2ttmSWNq0OVi2cF40ZsV64ly7a3m6n2WBYmhqd3ghSprNHXwJBwYwu1L+9CF9oLQXHs9cUDhqyQB+3iDU2Ro/rtZsGcnvnIiDHRIWZ94zcOTOpdUH4pBujc8jF3qdw99UwIBJQ==
-----END PUBLIC KEY-----""",
    },
    "hu": {
        "base_url": "https://player.telekomtvgo.hu",
        "bifrost_url": "https://tv-hu-prod.yo-digital.com/bifrost",
        "natco_key": "Tydx7H7fJO6HxgjvJok0ZhVWFmX3om0P",
        "app_key": "exSJHBiSAN6wAAeqdWLdTUfdTi2PNark",
        "language": "hu",
        "rsa_key": """-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA0EsuGonW8+y5Oq2Hopru5oFCaXEDMBrWPDkzIeY1Vvot3z/l9Q3/bcUQV3Yo6DvbhlARQnMeqiKJ5dutZmdxuj+nhZq9FcL20RUywqGnxTCHaGAEb05Qlovu7Rbld2GeJa4nFP1RY5glUlr/DYVB+tIHqPfZVUSc1PS+l5QkB9TJir57ALxERBJGjT5vhQixXGf6IqmLkxm1okIbuGJa2ttmSWNq0OVi2cF40ZsV64ly7a3m6n2WBYmhqd3ghSprNHXwJBwYwu1L+9CF9oLQXHs9cUDhqyQB+3iDU2Ro/rtZsGcnvnIiDHRIWZ94zcOTOpdUH4pBujc8jF3qdw99UwIBJQ==
-----END PUBLIC KEY-----""",
    },
}

# ============================================================================
# Application Configuration
# ============================================================================

APP_VERSION = "02.0.1340"
OS = "Linux"
BROWSER = "Chrome"
BROWSER_VERSION = "143"
DEVICE_NAME = f"{OS} - {BROWSER}"

# ============================================================================
# Device Configuration
# ============================================================================

DEVICE_MODEL = "WEB"
DEVICE_TYPE = "WEB"
DEVICE_OS = OS
DEVICE_MANUFACTURER = f"{OS} x86_64"
DEVICE_CONCURRENCY_PARAM = "TVSOA-restriction-unmanagedDeviceStreamLimit"

# User agent configuration
USER_AGENT = f"Mozilla/5.0 (X11; {OS} x86_64) AppleWebKit/537.36 (KHTML, like Gecko) {BROWSER}/{BROWSER_VERSION}.0.0.0 Safari/537.36"
X_USER_AGENT = f"{DEVICE_MODEL.lower()}|{DEVICE_TYPE.lower()}|{BROWSER}-{BROWSER_VERSION}|{APP_VERSION}|1"

# ============================================================================
# API Endpoints
# ============================================================================

# Base API URLs
GATEWAY_BASE_URL = "https://gateway-{natco}-proxy.tv.yo-digital.com"

# API endpoints
API_ENDPOINTS = {
    "LOGIN": GATEWAY_BASE_URL + "/{natco}-idm/P/onboarding/login",
    "REFRESH_TOKEN": GATEWAY_BASE_URL + "/{natco}-idm/P/onboarding/refresh-token",
    "UPGRADE_TOKEN": GATEWAY_BASE_URL + "/{natco}-idm/P/onboarding/upgrade-token",
    "USER_ACCOUNT": "{bifrost_url}/user/account",
    "EPG_CHANNELS": "{bifrost_url}/epg/channel",
    "STARTUP_PAGE": "{base_url}/epg",
}

# Widevine configuration
WV_URL = "https://widevine.entitlement.theplatform.eu/wv/web/ModularDrm/getRawWidevineLicense?schema=1.0&form=json&releasePid="
ACC_URL = "http://access.auth.theplatform.com/data/Account"

# ============================================================================
# Authentication Configuration
# ============================================================================

# Login context and type
LOGIN_CONTEXT = "login"
LOGIN_TYPE = "telekom"
CHANNEL_ID = "Tv"

# Authentication flows and steps
AUTH_FLOWS = {
    "USERNAME_PASSWORD_LOGIN": "USERNAME_PASSWORD_LOGIN",
    "START_UP": "START_UP",
}

AUTH_STEPS = {
    "GET_ACCESS_TOKEN": "GET_ACCESS_TOKEN",
    "REFRESH_TOKEN": "REFRESH_TOKEN",
    "UPGRADE_TOKEN": "UPGRADE_TOKEN",
    "GET_USER_ACCOUNT": "GET_USER_ACCOUNT",
    "EPG_CHANNEL": "EPG_CHANNEL",
}

CALL_TYPES = {"GUEST_USER": "GUEST_USER", "AUTH_USER": "AUTH_USER"}

# ============================================================================
# DRM Configuration
# ============================================================================

DRM_SYSTEM_WIDEVINE = "widevine"

# DRM request headers
DRM_REQUEST_HEADERS = {
    "Content-Type": "application/octet-stream",
    "User-Agent": USER_AGENT,
}

# ============================================================================
# Request Configuration
# ============================================================================

DEFAULT_REQUEST_TIMEOUT = 30
DEFAULT_MAX_RETRIES = 3

# ============================================================================
# Headers Configuration
# ============================================================================

BASE_HEADERS = {
    "User-Agent": USER_AGENT,
}

AUTH_HEADERS_BASE = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-User-Agent": X_USER_AGENT,
    "Tenant": "tv",
}

# ============================================================================
# Content Configuration
# ============================================================================

CONTENT_TYPE_LIVE = "LIVE"
STREAMING_FORMAT_DASH = "dash"

# ============================================================================
# Device Management
# ============================================================================

MANAGE_DEVICE = False
BROADCASTING_STREAM_LIMITATION_APPLIES = False


def get_country_config(country: str) -> dict:
    """Get configuration for specific country"""
    return COUNTRY_CONFIG.get(country, COUNTRY_CONFIG[DEFAULT_COUNTRY])


def get_base_url(country: str) -> str:
    """Get base URL for country"""
    return get_country_config(country)["base_url"]


def get_bifrost_url(country: str) -> str:
    """Get bifrost URL for country"""
    return get_country_config(country)["bifrost_url"]


def get_natco_key(country: str) -> str:
    """Get natco key for country"""
    return get_country_config(country)["natco_key"]


def get_app_key(country: str) -> str:
    """Get app key for country"""
    return get_country_config(country)["app_key"]


def get_language(country: str) -> str:
    """Get language for country"""
    return get_country_config(country)["language"]


def get_rsa_key(country: str) -> str:
    """Get RSA public key for country"""
    return get_country_config(country)["rsa_key"]


def get_base_headers() -> Dict[str, str]:
    """Get base headers for requests"""
    return {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def get_guest_headers(country: str, device_id: str, session_id: str) -> Dict[str, str]:
    """Get headers for guest/unauthenticated requests"""
    import uuid

    headers = {
        "User-Agent": USER_AGENT,
        "X-User-Agent": X_USER_AGENT,
        "X-Call-Type": "GUEST_USER",
        "X-Tv-Flow": "START_UP",
        "X-Tv-Step": "EPG_CHANNEL",
        "x-request-session-id": session_id,
        "x-request-tracking-id": str(uuid.uuid4()),
        "Tenant": "tv",
        "Origin": get_base_url(country),
        "App_key": get_app_key(country),
        "App_version": APP_VERSION,
        "Device-Id": device_id,
        "Device-Name": DEVICE_NAME,
    }
    return headers
