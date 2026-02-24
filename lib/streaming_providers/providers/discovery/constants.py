# streaming_providers/providers/discovery/constants.py
"""
Discovery+ Provider Constants

All configuration values for the Discovery+ streaming provider.
"""
from enum import Enum
from typing import Dict, List, Final, Optional


# ============================================================================
# Enums for Type Safety
# ============================================================================

class StreamingMode(str, Enum):
    """Streaming modes"""
    LIVE = "live"
    VOD = "vod"


class CDMMode(str, Enum):
    """CDM (Content Decryption Module) modes"""
    EXTERNAL = "external"
    INTERNAL = "internal"


class VideoQuality(str, Enum):
    """Video quality settings"""
    BEST = "best"
    HD = "hd"
    SD = "sd"


class DRMSystem(str, Enum):
    """DRM systems"""
    WIDEVINE = "widevine"
    CLEARKEY = "clearkey"
    PLAYREADY = "playready"


class AuthProvider(str, Enum):
    """Authentication providers"""
    USERNAME_PASSWORD = "USERNAME_PASSWORD"
    ANONYMOUS = "anonymous"


class PlatformOS(str, Enum):
    """
    Target OS platform used for device/header spoofing.

    LINUX   → Chrome browser, Widevine + ClearKey DRM, x-disco-client os_version="0.0.0"
    WINDOWS → Microsoft Edge browser, PlayReady DRM,   x-disco-client os_version="NT 10.0"
    """
    LINUX = "linux"
    WINDOWS = "windows"


# Active platform — change this single constant to switch all OS-dependent behaviour.
# LINUX preserves existing behaviour exactly; WINDOWS mirrors a real Edge/Windows client.
DEFAULT_PLATFORM_OS: Final[PlatformOS] = PlatformOS.WINDOWS


# ============================================================================
# Basic Configuration
# ============================================================================

# Provider information
DISCOVERY_LOGO: Final[
    str] = "https://upload.wikimedia.org/wikipedia/commons/thumb/f/f1/Discovery%2B_logo.svg/2560px-Discovery%2B_logo.svg.png"

# Bootstrap endpoint for dynamic configuration
DISCOVERY_BOOTSTRAP_URL: Final[
    str] = "https://default.any-any.prd.api.discoveryplus.com/session-context/headwaiter/v1/bootstrap"

# Default realm
DEFAULT_REALM: Final[str] = "bolt"

# ============================================================================
# Authentication Configuration
# ============================================================================

# Supported auth types
SUPPORTED_AUTH_TYPES: Final[List[str]] = [
    "anonymous",  # Anonymous token
    "user_credentials",  # Username/password login
]

# ============================================================================
# Country/Region Configuration
# ============================================================================

# Supported countries (EMEA region)
SUPPORTED_COUNTRIES: Final[List[str]] = [
    "de", "at", "ch", "dk", "fi", "no", "se", "it", "nl", "es", "uk", "ie",
]

# Home market mapping (immutable)
HOME_MARKET_MAPPING: Final[Dict[str, str]] = {
    "de": "emea", "at": "emea", "ch": "emea",
    "dk": "emea", "fi": "emea", "no": "emea", "se": "emea",
    "it": "emea", "nl": "emea", "es": "emea",
    "uk": "uk", "ie": "uk",
}

# Tenant
DEFAULT_TENANT: Final[str] = "dplus"

# Environment
DEFAULT_ENV: Final[str] = "prd"

# Domain
DEFAULT_DOMAIN: Final[str] = "api.discoveryplus.com"

# Default country
DEFAULT_COUNTRY: Final[str] = "de"

# ============================================================================
# CMS Configuration
# ============================================================================

CMS_INCLUDE_PARAMS: Final[str] = "default"
CMS_PAGE_SIZE: Final[int] = 50

# Known collection IDs for TV channels (will be discovered dynamically, but these are fallbacks)
CHANNEL_COLLECTIONS: Final[Dict[str, List[str]]] = {
    "de": [
        "158509151486067887066538918357725817419",  # "Unsere TV-Kanäle" (Germany)
        "191019300316436018732917730141471355952",  # DMAX Austria
    ],
    "at": [
        "191019300316436018732917730141471355952",  # DMAX Austria
    ],
    "ch": [],
    "uk": [],
    "ie": [],
}

# Collection item types that represent channels
CHANNEL_ITEM_TYPES: Final[List[str]] = ["distributionChannel", "channel", "linearChannel", "liveChannel"]

# ============================================================================
# User Agent Configuration
# ============================================================================

# Per-platform user agent strings.
# LINUX  → Chrome on Linux  (original behaviour)
# WINDOWS → Edge on Windows (matches real captured HAR traffic)
DISCOVERY_USER_AGENT_LINUX: Final[str] = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
)
DISCOVERY_USER_AGENT_WINDOWS: Final[str] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36 Edg/139.0.0.0"
)

# Convenience alias — resolves to the Linux UA by default so existing callers
# that reference DISCOVERY_USER_AGENT directly are unaffected.
DISCOVERY_USER_AGENT: Final[str] = DISCOVERY_USER_AGENT_LINUX

# ============================================================================
# Device Configuration
# ============================================================================

# Device ID (consistent across sessions for anonymous tracking)
DEFAULT_DEVICE_ID: Final[str] = "a2f463fa-2052-4af1-ae16-26d8289c6b94"

# ============================================================================
# Client / Header Configuration
# ============================================================================

# Client version string — used in x-disco-client and x-device-info headers
DISCOVERY_CLIENT_VERSION: Final[str] = "6.14.0"

# Full x-disco-client header value — WEB:{os_version}:dplus:{client_version}
# OS version is "0.0.0" for web platform

# x-disco-params header value
DISCOVERY_DISCO_PARAMS: Final[str] = "realm=bolt,bid=dplus,features=ar"

# x-device-info header templates — one per OS platform.
# Format placeholders: {device_id}, {session_id}
DISCOVERY_DEVICE_INFO_TEMPLATE_LINUX: Final[str] = (
    f"dplus/{DISCOVERY_CLIENT_VERSION} (desktop/desktop; Linux/x86_64; {{device_id}}/{{session_id}})"
)
DISCOVERY_DEVICE_INFO_TEMPLATE_WINDOWS: Final[str] = (
    f"dplus/{DISCOVERY_CLIENT_VERSION} (desktop/desktop; Windows/NT 10.0; {{device_id}}/{{session_id}})"
)

# x-wbd-device-consent header value
DISCOVERY_DEVICE_CONSENT: Final[str] = "gpc=0"

# Default timezone for x-wbd-time-zone header
DISCOVERY_DEFAULT_TIMEZONE: Final[str] = "Europe/Berlin"

# Origin / Referer for auth requests (login, bootstrap)
DISCOVERY_AUTH_ORIGIN: Final[str] = "https://auth.discoveryplus.com"
DISCOVERY_AUTH_REFERER: Final[str] = "https://auth.discoveryplus.com/"

# Arkose (FunCaptcha) — required before POST /login
DISCOVERY_ARKOSE_SITEKEY: Final[str] = "09CB1E22-0FB7-4AD8-957C-4F06CAFB3C7E"
DISCOVERY_ARKOSE_DATA_URL: Final[str] = (
    "https://default.dplus-emea.prd.api.discoveryplus.com/users/arkose/data"
)
DISCOVERY_ARKOSE_DATA_PAYLOAD: Final[Dict] = {
    "data": {
        "attributes": {"relativePath": "/login", "styleTheme": "dplus"},
        "type": "arkoseDataExchange",
    }
}
# Arkose FunCaptcha token exchange — Discovery+ hosts their own FC endpoint
DISCOVERY_ARKOSE_FC_URL: Final[str] = (
    f"https://a4gds3vfh.discoveryplus.com/fc/gt2/public_key/{DISCOVERY_ARKOSE_SITEKEY}"
)

# ============================================================================
# HMAC / Client ID Configuration
# ============================================================================

# HMAC key for web platform (base64-decoded from feature flags response)
# Raw b64: NTVlZWExODktZTliNi00NzlmLWJjNTEtMjIyNGNmZGE1NmZl
DISCOVERY_HMAC_KEY: Final[str] = "55eea189-e9b6-479f-bc51-2224cfda56fe"

# x-disco-client-id prefix matches hmacKeys "id" field for web
DISCOVERY_CLIENT_ID_PREFIX: Final[str] = "web1_prd"

# x-disco-client header — WEB:{os_version}:dplus:{client_version}
# os_version encodes the OS: "0.0.0" for Linux web, "NT 10.0" for Windows
DISCOVERY_DISCO_CLIENT_LINUX: Final[str] = f"WEB:0.0.0:dplus:{DISCOVERY_CLIENT_VERSION}"
DISCOVERY_DISCO_CLIENT_WINDOWS: Final[str] = f"WEB:NT 10.0:dplus:{DISCOVERY_CLIENT_VERSION}"

# Feature flags endpoint — provides hmacKeys, gisdk clientId, arkose config etc.
# x-gisdk clientId comes from the response and is session-specific.
DISCOVERY_FEATURE_FLAGS_URL: Final[str] = (
    "https://default.any-any.prd.api.discoveryplus.com/labs/api/v1/sessions/feature-flags/decisions"
)
DISCOVERY_FEATURE_FLAGS_PAYLOAD: Final[Dict] = {
    "context": {"deviceType": "desktop", "domain": "discoveryplus.com"},
    "projectId": "7e52f0d0-d8b5-4eda-983b-597e4e2102a2",
}


def get_default_device_info(platform_os: Optional[PlatformOS] = None) -> Dict[str, any]:
    """
    Return a fresh copy of default device info for the given OS platform.

    Args:
        platform_os: Target OS platform. Defaults to DEFAULT_PLATFORM_OS.
                     PlatformOS.LINUX  → Chrome on Linux  (original behaviour)
                     PlatformOS.WINDOWS → Edge on Windows

    Returns:
        Dictionary containing device information suitable for the playbackInfo body.
    """
    if platform_os is None:
        platform_os = DEFAULT_PLATFORM_OS

    if platform_os == PlatformOS.WINDOWS:
        os_info = {"name": "Windows", "version": "NT 10.0"}
        browser_info = {"name": "Microsoft Edge", "version": "139.0.0.0"}
    else:
        # LINUX — preserves original behaviour exactly
        os_info = {"name": "Linux", "version": "0.0.0"}
        browser_info = {"name": "Chrome", "version": "144.0.0.0"}

    return {
        "deviceId": DEFAULT_DEVICE_ID,
        "browser": browser_info,
        "make": "desktop",
        "model": "desktop",
        "os": os_info,
        "platform": "WEB",
        "deviceType": "web",
        "player": {
            "sdk": {"name": "Beam Player Desktop", "version": DISCOVERY_CLIENT_VERSION},
            "mediaEngine": {
                "name": "GLUON_BROWSER",
                "version": "7.0.0",
                "labsConfigVersion": "playback_engine_gluon@web-1.2.0,playback_engine_gluon_disable_network_request_event@default-1.0.0,playback_engine_gluon_segment_download_during_drminit@1.0.0,playback_engine_gluon_abr_protocol_hybrid@1.0.0,playback_engine_gluon_initial_track_selection@1.0.0",
            },
            "playerView": {"height": 1080, "width": 1920},
        },
    }


def get_default_capabilities(platform_os: Optional[PlatformOS] = None) -> Dict[str, any]:
    """
    Return a fresh copy of default capabilities for the given OS platform.

    The DRM advertised differs by platform:
      LINUX   → ClearKey + Widevine L3   (original behaviour)
      WINDOWS → ClearKey + PlayReady SL3000  (matches real Edge/Windows client)

    Args:
        platform_os: Target OS platform. Defaults to DEFAULT_PLATFORM_OS.

    Returns:
        Dictionary containing device capabilities suitable for the playbackInfo body.
    """
    if platform_os is None:
        platform_os = DEFAULT_PLATFORM_OS

    if platform_os == PlatformOS.WINDOWS:
        cdm_list = [
            {"drmKeySystem": "clearkey"},
            {"drmKeySystem": "playready", "maxSecurityLevel": "sl3000"},
        ]
    else:
        # LINUX — preserves original behaviour exactly
        cdm_list = [
            {"drmKeySystem": "clearkey"},
            {"drmKeySystem": "widevine", "maxSecurityLevel": "l3"},
        ]

    return {
        "manifests": {"formats": {"dash": {}}},
        "codecs": {
            "audio": {"decoders": [{"codec": "aac", "profiles": ["lc", "hev", "hev2"]}]},
            "video": {
                "decoders": [
                    {
                        "codec": "h264",
                        "profiles": ["high", "main", "baseline"],
                        "maxLevel": "5.2",
                        "levelConstraints": {
                            "width": {"min": 0, "max": 973},
                            "height": {"min": 0, "max": 919},
                            "framerate": {"min": 0, "max": 60},
                        },
                    },
                    {
                        "codec": "h265",
                        "profiles": ["main10", "main"],
                        "maxLevel": "5.2",
                        "levelConstraints": {
                            "width": {"min": 0, "max": 973},
                            "height": {"min": 0, "max": 919},
                            "framerate": {"min": 0, "max": 60},
                        },
                    },
                ],
                "hdrFormats": [],
            },
        },
        "contentProtection": {
            "contentDecryptionModules": cdm_list
        },
        "devicePlatform": {
            "memory": {"allocatedMemory": 0, "freeAvailableMemory": 1.7976931348623157e308},
            "network": {
                "capabilities": {"protocols": {"http": {"byteRangeRequests": True}}},
                "lastKnownStatus": {"networkTransportType": "unknown"},
            },
            "videoSink": {
                "capabilities": {"colorGamuts": ["standard"], "hdrFormats": []},
                "lastKnownStatus": {"height": 1080, "width": 1920},
            },
        },
    }


def get_disco_client(platform_os: Optional[PlatformOS] = None) -> str:
    """
    Return the x-disco-client header value for the given OS platform.

    Args:
        platform_os: Target OS platform. Defaults to DEFAULT_PLATFORM_OS.

    Returns:
        x-disco-client header string, e.g. "WEB:0.0.0:dplus:6.14.0"
    """
    if platform_os is None:
        platform_os = DEFAULT_PLATFORM_OS
    if platform_os == PlatformOS.WINDOWS:
        return DISCOVERY_DISCO_CLIENT_WINDOWS
    return DISCOVERY_DISCO_CLIENT_LINUX


def get_device_info_template(platform_os: Optional[PlatformOS] = None) -> str:
    """
    Return the x-device-info header template for the given OS platform.
    The caller must still call .format(device_id=..., session_id=...) on the result.

    Args:
        platform_os: Target OS platform. Defaults to DEFAULT_PLATFORM_OS.

    Returns:
        x-device-info template string with {device_id} and {session_id} placeholders.
    """
    if platform_os is None:
        platform_os = DEFAULT_PLATFORM_OS
    if platform_os == PlatformOS.WINDOWS:
        return DISCOVERY_DEVICE_INFO_TEMPLATE_WINDOWS
    return DISCOVERY_DEVICE_INFO_TEMPLATE_LINUX


# ============================================================================
# Playback Configuration
# ============================================================================

DEFAULT_PLAYBACK_SESSION_ID: Final[str] = "fb20e22e-abcd-490a-a83d-8c71f79e7435"
DEFAULT_APPLICATION_SESSION_ID: Final[str] = "74985592-a061-4597-ab5b-51492d0fc2c6"

# ============================================================================
# DRM Configuration
# ============================================================================

DRM_SYSTEM_WIDEVINE: Final[str] = DRMSystem.WIDEVINE.value
DRM_SYSTEM_PLAYREADY: Final[str] = DRMSystem.PLAYREADY.value


def get_user_agent(platform_os: Optional[PlatformOS] = None) -> str:
    """
    Return the User-Agent string for the given OS platform.

    Args:
        platform_os: Target OS platform. Defaults to DEFAULT_PLATFORM_OS.

    Returns:
        User-Agent header string.
    """
    if platform_os is None:
        platform_os = DEFAULT_PLATFORM_OS
    if platform_os == PlatformOS.WINDOWS:
        return DISCOVERY_USER_AGENT_WINDOWS
    return DISCOVERY_USER_AGENT_LINUX


def get_drm_request_headers(platform_os: Optional[PlatformOS] = None) -> Dict[str, str]:
    """
    Return a fresh copy of DRM request headers for the given OS platform.

    Args:
        platform_os: Target OS platform. Defaults to DEFAULT_PLATFORM_OS.

    Returns:
        Dictionary containing DRM request headers.
    """
    return {
        "Content-Type": "application/octet-stream",
        "User-Agent": get_user_agent(platform_os),
        "Origin": "https://play.discoveryplus.com",
        "Referer": "https://play.discoveryplus.com/",
        "traceparent": "00-aba275155d9ed5c2b54d576682cb30e6-ddfd854be17b3a6e-01",
    }


# ============================================================================
# Request Configuration
# ============================================================================

DEFAULT_REQUEST_TIMEOUT: Final[int] = 30
DEFAULT_MAX_RETRIES: Final[int] = 3
DEFAULT_RETRY_DELAY: Final[int] = 1


# ============================================================================
# Error Codes
# ============================================================================


class ErrorCode(str, Enum):
    """Discovery+ error codes"""
    PLAYBACK_RESTRICTED = "PLAYBACK_RESTRICTED"
    UNAUTHORIZED = "UNAUTHORIZED"
    NOT_FOUND = "NOT_FOUND"
    GEOBLOCKED = "GEOBLOCKED"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"