# streaming_providers/providers/discovery/constants.py
"""
Discovery+ Provider Constants

All configuration values for the Discovery+ streaming provider.
"""
from enum import Enum
from typing import Dict, List, Final


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


class AuthProvider(str, Enum):
    """Authentication providers"""
    USERNAME_PASSWORD = "USERNAME_PASSWORD"
    ANONYMOUS = "anonymous"


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

CMS_INCLUDE_PARAMS: Final[str] = "default,viewingHistory,isFavorite,contentAction,badges"
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

DISCOVERY_USER_AGENT: Final[
    str] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"

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

# Full x-disco-client header value
DISCOVERY_DISCO_CLIENT: Final[str] = f"WEB:x86_64:dplus:{DISCOVERY_CLIENT_VERSION}"

# x-disco-params header value
DISCOVERY_DISCO_PARAMS: Final[str] = "realm=bolt,bid=dplus,features=ar"

# x-device-info header template — format with device_id and session_id
DISCOVERY_DEVICE_INFO_TEMPLATE: Final[str] = (
    f"dplus/{DISCOVERY_CLIENT_VERSION} (desktop/desktop; Linux/x86_64; {{device_id}}/{{session_id}})"
)

# x-wbd-device-consent header value
DISCOVERY_DEVICE_CONSENT: Final[str] = "gpc=0"

# Default timezone for x-wbd-time-zone header
DISCOVERY_DEFAULT_TIMEZONE: Final[str] = "Europe/Berlin"

# Origin / Referer for auth requests (login, bootstrap)
DISCOVERY_AUTH_ORIGIN: Final[str] = "https://auth.discoveryplus.com"
DISCOVERY_AUTH_REFERER: Final[str] = "https://auth.discoveryplus.com/"


def get_default_device_info() -> Dict[str, any]:
    """
    Return a fresh copy of default device info.

    Returns:
        Dictionary containing device information
    """
    return {
        "deviceId": DEFAULT_DEVICE_ID,
        "browser": {"name": "Chrome", "version": "144.0.0.0"},
        "make": "desktop",
        "model": "desktop",
        "os": {"name": "Linux", "version": "0.0.0"},
        "platform": "WEB",
        "deviceType": "web",
        "player": {
            "sdk": {"name": "Beam Player Desktop", "version": "6.14.0"},
            "mediaEngine": {
                "name": "GLUON_BROWSER",
                "version": "7.0.0",
                "labsConfigVersion": "playback_engine_gluon@web-1.2.0,playback_engine_gluon_disable_network_request_event@default-1.0.0,playback_engine_gluon_segment_download_during_drminit@1.0.0,playback_engine_gluon_abr_protocol_hybrid@1.0.0,playback_engine_gluon_initial_track_selection@1.0.0",
            },
            "playerView": {"height": 1080, "width": 1920},
        },
    }


def get_default_capabilities() -> Dict[str, any]:
    """
    Return a fresh copy of default capabilities.

    Returns:
        Dictionary containing device capabilities
    """
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
            "contentDecryptionModules": [
                {"drmKeySystem": "clearkey"},
                {"drmKeySystem": "widevine", "maxSecurityLevel": "l3"},
            ]
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


# ============================================================================
# Playback Configuration
# ============================================================================

DEFAULT_PLAYBACK_SESSION_ID: Final[str] = "fb20e22e-abcd-490a-a83d-8c71f79e7435"
DEFAULT_APPLICATION_SESSION_ID: Final[str] = "74985592-a061-4597-ab5b-51492d0fc2c6"

# ============================================================================
# DRM Configuration
# ============================================================================

DRM_SYSTEM_WIDEVINE: Final[str] = DRMSystem.WIDEVINE.value


def get_drm_request_headers() -> Dict[str, str]:
    """
    Return a fresh copy of DRM request headers.

    Returns:
        Dictionary containing DRM request headers
    """
    return {
        "Content-Type": "application/octet-stream",
        "User-Agent": DISCOVERY_USER_AGENT,
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