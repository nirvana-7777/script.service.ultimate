# streaming_providers/providers/discovery/__init__.py
"""
Discovery+ Provider Package

Provides access to Discovery+ streaming content with support for:
- Anonymous and user authentication
- Live channels and VOD content
- DRM-protected streams
- Multi-country support (EMEA)
"""
from .provider import DiscoveryProvider

from .auth import (
    DiscoveryAuthenticator,
    DiscoveryAuthToken,
    DiscoveryAnonymousCredentials,
    DiscoveryUserCredentials,
)
from .constants import (
    DEFAULT_COUNTRY,
    SUPPORTED_COUNTRIES,
    CHANNEL_COLLECTIONS,
    CHANNEL_ITEM_TYPES,
    DISCOVERY_USERS_ME_URL,
    StreamingMode,
    CDMMode,
    VideoQuality,
    DRMSystem,
    AuthProvider,
    ErrorCode,
)
from .exceptions import (
    DiscoveryError,
    PlaybackRestrictedException,
    AuthenticationError,
    InvalidCredentialsError,
    UnsupportedCredentialTypeError,
    TokenExpiredError,
    EndpointDiscoveryError,
    ChannelNotFoundError,
    ManifestFetchError,
    DRMConfigurationError,
)
from .models import DiscoveryChannel

# Note: DiscoveryProvider would be imported here when available
# from .provider import DiscoveryProvider

__all__ = [
    # Provider class (when available)
    "DiscoveryProvider",

    # Models
    "DiscoveryChannel",

    # Exceptions
    "DiscoveryError",
    "PlaybackRestrictedException",
    "AuthenticationError",
    "InvalidCredentialsError",
    "UnsupportedCredentialTypeError",
    "TokenExpiredError",
    "EndpointDiscoveryError",
    "ChannelNotFoundError",
    "ManifestFetchError",
    "DRMConfigurationError",

    # Authentication
    "DiscoveryAuthenticator",
    "DiscoveryAuthToken",
    "DiscoveryAnonymousCredentials",
    "DiscoveryUserCredentials",

    # Constants - Values
    "DEFAULT_COUNTRY",
    "SUPPORTED_COUNTRIES",
    "CHANNEL_COLLECTIONS",
    "CHANNEL_ITEM_TYPES",
    "DISCOVERY_USERS_ME_URL",

    # Constants - Enums
    "StreamingMode",
    "CDMMode",
    "VideoQuality",
    "DRMSystem",
    "AuthProvider",
    "ErrorCode",
]

__version__ = "2.0.0"