# streaming_providers/providers/magenta2/__init__.py
from .auth import Magenta2Authenticator, Magenta2AuthToken, Magenta2Credentials
from .config_models import (BootstrapConfig, DrmConfig, ManifestConfig,
                            MpxConfig, OpenIDConfig, ProviderConfig,
                            TvHubConfig)
from .constants import SUPPORTED_COUNTRIES
from .discovery import DiscoveryService
from .endpoint_manager import EndpointCategory, EndpointManager
from .models import (DeviceLimitExceededException, Magenta2Channel,
                     Magenta2PlaybackRestrictedException)
from .provider import Magenta2Provider

__all__ = [
    # Core provider
    "Magenta2Provider",
    # Models
    "Magenta2Channel",
    "Magenta2PlaybackRestrictedException",
    "DeviceLimitExceededException",
    # Authentication
    "Magenta2Authenticator",
    "Magenta2AuthToken",
    "Magenta2Credentials",
    # New discovery system
    "DiscoveryService",
    "EndpointManager",
    "EndpointCategory",
    # Configuration models
    "BootstrapConfig",
    "ManifestConfig",
    "OpenIDConfig",
    "ProviderConfig",
    "MpxConfig",
    "DrmConfig",
    "TvHubConfig",
    # Constants
    "SUPPORTED_COUNTRIES",
]

__version__ = "2.0.0"  # Major version bump for architectural changes
