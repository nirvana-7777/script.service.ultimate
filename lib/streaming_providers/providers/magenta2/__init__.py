# streaming_providers/providers/magenta2/__init__.py
from .provider import Magenta2Provider
from .models import Magenta2Channel, Magenta2PlaybackRestrictedException, DeviceLimitExceededException
from .auth import Magenta2Authenticator, Magenta2AuthToken, Magenta2Credentials
from .discovery import DiscoveryService
from .endpoint_manager import EndpointManager, EndpointCategory
from .config_models import BootstrapConfig, ManifestConfig, OpenIDConfig, ProviderConfig, MpxConfig, DrmConfig, \
    TvHubConfig
from .constants import (
    SUPPORTED_COUNTRIES,
)

__all__ = [
    # Core provider
    'Magenta2Provider',

    # Models
    'Magenta2Channel',
    'Magenta2PlaybackRestrictedException',
    'DeviceLimitExceededException',

    # Authentication
    'Magenta2Authenticator',
    'Magenta2AuthToken',
    'Magenta2Credentials',

    # New discovery system
    'DiscoveryService',
    'EndpointManager',
    'EndpointCategory',

    # Configuration models
    'BootstrapConfig',
    'ManifestConfig',
    'OpenIDConfig',
    'ProviderConfig',
    'MpxConfig',
    'DrmConfig',
    'TvHubConfig',

    # Constants
    'SUPPORTED_COUNTRIES',
]

__version__ = '2.0.0'  # Major version bump for architectural changes