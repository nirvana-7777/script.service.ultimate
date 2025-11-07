# streaming_providers/providers/magenta_eu/__init__.py
from .provider import MagentaProvider
from .auth import MagentaAuthenticator, MagentaAuthToken
from .constants import (
    SUPPORTED_COUNTRIES,
    DEFAULT_COUNTRY,
    COUNTRY_CONFIG,
    API_ENDPOINTS
)

__all__ = [
    'MagentaProvider',
    'MagentaAuthenticator',
    'MagentaAuthToken',
    'SUPPORTED_COUNTRIES',
    'DEFAULT_COUNTRY',
    'COUNTRY_CONFIG',
    'API_ENDPOINTS'
]

__version__ = '1.0.0'