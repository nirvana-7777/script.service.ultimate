# streaming_providers/providers/magenta_eu/__init__.py
from .auth import MagentaAuthenticator, MagentaAuthToken
from .constants import (API_ENDPOINTS, COUNTRY_CONFIG, DEFAULT_COUNTRY,
                        SUPPORTED_COUNTRIES)
from .provider import MagentaEUProvider

__all__ = [
    "MagentaEUProvider",
    "MagentaAuthenticator",
    "MagentaAuthToken",
    "SUPPORTED_COUNTRIES",
    "DEFAULT_COUNTRY",
    "COUNTRY_CONFIG",
    "API_ENDPOINTS",
]

__version__ = "1.0.0"
