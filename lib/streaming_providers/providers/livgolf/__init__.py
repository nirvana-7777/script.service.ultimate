# streaming_providers/providers/livgolf/__init__.py
from .auth import LivGolfAuthToken, LivGolfAuthenticator
from .constants import (
    API_ENDPOINTS,
    DEFAULT_CHAMPION_ID,
    PROVIDER_LABEL,
    PROVIDER_LOGO,
    PROVIDER_NAME,
)
from .channel_manager import LivGolfChannelManager
from .provider import LivGolfProvider

__all__ = [
    "LivGolfProvider",
    "LivGolfAuthenticator",
    "LivGolfAuthToken",
    "LivGolfChannelManager",
    "PROVIDER_NAME",
    "PROVIDER_LABEL",
    "PROVIDER_LOGO",
    "API_ENDPOINTS",
    "DEFAULT_CHAMPION_ID",
]

__version__ = "1.0.0"
