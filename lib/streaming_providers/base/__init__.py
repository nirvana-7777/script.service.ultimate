# streaming_providers/base/__init__.py
"""
Base module for streaming providers

This module contains the core abstractions and models used by all providers.
"""

from .drm import DRMPlugin, DRMPluginManager
from .manager import ProviderManager
from .models import StreamingChannel
from .provider import StreamingProvider

__all__ = [
    "StreamingChannel",
    "StreamingProvider",
    "ProviderManager",
    "DRMPlugin",
    "DRMPluginManager",
]
