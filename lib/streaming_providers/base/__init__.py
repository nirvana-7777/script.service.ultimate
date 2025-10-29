# streaming_providers/base/__init__.py
"""
Base module for streaming providers

This module contains the core abstractions and models used by all providers.
"""

from .models import StreamingChannel
from .provider import StreamingProvider
from .manager import ProviderManager
from .drm import DRMPlugin, DRMPluginManager

__all__ = [
    "StreamingChannel",
    "StreamingProvider", 
    "ProviderManager",
    "DRMPlugin",
    "DRMPluginManager",
]
