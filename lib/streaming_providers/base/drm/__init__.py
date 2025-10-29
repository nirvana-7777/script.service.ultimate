# streaming_providers/base/drm/__init__.py
"""
Plugin system for DRM configuration processing

This module contains the core abstractions for DRM plugins.
All plugin implementations are automatically discovered by the DRMPluginManager.
"""

from .drm_plugin import DRMPlugin
from .plugin_manager import DRMPluginManager

# The plugin manager handles automatic discovery and registration
# No need to manually import or register plugins here

__all__ = [
    "DRMPlugin",
    "DRMPluginManager",
]
