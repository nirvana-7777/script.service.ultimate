#!/usr/bin/env python3
"""
Route handlers for Ultimate Backend Service
"""

from .cache import setup_cache_routes
from .config import setup_config_routes
from .drm import setup_drm_routes
from .epg import setup_epg_routes
from .m3u import setup_m3u_routes
from .providers import setup_provider_routes
from .streams import setup_stream_routes

__all__ = [
    "setup_provider_routes",
    "setup_stream_routes",
    "setup_m3u_routes",
    "setup_drm_routes",
    "setup_cache_routes",
    "setup_config_routes",
    "setup_epg_routes",
]
