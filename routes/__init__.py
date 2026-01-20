#!/usr/bin/env python3
"""
Route handlers for Ultimate Backend Service
"""

import os
import sys

# Add lib path for imports - this will be executed when routes module is imported
script_dir = os.path.dirname(os.path.abspath(__file__))
app_dir = os.path.dirname(script_dir)  # /app
LIB_PATH = os.path.join(app_dir, "lib")
if os.path.exists(LIB_PATH) and LIB_PATH not in sys.path:
    sys.path.insert(0, LIB_PATH)

# Now import the route setup functions
from .providers import setup_provider_routes
from .streams import setup_stream_routes
from .m3u import setup_m3u_routes
from .drm import setup_drm_routes
from .cache import setup_cache_routes
from .config import setup_config_routes
from .epg import setup_epg_routes

__all__ = [
    'setup_provider_routes',
    'setup_stream_routes',
    'setup_m3u_routes',
    'setup_drm_routes',
    'setup_cache_routes',
    'setup_config_routes',
    'setup_epg_routes'
]