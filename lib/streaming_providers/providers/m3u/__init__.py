# streaming_providers/providers/m3u/__init__.py
"""
M3U Playlist Provider

A universal provider that reads local M3U/M3U8 playlist files
to extract channel information, manifests, and DRM configuration.

Features:
- Extended M3U attribute parsing (TVG, custom, DRM)
- Support for DASH (.mpd) and HLS (.m3u8) formats
- Kodi/VLC properties support
- Auto-detection of content type, quality, radio channels
- Caching with TTL and file modification tracking
"""

from .provider import M3UProvider

__all__ = ["M3UProvider"]

# Provider metadata for registration
PROVIDER_METADATA = {
    "name": "m3u",
    "label": "M3U Playlist",
    "description": "Universal M3U/M3U8 playlist parser with DRM support",
    "supports_countries": ["*"],  # All countries
    "requires_auth": False,
    "supports_live": True,
    "supports_vod": True,
    "supports_radio": True,
    "supports_drm": True,
    "supports_catchup": False,
    "supports_epg": False,
    "formats": ["dash", "hls"],
}