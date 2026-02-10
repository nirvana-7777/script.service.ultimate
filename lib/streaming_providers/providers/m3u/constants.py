# streaming_providers/providers/m3u/constants.py
# ============================================================================
# M3U Provider Configuration
# ============================================================================

# M3U provider logo (generic playlist icon)
M3U_LOGO = "https://upload.wikimedia.org/wikipedia/commons/thumb/8/8d/Playlist_icon.svg/240px-Playlist_icon.svg.png"

# ============================================================================
# Environment Variables
# ============================================================================

# Environment variable for M3U playlists directory
# Similar to DRM_PLUGINS_PATH, this can be set to specify where M3U files are located
# Example: M3U_PLAYLISTS_PATH=/playlists
ENV_M3U_PLAYLISTS_PATH = "M3U_PLAYLISTS_PATH"

# ============================================================================
# File Configuration
# ============================================================================

# Supported file extensions
SUPPORTED_EXTENSIONS = [".m3u", ".m3u8"]

# Default encoding for M3U files
DEFAULT_ENCODING = "utf-8"

# Fallback encodings to try if default fails
FALLBACK_ENCODINGS = ["latin-1", "iso-8859-1", "windows-1252"]

# ============================================================================
# M3U Parsing Configuration
# ============================================================================

# M3U header identifier
M3U_HEADER = "#EXTM3U"

# Extended M3U info line identifier
EXTINF_PREFIX = "#EXTINF:"

# Additional directive prefixes
DIRECTIVE_PREFIXES = {
    "PLAYLIST": "#PLAYLIST:",
    "EXT_X_VERSION": "#EXT-X-VERSION:",
    "KODIPROP": "#KODIPROP:",
    "EXTVLCOPT": "#EXTVLCOPT:",
    "EXTGRP": "#EXTGRP:",
}

# ============================================================================
# Attribute Mapping Configuration
# ============================================================================

# Standard TVG attributes in M3U files
TVG_ATTRIBUTES = {
    "tvg-id": "channel_id",
    "tvg-name": "name",
    "tvg-logo": "logo_url",
    "tvg-language": "language",
    "tvg-country": "country",
    "tvg-url": "epg_url",
    "tvg-shift": "epg_shift",
    "group-title": "genre",
    "tvg-chno": "channel_number",
}

# Additional custom attributes
CUSTOM_ATTRIBUTES = {
    "channel-id": "channel_id",
    "logo": "logo_url",
    "country": "country",
    "language": "language",
    "group": "genre",
    "chno": "channel_number",
}

# DRM-related attributes
DRM_ATTRIBUTES = {
    "drm": "drm_system",
    "license-url": "license_url",
    "license-key": "license_key",
    "certificate-url": "certificate_url",
    "clearkey": "clearkey",
}

# Kodi/VLC property mappings
KODI_VLC_PROPERTIES = {
    "inputstream": "streaming_format",
    "inputstream.adaptive.license_type": "drm_system",
    "inputstream.adaptive.license_key": "license_url",
    "inputstream.adaptive.manifest_type": "streaming_format",
    "http-user-agent": "user_agent",
    "http-referrer": "referer",
}

# ============================================================================
# Streaming Format Detection
# ============================================================================

# Manifest format detection patterns
MANIFEST_PATTERNS = {
    "dash": [".mpd", "dash"],
    "hls": [".m3u8", "hls", "m3u"],
    "smooth": [".ism", "smooth"],
}

# Default streaming format
DEFAULT_STREAMING_FORMAT = "dash"

# ============================================================================
# Content Type Detection
# ============================================================================

# Content type keywords for auto-detection
CONTENT_TYPE_KEYWORDS = {
    "LIVE": ["live", "tv", "channel"],
    "VOD": ["vod", "movie", "film", "video"],
    "RADIO": ["radio", "audio", "musik", "music"],
    "SERIES": ["series", "show", "episode"],
}

# Default content type
DEFAULT_CONTENT_TYPE = "LIVE"

# ============================================================================
# Quality Detection
# ============================================================================

# Quality detection patterns in channel names
QUALITY_PATTERNS = {
    "4K": ["4k", "uhd", "2160p"],
    "UHD": ["uhd", "ultra hd"],
    "HD": ["hd", "1080p", "720p", "high definition"],
    "SD": ["sd", "480p", "360p", "standard"],
    "AUDIO": ["radio", "audio only", "musik"],
}

# Default quality
DEFAULT_QUALITY = "HD"

# ============================================================================
# Channel Configuration
# ============================================================================

# Default channel settings
DEFAULT_CHANNEL_CONFIG = {
    "video": "best",
    "on_demand": True,
    "speed_up": True,
    "use_cdm": False,  # Will be set to True if DRM detected
    "cdm_mode": "external",
    "session_manifest": False,
    "mode": "live",
    "content_type": "LIVE",
}

# ============================================================================
# Caching Configuration
# ============================================================================

# Cache TTL in seconds (30 minutes default)
DEFAULT_CACHE_TTL = 1800

# Enable auto-refresh when cache expires
AUTO_REFRESH_ON_EXPIRE = True

# ============================================================================
# Validation Configuration
# ============================================================================

# Minimum required fields for a valid channel entry
REQUIRED_FIELDS = ["name", "manifest"]

# Skip channels without manifest URLs
SKIP_INVALID_CHANNELS = True

# Log warnings for channels with missing optional fields
WARN_MISSING_OPTIONAL_FIELDS = True

# ============================================================================
# Default Values
# ============================================================================

# Default country code
DEFAULT_COUNTRY = "XX"  # Unknown/International

# Default language code
DEFAULT_LANGUAGE = "und"  # Undetermined

# Default provider name for M3U channels
DEFAULT_PROVIDER_NAME = "m3u"

# ============================================================================
# User Agent Configuration
# ============================================================================

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/132.0.0.0 Safari/537.36"
)

# ============================================================================
# Request Configuration
# ============================================================================

# Default timeout for HTTP requests (seconds)
DEFAULT_REQUEST_TIMEOUT = 30

# Default maximum retries for failed requests
DEFAULT_MAX_RETRIES = 3