# streaming_providers/providers/scripts/constants.py
# ============================================================================
# Scripts Provider Configuration
# ============================================================================

# Scripts provider logo (generic script/plugin icon)
SCRIPTS_LOGO = "https://upload.wikimedia.org/wikipedia/commons/thumb/6/6a/Python-logo-notext.svg/240px-Python-logo-notext.svg.png"

# ============================================================================
# Exception Classes
# ============================================================================

class ScriptProviderError(Exception):
    """Base exception for script provider errors"""
    pass

class ScriptNotFoundError(ScriptProviderError):
    """Raised when a script file cannot be found"""
    pass

class ScriptTimeoutError(ScriptProviderError):
    """Raised when script execution times out"""
    pass

class ScriptExecutionError(ScriptProviderError):
    """Raised when script execution fails"""
    pass

class InvalidScriptOutputError(ScriptProviderError):
    """Raised when script output is invalid or malformed"""
    pass

class MissingActionError(ScriptProviderError):
    """Raised when script doesn't support required action"""
    pass

# ============================================================================
# Environment Variables
# ============================================================================

# Environment variable for scripts directory
# Similar to M3U_PLAYLISTS_PATH, this can be set to specify where provider scripts are located
# Example: SCRIPTS_PROVIDERS_PATH=/custom/scripts
ENV_SCRIPTS_PROVIDERS_PATH = "SCRIPTS_PROVIDERS_PATH"

# ============================================================================
# File Configuration
# ============================================================================

# Supported file extensions (only Python files)
SUPPORTED_EXTENSIONS = [".py"]

# Excluded filenames (don't treat as providers)
EXCLUDED_FILENAMES = [
    "__init__.py",
    "__pycache__",
    "constants.py",
    "provider.py",
    "base.py",
    "utils.py",
]

# Default encoding for script files
DEFAULT_ENCODING = "utf-8"

# ============================================================================
# Script Execution Configuration
# ============================================================================

# Default timeout for script execution in seconds
# Prevents hanging scripts from blocking the provider
DEFAULT_SCRIPT_TIMEOUT = 30

# Maximum output size in bytes (1MB limit)
# Prevents scripts from generating massive output
MAX_OUTPUT_SIZE = 1048576

# ============================================================================
# Action Types
# ============================================================================

# Valid actions a script must support
VALID_ACTIONS = ["channels", "manifest", "cdm"]

# Action that returns channel list
ACTION_CHANNELS = "channels"

# Action that returns manifest URL and headers
ACTION_MANIFEST = "manifest"

# Action that returns DRM keys
ACTION_CDM = "cdm"

# ============================================================================
# Channel Configuration
# ============================================================================

# Default channel settings for script-provided channels
DEFAULT_CHANNEL_CONFIG = {
    "video": "best",
    "on_demand": True,
    "speed_up": True,
    "use_cdm": False,  # Will be set to True if DRM config is provided
    "cdm_mode": "external",
    "session_manifest": True,  # Scripts typically provide manifest on demand
    "mode": "live",
    "content_type": "LIVE",
}

# Minimum required fields for a valid channel entry
REQUIRED_CHANNEL_FIELDS = ["Name", "ManifestScript"]

# Channel field mappings from script output to StreamingChannel
CHANNEL_FIELD_MAPPING = {
    "Name": "name",
    "Id": "channel_id",
    "Mode": "mode",
    "SessionManifest": "session_manifest",
    "ManifestScript": "manifest_script",
    "CdmType": "cdm_type",
    "UseCdm": "use_cdm",
    "Cdm": "cdm",
    "CdmMode": "cdm_mode",
    "Video": "video",
    "OnDemand": "on_demand",
    "SpeedUp": "speed_up",
    "LogoUrl": "logo_url",
    "ChannelNumber": "channel_number",
    "Quality": "quality",
    "ContentType": "content_type",
    "Country": "country",
    "Language": "language",
    "StreamingFormat": "streaming_format",
}

# ============================================================================
# Manifest Response Configuration
# ============================================================================

# Expected fields in manifest action response
REQUIRED_MANIFEST_FIELDS = ["ManifestUrl"]

# Optional manifest response fields
OPTIONAL_MANIFEST_FIELDS = ["Headers", "Heartbeat"]

# ============================================================================
# DRM/ClearKey Configuration
# ============================================================================

# DRM system mapping for script outputs
DRM_SYSTEM_MAPPING = {
    "widevine": "widevine",
    "playready": "playready",
    "clearkey": "clearkey",
    "fairplay": "fairplay",
    "wiseplay": "wiseplay",
}

# Default DRM system if not specified
DEFAULT_DRM_SYSTEM = "widevine"

# ============================================================================
# Caching Configuration
# ============================================================================

# Cache TTL in seconds for channels list (5 minutes default)
# Channels don't change frequently
CHANNELS_CACHE_TTL = 300

# Cache TTL in seconds for DRM keys (1 hour default)
# Keys are usually static or long-lived
CDM_CACHE_TTL = 3600

# Don't cache manifest responses (they're ephemeral)
CACHE_MANIFEST = False

# Enable auto-refresh when cache expires
AUTO_REFRESH_ON_EXPIRE = True

# ============================================================================
# Validation Configuration
# ============================================================================

# Skip channels with missing required fields
SKIP_INVALID_CHANNELS = True

# Log warnings for channels with missing optional fields
WARN_MISSING_OPTIONAL_FIELDS = True

# ============================================================================
# Default Values
# ============================================================================

# Default country code for scripts without country specification
DEFAULT_COUNTRY = "XX"  # Unknown/International

# Default language code
DEFAULT_LANGUAGE = "und"  # Undetermined

# Default provider name prefix
DEFAULT_PROVIDER_PREFIX = "script"

# ============================================================================
# Proxy Configuration
# ============================================================================

# Proxy argument format for scripts
PROXY_ARG_FORMAT = "--proxy={}"

# ============================================================================
# Error Messages
# ============================================================================

ERROR_SCRIPT_NOT_FOUND = "Script not found: {filename}"
ERROR_SCRIPT_TIMEOUT = "Script execution timed out after {timeout}s: {filename}"
ERROR_SCRIPT_FAILED = "Script execution failed (exit code {code}): {filename}"
ERROR_INVALID_JSON = "Script returned invalid JSON: {error}"
ERROR_MISSING_ACTION = "Script does not support action '{action}': {filename}"
ERROR_CHANNELS_MISSING_FIELD = "Channel missing required field '{field}': {name}"
ERROR_MANIFEST_MISSING_FIELD = "Manifest response missing required field '{field}'"
ERROR_CDM_INVALID_FORMAT = "Invalid CDM key format (expected KID:KEY hex pairs): {line}"