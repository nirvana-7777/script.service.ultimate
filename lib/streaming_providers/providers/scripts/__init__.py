# streaming_providers/providers/scripts/__init__.py
"""
Scripts Provider

A universal provider that executes Python scripts to provide streaming functionality.
Each script in the configured directory becomes a separate provider instance.

Features:
- Auto-discovers all Python scripts in SCRIPTS_PROVIDERS_PATH
- Each script must support actions: channels, manifest, cdm
- Caching for channels and DRM keys
- Subprocess execution with timeout
- Proxy support passed through to scripts
"""

import os
import re
from typing import Optional, List, Dict, Any

from .provider import ScriptsProvider

__all__ = ["ScriptsProvider"]

# Provider metadata for registration
PROVIDER_METADATA = {
    "name": "scripts",
    "label": "Scripts Provider",
    "description": "Universal script-based provider executor",
    "supports_countries": ["*"],  # All countries, scripts can handle country internally
    "requires_auth": False,  # Auth handled internally by scripts
    "supports_live": True,
    "supports_vod": True,  # Scripts can implement VOD
    "supports_radio": False,  # Usually TV channels
    "supports_drm": True,  # Scripts can return DRM keys
    "supports_catchup": False,  # Not implemented
    "supports_epg": False,  # Not implemented
    "formats": ["dash", "hls"],  # Scripts determine format
}


# Discovery function for dynamic provider registration
def discover_script_providers(config_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Discover all Python scripts and return metadata for provider registration

    This matches the pattern used by M3UProvider.discover_groups()

    Args:
        config_dir: Configuration directory path

    Returns:
        List of provider instance metadata dictionaries
    """
    from .provider import ScriptsProvider

    try:
        scripts = ScriptsProvider.discover_scripts(config_dir)
    except Exception as e:
        # If discovery fails, return empty list rather than crashing
        import logging
        logging.error(f"Failed to discover script providers: {e}")
        return []

    instances = []

    for script in scripts:
        # Clean name for provider identifier
        name = os.path.splitext(script)[0]
        clean_name = re.sub(r'[^a-z0-9_]+', '', name.lower())
        provider_name = clean_name if clean_name else "script"

        # Create readable label
        label = name.replace('_', ' ').title()

        instances.append({
            "plugin": provider_name,
            "script": script,
            "label": label,
            "country": "XX",  # Default country - scripts handle country via params
            "requires_country_suffix": False,  # Scripts handle country via params
            "provider_class": ScriptsProvider,
            "init_kwargs": {
                "script_filename": script,
            }
        })

    return instances