# lib/streaming_providers/__init__.py
import importlib
from typing import Dict, Type
import os
import sys

# Import the centralized logger
from .base.utils.logger import logger

AVAILABLE_PROVIDERS: Dict[str, Type] = {}


def _discover_providers():
    """Kodi-compatible provider discovery"""
    try:
        # Import the base provider class first
        from .base.provider import StreamingProvider

        # Get the current package path
        current_dir = os.path.dirname(__file__)
        providers_dir = os.path.join(current_dir, 'providers')

        logger.info(f"Looking for providers in: {providers_dir}")

        # Check if providers directory exists
        if not os.path.exists(providers_dir):
            logger.error(f"Providers directory does not exist: {providers_dir}")
            return

        # Add the lib directory to Python path if not already there
        lib_dir = os.path.dirname(current_dir)
        if lib_dir not in sys.path:
            sys.path.insert(0, lib_dir)
            logger.debug(f"Added lib directory to Python path: {lib_dir}")

        # Iterate through subdirectories in providers folder
        for item in os.listdir(providers_dir):
            provider_path = os.path.join(providers_dir, item)

            # Skip if not a directory or if it starts with __
            if not os.path.isdir(provider_path) or item.startswith('__'):
                continue

            # Check if __init__.py exists in the provider directory
            init_file = os.path.join(provider_path, '__init__.py')
            if not os.path.exists(init_file):
                logger.debug(f"No __init__.py found in {item}, skipping")
                continue

            try:
                logger.debug(f"Attempting to import provider: {item}")

                # Import the provider module using absolute import
                module_name = f'streaming_providers.providers.{item}'
                module = importlib.import_module(module_name)

                # Find provider classes in the module
                provider_found = False
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and
                            issubclass(attr, StreamingProvider) and
                            attr != StreamingProvider):
                        AVAILABLE_PROVIDERS[item] = attr
                        logger.info(f"Discovered provider: {item} -> {attr_name}")
                        provider_found = True
                        break

                if not provider_found:
                    logger.warning(f"No valid provider class found in {item}")

            except ImportError as e:
                logger.error(f"Could not import provider {item}: {e}")
                logger.debug(f"Python path: {sys.path}")
            except Exception as e:
                logger.error(f"Error processing provider {item}: {e}")

    except Exception as e:
        logger.error(f"Error during provider discovery: {e}")
        logger.debug(f"Current working directory: {os.getcwd()}")
        logger.debug(f"Python path: {sys.path}")


def get_configured_manager(country: str = 'de') -> 'ProviderManager':
    """
    Get manager with settings-aware providers

    Args:
        country: Default country code for providers without country detection (default: 'de')

    Returns:
        Configured ProviderManager instance with all detected providers
    """
    from .base.manager import ProviderManager
    from .base.settings.settings_manager import SettingsManager

    # Create manager
    manager = ProviderManager()

    # Initialize settings manager to detect providers
    settings_manager = SettingsManager(enable_kodi_integration=True)

    # Detect providers from Kodi (if available) or use all available providers
    detected_providers = None

    if settings_manager.kodi_bridge and settings_manager.kodi_bridge.is_kodi_environment():
        detected_providers = settings_manager.kodi_bridge.detect_all_providers_from_kodi()
        logger.info(f"Detected providers from Kodi: {detected_providers}")
    else:
        logger.info(f"Not in Kodi environment, will register all available providers with default country '{country}'")

    # Use the new discover_providers method with detected providers
    registered = manager.discover_providers(
        country=country,
        detected_providers=detected_providers
    )

    logger.info(f"Registered {len(registered)} providers: {registered}")

    return manager


# Initial discovery
_discover_providers()

__all__ = ['AVAILABLE_PROVIDERS', 'get_configured_manager']