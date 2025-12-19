# streaming_providers/base/settings/settings_manager.py
"""
Unified Settings Manager - Country-Aware Implementation
Supports country-specific credentials, sessions, and configurations
"""

import json
import time
import os
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path
from dataclasses import dataclass, field

from ..auth.session_manager import SessionManager
from ..auth.credential_manager import CredentialManager
from ..auth.credentials import BaseCredentials, ClientCredentials, UserPasswordCredentials
from ..network.proxy_manager import ProxyConfigManager
from ..models.proxy_models import ProxyConfig
from ..utils.logger import logger
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .kodi_settings_bridge import KodiSettingsBridge


@dataclass
class ProviderRegistration:
    """Information about a registered provider"""
    name: str
    registered_at: float = field(default_factory=time.time)
    is_active: bool = True
    settings_schema: Optional[Dict[str, Any]] = None
    supports_countries: bool = False  # NEW: Flag if provider supports country-specific settings
    available_countries: List[str] = field(default_factory=list)  # NEW: List of supported countries


# Maintain backward compatibility by keeping the original class name
UnifiedSettingsManager = None  # Will be set below for backward compatibility


class SettingsManager:
    """
    Unified interface for all streaming provider settings management.
    Now supports country-specific settings for multi-region providers.
    """

    def __init__(self, config_dir: Optional[str] = None, enable_kodi_integration: bool = True):
        """
        Initialize unified settings manager

        Args:
            config_dir: Optional config directory override
            enable_kodi_integration: Enable Kodi settings bridge integration
        """
        # Store config directory for component managers
        self.config_dir_path = config_dir

        # Initialize VFS for all file operations
        from ..utils.vfs import VFS
        self.vfs = VFS(config_dir=config_dir)

        # Maintain config_path for backward compatibility
        if config_dir:
            self.config_path = Path(config_dir)
        else:
            # Let VFS handle default path resolution, but provide Path object if needed
            self.config_path = Path(self.vfs.base_path) if self.vfs.base_path else None

        self.settings_file = 'unified_settings.json'

        # Initialize component managers - pass the original config_dir
        self.session_manager = SessionManager(self.config_dir_path)
        self.credential_manager = CredentialManager(self.config_dir_path)
        self.proxy_manager = ProxyConfigManager(self.config_dir_path)

        # Initialize Kodi integration if enabled
        self.enable_kodi_integration = enable_kodi_integration
        self.kodi_bridge: Optional['KodiSettingsBridge'] = None

        if enable_kodi_integration:
            success = self._setup_kodi_integration()
            if not success:
                self.kodi_bridge = None
                self.enable_kodi_integration = False

        # Provider registry
        self._registered_providers: Dict[str, ProviderRegistration] = {}

        # Load existing configuration
        self._load_configuration()

        # Perform Kodi sync if bridge is available and in Kodi environment
        if self.enable_kodi_integration and self.kodi_bridge and self.kodi_bridge.is_kodi_environment():
            logger.info("Performing initial sync from Kodi...")

            # First, detect all providers from Kodi (including unregistered ones)
            detected_providers = self.kodi_bridge.detect_all_providers_from_kodi()
            logger.info(f"Detected providers from Kodi: {detected_providers}")

            # Auto-register any unregistered providers
            for provider_name, countries in detected_providers.items():
                if not self.is_provider_registered(provider_name):
                    logger.info(f"Auto-registering provider '{provider_name}' from Kodi")
                    self.register_provider(
                        provider_name,
                        supports_countries=bool(countries),
                        available_countries=countries if countries else []
                    )
                else:
                    # Provider already registered - check if we need to upgrade to multi-country
                    if countries and not self.provider_supports_countries(provider_name):
                        logger.info(f"Auto-upgrading existing provider '{provider_name}' to multi-country: {countries}")
                        reg = self._registered_providers[provider_name]
                        reg.supports_countries = True
                        reg.available_countries = countries
                        self._save_configuration()

            # Now sync all registered providers
            for provider_name in self.list_registered_providers():
                # Check current registration status
                if self.provider_supports_countries(provider_name):
                    # Multi-country provider - sync each country
                    available_countries = self.get_provider_countries(provider_name)
                    logger.info(f"Syncing multi-country provider {provider_name} for countries: {available_countries}")

                    for country in available_countries:
                        logger.info(f"Syncing credentials for {provider_name} ({country})...")
                        self._sync_credentials_from_kodi(provider_name, country)

                        logger.info(f"Syncing proxy for {provider_name} ({country})...")
                        self._sync_proxy_from_kodi(provider_name, country)
                else:
                    # Single-country provider (backward compatibility)
                    logger.info(f"Syncing credentials for {provider_name}...")
                    self._sync_credentials_from_kodi(provider_name)

                    logger.info(f"Syncing proxy for {provider_name}...")
                    self._sync_proxy_from_kodi(provider_name)

        logger.info(f"Initialized SettingsManager with config dir: {self.config_dir_path}")

    def _setup_kodi_integration(self) -> bool:
        """Setup Kodi integration, return True if successful"""
        try:
            from .kodi_settings_bridge import KodiSettingsBridge
        except ImportError:
            logger.debug("KodiSettingsBridge not available")
            return False

        try:
            self.kodi_bridge = KodiSettingsBridge()
            if self.kodi_bridge and self.kodi_bridge.is_kodi_environment():
                logger.info("Kodi integration enabled")
                return True
            else:
                logger.debug("KodiSettingsBridge created but not in Kodi environment")
                self.kodi_bridge = None
                return False
        except Exception as e:
            logger.error(f"Failed to initialize Kodi bridge: {e}")
            self.kodi_bridge = None
            return False

    # ============= Internal Methods =============

    def _load_configuration(self) -> None:
        """Load settings manager configuration from file using VFS"""
        if not self.vfs.exists(self.settings_file):
            logger.debug("No unified settings file found, starting fresh")
            return

        try:
            data = self.vfs.read_json(self.settings_file)

            # Load provider registrations
            providers_data = data.get('providers', {})
            for provider_name, provider_info in providers_data.items():
                try:
                    registration = ProviderRegistration(
                        name=provider_name,
                        registered_at=provider_info.get('registered_at', time.time()),
                        is_active=provider_info.get('is_active', True),
                        settings_schema=provider_info.get('settings_schema'),
                        supports_countries=provider_info.get('supports_countries', False),
                        available_countries=provider_info.get('available_countries', [])
                    )
                    self._registered_providers[provider_name] = registration
                    logger.debug(f"Loaded provider registration: {provider_name} "
                                 f"(countries: {registration.supports_countries})")
                except Exception as e:
                    logger.error(f"Error loading provider {provider_name}: {e}")

            logger.info(f"Loaded {len(self._registered_providers)} provider registrations")

        except Exception as e:
            logger.error(f"Error loading unified settings configuration: {e}")

    def _save_configuration(self) -> bool:
        """Save settings manager configuration to file using VFS"""
        try:
            data = {
                'version': '2.1',  # Bumped version for country support
                'last_updated': time.time(),
                'kodi_integration_enabled': self.enable_kodi_integration,
                'providers': {}
            }

            # Save provider registrations
            for name, reg in self._registered_providers.items():
                data['providers'][name] = {
                    'registered_at': reg.registered_at,
                    'is_active': reg.is_active,
                    'settings_schema': reg.settings_schema,
                    'supports_countries': reg.supports_countries,
                    'available_countries': reg.available_countries
                }

            success = self.vfs.write_json(self.settings_file, data)
            if success:
                logger.debug("Successfully saved unified settings configuration")
            else:
                logger.error("Failed to save unified settings configuration")
            return success

        except Exception as e:
            logger.error(f"Error saving unified settings configuration: {e}")
            return False

    # ============= Authentication Manager Interface =============
    # These methods provide the clean interface that BaseAuthenticator expects

    def get_provider_credentials(self, provider_name: str, country: Optional[str] = None) -> Optional[BaseCredentials]:
        """
        Get credentials for a provider with optional country and automatic Kodi sync

        Args:
            provider_name: Name of the provider
            country: Optional country code (e.g., 'de', 'at', 'ch')

        Returns:
            BaseCredentials instance or None
        """
        country_str = f" (country: {country})" if country else ""
        logger.debug(f"SettingsManager: Loading credentials for '{provider_name}{country_str}'")

        # Try file-based credentials first
        credentials = self.credential_manager.load_credentials(provider_name, country)
        logger.debug(f"SettingsManager: File credentials result: {type(credentials)}")

        if credentials:
            logger.debug(f"SettingsManager: File credentials type: {credentials.credential_type}")
            if hasattr(credentials, 'username'):
                logger.debug(f"SettingsManager: File credentials username: {credentials.username}")
            else:
                logger.debug(f"SettingsManager: File credentials class: {credentials.__class__.__name__}")
        else:
            logger.debug(f"SettingsManager: No file credentials found for {provider_name}{country_str}")

        # If no file credentials and Kodi is available, try syncing from Kodi
        if not credentials and self.kodi_bridge and self.kodi_bridge.is_kodi_environment():
            logger.debug(f"SettingsManager: No file credentials for {provider_name}{country_str}, trying Kodi sync")
            if self._sync_credentials_from_kodi(provider_name, country):
                credentials = self.credential_manager.load_credentials(provider_name, country)
                logger.debug(f"SettingsManager: After Kodi sync, credentials: {type(credentials)}")
                if credentials:
                    logger.debug(f"SettingsManager: Synced credentials type: {credentials.credential_type}")

        logger.debug(f"SettingsManager: Final credentials for {provider_name}{country_str}: {credentials is not None}")
        return credentials

    def save_provider_credentials(self, provider_name: str, credentials: BaseCredentials,
                                  country: Optional[str] = None) -> bool:
        """
        Save credentials for a provider to both file and optionally Kodi

        Args:
            provider_name: Name of the provider
            credentials: Credentials to save
            country: Optional country code

        Returns:
            True if successful, False otherwise
        """
        # Save to file first
        file_success = self.credential_manager.save_credentials(provider_name, credentials, country)

        if not file_success:
            country_str = f" (country: {country})" if country else ""
            logger.error(f"Failed to save credentials to file for {provider_name}{country_str}")
            return False

        # Sync to Kodi if available and in Kodi environment
        if self.kodi_bridge and self.kodi_bridge.is_kodi_environment():
            kodi_success = self.kodi_bridge.write_credentials_to_kodi(provider_name, credentials, country)
            if not kodi_success:
                logger.warning(f"Failed to sync credentials to Kodi for {provider_name}")
                # Don't fail the entire operation if Kodi sync fails

        return True

    def load_token_data(self, provider_name: str, country: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Load token data for a provider

        Args:
            provider_name: Name of the provider
            country: Optional country code

        Returns:
            Dictionary with token data or None
        """
        return self.session_manager.load_token_data(provider_name, country)

    def save_token_data(self, provider_name: str, token_data: Dict[str, Any],
                        country: Optional[str] = None) -> bool:
        """
        Save token data for a provider

        Args:
            provider_name: Name of the provider
            token_data: Token data to save
            country: Optional country code

        Returns:
            True if successful, False otherwise
        """
        return self.session_manager.save_session(provider_name, token_data, country)

    def get_device_id(self, provider_name: str, country: Optional[str] = None) -> str:
        """
        Get or generate device ID for a provider

        Args:
            provider_name: Name of the provider
            country: Optional country code

        Returns:
            Device ID string
        """
        return self.session_manager.get_device_id(provider_name, country)

    def clear_token(self, provider_name: str, country: Optional[str] = None) -> bool:
        """
        Clear token data for a provider

        Args:
            provider_name: Name of the provider
            country: Optional country code

        Returns:
            True if successful, False otherwise
        """
        return self.session_manager.clear_token(provider_name, country)

    # ============= Provider Management =============

    def register_provider(self, provider_name: str, settings_schema: Optional[Dict[str, Any]] = None,
                          supports_countries: bool = False,
                          available_countries: Optional[List[str]] = None) -> bool:
        """
        Register a provider with the settings manager

        Args:
            provider_name: Name of the provider to register
            settings_schema: DEPRECATED - no longer used (kept for backward compatibility)
            supports_countries: Whether this provider supports country-specific settings
            available_countries: List of supported country codes (e.g., ['de', 'at', 'ch'])

        Returns:
            True if successful, False otherwise
        """
        try:
            registration = ProviderRegistration(
                name=provider_name,
                is_active=True,
                settings_schema=settings_schema,  # Keep for backward compat, but not used
                supports_countries=supports_countries,
                available_countries=available_countries or []
            )

            self._registered_providers[provider_name] = registration

            # Schema registration is no longer needed - Kodi bridge uses convention
            # if self.kodi_bridge:
            #     self.kodi_bridge.register_provider_schema(provider_name, settings_schema)  # ← REMOVED

            # Save configuration
            success = self._save_configuration()
            if success:
                country_info = f" (supports countries: {available_countries})" if supports_countries else ""
                logger.info(f"Successfully registered provider: {provider_name}{country_info}")
            return success

        except Exception as e:
            logger.error(f"Error registering provider {provider_name}: {e}")
            return False

    def unregister_provider(self, provider_name: str, cleanup_data: bool = False) -> bool:
        """
        Unregister a provider and optionally clean up its data

        Args:
            provider_name: Name of the provider to unregister
            cleanup_data: Whether to delete all data for this provider

        Returns:
            True if successful, False otherwise
        """
        if provider_name not in self._registered_providers:
            logger.warning(f"Provider {provider_name} is not registered")
            return True

        try:
            # Cleanup data if requested
            if cleanup_data:
                # Clear all country data if provider supports countries
                reg = self._registered_providers[provider_name]
                if reg.supports_countries:
                    for country in reg.available_countries:
                        self.credential_manager.delete_credentials(provider_name, country)
                        self.session_manager.clear_session(provider_name, country)
                        self.proxy_manager.remove_proxy_config(provider_name, country)
                else:
                    # Clear non-country-specific data
                    self.credential_manager.delete_credentials(provider_name)
                    self.session_manager.clear_session(provider_name)
                    self.proxy_manager.remove_proxy_config(provider_name)

            # Remove from registry
            del self._registered_providers[provider_name]

            # Save configuration
            success = self._save_configuration()
            if success:
                logger.info(f"Successfully unregistered provider: {provider_name}")
            return success

        except Exception as e:
            logger.error(f"Error unregistering provider {provider_name}: {e}")
            return False

    def list_registered_providers(self) -> List[str]:
        """Get list of all registered providers"""
        return [name for name, reg in self._registered_providers.items() if reg.is_active]

    def is_provider_registered(self, provider_name: str) -> bool:
        """Check if a provider is registered"""
        return provider_name in self._registered_providers and self._registered_providers[provider_name].is_active

    def get_provider_countries(self, provider_name: str) -> List[str]:
        """
        Get list of available countries for a provider

        Args:
            provider_name: Name of the provider

        Returns:
            List of country codes, empty if provider doesn't support countries
        """
        if provider_name not in self._registered_providers:
            return []

        reg = self._registered_providers[provider_name]
        return reg.available_countries if reg.supports_countries else []

    def provider_supports_countries(self, provider_name: str) -> bool:
        """
        Check if a provider supports country-specific settings

        Args:
            provider_name: Name of the provider

        Returns:
            True if provider supports countries, False otherwise
        """
        if provider_name not in self._registered_providers:
            return False

        return self._registered_providers[provider_name].supports_countries

    # ============= Configuration Status =============

    def get_provider_status(self, provider_name: str, country: Optional[str] = None) -> Dict[str, Any]:
        """
        Get comprehensive status for a provider

        Args:
            provider_name: Name of the provider
            country: Optional country code

        Returns:
            Dictionary with provider status information
        """
        if not self.is_provider_registered(provider_name):
            return {
                'provider_name': provider_name,
                'country': country,
                'is_registered': False,
                'is_enabled': self.is_provider_enabled(provider_name, country),
                'error': 'Provider not registered'
            }

        registration = self._registered_providers[provider_name]

        # Check credential status
        credentials = self.get_provider_credentials(provider_name, country)
        has_credentials = credentials is not None
        credentials_valid = credentials.validate() if credentials else False

        # Check session status
        token_data = self.load_token_data(provider_name, country)
        has_active_session = token_data is not None

        # Check proxy status
        proxy_config = self.proxy_manager.get_proxy_config(provider_name, country)
        has_proxy = proxy_config is not None

        status = {
            'provider_name': provider_name,
            'country': country,
            'is_registered': True,
            'is_enabled': self.is_provider_enabled(provider_name, country),
            'registered_at': registration.registered_at,
            'supports_countries': registration.supports_countries,
            'credentials': {
                'has_credentials': has_credentials,
                'credentials_valid': credentials_valid,
                'credential_type': credentials.credential_type if credentials else None
            },
            'session': {
                'has_active_session': has_active_session,
                'device_id': self.get_device_id(provider_name, country)
            },
            'proxy': {
                'has_proxy': has_proxy,
                'proxy_enabled': has_proxy
            },
            'kodi_integration': {
                'enabled': self.enable_kodi_integration,
                'environment': self.kodi_bridge.is_kodi_environment() if self.kodi_bridge else False
            }
        }

        # Add country-specific info if applicable
        if registration.supports_countries:
            status['available_countries'] = registration.available_countries

            # Get session data for all countries
            all_countries = self.session_manager.get_all_countries(provider_name)
            status['configured_countries'] = all_countries

        scoped_tokens = {}
        available_scopes = self.list_scoped_tokens(provider_name, country)

        for scope in available_scopes:
            scope_status = self.get_scoped_token_status(provider_name, scope, country)
            scoped_tokens[scope] = scope_status

        if scoped_tokens:
            status['scoped_tokens'] = scoped_tokens

        return status

    def is_provider_ready(self, provider_name: str, country: Optional[str] = None) -> bool:
        """
        Check if provider is fully configured and ready to use

        Args:
            provider_name: Name of the provider
            country: Optional country code

        Returns:
            True if ready, False otherwise
        """
        status = self.get_provider_status(provider_name, country)

        if not status.get('is_registered'):
            return False

        # Provider is ready if it has valid credentials
        credentials_status = status.get('credentials', {})
        return credentials_status.get('has_credentials', False) and credentials_status.get('credentials_valid', False)

    def get_ready_providers(self, country: Optional[str] = None) -> List[str]:
        """
        Get list of providers that are fully configured and ready

        Args:
            country: Optional country code to check

        Returns:
            List of provider names
        """
        ready = []
        for provider_name in self.list_registered_providers():
            if self.is_provider_ready(provider_name, country):
                ready.append(provider_name)
        return ready

    # ============= Kodi Integration =============

    def _sync_credentials_from_kodi(self, provider_name: str, country: Optional[str] = None) -> bool:
        """
        Sync credentials from Kodi for a single provider

        Args:
            provider_name: Name of the provider
            country: Optional country code

        Returns:
            True if successful or no sync needed, False on error
        """
        country_str = f" (country: {country})" if country else ""
        logger.debug(f"SettingsManager: Attempting Kodi sync for {provider_name}{country_str}")

        if not self.kodi_bridge or not self.kodi_bridge.is_kodi_environment():
            logger.debug(f"SettingsManager: Kodi bridge not available for {provider_name}{country_str}")
            return False

        try:
            kodi_credentials = self.kodi_bridge.read_credentials_from_kodi(provider_name, country)
            logger.debug(f"SettingsManager: Kodi credentials result: {type(kodi_credentials)}")

            if not kodi_credentials:
                logger.debug(f"SettingsManager: No Kodi credentials found for {provider_name}{country_str}")
                return True  # Not an error

            if not kodi_credentials.validate():
                logger.debug(f"SettingsManager: Invalid Kodi credentials for {provider_name}{country_str}")
                return True  # Not an error

            # Check if different from current file credentials
            file_credentials = self.credential_manager.load_credentials(provider_name, country)

            # ← FIX: Only skip if BOTH exist AND are equal
            if file_credentials and self._credentials_equal(kodi_credentials, file_credentials):
                logger.debug(f"SettingsManager: Credentials already in sync for {provider_name}{country_str}")
                return True

            # Save Kodi credentials to file
            logger.info(f"SettingsManager: Saving credentials from Kodi for {provider_name}{country_str}")
            success = self.credential_manager.save_credentials(provider_name, kodi_credentials, country)
            logger.debug(f"SettingsManager: Kodi sync save result: {success}")

            if success:
                logger.info(f"Synced credentials from Kodi for {provider_name}{country_str}")
            return success

        except Exception as e:
            logger.error(f"Error syncing credentials from Kodi for {provider_name}{country_str}: {e}")
            return False

    def sync_all_from_kodi(self) -> Dict[str, bool]:
        """
        Sync all provider settings from Kodi (both single and multi-country)

        Returns:
            Dictionary mapping provider names (or provider_country) to sync success status
        """
        if not self.kodi_bridge or not self.kodi_bridge.is_kodi_environment():
            logger.debug("Not in Kodi environment, skipping sync")
            return {}

        results = {}

        # Detect all providers from Kodi
        detected_providers = self.kodi_bridge.detect_all_providers_from_kodi()

        for provider_name, countries in detected_providers.items():
            # Auto-register if not registered
            if not self.is_provider_registered(provider_name):
                self.register_provider(
                    provider_name,
                    supports_countries=bool(countries),
                    available_countries=countries if countries else []
                )

            # Sync based on whether it's multi-country or not
            if countries:
                # Multi-country provider
                for country in countries:
                    cred_success = self._sync_credentials_from_kodi(provider_name, country)
                    proxy_success = self._sync_proxy_from_kodi(provider_name, country)
                    results[f"{provider_name}_{country}"] = cred_success or proxy_success
            else:
                # Single provider
                cred_success = self._sync_credentials_from_kodi(provider_name)
                proxy_success = self._sync_proxy_from_kodi(provider_name)
                results[provider_name] = cred_success or proxy_success

        return results

    @staticmethod
    def _credentials_equal(cred1: Optional[BaseCredentials], cred2: Optional[BaseCredentials]) -> bool:
        """Compare two credentials for equality"""
        if cred1 is None and cred2 is None:
            return True
        if cred1 is None or cred2 is None:
            return False
        if type(cred1) != type(cred2):
            return False

        # Use the credential objects' own comparison logic if available
        if hasattr(cred1, '__eq__'):
            return cred1 == cred2

        # Fallback to basic attribute comparison
        return getattr(cred1, '__dict__', {}) == getattr(cred2, '__dict__', {})

    # ============= Proxy Configuration =============

    def get_provider_proxy(self, provider_name: str, country: Optional[str] = None) -> Optional[ProxyConfig]:
        """Get proxy configuration for a provider with Kodi sync"""
        # Try proxy manager first
        proxy_config = self.proxy_manager.get_proxy_config(provider_name, country)

        # If no proxy config and Kodi available, sync from Kodi
        if not proxy_config and self.kodi_bridge and self.kodi_bridge.is_kodi_environment():
            if self._sync_proxy_from_kodi(provider_name, country):
                proxy_config = self.proxy_manager.get_proxy_config(provider_name, country)

        return proxy_config

    def _sync_proxy_from_kodi(self, provider_name: str, country: Optional[str] = None) -> bool:
        """Sync proxy config from Kodi to proxy manager"""
        if not self.kodi_bridge:
            return False

        kodi_proxy_config = self.kodi_bridge.read_proxy_config_from_kodi(provider_name, country)
        if kodi_proxy_config:
            return self.proxy_manager.set_proxy_config(provider_name, kodi_proxy_config, country)
        return False

    def set_provider_proxy(self, provider_name: str, proxy_config: ProxyConfig,
                           country: Optional[str] = None) -> bool:
        """Set proxy configuration for a provider with Kodi sync"""
        success = self.proxy_manager.set_proxy_config(provider_name, proxy_config, country)

        # Also sync to Kodi if available
        if success and self.kodi_bridge and self.kodi_bridge.is_kodi_environment():
            self.kodi_bridge.write_proxy_config_to_kodi(provider_name, proxy_config, country)

        return success

    def remove_provider_proxy(self, provider_name: str, country: Optional[str] = None) -> bool:
        """Remove proxy configuration for a provider"""
        return self.proxy_manager.remove_proxy_config(provider_name, country)

    # ============= Session Management =============

    def clear_provider_session(self, provider_name: str, country: Optional[str] = None) -> bool:
        """Clear all session data for a provider"""
        return self.session_manager.clear_session(provider_name, country)

    def get_provider_session_info(self, provider_name: str, country: Optional[str] = None) -> Dict[str, Any]:
        """Get session information for a provider"""
        session_data = self.session_manager.load_session(provider_name, country)

        if not session_data:
            return {
                'provider_name': provider_name,
                'country': country,
                'has_session': False
            }

        return {
            'provider_name': provider_name,
            'country': country,
            'has_session': True,
            'device_id': session_data.get('device_id'),
            'has_token': 'access_token' in session_data,
            'token_expires_in': session_data.get('expires_in'),
            'token_issued_at': session_data.get('issued_at')
        }

    # ============= Bulk Operations =============

    def reset_provider(self, provider_name: str,
                       reset_credentials: bool = True,
                       reset_session: bool = True,
                       reset_proxy: bool = True,
                       country: Optional[str] = None) -> bool:
        """
        Reset various data for a provider

        Args:
            provider_name: Name of the provider
            reset_credentials: Reset stored credentials
            reset_session: Reset session data (tokens, device ID)
            reset_proxy: Reset proxy configuration
            country: Optional country code (if None, resets all countries for multi-country providers)

        Returns:
            True if successful, False otherwise
        """
        if not self.is_provider_registered(provider_name):
            logger.error(f"Provider {provider_name} is not registered")
            return False

        success = True

        try:
            # If provider supports countries and no specific country given, reset all
            if country is None and self.provider_supports_countries(provider_name):
                countries = self.get_provider_countries(provider_name)
                for ctry in countries:
                    if reset_credentials:
                        self.credential_manager.delete_credentials(provider_name, ctry)
                    if reset_session:
                        self.session_manager.clear_session(provider_name, ctry)
                    if reset_proxy:
                        self.proxy_manager.remove_proxy_config(provider_name, ctry)
                logger.info(f"Reset all countries for {provider_name}")
            else:
                # Reset specific country or non-country provider
                if reset_credentials:
                    self.credential_manager.delete_credentials(provider_name, country)
                    logger.info(f"Reset credentials for {provider_name}" +
                                (f" ({country})" if country else ""))

                if reset_session:
                    self.session_manager.clear_session(provider_name, country)
                    logger.info(f"Reset session for {provider_name}" +
                                (f" ({country})" if country else ""))

                if reset_proxy:
                    self.proxy_manager.remove_proxy_config(provider_name, country)
                    logger.info(f"Reset proxy config for {provider_name}" +
                                (f" ({country})" if country else ""))

        except Exception as e:
            logger.error(f"Error resetting provider {provider_name}: {e}")
            success = False

        return success

    def export_provider_settings(self, provider_name: str, country: Optional[str] = None) -> Dict[str, Any]:
        """
        Export all settings for a single provider

        Args:
            provider_name: Name of the provider
            country: Optional country code

        Returns:
            Dictionary with all provider settings
        """
        if not self.is_provider_registered(provider_name):
            return {'error': 'Provider not registered'}

        export_data: Dict[str, Any] = {
            'provider_name': provider_name,
            'country': country,
            'exported_at': time.time(),
            'registration': self._registered_providers[provider_name].__dict__,
            'status': self.get_provider_status(provider_name, country)
        }

        # Export credentials (without sensitive data)
        credentials = self.get_provider_credentials(provider_name, country)
        if credentials:
            cred_export = credentials.__dict__.copy()
            # Mask sensitive fields
            for cred_field in ['password', 'client_secret']:
                if cred_field in cred_export:
                    cred_export[cred_field] = '***MASKED***'
            export_data['credentials'] = cred_export

        # Export proxy config
        proxy_config = self.get_provider_proxy(provider_name, country)
        if proxy_config:
            export_data['proxy'] = proxy_config.to_dict()

        # Export session info (without tokens)
        session_info = self.get_provider_session_info(provider_name, country)
        export_data['session'] = session_info

        # If provider supports countries, export all countries
        if country is None and self.provider_supports_countries(provider_name):
            countries_data = {}
            for ctry in self.get_provider_countries(provider_name):
                countries_data[ctry] = self.export_provider_settings(provider_name, ctry)
            export_data['countries'] = countries_data

        return export_data

    def export_all_settings(self, export_path: Optional[str] = None) -> str:
        """
        Export all settings to a file

        Args:
            export_path: Optional path for export file

        Returns:
            Path to exported file
        """
        if not export_path:
            timestamp = int(time.time())
            # Use config_path for backward compatibility
            if self.config_path:
                export_path = str(self.config_path / f'settings_export_{timestamp}.json')
            else:
                export_path = f'settings_export_{timestamp}.json'

        export_data: Dict[str, Any] = {
            'metadata': {
                'exported_at': time.time(),
                'version': '2.1',
                'source': 'unified_settings_manager_v2.1_country_aware'
            },
            'system_info': {
                'config_dir': str(self.config_path) if self.config_path else 'default_vfs_path',
                'kodi_integration_enabled': self.enable_kodi_integration,
                'registered_provider_count': len(self._registered_providers)
            },
            'providers': {}
        }

        # Export each provider
        for provider_name in self.list_registered_providers():
            export_data['providers'][provider_name] = self.export_provider_settings(provider_name)

        # Write to file - use standard filesystem for exports (not VFS)
        with open(export_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)

        logger.info(f"Exported all settings to: {export_path}")
        return export_path

    # ============= System Information =============

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""

        # Handle config directory status safely - use config_path for backward compatibility
        if self.config_path:
            config_status = {
                'path': str(self.config_path),
                'exists': self.config_path.exists(),
                'writable': os.access(str(self.config_path), os.W_OK) if self.config_path.exists() else False
            }
        else:
            config_status = {
                'path': 'default_vfs_path',
                'exists': 'unknown',
                'writable': 'unknown'
            }

        return {
            'config_directory': config_status,
            'providers': {
                'registered': len(self._registered_providers),
                'active': len(self.list_registered_providers()),
                'ready': len(self.get_ready_providers()),
                'country_aware': sum(1 for reg in self._registered_providers.values() if reg.supports_countries)
            },
            'kodi_integration': {
                'enabled': self.enable_kodi_integration,
                'bridge_available': self.kodi_bridge is not None,
                'in_kodi_environment': self.kodi_bridge.is_kodi_environment() if self.kodi_bridge else False
            },
            'storage': {
                'credential_providers': len(self.credential_manager.list_providers()),
                'proxy_configs': len(self.proxy_manager.list_proxy_configs())
            }
        }

    def debug_provider(self, provider_name: str, country: Optional[str] = None) -> Dict[str, Any]:
        """
        Get detailed debug information for a provider

        Args:
            provider_name: Name of the provider
            country: Optional country code

        Returns:
            Dictionary with debug information
        """
        debug_info: Dict[str, Any] = {
            'provider_name': provider_name,
            'country': country,
            'timestamp': time.time()
        }

        # Registration info
        if provider_name in self._registered_providers:
            reg = self._registered_providers[provider_name]
            debug_info['registration'] = {
                'is_registered': True,
                'registered_at': reg.registered_at,
                'is_active': reg.is_active,
                'has_schema': reg.settings_schema is not None,
                'supports_countries': reg.supports_countries,
                'available_countries': reg.available_countries
            }
        else:
            debug_info['registration'] = {'is_registered': False}

        # File system checks - use config_path for backward compatibility
        if self.config_path:
            debug_info['filesystem'] = {
                'config_dir_exists': self.config_path.exists(),
                'config_dir_writable': os.access(str(self.config_path), os.W_OK) if self.config_path.exists() else False
            }
        else:
            debug_info['filesystem'] = {
                'config_dir_exists': 'using_vfs_default',
                'config_dir_writable': 'using_vfs_default'
            }

        # Component manager status
        debug_info['components'] = {
            'credential_manager': {
                'has_credentials': provider_name in self.credential_manager.list_providers()
            },
            'session_manager': {
                'has_session': self.session_manager.load_session(provider_name, country) is not None,
                'device_id': self.session_manager.get_device_id(provider_name, country),
                'all_countries': self.session_manager.get_all_countries(provider_name)
            },
            'proxy_manager': {
                'has_proxy': provider_name in self.proxy_manager.list_proxy_configs()
            }
        }

        # Kodi integration status
        if self.kodi_bridge:
            debug_info['kodi'] = {
                'bridge_available': True,
                'in_environment': self.kodi_bridge.is_kodi_environment(),
                'provider_test': self.kodi_bridge.test_provider_connectivity(provider_name) if hasattr(
                    self.kodi_bridge, 'test_provider_connectivity') else 'test_unavailable'
            }
        else:
            debug_info['kodi'] = {'bridge_available': False}

        return debug_info

    # ============= Country-Specific Helper Methods =============

    def get_credential_info(self, provider_name: str, country: Optional[str] = None) -> Dict[str, Any]:
        """
        Get information about credentials for a provider

        Args:
            provider_name: Name of the provider
            country: Optional country code

        Returns:
            Dictionary with credential information
        """
        credentials = self.get_provider_credentials(provider_name, country)

        return {
            'provider_name': provider_name,
            'country': country,
            'has_credentials': credentials is not None,
            'credentials_valid': credentials.validate() if credentials else False,
            'credential_type': credentials.credential_type if credentials else None,
            'source': 'file'  # Could be extended to track source
        }

    def list_provider_countries_with_data(self, provider_name: str) -> List[str]:
        """
        Get list of countries that actually have session/credential data for a provider

        Args:
            provider_name: Name of the provider

        Returns:
            List of country codes with data
        """
        if not self.provider_supports_countries(provider_name):
            return []

        # Get countries with session data
        return self.session_manager.get_all_countries(provider_name)

    def migrate_to_country_structure(self, provider_name: str, default_country: str) -> bool:
        """
        Migrate a non-country provider to country-aware structure

        Args:
            provider_name: Name of the provider
            default_country: Country code to migrate existing data to (e.g., 'de')

        Returns:
            True if successful, False otherwise
        """
        if not self.is_provider_registered(provider_name):
            logger.error(f"Provider {provider_name} is not registered")
            return False

        if self.provider_supports_countries(provider_name):
            logger.warning(f"Provider {provider_name} already supports countries")
            return True

        try:
            logger.info(f"Migrating {provider_name} to country structure with default: {default_country}")

            # Load existing non-country data
            old_credentials = self.credential_manager.load_credentials(provider_name)
            old_session = self.session_manager.load_session(provider_name)
            old_proxy = self.proxy_manager.get_proxy_config(provider_name)

            # Save to country-specific locations
            if old_credentials:
                self.credential_manager.save_credentials(provider_name, old_credentials, default_country)
                logger.debug(f"Migrated credentials to {default_country}")

            if old_session:
                self.session_manager.save_session(provider_name, old_session, default_country)
                logger.debug(f"Migrated session to {default_country}")

            if old_proxy:
                self.proxy_manager.set_proxy_config(provider_name, old_proxy, default_country)
                logger.debug(f"Migrated proxy to {default_country}")

            # Clear old non-country data
            self.credential_manager.delete_credentials(provider_name, None)
            self.session_manager.clear_session(provider_name, None)
            self.proxy_manager.remove_proxy_config(provider_name, None)

            # Update registration
            reg = self._registered_providers[provider_name]
            reg.supports_countries = True
            reg.available_countries = [default_country]
            self._save_configuration()

            logger.info(f"Successfully migrated {provider_name} to country structure")
            return True

        except Exception as e:
            logger.error(f"Error migrating {provider_name} to country structure: {e}")
            return False

    # ============= Scoped Token Management (Pass-through to SessionManager) =============

    def save_scoped_token(self, provider_name: str, scope: str, token_data: Dict[str, Any],
                          country: Optional[str] = None) -> bool:
        """
        Save authentication token for a specific scope

        Pass-through method to SessionManager.save_scoped_token()

        Args:
            provider_name: Name of the provider
            scope: Token scope (e.g., 'tvhubs', 'taa', 'yo_digital')
            token_data: Token data to save (should include access_token, expires_in, etc.)
            country: Optional country code

        Returns:
            True if successful, False otherwise

        Examples:
            # Save tvhubs token (access token only)
            settings_manager.save_scoped_token('magenta2', 'tvhubs', {
                'access_token': '...',
                'token_type': 'Bearer',
                'expires_in': 7200,
                'issued_at': 1234567890
            }, 'de')

            # Save yo_digital token (access + refresh, each with own expiry)
            settings_manager.save_scoped_token('magenta2', 'yo_digital', {
                'access_token': '...',
                'access_token_expires_in': 3600,
                'access_token_issued_at': 1234567890,
                'refresh_token': '...',
                'refresh_token_expires_in': 86400,
                'refresh_token_issued_at': 1234567890,
                'token_type': 'Bearer'
            }, 'de')
        """
        return self.session_manager.save_scoped_token(provider_name, scope, token_data, country)

    def load_scoped_token(self, provider_name: str, scope: str,
                          country: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Load token data for a specific scope

        Pass-through method to SessionManager.load_scoped_token()

        Args:
            provider_name: Name of the provider
            scope: Token scope (e.g., 'tvhubs', 'taa', 'yo_digital')
            country: Optional country code

        Returns:
            Token data dictionary or None if not found or expired

        Note:
            This method checks token expiration automatically.
            For yo_digital tokens, it checks both access_token and refresh_token expiry.
        """
        return self.session_manager.load_scoped_token(provider_name, scope, country)

    def clear_scoped_token(self, provider_name: str, scope: str,
                           country: Optional[str] = None) -> bool:
        """
        Clear token for a specific scope

        Pass-through method to SessionManager.clear_scoped_token()

        Args:
            provider_name: Name of the provider
            scope: Token scope to clear
            country: Optional country code

        Returns:
            True if successful, False otherwise

        Example:
            # Clear only the tvhubs token, keep taa and yo_digital
            settings_manager.clear_scoped_token('magenta2', 'tvhubs', 'de')
        """
        return self.session_manager.clear_scoped_token(provider_name, scope, country)

    def list_scoped_tokens(self, provider_name: str, country: Optional[str] = None) -> List[str]:
        """
        List all available token scopes for a provider

        Args:
            provider_name: Name of the provider
            country: Optional country code

        Returns:
            List of scope names (e.g., ['tvhubs', 'taa', 'yo_digital'])

        Example:
            scopes = settings_manager.list_scoped_tokens('magenta2', 'de')
            # Returns: ['tvhubs', 'taa', 'yo_digital']
        """
        session_data = self.session_manager.load_session(provider_name, country)
        if not session_data:
            return []

        # Filter out non-scope keys (device_id, refresh_token at provider level)
        non_scope_keys = {'device_id', 'refresh_token'}
        scopes = [
            key for key in session_data.keys()
            if isinstance(session_data[key], dict) and key not in non_scope_keys
        ]

        return scopes

    def get_scoped_token_status(self, provider_name: str, scope: str,
                                country: Optional[str] = None) -> Dict[str, Any]:
        """
        Get detailed status information for a scoped token

        Args:
            provider_name: Name of the provider
            scope: Token scope
            country: Optional country code

        Returns:
            Dictionary with token status information

        Example:
            status = settings_manager.get_scoped_token_status('magenta2', 'yo_digital', 'de')
            # Returns:
            # {
            #     'exists': True,
            #     'access_token_valid': True,
            #     'access_token_expires_at': 1234567890,
            #     'refresh_token_valid': True,
            #     'refresh_token_expires_at': 1234654290,
            #     'scope': 'yo_digital'
            # }
        """
        token_data = self.load_scoped_token(provider_name, scope, country)

        if not token_data:
            return {
                'exists': False,
                'scope': scope,
                'provider_name': provider_name,
                'country': country
            }

        status = {
            'exists': True,
            'scope': scope,
            'provider_name': provider_name,
            'country': country,
            'token_type': token_data.get('token_type', 'Bearer')
        }

        # Check access token expiration
        if 'access_token' in token_data:
            status['has_access_token'] = True

            # Standard expiration (single expires_in and issued_at)
            if 'expires_in' in token_data and 'issued_at' in token_data:
                expires_at = token_data['issued_at'] + token_data['expires_in']
                status['access_token_expires_at'] = expires_at
                status['access_token_valid'] = time.time() < expires_at

            # yo_digital style (separate access_token_expires_in)
            elif 'access_token_expires_in' in token_data and 'access_token_issued_at' in token_data:
                expires_at = token_data['access_token_issued_at'] + token_data['access_token_expires_in']
                status['access_token_expires_at'] = expires_at
                status['access_token_valid'] = time.time() < expires_at
            else:
                status['access_token_valid'] = None  # Cannot determine

        # Check refresh token expiration (for yo_digital)
        if 'refresh_token' in token_data:
            status['has_refresh_token'] = True

            if 'refresh_token_expires_in' in token_data and 'refresh_token_issued_at' in token_data:
                expires_at = token_data['refresh_token_issued_at'] + token_data['refresh_token_expires_in']
                status['refresh_token_expires_at'] = expires_at
                status['refresh_token_valid'] = time.time() < expires_at
            else:
                status['refresh_token_valid'] = None  # Cannot determine

        return status

    def is_provider_enabled(self, provider_name: str, country: Optional[str] = None) -> bool:
        """Check if provider is enabled (using ProviderEnableManager)"""
        # Import here to avoid circular imports
        from .provider_enable_manager import ProviderEnableManager

        enable_manager = ProviderEnableManager(self.config_dir_path)

        # Handle country parameter if provider_name doesn't have suffix
        if country and '_' not in provider_name:
            provider_to_check = f"{provider_name}_{country}"
        else:
            provider_to_check = provider_name

        return enable_manager.is_provider_enabled(provider_to_check)

    # ============= API Import Methods =============

    @staticmethod
    def parse_provider_country(provider_name: str) -> Tuple[str, Optional[str]]:
        """
        Parse provider_country format into (provider, country)

        Examples:
            "joyn_de" → ("joyn", "de")
            "magenta2_de" → ("magenta2", "de")
            "some_provider" → ("some_provider", None)

        Args:
            provider_name: Combined provider name like "joyn_de" or plain "provider"

        Returns:
            Tuple of (provider, country) where country may be None
        """
        # Split by last underscore
        parts = provider_name.rsplit('_', 1)

        # Check if last part looks like a country code (2-3 alphabetic chars)
        if len(parts) == 2 and len(parts[1]) in (2, 3) and parts[1].isalpha():
            return parts[0], parts[1].lower()

        # No country suffix detected
        return provider_name, None

    def save_provider_credentials_from_api(self, provider_name: str,
                                           credentials_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Save credentials from API request (bypasses Kodi sync)

        Args:
            provider_name: Provider name, optionally with country (e.g., "joyn_de")
            credentials_data: Dictionary with credential data
                For user_password: {"username": "...", "password": "...", "client_id": "..." (optional)}
                For client_credentials: {"client_id": "...", "client_secret": "..."}

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Parse provider and country
            provider, country = self.parse_provider_country(provider_name)

            # Check if provider is registered
            if not self.is_provider_registered(provider):
                return False, f'Provider "{provider}" is not registered'

            # Validate credentials_data format
            if not isinstance(credentials_data, dict):
                return False, "Credentials data must be a dictionary"

            # Determine credential type and create appropriate object
            credentials = self._parse_credentials_from_dict(credentials_data)

            if not credentials:
                return False, "Invalid credentials format. Must provide either (username + password) or (client_id + client_secret)"

            # Validate credentials
            if not credentials.validate():
                return False, f"Credential validation failed: missing required fields"

            # Save directly to file (bypass Kodi sync)
            success = self.credential_manager.save_credentials(provider, credentials, country)

            if success:
                country_str = f" ({country})" if country else ""
                logger.info(f"Successfully saved credentials from API for {provider}{country_str}")
                return True, "Credentials saved successfully"
            else:
                return False, "Failed to save credentials to file"

        except Exception as e:
            logger.error(f"Error saving credentials from API for {provider_name}: {e}")
            return False, f"Internal error: {str(e)}"


    @staticmethod
    def _parse_credentials_from_dict(credentials_data: Dict[str, Any]) -> Optional[BaseCredentials]:
        """
        Parse credentials dictionary and create appropriate credential object

        Args:
            credentials_data: Dictionary with credential data

        Returns:
            BaseCredentials instance or None if invalid
        """
        # Check for user_password credentials
        has_username = 'username' in credentials_data and credentials_data['username']
        has_password = 'password' in credentials_data and credentials_data['password']

        if has_username and has_password:
            return UserPasswordCredentials(
                username=credentials_data['username'].strip(),
                password=credentials_data['password'].strip(),
                client_id=credentials_data.get('client_id', '').strip() or None
            )

        # Check for client credentials
        has_client_id = 'client_id' in credentials_data and credentials_data['client_id']
        has_client_secret = 'client_secret' in credentials_data and credentials_data['client_secret']

        if has_client_id and has_client_secret:
            return ClientCredentials(
                client_id=credentials_data['client_id'].strip(),
                client_secret=credentials_data['client_secret'].strip()
            )

        # Invalid format
        return None


    def save_provider_proxy_from_api(self, provider_name: str,
                                     proxy_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Save proxy configuration from API request (bypasses Kodi sync)

        Args:
            provider_name: Provider name, optionally with country (e.g., "joyn_de")
            proxy_data: Dictionary with proxy data
                Required: {"host": "...", "port": 8080}
                Optional: {"proxy_type": "http", "username": "...", "password": "...",
                          "timeout": 30, "verify_ssl": true}

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Parse provider and country
            provider, country = self.parse_provider_country(provider_name)

            # Check if provider is registered
            if not self.is_provider_registered(provider):
                return False, f'Provider "{provider}" is not registered'

            # Validate proxy_data format
            if not isinstance(proxy_data, dict):
                return False, "Proxy data must be a dictionary"

            # Create ProxyConfig object
            proxy_config = self._parse_proxy_from_dict(proxy_data)

            if not proxy_config:
                return False, "Invalid proxy format. Must provide 'host' and 'port'"

            # Validate proxy config
            if not proxy_config.validate():
                return False, "Proxy validation failed: invalid host, port, or timeout"

            # Save directly to file (bypass Kodi sync)
            success = self.proxy_manager.set_proxy_config(provider, proxy_config, country)

            if success:
                country_str = f" ({country})" if country else ""
                logger.info(f"Successfully saved proxy config from API for {provider}{country_str}")
                return True, "Proxy configuration saved successfully"
            else:
                return False, "Failed to save proxy configuration to file"

        except Exception as e:
            logger.error(f"Error saving proxy config from API for {provider_name}: {e}")
            return False, f"Internal error: {str(e)}"


    @staticmethod
    def _parse_proxy_from_dict(proxy_data: Dict[str, Any]) -> Optional[ProxyConfig]:
        """
        Parse proxy dictionary and create ProxyConfig object

        Args:
            proxy_data: Dictionary with proxy data

        Returns:
            ProxyConfig instance or None if invalid
        """
        from ..models.proxy_models import ProxyConfig, ProxyAuth, ProxyType, ProxyScope

        # Required fields
        if 'host' not in proxy_data or not proxy_data['host']:
            return None
        if 'port' not in proxy_data:
            return None

        try:
            port = int(proxy_data['port'])
        except (ValueError, TypeError):
            return None

        # Optional proxy type
        proxy_type = ProxyType.HTTP
        if 'proxy_type' in proxy_data:
            try:
                proxy_type = ProxyType(proxy_data['proxy_type'].lower())
            except (ValueError, AttributeError):
                pass  # Use default

        # Optional authentication
        auth = None
        if 'username' in proxy_data and 'password' in proxy_data:
            if proxy_data['username'] and proxy_data['password']:
                auth = ProxyAuth(
                    username=proxy_data['username'].strip(),
                    password=proxy_data['password'].strip()
                )

        # Optional scope (default to all enabled)
        scope = ProxyScope()
        if 'scope' in proxy_data and isinstance(proxy_data['scope'], dict):
            scope_data = proxy_data['scope']
            scope = ProxyScope(
                api_calls=scope_data.get('api_calls', True),
                authentication=scope_data.get('authentication', True),
                manifests=scope_data.get('manifests', True),
                license=scope_data.get('license', True),
                all=scope_data.get('all', True)
            )

        # Optional settings
        timeout = proxy_data.get('timeout', 30)
        verify_ssl = proxy_data.get('verify_ssl', True)

        return ProxyConfig(
            host=proxy_data['host'].strip(),
            port=port,
            proxy_type=proxy_type,
            auth=auth,
            scope=scope,
            timeout=timeout,
            verify_ssl=verify_ssl
        )


    def delete_provider_credentials_from_api(self, provider_name: str) -> Tuple[bool, str]:
        """
        Delete credentials via API request

        Args:
            provider_name: Provider name, optionally with country (e.g., "joyn_de")

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Parse provider and country
            provider, country = self.parse_provider_country(provider_name)

            # Check if provider is registered
            if not self.is_provider_registered(provider):
                return False, f'Provider "{provider}" is not registered'

            # Delete credentials
            success = self.credential_manager.delete_credentials(provider, country)

            if success:
                country_str = f" ({country})" if country else ""
                logger.info(f"Successfully deleted credentials from API for {provider}{country_str}")
                return True, "Credentials deleted successfully"
            else:
                return False, "Failed to delete credentials"

        except Exception as e:
            logger.error(f"Error deleting credentials from API for {provider_name}: {e}")
            return False, f"Internal error: {str(e)}"


    def delete_provider_proxy_from_api(self, provider_name: str) -> Tuple[bool, str]:
        """
        Delete proxy configuration via API request

        Args:
            provider_name: Provider name, optionally with country (e.g., "joyn_de")

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            # Parse provider and country
            provider, country = self.parse_provider_country(provider_name)

            # Check if provider is registered
            if not self.is_provider_registered(provider):
                return False, f'Provider "{provider}" is not registered'

            # Delete proxy config
            success = self.proxy_manager.remove_proxy_config(provider, country)

            if success:
                country_str = f" ({country})" if country else ""
                logger.info(f"Successfully deleted proxy config from API for {provider}{country_str}")
                return True, "Proxy configuration deleted successfully"
            else:
                return False, "Failed to delete proxy configuration"

        except Exception as e:
            logger.error(f"Error deleting proxy config from API for {provider_name}: {e}")
            return False, f"Internal error: {str(e)}"


# For imports that expect the old interface
UnifiedSettingsManager = SettingsManager  # Backward compatibility alias

__all__ = ['SettingsManager', 'UnifiedSettingsManager', 'ProviderRegistration']