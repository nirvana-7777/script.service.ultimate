# streaming_providers/base/provider_registry.py
"""
Core provider registry handling discovery, metadata, and lifecycle management.
"""
from typing import Dict, List, Optional, Any
from .provider import StreamingProvider
from .utils.logger import logger


class ProviderMetadata:
    """Metadata for a provider instance with lazy initialization."""

    def __init__(self, plugin_class, country: str, enabled: bool = False):
        self.plugin_class = plugin_class
        self.country = country.lower()
        self.enabled = enabled
        self.instance: Optional[StreamingProvider] = None
        self._extract_metadata()

    def _extract_metadata(self):
        """Extract static metadata from provider class without instantiation"""
        self.plugin_name = self.plugin_class.__name__.lower().replace('provider', '')

        # Check if provider supports multiple countries
        supports_multiple = self.plugin_class.supports_multiple_countries()

        if supports_multiple:
            # Multi-country provider: include country in name
            self.name = f"{self.plugin_name}_{self.country}"
            self.is_multi_country = True
        else:
            # Single-country provider
            self.name = self.plugin_name

            # Check if provider has an explicit single country
            supported_countries = self.plugin_class.get_static_supported_countries()
            if len(supported_countries) == 1:
                # Provider has exactly one supported country (e.g., HRTi with ["HR"])
                # Use that country instead of the passed-in country
                self.country = supported_countries[0].upper()
                self.is_multi_country = False
            else:
                # True single-country or country-agnostic (empty list)
                self.is_multi_country = False

        # Rest of the method remains the same...
        self.label = self.plugin_class.get_static_label(self.country)
        self.supported_auth_types = self.plugin_class.get_static_auth_types()
        self.logo = self.plugin_class.get_static_logo()
        self.supported_countries = self.plugin_class.get_static_supported_countries()
        self.requires_credentials = any(
            auth_type in ['user_credentials', 'client_credentials']
            for auth_type in self.supported_auth_types
        )

    def create_instance(self) -> Optional[StreamingProvider]:
        """Lazily create provider instance if enabled"""
        if not self.enabled:
            return None

        if self.instance is None:
            try:
                logger.info(f"Creating instance for provider: {self.name}")
                self.instance = self.plugin_class(country=self.country)
                logger.debug(f"Successfully created instance for {self.name}")
            except Exception as e:
                logger.error(f"Failed to create instance for {self.name}: {e}")
                self.instance = None

        return self.instance

    def destroy_instance(self):
        """Clean up provider instance"""
        if self.instance:
            logger.debug(f"Destroying instance for provider: {self.name}")
            self.instance = None

    def set_enabled(self, enabled: bool):
        """Update enabled status and manage instance accordingly"""
        self.enabled = enabled
        if enabled and self.instance is None:
            self.create_instance()
        elif not enabled and self.instance is not None:
            self.destroy_instance()

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary for API response"""
        return {
            'name': self.name,
            'label': self.label,
            'plugin': self.plugin_name,
            'country': self.country.upper(),
            'enabled': self.enabled,
            'instance_ready': self.instance is not None,
            'requires_credentials': self.requires_credentials,
            'supported_auth_types': self.supported_auth_types,
            'logo': self.logo,
            'is_multi_country': self.is_multi_country,
            'supported_countries': self.supported_countries
        }


class ProviderRegistry:
    """
    Core registry for provider discovery, metadata, and lifecycle management.
    Separated concern: Provider registration and access.
    """

    def __init__(self):
        self.providers: Dict[str, StreamingProvider] = {}  # Active instances
        self.provider_metadata: Dict[str, ProviderMetadata] = {}  # All providers
        logger.info("ProviderRegistry: Initialized")

    @staticmethod
    def _is_provider_enabled(provider_name: str, country: Optional[str] = None) -> bool:
        """Check if a provider is enabled via settings manager."""
        try:
            from .settings.provider_enable_manager import ProviderEnableManager
            enable_manager = ProviderEnableManager()

            instance_name = f"{provider_name}_{country}" if country else provider_name
            return enable_manager.is_provider_enabled(instance_name)
        except Exception as e:
            logger.warning(f"Could not check enable status for '{provider_name}': {e}")
            return True

    def discover_all_providers(self, default_country: str = 'DE') -> List[str]:
        """Discover ALL provider instances and extract metadata."""
        from streaming_providers import AVAILABLE_PROVIDERS

        logger.info("ProviderRegistry: Discovering provider instances")
        discovered = []

        for plugin_name, plugin_class in AVAILABLE_PROVIDERS.items():
            if plugin_class.supports_multiple_countries():
                for country in plugin_class.get_static_supported_countries():
                    instance_name = f"{plugin_name}_{country}"
                    enabled = self._is_provider_enabled(plugin_name, country)

                    metadata = ProviderMetadata(plugin_class, country, enabled)
                    self.provider_metadata[instance_name] = metadata
                    discovered.append(instance_name)

                    if enabled:
                        instance = metadata.create_instance()
                        if instance:
                            self.providers[instance_name] = instance
            else:
                instance_name = plugin_name
                enabled = self._is_provider_enabled(plugin_name)

                metadata = ProviderMetadata(plugin_class, default_country, enabled)
                self.provider_metadata[instance_name] = metadata
                discovered.append(instance_name)

                if enabled:
                    instance = metadata.create_instance()
                    if instance:
                        self.providers[instance_name] = instance

        logger.info(f"ProviderRegistry: Discovered {len(discovered)} provider instances")
        return discovered

    def get_provider(self, provider_name: str) -> Optional[StreamingProvider]:
        """Get provider instance, creating it lazily if needed."""
        provider = self.providers.get(provider_name)
        if provider:
            return provider

        metadata = self.provider_metadata.get(provider_name)
        if not metadata or not metadata.enabled:
            return None

        provider = metadata.create_instance()
        if provider:
            self.providers[provider_name] = provider
        return provider

    def set_provider_enabled(self, provider_name: str, enabled: bool) -> bool:
        """Enable or disable a provider dynamically."""
        metadata = self.provider_metadata.get(provider_name)
        if not metadata:
            logger.error(f"Cannot enable/disable unknown provider '{provider_name}'")
            return False

        metadata.set_enabled(enabled)

        if enabled and metadata.instance:
            self.providers[provider_name] = metadata.instance
        elif not enabled and provider_name in self.providers:
            del self.providers[provider_name]

        try:
            from .settings.provider_enable_manager import ProviderEnableManager
            enable_manager = ProviderEnableManager()
            success, message = enable_manager.set_provider_enabled(provider_name, enabled)
            return success
        except Exception as e:
            logger.error(f"Error updating enable status: {e}")
            return False

    def reinitialize_provider(self, provider_name: str) -> bool:
        """Reinitialize a provider instance."""
        metadata = self.provider_metadata.get(provider_name)
        if not metadata or not metadata.enabled:
            return False

        try:
            metadata.destroy_instance()
            new_instance = metadata.create_instance()
            if new_instance:
                self.providers[provider_name] = new_instance
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to reinitialize '{provider_name}': {e}")
            return False

    def get_all_providers_metadata(self) -> List[Dict[str, Any]]:
        """Get metadata for ALL provider instances."""
        return [m.to_dict() for m in self.provider_metadata.values()]

    def list_providers(self) -> List[str]:
        """List enabled provider names."""
        return list(self.providers.keys())

    def list_all_providers(self) -> List[str]:
        """List ALL provider names (enabled + disabled)."""
        return list(self.provider_metadata.keys())

    def get_enabled_providers(self) -> List[str]:
        """Get list of enabled provider names."""
        return [name for name, m in self.provider_metadata.items() if m.enabled]

    def clear_providers(self):
        """Clear all providers."""
        self.providers.clear()
        logger.info("ProviderRegistry: Cleared all providers")
