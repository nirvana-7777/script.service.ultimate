# streaming_providers/base/manager.py
from typing import Dict, List, Optional
from .provider import StreamingProvider
from .models import StreamingChannel, DRMSystem
from .drm import DRMPluginManager
from .utils.logger import logger

class ProviderManager:
    """
    Central manager for handling multiple streaming providers.
    Handles provider registration, discovery, and channel fetching operations.
    """

    def __init__(self):
        """Initialize with empty provider registry and DRM plugin manager"""
        self.providers: Dict[str, StreamingProvider] = {}
        self.drm_plugin_manager = DRMPluginManager()
        logger.info("ProviderManager: Initialized with DRM plugin manager")

    def register_provider(self, provider: StreamingProvider) -> None:
        """
        Register a single provider instance.

        Args:
            provider: Configured provider instance to register
        """
        if not isinstance(provider, StreamingProvider):
            logger.error(f"ProviderManager: Failed to register provider - invalid type: {type(provider)}")
            raise ValueError("Only StreamingProvider instances can be registered")
        
        self.providers[provider.provider_name] = provider
        logger.info(f"ProviderManager: Registered provider '{provider.provider_name}'")

    def register_providers(self, providers: List[StreamingProvider]) -> None:
        """
        Register multiple provider instances at once.

        Args:
            providers: List of configured provider instances
        """
        logger.info(f"ProviderManager: Registering {len(providers)} providers")
        for provider in providers:
            self.register_provider(provider)

    def discover_providers(self, country: str = 'DE', detected_providers: Dict[str, List[str]] = None) -> List[str]:
        """
        Discover and register all available providers for a country.

        Args:
            country: Country code for provider configuration (used as fallback)
            detected_providers: Optional dict mapping provider names to country lists.
                              If None, falls back to discovering all AVAILABLE_PROVIDERS.

        Returns:
            List of discovered provider names (without country suffixes for compatibility)
        """
        from streaming_providers import AVAILABLE_PROVIDERS

        # Backward compatibility: if no detected_providers, use original discovery logic
        if detected_providers is None:
            logger.info(f"ProviderManager: Discovering providers for country '{country}'")
            registered = []
            failed = []

            for provider_name, provider_class in AVAILABLE_PROVIDERS.items():
                if provider_name not in self.providers:
                    try:
                        provider = provider_class(country=country)
                        self.register_provider(provider)
                        registered.append(provider_name)
                    except Exception as e:
                        failed.append((provider_name, str(e)))
                        logger.warning(f"ProviderManager: Could not initialize provider '{provider_name}': {e}")

            logger.info(
                f"ProviderManager: Discovery completed - {len(registered)} providers registered, {len(failed)} failed")
            return registered

        # New multi-country logic
        logger.info(f"ProviderManager: Discovering providers with multi-country support")
        registered = []
        failed = []

        for provider_name, countries in detected_providers.items():
            if provider_name not in AVAILABLE_PROVIDERS:
                logger.warning(f"ProviderManager: Provider '{provider_name}' not in AVAILABLE_PROVIDERS, skipping")
                continue

            provider_class = AVAILABLE_PROVIDERS[provider_name]

            try:
                if countries:  # Multi-country provider
                    for country_code in countries:
                        provider_key = f"{provider_name}_{country_code}"
                        if provider_key not in self.providers:
                            provider = provider_class(country=country_code.lower())
                            self.providers[provider_key] = provider
                            logger.debug(f"ProviderManager: Registered {provider_key}")

                    # Return base provider name once for backward compatibility
                    if provider_name not in registered:
                        registered.append(provider_name)
                else:  # Single country provider (fallback to default country)
                    if provider_name not in self.providers:
                        provider = provider_class(country=country.lower())
                        self.providers[provider_name] = provider
                        registered.append(provider_name)
            except Exception as e:
                failed.append((provider_name, str(e)))
                logger.warning(f"ProviderManager: Could not initialize provider '{provider_name}': {e}")

        logger.info(
            f"ProviderManager: Discovery completed - {len(registered)} providers registered, {len(failed)} failed")
        return registered

    def discover_drm_plugins(self) -> List[str]:
        """
        Discover and register all available DRM plugins.

        Returns:
            List of discovered plugin names
        """
        logger.info("ProviderManager: Discovering DRM plugins")
        discovered = self.drm_plugin_manager.discover_plugins()
        logger.info(f"ProviderManager: DRM plugin discovery completed - {len(discovered)} plugins available")
        return discovered

    def get_provider(self, provider_name: str) -> Optional[StreamingProvider]:
        """
        Get registered provider by name.

        Args:
            provider_name: Name of the provider to retrieve

        Returns:
            The provider instance or None if not found
        """
        provider = self.providers.get(provider_name)
        if not provider:
            logger.debug(f"ProviderManager: Provider '{provider_name}' not found")
        return provider

    def get_provider_http_manager(self, provider_name: str):
        """
        Get HTTP manager for a specific provider.

        Args:
            provider_name: Name of the provider

        Returns:
            HTTPManager instance if provider exists and has one, None otherwise
        """
        provider = self.get_provider(provider_name)
        if not provider:
            logger.warning(f"ProviderManager: Provider '{provider_name}' not found")
            return None

        http_manager = provider.http_manager
        if not http_manager:
            logger.warning(f"ProviderManager: Provider '{provider_name}' has no HTTP manager configured")
            return None

        logger.debug(f"ProviderManager: Retrieved HTTP manager for provider '{provider_name}'")
        return http_manager

    def needs_proxy(self, provider_name: str) -> bool:
        """
        Check if a provider needs proxy support.

        Args:
            provider_name: Name of the provider

        Returns:
            True if provider has proxy configured, False otherwise
        """
        http_manager = self.get_provider_http_manager(provider_name)
        if not http_manager:
            return False

        has_proxy = http_manager.config.proxy_config is not None
        if has_proxy:
            logger.debug(f"ProviderManager: Provider '{provider_name}' requires proxy")
        else:
            logger.debug(f"ProviderManager: Provider '{provider_name}' does not require proxy")

        return has_proxy

    def get_provider_choices(self) -> Dict[int, str]:
        """
        Get numbered provider choices for user selection.
        Includes an 'all' option as the last choice.

        Returns:
            Mapping of choice numbers to provider names
        """
        choices = {i+1: name for i, name in enumerate(self.providers.keys())}
        choices[len(choices)+1] = 'all'
        return choices

    def get_selected_providers(self, choices_input: str) -> List[str]:
        """
        Convert user input string to list of provider names.

        Args:
            choices_input: Comma-separated string of choice numbers

        Returns:
            List of selected provider names
        """
        available = list(self.providers.keys())
        if not available:
            logger.warning("ProviderManager: No providers available for selection")
            return []

        selected = []
        for choice in choices_input.split(','):
            choice = choice.strip()
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(available):
                    selected.append(available[idx])
                elif idx == len(available):  # 'all' option
                    selected = available.copy()
        
        result = selected or available
        logger.debug(f"ProviderManager: Selected {len(result)} providers from input '{choices_input}'")
        return result

    def get_channels(self, provider_name: str, fetch_manifests: bool = False, **kwargs) -> List[StreamingChannel]:
        """
        Get channels from a specific provider.

        Args:
            provider_name: Name of the provider
            fetch_manifests: Whether to enrich channels with manifest data
            **kwargs: Additional arguments for channel fetching

        Returns:
            List of channels from the provider

        Raises:
            ValueError: If provider not found
        """
        provider = self.get_provider(provider_name)
        if not provider:
            logger.error(f"ProviderManager: Cannot get channels - provider '{provider_name}' not found")
            raise ValueError(f"Provider '{provider_name}' not found")

        logger.debug(f"ProviderManager: Fetching channels from provider '{provider_name}' (fetch_manifests={fetch_manifests})")
        channels = provider.fetch_channels(**kwargs)
        logger.info(f"ProviderManager: Retrieved {len(channels)} channels from provider '{provider_name}'")

        if fetch_manifests and not provider.uses_dynamic_manifests:
            logger.debug(f"ProviderManager: Enriching channels with manifest data for provider '{provider_name}'")
            enriched_channels = []
            for channel in channels:
                enriched = provider.enrich_channel_data(channel, **kwargs)
                if enriched is not None:
                    enriched_channels.append(enriched)
            logger.info(f"ProviderManager: Enriched {len(enriched_channels)} out of {len(channels)} channels")
            return enriched_channels
        return channels

    def get_channel_manifest(self, provider_name: str, channel_id: str, **kwargs) -> Optional[str]:
        """
        Get manifest URL for a specific channel from a provider.

        Args:
            provider_name: Name of the provider
            channel_id: ID of the channel
            **kwargs: Additional arguments (e.g., country)

        Returns:
            Manifest URL string, or None if not available

        Raises:
            ValueError: If provider not found
        """
        provider = self.get_provider(provider_name)
        if not provider:
            logger.error(f"ProviderManager: Cannot get manifest - provider '{provider_name}' not found")
            raise ValueError(f"Provider '{provider_name}' not found")

        manifest_url = provider.get_manifest(channel_id, **kwargs)
        if manifest_url:
            logger.debug(f"ProviderManager: Retrieved manifest for channel '{channel_id}' from provider '{provider_name}'")
        else:
            logger.warning(f"ProviderManager: No manifest available for channel '{channel_id}' from provider '{provider_name}'")
        return manifest_url

    def get_channel_epg(self, provider_name: str, channel_id: str, **kwargs) -> List[Dict]:
        """
        Get EPG data for a specific channel from a provider.

        Args:
            provider_name: Name of the provider
            channel_id: ID of the channel
            **kwargs: Additional arguments (e.g., start_time, end_time, country)

        Returns:
            List of EPG entries

        Raises:
            ValueError: If provider not found
        """
        provider = self.get_provider(provider_name)
        if not provider:
            logger.error(f"ProviderManager: Cannot get EPG - provider '{provider_name}' not found")
            raise ValueError(f"Provider '{provider_name}' not found")

        epg_data = provider.get_epg(channel_id, **kwargs)
        logger.debug(f"ProviderManager: Retrieved {len(epg_data)} EPG entries for channel '{channel_id}' from provider '{provider_name}'")
        return epg_data

    def get_provider_epg_xmltv(self, provider_name: str, **kwargs) -> Optional[str]:
        """
        Get complete EPG data for a provider in XMLTV format.

        Args:
            provider_name: Name of the provider
            **kwargs: Additional arguments (e.g., country)

        Returns:
            XMLTV formatted string, or None if not available

        Raises:
            ValueError: If provider not found
        """
        provider = self.get_provider(provider_name)
        if not provider:
            logger.error(f"ProviderManager: Cannot get XMLTV EPG - provider '{provider_name}' not found")
            raise ValueError(f"Provider '{provider_name}' not found")

        xmltv_data = provider.get_epg_xmltv(**kwargs)
        if xmltv_data:
            logger.info(f"ProviderManager: Retrieved XMLTV EPG data for provider '{provider_name}'")
        else:
            logger.warning(f"ProviderManager: No XMLTV EPG data available for provider '{provider_name}'")
        return xmltv_data

    def get_channel_drm_configs(self, provider_name: str, channel_id: str, **kwargs) -> List:
        provider = self.get_provider(provider_name)
        if not provider:
            logger.error(f"ProviderManager: Cannot get DRM configs - provider '{provider_name}' not found")
            raise ValueError(f"Provider '{provider_name}' not found")

        logger.debug(f"ProviderManager: Getting DRM configs for channel '{channel_id}' from provider '{provider_name}'")

        # Get raw DRM configs from provider
        drm_configs = provider.get_drm_configs_by_id(channel_id, **kwargs)
        logger.debug(f"ProviderManager: Retrieved {len(drm_configs)} raw DRM configs")

        # Check if we need PSSH data at all
        pssh_data_list = []
        if drm_configs and self.drm_plugin_manager.plugins:
            # Get DRM systems from configs
            config_drm_systems = {config.system for config in drm_configs}
            # Get DRM systems that have plugins (excluding GENERIC which processes all)
            plugin_drm_systems = set(self.drm_plugin_manager.plugins.keys())

            # Check if there's overlap OR if there's a GENERIC plugin (which processes everything)
            needs_pssh = bool(
                config_drm_systems & plugin_drm_systems or
                DRMSystem.GENERIC in plugin_drm_systems
            )

            if needs_pssh:
                manifest_url = provider.get_manifest(channel_id, **kwargs)
                if manifest_url:
                    logger.debug(
                        f"ProviderManager: PSSH needed - extracting from manifest (matching systems: {config_drm_systems & plugin_drm_systems})")
                    try:
                        pssh_data_list = self._extract_pssh_from_manifest(manifest_url)
                        logger.debug(f"ProviderManager: Extracted {len(pssh_data_list)} PSSH data entries")
                    except Exception as e:
                        logger.warning(f"ProviderManager: Could not extract PSSH data from manifest: {e}")
            else:
                logger.debug(
                    f"ProviderManager: No matching plugins for DRM systems {config_drm_systems}, skipping PSSH extraction")
        else:
            logger.debug(f"ProviderManager: No configs or no plugins registered, skipping PSSH extraction")

        # Process through DRM plugins with PSSH data
        processed_configs = self.drm_plugin_manager.process_drm_configs(drm_configs, pssh_data_list, **kwargs)
        logger.info(
            f"ProviderManager: Processed DRM configs for channel '{channel_id}' - {len(processed_configs)} configs returned")

        return processed_configs

    def _extract_pssh_from_manifest(self, manifest_url: str) -> List:
        """
        Extract PSSH data from a manifest URL.
        
        Args:
            manifest_url: URL of the manifest to parse
            
        Returns:
            List of PSSHData objects extracted from the manifest
        """
        import requests
        from .utils.manifest_parser import ManifestParser
        
        try:
            # Fetch the manifest content
            response = requests.get(manifest_url, timeout=10)
            response.raise_for_status()
            
            # Parse and extract PSSH data
            return ManifestParser.extract_pssh_from_manifest(response.text, manifest_url)
            
        except Exception as e:
            logger.warning(f"ProviderManager: Failed to fetch or parse manifest from {manifest_url}: {e}")
            return []

    def get_all_channels(self, fetch_manifests: bool = True, **kwargs) -> Dict[str, List[StreamingChannel]]:
        """
        Get channels from all registered providers.

        Args:
            fetch_manifests: Whether to enrich channels with manifest data
            **kwargs: Additional arguments for channel fetching

        Returns:
            Dictionary mapping provider names to their channels
        """
        logger.info(f"ProviderManager: Fetching channels from all {len(self.providers)} providers (fetch_manifests={fetch_manifests})")
        
        result = {}
        total_channels = 0
        
        for name in self.providers:
            try:
                channels = self.get_channels(name, fetch_manifests, **kwargs)
                result[name] = channels
                total_channels += len(channels)
            except Exception as e:
                logger.error(f"ProviderManager: Failed to get channels from provider '{name}': {e}")
                result[name] = []
        
        logger.info(f"ProviderManager: Retrieved {total_channels} total channels from all providers")
        return result

    def list_providers(self) -> List[str]:
        """List names of all registered providers"""
        return list(self.providers.keys())

    def clear_providers(self) -> None:
        """Clear all registered providers"""
        provider_count = len(self.providers)
        self.providers.clear()
        logger.info(f"ProviderManager: Cleared {provider_count} registered providers")

    def list_drm_plugins(self) -> Dict:
        """List all registered DRM plugins"""
        return self.drm_plugin_manager.list_plugins()

    def clear_drm_plugins(self) -> None:
        """Clear all registered DRM plugins"""
        logger.info("ProviderManager: Clearing all DRM plugins")
        self.drm_plugin_manager.clear_plugins()
