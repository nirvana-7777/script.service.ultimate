# streaming_providers/base/manager.py
from typing import Dict, List, Optional
from .provider import StreamingProvider
from .models import StreamingChannel, DRMSystem
from .drm import DRMPluginManager
from .epg import EPGManager
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

        self.epg_manager = EPGManager()

        logger.info("ProviderManager: Initialized with DRM plugin manager and EPG manager")

    @staticmethod
    def _is_provider_enabled(provider_name: str, country: Optional[str] = None) -> bool:
        """
        Check if a provider is enabled via settings manager.

        Args:
            provider_name: Name of the provider
            country: Optional country code

        Returns:
            True if provider is enabled, False otherwise
        """
        try:
            from .settings.settings_manager import SettingsManager
            # Create or get existing settings manager
            settings_manager = SettingsManager()
            return settings_manager.is_provider_enabled(provider_name, country)
        except Exception as e:
            logger.warning(f"Could not check enable status for '{provider_name}': {e}, defaulting to enabled")
            return True

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
        from streaming_providers import AVAILABLE_PROVIDERS

        # Backward compatibility: if no detected_providers, use original discovery logic
        if detected_providers is None:
            logger.info(f"ProviderManager: Discovering providers for country '{country}'")
            registered = []
            failed = []

            for provider_name, provider_class in AVAILABLE_PROVIDERS.items():
                if provider_name not in self.providers:
                    # CHECK ENABLED STATUS
                    if not self._is_provider_enabled(provider_name):
                        logger.debug(f"ProviderManager: Provider '{provider_name}' is disabled, skipping")
                        continue

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
                    enabled_countries = []
                    for country_code in countries:
                        # CHECK COUNTRY-SPECIFIC ENABLED STATUS
                        logger.debug(f"DEBUG: Checking enable for {provider_name}_{country_code}")
                        if not self._is_provider_enabled(provider_name, country_code):
                            logger.debug(
                                f"ProviderManager: Provider '{provider_name}_{country_code}' is disabled, skipping")
                            continue

                        provider_key = f"{provider_name}_{country_code}"
                        if provider_key not in self.providers:
                            provider = provider_class(country=country_code.lower())
                            self.providers[provider_key] = provider
                            enabled_countries.append(country_code)
                            logger.debug(f"ProviderManager: Registered {provider_key}")

                    # Only add to registered list if at least one country is enabled
                    if enabled_countries and provider_name not in registered:
                        registered.append(provider_name)

                else:  # Single country provider (fallback to default country)
                    # CHECK ENABLED STATUS
                    if not self._is_provider_enabled(provider_name):
                        logger.debug(f"ProviderManager: Provider '{provider_name}' is disabled, skipping")
                        continue

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
        channels = provider.get_channels(**kwargs)
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

        # CHECK IF PROVIDER IMPLEMENTS ITS OWN EPG
        if provider.implements_epg:
            # Use provider's native EPG implementation
            logger.debug(f"ProviderManager: Using native EPG for provider '{provider_name}'")
            epg_data = provider.get_epg(channel_id, **kwargs)
        else:
            # Use generic EPG manager
            logger.debug(f"ProviderManager: Using generic EPG for provider '{provider_name}'")
            epg_data = self.epg_manager.get_epg(
                provider_name=provider_name,
                channel_id=channel_id,
                start_time=kwargs.get('start_time'),
                end_time=kwargs.get('end_time')
            )

        logger.debug(
            f"ProviderManager: Retrieved {len(epg_data)} EPG entries for channel '{channel_id}' from provider '{provider_name}'")
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

        # Only use provider's XMLTV if it implements EPG
        if provider.implements_epg:
            logger.debug(f"ProviderManager: Using native XMLTV EPG for provider '{provider_name}'")
            xmltv_data = provider.get_epg_xmltv(**kwargs)
        else:
            # For generic EPG, we don't generate XMLTV format
            # (The EPG XML is already in XMLTV format, but it's global, not provider-specific)
            logger.warning(
                f"ProviderManager: Provider '{provider_name}' does not implement EPG, no provider-specific XMLTV available")
            xmltv_data = None

        if xmltv_data:
            logger.info(f"ProviderManager: Retrieved XMLTV EPG data for provider '{provider_name}'")
        else:
            logger.warning(f"ProviderManager: No XMLTV EPG data available for provider '{provider_name}'")

        return xmltv_data

    def clear_epg_cache(self) -> bool:
        """
        Clear the generic EPG cache.

        Returns:
            True if cleared successfully
        """
        logger.info("ProviderManager: Clearing EPG cache")
        return self.epg_manager.clear_cache()

    def reload_epg_mapping(self) -> bool:
        """
        Reload EPG channel mapping from file.

        Returns:
            True if reloaded successfully
        """
        logger.info("ProviderManager: Reloading EPG mapping")
        return self.epg_manager.reload_mapping()

    def get_epg_cache_info(self) -> Optional[Dict]:
        """
        Get information about EPG cache.

        Returns:
            Dictionary with cache info, or None if no cache
        """
        return self.epg_manager.get_cache_info()

    def get_epg_mapping_stats(self) -> Dict:
        """
        Get statistics about EPG channel mapping.

        Returns:
            Dictionary with mapping statistics
        """
        return self.epg_manager.get_mapping_stats()

    def has_epg_mapping(self, provider_name: str, channel_id: str) -> bool:
        """
        Check if EPG mapping exists for a specific channel.

        Args:
            provider_name: Name of provider
            channel_id: Channel ID

        Returns:
            True if mapping exists
        """
        return self.epg_manager.has_mapping_for_channel(provider_name, channel_id)

    def get_channel_drm_configs(self, provider_name: str, channel_id: str, **kwargs) -> List:
        provider = self.get_provider(provider_name)
        if not provider:
            logger.error(f"ProviderManager: Cannot get DRM configs - provider '{provider_name}' not found")
            raise ValueError(f"Provider '{provider_name}' not found")

        logger.debug(f"ProviderManager: Getting DRM configs for channel '{channel_id}' from provider '{provider_name}'")

        # Get raw DRM configs from provider
        drm_configs = provider.get_drm(channel_id, **kwargs)
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

    # ==============================================================================
    # CATCHUP METHODS - Add these after get_channel_drm_configs() method
    # ==============================================================================

    def get_catchup_manifest(self,
                             provider_name: str,
                             channel_id: str,
                             start_time: int,
                             end_time: int,
                             epg_id: Optional[str] = None,
                             country: Optional[str] = None) -> Optional[str]:
        """
        Get catchup manifest URL for a channel.

        Args:
            provider_name: Name of the provider
            channel_id: Channel identifier
            start_time: Start time as Unix timestamp
            end_time: End time as Unix timestamp
            epg_id: Optional EPG event ID
            country: Optional country code

        Returns:
            Manifest URL for catchup content, or None if not available

        Raises:
            ValueError: If provider not found
        """
        provider = self.get_provider(provider_name)

        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found")

        # Check if provider supports catchup
        if not provider.supports_catchup:
            logger.warning(f"Provider '{provider_name}' does not support catchup")
            return None

        # Validate catchup request
        is_valid, error_msg = provider.validate_catchup_request(start_time, end_time)
        if not is_valid:
            logger.error(f"Invalid catchup request for {provider_name}/{channel_id}: {error_msg}")
            return None

        try:
            # Call provider's catchup manifest method
            manifest_url = provider.get_catchup_manifest(
                channel_id=channel_id,
                start_time=start_time,
                end_time=end_time,
                epg_id=epg_id,
                country=country
            )

            if manifest_url:
                logger.info(f"Got catchup manifest for {provider_name}/{channel_id}: {manifest_url[:100]}...")
            else:
                logger.warning(f"No catchup manifest returned for {provider_name}/{channel_id}")

            return manifest_url

        except NotImplementedError:
            logger.error(f"Provider '{provider_name}' has not implemented get_catchup_manifest()")
            return None
        except Exception as e:
            logger.error(f"Error getting catchup manifest for {provider_name}/{channel_id}: {e}",
                         exc_info=True)
            return None

    def get_catchup_drm_configs(self,
                                provider_name: str,
                                channel_id: str,
                                start_time: int,
                                end_time: int,
                                epg_id: Optional[str] = None,
                                country: Optional[str] = None) -> List:
        """
        Get DRM configurations for catchup content.

        Args:
            provider_name: Name of the provider
            channel_id: Channel identifier
            start_time: Start time as Unix timestamp
            end_time: End time as Unix timestamp
            epg_id: Optional EPG event ID
            country: Optional country code

        Returns:
            List of DRM configurations

        Raises:
            ValueError: If provider not found
        """
        provider = self.get_provider(provider_name)

        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found")

        # Check if provider supports catchup
        if not provider.supports_catchup:
            logger.debug(f"Provider '{provider_name}' does not support catchup, using live DRM")
            return self.get_channel_drm_configs(provider_name, channel_id, country=country)

        try:
            # Call provider's catchup DRM method
            drm_configs = provider.get_catchup_drm(
                channel_id=channel_id,
                start_time=start_time,
                end_time=end_time,
                epg_id=epg_id,
                country=country
            )

            if drm_configs:
                logger.debug(f"Got {len(drm_configs)} DRM config(s) for catchup {provider_name}/{channel_id}")
            else:
                logger.debug(f"No catchup DRM configs for {provider_name}/{channel_id}")

            return drm_configs

        except NotImplementedError:
            logger.debug(f"Provider '{provider_name}' has not implemented get_catchup_drm(), "
                         f"using live DRM")
            return self.get_channel_drm_configs(provider_name, channel_id, country=country)
        except Exception as e:
            logger.error(f"Error getting catchup DRM for {provider_name}/{channel_id}: {e}",
                         exc_info=True)
            # Fallback to live DRM on error
            return self.get_channel_drm_configs(provider_name, channel_id, country=country)

    def get_catchup_window(self,
                           provider_name: str,
                           channel_id: Optional[str] = None) -> int:
        """
        Get catchup window in HOURS for a provider or specific channel.

        Args:
            provider_name: Name of the provider
            channel_id: Optional channel identifier for channel-specific window

        Returns:
            Catchup window in hours (0 = no catchup support)
        """
        provider = self.get_provider(provider_name)

        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found")

        # Get channel-specific window if channel_id provided
        if channel_id:
            try:
                return provider.get_catchup_window_for_channel(channel_id)
            except Exception as e:
                logger.warning(f"Error getting channel-specific catchup window: {e}")
                # Fallback to provider-wide window

        # Return provider-wide catchup window
        return provider.catchup_window

    def supports_catchup(self, provider_name: str) -> bool:
        """
        Check if a provider supports catchup.

        Args:
            provider_name: Name of the provider

        Returns:
            True if provider supports catchup

        Raises:
            ValueError: If provider not found
        """
        provider = self.get_provider(provider_name)

        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found")

        return provider.supports_catchup

    def get_all_catchup_capabilities(self) -> Dict[str, Dict[str, any]]:
        """
        Get catchup capabilities for all providers.

        Returns:
            Dictionary mapping provider names to their catchup capabilities:
            {
                'provider_name': {
                    'supports_catchup': bool,
                    'catchup_window': int,  # IN HOURS
                    'catchup_enabled': bool
                }
            }
        """
        capabilities = {}

        for provider_name in self.list_providers():
            try:
                provider = self.get_provider(provider_name)
                capabilities[provider_name] = {
                    'supports_catchup': provider.supports_catchup,
                    'catchup_window': provider.catchup_window,
                    'catchup_enabled': provider.supports_catchup and provider.catchup_window > 0
                }
            except Exception as e:
                logger.warning(f"Error getting catchup capabilities for {provider_name}: {e}")
                capabilities[provider_name] = {
                    'supports_catchup': False,
                    'catchup_window': 0,
                    'catchup_enabled': False
                }

        return capabilities

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

    @staticmethod
    def get_provider_class(provider_name: str):
        """
        Get provider class from AVAILABLE_PROVIDERS registry.

        Args:
            provider_name: Name of the provider (without country suffix)

        Returns:
            Provider class or None if not found
        """
        from streaming_providers import AVAILABLE_PROVIDERS

        # Remove country suffix if present (e.g., "joyn_de" -> "joyn")
        base_name = provider_name
        if '_' in provider_name:
            # Check if suffix looks like a country code (2-3 letters)
            name_parts = provider_name.rsplit('_', 1)
            if len(name_parts[1]) in (2, 3) and name_parts[1].isalpha():
                base_name = name_parts[0]

        return AVAILABLE_PROVIDERS.get(base_name)


    def reinitialize_provider(self, provider_name: str) -> bool:
        """
        Reinitialize a provider instance (e.g., after credentials change).

        Args:
            provider_name: Name of the provider to reinitialize

        Returns:
            True if successful, False otherwise

        Note:
            This creates a new provider instance with the same country,
            preserving the original configuration but with fresh HTTP session.
        """
        logger.info(f"ProviderManager: Reinitializing provider '{provider_name}'")

        # Get existing provider to extract configuration
        existing_provider = self.get_provider(provider_name)
        if not existing_provider:
            logger.error(f"ProviderManager: Cannot reinitialize - provider '{provider_name}' not found")
            return False

        # Extract country from existing provider
        country = getattr(existing_provider, 'country', 'DE')

        # Get provider class
        provider_class = self.get_provider_class(provider_name)
        if not provider_class:
            logger.error(f"ProviderManager: Provider class not found for '{provider_name}'")
            return False

        try:
            # Create new provider instance with same country
            new_provider = provider_class(country=country)

            # Replace in registry
            self.providers[provider_name] = new_provider

            logger.info(f"ProviderManager: Successfully reinitialized provider '{provider_name}'")
            return True

        except Exception as e:
            logger.error(f"ProviderManager: Failed to reinitialize provider '{provider_name}': {e}")
            return False


    def reinitialize_providers(self, provider_names: List[str]) -> Dict[str, bool]:
        """
        Reinitialize multiple providers.

        Args:
            provider_names: List of provider names to reinitialize

        Returns:
            Dictionary mapping provider names to success status
        """
        logger.info(f"ProviderManager: Reinitializing {len(provider_names)} providers")

        results = {}
        for provider_name in provider_names:
            success = self.reinitialize_provider(provider_name)
            results[provider_name] = success

        successful = sum(1 for result in results.values() if result)
        logger.info(f"ProviderManager: Reinitialization completed - {successful}/{len(provider_names)} successful")

        return results


    def reinitialize_all_providers(self) -> Dict[str, bool]:
        """
        Reinitialize all registered providers.

        Returns:
            Dictionary mapping provider names to success status
        """
        provider_names = list(self.providers.keys())
        return self.reinitialize_providers(provider_names)