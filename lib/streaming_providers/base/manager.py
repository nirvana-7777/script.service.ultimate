# streaming_providers/base/manager.py
"""
Main ProviderManager as a facade coordinating all operations.
Maintains backward compatibility while delegating to specialized classes.
"""
from typing import Dict, List, Optional, Any
from .provider_registry import ProviderRegistry
from .channel_operations import ChannelOperations
from .epg_operations import EPGOperations
from .drm_operations import DRMOperations
from .catchup_operations import CatchupOperations
from .subscription_operations import SubscriptionOperations
from .models import StreamingChannel
from .utils.logger import logger


class ProviderManager:
    """
    Facade coordinating all provider-related operations.
    Maintains backward compatibility while delegating to specialized classes.
    """

    def __init__(self):
        # Core components
        self.registry = ProviderRegistry()

        # Specialized operations
        self.channel_ops = ChannelOperations(self.registry)
        self.epg_ops = EPGOperations(self.registry)
        self.drm_ops = DRMOperations(self.registry)
        self.catchup_ops = CatchupOperations(self.registry, self.drm_ops)
        self.subscription_ops = SubscriptionOperations(self.registry)

        # Backward compatibility - expose managers directly
        self.drm_plugin_manager = self.drm_ops.drm_plugin_manager
        self.epg_manager = self.epg_ops.epg_manager

        # Legacy compatibility - expose providers dict
        self.providers = self.registry.providers
        self.provider_metadata = self.registry.provider_metadata

        logger.info("ProviderManager: Initialized with modular architecture")

    # ==========================================================================
    # REGISTRY OPERATIONS (delegate to ProviderRegistry)
    # ==========================================================================

    def discover_all_providers(self, default_country: str = 'DE') -> List[str]:
        return self.registry.discover_all_providers(default_country)

    def discover_providers(self, country: str = 'DE',
                           detected_providers: Dict = None) -> List[str]:
        """Legacy method for backward compatibility."""
        if not self.registry.provider_metadata:
            self.registry.discover_all_providers(country)
        return self.registry.get_enabled_providers()

    def get_provider(self, provider_name: str):
        return self.registry.get_provider(provider_name)

    def set_provider_enabled(self, provider_name: str, enabled: bool) -> bool:
        return self.registry.set_provider_enabled(provider_name, enabled)

    def get_all_providers_metadata(self) -> List[Dict[str, Any]]:
        return self.registry.get_all_providers_metadata()

    def reinitialize_provider(self, provider_name: str) -> bool:
        return self.registry.reinitialize_provider(provider_name)

    def reinitialize_providers(self, provider_names: List[str]) -> Dict[str, bool]:
        return {name: self.registry.reinitialize_provider(name)
                for name in provider_names}

    def reinitialize_all_providers(self) -> Dict[str, bool]:
        enabled = self.registry.get_enabled_providers()
        return self.reinitialize_providers(enabled)

    def list_providers(self) -> List[str]:
        return self.registry.list_providers()

    def list_all_providers(self) -> List[str]:
        return self.registry.list_all_providers()

    def clear_providers(self):
        self.registry.clear_providers()

    @staticmethod
    def get_provider_class(provider_name: str):
        """Get provider class from AVAILABLE_PROVIDERS registry."""
        from streaming_providers import AVAILABLE_PROVIDERS

        # Remove country suffix if present
        base_name = provider_name
        if '_' in provider_name:
            name_parts = provider_name.rsplit('_', 1)
            if len(name_parts[1]) in (2, 3) and name_parts[1].isalpha():
                base_name = name_parts[0]

        return AVAILABLE_PROVIDERS.get(base_name)

    # ==========================================================================
    # CHANNEL OPERATIONS (delegate to ChannelOperations)
    # ==========================================================================

    def get_channels(self, provider_name: str, fetch_manifests: bool = False,
                     **kwargs) -> List[StreamingChannel]:
        return self.channel_ops.get_channels(provider_name, fetch_manifests, **kwargs)

    def get_channel_manifest(self, provider_name: str, channel_id: str,
                             **kwargs) -> Optional[str]:
        return self.channel_ops.get_channel_manifest(provider_name, channel_id, **kwargs)

    def get_all_channels(self, fetch_manifests: bool = True,
                         **kwargs) -> Dict[str, List[StreamingChannel]]:
        return self.channel_ops.get_all_channels(fetch_manifests, **kwargs)

    # ==========================================================================
    # EPG OPERATIONS (delegate to EPGOperations)
    # ==========================================================================

    def get_channel_epg(self, provider_name: str, channel_id: str,
                        **kwargs) -> List[Dict]:
        return self.epg_ops.get_channel_epg(provider_name, channel_id, **kwargs)

    def get_provider_epg_xmltv(self, provider_name: str, **kwargs) -> Optional[str]:
        return self.epg_ops.get_provider_epg_xmltv(provider_name, **kwargs)

    def clear_epg_cache(self) -> bool:
        return self.epg_ops.clear_epg_cache()

    def reload_epg_mapping(self) -> bool:
        return self.epg_ops.reload_epg_mapping()

    def get_epg_cache_info(self) -> Optional[Dict]:
        return self.epg_ops.get_epg_cache_info()

    def get_epg_mapping_stats(self) -> Dict:
        return self.epg_ops.get_epg_mapping_stats()

    def has_epg_mapping(self, provider_name: str, channel_id: str) -> bool:
        return self.epg_ops.has_epg_mapping(provider_name, channel_id)

    # ==========================================================================
    # DRM OPERATIONS (delegate to DRMOperations)
    # ==========================================================================

    def get_channel_drm_configs(self, provider_name: str, channel_id: str,
                                **kwargs) -> List:
        return self.drm_ops.get_channel_drm_configs(provider_name, channel_id, **kwargs)

    def list_drm_plugins(self) -> Dict:
        return self.drm_ops.list_drm_plugins()

    def clear_drm_plugins(self):
        self.drm_ops.clear_drm_plugins()

    # ==========================================================================
    # CATCHUP OPERATIONS (delegate to CatchupOperations)
    # ==========================================================================

    def get_catchup_manifest(self, provider_name: str, channel_id: str,
                             start_time: int, end_time: int,
                             epg_id: Optional[str] = None,
                             country: Optional[str] = None) -> Optional[str]:
        return self.catchup_ops.get_catchup_manifest(
            provider_name, channel_id, start_time, end_time, epg_id, country
        )

    def get_catchup_drm_configs(self, provider_name: str, channel_id: str,
                                start_time: int, end_time: int,
                                epg_id: Optional[str] = None,
                                country: Optional[str] = None) -> List:
        return self.catchup_ops.get_catchup_drm_configs(
            provider_name, channel_id, start_time, end_time, epg_id, country
        )

    def get_catchup_window(self, provider_name: str,
                           channel_id: Optional[str] = None) -> int:
        return self.catchup_ops.get_catchup_window(provider_name, channel_id)

    def supports_catchup(self, provider_name: str) -> bool:
        return self.catchup_ops.supports_catchup(provider_name)

    def get_all_catchup_capabilities(self) -> Dict[str, Dict]:
        return self.catchup_ops.get_all_catchup_capabilities()

    # ==========================================================================
    # SUBSCRIPTION OPERATIONS (delegate to SubscriptionOperations)
    # ==========================================================================

    def get_subscription_status(self, provider_name: str, **kwargs):
        return self.subscription_ops.get_subscription_status(provider_name, **kwargs)

    def get_subscribed_channels(self, provider_name: str, **kwargs):
        return self.subscription_ops.get_subscribed_channels(provider_name, **kwargs)

    def get_available_packages(self, provider_name: str, **kwargs):
        return self.subscription_ops.get_available_packages(provider_name, **kwargs)

    def is_channel_accessible(self, provider_name: str, channel_id: str, **kwargs):
        return self.subscription_ops.is_channel_accessible(
            provider_name, channel_id, **kwargs
        )

    # ==========================================================================
    # UTILITY METHODS (remain in ProviderManager as helpers)
    # ==========================================================================

    def get_provider_http_manager(self, provider_name: str):
        """Get HTTP manager for a specific provider."""
        provider = self.get_provider(provider_name)
        if not provider:
            logger.warning(f"ProviderManager: Provider '{provider_name}' not found")
            return None

        http_manager = provider.http_manager
        if not http_manager:
            logger.warning(f"ProviderManager: Provider '{provider_name}' has no HTTP manager")
            return None

        logger.debug(f"ProviderManager: Retrieved HTTP manager for '{provider_name}'")
        return http_manager

    def needs_proxy(self, provider_name: str) -> bool:
        """Check if a provider needs proxy support."""
        http_manager = self.get_provider_http_manager(provider_name)
        if not http_manager:
            return False

        has_proxy = http_manager.config.proxy_config is not None
        logger.debug(
            f"ProviderManager: Provider '{provider_name}' {'requires' if has_proxy else 'does not require'} proxy")
        return has_proxy

    def get_provider_choices(self) -> Dict[int, str]:
        """
        Get numbered provider choices for user selection.
        Includes an 'all' option as the last choice.
        """
        enabled_providers = self.registry.get_enabled_providers()
        choices = {i + 1: name for i, name in enumerate(enabled_providers)}
        choices[len(choices) + 1] = 'all'
        return choices

    def get_selected_providers(self, choices_input: str) -> List[str]:
        """
        Convert user input string to list of provider names.

        Args:
            choices_input: Comma-separated string of choice numbers

        Returns:
            List of selected provider names
        """
        available = self.registry.get_enabled_providers()

        if not available:
            logger.warning("ProviderManager: No enabled providers available for selection")
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
                    break

        result = selected if selected else available
        logger.debug(f"ProviderManager: Selected {len(result)} providers from input '{choices_input}'")
        return result

    # ==========================================================================
    # LEGACY COMPATIBILITY METHODS
    # ==========================================================================

    def _extract_pssh_from_manifest(self, manifest_url: str) -> List:
        """
        Extract PSSH data from a manifest URL.
        Kept for backward compatibility but delegated to DRMOperations.
        """
        return self.drm_ops._extract_pssh_from_manifest(manifest_url)