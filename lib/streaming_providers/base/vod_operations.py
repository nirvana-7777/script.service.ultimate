# streaming_providers/base/vod_operations.py
"""
VOD-related operations separated from core registry.
Follows the same pattern as ChannelOperations and EventOperations.
"""

from typing import Dict, List, Optional, Union

from .models.vod import VodCategory, VodItem
from .utils.logger import logger


class VodOperations:
    """Handles all VOD browsing and manifest operations."""

    def __init__(self, registry):
        self.registry = registry
        logger.debug("VodOperations: Initialized")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_provider(self, provider_name: str):
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")
        return provider

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_vod_node(
        self,
        provider_name: str,
        content_id: str = "",
        **kwargs,
    ) -> List[Union[VodCategory, VodItem]]:
        """
        Return the children of a VOD node.

        Args:
            provider_name: Provider to query.
            content_id:    Opaque node identifier from a previous response
                           (VodCategory.content_id).  Empty string → root.

        Returns:
            Mixed list of VodCategory and VodItem entries.

        Raises:
            ValueError: Provider not found.
        """
        provider = self._get_provider(provider_name)
        children = provider.get_vod_category(content_id=content_id, **kwargs)
        label = content_id or "root"
        logger.info(
            f"Retrieved {len(children)} VOD entries from '{provider_name}' "
            f"at '{label}'"
        )
        return children

    def get_vod_manifest(
        self, provider_name: str, vod_id: str, **kwargs
    ) -> Optional[str]:
        """
        Get manifest URL for a specific VOD item.

        Delegates directly to provider.get_manifest(content_id) — identical
        to channel and event manifest resolution.
        """
        provider = self._get_provider(provider_name)
        manifest_url = provider.get_manifest(content_id=vod_id, **kwargs)
        if manifest_url:
            logger.debug(
                f"Retrieved manifest for VOD '{vod_id}' from '{provider_name}'"
            )
        return manifest_url

    def get_vod_drm_configs(
        self, provider_name: str, vod_id: str, **kwargs
    ):
        """
        Get DRM configs for a specific VOD item.

        Delegates directly to provider.get_drm(content_id).
        """
        provider = self._get_provider(provider_name)
        return provider.get_drm(content_id=vod_id, **kwargs)

    def get_all_vod_roots(self) -> Dict[str, List[Union[VodCategory, VodItem]]]:
        """
        Get root VOD entries from all enabled providers that implement VOD.

        Providers that return implements_vod=False are silently skipped.
        """
        enabled = self.registry.get_enabled_providers()
        logger.info(f"Fetching VOD roots from {len(enabled)} providers")

        result = {}
        total = 0

        for name in enabled:
            try:
                provider = self.registry.get_provider(name)
                if not getattr(provider, "implements_vod", False):
                    continue
                entries = self.get_vod_node(name, [])
                result[name] = entries
                total += len(entries)
            except Exception as e:
                logger.error(f"Failed to get VOD root from '{name}': {e}")
                result[name] = []

        logger.info(f"Retrieved {total} total root VOD entries")
        return result