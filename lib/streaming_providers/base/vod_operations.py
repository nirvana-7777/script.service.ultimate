# streaming_providers/base/vod_operations.py
"""
VOD-related operations separated from core registry.
Follows the same pattern as ChannelOperations and EventOperations.
"""

from typing import Dict, List, Optional, Union

from .models.vod import VodCategory, VodItem, build_slug_map
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

    def _resolve_path_to_ids(
        self, provider_name: str, slug_segments: List[str]
    ) -> List[str]:
        """
        Walk the VOD tree segment by segment, converting URL slugs to
        content_ids.

        Strategy per segment:
          1. Ask the provider for the children of the current path (using
             already-resolved IDs up to this point).
          2. Build a slug → id map for those children.
          3. Look up the next slug in that map.
          4. If found, append the resolved id and continue.
          5. If not found, raise ValueError (→ 404).

        Returns the fully resolved list of content_ids.
        """
        provider = self._get_provider(provider_name)
        resolved_ids: List[str] = []

        for slug in slug_segments:
            children = provider.get_vod_category(resolved_ids)
            slug_map = build_slug_map(children)

            if slug not in slug_map:
                raise ValueError(
                    f"VOD path segment '{slug}' not found under "
                    f"'{'/'.join(resolved_ids) or 'root'}' "
                    f"for provider '{provider_name}'"
                )

            resolved_ids.append(slug_map[slug])

        return resolved_ids

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_vod_node(
        self,
        provider_name: str,
        slug_segments: List[str],
    ) -> List[Union[VodCategory, VodItem]]:
        """
        Resolve a slug path and return the children of that node.

        Args:
            provider_name: Provider to query.
            slug_segments: URL path segments as slugs, e.g.
                           ["sports", "golf", "pga"].
                           Empty list → root level.

        Returns:
            Mixed list of VodCategory and VodItem entries.

        Raises:
            ValueError: Provider not found, or any path segment does not
                        resolve to a known child (→ 404).
        """
        provider = self._get_provider(provider_name)

        if not slug_segments:
            # Root — no resolution needed
            children = provider.get_vod_category([])
            logger.info(
                f"Retrieved {len(children)} root VOD entries from '{provider_name}'"
            )
            return children

        # Pass slug segments directly to the provider.
        # Providers whose content_ids are full route paths (e.g. Discovery+)
        # will join the segments themselves into the correct CMS route.
        # The old slug-walking approach (_resolve_path_to_ids) is bypassed
        # because it fetches every intermediate level unnecessarily and fails
        # when the provider's tree is too deep or slugs don't match exactly.
        children = provider.get_vod_category(slug_segments)

        logger.info(
            f"Retrieved {len(children)} VOD entries from '{provider_name}' "
            f"at path '{'/'.join(slug_segments)}'"
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