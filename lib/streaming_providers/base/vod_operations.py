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
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kwargs,
    ) -> Dict:
        """
        Return the children of a VOD node, with optional paging support.

        Args:
            provider_name: Provider to query.
            content_id:    Opaque node identifier from a previous response
                           (VodCategory.content_id).  Empty string → root.
            cursor:        Opaque continuation token from a previous response's
                           next_cursor field.  None → first page.
                           Providers encode their own paging state (offset int,
                           next-page URL, scroll token, etc.) in this string.
            page_size:     Hint for how many entries to return per page.
                           Providers may ignore or clamp this value.

        Returns:
            {
                "entries":     List[VodCategory | VodItem],
                "next_cursor": Optional[str],   # None = no further pages
                "total":       Optional[int],   # total count if known by provider
            }
            Providers that have not yet been updated to support paging may
            return a plain list; this method normalises that into the dict
            shape above with next_cursor=None so callers never need to
            special-case the old return type.

        Raises:
            ValueError: Provider not found.
        """
        provider = self._get_provider(provider_name)
        label = content_id or "root"
        logger.debug(
            f"VodOperations: Fetching VOD node '{label}' from '{provider_name}' "
            f"(cursor={cursor!r}, page_size={page_size})"
        )

        raw = provider.get_vod_category(
            content_id=content_id,
            cursor=cursor,
            page_size=page_size,
            **kwargs,
        )

        # Normalise: providers that have not yet adopted paging return a plain
        # list.  Wrap it so all callers always get the same dict shape.
        if isinstance(raw, list):
            result = {"entries": raw, "next_cursor": None, "total": None}
        else:
            result = raw

        entries = result.get("entries", [])
        next_cursor = result.get("next_cursor")
        logger.info(
            f"VodOperations: Retrieved {len(entries)} VOD entries from '{provider_name}' "
            f"at '{label}'"
            + (f" — next_cursor present" if next_cursor else "")
        )
        return result

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

    def search_vod(
        self,
        provider_name: str,
        query: str,
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kwargs,
    ) -> Dict:
        """
        Search the VOD catalogue of a single provider.

        Args:
            provider_name: Provider to query.
            query:         Free-text search string entered by the user.
            cursor:        Opaque continuation token from a previous response's
                           next_cursor field.  None → first page.
            page_size:     Hint for how many entries to return per page.
                           Providers may ignore or clamp this value.

        Returns:
            {
                "entries":     List[VodCategory | VodItem],
                "next_cursor": Optional[str],   # None = no further pages
                "total":       Optional[int],   # total count if known by provider
            }
            Providers that do not implement search return an empty entries list
            with next_cursor=None.

        Raises:
            ValueError: Provider not found.
        """
        provider = self._get_provider(provider_name)
        logger.debug(
            f"VodOperations: Searching VOD in '{provider_name}' "
            f"(query={query!r}, cursor={cursor!r}, page_size={page_size})"
        )

        raw = provider.search_vod(
            query=query,
            cursor=cursor,
            page_size=page_size,
            **kwargs,
        )

        # Normalise: providers may return a plain list or the paged dict shape.
        if isinstance(raw, list):
            result = {"entries": raw, "next_cursor": None, "total": None}
        else:
            result = raw

        entries = result.get("entries", [])
        next_cursor = result.get("next_cursor")
        logger.info(
            f"VodOperations: Search '{query}' in '{provider_name}' returned "
            f"{len(entries)} entries"
            + (f" — next_cursor present" if next_cursor else "")
        )
        return result

    def search_all_vod(
        self, query: str, **kwargs
    ) -> Dict[str, List[Union[VodCategory, VodItem]]]:
        """
        Search the VOD catalogue across all enabled providers that implement VOD.

        Providers that return implements_vod=False are silently skipped.
        Only fetches the first page of results per provider — callers that
        need subsequent pages should use search_vod directly.

        Args:
            query: Free-text search string entered by the user.

        Returns:
            Dict mapping provider name → list of matching VodCategory/VodItem
            objects.  Providers that fail or return no results are included
            with an empty list so the caller always gets a complete map of
            enabled VOD providers.
        """
        enabled = self.registry.get_enabled_providers()
        logger.info(f"Searching VOD across {len(enabled)} providers (query={query!r})")

        result = {}
        total = 0

        for name in enabled:
            try:
                provider = self.registry.get_provider(name)
                if not getattr(provider, "implements_vod", False):
                    continue
                node = self.search_vod(name, query=query, **kwargs)
                entries = node["entries"]
                result[name] = entries
                total += len(entries)
            except Exception as e:
                logger.error(f"Failed to search VOD in '{name}': {e}")
                result[name] = []

        logger.info(f"VOD search '{query}' returned {total} total entries")
        return result

    def get_all_vod_roots(self) -> Dict[str, List[Union[VodCategory, VodItem]]]:
        """
        Get root VOD entries from all enabled providers that implement VOD.

        Providers that return implements_vod=False are silently skipped.
        Only fetches the first page of root entries per provider — callers
        that need subsequent pages should use get_vod_node directly.
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
                node = self.get_vod_node(name, content_id="")
                entries = node["entries"]
                result[name] = entries
                total += len(entries)
            except Exception as e:
                logger.error(f"Failed to get VOD root from '{name}': {e}")
                result[name] = []

        logger.info(f"Retrieved {total} total root VOD entries")
        return result