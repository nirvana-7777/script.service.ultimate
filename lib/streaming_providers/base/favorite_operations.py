# streaming_providers/base/favorite_operations.py
"""
Favorite-related operations separated from core registry.
Mirrors the structure of BookmarkOperations.
"""

from typing import Dict, List, Optional

from .models.favorite import Favorite, FavoriteType
from .utils.logger import logger


class FavoriteOperations:
    """Handles all favorite-related operations."""

    def __init__(self, registry):
        self.registry = registry
        logger.debug("FavoriteOperations: Initialized")

    def get_favorites(
            self,
            provider_name: str,
            favorite_type: Optional[FavoriteType] = None,
    ) -> List[Favorite]:
        """Get favorites from a specific provider."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        if not provider.implements_favorites:
            return []

        favorites = provider.get_favorites()

        if favorite_type:
            favorites = [f for f in favorites if f.favorite_type == favorite_type]

        return favorites

    def add_favorite(
            self,
            provider_name: str,
            content_id: str,
            favorite_type: FavoriteType,
            title: Optional[str] = None,
            **kwargs,
    ) -> Optional[Favorite]:
        """Add a favorite."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        if not provider.implements_favorites:
            return None

        return provider.add_favorite(
            content_id=content_id,
            favorite_type=favorite_type,
            title=title,
            **kwargs,
        )

    def remove_favorite(
            self, provider_name: str, content_id: str
    ) -> bool:
        """Remove a favorite."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        if not provider.implements_favorites:
            return False

        try:
            provider.remove_favorite(content_id=content_id)
            return True
        except KeyError:
            return False

    def get_all_favorites(
            self,
            favorite_type: Optional[FavoriteType] = None,
    ) -> Dict[str, List[Favorite]]:
        """Get favorites from all enabled providers."""
        enabled = self.registry.get_enabled_providers()
        result = {}
        errors = {}

        for name in enabled:
            try:
                favorites = self.get_favorites(name, favorite_type=favorite_type)
                result[name] = favorites
            except Exception as e:
                logger.error(f"Failed to get favorites from '{name}': {e}")
                result[name] = []
                errors[name] = str(e)

        if errors:
            result["_errors"] = errors

        return result

    def is_favorited(
            self, provider_name: str, content_id: str
    ) -> bool:
        """Check if content is favorited."""
        favorites = self.get_favorites(provider_name)
        return any(f.content_id == content_id for f in favorites)