"""Provider favorites mixin."""

from typing import List, Optional

from ..models.favorite import Favorite, FavoriteType


class ProviderFavoritesMixin:
    @property
    def implements_favorites(self) -> bool:
        """
        True if this provider can store/retrieve user favorites.

        Default False. Override in providers that support favorites.
        """
        return False

    def get_favorites(self, **kwargs) -> List["Favorite"]:
        """
        Return all favorites for the authenticated user.

        Returns:
            List of Favorite objects, or [] if not supported or none exist.
        """
        return []

    def add_favorite(
            self,
            content_id: str,
            favorite_type: FavoriteType,
            title: Optional[str] = None,
            **kwargs,
    ) -> "Favorite":
        """
        Add a content to user's favorites.

        Args:
            content_id: Content identifier.
            favorite_type: Type of content (PROGRAM, CLIP, LIVE, EVENT).
            title: Content title (optional for caching).

        Returns:
            The saved Favorite object.

        Raises:
            RuntimeError: If the provider rejects the favorite.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement add_favorite()."
        )

    def remove_favorite(self, content_id: str, **kwargs) -> None:
        """
        Remove a content from user's favorites.

        Args:
            content_id: Content identifier to remove.

        Raises:
            KeyError: If no favorite with this content_id exists.
            RuntimeError: If the provider refuses deletion.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement remove_favorite()."
        )