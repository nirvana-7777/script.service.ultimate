# streaming_providers/base/managers/favorites.py
"""
FavoritesManager ABC.

Public interface
----------------
    get_favorites(**kw)                                 -> List[Favorite]   [abstract]
    add_favorite(content_id, **kw)                      -> Favorite         [abstract]
    remove_favorite(content_id, **kw)                   -> None             [abstract]
    is_favorite(content_id, favorites=None)             -> bool             [concrete]

Constructor contract
--------------------
Four required keyword-only collaborators.

Return-value conventions
------------------------
get_favorites returns [] when the user has no favorites or the provider
does not support favorites. Not an error.

add_favorite returns the created Favorite. Raises OperationFailedError on
rejection (e.g. provider's backend refuses the operation).

remove_favorite raises ItemNotFoundError if the content_id is not currently
favorited, and OperationFailedError on backend failure. Deleting a
non-existent favorite is an ItemNotFoundError -- which is also a KeyError,
consistent with ProviderFavoritesMixin.

ItemNotFoundError is both a NotFoundError (ProviderError) and a KeyError, and
OperationFailedError is both a ProviderError and a RuntimeError, so handlers
written against the old KeyError / RuntimeError convention keep working.

Provider guidance
-----------------
Favorites can be content of any type: a channel, a programme, a clip,
a series. The content_id is whatever the provider uses to identify the
favorited item. FavoriteType on the returned Favorite distinguishes
them (PROGRAM, CHANNEL, CLIP, LIVE, EVENT).
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, List, Optional

from ..models.favorite import Favorite, FavoriteType
from ._base import ManagerBase


class FavoritesManager(ManagerBase):
    """Abstract base for provider favorites managers."""

    # ------------------------------------------------------------------
    # Abstract
    # ------------------------------------------------------------------

    @abstractmethod
    def get_favorites(self, **kw: Any) -> List[Favorite]:
        """
        Return all favorites for the authenticated user.

        Return [] when the user has no favorites. Do NOT raise for
        "empty" -- that is a valid state.
        """
        raise NotImplementedError

    @abstractmethod
    def add_favorite(
        self,
        content_id: str,
        favorite_type: FavoriteType = FavoriteType.PROGRAM,
        title: Optional[str] = None,
        **kw: Any,
    ) -> Favorite:
        """
        Add a favorite.

        Raises OperationFailedError (also a RuntimeError) if the provider
        refuses the operation.
        """
        raise NotImplementedError

    @abstractmethod
    def remove_favorite(self, content_id: str, **kw: Any) -> None:
        """
        Remove a favorite.

        Raises:
            ItemNotFoundError:    if content_id is not currently favorited
                                  (also a KeyError).
            OperationFailedError: on backend failure (also a RuntimeError).
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Concrete
    # ------------------------------------------------------------------

    def is_favorite(
        self,
        content_id: str,
        favorites: Optional[List[Favorite]] = None,
        **kw: Any,
    ) -> bool:
        """
        Return True if content_id is currently favorited.

        Pass favorites=... to avoid a redundant get_favorites() call
        when checking multiple ids.
        """
        if favorites is None:
            favorites = self.get_favorites(**kw)
        return any(f.content_id == content_id for f in favorites)