# streaming_providers/providers/_template/favorites_manager.py
"""
{TODO: Provider name} favorites manager (optional).

Include this file only if the provider supports user favorites on
programs / channels. Providers without favorites don't create a
favorites manager -- the provider's implements_favorites is False and
calls to get_favorites return [].

See ../_template/README.md ("Favorites and bookmarks") for the contract.

Contract summary
----------------
* User-scoped; operates on whatever content_id the caller provides, so
  it does not participate in the content_id router.
* Each returned Favorite carries a FavoriteType (program / channel /
  clip / live / event). Providers that support only some types validate
  the incoming type in add_favorite and reject the others
  (BadRequestError).
* Removing a non-existent favorite raises KeyError.
* Backend failures raise a ProviderError subclass from base.errors.

VERIFY the imports and signatures below against
base/provider_mixins/favorites.py (ProviderFavoritesMixin) and the
FavoritesManager ABC when you copy this file -- this scaffold mirrors the
bookmarks template and the README, not the ABC source.
"""

from typing import List, Optional

from ...base.managers import FavoritesManager
from ...base.models.favorite import Favorite, FavoriteType   # adjust path
from ...base.utils.logger import logger


class YourFavoritesManager(FavoritesManager):
    """Favorites for {TODO: provider name}."""

    def __init__(
        self,
        *,
        http_manager,
        auth,
        country,
        config,
        favorites_cache=None,
    ):
        super().__init__(
            http_manager=http_manager,
            auth=auth,
            country=country,
            config=config,
        )
        self._favorites_cache = (
            favorites_cache if favorites_cache is not None else {}
        )

    # ----- Abstract methods -----

    def get_favorites(self, **kw) -> List[Favorite]:
        """Return all favorites for the user. [] when there are none."""
        raise NotImplementedError("YourFavoritesManager.get_favorites")

    def add_favorite(
        self,
        content_id: str,
        favorite_type: Optional[FavoriteType] = None,
        **kw,
    ) -> Favorite:
        """
        Add a favorite.

        Reject unsupported FavoriteType values with BadRequestError.
        """
        raise NotImplementedError("YourFavoritesManager.add_favorite")

    def remove_favorite(self, content_id: str, **kw) -> None:
        """
        Remove a favorite.

        Raises:
            KeyError:      if no favorite exists for content_id.
            ProviderError: (a subclass) on backend failure.
        """
        raise NotImplementedError("YourFavoritesManager.remove_favorite")