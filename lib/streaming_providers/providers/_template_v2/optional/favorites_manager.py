# streaming_providers/providers/example/favorites_manager.py
"""
Favorites manager skeleton.

--- WIRING ---
from .favorites_manager import ExampleFavoritesManager
def _build_favorites(self):
    return ExampleFavoritesManager(http_manager=self.http_manager, auth=self.auth,
                                   country=self.country, config=self.provider_config)
--- END WIRING ---

Contract: get_favorites -> [] when empty (not an error); add_favorite returns
the Favorite (FavoriteType: PROGRAM, CLIP, LIVE, EVENT -- there is no
CHANNEL) and raises OperationFailedError on refusal; remove_favorite raises
ItemNotFoundError (also a KeyError: the backend's FavoriteOperations catches
KeyError -> False) when it is not favorited. The backend calls add/remove by
KEYWORD (content_id=, favorite_type=, title=).
"""

from typing import Any, List, Optional

from ....base.errors import ItemNotFoundError
from ....base.managers import FavoritesManager
from ....base.models.favorite import Favorite, FavoriteType


class ExampleFavoritesManager(FavoritesManager):
    def get_favorites(self, **kw: Any) -> List[Favorite]:
        return []            # TODO

    def add_favorite(
        self,
        content_id: str,
        favorite_type: FavoriteType = FavoriteType.PROGRAM,
        title: Optional[str] = None,
        **kw: Any,
    ) -> Favorite:
        # TODO: call the backend, then return the saved Favorite
        return Favorite.create("example", content_id, favorite_type, title)

    def remove_favorite(self, content_id: str, **kw: Any) -> None:
        raise ItemNotFoundError(content_id)    # TODO
