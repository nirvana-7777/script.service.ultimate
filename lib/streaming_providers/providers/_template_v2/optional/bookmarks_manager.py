# streaming_providers/providers/example/bookmarks_manager.py
"""
Bookmarks (resume position) manager skeleton.

--- WIRING ---
from .bookmarks_manager import ExampleBookmarksManager
def _build_bookmarks(self):
    return ExampleBookmarksManager(http_manager=self.http_manager, auth=self.auth,
                                   country=self.country, config=self.provider_config)
--- END WIRING ---

Contract: update_bookmark is called on EVERY playback stop/pause, so a
repeated write of the same position must be a harmless no-op.
position_seconds: 0 = start, -1 = completed (>= 95 % counts as completed too;
providers just store what they get). Parameter order is
(content_id, position_seconds, content_type, ...) -- the ProviderManager
facade uses (content_type, position_seconds); callers must use KEYWORDS (the
backend does). delete_bookmark raises ItemNotFoundError (also a KeyError).
"""

from typing import Any, List, Optional

from ....base.errors import ItemNotFoundError
from ....base.managers import BookmarksManager
from ....base.models.bookmark import Bookmark, ContentType


class ExampleBookmarksManager(BookmarksManager):
    def get_bookmarks(self, **kw: Any) -> List[Bookmark]:
        return []            # TODO

    def update_bookmark(
        self,
        content_id: str,
        position_seconds: int,
        content_type: ContentType,
        duration_seconds: Optional[int] = None,
        title: Optional[str] = None,
        **kw: Any,
    ) -> Bookmark:
        # TODO: persist, then return the confirmed Bookmark
        return Bookmark.create(
            "example", content_id, content_type, position_seconds, duration_seconds, title
        )

    def delete_bookmark(self, content_id: str, **kw: Any) -> None:
        raise ItemNotFoundError(content_id)    # TODO
