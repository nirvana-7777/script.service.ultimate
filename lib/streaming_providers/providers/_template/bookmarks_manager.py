# streaming_providers/providers/_template/bookmarks_manager.py
"""
{TODO: Provider name} bookmarks manager (optional).

Include this file only if the provider supports resume positions.
Providers without bookmarks don't create a bookmarks manager -- the
provider's implements_bookmarks is False and calls to get_bookmarks
return [].

See ../_template/README.md for the contract.

Reference implementation
------------------------
No existing provider implements bookmarks today. The base mixin
ProviderBookmarksMixin (base/provider_mixins/bookmarks.py) documents
the shape callers expect. Read it before writing yours -- the
semantics of position_seconds = -1, the COMPLETION_THRESHOLD, and the
KeyError on delete-missing are all there.

Call frequency
--------------
update_bookmark is called on every playback stop / pause, often
consecutively for the same position. Providers should tolerate
repeated no-op writes to the same position without erroring or
firing spurious events.
"""

from typing import Any, List, Optional

from ...base.managers import BookmarksManager
from ...base.models.bookmark import Bookmark, ContentType
from ...base.utils.logger import logger


class YourBookmarksManager(BookmarksManager):
    """Bookmarks for {TODO: provider name}."""

    def __init__(
        self,
        *,
        http_manager,
        auth,
        country,
        config,
        bookmarks_cache=None,
    ):
        super().__init__(
            http_manager=http_manager,
            auth=auth,
            country=country,
            config=config,
        )
        self._bookmarks_cache = (
            bookmarks_cache if bookmarks_cache is not None else {}
        )

    # ----- Abstract methods -----

    def get_bookmarks(self, **kw) -> List[Bookmark]:
        """Return all bookmarks for the user. [] when there are none."""
        raise NotImplementedError("YourBookmarksManager.get_bookmarks")

    def update_bookmark(
        self,
        content_id: str,
        position_seconds: int,
        content_type: ContentType,
        duration_seconds: Optional[int] = None,
        title: Optional[str] = None,
        **kw,
    ) -> Bookmark:
        """
        Save or update a bookmark. Called on playback stop / pause.

        position_seconds = -1 marks the content as completed.

        Raises RuntimeError if the provider rejects.
        """
        raise NotImplementedError("YourBookmarksManager.update_bookmark")

    def delete_bookmark(self, content_id: str, **kw) -> None:
        """
        Delete a bookmark.

        Raises:
            KeyError:     if no bookmark exists for content_id.
            RuntimeError: on backend failure.
        """
        raise NotImplementedError("YourBookmarksManager.delete_bookmark")