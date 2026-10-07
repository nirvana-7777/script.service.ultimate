# streaming_providers/base/managers/bookmarks.py
"""
BookmarksManager ABC.

Public interface
----------------
    get_bookmarks(**kw)                                 -> List[Bookmark]   [abstract]
    update_bookmark(content_id, position_seconds, ...)  -> Bookmark         [abstract]
    delete_bookmark(content_id, **kw)                   -> None             [abstract]

Constructor contract
--------------------
Four required keyword-only collaborators.

Return-value conventions
------------------------
get_bookmarks returns [] when the user has no bookmarks. Not an error.

update_bookmark raises OperationFailedError if the provider rejects the write
(e.g. content inaccessible, backend error). It is called on every
playback stop / pause, so providers should tolerate a write that
overwrites the same position with a no-op rather than failing.

delete_bookmark raises ItemNotFoundError if no bookmark exists for
content_id, so callers can distinguish "already gone" from "successfully
deleted". The base ProviderBookmarksMixin documents the same rule (as
KeyError; ItemNotFoundError is a KeyError subclass).

ItemNotFoundError is both a NotFoundError (ProviderError) and a KeyError, and
OperationFailedError is both a ProviderError and a RuntimeError, so handlers
written against the old KeyError / RuntimeError convention keep working.

Caller guidance
---------------
`position_seconds = -1` marks the content as completed. A position
that reaches the model's COMPLETION_THRESHOLD (>= 95% by default) is
also treated as completed by the caller -- providers just store what
they are given.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, List, Optional

from ..models.bookmark import Bookmark, ContentType
from ._base import ManagerBase


class BookmarksManager(ManagerBase):
    """Abstract base for provider bookmarks managers."""

    # ------------------------------------------------------------------
    # Abstract
    # ------------------------------------------------------------------

    @abstractmethod
    def get_bookmarks(self, **kw: Any) -> List[Bookmark]:
        """
        Return all bookmarks for the authenticated user.

        Return [] when the user has no bookmarks.
        """
        raise NotImplementedError

    @abstractmethod
    def update_bookmark(
        self,
        content_id: str,
        position_seconds: int,
        content_type: ContentType,
        duration_seconds: Optional[int] = None,
        title: Optional[str] = None,
        **kw: Any,
    ) -> Bookmark:
        """
        Save or update a bookmark.

        Called on playback stop / pause, so should be tolerant of
        repeated writes to the same position (a no-op write is fine).

        Raises OperationFailedError (also a RuntimeError) if the provider
        rejects the write.
        """
        raise NotImplementedError

    @abstractmethod
    def delete_bookmark(self, content_id: str, **kw: Any) -> None:
        """
        Delete a bookmark.

        Raises:
            ItemNotFoundError:    if no bookmark exists for content_id
                                  (also a KeyError).
            OperationFailedError: on backend failure (also a RuntimeError).
        """
        raise NotImplementedError