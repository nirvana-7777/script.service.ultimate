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

update_bookmark raises RuntimeError if the provider rejects the write
(e.g. content inaccessible, backend error). It is called on every
playback stop / pause, so providers should tolerate a write that
overwrites the same position with a no-op rather than failing.

delete_bookmark raises KeyError if no bookmark exists for content_id,
so callers can distinguish "already gone" from "successfully deleted".
The base ProviderBookmarksMixin documents the same rule.

Caller guidance
---------------
`position_seconds = -1` marks the content as completed. A position
that reaches the model's COMPLETION_THRESHOLD (>= 95% by default) is
also treated as completed by the caller -- providers just store what
they are given.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, List, Optional

from ..models.bookmark import Bookmark, ContentType
from ..protocols import AuthProtocol
from ..utils.logger import logger


class BookmarksManager(ABC):
    """Abstract base for provider bookmarks managers."""

    def __init__(
        self,
        *,
        http_manager: Any,
        auth: AuthProtocol,
        country: str,
        config: Any,
    ) -> None:
        if not isinstance(auth, AuthProtocol):
            logger.warning(
                f"{self.__class__.__name__}: auth does not match AuthProtocol "
                f"(missing one of get_access_token / build_headers / "
                f"invalidate). Got {type(auth).__name__}."
            )
        self.http_manager = http_manager
        self.auth = auth
        self.country = country
        self.config = config

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

        Raises RuntimeError if the provider rejects the write.
        """
        raise NotImplementedError

    @abstractmethod
    def delete_bookmark(self, content_id: str, **kw: Any) -> None:
        """
        Delete a bookmark.

        Raises:
            KeyError:     if no bookmark exists for content_id.
            RuntimeError: on backend failure.
        """
        raise NotImplementedError