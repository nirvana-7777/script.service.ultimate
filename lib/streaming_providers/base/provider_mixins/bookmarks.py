"""Provider bookmark (resume-position) mixin."""

from typing import Any, Dict, List, Optional

from ..models.bookmark import Bookmark, ContentType


class ProviderBookmarksMixin:
    @property
    def implements_bookmarks(self) -> bool:
        """
        True if this provider can store/retrieve playback positions.

        Return False (default) for providers that do not have bookmark /
        continue-watching functionality.  BookmarkOperations will skip
        providers where this returns False when aggregating across all
        providers.

        Providers that support bookmarks should override this to return True
        and implement get_bookmarks(), update_bookmark(), and
        delete_bookmark().
        """
        return False

    def get_bookmarks(self, **kwargs) -> List[Bookmark]:
        """
        Return all bookmarks for the authenticated user.

        This method should fetch the user's continue-watching list or
        playback positions from the provider's backend.

        Args:
            **kwargs: Provider-specific filtering options (e.g., content_type,
                      limit, offset).

        Returns:
            List of Bookmark objects, or [] if bookmarks are not supported
            or none exist.

        Note:
            The returned Bookmark objects should have their content_type field
            properly set (LIVE, VOD, EVENT, RECORDING, etc.) so that the
            client can correctly resolve the content.

        Default implementation returns an empty list.  Override in provider
        plugins that support bookmark storage.
        """
        return []

    def update_bookmark(
        self,
        content_id: str,
        position_seconds: int,
        content_type: ContentType,
        duration_seconds: Optional[int] = None,
        title: Optional[str] = None,
        **kwargs,
    ) -> Bookmark:
        """
        Save or update a bookmark for specific content.

        This method is called automatically when playback stops or pauses.
        The provider should store the position and associate it with the
        authenticated user.

        Args:
            content_id:       The content being watched (channel ID, VOD ID,
                              etc.).
            position_seconds: Where playback stopped in seconds from start.
                              0 = not started / start of content.
                              -1 = explicitly marked as completed.
                              Content is also considered complete once position
                              reaches the model's COMPLETION_THRESHOLD
                              (>=95% by default).
            content_type:     Type of content being bookmarked.  Required —
                              callers always know what they are bookmarking,
                              so this is never None.
            duration_seconds: Total duration of the content (optional but
                              recommended for progress calculations).
            title:            Content title for caching (optional — provider
                              may ignore and use its own metadata store).
            **kwargs:         Provider-specific arguments (e.g., episode
                              number, season number, series ID).

        Returns:
            The saved Bookmark object as confirmed by the provider.

        Raises:
            RuntimeError: If the provider rejects the bookmark (e.g. user not
                          authenticated, content not accessible).

        Note:
            At minimum the provider should persist content_id and
            position_seconds so that get_bookmarks() can later return this
            bookmark.

        Default implementation raises NotImplementedError so misconfigured
        providers fail loudly rather than silently doing nothing.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement update_bookmark(). "
            "Override this method to support bookmark storage."
        )

    def delete_bookmark(self, content_id: str, **kwargs) -> None:
        """
        Delete a bookmark from the provider's backend.

        Called when:
        - User manually removes a bookmark from "Continue Watching"
        - Content is removed from the provider
        - Cleanup of stale bookmarks

        Args:
            content_id: The content identifier whose bookmark should be
                        removed.
            **kwargs:   Provider-specific arguments.

        Returns:
            None on success.

        Raises:
            KeyError:     If no bookmark with this content_id exists.
            RuntimeError: If the provider refuses deletion (e.g. permission
                          denied, backend error).

        Note:
            Deleting a non-existent bookmark must raise KeyError rather than
            silently succeeding, so that callers can distinguish "already
            gone" from "successfully deleted".

        Default implementation raises NotImplementedError so misconfigured
        providers fail loudly.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement delete_bookmark(). "
            "Override this method to support bookmark deletion."
        )

    # =========================================================================
    # BOOKMARK HELPER METHODS (Optional overrides)
    # =========================================================================

    def batch_update_bookmarks(
        self, updates: List[Dict[str, Any]], **kwargs
    ) -> List[Bookmark]:
        """
        Update multiple bookmarks in a single batch operation.

        Useful for synchronising local bookmark state with the provider
        backend, or for bulk writes after a playback session.

        Args:
            updates: List of dictionaries, each containing::

                {
                    "content_id":       str,
                    "position_seconds": int,
                    "content_type":     ContentType,
                    "duration_seconds": Optional[int],
                    "title":            Optional[str],
                    ... (other provider-specific kwargs)
                }

            **kwargs: Provider-specific batch options passed to every
                      individual update_bookmark() call.

        Returns:
            List of updated Bookmark objects in the same order as ``updates``.
            If an individual update fails, the exception propagates and the
            list contains only the bookmarks that succeeded before the
            failure.

        Raises:
            RuntimeError: If the batch operation fails partially or completely.

        Note:
            The default implementation falls back to individual
            update_bookmark() calls and does **not** mutate the dicts in
            ``updates``.  Override if your provider supports a native batch
            endpoint for efficiency.
        """
        results = []
        for raw in updates:
            # Work on a copy so the caller's dicts are never mutated.
            update = raw.copy()
            content_id = update.pop("content_id")
            position_seconds = update.pop("position_seconds")
            content_type = update.pop("content_type")
            duration_seconds = update.pop("duration_seconds", None)
            title = update.pop("title", None)

            result = self.update_bookmark(
                content_id=content_id,
                position_seconds=position_seconds,
                content_type=content_type,
                duration_seconds=duration_seconds,
                title=title,
                **update,
                **kwargs,
            )
            results.append(result)

        return results