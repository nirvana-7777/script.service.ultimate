# streaming_providers/base/bookmark_operations.py
"""
Bookmark-related operations separated from core registry.
Mirrors the structure of RecordingOperations.
"""

from typing import Dict, List, Optional

from .models.bookmark import Bookmark, ContentType, ValidationLevel
from .utils.logger import logger


_VALID_SORT_FIELDS = {"last_updated", "created_at", "title", "provider"}


class BookmarkOperations:
    """Handles all bookmark-related operations."""

    def __init__(self, registry):
        self.registry = registry
        logger.debug("BookmarkOperations: Initialized")

    # ==========================================================================
    # SINGLE PROVIDER OPERATIONS
    # ==========================================================================

    def get_bookmarks(
        self,
        provider_name: str,
        content_type: Optional[ContentType] = None,
        include_completed: bool = False,
        include_stale: bool = False,
        max_age_hours: int = 720,
    ) -> List[Bookmark]:
        """
        Get bookmarks from a specific provider.

        Args:
            provider_name: Name of the provider to query.
            content_type: Optional filter by content type (LIVE, VOD, EVENT, etc.).
            include_completed: If True, include bookmarks marked as completed.
                              If False, completed bookmarks are filtered out.
            include_stale: If True, include bookmarks older than max_age_hours.
                          If False, stale bookmarks are filtered out.
            max_age_hours: Maximum age in hours before a bookmark is considered stale.
                          Only used when include_stale=False.

        Returns:
            List of Bookmark objects.

        Raises:
            ValueError: If the provider is not found or disabled.
        """
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        # Check if provider supports bookmarks
        if not provider.implements_bookmarks:
            logger.debug(
                f"Provider '{provider_name}' does not implement bookmarks, returning empty list"
            )
            return []

        # Fetch bookmarks from provider
        bookmarks = provider.get_bookmarks()

        # Apply filters
        filtered = []
        for bookmark in bookmarks:
            # Filter by content type
            if content_type and bookmark.content_type != content_type:
                continue

            # Filter out completed bookmarks if requested
            if not include_completed and bookmark.is_completed:
                continue

            # Filter out stale bookmarks if requested
            if not include_stale and bookmark.is_stale(max_age_hours):
                continue

            filtered.append(bookmark)

        logger.info(
            f"Retrieved {len(filtered)} bookmarks from '{provider_name}' "
            f"(filtered from {len(bookmarks)} total)"
        )
        return filtered

    def get_bookmark(
        self, provider_name: str, content_id: str
    ) -> Optional[Bookmark]:
        """
        Get a specific bookmark by content ID from a provider.

        Completed and stale bookmarks are included so that a bookmark is never
        silently missed just because it is old or finished.

        Args:
            provider_name: Name of the provider.
            content_id: Content identifier.

        Returns:
            Bookmark object if found, None otherwise.

        Raises:
            ValueError: If the provider is not found or disabled.
        """
        bookmarks = self.get_bookmarks(
            provider_name, include_completed=True, include_stale=True
        )
        for bookmark in bookmarks:
            if bookmark.content_id == content_id:
                return bookmark
        return None

    def update_bookmark(
        self,
        provider_name: str,
        content_id: str,
        content_type: ContentType,
        position_seconds: int,
        duration_seconds: Optional[int] = None,
        title: Optional[str] = None,
        **kwargs,
    ) -> Optional[Bookmark]:
        """
        Update or create a bookmark for a specific content.

        Args:
            provider_name: Name of the provider.
            content_id: Content identifier.
            content_type: Type of content (required — callers always know what
                          they are bookmarking; avoids costly provider API calls
                          to infer the type).
            position_seconds: Playback position in seconds (0 = start, -1 = completed).
                              Content is also considered complete once position
                              reaches the model's COMPLETION_THRESHOLD (≥ 95 % by
                              default), so an explicit -1 is not strictly required.
            duration_seconds: Total duration of the content (optional but recommended).
            title: Content title for caching (optional).
            **kwargs: Additional metadata (thumbnail_url, series_title, etc.).

        Returns:
            Updated Bookmark object, or None if provider doesn't support bookmarks.

        Raises:
            ValueError: If the provider is not found or disabled, or if
                        position_seconds is out of range.
            RuntimeError: If the provider rejects the update.
        """
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        if not provider.implements_bookmarks:
            logger.warning(
                f"Provider '{provider_name}' does not implement bookmarks, "
                f"cannot update bookmark for '{content_id}'"
            )
            return None

        if position_seconds < -1:
            raise ValueError(
                f"position_seconds must be >= -1, got {position_seconds}"
            )

        try:
            bookmark = provider.update_bookmark(
                content_id=content_id,
                position_seconds=position_seconds,
                duration_seconds=duration_seconds,
                title=title,
                content_type=content_type,
                **kwargs,
            )

            logger.info(
                f"Updated bookmark for '{content_id}' from '{provider_name}' "
                f"at position {position_seconds}s"
            )
            return bookmark

        except Exception as e:
            logger.error(f"Failed to update bookmark for '{content_id}': {e}")
            raise RuntimeError(f"Provider rejected bookmark update: {e}") from e

    def delete_bookmark(
        self, provider_name: str, content_id: str
    ) -> bool:
        """
        Delete a bookmark from a specific provider.

        Args:
            provider_name: Name of the provider.
            content_id: Content identifier.

        Returns:
            True if deleted, False if bookmark didn't exist or provider doesn't support.

        Raises:
            ValueError: If the provider is not found or disabled.
            RuntimeError: If the provider refuses deletion.
        """
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        if not provider.implements_bookmarks:
            logger.debug(
                f"Provider '{provider_name}' does not implement bookmarks, "
                f"cannot delete bookmark for '{content_id}'"
            )
            return False

        try:
            provider.delete_bookmark(content_id=content_id)
            logger.info(f"Deleted bookmark for '{content_id}' from '{provider_name}'")
            return True
        except KeyError:
            logger.debug(f"Bookmark for '{content_id}' not found on '{provider_name}'")
            return False
        except Exception as e:
            logger.error(f"Failed to delete bookmark for '{content_id}': {e}")
            raise RuntimeError(f"Provider refused bookmark deletion: {e}") from e

    def mark_completed(
        self,
        provider_name: str,
        content_id: str,
        content_type: ContentType,
        duration_seconds: Optional[int] = None,
        title: Optional[str] = None,
        **kwargs,
    ) -> Optional[Bookmark]:
        """
        Mark a content as completed (watched to end).

        Sets position to -1, which the Bookmark model treats as explicitly
        completed. Note that the model also considers content complete once
        playback reaches the COMPLETION_THRESHOLD (≥ 95 % by default), so
        this method is only needed when an explicit completion event occurs
        before that threshold is reached.

        Args:
            provider_name: Name of the provider.
            content_id: Content identifier.
            content_type: Type of content.
            duration_seconds: Total duration (optional).
            title: Content title (optional).
            **kwargs: Additional metadata.

        Returns:
            Updated Bookmark with position set to -1, or None if not supported.

        Raises:
            ValueError: If the provider is not found or disabled.
        """
        return self.update_bookmark(
            provider_name=provider_name,
            content_id=content_id,
            content_type=content_type,
            position_seconds=-1,
            duration_seconds=duration_seconds,
            title=title,
            **kwargs,
        )

    # ==========================================================================
    # AGGREGATE OPERATIONS (ALL PROVIDERS)
    # ==========================================================================

    def get_all_bookmarks(
        self,
        content_type: Optional[ContentType] = None,
        include_completed: bool = False,
        include_stale: bool = False,
        max_age_hours: int = 720,
    ) -> Dict[str, List[Bookmark]]:
        """
        Get bookmarks from all enabled providers.

        Args:
            content_type: Optional filter by content type.
            include_completed: If True, include completed bookmarks.
            include_stale: If True, include stale bookmarks.
            max_age_hours: Maximum age for stale detection (when include_stale=False).

        Returns:
            Dict mapping provider name → list of Bookmark objects.
            Failed providers map to an empty list; check the 'errors' log for
            details, or use the 'errors' key in the returned dict if you need
            programmatic access to failures.

            Note: An empty list means either the provider has no bookmarks OR
            the provider failed. To distinguish these cases, consult the
            'errors' entry in the returned dict (present only on failure).
        """
        enabled = self.registry.get_enabled_providers()
        logger.info(f"Fetching bookmarks from {len(enabled)} providers")

        result: Dict[str, List[Bookmark]] = {}
        errors: Dict[str, str] = {}
        total = 0

        for name in enabled:
            try:
                bookmarks = self.get_bookmarks(
                    provider_name=name,
                    content_type=content_type,
                    include_completed=include_completed,
                    include_stale=include_stale,
                    max_age_hours=max_age_hours,
                )
                result[name] = bookmarks
                total += len(bookmarks)
            except Exception as e:
                logger.error(f"Failed to get bookmarks from '{name}': {e}")
                result[name] = []
                errors[name] = str(e)

        if errors:
            result["_errors"] = errors  # type: ignore[assignment]

        logger.info(f"Retrieved {total} total bookmarks")
        return result

    def get_all_bookmarks_flat(
        self,
        content_type: Optional[ContentType] = None,
        include_completed: bool = False,
        include_stale: bool = False,
        max_age_hours: int = 720,
        sort_by: str = "last_updated",
    ) -> List[Bookmark]:
        """
        Get all bookmarks as a flat list sorted by the specified field.

        Args:
            content_type: Optional filter by content type.
            include_completed: If True, include completed bookmarks.
            include_stale: If True, include stale bookmarks.
            max_age_hours: Maximum age for stale detection.
            sort_by: Sort field. Must be one of: 'last_updated', 'created_at',
                     'title', 'provider'. Date fields sort descending (newest
                     first); string fields sort ascending.

        Returns:
            Flat list of Bookmark objects sorted by sort_by.

        Raises:
            ValueError: If sort_by is not a recognised field.
        """
        if sort_by not in _VALID_SORT_FIELDS:
            raise ValueError(
                f"Invalid sort_by '{sort_by}'. Must be one of: "
                f"{sorted(_VALID_SORT_FIELDS)}"
            )

        all_bookmarks = self.get_all_bookmarks(
            content_type=content_type,
            include_completed=include_completed,
            include_stale=include_stale,
            max_age_hours=max_age_hours,
        )

        # Flatten, skipping the internal _errors sentinel key
        flat_list: List[Bookmark] = []
        for key, bookmarks in all_bookmarks.items():
            if key == "_errors":
                continue
            flat_list.extend(bookmarks)  # type: ignore[arg-type]

        if sort_by == "last_updated":
            flat_list.sort(key=lambda b: b.last_updated, reverse=True)
        elif sort_by == "created_at":
            flat_list.sort(key=lambda b: b.created_at, reverse=True)
        elif sort_by == "title":
            flat_list.sort(key=lambda b: b.title or "")
        elif sort_by == "provider":
            flat_list.sort(key=lambda b: b.provider)

        return flat_list

    # ==========================================================================
    # BULK OPERATIONS
    # ==========================================================================

    def cleanup_stale_bookmarks(
        self,
        max_age_hours: int = 720,
        dry_run: bool = True,
        provider_filter: Optional[List[str]] = None,
    ) -> Dict[str, int]:
        """
        Remove bookmarks older than max_age_hours.

        Args:
            max_age_hours: Age threshold in hours (default 720 = 30 days).
            dry_run: If True, only report what would be deleted without actually deleting.
            provider_filter: Optional list of provider names to restrict cleanup.

        Returns:
            Dict mapping provider name → number of bookmarks deleted
            (or would-be deleted for dry_run).
        """
        enabled = self.registry.get_enabled_providers()
        if provider_filter:
            enabled = [p for p in enabled if p in provider_filter]

        results = {}

        for name in enabled:
            try:
                # include_stale=False so get_bookmarks returns only stale ones,
                # and include_completed=True so completed-but-stale entries are
                # also cleaned up.
                stale = self.get_bookmarks(
                    provider_name=name,
                    include_completed=True,
                    include_stale=False,
                    max_age_hours=max_age_hours,
                )

                if dry_run:
                    results[name] = len(stale)
                    if stale:
                        logger.info(
                            f"[DRY RUN] Would delete {len(stale)} stale bookmarks "
                            f"from '{name}'"
                        )
                else:
                    deleted = 0
                    for bookmark in stale:
                        try:
                            self.delete_bookmark(name, bookmark.content_id)
                            deleted += 1
                        except Exception as e:
                            logger.error(
                                f"Failed to delete stale bookmark '{bookmark.content_id}' "
                                f"from '{name}': {e}"
                            )
                    results[name] = deleted
                    if deleted:
                        logger.info(f"Deleted {deleted} stale bookmarks from '{name}'")

            except Exception as e:
                logger.error(f"Failed to cleanup bookmarks from '{name}': {e}")
                results[name] = 0

        return results

    def delete_all_bookmarks_for_content(
        self, content_id: str, provider_filter: Optional[List[str]] = None
    ) -> Dict[str, bool]:
        """
        Delete bookmarks for a specific content ID across all providers.

        Useful when content is removed from a provider. delete_bookmark() handles
        the not-found case gracefully (returns False), so no existence pre-check
        is needed.

        Args:
            content_id: Content identifier to delete.
            provider_filter: Optional list of provider names to restrict deletion.

        Returns:
            Dict mapping provider name → True if deleted, False if not found or
            provider doesn't support bookmarks.
        """
        enabled = self.registry.get_enabled_providers()
        if provider_filter:
            enabled = [p for p in enabled if p in provider_filter]

        results = {}

        for name in enabled:
            try:
                results[name] = self.delete_bookmark(name, content_id)
            except Exception as e:
                logger.error(
                    f"Failed to delete bookmark for '{content_id}' from '{name}': {e}"
                )
                results[name] = False

        return results

    # ==========================================================================
    # STATISTICS AND UTILITIES
    # ==========================================================================

    def get_bookmark_stats(self, max_age_hours: int = 720) -> Dict:
        """
        Get statistics about bookmarks across all providers.

        Args:
            max_age_hours: Age threshold used for staleness classification.
                           Should match the value used in get_bookmarks() calls
                           so that stats are consistent with filtering behaviour.

        Returns:
            Dictionary with counts by status, content type, and provider.
        """
        all_bookmarks = self.get_all_bookmarks(include_completed=True, include_stale=True)

        stats = {
            "total": 0,
            "completed": 0,
            "in_progress": 0,
            "stale": 0,
            "by_content_type": {},
            "by_provider": {},
        }

        for provider, bookmarks in all_bookmarks.items():
            if provider == "_errors":
                continue
            stats["by_provider"][provider] = len(bookmarks)
            stats["total"] += len(bookmarks)

            for bookmark in bookmarks:  # type: ignore[union-attr]
                if bookmark.is_completed:
                    stats["completed"] += 1
                else:
                    stats["in_progress"] += 1

                if bookmark.is_stale(max_age_hours):
                    stats["stale"] += 1

                ct = bookmark.content_type.value
                stats["by_content_type"][ct] = stats["by_content_type"].get(ct, 0) + 1

        return stats

    def validate_bookmarks(
        self, provider_name: str, auto_fix: bool = False
    ) -> Dict:
        """
        Validate all bookmarks from a provider and optionally fix common issues.

        Args:
            provider_name: Name of the provider.
            auto_fix: If True, attempt to fix fixable issues (e.g., position
                      exceeding duration). Note that the corrected position is
                      clipped to just below the model's COMPLETION_THRESHOLD so
                      that the auto-fix does not inadvertently mark content as
                      complete.

        Returns:
            Dictionary with validation results::

                {
                    "total":    int,
                    "errors":   List[Dict],   # fatal issues
                    "warnings": List[Dict],   # non-fatal issues
                    "fixed":    int,          # number of bookmarks auto-fixed
                }
        """
        bookmarks = self.get_bookmarks(
            provider_name, include_completed=True, include_stale=True
        )

        results: Dict = {
            "total": len(bookmarks),
            "errors": [],
            "warnings": [],
            "fixed": 0,
        }

        for bookmark in bookmarks:
            issues = bookmark.validate()
            for level, message in issues:
                issue_info = {
                    "bookmark_id": bookmark.bookmark_id,
                    "content_id": bookmark.content_id,
                    "message": message,
                }

                if level == ValidationLevel.ERROR:
                    results["errors"].append(issue_info)
                else:
                    results["warnings"].append(issue_info)

                if auto_fix and level == ValidationLevel.WARNING:
                    if "exceeds duration" in message and bookmark.duration_seconds:
                        # Clip to just below the completion threshold so the fix
                        # does not accidentally mark the content as complete.
                        safe_max = int(
                            bookmark.duration_seconds
                            * bookmark.COMPLETION_THRESHOLD
                        ) - 1
                        fixed_position = min(bookmark.position_seconds, safe_max)
                        try:
                            self.update_bookmark(
                                provider_name,
                                bookmark.content_id,
                                bookmark.content_type,
                                fixed_position,
                                bookmark.duration_seconds,
                            )
                            results["fixed"] += 1
                        except Exception:
                            pass

        return results