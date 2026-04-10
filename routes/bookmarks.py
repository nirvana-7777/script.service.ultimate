#!/usr/bin/env python3
"""
Bookmark-related route handlers.
Mirrors the structure of recordings.py.
"""

from bottle import request, response
from streaming_providers.base.models.bookmark import ContentType
from streaming_providers.base.utils import logger


def setup_bookmarks_routes(app, manager, service):
    """Setup bookmark-related routes."""

    # ==========================================================================
    # SINGLE PROVIDER ROUTES
    # ==========================================================================

    @app.route("/api/providers/<provider>/bookmarks", method="GET")
    def get_provider_bookmarks(provider):
        """
        Get bookmarks from a specific provider.

        Query parameters:
        - content_type: Optional (LIVE, VOD, EVENT, RECORDING, SERIES, RADIO)
        - include_completed: Optional bool (true/false) — default false
        - include_stale: Optional bool (true/false) — default false
        - max_age_hours: Optional int — default 720 (30 days)

        Returns:
        {
            "provider": "provider_name",
            "bookmarks": [ { ...Bookmark fields... } ],
            "count": 1,
            "filters": {
                "content_type": null,
                "include_completed": false,
                "include_stale": false,
                "max_age_hours": 720
            }
        }
        """
        try:
            content_type_str = request.params.get("content_type")
            content_type = None
            if content_type_str:
                try:
                    content_type = ContentType(content_type_str.upper())
                except ValueError:
                    response.status = 400
                    return {
                        "error": "Invalid content_type",
                        "message": f"content_type must be one of: {[ct.value for ct in ContentType]}",
                        "provider": provider,
                    }

            include_completed = request.params.get("include_completed", "false").lower() in (
                "1", "true", "yes"
            )
            include_stale = request.params.get("include_stale", "false").lower() in (
                "1", "true", "yes"
            )

            try:
                max_age_hours = int(request.params.get("max_age_hours", "720"))
                if max_age_hours < 0:
                    raise ValueError
            except ValueError:
                response.status = 400
                return {
                    "error": "Invalid max_age_hours",
                    "message": "max_age_hours must be a non-negative integer",
                    "provider": provider,
                }

            try:
                bookmarks = manager.get_bookmarks(
                    provider_name=provider,
                    content_type=content_type,
                    include_completed=include_completed,
                    include_stale=include_stale,
                    max_age_hours=max_age_hours,
                )
            except ValueError as e:
                response.status = 404
                return {
                    "error": "Provider not found",
                    "message": str(e),
                    "provider": provider,
                }
            except Exception as e:
                logger.error(f"Failed to get bookmarks from '{provider}': {e}")
                response.status = 500
                return {
                    "error": "Failed to get bookmarks",
                    "message": str(e),
                    "provider": provider,
                }

            response.status = 200
            return {
                "provider": provider,
                "bookmarks": [b.to_dict(include_none=False) for b in bookmarks],
                "count": len(bookmarks),
                "filters": {
                    "content_type": content_type.value if content_type else None,
                    "include_completed": include_completed,
                    "include_stale": include_stale,
                    "max_age_hours": max_age_hours,
                },
            }

        except Exception as e:
            logger.error(f"Unexpected error in get_provider_bookmarks: {e}")
            response.status = 500
            return {"error": "Internal server error", "message": str(e), "provider": provider}

    @app.route("/api/providers/<provider>/bookmarks/<content_id>", method="GET")
    def get_provider_bookmark(provider, content_id):
        """
        Get a single bookmark by content ID from a specific provider.

        Returns:
        { ...Bookmark fields... }
        """
        try:
            try:
                bookmark = manager.get_bookmark(
                    provider_name=provider,
                    content_id=content_id,
                )
            except ValueError as e:
                response.status = 404
                return {"error": "Provider not found", "message": str(e), "provider": provider}
            except Exception as e:
                logger.error(f"Failed to get bookmark from '{provider}': {e}")
                response.status = 500
                return {
                    "error": "Failed to get bookmark",
                    "message": str(e),
                    "provider": provider,
                }

            if not bookmark:
                response.status = 404
                return {
                    "error": "Bookmark not found",
                    "message": f"No bookmark with content_id '{content_id}' from '{provider}'",
                    "provider": provider,
                    "content_id": content_id,
                }

            response.status = 200
            return bookmark.to_dict(include_none=False)

        except Exception as e:
            logger.error(f"Unexpected error in get_provider_bookmark: {e}")
            response.status = 500
            return {"error": "Internal server error", "message": str(e), "provider": provider}

    @app.route("/api/providers/<provider>/bookmarks/<content_id>", method="POST")
    def update_provider_bookmark(provider, content_id):
        """
        Update or create a bookmark for a specific content.

        Request body (JSON):
        {
            "content_type":    "VOD",          // Required
            "position_seconds": 120,           // Required: >= -1
            "duration_seconds": 3600,          // Optional: positive integer
            "title":           "Movie Title",  // Optional
            "thumbnail_url":   "https://...",  // Optional
            "series_title":    "Series Name",  // Optional
            "season_number":   1,              // Optional
            "episode_number":  5,              // Optional
            "episode_name":    "Episode Title",// Optional
            "channel_name":    "Channel Name", // Optional
            "channel_logo":    "https://..."   // Optional
        }

        Returns:
        { ...Updated Bookmark fields... }
        """
        try:
            data = request.json
            if not data:
                response.status = 400
                return {
                    "error": "Invalid request",
                    "message": "Request body is required",
                    "provider": provider,
                    "content_id": content_id,
                }

            # --- content_type (required) ---
            content_type_str = data.get("content_type")
            if not content_type_str:
                response.status = 400
                return {
                    "error": "Missing required field",
                    "message": "content_type is required",
                    "provider": provider,
                    "content_id": content_id,
                }
            try:
                content_type = ContentType(content_type_str.upper())
            except ValueError:
                response.status = 400
                return {
                    "error": "Invalid content_type",
                    "message": f"content_type must be one of: {[ct.value for ct in ContentType]}",
                    "provider": provider,
                    "content_id": content_id,
                }

            # --- position_seconds (required) ---
            position_seconds = data.get("position_seconds")
            if position_seconds is None:
                response.status = 400
                return {
                    "error": "Missing required field",
                    "message": "position_seconds is required",
                    "provider": provider,
                    "content_id": content_id,
                }
            try:
                position_seconds = int(position_seconds)
                if position_seconds < -1:
                    raise ValueError
            except ValueError:
                response.status = 400
                return {
                    "error": "Invalid position_seconds",
                    "message": "position_seconds must be an integer >= -1",
                    "provider": provider,
                    "content_id": content_id,
                }

            # --- duration_seconds (optional, must be positive if present) ---
            duration_seconds = data.get("duration_seconds")
            if duration_seconds is not None:
                try:
                    duration_seconds = int(duration_seconds)
                    if duration_seconds <= 0:
                        raise ValueError
                except ValueError:
                    response.status = 400
                    return {
                        "error": "Invalid duration_seconds",
                        "message": "duration_seconds must be a positive integer",
                        "provider": provider,
                        "content_id": content_id,
                    }

            try:
                bookmark = manager.update_bookmark(
                    provider_name=provider,
                    content_id=content_id,
                    content_type=content_type,
                    position_seconds=position_seconds,
                    duration_seconds=duration_seconds,
                    title=data.get("title"),
                    thumbnail_url=data.get("thumbnail_url"),
                    series_title=data.get("series_title"),
                    season_number=data.get("season_number"),
                    episode_number=data.get("episode_number"),
                    episode_name=data.get("episode_name"),
                    channel_name=data.get("channel_name"),
                    channel_logo=data.get("channel_logo"),
                )
            except ValueError as e:
                response.status = 404
                return {
                    "error": "Provider not found",
                    "message": str(e),
                    "provider": provider,
                    "content_id": content_id,
                }
            except RuntimeError as e:
                response.status = 409
                return {
                    "error": "Bookmark update rejected",
                    "message": str(e),
                    "provider": provider,
                    "content_id": content_id,
                }
            except Exception as e:
                logger.error(f"Failed to update bookmark '{content_id}' from '{provider}': {e}")
                response.status = 500
                return {
                    "error": "Failed to update bookmark",
                    "message": str(e),
                    "provider": provider,
                    "content_id": content_id,
                }

            if bookmark is None:
                response.status = 501
                return {
                    "error": "Bookmarks not supported",
                    "message": f"Provider '{provider}' does not support bookmarks",
                    "provider": provider,
                    "content_id": content_id,
                }

            response.status = 200
            return bookmark.to_dict(include_none=False)

        except Exception as e:
            logger.error(f"Unexpected error in update_provider_bookmark: {e}")
            response.status = 500
            return {
                "error": "Internal server error",
                "message": str(e),
                "provider": provider,
                "content_id": content_id,
            }

    @app.route("/api/providers/<provider>/bookmarks/<content_id>/complete", method="POST")
    def mark_bookmark_completed(provider, content_id):
        """
        Mark a bookmark as completed (watched to end).

        Request body (JSON):
        {
            "content_type":    "VOD",  // Required
            "duration_seconds": 3600, // Optional: positive integer
            "title": "Movie Title"    // Optional
        }

        Returns:
        { ...Updated Bookmark fields... }
        """
        try:
            data = request.json or {}

            # --- content_type (required) ---
            content_type_str = data.get("content_type")
            if not content_type_str:
                response.status = 400
                return {
                    "error": "Missing required field",
                    "message": "content_type is required",
                    "provider": provider,
                    "content_id": content_id,
                }
            try:
                content_type = ContentType(content_type_str.upper())
            except ValueError:
                response.status = 400
                return {
                    "error": "Invalid content_type",
                    "message": f"content_type must be one of: {[ct.value for ct in ContentType]}",
                    "provider": provider,
                    "content_id": content_id,
                }

            # --- duration_seconds (optional, must be positive if present) ---
            duration_seconds = data.get("duration_seconds")
            if duration_seconds is not None:
                try:
                    duration_seconds = int(duration_seconds)
                    if duration_seconds <= 0:
                        raise ValueError
                except ValueError:
                    response.status = 400
                    return {
                        "error": "Invalid duration_seconds",
                        "message": "duration_seconds must be a positive integer",
                        "provider": provider,
                        "content_id": content_id,
                    }

            try:
                bookmark = manager.mark_bookmark_completed(
                    provider_name=provider,
                    content_id=content_id,
                    content_type=content_type,
                    duration_seconds=duration_seconds,
                    title=data.get("title"),
                )
            except ValueError as e:
                response.status = 404
                return {
                    "error": "Provider not found",
                    "message": str(e),
                    "provider": provider,
                    "content_id": content_id,
                }
            except RuntimeError as e:
                response.status = 409
                return {
                    "error": "Bookmark update rejected",
                    "message": str(e),
                    "provider": provider,
                    "content_id": content_id,
                }
            except Exception as e:
                logger.error(f"Failed to mark bookmark '{content_id}' as completed: {e}")
                response.status = 500
                return {
                    "error": "Failed to mark bookmark as completed",
                    "message": str(e),
                    "provider": provider,
                    "content_id": content_id,
                }

            if bookmark is None:
                response.status = 501
                return {
                    "error": "Bookmarks not supported",
                    "message": f"Provider '{provider}' does not support bookmarks",
                    "provider": provider,
                    "content_id": content_id,
                }

            response.status = 200
            return bookmark.to_dict(include_none=False)

        except Exception as e:
            logger.error(f"Unexpected error in mark_bookmark_completed: {e}")
            response.status = 500
            return {
                "error": "Internal server error",
                "message": str(e),
                "provider": provider,
                "content_id": content_id,
            }

    @app.route("/api/providers/<provider>/bookmarks/<content_id>", method="DELETE")
    def delete_provider_bookmark(provider, content_id):
        """
        Delete a bookmark from a specific provider.

        Returns:
            204 No Content on success.
            404 if the provider or bookmark is not found.
            409 if the provider refuses deletion.
            500 on unexpected errors.
        """
        try:
            try:
                deleted = manager.delete_bookmark(
                    provider_name=provider,
                    content_id=content_id,
                )
            except ValueError as e:
                response.status = 404
                return {
                    "error": "Provider not found",
                    "message": str(e),
                    "provider": provider,
                    "content_id": content_id,
                }
            except RuntimeError as e:
                response.status = 409
                return {
                    "error": "Deletion refused by provider",
                    "message": str(e),
                    "provider": provider,
                    "content_id": content_id,
                }
            except Exception as e:
                logger.error(f"Failed to delete bookmark '{content_id}' from '{provider}': {e}")
                response.status = 500
                return {
                    "error": "Failed to delete bookmark",
                    "message": str(e),
                    "provider": provider,
                    "content_id": content_id,
                }

            # delete_bookmark returns False when the bookmark didn't exist or
            # the provider doesn't support bookmarks — both map to 404.
            if not deleted:
                response.status = 404
                return {
                    "error": "Bookmark not found",
                    "message": f"No bookmark with content_id '{content_id}' from '{provider}'",
                    "provider": provider,
                    "content_id": content_id,
                }

            response.status = 204
            return ""

        except Exception as e:
            logger.error(f"Unexpected error in delete_provider_bookmark: {e}")
            response.status = 500
            return {
                "error": "Internal server error",
                "message": str(e),
                "provider": provider,
                "content_id": content_id,
            }

    # ==========================================================================
    # AGGREGATE ROUTES (ALL PROVIDERS)
    # ==========================================================================

    @app.route("/api/bookmarks/all", method="GET")
    def get_all_bookmarks():
        """
        Get bookmarks from all enabled providers.

        Query parameters:
        - content_type:       Optional (LIVE, VOD, EVENT, RECORDING, SERIES, RADIO)
        - include_completed:  Optional bool (true/false) — default false
        - include_stale:      Optional bool (true/false) — default false
        - max_age_hours:      Optional int — default 720 (30 days)
        - sort_by:            Optional — 'last_updated', 'created_at', 'title',
                              'provider'. Default: 'last_updated'

        Returns:
        {
            "bookmarks": [ { ...Bookmark fields... } ],
            "count": 1,
            "by_provider": { "provider_name": 1 },
            "filters": { ... },
            "errors": { ... }  // Only present if any providers failed
        }
        """
        try:
            content_type_str = request.params.get("content_type")
            content_type = None
            if content_type_str:
                try:
                    content_type = ContentType(content_type_str.upper())
                except ValueError:
                    response.status = 400
                    return {
                        "error": "Invalid content_type",
                        "message": f"content_type must be one of: {[ct.value for ct in ContentType]}",
                    }

            include_completed = request.params.get("include_completed", "false").lower() in (
                "1", "true", "yes"
            )
            include_stale = request.params.get("include_stale", "false").lower() in (
                "1", "true", "yes"
            )

            try:
                max_age_hours = int(request.params.get("max_age_hours", "720"))
                if max_age_hours < 0:
                    raise ValueError
            except ValueError:
                response.status = 400
                return {
                    "error": "Invalid max_age_hours",
                    "message": "max_age_hours must be a non-negative integer",
                }

            sort_by = request.params.get("sort_by", "last_updated")
            if sort_by not in ("last_updated", "created_at", "title", "provider"):
                response.status = 400
                return {
                    "error": "Invalid sort_by",
                    "message": "sort_by must be one of: last_updated, created_at, title, provider",
                }

            # Single call: fetch the dict, extract errors, derive sorted flat list
            # from the same data — avoids making two full provider round-trips.
            all_data = manager.get_all_bookmarks(
                content_type=content_type,
                include_completed=include_completed,
                include_stale=include_stale,
                max_age_hours=max_age_hours,
            )
            errors = all_data.pop("_errors", None)

            # Flatten and sort
            flat_list = [b for bookmarks in all_data.values() for b in bookmarks]
            reverse = sort_by in ("last_updated", "created_at")
            key_fn = {
                "last_updated": lambda b: b.last_updated,
                "created_at":   lambda b: b.created_at,
                "title":        lambda b: b.title or "",
                "provider":     lambda b: b.provider,
            }[sort_by]
            flat_list.sort(key=key_fn, reverse=reverse)

            by_provider = {}
            for bookmark in flat_list:
                by_provider[bookmark.provider] = by_provider.get(bookmark.provider, 0) + 1

            result = {
                "bookmarks": [b.to_dict(include_none=False) for b in flat_list],
                "count": len(flat_list),
                "by_provider": by_provider,
                "filters": {
                    "content_type": content_type.value if content_type else None,
                    "include_completed": include_completed,
                    "include_stale": include_stale,
                    "max_age_hours": max_age_hours,
                    "sort_by": sort_by,
                },
            }
            if errors:
                result["errors"] = errors

            response.status = 200
            return result

        except Exception as e:
            logger.error(f"Unexpected error in get_all_bookmarks: {e}")
            response.status = 500
            return {"error": "Internal server error", "message": str(e)}

    # ==========================================================================
    # STATISTICS AND MAINTENANCE ROUTES
    # ==========================================================================

    @app.route("/api/bookmarks/stats", method="GET")
    def get_bookmark_stats():
        """
        Get statistics about bookmarks across all providers.

        Query parameters:
        - max_age_hours: Optional int — default 720 (30 days)

        Returns:
        {
            "total": 42,
            "completed": 10,
            "in_progress": 32,
            "stale": 5,
            "by_content_type": { "VOD": 30, "EVENT": 8, "RECORDING": 4 },
            "by_provider": { "rtl_de": 20, "joyn_de": 15, "zdf": 7 }
        }
        """
        try:
            try:
                max_age_hours = int(request.params.get("max_age_hours", "720"))
                if max_age_hours < 0:
                    raise ValueError
            except ValueError:
                response.status = 400
                return {
                    "error": "Invalid max_age_hours",
                    "message": "max_age_hours must be a non-negative integer",
                }

            response.status = 200
            return manager.get_bookmark_stats(max_age_hours=max_age_hours)

        except Exception as e:
            logger.error(f"Unexpected error in get_bookmark_stats: {e}")
            response.status = 500
            return {"error": "Internal server error", "message": str(e)}

    @app.route("/api/providers/<provider>/bookmarks/validate", method="GET")
    def validate_provider_bookmarks(provider):
        """
        Validate all bookmarks from a provider (read-only).

        Returns validation issues without modifying any data. To auto-fix
        issues, use POST /api/providers/<provider>/bookmarks/fix instead.

        Returns:
        {
            "total": 10,
            "errors": [...],
            "warnings": [...],
            "fixed": 0
        }
        """
        try:
            try:
                result = manager.validate_bookmarks(provider_name=provider, auto_fix=False)
            except ValueError as e:
                response.status = 404
                return {"error": "Provider not found", "message": str(e), "provider": provider}
            except Exception as e:
                logger.error(f"Failed to validate bookmarks for '{provider}': {e}")
                response.status = 500
                return {
                    "error": "Failed to validate bookmarks",
                    "message": str(e),
                    "provider": provider,
                }

            response.status = 200
            return result

        except Exception as e:
            logger.error(f"Unexpected error in validate_provider_bookmarks: {e}")
            response.status = 500
            return {"error": "Internal server error", "message": str(e), "provider": provider}

    @app.route("/api/providers/<provider>/bookmarks/fix", method="POST")
    def fix_provider_bookmarks(provider):
        """
        Validate and auto-fix bookmark issues for a provider.

        Auto-fix clips positions that exceed duration to just below the
        completion threshold, preventing unintended completion marking.
        Only WARNING-level issues are fixed; ERROR-level issues require
        manual intervention.

        Returns:
        {
            "total": 10,
            "errors": [...],
            "warnings": [...],
            "fixed": 2
        }
        """
        try:
            try:
                result = manager.validate_bookmarks(provider_name=provider, auto_fix=True)
            except ValueError as e:
                response.status = 404
                return {"error": "Provider not found", "message": str(e), "provider": provider}
            except Exception as e:
                logger.error(f"Failed to fix bookmarks for '{provider}': {e}")
                response.status = 500
                return {
                    "error": "Failed to fix bookmarks",
                    "message": str(e),
                    "provider": provider,
                }

            response.status = 200
            return result

        except Exception as e:
            logger.error(f"Unexpected error in fix_provider_bookmarks: {e}")
            response.status = 500
            return {"error": "Internal server error", "message": str(e), "provider": provider}

    @app.route("/api/bookmarks/cleanup", method="POST")
    def cleanup_stale_bookmarks():
        """
        Remove stale bookmarks older than max_age_hours.

        Request body (JSON):
        {
            "max_age_hours":   720,          // Optional, default 720
            "dry_run":         true,         // Optional, default true
            "provider_filter": ["rtl_de"]    // Optional, list of provider name strings
        }

        Returns:
        {
            "deleted": { "rtl_de": 5, "joyn_de": 3 },
            "total_deleted": 8,
            "dry_run": false
        }
        """
        try:
            data = request.json or {}

            try:
                max_age_hours = int(data.get("max_age_hours", 720))
                if max_age_hours < 0:
                    raise ValueError
            except ValueError:
                response.status = 400
                return {
                    "error": "Invalid max_age_hours",
                    "message": "max_age_hours must be a non-negative integer",
                }

            dry_run = data.get("dry_run", True)
            if not isinstance(dry_run, bool):
                response.status = 400
                return {
                    "error": "Invalid dry_run",
                    "message": "dry_run must be a boolean",
                }

            provider_filter = data.get("provider_filter")
            if provider_filter is not None:
                if not isinstance(provider_filter, list) or not all(
                    isinstance(p, str) for p in provider_filter
                ):
                    response.status = 400
                    return {
                        "error": "Invalid provider_filter",
                        "message": "provider_filter must be a list of provider name strings",
                    }

            results = manager.cleanup_stale_bookmarks(
                max_age_hours=max_age_hours,
                dry_run=dry_run,
                provider_filter=provider_filter,
            )

            response.status = 200
            return {
                "deleted": results,
                "total_deleted": sum(results.values()),
                "dry_run": dry_run,
            }

        except Exception as e:
            logger.error(f"Unexpected error in cleanup_stale_bookmarks: {e}")
            response.status = 500
            return {"error": "Internal server error", "message": str(e)}