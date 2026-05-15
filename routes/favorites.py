#!/usr/bin/env python3
"""
Favorite-related route handlers.
Mirrors the structure of bookmarks.py.
"""

from bottle import request, response
from streaming_providers.base.models.favorite import FavoriteType
from streaming_providers.base.utils import logger


def setup_favorites_routes(app, manager, service):
    """Setup favorite-related routes."""

    # ==========================================================================
    # SINGLE PROVIDER ROUTES
    # ==========================================================================

    @app.route("/api/providers/<provider>/favorites", method="GET")
    def get_provider_favorites(provider):
        """
        Get favorites from a specific provider.

        Query parameters:
        - favorite_type: Optional (PROGRAM, CLIP, LIVE, EVENT)

        Returns:
        {
            "provider": "provider_name",
            "favorites": [ { ...Favorite fields... } ],
            "count": 1,
            "filters": {
                "favorite_type": null
            }
        }
        """
        try:
            favorite_type_str = request.params.get("favorite_type")
            favorite_type = None
            if favorite_type_str:
                try:
                    favorite_type = FavoriteType(favorite_type_str.upper())
                except ValueError:
                    response.status = 400
                    return {
                        "error": "Invalid favorite_type",
                        "message": f"favorite_type must be one of: {[ft.value for ft in FavoriteType]}",
                        "provider": provider,
                    }

            try:
                favorites = manager.get_favorites(
                    provider_name=provider,
                    favorite_type=favorite_type,
                )
            except ValueError as e:
                response.status = 404
                return {
                    "error": "Provider not found",
                    "message": str(e),
                    "provider": provider,
                }
            except Exception as e:
                logger.error(f"Failed to get favorites from '{provider}': {e}")
                response.status = 500
                return {
                    "error": "Failed to get favorites",
                    "message": str(e),
                    "provider": provider,
                }

            response.status = 200
            return {
                "provider": provider,
                "favorites": [f.to_dict() for f in favorites],
                "count": len(favorites),
                "filters": {
                    "favorite_type": favorite_type.value if favorite_type else None,
                },
            }

        except Exception as e:
            logger.error(f"Unexpected error in get_provider_favorites: {e}")
            response.status = 500
            return {"error": "Internal server error", "message": str(e), "provider": provider}

    @app.route("/api/providers/<provider>/favorites/<content_id>", method="GET")
    def get_provider_favorite(provider, content_id):
        """
        Check if a specific content ID is favorited.

        Returns:
        {
            "provider": "provider_name",
            "content_id": "123",
            "is_favorited": true,
            "favorite": { ...Favorite fields... }  // Only if favorited
        }
        """
        try:
            try:
                is_favorited = manager.is_favorited(
                    provider_name=provider,
                    content_id=content_id,
                )
                # If favorited, get the full favorite object
                favorite = None
                if is_favorited:
                    favorites = manager.get_favorites(provider_name=provider)
                    for f in favorites:
                        if f.content_id == content_id:
                            favorite = f
                            break
            except ValueError as e:
                response.status = 404
                return {"error": "Provider not found", "message": str(e), "provider": provider}
            except Exception as e:
                logger.error(f"Failed to check favorite from '{provider}': {e}")
                response.status = 500
                return {
                    "error": "Failed to check favorite",
                    "message": str(e),
                    "provider": provider,
                }

            response.status = 200
            result = {
                "provider": provider,
                "content_id": content_id,
                "is_favorited": is_favorited,
            }
            if favorite:
                result["favorite"] = favorite.to_dict()

            return result

        except Exception as e:
            logger.error(f"Unexpected error in get_provider_favorite: {e}")
            response.status = 500
            return {"error": "Internal server error", "message": str(e), "provider": provider}

    @app.route("/api/providers/<provider>/favorites/<content_id>", method="POST")
    def add_provider_favorite(provider, content_id):
        """
        Add a favorite.

        Request body (JSON):
        {
            "favorite_type":   "PROGRAM",     // Required
            "title":           "Show Title",  // Optional
            "thumbnail_url":   "https://...", // Optional
            "series_title":    "Series Name"  // Optional (for series/program)
        }

        Returns:
        { ...Favorite fields... }
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

            # --- favorite_type (required) ---
            favorite_type_str = data.get("favorite_type")
            if not favorite_type_str:
                response.status = 400
                return {
                    "error": "Missing required field",
                    "message": "favorite_type is required",
                    "provider": provider,
                    "content_id": content_id,
                }
            try:
                favorite_type = FavoriteType(favorite_type_str.upper())
            except ValueError:
                response.status = 400
                return {
                    "error": "Invalid favorite_type",
                    "message": f"favorite_type must be one of: {[ft.value for ft in FavoriteType]}",
                    "provider": provider,
                    "content_id": content_id,
                }

            try:
                favorite = manager.add_favorite(
                    provider_name=provider,
                    content_id=content_id,
                    favorite_type=favorite_type,
                    title=data.get("title"),
                    thumbnail_url=data.get("thumbnail_url"),
                    series_title=data.get("series_title"),
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
                    "error": "Favorite addition rejected",
                    "message": str(e),
                    "provider": provider,
                    "content_id": content_id,
                }
            except Exception as e:
                logger.error(f"Failed to add favorite '{content_id}' to '{provider}': {e}")
                response.status = 500
                return {
                    "error": "Failed to add favorite",
                    "message": str(e),
                    "provider": provider,
                    "content_id": content_id,
                }

            if favorite is None:
                response.status = 501
                return {
                    "error": "Favorites not supported",
                    "message": f"Provider '{provider}' does not support favorites",
                    "provider": provider,
                    "content_id": content_id,
                }

            response.status = 200
            return favorite.to_dict()

        except Exception as e:
            logger.error(f"Unexpected error in add_provider_favorite: {e}")
            response.status = 500
            return {
                "error": "Internal server error",
                "message": str(e),
                "provider": provider,
                "content_id": content_id,
            }

    @app.route("/api/providers/<provider>/favorites/<content_id>", method="DELETE")
    def remove_provider_favorite(provider, content_id):
        """
        Remove a favorite.

        Returns:
            204 No Content on success.
            404 if the provider or favorite is not found.
            409 if the provider refuses deletion.
            500 on unexpected errors.
        """
        try:
            try:
                removed = manager.remove_favorite(
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
                logger.error(f"Failed to remove favorite '{content_id}' from '{provider}': {e}")
                response.status = 500
                return {
                    "error": "Failed to remove favorite",
                    "message": str(e),
                    "provider": provider,
                    "content_id": content_id,
                }

            if not removed:
                response.status = 404
                return {
                    "error": "Favorite not found",
                    "message": f"No favorite with content_id '{content_id}' from '{provider}'",
                    "provider": provider,
                    "content_id": content_id,
                }

            response.status = 204
            return ""

        except Exception as e:
            logger.error(f"Unexpected error in remove_provider_favorite: {e}")
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

    @app.route("/api/favorites/all", method="GET")
    def get_all_favorites():
        """
        Get favorites from all enabled providers.

        Query parameters:
        - favorite_type: Optional (PROGRAM, CLIP, LIVE, EVENT)

        Returns:
        {
            "favorites": [ { ...Favorite fields... } ],
            "count": 1,
            "by_provider": { "provider_name": 1 },
            "filters": { "favorite_type": null },
            "errors": { ... }  // Only present if any providers failed
        }
        """
        try:
            favorite_type_str = request.params.get("favorite_type")
            favorite_type = None
            if favorite_type_str:
                try:
                    favorite_type = FavoriteType(favorite_type_str.upper())
                except ValueError:
                    response.status = 400
                    return {
                        "error": "Invalid favorite_type",
                        "message": f"favorite_type must be one of: {[ft.value for ft in FavoriteType]}",
                    }

            all_data = manager.get_all_favorites(favorite_type=favorite_type)
            errors = all_data.pop("_errors", None)

            # Flatten the list
            flat_list = [f for favorites in all_data.values() for f in favorites]

            by_provider = {}
            for favorite in flat_list:
                by_provider[favorite.provider] = by_provider.get(favorite.provider, 0) + 1

            result = {
                "favorites": [f.to_dict() for f in flat_list],
                "count": len(flat_list),
                "by_provider": by_provider,
                "filters": {
                    "favorite_type": favorite_type.value if favorite_type else None,
                },
            }
            if errors:
                result["errors"] = errors

            response.status = 200
            return result

        except Exception as e:
            logger.error(f"Unexpected error in get_all_favorites: {e}")
            response.status = 500
            return {"error": "Internal server error", "message": str(e)}

    # ==========================================================================
    # BULK OPERATIONS ROUTES
    # ==========================================================================

    @app.route("/api/favorites/clear", method="POST")
    def clear_all_favorites():
        """
        Remove all favorites from all providers (or specific providers).

        Request body (JSON):
        {
            "provider_filter": ["rtl_de"]    // Optional, list of provider name strings
        }

        Returns:
        {
            "deleted": { "rtl_de": 5, "joyn_de": 3 },
            "total_deleted": 8
        }
        """
        try:
            data = request.json or {}

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

            results = {}
            total = 0

            # Get all favorites first
            all_favorites = manager.get_all_favorites()
            errors = all_favorites.pop("_errors", None)

            for provider_name, favorites in all_favorites.items():
                if provider_filter and provider_name not in provider_filter:
                    continue

                deleted = 0
                for favorite in favorites:
                    try:
                        if manager.remove_favorite(provider_name, favorite.content_id):
                            deleted += 1
                    except Exception as e:
                        logger.error(f"Failed to remove favorite {favorite.content_id}: {e}")

                if deleted > 0:
                    results[provider_name] = deleted
                    total += deleted

            response.status = 200
            return {
                "deleted": results,
                "total_deleted": total,
            }

        except Exception as e:
            logger.error(f"Unexpected error in clear_all_favorites: {e}")
            response.status = 500
            return {"error": "Internal server error", "message": str(e)}