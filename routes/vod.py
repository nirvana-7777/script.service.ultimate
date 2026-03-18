#!/usr/bin/env python3
# routes/vod.py
"""
VOD (Video on Demand) browse route handlers.

Browse endpoints
----------------
GET /api/providers/<provider>/vod
    Returns the root-level VOD entries (categories and/or items).

GET /api/providers/<provider>/vod/<path:path>
    Navigates the VOD tree by URL-safe path segments.
    e.g. /api/providers/discovery_de/vod/sports/nordic-combined

    Response:
    {
        "provider": "discovery_de",
        "path": "sports/nordic-combined",
        "entries": [
            {"type": "vod_category", "id": "...", "name": "...", "slug": "..."},
            {"type": "vod",          "id": "...", "name": "...", "slug": "..."}
        ],
        "count": 12
    }

Stream / manifest / DRM endpoints for VodItems are in streams.py:
    GET /api/providers/<provider>/vod/<vod_id>/manifest
    GET /api/providers/<provider>/vod/<vod_id>/stream/index.mpd
    GET /api/providers/<provider>/vod/<vod_id>/drm
These are registered in streams.py (same pattern as channels and events)
and must be set up BEFORE setup_vod_routes() so Bottle matches them first.
"""

from bottle import response
from streaming_providers.base.utils import logger


def setup_vod_routes(app, manager):

    def _serialize(entries) -> list:
        return [e.to_dict() for e in entries]

    @app.route("/api/providers/<provider>/vod", method="GET")
    def get_vod_root(provider):
        try:
            entries = manager.get_vod_node(provider_name=provider, content_id="")
        except ValueError as e:
            response.status = 404
            return {"error": "Provider not found", "message": str(e), "provider": provider}
        except Exception as e:
            logger.error(f"Failed to get VOD root from provider: {e}")
            response.status = 500
            return {"error": "Failed to get VOD entries", "message": str(e), "provider": provider}
        serialized = _serialize(entries)
        response.status = 200
        return {"provider": provider, "content_id": "", "entries": serialized, "count": len(serialized)}

    @app.route("/api/providers/<provider>/vod/<content_id>", method="GET")
    def get_vod_node(provider, content_id):
        """
        Navigate to any VOD node by its opaque content_id.

        content_id is treated as a single opaque token — never split or parsed.
        It is the value returned in VodCategory.content_id from a previous response.

        Examples:
            GET /api/providers/magenta2/vod/lane%3A322341
            GET /api/providers/magenta2/vod/series%3AGN_SERIES_20914057
            GET /api/providers/discovery_de/vod/sports
        """
        if not content_id:
            return get_vod_root(provider)
        try:
            entries = manager.get_vod_node(
                provider_name=provider,
                content_id=content_id,
            )
        except ValueError as e:
            response.status = 404
            return {"error": "Not found", "message": str(e), "provider": provider, "content_id": content_id}
        except Exception as e:
            logger.error(f"Failed to get VOD node from provider: {e}")
            response.status = 500
            return {"error": "Failed to get VOD entries", "message": str(e), "provider": provider, "content_id": content_id}
        serialized = _serialize(entries)
        response.status = 200
        return {"provider": provider, "content_id": content_id, "entries": serialized, "count": len(serialized)}