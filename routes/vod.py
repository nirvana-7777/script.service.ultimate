#!/usr/bin/env python3
# routes/vod.py
"""
VOD (Video on Demand) route handlers.

Browse endpoints
----------------
GET /api/providers/<provider>/vod
    Returns the root-level VOD entries (categories and/or items).

GET /api/providers/<provider>/vod/<path:path>
    Navigates the VOD tree by URL-safe name slugs.
    e.g. /api/providers/myprovider/vod/sports/golf/pga/tournament_x

    Response:
    {
        "provider": "myprovider",
        "path": "sports/golf/pga",
        "entries": [
            {"type": "vod_category", "id": "...", "name": "...", "slug": "..."},
            {"type": "vod",          "id": "...", "name": "...", "slug": "..."}
        ],
        "count": 12
    }

Stream/manifest/DRM endpoints for VodItem are registered in streams.py
following the identical pattern used for channels and events.
"""

from bottle import response
from streaming_providers.base.utils import logger


def setup_vod_routes(app, manager):

    def _serialize(entries) -> list:
        return [e.to_dict() for e in entries]

    @app.route("/api/providers/<provider>/vod", method="GET")
    def get_vod_root(provider):
        try:
            entries = manager.vod_ops.get_vod_node(provider_name=provider, slug_segments=[])
        except ValueError as e:
            response.status = 404
            return {"error": "Provider not found", "message": str(e), "provider": provider}
        except Exception as e:
            logger.error(f"Failed to get VOD root from provider: {e}")
            response.status = 500
            return {"error": "Failed to get VOD entries", "message": str(e), "provider": provider}
        serialized = _serialize(entries)
        response.status = 200
        return {"provider": provider, "path": "", "entries": serialized, "count": len(serialized)}

    @app.route("/api/providers/<provider>/vod/<path:path>", method="GET")
    def get_vod_path(provider, path):
        slug_segments = [s for s in path.split("/") if s]
        if not slug_segments:
            return get_vod_root(provider)
        try:
            entries = manager.vod_ops.get_vod_node(provider_name=provider, slug_segments=slug_segments)
        except ValueError as e:
            response.status = 404
            return {"error": "Not found", "message": str(e), "provider": provider, "path": path}
        except Exception as e:
            logger.error(f"Failed to get VOD path from provider: {e}")
            response.status = 500
            return {"error": "Failed to get VOD entries", "message": str(e), "provider": provider, "path": path}
        serialized = _serialize(entries)
        response.status = 200
        return {"provider": provider, "path": path, "entries": serialized, "count": len(serialized)}