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

    Query parameters:
        cursor    Opaque continuation token returned in a previous response's
                  next_cursor field.  Omit (or pass empty) for the first page.
        size      Number of entries to request per page (default: 24).
                  Providers may clamp or ignore this value.

    Response:
    {
        "provider":    "discovery_de",
        "content_id":  "sports/nordic-combined",
        "entries": [
            {"type": "vod_category", "id": "...", "name": "...", "slug": "..."},
            {"type": "vod",          "id": "...", "name": "...", "slug": "..."}
        ],
        "count":       12,
        "next_cursor": "<opaque>",   # null when no further pages exist
        "total":       120           # null when provider does not expose total
    }

Stream / manifest / DRM endpoints for VodItems are in streams.py:
    GET /api/providers/<provider>/vod/<vod_id>/manifest
    GET /api/providers/<provider>/vod/<vod_id>/stream/index.mpd
    GET /api/providers/<provider>/vod/<vod_id>/drm
These are registered in streams.py (same pattern as channels and events)
and must be set up BEFORE setup_vod_routes() so Bottle matches them first.
"""

from bottle import request, response
from streaming_providers.base.utils import logger


def setup_vod_routes(app, manager):

    def _serialize(entries) -> list:
        return [e.to_dict() for e in entries]

    def _parse_paging_params() -> tuple[str | None, int]:
        """
        Extract and validate paging query parameters from the current request.

        Returns:
            (cursor, page_size) — cursor is None when not supplied or empty.
        """
        cursor = request.query.get("cursor") or None
        try:
            page_size = int(request.query.get("size", 24))
            if page_size < 1:
                page_size = 24
        except (ValueError, TypeError):
            page_size = 24
        return cursor, page_size

    @app.route("/api/providers/<provider>/vod", method="GET")
    def get_vod_root(provider):
        cursor, page_size = _parse_paging_params()
        try:
            result = manager.get_vod_node(
                provider_name=provider,
                content_id="",
                cursor=cursor,
                page_size=page_size,
            )
        except ValueError as e:
            response.status = 404
            return {"error": "Provider not found", "message": str(e), "provider": provider}
        except Exception as e:
            logger.error(f"Failed to get VOD root from provider: {e}")
            response.status = 500
            return {"error": "Failed to get VOD entries", "message": str(e), "provider": provider}
        serialized = _serialize(result["entries"])
        response.status = 200
        return {
            "provider": provider,
            "content_id": "",
            "entries": serialized,
            "count": len(serialized),
            "next_cursor": result.get("next_cursor"),
            "total": result.get("total"),
        }

    @app.route("/api/providers/<provider>/vod/<content_id:path>", method="GET")
    def get_vod_node(provider, content_id):
        """
        Navigate to any VOD node by its opaque content_id.

        Uses Bottle's :path wildcard so content_ids containing slashes
        (e.g. "/video-tv/filme", "UnstructuredGrid/322341") are captured
        in full without splitting.  Clients may also URL-encode slashes
        (%2F) for extra safety — Bottle decodes them automatically.

        Examples:
            GET /api/providers/rtlplus/vod/video-tv/filme
            GET /api/providers/magenta2/vod/lane%3A322341
            GET /api/providers/discovery_de/vod/%2Fsports%2Fnordic-combined
        """
        if not content_id:
            return get_vod_root(provider)

        cursor, page_size = _parse_paging_params()
        try:
            result = manager.get_vod_node(
                provider_name=provider,
                content_id=content_id,
                cursor=cursor,
                page_size=page_size,
            )
        except ValueError as e:
            response.status = 404
            return {"error": "Not found", "message": str(e), "provider": provider, "content_id": content_id}
        except Exception as e:
            logger.error(f"Failed to get VOD node from provider: {e}")
            response.status = 500
            return {"error": "Failed to get VOD entries", "message": str(e), "provider": provider, "content_id": content_id}
        serialized = _serialize(result["entries"])
        response.status = 200
        return {
            "provider": provider,
            "content_id": content_id,
            "entries": serialized,
            "count": len(serialized),
            "next_cursor": result.get("next_cursor"),
            "total": result.get("total"),
        }