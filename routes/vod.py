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

Search endpoints
----------------
GET /api/providers/<provider>/vod/search
    Search the VOD catalogue of a single provider.

GET /api/vod/search
    Search the VOD catalogue across all enabled providers that implement VOD.

    Query parameters:
        q         Required. Free-text search string.
        cursor    Opaque continuation token (single-provider search only).
        size      Number of entries to request per page (default: 24).

    Single-provider response:
    {
        "provider":    "discovery_de",
        "query":       "football",
        "entries":     [...],
        "count":       8,
        "next_cursor": "<opaque>",
        "total":       42
    }

    Cross-provider response:
    {
        "query":   "football",
        "results": {
            "discovery_de": {"entries": [...], "count": 3},
            "rtlplus":      {"entries": [...], "count": 5}
        },
        "total_count": 8
    }

Stream / manifest / DRM endpoints for VodItems are in streams.py:
    GET /api/providers/<provider>/vod/<vod_id>/manifest
    GET /api/providers/<provider>/vod/<vod_id>/stream/index.mpd
    GET /api/providers/<provider>/vod/<vod_id>/drm
These are registered in streams.py (same pattern as channels and events)
and must be set up BEFORE setup_vod_routes() so Bottle matches them first.

NOTE: Search routes are registered before the <content_id:path> wildcard so
that /vod/search is not swallowed by get_vod_node.
"""

from bottle import request, response
from streaming_providers.base.utils import logger


def setup_vod_routes(app, manager):

    def _base_url() -> str:
        return f"{request.urlparts.scheme}://{request.urlparts.netloc}"

    def _serialize(entries, provider: str) -> list:
        """
        Serialize VOD entries to dicts.

        For VodItem entries (type == "vod"), inject absolute ``manifest_url``
        and ``stream_url`` built from the item's own ``content_id``.

        The client constructs stream URLs from the browsing path (the URL it
        used to navigate to this listing), not from the item's ``id`` field.
        For container nodes (catalogue_, series_) this produces a nav-node id
        that get_manifest correctly rejects. Injecting explicit URLs here gives
        the client an unambiguous playback target for each item, regardless of
        what navigation path led to this listing.

        VodCategory entries are left unchanged — they are never playable.
        """
        base = _base_url()
        result = []
        for e in entries:
            d = e.to_dict()
            if d.get("type") == "vod" and e.content_id:
                d["manifest_url"] = (
                    f"{base}/api/providers/{provider}/vod/{e.content_id}/manifest"
                )
                d["stream_url"] = (
                    f"{base}/api/providers/{provider}/vod/{e.content_id}/stream/index.mpd"
                )
            result.append(d)
        return result

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
        serialized = _serialize(result["entries"], provider)
        response.status = 200
        return {
            "provider": provider,
            "content_id": "",
            "entries": serialized,
            "count": len(serialized),
            "next_cursor": result.get("next_cursor"),
            "total": result.get("total"),
        }

    # ------------------------------------------------------------------
    # Search routes — registered BEFORE the <content_id:path> wildcard so
    # that /vod/search is not captured by get_vod_node.
    # ------------------------------------------------------------------

    @app.route("/api/providers/<provider>/vod/search", method="GET")
    def search_vod(provider):
        """Search the VOD catalogue of a single provider."""
        query = request.query.get("q", "").strip()
        if not query:
            response.status = 400
            return {"error": "Missing required query parameter 'q'", "provider": provider}

        cursor, page_size = _parse_paging_params()
        try:
            result = manager.search_vod(
                provider_name=provider,
                query=query,
                cursor=cursor,
                page_size=page_size,
            )
        except ValueError as e:
            response.status = 404
            return {"error": "Provider not found", "message": str(e), "provider": provider}
        except Exception as e:
            logger.error(f"Failed to search VOD in provider '{provider}': {e}")
            response.status = 500
            return {"error": "Failed to search VOD", "message": str(e), "provider": provider}

        serialized = _serialize(result["entries"], provider)
        response.status = 200
        return {
            "provider": provider,
            "query": query,
            "entries": serialized,
            "count": len(serialized),
            "next_cursor": result.get("next_cursor"),
            "total": result.get("total"),
        }

    @app.route("/api/vod/search", method="GET")
    def search_all_vod():
        """Search the VOD catalogue across all enabled providers."""
        query = request.query.get("q", "").strip()
        if not query:
            response.status = 400
            return {"error": "Missing required query parameter 'q'"}

        try:
            provider_results = manager.search_all_vod(query=query)
        except Exception as e:
            logger.error(f"Failed to search VOD across providers: {e}")
            response.status = 500
            return {"error": "Failed to search VOD", "message": str(e)}

        results = {}
        total_count = 0
        for provider_name, entries in provider_results.items():
            serialized = _serialize(entries, provider_name)
            results[provider_name] = {"entries": serialized, "count": len(serialized)}
            total_count += len(serialized)

        response.status = 200
        return {
            "query": query,
            "results": results,
            "total_count": total_count,
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
        serialized = _serialize(result["entries"], provider)
        response.status = 200
        return {
            "provider": provider,
            "content_id": content_id,
            "entries": serialized,
            "count": len(serialized),
            "next_cursor": result.get("next_cursor"),
            "total": result.get("total"),
        }