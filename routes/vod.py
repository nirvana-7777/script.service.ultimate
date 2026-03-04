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

Stream/manifest/DRM endpoints
------------------------------
GET /api/providers/<provider>/vod/<path:path>/manifest
    Returns the manifest URL for the VOD item whose id is the last
    segment of <path>.
    e.g. /api/providers/discovery_de/vod/sports/nordic-combined/6bbea4ab-.../manifest

GET /api/providers/<provider>/vod/<path:path>/drm
    Returns DRM configs for the VOD item whose id is the last segment of <path>.

Route registration order matters: the explicit /manifest and /drm routes are
registered BEFORE the generic <path:path> route so Bottle matches them first.
"""

from bottle import response
from streaming_providers.base.utils import logger


def setup_vod_routes(app, manager):

    def _serialize(entries) -> list:
        return [e.to_dict() for e in entries]

    # ------------------------------------------------------------------
    # Root
    # ------------------------------------------------------------------

    @app.route("/api/providers/<provider>/vod", method="GET")
    def get_vod_root(provider):
        try:
            entries = manager.get_vod_node(provider_name=provider, slug_segments=[])
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

    # ------------------------------------------------------------------
    # Manifest & DRM  — must be registered BEFORE the generic path route
    # so Bottle matches /manifest and /drm suffixes here first.
    # <path:path> captures everything before the suffix, e.g.
    #   "sports/nordic-combined/6bbea4ab-735c-469b-89d2-2a38c195ce07"
    # The last segment of that path is the vod_id (edit_id / content_id).
    # ------------------------------------------------------------------

    @app.route("/api/providers/<provider>/vod/<path:path>/manifest", method="GET")
    def get_vod_item_manifest(provider, path):
        segments = [s for s in path.split("/") if s]
        if not segments:
            response.status = 400
            return {"error": "Missing VOD item id", "provider": provider}
        vod_id = segments[-1]
        try:
            manifest_url = manager.get_vod_manifest(provider_name=provider, vod_id=vod_id)
        except ValueError as e:
            response.status = 404
            return {"error": "Not found", "message": str(e), "provider": provider, "vod_id": vod_id}
        except Exception as e:
            logger.error(f"Failed to get VOD manifest: {e}")
            response.status = 500
            return {"error": "Failed to get manifest", "message": str(e), "provider": provider, "vod_id": vod_id}
        if not manifest_url:
            response.status = 404
            return {"error": "No manifest available", "provider": provider, "vod_id": vod_id}
        response.status = 200
        return {"provider": provider, "vod_id": vod_id, "manifest_url": manifest_url}

    @app.route("/api/providers/<provider>/vod/<path:path>/drm", method="GET")
    def get_vod_item_drm(provider, path):
        segments = [s for s in path.split("/") if s]
        if not segments:
            response.status = 400
            return {"error": "Missing VOD item id", "provider": provider}
        vod_id = segments[-1]
        try:
            drm_configs = manager.get_vod_drm_configs(provider_name=provider, vod_id=vod_id)
        except ValueError as e:
            response.status = 404
            return {"error": "Not found", "message": str(e), "provider": provider, "vod_id": vod_id}
        except Exception as e:
            logger.error(f"Failed to get VOD DRM configs: {e}")
            response.status = 500
            return {"error": "Failed to get DRM configs", "message": str(e), "provider": provider, "vod_id": vod_id}
        response.status = 200
        return {"provider": provider, "vod_id": vod_id, "drm": [d.to_dict() for d in (drm_configs or [])]}

    # ------------------------------------------------------------------
    # Generic browse — registered last so /manifest and /drm win above
    # ------------------------------------------------------------------

    @app.route("/api/providers/<provider>/vod/<path:path>", method="GET")
    def get_vod_path(provider, path):
        slug_segments = [s for s in path.split("/") if s]
        if not slug_segments:
            return get_vod_root(provider)
        try:
            entries = manager.get_vod_node(provider_name=provider, slug_segments=slug_segments)
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