#!/usr/bin/env python3
"""
VOD (Video on Demand) stream routes.

VOD content uses the same transport pattern as events but with hierarchical
IDs (paths like "clip_1417600/stream") and without catchup support.
"""

from bottle import HTTPResponse, request, response
from streaming_providers.base.utils import logger


def setup_vod_routes(app, manager, service, helpers):
    """Setup all VOD-related stream routes."""

    CONTENT_TYPE_VOD = helpers["CONTENT_TYPE_VOD"]
    _build_drm_header = helpers["_build_drm_header"]
    _build_stream_headers = helpers["_build_stream_headers"]
    _resolve_stream = helpers["_resolve_stream"]
    _resolve_decrypted_stream = helpers["_resolve_decrypted_stream"]
    _get_drm_configs = helpers["_get_drm_configs"]

    @app.route("/api/providers/<provider>/vod/<path:path>/stream/index.mpd")
    def get_vod_stream(provider, path):
        # Extract vod_id as the first segment before any slashes
        # Example: "clip_1417600/stream" -> "clip_1417600"
        vod_id = path.split("/")[0]

        try:
            country = request.query.get("country")
            return _resolve_stream(
                CONTENT_TYPE_VOD, provider, vod_id, country=country
            )
        except HTTPResponse:
            raise
        except ValueError as e:
            logger.error(f"stream error for VOD {provider}/{vod_id}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"stream error for VOD {provider}/{vod_id}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    @app.route("/api/providers/<provider>/vod/<path:path>/manifest")
    def get_vod_manifest(provider, path):
        vod_id = path.split("/")[0]
        try:
            country = request.query.get("country")
            base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
            stream_url = (
                f"{base_url}/api/providers/{provider}/vod/{vod_id}/stream/index.mpd"
            )
            if country:
                stream_url += f"?country={country}"

            _build_drm_header(CONTENT_TYPE_VOD, provider, vod_id, country=country)
            _build_stream_headers(CONTENT_TYPE_VOD, provider, vod_id, country=country)

            return {
                "provider": provider,
                "vod_id": vod_id,
                "manifest_url": stream_url,
            }

        except ValueError as e:
            logger.error(f"manifest endpoint error for VOD {provider}/{vod_id}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"manifest endpoint error for VOD {provider}/{vod_id}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    @app.route("/api/providers/<provider>/vod/<path:path>/stream/decrypted/index.mpd")
    def get_vod_stream_decrypted(provider, path):
        vod_id = path.split("/")[0]
        return _resolve_decrypted_stream(
            CONTENT_TYPE_VOD, provider, vod_id, highest_quality_only=False
        )

    @app.route("/api/providers/<provider>/vod/<path:path>/stream/decrypted/ffmpeg/index.mpd")
    def get_vod_stream_decrypted_ffmpeg(provider, path):
        vod_id = path.split("/")[0]
        return _resolve_decrypted_stream(
            CONTENT_TYPE_VOD, provider, vod_id, highest_quality_only=True
        )

    @app.route("/api/providers/<provider>/vod/<path:path>/drm")
    def get_vod_drm(provider, path):
        vod_id = path.split("/")[0]
        try:
            country = request.query.get("country")
            drm_configs = _get_drm_configs(
                CONTENT_TYPE_VOD, provider, vod_id, country=country
            )

            merged = {}
            for config in drm_configs:
                merged.update(
                    config.to_dict() if hasattr(config, "to_dict") else config
                )

            return {
                "provider": provider,
                "vod_id": vod_id,
                "content_type": CONTENT_TYPE_VOD,
                "drm_configs": merged,
            }

        except ValueError as e:
            logger.error(f"DRM endpoint error for VOD {provider}/{vod_id}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"DRM endpoint error for VOD {provider}/{vod_id}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}