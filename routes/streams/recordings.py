#!/usr/bin/env python3
"""
Recording stream routes.

Recordings are always on-demand (pre-captured), so:
  - No catchup path (unlike channels)
  - No ffmpeg variant (not a live/adaptive stream that needs quality pinning)
  - recording_id is a flat identifier, no path hierarchy needed
"""

from bottle import HTTPResponse, request, response
from streaming_providers.base.utils import logger


def setup_recording_routes(app, manager, service, helpers):
    """Setup all recording-related stream routes."""

    CONTENT_TYPE_RECORDING = helpers["CONTENT_TYPE_RECORDING"]
    _build_drm_header = helpers["_build_drm_header"]
    _build_stream_headers = helpers["_build_stream_headers"]
    _resolve_stream = helpers["_resolve_stream"]
    _resolve_decrypted_stream = helpers["_resolve_decrypted_stream"]
    _get_drm_configs = helpers["_get_drm_configs"]

    @app.route("/api/providers/<provider>/recordings/<recording_id>/manifest")
    def get_recording_manifest(provider, recording_id):
        """
        Returns JSON with a manifest_url pointing to the recording stream endpoint.
        Attaches x-kodi-drm-configs header.
        """
        try:
            country = request.query.get("country")
            base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
            stream_url = (
                f"{base_url}/api/providers/{provider}"
                f"/recordings/{recording_id}/stream/index.mpd"
            )
            if country:
                stream_url += f"?country={country}"

            _build_drm_header(
                CONTENT_TYPE_RECORDING, provider, recording_id, country=country
            )
            _build_stream_headers(
                CONTENT_TYPE_RECORDING, provider, recording_id, country=country
            )

            return {
                "provider": provider,
                "recording_id": recording_id,
                "manifest_url": stream_url,
            }

        except ValueError as e:
            logger.error(
                f"manifest endpoint error for recording {provider}/{recording_id}: {e}"
            )
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(
                f"manifest endpoint error for recording {provider}/{recording_id}: {e}"
            )
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    @app.route("/api/providers/<provider>/recordings/<recording_id>/stream/index.mpd")
    def get_recording_stream(provider, recording_id):
        """
        Returns HTTP 302 redirect to the recording manifest, or a rewritten
        manifest body when media proxy is active.
        """
        try:
            country = request.query.get("country")
            return _resolve_stream(
                CONTENT_TYPE_RECORDING, provider, recording_id, country=country
            )
        except HTTPResponse:
            raise
        except ValueError as e:
            logger.error(
                f"stream error for recording {provider}/{recording_id}: {e}"
            )
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(
                f"stream error for recording {provider}/{recording_id}: {e}"
            )
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    @app.route(
        "/api/providers/<provider>/recordings/<recording_id>/stream/proxied/index.mpd"
    )
    def get_recording_stream_decrypted(provider, recording_id):
        """Proxied recording stream — all quality representations."""
        return _resolve_decrypted_stream(
            CONTENT_TYPE_RECORDING, provider, recording_id, highest_quality_only=False
        )

    @app.route("/api/providers/<provider>/recordings/<recording_id>/drm")
    def get_recording_drm(provider, recording_id):
        """Return DRM configs for a specific recording."""
        try:
            country = request.query.get("country")
            drm_configs = _get_drm_configs(
                CONTENT_TYPE_RECORDING, provider, recording_id, country=country
            )

            merged = {}
            for config in drm_configs:
                merged.update(
                    config.to_dict() if hasattr(config, "to_dict") else config
                )

            return {
                "provider": provider,
                "recording_id": recording_id,
                "content_type": CONTENT_TYPE_RECORDING,
                "drm_configs": merged,
            }

        except ValueError as e:
            logger.error(
                f"DRM endpoint error for recording {provider}/{recording_id}: {e}"
            )
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(
                f"DRM endpoint error for recording {provider}/{recording_id}: {e}"
            )
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}