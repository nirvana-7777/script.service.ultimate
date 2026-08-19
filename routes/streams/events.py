#!/usr/bin/env python3
"""
Event-specific stream routes.

Events are temporary/live streams (sports, special broadcasts, etc.). They
share the same transport pattern as channels but without catchup support.
"""

from bottle import HTTPResponse, request, response
from streaming_providers.base.utils import logger


def setup_event_routes(app, manager, service, helpers):
    """Setup all event-related stream routes."""

    CONTENT_TYPE_EVENT = helpers["CONTENT_TYPE_EVENT"]
    _build_drm_header = helpers["_build_drm_header"]
    _build_stream_headers = helpers["_build_stream_headers"]
    _resolve_stream = helpers["_resolve_stream"]
    _resolve_decrypted_stream = helpers["_resolve_decrypted_stream"]
    _get_drm_configs = helpers["_get_drm_configs"]

    @app.route("/api/providers/<provider>/events/<event_id>/manifest")
    def get_event_manifest(provider, event_id):
        """
        Returns JSON with a manifest_url pointing to the event stream endpoint.
        Attaches x-kodi-drm-configs header.

        Response includes both stream_url (auto DRM) and sw_drm_stream_url
        (software / ClearKey DRM).
        """
        try:
            country = request.query.get("country")
            base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
            qs = f"?country={country}" if country else ""
            stream_url = (
                f"{base_url}/api/providers/{provider}/events/{event_id}"
                f"/stream/index.mpd{qs}"
            )
            sw_drm_stream_url = (
                f"{base_url}/api/providers/{provider}/events/{event_id}"
                f"/stream/sw-drm/index.mpd{qs}"
            )

            _build_drm_header(CONTENT_TYPE_EVENT, provider, event_id, country=country)
            _build_stream_headers(CONTENT_TYPE_EVENT, provider, event_id, country=country)

            return {
                "provider": provider,
                "event_id": event_id,
                "manifest_url": stream_url,
                "sw_drm_manifest_url": sw_drm_stream_url,
            }

        except ValueError as e:
            logger.error(f"manifest endpoint error for event {provider}/{event_id}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"manifest endpoint error for event {provider}/{event_id}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    @app.route("/api/providers/<provider>/events/<event_id>/stream/index.mpd")
    def get_event_stream(provider, event_id):
        """
        Returns HTTP 302 redirect to the event manifest, or a rewritten
        manifest body when media proxy is active.
        """
        try:
            country = request.query.get("country")
            return _resolve_stream(
                CONTENT_TYPE_EVENT, provider, event_id, country=country
            )
        except HTTPResponse:
            raise
        except ValueError as e:
            logger.error(f"stream error for event {provider}/{event_id}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"stream error for event {provider}/{event_id}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    @app.route("/api/providers/<provider>/events/<event_id>/stream/sw-drm/index.mpd")
    def get_event_stream_sw_drm(provider, event_id):
        """
        Software-DRM event stream endpoint.

        Identical to the standard event stream endpoint except that
        drm_variant='software' is passed through to the resolution helpers.
        """
        try:
            country = request.query.get("country")
            return _resolve_stream(
                CONTENT_TYPE_EVENT, provider, event_id,
                country=country, drm_variant="software",
            )
        except HTTPResponse:
            raise
        except ValueError as e:
            logger.error(f"sw-drm stream error for event {provider}/{event_id}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"sw-drm stream error for event {provider}/{event_id}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    @app.route(
        "/api/providers/<provider>/events/<event_id>/stream/proxied/index.mpd"
    )
    def get_event_stream_decrypted(provider, event_id):
        """Proxied event stream — all quality representations."""
        return _resolve_decrypted_stream(
            CONTENT_TYPE_EVENT, provider, event_id, highest_quality_only=False
        )

    @app.route(
        "/api/providers/<provider>/events/<event_id>/stream/proxied/ffmpeg/index.mpd"
    )
    def get_event_stream_decrypted_ffmpeg(provider, event_id):
        """Proxied event stream — highest quality only, optimised for ffmpeg."""
        return _resolve_decrypted_stream(
            CONTENT_TYPE_EVENT, provider, event_id, highest_quality_only=True
        )

    @app.route("/api/providers/<provider>/events/<event_id>/drm")
    def get_event_drm(provider, event_id):
        """Return DRM configs for a specific event."""
        try:
            country = request.query.get("country")
            drm_configs = _get_drm_configs(
                CONTENT_TYPE_EVENT, provider, event_id, country=country
            )

            merged = {}
            for config in drm_configs:
                merged.update(
                    config.to_dict() if hasattr(config, "to_dict") else config
                )

            return {
                "provider": provider,
                "event_id": event_id,
                "content_type": CONTENT_TYPE_EVENT,
                "drm_configs": merged,
            }

        except ValueError as e:
            logger.error(f"DRM endpoint error for event {provider}/{event_id}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"DRM endpoint error for event {provider}/{event_id}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}