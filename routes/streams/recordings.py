#!/usr/bin/env python3
"""
Recording stream routes.

Recordings are always on-demand (pre-captured), so:
  - No catchup path (unlike channels)
  - recording_id is a flat identifier, no path hierarchy needed

As of the query-param consolidation (mirrors channels.py's
_handle_channel_stream), there's a single /stream/index.mpd route rather
than a separate /stream/proxied/ route. That combination is now reached via
client_drm on the one route, resolved directly through
_resolve_stream_unified.
"""

from bottle import HTTPResponse, request, response
from streaming_providers.base.utils import logger


def setup_recording_routes(app, manager, service, helpers):
    """Setup all recording-related stream routes."""

    CONTENT_TYPE_RECORDING = helpers["CONTENT_TYPE_RECORDING"]
    _build_drm_header = helpers["_build_drm_header"]
    _build_stream_headers = helpers["_build_stream_headers"]
    _resolve_stream_unified = helpers["_resolve_stream_unified"]
    _get_drm_configs = helpers["_get_drm_configs"]

    def _handle_recording_stream(provider, recording_id):
        """Single implementation backing /stream/index.mpd — the only
        recording stream route. Replaces the former /stream/proxied/ route,
        which hardcoded receiver_side=False. Mirrors channels.py's
        _handle_channel_stream, minus catchup handling — recordings have no
        catchup. highest_quality_only is accepted for symmetry with the
        other content types even though no /stream/proxied/ffmpeg/ route
        ever existed here (recordings are on-demand, not live/adaptive, so
        there was never a quality-pinning need) — it's a no-op unless a
        caller opts in."""
        try:
            country = request.query.get("country")
            drm_variant = request.query.get("drm_variant", "auto")
            no_proxy = request.query.get("no_proxy", "false").lower() == "true"
            # Old /stream/index.mpd (via the deprecated _resolve_stream
            # wrapper) hardcoded receiver_side=True, so client_drm defaults
            # to "true" here to preserve that for callers that don't pass
            # it explicitly — same reasoning as events.py/vod.py.
            client_drm = request.query.get("client_drm", "true").lower() == "true"
            highest_quality_only = request.query.get("highest_quality_only", "false").lower() == "true"

            logger.debug(
                f"_handle_recording_stream: provider={provider} recording={recording_id} "
                f"country={country!r} drm_variant={drm_variant} "
                f"client_drm={client_drm} no_proxy={no_proxy} "
                f"highest_quality_only={highest_quality_only}"
            )

            return _resolve_stream_unified(
                CONTENT_TYPE_RECORDING, provider, recording_id,
                country=country,
                drm_variant=drm_variant,
                receiver_side=client_drm,
                no_proxy=no_proxy,
                highest_quality_only=highest_quality_only,
            )

        except HTTPResponse:
            raise
        except ValueError as e:
            logger.error(f"stream error for recording {provider}/{recording_id}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"stream error for recording {provider}/{recording_id}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

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
        Single stream endpoint for recording playback. Replaces the former
        /stream/proxied/ route, which is removed. client_drm=false now
        reaches what that route used to do; see get_channel_stream in
        channels.py for the full query-param list (client_drm, drm_variant,
        no_proxy, highest_quality_only, country).
        """
        return _handle_recording_stream(provider, recording_id)

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