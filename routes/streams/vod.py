#!/usr/bin/env python3
"""
VOD (Video on Demand) stream routes.

VOD content uses the same transport pattern as events but with hierarchical
IDs (paths like "clip_1417600/stream") and without catchup support.

As of the query-param consolidation (mirrors channels.py's
_handle_channel_stream), there's a single /stream/index.mpd route rather
than separate /stream/proxied/ and /stream/proxied/ffmpeg/ routes. Those
combinations are now reached via client_drm/no_proxy/highest_quality_only
query params on the one route, resolved directly through
_resolve_stream_unified.
"""

from bottle import HTTPResponse, request, response
from streaming_providers.base.utils import logger


def setup_vod_routes(app, manager, service, helpers):
    """Setup all VOD-related stream routes."""

    CONTENT_TYPE_VOD = helpers["CONTENT_TYPE_VOD"]
    _build_drm_header = helpers["_build_drm_header"]
    _build_stream_headers = helpers["_build_stream_headers"]
    _resolve_stream_unified = helpers["_resolve_stream_unified"]
    _get_drm_configs = helpers["_get_drm_configs"]

    def _handle_vod_stream(provider, vod_id):
        """Single implementation backing /stream/index.mpd — the only VOD
        stream route. Replaces the former /stream/proxied/ and
        /stream/proxied/ffmpeg/ routes, each of which used to hardcode one
        fixed combination of receiver_side/highest_quality_only. Mirrors
        channels.py's _handle_channel_stream, minus catchup handling — VOD
        has no catchup. drm_variant is accepted for symmetry with events/
        channels even though no VOD provider integration currently uses a
        software-DRM variant."""
        try:
            country = request.query.get("country")
            drm_variant = request.query.get("drm_variant", "auto")
            no_proxy = request.query.get("no_proxy", "false").lower() == "true"
            # client_drm is the public query-param name; receiver_side is
            # what _resolve_stream_unified calls the same axis internally —
            # translated here at the route boundary, same as channels.py.
            # Old /stream/index.mpd (via the deprecated _resolve_stream
            # wrapper) hardcoded receiver_side=True, so client_drm defaults
            # to "true" here to preserve that for callers that don't pass
            # it explicitly. This intentionally differs from channels.py's
            # "false" default — that reflects channels' own prior behavior,
            # not a shared convention.
            client_drm = request.query.get("client_drm", "true").lower() == "true"
            highest_quality_only = request.query.get("highest_quality_only", "false").lower() == "true"

            logger.debug(
                f"_handle_vod_stream: provider={provider} vod_id={vod_id} "
                f"country={country!r} drm_variant={drm_variant} "
                f"client_drm={client_drm} no_proxy={no_proxy} "
                f"highest_quality_only={highest_quality_only}"
            )

            return _resolve_stream_unified(
                CONTENT_TYPE_VOD, provider, vod_id,
                country=country,
                drm_variant=drm_variant,
                receiver_side=client_drm,
                no_proxy=no_proxy,
                highest_quality_only=highest_quality_only,
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

    @app.route("/api/providers/<provider>/vod/<path:path>/stream/index.mpd")
    def get_vod_stream(provider, path):
        """
        Single stream endpoint for VOD playback. Replaces the former
        /stream/proxied/ and /stream/proxied/ffmpeg/ routes, which are
        removed. Every combination those routes used to hardcode is now
        expressed via independent, freely-combinable query params (see
        get_channel_stream in channels.py for the full list): client_drm,
        drm_variant, no_proxy, highest_quality_only, country.
        """
        # Extract vod_id as the first segment before any slashes
        # Example: "clip_1417600/stream" -> "clip_1417600"
        vod_id = path.split("/")[0]
        return _handle_vod_stream(provider, vod_id)

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