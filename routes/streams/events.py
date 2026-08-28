#!/usr/bin/env python3
"""
Event-specific stream routes.

Events are temporary/live streams (sports, special broadcasts, etc.). They
share the same transport pattern as channels but without catchup support.

As of the query-param consolidation (mirrors channels.py's
_handle_channel_stream), there's a single /stream/index.mpd route rather
than separate /stream/sw-drm/, /stream/proxied/, and /stream/proxied/ffmpeg/
routes. Those combinations are now reached via drm_variant/client_drm/
no_proxy/highest_quality_only query params on the one route, resolved
directly through _resolve_stream_unified.
"""

from bottle import HTTPResponse, request, response
from streaming_providers.base.utils import logger


def setup_event_routes(app, manager, service, helpers):
    """Setup all event-related stream routes."""

    CONTENT_TYPE_EVENT = helpers["CONTENT_TYPE_EVENT"]
    _build_drm_header = helpers["_build_drm_header"]
    _build_stream_headers = helpers["_build_stream_headers"]
    _resolve_stream_unified = helpers["_resolve_stream_unified"]
    _get_drm_configs = helpers["_get_drm_configs"]

    def _handle_event_stream(provider, event_id):
        """Single implementation backing /stream/index.mpd — the only event
        stream route. Replaces the former /stream/sw-drm/, /stream/proxied/,
        and /stream/proxied/ffmpeg/ routes, each of which used to hardcode
        one fixed combination of drm_variant/receiver_side/
        highest_quality_only. Mirrors channels.py's _handle_channel_stream,
        minus catchup handling — events have no catchup."""
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
                f"_handle_event_stream: provider={provider} event={event_id} "
                f"country={country!r} drm_variant={drm_variant} "
                f"client_drm={client_drm} no_proxy={no_proxy} "
                f"highest_quality_only={highest_quality_only}"
            )

            return _resolve_stream_unified(
                CONTENT_TYPE_EVENT, provider, event_id,
                country=country,
                drm_variant=drm_variant,
                receiver_side=client_drm,
                no_proxy=no_proxy,
                highest_quality_only=highest_quality_only,
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

    @app.route("/api/providers/<provider>/events/<event_id>/manifest")
    def get_event_manifest(provider, event_id):
        """
        Returns JSON with a manifest_url pointing to the single stream
        endpoint. Attaches x-kodi-drm-configs header.

        sw_drm_manifest_url is kept in the response for backward
        compatibility with existing clients (pvr.ultimate /
        plugin.video.ultimate may read this field by name) — it's now just
        manifest_url with drm_variant=software&client_drm=true appended,
        rather than a separate route.
        """
        try:
            country = request.query.get("country")
            base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
            qs = f"?country={country}" if country else ""
            stream_url = (
                f"{base_url}/api/providers/{provider}/events/{event_id}"
                f"/stream/index.mpd{qs}"
            )
            sw_drm_qs_sep = "&" if qs else "?"
            sw_drm_stream_url = (
                f"{stream_url}{sw_drm_qs_sep}drm_variant=software&client_drm=true"
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
        Single stream endpoint for event playback. Replaces the former
        /stream/sw-drm/, /stream/proxied/, and /stream/proxied/ffmpeg/
        routes, which are removed. Every combination those routes used to
        hardcode is now expressed via independent, freely-combinable query
        params (see get_channel_stream in channels.py for the full list):

          client_drm=true|false            client decrypts ClearKey itself
                                            if true; server decrypts to
                                            plaintext segments if false.
                                            Default false.
          drm_variant=auto|software        which upstream DRM/quality
                                            variant to request. Default auto.
          no_proxy=true|false               force redirect/fetch even if the
                                            content would normally be
                                            proxied. Default false.
          highest_quality_only=true|false  collapse to a single
                                            highest-quality representation
                                            (e.g. for ffmpeg piping). Default
                                            false.
          country                          as before.

        Returns an HTTP 302 redirect to the upstream manifest, or a
        rewritten manifest body when the media proxy is involved.
        """
        return _handle_event_stream(provider, event_id)

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