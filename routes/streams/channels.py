#!/usr/bin/env python3
"""
Channel-specific stream routes.

All channel routes delegate to the shared helpers in __init__.py for actual
stream resolution. This module only defines route decorators and the minimal
channel-specific catchup handling logic.
"""

from bottle import HTTPResponse, request, response
from streaming_providers.base.utils import logger


def setup_channel_routes(app, manager, service, helpers):
    """Setup all channel-related stream routes."""

    CONTENT_TYPE_CHANNEL = helpers["CONTENT_TYPE_CHANNEL"]
    _build_drm_header = helpers["_build_drm_header"]
    _build_stream_headers = helpers["_build_stream_headers"]
    _resolve_stream_unified = helpers["_resolve_stream_unified"]
    _get_drm_configs = helpers["_get_drm_configs"]

    def _handle_channel_stream(provider, channel_id):
        """Single implementation backing /stream/index.mpd — the only channel
        stream route. Replaces the former /stream/sw-drm/, /stream/noproxy/,
        /stream/proxied/, and /stream/proxied/ffmpeg/ routes, each of which
        used to hardcode one fixed combination of drm_variant/receiver_side/
        no_proxy/highest_quality_only. Those axes are independent, so folding
        them into query params makes every combination reachable — including
        ones no route could express before (e.g. client-side decrypt +
        highest_quality_only)."""
        try:
            start_time = request.query.get("start_time")
            end_time = request.query.get("end_time")
            epg_id = request.query.get("epg_id")
            country = request.query.get("country")
            is_catchup = bool(start_time and end_time)

            drm_variant = request.query.get("drm_variant", "auto")
            no_proxy = request.query.get("no_proxy", "false").lower() == "true"
            # client_drm is the public query-param name (self-explanatory in a
            # URL); receiver_side is what _resolve_stream_unified calls the
            # same axis internally — translated here at the route boundary.
            client_drm = request.query.get("client_drm", "false").lower() == "true"
            highest_quality_only = request.query.get("highest_quality_only", "false").lower() == "true"

            logger.debug(
                f"_handle_channel_stream: provider={provider} channel={channel_id} "
                f"start_time={start_time!r} end_time={end_time!r} "
                f"epg_id={epg_id!r} country={country!r} is_catchup={is_catchup} "
                f"drm_variant={drm_variant} client_drm={client_drm} "
                f"no_proxy={no_proxy} highest_quality_only={highest_quality_only}"
            )

            # Always defined so the _resolve_stream_unified call below is
            # unconditionally safe, even though the ternary guards already
            # prevent None from being passed when is_catchup is False.
            start_time_int: int | None = None
            end_time_int: int | None = None

            if is_catchup:
                try:
                    start_time_int = int(start_time)
                    end_time_int = int(end_time)
                    logger.debug(f"CATCHUP: times parsed OK: {start_time_int} to {end_time_int}")
                except (ValueError, TypeError):
                    logger.warning(
                        f"CATCHUP: could not parse start_time={start_time!r} / end_time={end_time!r} as int"
                    )
                    response.status = 400
                    return {"error": "Invalid start_time or end_time format"}

                # Window validation (catchup_hours lookup, age check) lives
                # inside _resolve_stream_unified via _validate_catchup_window.

            return _resolve_stream_unified(
                CONTENT_TYPE_CHANNEL, provider, channel_id,
                country=country,
                is_catchup=is_catchup,
                start_time=start_time_int if is_catchup else None,
                end_time=end_time_int if is_catchup else None,
                epg_id=epg_id if is_catchup else None,
                drm_variant=drm_variant,
                receiver_side=client_drm,
                no_proxy=no_proxy,
                highest_quality_only=highest_quality_only,
            )

        except HTTPResponse:
            raise
        except ValueError as e:
            logger.error(f"stream error for channel {provider}/{channel_id}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"stream error for channel {provider}/{channel_id}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    # =========================================================================
    # CHANNEL ROUTES
    # =========================================================================

    @app.route("/api/providers/<provider>/channels/<channel_id>/manifest")
    def get_channel_manifest(provider, channel_id):
        """
        Returns JSON with a manifest_url pointing to the single stream
        endpoint. Attaches x-kodi-drm-configs header.

        As of the query-param consolidation, there's one stream_url rather
        than a separate URL per DRM/proxy/quality combination — the caller
        appends whatever combination of client_drm/drm_variant/no_proxy/
        highest_quality_only query params it needs (see get_channel_stream's
        docstring for the full list). catchup_stream_url_template still
        carries {start_time}/{end_time} placeholders for DVR/catchup playback.
        """
        try:
            country = request.query.get("country")
            base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
            qs = f"?country={country}" if country else ""
            stream_url = (
                f"{base_url}/api/providers/{provider}/channels/{channel_id}"
                f"/stream/index.mpd{qs}"
            )
            # Catchup template — callers substitute {start_time}/{end_time} with
            # Unix timestamps.  Matches the query params consumed by _handle_channel_stream.
            catchup_qs_sep = "&" if qs else "?"
            catchup_stream_url_template = (
                f"{base_url}/api/providers/{provider}/channels/{channel_id}"
                f"/stream/index.mpd{qs}{catchup_qs_sep}"
                f"start_time={{start_time}}&end_time={{end_time}}"
            )

            _build_drm_header(CONTENT_TYPE_CHANNEL, provider, channel_id, country=country)
            _build_stream_headers(CONTENT_TYPE_CHANNEL, provider, channel_id, country=country)

            return {
                "provider": provider,
                "channel_id": channel_id,
                "manifest_url": stream_url,
                "catchup_stream_url_template": catchup_stream_url_template,
            }

        except ValueError as e:
            logger.error(f"manifest endpoint error for {provider}/{channel_id}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"manifest endpoint error for {provider}/{channel_id}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    @app.route("/api/providers/<provider>/channels/<channel_id>/stream/index.mpd")
    def get_channel_stream(provider, channel_id):
        """
        Single stream endpoint for all channel playback — live and catchup.
        Replaces the former /stream/sw-drm/, /stream/noproxy/, /stream/proxied/,
        and /stream/proxied/ffmpeg/ routes, which are removed. Every
        combination those routes used to hardcode (and some that were
        previously unreachable through any route) is now expressed via
        independent, freely-combinable query params:

          client_drm=true|false            client decrypts ClearKey itself
                                            (receiver-side rewrite) if true;
                                            server decrypts to plaintext
                                            segments if false. Default false.
          drm_variant=auto|software        which upstream DRM/quality variant
                                            to request (e.g. Widevine L1 vs
                                            L3). Default auto.
          no_proxy=true|false               force redirect/fetch even if the
                                            content would normally be proxied.
                                            Default false.
          highest_quality_only=true|false  collapse to a single
                                            highest-quality representation
                                            (e.g. for ffmpeg piping). Default
                                            false.
          start_time / end_time / epg_id / country - catchup + context, as
                                            before.

        Returns an HTTP 302 redirect to the upstream manifest, or a rewritten
        manifest body when the media proxy is involved.
        """
        return _handle_channel_stream(provider, channel_id)

    @app.route("/api/providers/<provider>/channels/<channel_id>/drm")
    def get_channel_drm(provider, channel_id):
        """
        Return DRM configs for a channel.  Supports catchup via query params.
        """
        try:
            start_time = request.query.get("start_time")
            end_time = request.query.get("end_time")
            epg_id = request.query.get("epg_id")
            country = request.query.get("country")
            is_catchup = bool(start_time and end_time)

            if is_catchup:
                try:
                    start_time_int = int(start_time)
                    end_time_int = int(end_time)
                except (ValueError, TypeError):
                    response.status = 400
                    return {"error": "Invalid start_time or end_time format"}

                drm_configs = manager.get_catchup_drm_configs(
                    provider_name=provider,
                    channel_id=channel_id,
                    start_time=start_time_int,
                    end_time=end_time_int,
                    epg_id=epg_id,
                    country=country,
                )
            else:
                drm_configs = _get_drm_configs(
                    CONTENT_TYPE_CHANNEL, provider, channel_id, country=country
                )

            merged = {}
            for config in drm_configs:
                merged.update(
                    config.to_dict() if hasattr(config, "to_dict") else config
                )

            return {
                "provider": provider,
                "channel_id": channel_id,
                "content_type": CONTENT_TYPE_CHANNEL,
                "is_catchup": is_catchup,
                "drm_configs": merged,
            }

        except ValueError as e:
            logger.error(f"DRM endpoint error for channel {provider}/{channel_id}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"DRM endpoint error for channel {provider}/{channel_id}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}