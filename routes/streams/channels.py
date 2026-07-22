#!/usr/bin/env python3
"""
Channel-specific stream routes.

All channel routes delegate to the shared helpers in __init__.py for actual
stream resolution. This module only defines route decorators and the minimal
channel-specific catchup handling logic.
"""

import time
from bottle import HTTPResponse, request, response
from streaming_providers.base.utils import logger


def setup_channel_routes(app, manager, service, helpers):
    """Setup all channel-related stream routes."""

    CONTENT_TYPE_CHANNEL = helpers["CONTENT_TYPE_CHANNEL"]
    _build_drm_header = helpers["_build_drm_header"]
    _build_stream_headers = helpers["_build_stream_headers"]
    _resolve_stream = helpers["_resolve_stream"]
    _resolve_decrypted_stream = helpers["_resolve_decrypted_stream"]
    _get_drm_configs = helpers["_get_drm_configs"]

    def _handle_channel_stream(provider, channel_id, *, drm_variant="auto"):
        """Shared implementation for /stream/index.mpd and /stream/sw-drm/index.mpd."""
        try:
            start_time = request.query.get("start_time")
            end_time = request.query.get("end_time")
            epg_id = request.query.get("epg_id")
            country = request.query.get("country")
            is_catchup = bool(start_time and end_time)

            logger.debug(
                f"_handle_channel_stream: provider={provider} channel={channel_id} "
                f"start_time={start_time!r} end_time={end_time!r} "
                f"epg_id={epg_id!r} country={country!r} is_catchup={is_catchup} "
                f"drm_variant={drm_variant}"
            )

            # Always defined so the _resolve_stream call below is unconditionally safe,
            # even though the ternary guards already prevent None from being passed when
            # is_catchup is False.
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

                channels = manager.get_channels(provider_name=provider, fetch_manifests=False)
                channel_obj = next((c for c in channels if c.channel_id == channel_id), None)
                logger.debug(
                    f"CATCHUP: channel lookup id={channel_id!r} -> "
                    + (f"found (catchup_hours attr={getattr(channel_obj, 'catchup_hours', 'MISSING')!r}, "
                       f"catchup_window attr={getattr(channel_obj, 'catchup_window', 'MISSING')!r})"
                       if channel_obj else "NOT FOUND in channel list")
                )

                # The model field is catchup_hours (serialises as CatchupHours).
                # Fall back to catchup_window for providers using the older name.
                catchup_hours = (
                        getattr(channel_obj, "catchup_hours", None)
                        or getattr(channel_obj, "catchup_window", 0)
                ) if channel_obj else 0
                logger.debug(f"CATCHUP: resolved catchup_hours={catchup_hours!r}")

                if not catchup_hours:
                    logger.warning(
                        f"CATCHUP: rejecting {provider}/{channel_id} — "
                        f"catchup_hours=0 or attribute not found on channel model"
                    )
                    response.status = 400
                    return {"error": f'Catchup not supported for channel "{channel_id}"'}

                age_seconds = int(time.time()) - start_time_int
                logger.debug(
                    f"CATCHUP: window check age={age_seconds}s limit={catchup_hours * 3600}s ({catchup_hours}h)"
                )
                if age_seconds > catchup_hours * 3600:
                    response.status = 400
                    return {"error": f"Content outside catchup window (max {catchup_hours} hours)"}

            return _resolve_stream(
                CONTENT_TYPE_CHANNEL, provider, channel_id,
                country=country,
                is_catchup=is_catchup,
                start_time=start_time_int if is_catchup else None,
                end_time=end_time_int if is_catchup else None,
                epg_id=epg_id if is_catchup else None,
                drm_variant=drm_variant,
            )

        except HTTPResponse:
            raise
        except ValueError as e:
            label = "sw-drm " if drm_variant == "software" else ""
            logger.error(f"{label}stream error for channel {provider}/{channel_id}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            label = "sw-drm " if drm_variant == "software" else ""
            logger.error(f"{label}stream error for channel {provider}/{channel_id}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    # =========================================================================
    # CHANNEL ROUTES
    # =========================================================================

    @app.route("/api/providers/<provider>/channels/<channel_id>/manifest")
    def get_channel_manifest(provider, channel_id):
        """
        Returns JSON with a manifest_url pointing to the stream endpoint.
        Attaches x-kodi-drm-configs header.

        Response includes both stream_url (auto DRM) and sw_drm_stream_url
        (software / ClearKey DRM) so callers can pick the appropriate variant
        without a second round-trip.

        Also includes catchup_stream_url_template — a URL with {start_time} and
        {end_time} placeholders (Unix timestamps) that callers can expand for
        DVR/catchup playback, avoiding the need to construct the URL manually.
        """
        try:
            country = request.query.get("country")
            base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
            qs = f"?country={country}" if country else ""
            stream_url = (
                f"{base_url}/api/providers/{provider}/channels/{channel_id}"
                f"/stream/index.mpd{qs}"
            )
            sw_drm_stream_url = (
                f"{base_url}/api/providers/{provider}/channels/{channel_id}"
                f"/stream/sw-drm/index.mpd{qs}"
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
                "sw_drm_manifest_url": sw_drm_stream_url,
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
        """Returns HTTP 302 redirect to the actual manifest, or a rewritten
        manifest body when media proxy is active.  Supports live and catchup."""
        return _handle_channel_stream(provider, channel_id)

    @app.route("/api/providers/<provider>/channels/<channel_id>/stream/sw-drm/index.mpd")
    def get_channel_stream_sw_drm(provider, channel_id):
        """Software-DRM (ClearKey) variant. Identical transport to the standard
        endpoint; passes drm_variant='software' through to _resolve_stream."""
        return _handle_channel_stream(provider, channel_id, drm_variant="software")

    @app.route("/api/providers/<provider>/channels/<channel_id>/stream/decrypted/index.mpd")
    def get_channel_stream_decrypted(provider, channel_id):
        """Decrypted stream — all quality representations."""
        return _resolve_decrypted_stream(
            CONTENT_TYPE_CHANNEL, provider, channel_id, highest_quality_only=False
        )

    @app.route(
        "/api/providers/<provider>/channels/<channel_id>/stream/decrypted/ffmpeg/index.mpd"
    )
    def get_channel_stream_decrypted_ffmpeg(provider, channel_id):
        """Decrypted stream — highest quality only, optimised for ffmpeg."""
        return _resolve_decrypted_stream(
            CONTENT_TYPE_CHANNEL, provider, channel_id, highest_quality_only=True
        )

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