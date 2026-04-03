#!/usr/bin/env python3
"""
Stream and manifest route handlers.

Architecture
============
All content types (channels, events, future VOD) share identical transport-level
operations: resolve a manifest URL, fetch DRM configs, optionally rewrite the
manifest through a media proxy.  The typed route handlers (channel vs event vs
vod) are therefore thin wrappers around two shared helpers:

  _build_drm_header(content_type, provider, content_id, ...)
      Fetches DRM configs via the correct manager method and attaches them as a
      base64-encoded response header.  Non-fatal — logs a warning on failure.

  _resolve_stream(content_type, provider, content_id, ...)
      The single place that understands how to turn (type, provider, id) into a
      manifest response — redirect, proxied rewrite, or decrypted rewrite.

Adding VOD in the future means:
  1. Implement manager.get_vod_manifest() / get_vod_drm_configs() (same pattern).
  2. Register the three route URLs for /vod/<vod_id>/{stream,manifest,drm}.
  3. No changes to the shared helpers.
"""

import base64
import json
import re
from urllib.parse import urljoin
from datetime import datetime

from bottle import HTTPResponse, redirect, request, response
from streaming_providers.base.utils import logger
from streaming_providers.base.utils.manifest_utils import ManifestUtils

# ---------------------------------------------------------------------------
# Content-type constants — single source of truth used by helpers and routes
# ---------------------------------------------------------------------------
CONTENT_TYPE_CHANNEL = "channel"
CONTENT_TYPE_EVENT = "event"
CONTENT_TYPE_VOD = "vod"
CONTENT_TYPE_RECORDING = "recording"


def setup_stream_routes(app, manager, service):
    """Setup stream and manifest-related routes."""

    # =========================================================================
    # INTERNAL HELPERS
    # =========================================================================

    def _get_drm_configs(content_type: str, provider: str, content_id: str, **kwargs):
        """
        Dispatch DRM config retrieval to the correct manager method based on
        content type.  Returns a list of DRMConfig objects (may be empty).
        Raises ValueError for unknown provider; re-raises other exceptions.
        """
        if content_type == CONTENT_TYPE_CHANNEL:
            return manager.get_channel_drm_configs(
                provider_name=provider, channel_id=content_id, **kwargs
            )
        elif content_type == CONTENT_TYPE_EVENT:
            return manager.get_event_drm_configs(
                provider_name=provider, event_id=content_id, **kwargs
            )
        elif content_type == CONTENT_TYPE_VOD:
            return manager.get_vod_drm_configs(
                provider_name=provider, vod_id=content_id, **kwargs
            )
        elif content_type == CONTENT_TYPE_RECORDING:
            return manager.get_recording_drm_configs(
                provider_name=provider, recording_id=content_id, **kwargs
            )
        else:
            raise ValueError(f"Unknown content_type '{content_type}'")

    def _get_manifest_url(content_type: str, provider: str, content_id: str, **kwargs) -> str:
        """
        Dispatch manifest URL retrieval to the correct manager method.
        Returns the raw upstream manifest URL (before any proxy rewriting).
        """
        if content_type == CONTENT_TYPE_CHANNEL:
            return manager.get_channel_manifest(
                provider_name=provider, channel_id=content_id, **kwargs
            )
        elif content_type == CONTENT_TYPE_EVENT:
            return manager.get_event_manifest(
                provider_name=provider, event_id=content_id, **kwargs
            )
        elif content_type == CONTENT_TYPE_VOD:
            return manager.get_vod_manifest(
                provider_name=provider, vod_id=content_id, **kwargs
            )
        elif content_type == CONTENT_TYPE_RECORDING:
            return manager.get_recording_manifest(
                provider_name=provider, recording_id=content_id, **kwargs
            )
        else:
            raise ValueError(f"Unknown content_type '{content_type}'")

    def _build_drm_header(
        content_type: str,
        provider: str,
        content_id: str,
        country=None,
        # catchup-specific — only used for channels
        is_catchup: bool = False,
        start_time: int = None,
        end_time: int = None,
        epg_id: str = None,
    ):
        """
        Fetch DRM configs, serialise to JSON and attach as a base64-encoded
        response header (x-kodi-drm-configs).  Non-fatal: logs a warning and
        returns None on any error.
        """
        try:
            if is_catchup and content_type == CONTENT_TYPE_CHANNEL:
                drm_configs = manager.get_catchup_drm_configs(
                    provider_name=provider,
                    channel_id=content_id,
                    start_time=start_time,
                    end_time=end_time,
                    epg_id=epg_id,
                    country=country,
                )
            else:
                drm_configs = _get_drm_configs(
                    content_type, provider, content_id, country=country
                )

            merged = {}
            for config in drm_configs:
                config_dict = config.to_dict() if hasattr(config, "to_dict") else config
                merged.update(config_dict)

            encoded = base64.b64encode(
                json.dumps(merged).encode("utf-8")
            ).decode("ascii")

            response.headers["x-kodi-drm-configs"] = encoded
            return encoded

        except Exception as e:
            logger.warning(
                f"Could not build x-kodi-drm-configs header for "
                f"{content_type} {provider}/{content_id}: {e}"
            )
            return None

    def _build_stream_headers(
        content_type: str,
        provider: str,
        content_id: str,
        country=None,
        # catchup-specific — only used for channels
        is_catchup: bool = False,
        start_time: int = None,
        end_time: int = None,
        epg_id: str = None,
    ):
        """
        Fetch manifest and segment headers from the provider, serialise to JSON
        and attach as a base64-encoded response header (x-kodi-stream-headers).
        Non-fatal: logs a warning and returns None on any error.

        Payload structure:
            {
                "manifest": { <header-name>: <value>, ... },
                "segment":  { <header-name>: <value>, ... }
            }
        Both keys are always present (empty dict if the provider returns nothing).
        """
        try:
            provider_instance = manager.get_provider(provider)
            if not provider_instance:
                return None

            kwargs = {}
            if country:
                kwargs["country"] = country
            if is_catchup and content_type == CONTENT_TYPE_CHANNEL:
                kwargs.update(
                    start_time=start_time,
                    end_time=end_time,
                    epg_id=epg_id,
                )

            manifest_headers = provider_instance.get_manifest_headers(content_id, **kwargs)
            segment_headers = provider_instance.get_segment_headers(content_id, **kwargs)

            payload = {
                "manifest": manifest_headers or {},
                "segment": segment_headers or {},
            }

            encoded = base64.b64encode(
                json.dumps(payload).encode("utf-8")
            ).decode("ascii")

            response.headers["x-kodi-stream-headers"] = encoded
            return encoded

        except Exception as e:
            logger.warning(
                f"Could not build x-kodi-stream-headers header for "
                f"{content_type} {provider}/{content_id}: {e}"
            )
            return None

    def _stream_needs_headers(
            content_type: str, provider: str, content_id: str, country=None
    ) -> bool:
        """
        Returns True if the provider requires manifest or segment headers for
        this content — meaning a plain redirect would lose those headers and
        playback would likely fail.
        """
        try:
            provider_instance = manager.get_provider(provider)
            if not provider_instance:
                return False
            kwargs = {"country": country} if country else {}
            manifest_headers = provider_instance.get_manifest_headers(content_id, **kwargs) or {}
            segment_headers = provider_instance.get_segment_headers(content_id, **kwargs) or {}
            return bool(manifest_headers or segment_headers)
        except Exception as e:
            logger.warning(
                f"Could not check stream headers for {content_type} {provider}/{content_id}: {e}"
            )
            return False  # assume no headers needed; let the redirect attempt proceed

    def _inject_base_url(manifest_text: str, manifest_url: str) -> str:
        existing = ManifestUtils.extract_base_urls(manifest_text)
        if existing:
            return manifest_text

        # Strip the filename, keep the directory — e.g.
        # https://cdn.example.com/live/stream/index.mpd
        # → https://cdn.example.com/live/stream/
        base_url = urljoin(manifest_url, ".")

        base_url_element = f"<BaseURL>{base_url}</BaseURL>"
        return re.sub(
            r"(<MPD\b[^>]*>)",
            rf"\1\n  {base_url_element}",
            manifest_text,
            count=1,
        )

    def _resolve_stream(
            content_type: str,
            provider: str,
            content_id: str,
            country=None,
            # catchup-specific — only used for channels
            is_catchup: bool = False,
            start_time_int: int = None,
            end_time_int: int = None,
            epg_id: str = None,
    ):
        """
        Core stream resolution: attach DRM header, then either redirect to the
        upstream manifest or return a proxy-rewritten manifest body.
        """
        # --- DRM header (best-effort, never fatal) ---
        _build_drm_header(
            content_type, provider, content_id,
            country=country,
            is_catchup=is_catchup,
            start_time=start_time_int,
            end_time=end_time_int,
            epg_id=epg_id,
        )
        # --- Stream headers (best-effort, never fatal) ---
        _build_stream_headers(
            content_type, provider, content_id,
            country=country,
            is_catchup=is_catchup,
            start_time=start_time_int,
            end_time=end_time_int,
            epg_id=epg_id,
        )

        # --- Catchup path (channel-specific) ---
        if is_catchup:
            if manager.needs_proxy(provider):
                return service.get_proxied_catchup_manifest(
                    provider, content_id, start_time_int, end_time_int, epg_id, country
                )
            else:
                manifest_url = manager.get_catchup_manifest(
                    provider_name=provider,
                    channel_id=content_id,
                    start_time=start_time_int,
                    end_time=end_time_int,
                    epg_id=epg_id,
                    country=country,
                )
                if not manifest_url:
                    response.status = 404
                    return {
                        "error": f'Catchup manifest not available for channel "{content_id}"'
                    }
                logger.debug(f"Redirecting to catchup manifest: {manifest_url}")
                redirect(manifest_url)

        # --- Live / event / vod path ---
        if manager.needs_proxy(provider):
            # Check for ClearKey DRM — if present, rewrite manifest with ClearKey signaling
            # so the receiver can decrypt itself, rather than serving a plain proxy stream
            # with stripped ContentProtection that the player cannot handle.
            try:
                drm_configs = _get_drm_configs(
                    content_type, provider, content_id, country=country
                )
                drm_dict = {}
                for config in drm_configs:
                    drm_dict.update(
                        config.to_dict() if hasattr(config, "to_dict") else config
                    )
            except Exception as e:
                logger.warning(
                    f"Could not fetch DRM configs for {content_type} "
                    f"{provider}/{content_id} during proxy resolution: {e}"
                )
                drm_dict = {}

            keyids = (
                drm_dict.get("org.w3.clearkey", {})
                .get("license", {})
                .get("keyids", {})
            )

            if keyids:
                logger.debug(
                    f"ClearKey DRM detected for {provider}/{content_id} "
                    f"— using receiver-side ClearKey rewrite"
                )
                return service.get_decrypted_manifest(
                    provider, content_id, keyids,
                    receiver_side=True,
                )
            else:
                return service.get_proxied_manifest(provider, content_id)
        else:
            # Check if provider requires manifest context (needs HTTP manager to fetch)
            provider_instance = manager.get_provider(provider)

            if provider_instance is None:
                logger.warning(
                    f"_resolve_stream: manager.get_provider('{provider}') returned None — "
                    "cannot check requires_manifest_context; falling back to redirect"
                )

            if provider_instance and getattr(provider_instance, 'requires_manifest_context', False):
                logger.debug(
                    f"Provider {provider} requires manifest context — fetching manifest directly "
                    f"for {content_type}/{content_id}"
                )
                try:
                    manifest_url = _get_manifest_url(
                        content_type, provider, content_id, country=country
                    )
                    if not manifest_url:
                        response.status = 404
                        return {
                            "error": (
                                f'Manifest not available for {content_type} '
                                f'"{content_id}" from provider "{provider}"'
                            )
                        }

                    manifest_text, _, _, _ = service.fetch_manifest_for_rewriter(
                        provider, content_id, manifest_url
                    )

                    # Inject the upstream manifest URL as a BaseURL so the player can
                    # resolve relative segment URLs correctly. Without this, segments
                    # resolve against the local server URL and all requests fail.
                    manifest_text = _inject_base_url(manifest_text, manifest_url)

                    response.content_type = "application/dash+xml; charset=utf-8"
                    return manifest_text

                except Exception as e:
                    logger.error(
                        f"Failed to fetch manifest for {content_type}/{content_id} "
                        f"from {provider}: {e}"
                    )
                    response.status = 502
                    return {"error": f"Failed to fetch manifest: {str(e)}"}
            else:
                manifest_url = _get_manifest_url(
                    content_type, provider, content_id, country=country
                )
                if not manifest_url:
                    response.status = 404
                    return {
                        "error": (
                            f'Manifest not available for {content_type} '
                            f'"{content_id}" from provider "{provider}"'
                        )
                    }
                logger.debug(f"Redirecting to manifest: {manifest_url}")
                return redirect(manifest_url)

    def _resolve_decrypted_stream(
        content_type: str,
        provider: str,
        content_id: str,
        highest_quality_only: bool = False,
    ):
        """
        Shared handler for decrypted stream endpoints.
        Resolves DRM, then returns an appropriately rewritten manifest.
        """
        try:
            country = request.query.get("country")
            drm_configs = _get_drm_configs(
                content_type, provider, content_id, country=country
            )

            drm_dict = {}
            for config in drm_configs:
                drm_dict.update(
                    config.to_dict() if hasattr(config, "to_dict") else config
                )

            has_clearkey = "org.w3.clearkey" in drm_dict
            is_unencrypted = "none" in drm_dict

            if has_clearkey:
                if not service.media_proxy_url:
                    response.status = 503
                    return {"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"}

                keyids = (
                    drm_dict["org.w3.clearkey"]
                    .get("license", {})
                    .get("keyids", {})
                )
                if not keyids:
                    response.status = 400
                    return {"error": "ClearKey DRM found but no key IDs available"}

                return service.get_decrypted_manifest(
                    provider, content_id, keyids,
                    highest_quality_only=highest_quality_only,
                )


            elif is_unencrypted:

                needs_headers = _stream_needs_headers(content_type, provider, content_id, country)

                needs_proxy = manager.needs_proxy(provider)  # ← ADD THIS

                if (needs_headers or needs_proxy) and service.media_proxy_url:  # ← include needs_proxy

                    return service.get_proxied_manifest(

                        provider, content_id,

                        highest_quality_only=highest_quality_only,

                    )

                elif (needs_headers or needs_proxy) and not service.media_proxy_url:  # ← include needs_proxy

                    logger.warning(

                        f"Provider {provider}/{content_id} needs proxy/headers but MEDIA_PROXY_URL is not set; "

                        "falling back to redirect (playback may fail)"

                    )

                    manifest_url = _get_manifest_url(content_type, provider, content_id, country=country)

                    return redirect(manifest_url)

                else:

                    manifest_url = _get_manifest_url(content_type, provider, content_id, country=country)

                    if not manifest_url:
                        response.status = 404

                        return {"error": f'Manifest not available for {content_type} "{content_id}"'}

                    return redirect(manifest_url)

            else:
                response.status = 400
                return {
                    "error": (
                        f'{content_type.capitalize()} "{content_id}" does not support '
                        f"decrypted playback (requires ClearKey or unencrypted)"
                    )
                }

        except HTTPResponse:
            raise
        except ValueError as e:
            logger.error(f"API Error in decrypted {content_type} stream: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"API Error in decrypted {content_type} stream: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    # =========================================================================
    # CHANNEL ROUTES  (preserved exactly — backward-compatible)
    # =========================================================================

    @app.route("/api/providers/<provider>/channels/<channel_id>/manifest")
    def get_channel_manifest(provider, channel_id):
        """
        Returns JSON with a manifest_url pointing to the stream endpoint.
        Attaches x-kodi-drm-configs header.
        """
        try:
            country = request.query.get("country")
            base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
            stream_url = (
                f"{base_url}/api/providers/{provider}/channels/{channel_id}/stream/index.mpd"
            )
            if country:
                stream_url += f"?country={country}"

            _build_drm_header(CONTENT_TYPE_CHANNEL, provider, channel_id, country=country)
            _build_stream_headers(CONTENT_TYPE_CHANNEL, provider, channel_id, country=country)

            return {
                "provider": provider,
                "channel_id": channel_id,
                "manifest_url": stream_url,
            }

        except ValueError as e:
            logger.error(f"manifest endpoint error for {provider}/{channel_id}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"manifest endpoint error for {provider}/{channel_id}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    @app.route("/api/providers/<provider>/<content_type>/<content_id>/manifest/original")
    def get_original_manifest(provider, content_type, content_id):
        """
        Fetch and return the original manifest content without modifications.
        The server fetches the manifest and returns it as-is.

        Supported content_type values:
            - channels
            - events
            - vod
            - recordings

        Example:
            GET /api/providers/rtlplus/channels/123/manifest/original
            GET /api/providers/discovery_de/vod/movie123/manifest/original
        """
        try:
            country = request.query.get("country")

            # Get the upstream manifest URL based on content_type
            if content_type == "channels":
                manifest_url = manager.get_channel_manifest(
                    provider_name=provider,
                    channel_id=content_id,
                    country=country
                )
            elif content_type == "events":
                manifest_url = manager.get_event_manifest(
                    provider_name=provider,
                    event_id=content_id,
                    country=country
                )
            elif content_type == "vod":
                manifest_url = manager.get_vod_manifest(
                    provider_name=provider,
                    vod_id=content_id,
                    country=country
                )
            elif content_type == "recordings":
                manifest_url = manager.get_recording_manifest(
                    provider_name=provider,
                    recording_id=content_id,
                    country=country
                )
            else:
                response.status = 400
                return {"error": f"Invalid content_type: {content_type}"}

            if not manifest_url:
                response.status = 404
                return {"error": f'Manifest not available for {content_type} "{content_id}" from provider "{provider}"'}

            # Use existing helper to fetch manifest
            # _fetch_manifest_for_rewriter expects (provider, channel_id, manifest_url)
            # but we can pass content_id as channel_id since it's just an identifier
            manifest_text, _, _, _ = service.fetch_manifest_for_rewriter(
                provider, content_id, manifest_url
            )

            # Return unmodified manifest
            response.content_type = "application/dash+xml; charset=utf-8"
            return manifest_text

        except ValueError as e:
            logger.error(f"Original manifest error for {provider}/{content_type}/{content_id}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Original manifest error for {provider}/{content_type}/{content_id}: {e}")
            response.status = 500
            return {"error": f"Failed to fetch manifest: {str(e)}"}

    @app.route("/api/providers/<provider>/channels/<channel_id>/stream/index.mpd")
    def get_channel_stream(provider, channel_id):
        """
        Returns HTTP 302 redirect to the actual manifest, or a rewritten
        manifest body when media proxy is active.  Supports live and catchup.
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

                provider_instance = manager.get_provider(provider)
                catchup_hours = getattr(provider_instance, "catchup_window", 0)
                if catchup_hours == 0:
                    response.status = 400
                    return {"error": f'Catchup not supported for provider "{provider}"'}

                import time
                if (int(time.time()) - start_time_int) > catchup_hours * 3600:
                    response.status = 400
                    return {
                        "error": f"Content outside catchup window (max {catchup_hours} hours)"
                    }

                return _resolve_stream(
                    CONTENT_TYPE_CHANNEL, provider, channel_id,
                    country=country,
                    is_catchup=True,
                    start_time_int=start_time_int,
                    end_time_int=end_time_int,
                    epg_id=epg_id,
                )
            else:
                return _resolve_stream(
                    CONTENT_TYPE_CHANNEL, provider, channel_id, country=country
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

    # =========================================================================
    # EVENT ROUTES
    # =========================================================================

    @app.route("/api/providers/<provider>/events/<event_id>/manifest")
    def get_event_manifest(provider, event_id):
        """
        Returns JSON with a manifest_url pointing to the event stream endpoint.
        Attaches x-kodi-drm-configs header.
        """
        try:
            country = request.query.get("country")
            base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
            stream_url = (
                f"{base_url}/api/providers/{provider}/events/{event_id}/stream/index.mpd"
            )
            if country:
                stream_url += f"?country={country}"

            _build_drm_header(CONTENT_TYPE_EVENT, provider, event_id, country=country)
            _build_stream_headers(CONTENT_TYPE_EVENT, provider, event_id, country=country)

            return {
                "provider": provider,
                "event_id": event_id,
                "manifest_url": stream_url,
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

    @app.route(
        "/api/providers/<provider>/events/<event_id>/stream/decrypted/index.mpd"
    )
    def get_event_stream_decrypted(provider, event_id):
        """Decrypted event stream — all quality representations."""
        return _resolve_decrypted_stream(
            CONTENT_TYPE_EVENT, provider, event_id, highest_quality_only=False
        )

    @app.route(
        "/api/providers/<provider>/events/<event_id>/stream/decrypted/ffmpeg/index.mpd"
    )
    def get_event_stream_decrypted_ffmpeg(provider, event_id):
        """Decrypted event stream — highest quality only, optimised for ffmpeg."""
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

    # =========================================================================
    # VOD ROUTES  — identical transport pattern to event routes
    # /manifest  → returns local stream URL + attaches DRM header
    # /stream    → proxy-rewrites or redirects to upstream manifest
    # /drm       → returns raw DRM configs
    # =========================================================================

    @app.route("/api/providers/<provider>/vod/<path:path>/manifest")
    def get_vod_stream_manifest(provider, path):
        """
        Returns JSON with a manifest_url pointing to the VOD stream endpoint.
        The last segment of <path> is the vod_id (edit_id / content_id).
        Attaches x-kodi-drm-configs header.
        """
        vod_id = path.rstrip("/").rsplit("/", 1)[-1]
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

    @app.route("/api/providers/<provider>/vod/<path:path>/stream/index.mpd")
    def get_vod_stream(provider, path):
        vod_id = path.rstrip("/").rsplit("/", 1)[-1]
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

    @app.route(
        "/api/providers/<provider>/vod/<path:path>/stream/decrypted/index.mpd"
    )
    def get_vod_stream_decrypted(provider, path):
        vod_id = path.rstrip("/").rsplit("/", 1)[-1]
        return _resolve_decrypted_stream(
            CONTENT_TYPE_VOD, provider, vod_id, highest_quality_only=False
        )

    @app.route(
        "/api/providers/<provider>/vod/<path:path>/stream/decrypted/ffmpeg/index.mpd"
    )
    def get_vod_stream_decrypted_ffmpeg(provider, path):
        vod_id = path.rstrip("/").rsplit("/", 1)[-1]
        return _resolve_decrypted_stream(
            CONTENT_TYPE_VOD, provider, vod_id, highest_quality_only=True
        )

    @app.route("/api/providers/<provider>/vod/<path:path>/drm")
    def get_vod_drm(provider, path):
        vod_id = path.rstrip("/").rsplit("/", 1)[-1]
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

    # =========================================================================
    # RECORDING ROUTES  — identical transport pattern to VOD routes
    #
    # Recordings are always on-demand (pre-captured), so:
    #   - No catchup path (unlike channels)
    #   - No ffmpeg variant (not a live/adaptive stream that needs quality pinning)
    #   - recording_id is a flat identifier, no path hierarchy needed
    #
    # /manifest  → returns local stream URL + attaches DRM header
    # /stream    → proxy-rewrites or redirects to upstream manifest
    # /drm       → returns raw DRM configs
    # =========================================================================

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
        "/api/providers/<provider>/recordings/<recording_id>/stream/decrypted/index.mpd"
    )
    def get_recording_stream_decrypted(provider, recording_id):
        """Decrypted recording stream — all quality representations."""
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

    # =========================================================================
    # EPG ROUTES  (unchanged from original)
    # =========================================================================

    @app.route("/api/providers/<provider>/channels/<channel_id>/epg")
    def get_channel_epg(provider, channel_id):
        try:
            kwargs = {"country": request.query.get("country")}

            from datetime import timezone

            if request.query.get("start_time"):
                start_time_str = request.query.get("start_time")
                try:
                    kwargs["start_time"] = datetime.fromtimestamp(
                        int(start_time_str), tz=timezone.utc
                    )
                except (ValueError, TypeError):
                    try:
                        kwargs["start_time"] = datetime.fromisoformat(
                            start_time_str.replace("Z", "+00:00")
                        )
                    except ValueError:
                        logger.warning(f"Invalid start_time format: {start_time_str}")

            if request.query.get("end_time"):
                end_time_str = request.query.get("end_time")
                try:
                    kwargs["end_time"] = datetime.fromtimestamp(
                        int(end_time_str), tz=timezone.utc
                    )
                except (ValueError, TypeError):
                    try:
                        kwargs["end_time"] = datetime.fromisoformat(
                            end_time_str.replace("Z", "+00:00")
                        )
                    except ValueError:
                        logger.warning(f"Invalid end_time format: {end_time_str}")

            epg_data = manager.get_channel_epg(
                provider_name=provider, channel_id=channel_id, **kwargs
            )

            response.content_type = "application/json; charset=utf-8"
            return {"provider": provider, "channel_id": channel_id, "epg": epg_data}

        except ValueError as e:
            logger.error(f"EPG error for {provider}/{channel_id}: {e}")
            response.status = 404
            response.content_type = "application/json; charset=utf-8"
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"EPG error for {provider}/{channel_id}: {e}")
            response.status = 500
            response.content_type = "application/json; charset=utf-8"
            return {"error": f"Internal server error: {str(e)}"}

    @app.route("/api/providers/<provider>/epg")
    def get_provider_epg_xmltv(provider):
        try:
            response.content_type = "application/xml; charset=utf-8"
            response.headers["Content-Disposition"] = (
                f'attachment; filename="{provider}_epg.xml"'
            )

            xmltv_data = manager.get_provider_epg_xmltv(
                provider_name=provider, country=request.query.get("country")
            )

            if not xmltv_data:
                response.status = 404
                return {"error": f'EPG data not available for provider "{provider}"'}

            return xmltv_data

        except ValueError as e:
            logger.error(f"XMLTV EPG error for {provider}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"XMLTV EPG error for {provider}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}