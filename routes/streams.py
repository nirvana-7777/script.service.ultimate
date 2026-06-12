#!/usr/bin/env python3
"""
Stream and manifest route handlers.

Architecture
============
All content types (channels, events, future VOD) share identical transport-level
operations: resolve a manifest URL, fetch DRM configs, optionally rewrite the
manifest through a media proxy.  The typed route handlers (channel vs event vs
vod) are therefore thin wrappers around shared helpers:

  _validate_catchup_params(provider, channel_id, start_time_raw, end_time_raw)
      Validates catchup timestamps and window eligibility for a channel.
      Returns an error string on failure, or (start_time_int, end_time_int) on
      success.  Single source of truth — called by both _handle_channel_stream
      and _resolve_decrypted_stream.

  _build_drm_header(content_type, provider, content_id, ...)
      Fetches DRM configs via the correct manager method and attaches them as a
      base64-encoded response header.  Non-fatal — logs a warning on failure.

  _resolve_stream(content_type, provider, content_id, ...)
      The single place that understands how to turn (type, provider, id) into a
      manifest response — redirect, proxied rewrite, or decrypted rewrite.

  _resolve_decrypted_stream(content_type, provider, content_id, ...)
      Handles /stream/decrypted/ endpoints.  Supports live and catchup for
      channels (catchup via start_time/end_time query params).  Delegates all
      fetch/rewrite work to the service layer — never constructs rewriters
      directly.

Adding VOD in the future means:
  1. Implement manager.get_vod_manifest() / get_vod_drm_configs() (same pattern).
  2. Register the three route URLs for /vod/<vod_id>/{stream,manifest,drm}.
  3. No changes to the shared helpers.
"""

import base64
import json
import re
import time
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

    def _get_drm_configs(
        content_type: str,
        provider: str,
        content_id: str,
        drm_variant: str = "auto",
        **kwargs,
    ):
        """
        Dispatch DRM config retrieval to the correct manager method based on
        content type.  Returns a list of DRMConfig objects (may be empty).
        Raises ValueError for unknown provider; re-raises other exceptions.

        Args:
            drm_variant: 'auto' (provider default) or 'software' (prefer ClearKey).
                         Passed through to the provider via **kwargs so individual
                         providers can select an appropriate DRM scheme.
        """
        kwargs.setdefault("drm_variant", drm_variant)
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

    def _get_manifest_url(
        content_type: str,
        provider: str,
        content_id: str,
        drm_variant: str = "auto",
        **kwargs,
    ) -> str:
        """
        Dispatch manifest URL retrieval to the correct manager method.
        Returns the raw upstream manifest URL (before any proxy rewriting).

        Args:
            drm_variant: 'auto' or 'software'.  Passed through so providers that
                         expose separate ClearKey manifest URLs can return the
                         correct one.
        """
        kwargs.setdefault("drm_variant", drm_variant)
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
        drm_variant: str = "auto",
    ):
        """
        Fetch DRM configs, serialise to JSON and attach as a base64-encoded
        response header (x-kodi-drm-configs).  Non-fatal: logs a warning and
        returns None on any error.

        Args:
            drm_variant: 'auto' or 'software'.  Forwarded to the DRM config
                         fetch so the provider can return ClearKey configs when
                         the software-DRM variant is requested.
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
                    drm_variant=drm_variant,
                )
            else:
                drm_configs = _get_drm_configs(
                    content_type, provider, content_id,
                    country=country, drm_variant=drm_variant,
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
                f"{content_type} {provider}/{content_id} (variant={drm_variant}): {e}"
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
            content_type: str,
            provider: str,
            content_id: str,
            country=None,
            # catchup-specific — forwarded so providers can return catchup-appropriate headers
            is_catchup: bool = False,
            start_time: int = None,
            end_time: int = None,
            epg_id: str = None,
    ) -> bool:
        """
        Returns True if the provider requires manifest or segment headers for
        this content — meaning a plain redirect would lose those headers and
        playback would likely fail.

        Catchup context (is_catchup, start_time, end_time, epg_id) is forwarded
        to the provider so it can return headers appropriate for the DVR/catchup
        endpoint rather than the live endpoint.  Without this, providers that use
        different auth tokens for catchup would return live headers here and the
        proxy decision could be wrong.
        """
        try:
            provider_instance = manager.get_provider(provider)
            if not provider_instance:
                return False
            kwargs = {}
            if country:
                kwargs["country"] = country
            if is_catchup and content_type == CONTENT_TYPE_CHANNEL:
                kwargs.update(
                    start_time=start_time,
                    end_time=end_time,
                    epg_id=epg_id,
                )
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

    def _validate_catchup_params(
        provider: str,
        channel_id: str,
        start_time_raw,
        end_time_raw,
    ):
        """
        Validate catchup timestamps and window eligibility for a channel.

        Returns a tuple (start_time_int, end_time_int) on success, or raises
        ValueError with a human-readable message on any validation failure.

        Single source of truth — called by both _handle_channel_stream and
        _resolve_decrypted_stream so the logic is never duplicated.
        """
        try:
            start_time_int = int(start_time_raw)
            end_time_int   = int(end_time_raw)
        except (ValueError, TypeError):
            raise ValueError(
                f"Invalid start_time={start_time_raw!r} or end_time={end_time_raw!r}: "
                "expected Unix timestamps"
            )

        channels = manager.get_channels(provider_name=provider, fetch_manifests=False)
        channel_obj = next((c for c in channels if c.channel_id == channel_id), None)

        logger.debug(
            f"_validate_catchup_params: channel lookup id={channel_id!r} -> "
            + (
                f"found (catchup_hours={getattr(channel_obj, 'catchup_hours', 'MISSING')!r}, "
                f"catchup_window={getattr(channel_obj, 'catchup_window', 'MISSING')!r})"
                if channel_obj
                else "NOT FOUND in channel list"
            )
        )

        # The model field is catchup_hours (serialises as CatchupHours).
        # Fall back to catchup_window for providers using the older name.
        catchup_hours = (
            getattr(channel_obj, "catchup_hours", None)
            or getattr(channel_obj, "catchup_window", 0)
        ) if channel_obj else 0

        logger.debug(f"_validate_catchup_params: resolved catchup_hours={catchup_hours!r}")

        if not catchup_hours:
            raise ValueError(f'Catchup not supported for channel "{channel_id}"')

        age_seconds = int(time.time()) - start_time_int
        logger.debug(
            f"_validate_catchup_params: window check age={age_seconds}s "
            f"limit={catchup_hours * 3600}s ({catchup_hours}h)"
        )
        if age_seconds > catchup_hours * 3600:
            raise ValueError(
                f"Content outside catchup window (max {catchup_hours} hours)"
            )

        return start_time_int, end_time_int

    def _resolve_stream(
            content_type: str,
            provider: str,
            content_id: str,
            country=None,
            # catchup-specific — only used for channels
            is_catchup: bool = False,
            start_time: int = None,
            end_time: int = None,
            epg_id: str = None,
            drm_variant: str = "auto",
    ):
        """
        Core stream resolution: attach DRM header, then either redirect to the
        upstream manifest or return a proxy-rewritten manifest body.

        Args:
            drm_variant: 'auto' (provider decides) or 'software' (prefer ClearKey /
                         software-decodable DRM).  Threaded through to all helpers so
                         providers can return the correct manifest URL and DRM configs.
        """
        # --- DRM header (best-effort, never fatal) ---
        _build_drm_header(
            content_type, provider, content_id,
            country=country,
            is_catchup=is_catchup,
            start_time=start_time,
            end_time=end_time,
            epg_id=epg_id,
            drm_variant=drm_variant,
        )
        # --- Stream headers (best-effort, never fatal) ---
        _build_stream_headers(
            content_type, provider, content_id,
            country=country,
            is_catchup=is_catchup,
            start_time=start_time,
            end_time=end_time,
            epg_id=epg_id,
        )

        # --- Catchup path (channel-specific) ---
        if is_catchup:
            if manager.needs_proxy(provider):
                return service.get_proxied_catchup_manifest(
                    provider, content_id, start_time, end_time, epg_id, country,
                    drm_variant=drm_variant,
                )
            else:
                manifest_url = manager.get_catchup_manifest(
                    provider_name=provider,
                    channel_id=content_id,
                    start_time=start_time,
                    end_time=end_time,
                    epg_id=epg_id,
                    country=country,
                    drm_variant=drm_variant,
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
                    content_type, provider, content_id,
                    country=country, drm_variant=drm_variant,
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

            # When the caller explicitly requested software DRM and we found no
            # ClearKey keys, surface a clear error rather than silently serving a
            # Widevine stream the client cannot decrypt.
            if drm_variant == "software" and not keyids:
                logger.warning(
                    f"Software DRM requested but no ClearKey keys found for "
                    f"{provider}/{content_id}"
                )
                response.status = 400
                return {"error": "Software DRM not available for this content"}

            if keyids:
                logger.debug(
                    f"ClearKey DRM detected for {provider}/{content_id} "
                    f"(variant={drm_variant}) — using receiver-side ClearKey rewrite"
                )
                return service.get_decrypted_manifest(
                    provider, content_id, keyids,
                    receiver_side=True,
                    drm_variant=drm_variant,
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
                        content_type, provider, content_id,
                        country=country, drm_variant=drm_variant,
                    )
                    if not manifest_url:
                        response.status = 404
                        return {
                            "error": (
                                f'Manifest not available for {content_type} '
                                f'"{content_id}" from provider "{provider}"'
                            )
                        }

                    manifest_text, _, _, _, effective_url = service.fetch_manifest_for_rewriter(
                        provider, content_id, manifest_url
                    )

                    # Inject the upstream manifest URL as a BaseURL so the player can
                    # resolve relative segment URLs correctly. Without this, segments
                    # resolve against the local server URL and all requests fail.
                    manifest_text = _inject_base_url(manifest_text, effective_url)

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
                    content_type, provider, content_id,
                    country=country, drm_variant=drm_variant,
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

        Supports live and catchup content for channels.  Catchup is triggered
        by the presence of start_time + end_time query parameters (same aliases
        as _handle_channel_stream: start_time/start/utc and end_time/end).

        All fetch/rewrite work is delegated to the service layer — this handler
        only resolves DRM configs and routes to the appropriate service method.
        """
        try:
            country = request.query.get("country")

            # Parse catchup parameters — same aliases as _handle_channel_stream
            start_time_raw = (
                request.query.get("start_time")
                or request.query.get("start")
                or request.query.get("utc")
            )
            end_time_raw = request.query.get("end_time") or request.query.get("end")
            epg_id       = request.query.get("epg_id")
            is_catchup   = bool(start_time_raw and end_time_raw) and content_type == CONTENT_TYPE_CHANNEL

            start_time_int: int | None = None
            end_time_int:   int | None = None

            if is_catchup:
                # _validate_catchup_params raises ValueError with a human-readable
                # message on any failure; the except block below converts it to 400/404.
                start_time_int, end_time_int = _validate_catchup_params(
                    provider, content_id, start_time_raw, end_time_raw
                )

            # Fetch DRM configs — catchup and live use different manager methods
            if is_catchup:
                drm_configs = manager.get_catchup_drm_configs(
                    provider_name=provider,
                    channel_id=content_id,
                    start_time=start_time_int,
                    end_time=end_time_int,
                    epg_id=epg_id,
                    country=country,
                    drm_variant="software",  # decrypted endpoint implies software DRM
                )
            else:
                drm_configs = _get_drm_configs(
                    content_type, provider, content_id,
                    country=country, drm_variant="software",
                )

            drm_dict = {}
            for config in drm_configs:
                drm_dict.update(
                    config.to_dict() if hasattr(config, "to_dict") else config
                )

            has_clearkey  = "org.w3.clearkey" in drm_dict
            is_unencrypted = "none" in drm_dict

            # ------------------------------------------------------------------
            # ClearKey (software DRM) path
            # ------------------------------------------------------------------
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

                if is_catchup:
                    # Delegate to the service layer — it owns all fetch/rewrite
                    # logic including proxy decisions and segment header injection.
                    return service.get_decrypted_catchup_manifest(
                        provider, content_id, keyids,
                        start_time=start_time_int,
                        end_time=end_time_int,
                        epg_id=epg_id,
                        country=country,
                        highest_quality_only=highest_quality_only,
                        receiver_side=True,
                        drm_variant="software",
                    )
                else:
                    return service.get_decrypted_manifest(
                        provider, content_id, keyids,
                        highest_quality_only=highest_quality_only,
                        receiver_side=True,
                        drm_variant="software",
                    )

            # ------------------------------------------------------------------
            # Unencrypted path
            # ------------------------------------------------------------------
            elif is_unencrypted:
                if is_catchup:
                    # For unencrypted catchup we still need the DVR manifest URL —
                    # route through the same proxy-aware catchup path as _resolve_stream.
                    if manager.needs_proxy(provider):
                        return service.get_proxied_catchup_manifest(
                            provider, content_id,
                            start_time_int, end_time_int, epg_id, country,
                            drm_variant="auto",
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
                        logger.debug(
                            f"_resolve_decrypted_stream: redirecting to unencrypted "
                            f"catchup manifest: {manifest_url}"
                        )
                        return redirect(manifest_url)
                else:
                    needs_headers = _stream_needs_headers(content_type, provider, content_id, country)
                    needs_proxy   = manager.needs_proxy(provider)

                    if (needs_headers or needs_proxy) and service.media_proxy_url:
                        return service.get_proxied_manifest(
                            provider, content_id,
                            highest_quality_only=highest_quality_only,
                        )
                    elif (needs_headers or needs_proxy) and not service.media_proxy_url:
                        logger.warning(
                            f"Provider {provider}/{content_id} needs proxy/headers but "
                            "MEDIA_PROXY_URL is not set; falling back to redirect (playback may fail)"
                        )
                        manifest_url = _get_manifest_url(content_type, provider, content_id, country=country)
                        return redirect(manifest_url)
                    else:
                        manifest_url = _get_manifest_url(content_type, provider, content_id, country=country)
                        if not manifest_url:
                            response.status = 404
                            return {"error": f'Manifest not available for {content_type} "{content_id}"'}
                        return redirect(manifest_url)

            # ------------------------------------------------------------------
            # No supported DRM scheme
            # ------------------------------------------------------------------
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
            response.status = 400
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
            manifest_text, _, _, _, _ = service.fetch_manifest_for_rewriter(
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

    def _handle_channel_stream(provider, channel_id, *, drm_variant="auto"):
        """Shared implementation for /stream/index.mpd and /stream/sw-drm/index.mpd."""
        try:
            start_time_raw = (
                request.query.get("start_time")
                or request.query.get("start")
                or request.query.get("utc")
            )
            end_time_raw = request.query.get("end_time") or request.query.get("end")
            epg_id       = request.query.get("epg_id")
            country      = request.query.get("country")
            is_catchup   = bool(start_time_raw and end_time_raw)

            logger.debug(
                f"_handle_channel_stream: provider={provider} channel={channel_id} "
                f"start_time={start_time_raw!r} end_time={end_time_raw!r} "
                f"epg_id={epg_id!r} country={country!r} is_catchup={is_catchup} "
                f"drm_variant={drm_variant}"
            )

            # Always defined so the _resolve_stream call below is unconditionally safe,
            # even though the ternary guards already prevent None from being passed when
            # is_catchup is False.
            start_time_int: int | None = None
            end_time_int:   int | None = None

            if is_catchup:
                # _validate_catchup_params raises ValueError with a human-readable
                # message; the except block below converts it to 400/404.
                start_time_int, end_time_int = _validate_catchup_params(
                    provider, channel_id, start_time_raw, end_time_raw
                )
                logger.debug(
                    f"CATCHUP: validated OK: {start_time_int} to {end_time_int}"
                )

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
            response.status = 400
            return {"error": str(e)}
        except Exception as e:
            label = "sw-drm " if drm_variant == "software" else ""
            logger.error(f"{label}stream error for channel {provider}/{channel_id}: {e}")
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

    # =========================================================================
    # EVENT ROUTES
    # =========================================================================

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
        Software-DRM (ClearKey) event stream endpoint.

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
    def get_vod_stream_manifest(provider, path):
        vod_id = path.split("/")[0]  # Fix here too
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
        vod_id = path.split("/")[0]  # Fix here too
        return _resolve_decrypted_stream(
            CONTENT_TYPE_VOD, provider, vod_id, highest_quality_only=False
        )

    @app.route("/api/providers/<provider>/vod/<path:path>/stream/decrypted/ffmpeg/index.mpd")
    def get_vod_stream_decrypted_ffmpeg(provider, path):
        vod_id = path.split("/")[0]  # Fix here too
        return _resolve_decrypted_stream(
            CONTENT_TYPE_VOD, provider, vod_id, highest_quality_only=True
        )

    @app.route("/api/providers/<provider>/vod/<path:path>/drm")
    def get_vod_drm(provider, path):
        vod_id = path.split("/")[0]  # Fix here too
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