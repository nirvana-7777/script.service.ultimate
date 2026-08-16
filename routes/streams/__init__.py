#!/usr/bin/env python3
"""
Stream route shared helpers and orchestration.

This module contains the core logic that all content types (channels, events,
VOD, recordings) share. Individual content type modules define only their
route decorators and call the helpers defined here.

Architecture
============
All content types share identical transport-level operations: resolve a
manifest URL, fetch DRM configs, optionally rewrite the manifest through a
media proxy. The typed route handlers are thin wrappers around two shared
helpers:

  _build_drm_header(content_type, provider, content_id, ...)
      Fetches DRM configs via the correct manager method and attaches them as a
      base64-encoded response header. Non-fatal — logs a warning on failure.
      Returns the fetched DRMConfig list (or [] on failure) so callers that
      also need the configs don't have to fetch them a second time.

  _resolve_stream(content_type, provider, content_id, ...)
      The single place that understands how to turn (type, provider, id) into a
      manifest response — redirect, proxied rewrite, or decrypted rewrite.

  _resolve_decrypted_stream(content_type, provider, content_id, ...)
      Returns a manifest with server-side decryption (ClearKey keys injected).
"""

import base64
import json
import re
from urllib.parse import urljoin

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
    """Register all stream routes from submodules."""
    from .channels import setup_channel_routes
    from .events import setup_event_routes
    from .vod import setup_vod_routes
    from .recordings import setup_recording_routes

    # Build the shared helpers once and hand the same dict to every submodule,
    # rather than each submodule creating its own independent closure set.
    helpers = make_helpers(manager, service)

    setup_channel_routes(app, manager, service, helpers)
    setup_event_routes(app, manager, service, helpers)
    setup_vod_routes(app, manager, service, helpers)
    setup_recording_routes(app, manager, service, helpers)

    # =========================================================================
    # ORIGINAL MANIFEST ENDPOINT (shared across content types)
    # =========================================================================

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

            _get_manifest_url = helpers["_get_manifest_url"]

            # Map content_type string to constant
            content_type_map = {
                "channels": CONTENT_TYPE_CHANNEL,
                "events": CONTENT_TYPE_EVENT,
                "vod": CONTENT_TYPE_VOD,
                "recordings": CONTENT_TYPE_RECORDING,
            }

            if content_type not in content_type_map:
                response.status = 400
                return {"error": f"Invalid content_type: {content_type}"}

            ct_const = content_type_map[content_type]

            # Get the upstream manifest URL
            manifest_url = _get_manifest_url(
                ct_const, provider, content_id, country=country
            )

            if not manifest_url:
                response.status = 404
                return {"error": f'Manifest not available for {content_type} "{content_id}" from provider "{provider}"'}

            # Use service.fetch_manifest_for_rewriter to fetch manifest
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


def _serialize_drm_configs(drm_configs) -> dict:
    """
    Merge a list of DRMConfig objects (or plain dicts) into a single dict,
    keyed by DRM scheme (e.g. 'org.w3.clearkey', 'none').

    Shared by every call site that needs to turn a list of DRM configs into
    the merged dict shape used for the response header and for ClearKey
    keyid lookups.
    """
    merged = {}
    for config in drm_configs:
        config_dict = config.to_dict() if hasattr(config, "to_dict") else config
        merged.update(config_dict)
    return merged


def make_helpers(manager, service):
    """
    Factory function that creates helper functions with manager and service
    closures. Returns a dict of helpers for submodules to use.
    """

    # =========================================================================
    # INTERNAL HELPERS (with manager and service closed over)
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
        returns [] on any error.

        Args:
            drm_variant: 'auto' or 'software'.  Forwarded to the DRM config
                         fetch so the provider can return ClearKey configs when
                         the software-DRM variant is requested.

        Returns:
            The list of DRMConfig objects that were fetched (or [] on failure).
            Callers that also need the raw configs (e.g. _resolve_stream) can
            reuse this instead of fetching them again.
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

            merged = _serialize_drm_configs(drm_configs)

            encoded = base64.b64encode(
                json.dumps(merged).encode("utf-8")
            ).decode("ascii")

            response.headers["x-kodi-drm-configs"] = encoded
            return drm_configs

        except Exception as e:
            logger.warning(
                f"Could not build x-kodi-drm-configs header for "
                f"{content_type} {provider}/{content_id} (variant={drm_variant}): {e}"
            )
            return []

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
        """Inject BaseURL element into MPD if none exists."""
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
            start_time: int = None,
            end_time: int = None,
            epg_id: str = None,
            drm_variant: str = "auto",
            no_proxy: bool = False,
    ):
        """
        Core stream resolution: attach DRM header, then either redirect to the
        upstream manifest or return a proxy-rewritten manifest body.

        Args:
            drm_variant: 'auto' (provider decides) or 'software' (prefer ClearKey /
                         software-decodable DRM).  Threaded through to all helpers so
                         providers can return the correct manifest URL and DRM configs.
            no_proxy: If True, force the redirect-to-upstream branch even for
                      providers that would normally be proxied. This overrides the
                      manager.needs_proxy(provider) checks below rather than adding
                      a separate code path, so catchup, DRM header building, and
                      requires_manifest_context handling all continue to work
                      exactly as they do for the proxied case — only the
                      proxy-vs-redirect decision changes.
        """
        # --- DRM header (best-effort, never fatal). Also returns the DRM
        # configs it fetched so the proxy branch below can reuse them instead
        # of fetching from the provider a second time. ---
        drm_configs_for_header = _build_drm_header(
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
            if manager.needs_proxy(provider) and not no_proxy:
                return service.get_proxied_catchup_manifest(
                    provider, content_id, start_time, end_time, epg_id, country
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
        if manager.needs_proxy(provider) and not no_proxy:
            # Check for ClearKey DRM — if present, rewrite manifest with ClearKey signaling
            # so the receiver can decrypt itself, rather than serving a plain proxy stream
            # with stripped ContentProtection that the player cannot handle.
            #
            # Reuse the configs _build_drm_header already fetched above rather than
            # calling the provider again. This branch is only reached when
            # is_catchup is False, so drm_configs_for_header always corresponds to
            # the non-catchup fetch performed above.
            drm_dict = _serialize_drm_configs(drm_configs_for_header)

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
        Resolves DRM, then returns an appropriately rewritten manifest.

        For channel catchup (start_time + end_time query params present) the
        handler fetches the catchup DRM configs and catchup manifest URL so that
        server-side decryption operates on the correct DVR/time-shifted stream
        rather than the live channel manifest.  receiver_side is always False
        here — the /decrypted/ endpoint contract is that the server decrypts.
        """
        try:
            country = request.query.get("country")

            # ------------------------------------------------------------------
            # Catchup branch — channels only.
            # When start_time + end_time are present we must use the catchup
            # DRM configs and catchup manifest URL.  The live path below would
            # silently fetch the live manifest and encrypt/decrypt against the
            # wrong stream.
            # ------------------------------------------------------------------
            start_time = request.query.get("start_time")
            end_time = request.query.get("end_time")
            epg_id = request.query.get("epg_id")
            is_catchup = bool(start_time and end_time and content_type == CONTENT_TYPE_CHANNEL)

            if is_catchup:
                try:
                    start_time_int = int(start_time)
                    end_time_int = int(end_time)
                except (ValueError, TypeError):
                    response.status = 400
                    return {"error": "Invalid start_time or end_time format"}

                if not service.media_proxy_url:
                    response.status = 503
                    return {"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"}

                catchup_drm_configs = manager.get_catchup_drm_configs(
                    provider_name=provider,
                    channel_id=content_id,
                    start_time=start_time_int,
                    end_time=end_time_int,
                    epg_id=epg_id,
                    country=country,
                )
                catchup_drm_dict = _serialize_drm_configs(catchup_drm_configs)

                is_unencrypted = "none" in catchup_drm_dict
                keyids = (
                    catchup_drm_dict.get("org.w3.clearkey", {})
                    .get("license", {})
                    .get("keyids", {})
                )

                if is_unencrypted:
                    return service.get_proxied_catchup_manifest(
                        provider, content_id, start_time_int, end_time_int, epg_id, country
                    )

                if not keyids:
                    response.status = 400
                    return {"error": "ClearKey DRM not available for this catchup content"}

                return service.get_decrypted_catchup_manifest(
                    provider, content_id,
                    start_time=start_time_int,
                    end_time=end_time_int,
                    keyids=keyids,
                    epg_id=epg_id,
                    highest_quality_only=highest_quality_only,
                )

            # ------------------------------------------------------------------
            # Live / VOD / event / recording path
            # ------------------------------------------------------------------
            drm_configs = _get_drm_configs(
                content_type, provider, content_id, country=country
            )

            drm_dict = _serialize_drm_configs(drm_configs)

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
                # Decrypted-stream endpoints do not support catchup — catchup requires a
                # live DVR manifest URL which must be resolved via _resolve_stream / the
                # catchup path.  Unencrypted content here is always VOD or live-redirect.
                needs_headers = _stream_needs_headers(content_type, provider, content_id, country)
                needs_proxy = manager.needs_proxy(provider)

                if (needs_headers or needs_proxy) and service.media_proxy_url:
                    return service.get_proxied_manifest(
                        provider, content_id,
                        highest_quality_only=highest_quality_only,
                    )
                elif (needs_headers or needs_proxy) and not service.media_proxy_url:
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

    # Return all helpers as a dict for submodules to use
    return {
        "CONTENT_TYPE_CHANNEL": CONTENT_TYPE_CHANNEL,
        "CONTENT_TYPE_EVENT": CONTENT_TYPE_EVENT,
        "CONTENT_TYPE_VOD": CONTENT_TYPE_VOD,
        "CONTENT_TYPE_RECORDING": CONTENT_TYPE_RECORDING,
        "_get_drm_configs": _get_drm_configs,
        "_get_manifest_url": _get_manifest_url,
        "_build_drm_header": _build_drm_header,
        "_build_stream_headers": _build_stream_headers,
        "_stream_needs_headers": _stream_needs_headers,
        "_inject_base_url": _inject_base_url,
        "_resolve_stream": _resolve_stream,
        "_resolve_decrypted_stream": _resolve_decrypted_stream,
        "_serialize_drm_configs": _serialize_drm_configs,
    }