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
import time
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

    def _validate_catchup_window(provider: str, content_id: str, start_time: int):
        """
        Checks start_time against the channel's catchup_hours window.
        Returns an error dict (suitable for a 400 response) if the channel
        doesn't support catchup or the window has been exceeded; None if valid.

        Extracted from channels.py's _handle_channel_stream so
        _resolve_decrypted_stream can apply the same check — previously it
        skipped this validation entirely, letting catchup requests outside the
        provider's DVR window through to the decrypted-stream path when the
        standard path would reject them with a 400.
        """
        channels = manager.get_channels(provider_name=provider, fetch_manifests=False)
        channel_obj = next((c for c in channels if c.channel_id == content_id), None)

        catchup_hours = (
            getattr(channel_obj, "catchup_hours", None)
            or getattr(channel_obj, "catchup_window", 0)
        ) if channel_obj else 0

        if not catchup_hours:
            logger.warning(
                f"CATCHUP: rejecting {provider}/{content_id} — "
                f"catchup_hours=0 or attribute not found on channel model"
            )
            return {"error": f'Catchup not supported for channel "{content_id}"'}

        age_seconds = int(time.time()) - start_time
        if age_seconds > catchup_hours * 3600:
            return {"error": f"Content outside catchup window (max {catchup_hours} hours)"}

        return None

    def _redirect_or_fetch(content_type: str, provider: str, content_id: str,
                            country, drm_variant: str):
        """
        Shared tail behavior for every "no proxy involved" outcome, across all
        three modes: check requires_manifest_context and either fetch + inject
        BaseURL, or do a plain redirect. Extracted so mode="noproxy" (live/vod),
        mode="auto"'s non-proxied branch, and mode="playable"'s unencrypted/
        no-proxy-needed branch all get identical, correct behavior instead of
        three independently-maintained copies (previously the decrypt path had
        none of this at all and always redirected unconditionally).
        """
        provider_instance = manager.get_provider(provider)

        if provider_instance is None:
            logger.warning(
                f"_redirect_or_fetch: manager.get_provider('{provider}') returned None — "
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

    def _resolve_stream_unified(
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
            mode: str = "auto",
            receiver_side: bool = True,
            highest_quality_only: bool = False,
    ):
        """
        Single resolver for every stream endpoint — replaces the former
        _resolve_stream / _resolve_decrypted_stream split. Both names still
        exist below as thin wrappers for existing call sites.

        Args:
            drm_variant: 'auto' (provider decides) or 'software'. This selects
                         which upstream DRM/quality variant to request (e.g. a
                         provider's L1 vs L3 Widevine stream) — orthogonal to
                         `mode`, which governs transport (proxy/playable/redirect).
            mode: "auto"    - proxy if the provider needs it, else redirect/fetch.
                              ClearKey content is always rewritten receiver-side
                              (client decrypts) — this is the historical /stream/
                              contract and is not caller-configurable.
                  "playable" - guarantees the client gets a manifest it can
                              actually play without doing its own key
                              exchange, or an honest error — never a manifest
                              it can't handle. ClearKey content is rewritten
                              via the media proxy (receiver_side controls
                              client- vs server-side decrypt); requires
                              MEDIA_PROXY_URL. Unencrypted content falls
                              through to the same proxy/redirect behavior as
                              mode="auto" — nothing to decrypt but nothing
                              blocking playback either. Content that's
                              neither ClearKey nor unencrypted (e.g.
                              Widevine-only) is rejected with a 400, since
                              this mode can't hand such a client anything
                              playable — applies equally to live/VOD and
                              catchup. (Named for the contract it guarantees,
                              not the ClearKey mechanism it mostly relies on
                              — the old /stream/proxied/ endpoints this mode
                              backs are exactly this "simple client" case.)
                  "noproxy" - force redirect/fetch even if the provider would
                              normally be proxied.
            receiver_side: Only consulted when mode="playable". True = client
                           decrypts (ClearKey signaled in the manifest), False =
                           server decrypts and serves plaintext segments.
            highest_quality_only: Honored wherever the underlying service call
                           supports it (get_proxied_manifest, get_decrypted_manifest,
                           get_decrypted_catchup_manifest). get_proxied_catchup_manifest
                           has no such parameter today, so it's a no-op for
                           mode="auto"/"playable" catchup content that turns out
                           unencrypted. Meaningless for mode="noproxy" (plain
                           redirect, no rewriter involved).
        """
        # --- Catchup window validation (channels only), before anything else —
        # previously duplicated between channels.py (for auto/noproxy) and
        # _resolve_decrypted_stream (for decrypt); now the single source of truth
        # for every mode, so channels.py no longer needs its own copy. ---
        if is_catchup and content_type == CONTENT_TYPE_CHANNEL:
            window_error = _validate_catchup_window(provider, content_id, start_time)
            if window_error:
                response.status = 400
                return window_error

        # --- DRM header (best-effort, never fatal). Also returns the DRM
        # configs it fetched so the branches below can reuse them instead of
        # fetching from the provider a second time. ---
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

        drm_dict = _serialize_drm_configs(drm_configs_for_header)
        keyids = (
            drm_dict.get("org.w3.clearkey", {})
            .get("license", {})
            .get("keyids", {})
        )
        is_unencrypted = "none" in drm_dict

        # ==================================================================
        # Catchup path (channel-specific)
        # ==================================================================
        if is_catchup:
            if mode == "noproxy":
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
                return redirect(manifest_url)

            if mode == "playable":
                if keyids:
                    if not service.media_proxy_url:
                        response.status = 503
                        return {"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"}
                    return service.get_decrypted_catchup_manifest(
                        provider, content_id,
                        start_time=start_time, end_time=end_time,
                        keyids=keyids, epg_id=epg_id,
                        receiver_side=receiver_side,
                        highest_quality_only=highest_quality_only,
                    )
                elif is_unencrypted:
                    # Nothing to decrypt, but nothing blocking playback either —
                    # same fallback mode="auto" would use for this content.
                    return service.get_proxied_catchup_manifest(
                        provider, content_id, start_time, end_time, epg_id, country
                    )
                else:
                    # Encrypted but not ClearKey (e.g. Widevine-only catchup) —
                    # playable mode genuinely can't act on this, matching the
                    # live/VOD path's rejection below rather than silently
                    # proxying content the client likely can't play anyway.
                    response.status = 400
                    return {
                        "error": (
                            f'Catchup content for channel "{content_id}" does not support '
                            f"decrypted playback (requires ClearKey or unencrypted)"
                        )
                    }

            # mode == "auto"
            if manager.needs_proxy(provider):
                if keyids:
                    logger.debug(
                        f"ClearKey DRM detected for catchup {provider}/{content_id} — "
                        "using receiver-side ClearKey rewrite"
                    )
                    return service.get_decrypted_catchup_manifest(
                        provider, content_id,
                        start_time=start_time, end_time=end_time,
                        keyids=keyids, epg_id=epg_id,
                        receiver_side=True,
                        highest_quality_only=highest_quality_only,
                    )
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
                return redirect(manifest_url)

        # ==================================================================
        # Live / event / vod / recording path
        # ==================================================================
        if mode == "noproxy":
            return _redirect_or_fetch(content_type, provider, content_id, country, drm_variant)

        if mode == "playable":
            if keyids:
                if not service.media_proxy_url:
                    response.status = 503
                    return {"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"}
                return service.get_decrypted_manifest(
                    provider, content_id, keyids,
                    receiver_side=receiver_side,
                    drm_variant=drm_variant,
                    highest_quality_only=highest_quality_only,
                )
            elif is_unencrypted:
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
                    return _redirect_or_fetch(content_type, provider, content_id, country, drm_variant)
                else:
                    return _redirect_or_fetch(content_type, provider, content_id, country, drm_variant)
            else:
                # Neither ClearKey nor unencrypted (e.g. Widevine-only) — decrypt
                # mode has nothing useful to do with this, unlike mode="auto"
                # which would happily proxy it for the client's own DRM stack.
                response.status = 400
                return {
                    "error": (
                        f'{content_type.capitalize()} "{content_id}" does not support '
                        f"decrypted playback (requires ClearKey or unencrypted)"
                    )
                }

        # mode == "auto"
        if manager.needs_proxy(provider):
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
                    highest_quality_only=highest_quality_only,
                )
            else:
                return service.get_proxied_manifest(
                    provider, content_id,
                    highest_quality_only=highest_quality_only,
                )
        else:
            return _redirect_or_fetch(content_type, provider, content_id, country, drm_variant)

    def _resolve_stream(
            content_type: str,
            provider: str,
            content_id: str,
            country=None,
            is_catchup: bool = False,
            start_time: int = None,
            end_time: int = None,
            epg_id: str = None,
            drm_variant: str = "auto",
            no_proxy: bool = False,
    ):
        """
        Deprecated: thin wrapper around _resolve_stream_unified, kept so
        existing call sites (channels.py, events.py, vod.py, recordings.py)
        don't need to change. New code should call _resolve_stream_unified
        directly with an explicit mode.
        """
        return _resolve_stream_unified(
            content_type, provider, content_id,
            country=country,
            is_catchup=is_catchup,
            start_time=start_time,
            end_time=end_time,
            epg_id=epg_id,
            drm_variant=drm_variant,
            mode="noproxy" if no_proxy else "auto",
            receiver_side=True,
        )

    def _resolve_decrypted_stream(
            content_type: str,
            provider: str,
            content_id: str,
            highest_quality_only: bool = False,
    ):
        """
        Deprecated: thin wrapper around _resolve_stream_unified, kept so
        existing call sites (channels.py's /stream/proxied/ routes) don't need
        to change. Reads start_time/end_time/epg_id/country from the request
        query string itself, matching the original function's contract — those
        routes never passed catchup args explicitly. New code should call
        _resolve_stream_unified directly with mode="playable".
        """
        try:
            country = request.query.get("country")
            start_time = request.query.get("start_time")
            end_time = request.query.get("end_time")
            epg_id = request.query.get("epg_id")
            is_catchup = bool(start_time and end_time and content_type == CONTENT_TYPE_CHANNEL)

            if is_catchup:
                try:
                    start_time = int(start_time)
                    end_time = int(end_time)
                except (ValueError, TypeError):
                    response.status = 400
                    return {"error": "Invalid start_time or end_time format"}

            return _resolve_stream_unified(
                content_type, provider, content_id,
                country=country,
                is_catchup=is_catchup,
                start_time=start_time,
                end_time=end_time,
                epg_id=epg_id,
                mode="playable",
                receiver_side=False,
                highest_quality_only=highest_quality_only,
            )

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
        "_validate_catchup_window": _validate_catchup_window,
        "_resolve_stream": _resolve_stream,
        "_resolve_decrypted_stream": _resolve_decrypted_stream,
        "_resolve_stream_unified": _resolve_stream_unified,
        "_serialize_drm_configs": _serialize_drm_configs,
    }