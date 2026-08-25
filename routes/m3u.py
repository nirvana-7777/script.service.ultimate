#!/usr/bin/env python3
"""
M3U playlist route handlers
"""

from bottle import request, response
from streaming_providers.base.utils import logger


def setup_m3u_routes(app, manager, service):
    """Setup M3U playlist-related routes"""

    def _serve_cached(cache_key: str, filename: str):
        """Return cached M3U content with headers set, or None if not cached."""
        cached = service.vfs.read_text(cache_key)
        if not cached:
            return None
        logger.info(f"Serving cached M3U: {cache_key}")
        response.content_type = "audio/x-mpegurl; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return cached

    def _handle_m3u_route(generate_fn, log_ctx, cache_key=None, filename=None):
        """
        Shared cache-check / error-handling wrapper for M3U routes.

        generate_fn: no-arg callable that returns the M3U string. It is
        responsible for its own success-path response headers (all the
        service.generate_* methods already do this) and, for the
        proxy-gated "fast" endpoints, for their own 503 handling.

        cache_key: pass None for routes that must always regenerate live
        (the uncached "fast" proxied/ffmpeg endpoints, and the force
        /generate endpoints, which never checked cache in the original
        code either).
        """
        try:
            if cache_key:
                cached = _serve_cached(cache_key, filename)
                if cached is not None:
                    return cached
                logger.info(f"No valid cache found, generating M3U: {log_ctx}")

            return generate_fn()

        except ValueError as val_err:
            logger.error(f"API Error in {log_ctx}: {val_err}")
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(f"API Error in {log_ctx}: {api_err}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    def _force_regenerate(cache_key: str, generate_fn, log_ctx: str):
        """Delete cache then regenerate. Mirrors original /generate endpoints,
        which bypassed the cache-read path entirely."""
        try:
            service.vfs.delete(cache_key)
        except Exception:
            pass  # cache file may not exist yet - fine
        return _handle_m3u_route(generate_fn, log_ctx)

    # ── Normal / no-proxy playlists (cached) ──────────────────────────────

    @app.route("/api/m3u")
    def get_m3u_all():
        """Generates M3U playlist for all configured providers."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_all(save_to_cache=True),
            log_ctx="/api/m3u",
            cache_key="playlist.m3u",
            filename="playlist.m3u8",
        )

    @app.route("/api/m3u/noproxy")
    def get_m3u_all_noproxy():
        """Generates M3U playlist using direct (non-proxied) stream URLs."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_all(save_to_cache=True, no_proxy=True),
            log_ctx="/api/m3u/noproxy",
            cache_key="playlist_noproxy.m3u",
            filename="playlist_noproxy.m3u8",
        )

    @app.route("/api/m3u/generate")
    def generate_m3u_all():
        """Force regeneration of M3U playlist for all providers."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_all(save_to_cache=True),
            log_ctx="/api/m3u/generate",
        )

    @app.route("/api/m3u/noproxy/generate")
    def generate_m3u_all_noproxy():
        """Force regeneration of the no-proxy M3U playlist."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_all(save_to_cache=True, no_proxy=True),
            log_ctx="/api/m3u/noproxy/generate",
        )

    @app.route("/api/providers/<provider>/m3u")
    def get_m3u_provider(provider):
        """Generates M3U playlist for a specific provider."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_provider(provider, save_to_cache=True),
            log_ctx=f"/api/providers/{provider}/m3u",
            cache_key=f"{provider}.m3u",
            filename=f"{provider}_playlist.m3u8",
        )

    @app.route("/api/providers/<provider>/m3u/noproxy")
    def get_m3u_provider_noproxy(provider):
        """Generates no-proxy M3U playlist for a specific provider."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_provider(provider, save_to_cache=True, no_proxy=True),
            log_ctx=f"/api/providers/{provider}/m3u/noproxy",
            cache_key=f"{provider}_noproxy.m3u",
            filename=f"{provider}_playlist_noproxy.m3u8",
        )

    @app.route("/api/providers/<provider>/m3u/generate")
    def generate_m3u_provider(provider):
        """Force regeneration of M3U playlist for a specific provider."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_provider(provider, save_to_cache=True),
            log_ctx=f"/api/providers/{provider}/m3u/generate",
        )

    @app.route("/api/providers/<provider>/m3u/noproxy/generate")
    def generate_m3u_provider_noproxy(provider):
        """Force regeneration of no-proxy M3U playlist for a specific provider."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_provider(provider, save_to_cache=True, no_proxy=True),
            log_ctx=f"/api/providers/{provider}/m3u/noproxy/generate",
        )

    # ── Proxied / decrypted "fast" playlists (deliberately UNCACHED) ─────
    # These intentionally skip the cache layer - proxy/DRM session state
    # can shift between requests, and service.generate_m3u_proxied_fast /
    # generate_m3u_decrypted_ffmpeg_fast already own the 503 "media proxy
    # not configured" guard and their own response headers. Do not give
    # these a cache_key.

    @app.route("/api/m3u/proxied")
    def get_m3u_proxied():
        """Generates proxied M3U playlist for all providers. No caching."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_proxied_fast(providers=None),
            log_ctx="/api/m3u/proxied",
        )

    @app.route("/api/providers/<provider>/m3u/proxied")
    def get_m3u_proxied_provider(provider):
        """Generates proxied M3U playlist for a specific provider. No caching."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_proxied_fast(providers=provider),
            log_ctx=f"/api/providers/{provider}/m3u/proxied",
        )

    @app.route("/api/providers/<provider>/m3u/proxied/ffmpeg")
    def get_m3u_proxied_ffmpeg_provider(provider):
        """Generates ffmpeg-piped proxied M3U playlist for a provider. No caching."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_proxied_ffmpeg_fast(providers=provider),
            log_ctx=f"/api/providers/{provider}/m3u/proxied/ffmpeg",
        )

    # ── Filtered proxied playlists (cached; ClearKey or unencrypted only) ─
    # NOTE: cache filenames below match what
    # _generate_m3u_proxied_filtered_content() actually writes
    # ("*_proxied_filtered.m3u"), fixing a pre-existing mismatch where
    # this route checked "*_proxied_filtered.m3u" - a file the service
    # never wrote - so the cache never hit.

    @app.route("/api/m3u/proxied/filtered")
    def get_m3u_proxied_filtered():
        """Generates filtered proxied M3U (ClearKey/unencrypted channels only)."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_proxied_filtered_all(save_to_cache=True),
            log_ctx="/api/m3u/proxied/filtered",
            cache_key="playlist_proxied_filtered.m3u",
            filename="playlist_proxied_filtered.m3u8",
        )

    @app.route("/api/m3u/proxied/filtered/generate")
    def generate_m3u_proxied_filtered():
        """Force regeneration of filtered proxied M3U playlist."""
        return _force_regenerate(
            "playlist_proxied_filtered.m3u",
            lambda: service.generate_m3u_proxied_filtered_all(save_to_cache=True),
            log_ctx="/api/m3u/proxied/filtered/generate",
        )

    @app.route("/api/providers/<provider>/m3u/proxied/filtered")
    def get_m3u_proxied_filtered_provider(provider):
        """Generates filtered proxied M3U for a specific provider."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_proxied_filtered_provider(provider, save_to_cache=True),
            log_ctx=f"/api/providers/{provider}/m3u/proxied/filtered",
            cache_key=f"{provider}_proxied_filtered.m3u",
            filename=f"{provider}_proxied_filtered_playlist.m3u8",
        )

    @app.route("/api/providers/<provider>/m3u/proxied/filtered/generate")
    def generate_m3u_proxied_filtered_provider(provider):
        """Force regeneration of filtered proxied M3U for a specific provider."""
        return _force_regenerate(
            f"{provider}_proxied_filtered.m3u",
            lambda: service.generate_m3u_proxied_filtered_provider(provider, save_to_cache=True),
            log_ctx=f"/api/providers/{provider}/m3u/proxied/filtered/generate",
        )

    # ── Subscribed-channel playlists ──────────────────────────────────────
    # get_m3u_subscribed / get_m3u_subscribed_proxied still build their own
    # M3U content directly (they were never moved into service.py) - only the
    # boilerplate around them is shared via the same helpers used everywhere
    # else. The two bodies used to be ~90% duplicated hand-written copies of
    # each other, differing only in stream URL path, whether DRM directives
    # are looked up per-channel vs a fixed KODIPROP line, and whether the
    # result gets cached — now unified into one function with a `proxied` flag.

    def _generate_m3u_subscribed(proxied: bool = False):
        if proxied and not service.media_proxy_url:
            response.status = 503
            return {"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"}

        base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
        m3u_content = "#EXTM3U\n"

        for provider_name in manager.list_providers():
            try:
                channels = sorted(
                    manager.get_subscribed_channels(provider_name),
                    key=lambda ch: (ch.channel_number is None, ch.channel_number or 0),
                )

                try:
                    provider_label = getattr(
                        manager.get_provider(provider_name), "provider_label", provider_name
                    )
                except Exception:
                    provider_label = provider_name

                for channel in channels:
                    channel_id = channel.channel_id
                    channel_name = channel.name
                    channel_logo = channel.logo_url or ""
                    chno = (
                        f' tvg-chno="{channel.channel_number}" ch-number="{channel.channel_number}"'
                        if getattr(channel, "channel_number", None) is not None
                        else ""
                    )
                    epg_id = service.get_epg_id(channel_id)
                    epg_id_attr = f' tvg-epgid="{epg_id}"' if epg_id else ""
                    # /stream/proxied/ no longer exists as a separate route —
                    # folded into client_drm on the single /stream/index.mpd
                    # endpoint. client_drm=false for proxied (matches the
                    # static KODIPROP line below, server decrypts);
                    # client_drm=true otherwise (matches the dynamic
                    # per-channel DRM lookup below, client decrypts) — it
                    # now defaults to false, so this must be explicit or the
                    # non-proxied branch's entries would mismatch their own
                    # KODIPROP directives.
                    stream_path = (
                        "stream/index.mpd?client_drm=false" if proxied
                        else "stream/index.mpd?client_drm=true"
                    )
                    stream_url = (
                        f"{base_url}/api/providers/{provider_name}/channels/{channel_id}/{stream_path}"
                    )

                    m3u_content += (
                        f'#EXTINF:-1 tvg-id="{channel_id}"{epg_id_attr}{chno} '
                        f'tvg-logo="{channel_logo}" group-title="{provider_label}",{channel_name}\n'
                    )

                    if proxied:
                        # No KODIPROP line — client_drm=false, client doesn't
                        # use inputstream.adaptive when the server decrypts.
                        pass
                    else:
                        try:
                            drm_configs = manager.get_channel_drm_configs(provider_name, channel_id)
                            if drm_configs:
                                m3u_content += service.generate_drm_directives(drm_configs)
                        except Exception as drm_err:
                            logger.debug(f"Could not get DRM for {provider_name}/{channel_id}: {drm_err}")

                    m3u_content += f"{stream_url}\n"

            except Exception as provider_err:
                logger.warning(
                    f"Failed to process subscribed channels for '{provider_name}': {provider_err}"
                )
                continue

        filename = "playlist_subscribed_proxied.m3u8" if proxied else "playlist_subscribed.m3u8"

        # Proxied variant is deliberately uncached — proxy/DRM session state
        # can shift between requests, same rationale as the "fast" proxied
        # playlists above.
        if not proxied:
            if service.vfs.write_text("playlist_subscribed.m3u", m3u_content):
                logger.info("Subscribed M3U playlist cached to playlist_subscribed.m3u")

        response.content_type = "audio/x-mpegurl; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return m3u_content

    @app.route("/api/m3u/subscribed")
    def get_m3u_subscribed():
        """Generate M3U playlist with only subscribed channels."""
        return _handle_m3u_route(
            lambda: _generate_m3u_subscribed(proxied=False),
            log_ctx="/api/m3u/subscribed",
            cache_key="playlist_subscribed.m3u",
            filename="playlist_subscribed.m3u8",
        )

    @app.route("/api/m3u/subscribed/generate")
    def generate_m3u_subscribed():
        """Force regenerate subscribed M3U playlist."""
        return _force_regenerate(
            "playlist_subscribed.m3u",
            lambda: _generate_m3u_subscribed(proxied=False),
            log_ctx="/api/m3u/subscribed/generate",
        )

    @app.route("/api/m3u/subscribed/proxied")
    def get_m3u_subscribed_proxied():
        """Generate proxied M3U playlist with only subscribed channels. No caching."""
        return _handle_m3u_route(
            lambda: _generate_m3u_subscribed(proxied=True),
            log_ctx="/api/m3u/subscribed/proxied",
        )