#!/usr/bin/env python3
"""
M3U playlist route handlers
"""

import time

from bottle import request, response
from streaming_providers.base.utils import logger

# TTL for the plain M3U cache ("/api/m3u", "/api/providers/<provider>/m3u")
# only. Nothing embedded there goes stale from a security standpoint
# (drm_directives="" — no keys/license URLs baked in), but the channel
# LINEUP can change upstream (providers add/remove channels), and without
# an expiry the cache would otherwise only ever refresh via a manual
# /generate call. 24h bounds how long a new channel can be missing from
# the served playlist. clientdrm is unaffected — it's already uncached
# (see generate_m3u_clientdrm_all), so it never goes stale in the first
# place, for lineup or DRM credentials.
PLAIN_M3U_TTL_SECONDS = 24 * 60 * 60


def setup_m3u_routes(app, manager, service):
    """Setup M3U playlist-related routes"""

    def _cache_meta_key(cache_key: str) -> str:
        return f"{cache_key}.meta.json"

    def _touch_cache_meta(cache_key: str) -> None:
        """
        Record the write time for a cached M3U file, used by the TTL check
        in _serve_cached. Stored as a small JSON sidecar via
        vfs.write_json/read_json rather than filesystem mtime — VFS
        abstracts over an xbmcvfs (Kodi special:// paths) backend as well
        as a plain filesystem one, and os.path.getmtime doesn't work
        against the former.
        """
        service.vfs.write_json(_cache_meta_key(cache_key), {"cached_at": time.time()})

    def _serve_cached(cache_key: str, filename: str, ttl_seconds: int = None):
        """
        Return cached M3U content with headers set, or None if not cached
        (or, when ttl_seconds is given, if the sidecar meta file shows the
        cache is older than that — triggering a regeneration the same as
        a cold cache would).
        """
        if ttl_seconds is not None:
            meta = service.vfs.read_json(_cache_meta_key(cache_key))
            cached_at = meta.get("cached_at") if meta else None
            if cached_at is None:
                # No meta yet — e.g. a cache file written before this TTL
                # logic existed, or the meta write previously failed.
                # Treat as expired so it regenerates (and gets a meta file
                # going forward) rather than serving an unbounded-age file.
                logger.info(f"No cache-age metadata for {cache_key} — treating as expired")
                return None
            age = time.time() - cached_at
            if age > ttl_seconds:
                logger.info(
                    f"Cache expired for {cache_key} (age {age:.0f}s > TTL {ttl_seconds}s)"
                )
                return None

        cached = service.vfs.read_text(cache_key)
        if not cached:
            return None
        logger.info(f"Serving cached M3U: {cache_key}")
        response.content_type = "audio/x-mpegurl; charset=utf-8"
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return cached

    def _handle_m3u_route(generate_fn, log_ctx, cache_key=None, filename=None,
                           ttl_seconds=None, force=False):
        """
        Shared cache-check / error-handling wrapper for M3U routes.

        generate_fn: no-arg callable that returns the M3U string. It is
        responsible for its own success-path response headers (all the
        service.generate_* methods already do this) and, for the
        proxy-gated "fast" endpoints, for their own 503 handling.

        cache_key: pass None for routes that must always regenerate live
        (the uncached clientdrm endpoints and the ffmpeg endpoint) and
        never touch the TTL meta either. Pass it (with force=False) for a
        normal cache-first read, or (with force=True) to skip the read but
        still refresh the TTL meta after a forced regeneration — see the
        /generate routes below.

        ttl_seconds: pass None (default) to keep the existing "cache
        forever until /generate is called" behavior, with no meta file
        written. Currently only the plain M3U routes pass
        PLAIN_M3U_TTL_SECONDS — noproxy/filtered/subscribed keep the old
        no-expiry behavior unless you want that extended too.
        """
        try:
            if cache_key and not force:
                cached = _serve_cached(cache_key, filename, ttl_seconds=ttl_seconds)
                if cached is not None:
                    return cached
                logger.info(f"No valid cache found, generating M3U: {log_ctx}")

            result = generate_fn()

            # Refresh the TTL clock whenever this route actually writes to
            # the cache (cache miss above, or a forced /generate) — a
            # forced regen with no meta refresh would leave the TTL check
            # comparing against a stale timestamp forever, defeating the
            # point of the TTL.
            if cache_key and ttl_seconds is not None and isinstance(result, str):
                _touch_cache_meta(cache_key)

            return result

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

    # ── Plain playlists (cached, 24h TTL) ──────────────────────────────────
    # Server-side decrypt, bare stream URLs (no "?client_drm=false" — that's
    # the route's own default). Nothing per-channel here is request-time-
    # volatile from a DRM standpoint (no key/license lookups happen at
    # generation time), so caching is safe. The 24h TTL exists for a
    # different reason: the channel LINEUP itself can change upstream, and
    # without an expiry this would otherwise only refresh via a manual
    # /generate call.

    @app.route("/api/m3u")
    def get_m3u_all():
        """Generates M3U playlist for all configured providers. Cache expires after 24h."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_plain_all(save_to_cache=True),
            log_ctx="/api/m3u",
            cache_key="playlist.m3u",
            filename="playlist.m3u8",
            ttl_seconds=PLAIN_M3U_TTL_SECONDS,
        )

    @app.route("/api/m3u/generate")
    def generate_m3u_all():
        """Force regeneration of M3U playlist for all providers."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_plain_all(save_to_cache=True),
            log_ctx="/api/m3u/generate",
            cache_key="playlist.m3u",
            filename="playlist.m3u8",
            ttl_seconds=PLAIN_M3U_TTL_SECONDS,
            force=True,
        )

    @app.route("/api/providers/<provider>/m3u")
    def get_m3u_provider(provider):
        """Generates M3U playlist for a specific provider. Cache expires after 24h."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_plain_provider(provider, save_to_cache=True),
            log_ctx=f"/api/providers/{provider}/m3u",
            cache_key=f"{provider}.m3u",
            filename=f"{provider}_playlist.m3u8",
            ttl_seconds=PLAIN_M3U_TTL_SECONDS,
        )

    @app.route("/api/providers/<provider>/m3u/generate")
    def generate_m3u_provider(provider):
        """Force regeneration of M3U playlist for a specific provider."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_plain_provider(provider, save_to_cache=True),
            log_ctx=f"/api/providers/{provider}/m3u/generate",
            cache_key=f"{provider}.m3u",
            filename=f"{provider}_playlist.m3u8",
            ttl_seconds=PLAIN_M3U_TTL_SECONDS,
            force=True,
        )

    # ── Client-side-decrypt playlists (deliberately UNCACHED) ─────────────
    # Dynamic per-channel ClearKey lookup, key/kid pairs baked into KODIPROP
    # directives. Uncached on purpose: upstream keys can rotate, and a
    # cached playlist would silently serve a stale key until someone
    # force-regenerated it. Fresh generation per request avoids that
    # failure mode; revisit with a short TTL if per-request DRM lookups
    # turn out to be too frequent/expensive.

    @app.route("/api/m3u/clientdrm")
    def get_m3u_clientdrm():
        """Generates client-side-decrypt M3U playlist for all providers. No caching."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_clientdrm_all(),
            log_ctx="/api/m3u/clientdrm",
        )

    @app.route("/api/providers/<provider>/m3u/clientdrm")
    def get_m3u_clientdrm_provider(provider):
        """Generates client-side-decrypt M3U playlist for a specific provider. No caching."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_clientdrm_provider(provider),
            log_ctx=f"/api/providers/{provider}/m3u/clientdrm",
        )

    # ── No-proxy playlists (cached) ────────────────────────────────────────
    # Unrelated to the plain/clientdrm split above — "no_proxy" here means
    # bypassing the media proxy at the stream-route level, independent of
    # who does the decrypting. Still client-side-decrypt underneath
    # (client_drm=true&no_proxy=true), same as before this change; only the
    # service method name changed (generate_m3u_all -> generate_m3u_noproxy_all),
    # since generate_m3u_all now refers to the plain playlist above.

    @app.route("/api/m3u/noproxy")
    def get_m3u_all_noproxy():
        """Generates M3U playlist using direct (non-proxied) stream URLs."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_noproxy_all(save_to_cache=True),
            log_ctx="/api/m3u/noproxy",
            cache_key="playlist_noproxy.m3u",
            filename="playlist_noproxy.m3u8",
        )

    @app.route("/api/m3u/noproxy/generate")
    def generate_m3u_all_noproxy():
        """Force regeneration of the no-proxy M3U playlist."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_noproxy_all(save_to_cache=True),
            log_ctx="/api/m3u/noproxy/generate",
        )

    @app.route("/api/providers/<provider>/m3u/noproxy")
    def get_m3u_provider_noproxy(provider):
        """Generates no-proxy M3U playlist for a specific provider."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_noproxy_provider(provider, save_to_cache=True),
            log_ctx=f"/api/providers/{provider}/m3u/noproxy",
            cache_key=f"{provider}_noproxy.m3u",
            filename=f"{provider}_playlist_noproxy.m3u8",
        )

    @app.route("/api/providers/<provider>/m3u/noproxy/generate")
    def generate_m3u_provider_noproxy(provider):
        """Force regeneration of no-proxy M3U playlist for a specific provider."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_noproxy_provider(provider, save_to_cache=True),
            log_ctx=f"/api/providers/{provider}/m3u/noproxy/generate",
        )

    # ── ffmpeg-piped playlist (deliberately UNCACHED) ─────────────────────
    # Unchanged by this turn's split — left as-is per your call to leave
    # ffmpeg/filtered/subscribed alone for now.

    @app.route("/api/providers/<provider>/m3u/proxied/ffmpeg")
    def get_m3u_proxied_ffmpeg_provider(provider):
        """Generates ffmpeg-piped proxied M3U playlist for a provider. No caching."""
        return _handle_m3u_route(
            lambda: service.generate_m3u_proxied_ffmpeg_fast(providers=provider),
            log_ctx=f"/api/providers/{provider}/m3u/proxied/ffmpeg",
        )

    # ── Filtered proxied playlists (cached; ClearKey or unencrypted only) ─
    # Unchanged by this turn's split — left as-is per your call to leave
    # ffmpeg/filtered/subscribed alone for now. NOTE: cache filenames below
    # match what _generate_m3u_proxied_filtered_content() actually writes
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
    # Unchanged by this turn's split — left as-is per your call to leave
    # ffmpeg/filtered/subscribed alone for now. get_m3u_subscribed /
    # get_m3u_subscribed_proxied still build their own M3U content directly
    # (they were never moved into service.py) - only the boilerplate around
    # them is shared via the same helpers used everywhere else.

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