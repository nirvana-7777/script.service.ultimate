#!/usr/bin/env python3
"""
M3U playlist route handlers
"""

from bottle import request, response
from streaming_providers.base.utils import logger


def setup_m3u_routes(app, manager, service):
    """Setup M3U playlist-related routes"""

    @app.route("/api/m3u")
    def get_m3u_all():
        """
        Generates M3U playlist for all configured providers.
        Returns cached version if available, otherwise generates new one.

        Example: http://localhost:7777/api/m3u
        """
        try:
            cache_file = "playlist.m3u"

            # Try to read cached file
            cached_content = service.vfs.read_text(cache_file)

            if cached_content:
                logger.info("Serving cached M3U playlist for all providers")
                response.content_type = "audio/x-mpegurl; charset=utf-8"
                response.headers["Content-Disposition"] = (
                    'attachment; filename="playlist.m3u8"'
                )
                return cached_content

            # Cache doesn't exist or is corrupt, generate new M3U
            logger.info(
                "No valid cache found, generating M3U playlist for all providers"
            )
            return service.generate_m3u_all(save_to_cache=True)

        except Exception as api_err:
            logger.error(f"API Error in /api/m3u: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/m3u/noproxy")
    def get_m3u_all_noproxy():
        """
        Generates M3U playlist for all configured providers using direct
        (non-proxied) stream URLs. Forces a redirect to the upstream manifest
        even if a media proxy is configured. Cached separately from the normal
        playlist under playlist_noproxy.m3u.

        Example: http://localhost:7777/api/m3u/noproxy
        """
        try:
            cache_file = "playlist_noproxy.m3u"

            cached_content = service.vfs.read_text(cache_file)

            if cached_content:
                logger.info("Serving cached no-proxy M3U playlist for all providers")
                response.content_type = "audio/x-mpegurl; charset=utf-8"
                response.headers["Content-Disposition"] = (
                    'attachment; filename="playlist_noproxy.m3u8"'
                )
                return cached_content

            logger.info("No valid cache found, generating no-proxy M3U playlist for all providers")
            return service.generate_m3u_all(save_to_cache=True, no_proxy=True)

        except Exception as api_err:
            logger.error(f"API Error in /api/m3u/noproxy: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/m3u/generate")
    def generate_m3u_all():
        """
        Forces regeneration of M3U playlist for all providers and saves to cache.

        Example: http://localhost:7777/api/m3u/generate
        """
        try:
            logger.info("Force generating M3U playlist for all providers")
            return service.generate_m3u_all(save_to_cache=True)

        except Exception as api_err:
            logger.error(f"API Error in /api/m3u/generate: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/m3u/noproxy/generate")
    def generate_m3u_all_noproxy():
        """
        Forces regeneration of the no-proxy M3U playlist for all providers and
        saves it to cache under playlist_noproxy.m3u.

        Example: http://localhost:7777/api/m3u/noproxy/generate
        """
        try:
            logger.info("Force generating no-proxy M3U playlist for all providers")
            return service.generate_m3u_all(save_to_cache=True, no_proxy=True)

        except Exception as api_err:
            logger.error(f"API Error in /api/m3u/noproxy/generate: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/m3u")
    def get_m3u_provider(provider):
        """
        Generates M3U playlist for a specific provider.
        Returns cached version if available, otherwise generates new one.

        Example: http://localhost:7777/api/providers/rtlplus/m3u
        """
        try:
            cache_file = f"{provider}.m3u"

            # Try to read cached file
            cached_content = service.vfs.read_text(cache_file)

            if cached_content:
                logger.info(f"Serving cached M3U playlist for provider '{provider}'")
                response.content_type = "audio/x-mpegurl; charset=utf-8"
                response.headers["Content-Disposition"] = (
                    f'attachment; filename="{provider}_playlist.m3u8"'
                )
                return cached_content

            # Cache doesn't exist or is corrupt, generate new M3U
            logger.info(
                f"No valid cache found, generating M3U playlist for provider '{provider}'"
            )
            return service.generate_m3u_provider(provider, save_to_cache=True)

        except ValueError as val_err:
            logger.error(f"API Error in /api/providers/{provider}/m3u: {str(val_err)}")
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(f"API Error in /api/providers/{provider}/m3u: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/m3u/noproxy")
    def get_m3u_provider_noproxy(provider):
        """
        Generates M3U playlist for a specific provider using direct (non-proxied)
        stream URLs. Forces a redirect to the upstream manifest even if a media
        proxy is configured. Cached separately under "{provider}_noproxy.m3u".

        Example: http://localhost:7777/api/providers/rtlplus/m3u/noproxy
        """
        try:
            cache_file = f"{provider}_noproxy.m3u"

            cached_content = service.vfs.read_text(cache_file)

            if cached_content:
                logger.info(f"Serving cached no-proxy M3U playlist for provider '{provider}'")
                response.content_type = "audio/x-mpegurl; charset=utf-8"
                response.headers["Content-Disposition"] = (
                    f'attachment; filename="{provider}_playlist_noproxy.m3u8"'
                )
                return cached_content

            logger.info(f"No valid cache found, generating no-proxy M3U playlist for provider '{provider}'")
            return service.generate_m3u_provider(provider, save_to_cache=True, no_proxy=True)

        except ValueError as val_err:
            logger.error(f"API Error in /api/providers/{provider}/m3u/noproxy: {str(val_err)}")
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(f"API Error in /api/providers/{provider}/m3u/noproxy: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/m3u/generate")
    def generate_m3u_provider(provider):
        """
        Forces regeneration of M3U playlist for a specific provider and saves to cache.

        Example: http://localhost:7777/api/providers/rtlplus/m3u/generate
        """
        try:
            logger.info(f"Force generating M3U playlist for provider '{provider}'")
            return service.generate_m3u_provider(provider, save_to_cache=True)

        except ValueError as val_err:
            logger.error(
                f"API Error in /api/providers/{provider}/m3u/generate: {str(val_err)}"
            )
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(
                f"API Error in /api/providers/{provider}/m3u/generate: {str(api_err)}"
            )
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/m3u/noproxy/generate")
    def generate_m3u_provider_noproxy(provider):
        """
        Forces regeneration of the no-proxy M3U playlist for a specific provider
        and saves it to cache under "{provider}_noproxy.m3u".

        Example: http://localhost:7777/api/providers/rtlplus/m3u/noproxy/generate
        """
        try:
            logger.info(f"Force generating no-proxy M3U playlist for provider '{provider}'")
            return service.generate_m3u_provider(provider, save_to_cache=True, no_proxy=True)

        except ValueError as val_err:
            logger.error(
                f"API Error in /api/providers/{provider}/m3u/noproxy/generate: {str(val_err)}"
            )
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(
                f"API Error in /api/providers/{provider}/m3u/noproxy/generate: {str(api_err)}"
            )
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/m3u/proxied")
    def get_m3u_decrypted():
        """
        Generates proxied M3U playlist for all configured providers.
        Fast generation - includes ALL channels with proxied stream URLs.
        No filtering, no caching (very fast).

        Example: http://localhost:7777/api/m3u/proxied
        """
        try:
            logger.info("Generating fast proxied M3U playlist for all providers")
            return service.generate_m3u_decrypted_fast(providers=None)

        except Exception as api_err:
            logger.error(f"API Error in /api/m3u/proxied: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/m3u/proxied/filtered")
    def get_m3u_decrypted_filtered():
        """
        Generates filtered proxied M3U playlist for all configured providers.
        Only includes channels with ClearKey DRM or unencrypted channels.
        Returns cached version if available, otherwise generates new one.

        Example: http://localhost:7777/api/m3u/proxied/filtered
        """
        try:
            cache_file = "playlist_proxied_filtered.m3u"

            # Try to read cached file
            cached_content = service.vfs.read_text(cache_file)

            if cached_content:
                logger.info("Serving cached filtered proxied M3U playlist for all providers")
                response.content_type = "audio/x-mpegurl; charset=utf-8"
                response.headers["Content-Disposition"] = (
                    'attachment; filename="playlist_proxied_filtered.m3u8"'
                )
                return cached_content

            # Cache doesn't exist, generate new M3U
            logger.info(
                "No valid cache found, generating filtered proxied M3U playlist for all providers"
            )
            return service.generate_m3u_decrypted_filtered_all(save_to_cache=True)

        except Exception as api_err:
            logger.error(f"API Error in /api/m3u/proxied/filtered: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/m3u/proxied/filtered/generate")
    def generate_m3u_decrypted_filtered():
        """
        Forces regeneration of filtered proxied M3U playlist for all providers and saves to cache.

        Example: http://localhost:7777/api/m3u/proxied/filtered/generate
        """
        try:
            logger.info("Force generating filtered proxied M3U playlist for all providers")
            return service.generate_m3u_decrypted_filtered_all(save_to_cache=True)

        except Exception as api_err:
            logger.error(f"API Error in /api/m3u/proxied/filtered/generate: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/m3u/proxied")
    def get_m3u_decrypted_provider(provider):
        """
        Generates proxied M3U playlist for a specific provider.
        Fast generation - includes ALL channels with proxied stream URLs.
        No filtering, no caching (very fast).

        Example: http://localhost:7777/api/providers/rtlplus/m3u/proxied
        """
        try:
            logger.info(f"Generating fast proxied M3U playlist for provider '{provider}'")
            return service.generate_m3u_decrypted_fast(providers=provider)

        except ValueError as val_err:
            logger.error(
                f"API Error in /api/providers/{provider}/m3u/proxied: {str(val_err)}"
            )
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(
                f"API Error in /api/providers/{provider}/m3u/proxied: {str(api_err)}"
            )
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/m3u/proxied/ffmpeg")
    def get_m3u_decrypted_ffmpeg_provider(provider):
        """
        Generates proxied M3U playlist for a specific provider with ffmpeg piping.
        Fast generation - includes ALL channels with ffmpeg-piped proxied stream URLs.
        Streams are highest quality video only with all audio tracks copied.
        No filtering, no caching (very fast).

        Example: http://localhost:7777/api/providers/rtlplus/m3u/proxied/ffmpeg
        """
        try:
            logger.info(f"Generating fast proxied ffmpeg M3U playlist for provider '{provider}'")
            return service.generate_m3u_decrypted_ffmpeg_fast(providers=provider)

        except ValueError as val_err:
            logger.error(
                f"API Error in /api/providers/{provider}/m3u/proxied/ffmpeg: {str(val_err)}"
            )
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(
                f"API Error in /api/providers/{provider}/m3u/proxied/ffmpeg: {str(api_err)}"
            )
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/m3u/proxied/filtered")
    def get_m3u_decrypted_filtered_provider(provider):
        """
        Generates filtered proxied M3U playlist for a specific provider.
        Only includes channels with ClearKey DRM or unencrypted channels.
        Returns cached version if available, otherwise generates new one.

        Example: http://localhost:7777/api/providers/rtlplus/m3u/proxied/filtered
        """
        try:
            cache_file = f"{provider}_proxied_filtered.m3u"

            # Try to read cached file
            cached_content = service.vfs.read_text(cache_file)

            if cached_content:
                logger.info(
                    f"Serving cached filtered proxied M3U playlist for provider '{provider}'"
                )
                response.content_type = "audio/x-mpegurl; charset=utf-8"
                response.headers["Content-Disposition"] = (
                    f'attachment; filename="{provider}_proxied_filtered_playlist.m3u8"'
                )
                return cached_content

            # Cache doesn't exist, generate new M3U
            logger.info(
                f"No valid cache found, generating filtered proxied M3U playlist for provider '{provider}'"
            )
            return service.generate_m3u_decrypted_filtered_provider(
                provider, save_to_cache=True
            )

        except ValueError as val_err:
            logger.error(
                f"API Error in /api/providers/{provider}/m3u/proxied/filtered: {str(val_err)}"
            )
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(
                f"API Error in /api/providers/{provider}/m3u/proxied/filtered: {str(api_err)}"
            )
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/providers/<provider>/m3u/proxied/filtered/generate")
    def generate_m3u_decrypted_filtered_provider(provider):
        """
        Forces regeneration of filtered proxied M3U playlist for a specific provider and saves to cache.

        Example: http://localhost:7777/api/providers/rtlplus/m3u/proxied/filtered/generate
        """
        try:
            logger.info(
                f"Force generating filtered proxied M3U playlist for provider '{provider}'"
            )
            return service.generate_m3u_decrypted_filtered_provider(
                provider, save_to_cache=True
            )

        except ValueError as val_err:
            logger.error(
                f"API Error in /api/providers/{provider}/m3u/proxied/filtered/generate: {str(val_err)}"
            )
            response.status = 404
            return {"error": str(val_err)}
        except Exception as api_err:
            logger.error(
                f"API Error in /api/providers/{provider}/m3u/proxied/filtered/generate: {str(api_err)}"
            )
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/m3u/subscribed")
    def get_m3u_subscribed():
        """
        Generate M3U playlist with only subscribed channels.

        Note: This uses the same caching mechanism as regular M3U,
        but with '_subscribed' suffix in cache filename.
        """
        try:
            cache_file = "playlist_subscribed.m3u"

            # Try cached version
            cached_content = service.vfs.read_text(cache_file)
            if cached_content:
                logger.info("Serving cached subscribed M3U playlist")
                response.content_type = "audio/x-mpegurl; charset=utf-8"
                response.headers["Content-Disposition"] = (
                    'attachment; filename="playlist_subscribed.m3u8"'
                )
                return cached_content

            # Generate new M3U with subscribed channels
            base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
            m3u_content = "#EXTM3U\n"

            provider_list = manager.list_providers()
            for provider_name in provider_list:
                try:
                    channels = sorted(
                        manager.get_subscribed_channels(provider_name),
                        key=lambda ch: (ch.channel_number is None, ch.channel_number or 0)
                    )

                    for channel in channels:
                        # Generate M3U entry for each subscribed channel
                        channel_id = channel.channel_id
                        channel_name = channel.name
                        channel_logo = channel.logo_url or ""
                        chno = f' tvg-chno="{channel.channel_number}" ch-number="{channel.channel_number}"' if getattr(
                            channel, "channel_number", None) is not None else ""

                        # Get EPG ID if available
                        epg_id = service.get_epg_id(channel_id)
                        epg_id_attr = f' tvg-epgid="{epg_id}"' if epg_id else ""

                        # Get provider label
                        try:
                            provider_instance = manager.get_provider(provider_name)
                            provider_label = getattr(
                                provider_instance, "provider_label", provider_name
                            )
                        except Exception:
                            provider_label = provider_name

                        # Build stream URL with /index.mpd
                        stream_url = f"{base_url}/api/providers/{provider_name}/channels/{channel_id}/stream/index.mpd"

                        # Add M3U entry
                        m3u_content += f'#EXTINF:-1 tvg-id="{channel_id}"{epg_id_attr}{chno} tvg-logo="{channel_logo}" group-title="{provider_label}",{channel_name}\n'

                        # Add DRM directives if available
                        try:
                            drm_configs = manager.get_channel_drm_configs(
                                provider_name, channel_id
                            )
                            if drm_configs:
                                drm_directives = service.generate_drm_directives(
                                    drm_configs
                                )
                                m3u_content += drm_directives
                        except Exception as drm_err:
                            logger.debug(
                                f"Could not get DRM for {provider_name}/{channel_id}: {drm_err}"
                            )

                        m3u_content += f"{stream_url}\n"

                except Exception as provider_err:
                    logger.warning(
                        f"Failed to process subscribed channels for '{provider_name}': {str(provider_err)}"
                    )
                    continue

            # Cache the result
            if service.vfs.write_text(cache_file, m3u_content):
                logger.info(f"Subscribed M3U playlist cached to {cache_file}")

            response.content_type = "audio/x-mpegurl; charset=utf-8"
            response.headers["Content-Disposition"] = (
                'attachment; filename="playlist_subscribed.m3u8"'
            )
            return m3u_content

        except Exception as api_err:
            logger.error(f"API Error in /api/m3u/subscribed: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/m3u/subscribed/proxied")
    def get_m3u_subscribed_decrypted():
        """
        Generate proxied M3U playlist with only subscribed channels.
        Fast generation - no filtering, no caching.
        """
        try:
            logger.info("Generating fast proxied M3U playlist for subscribed channels")

            # Check if media proxy is configured
            if not service.media_proxy_url:
                response.status = 503
                return {"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"}

            base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
            m3u_content = "#EXTM3U\n"

            provider_list = manager.list_providers()
            for provider_name in provider_list:
                try:
                    channels = sorted(
                        manager.get_subscribed_channels(provider_name),
                        key=lambda ch: (ch.channel_number is None, ch.channel_number or 0)
                    )

                    # Get provider label
                    try:
                        provider_instance = manager.get_provider(provider_name)
                        provider_label = getattr(
                            provider_instance, "provider_label", provider_name
                        )
                    except Exception:
                        provider_label = provider_name

                    for channel in channels:
                        channel_id = channel.channel_id
                        channel_name = channel.name
                        channel_logo = channel.logo_url or ""
                        chno = f' tvg-chno="{channel.channel_number}" ch-number="{channel.channel_number}"' if getattr(
                            channel, "channel_number", None) is not None else ""

                        # Get EPG ID if available
                        epg_id = service.get_epg_id(channel_id)
                        epg_id_attr = f' tvg-epgid="{epg_id}"' if epg_id else ""

                        # Build proxied stream URL
                        stream_url = f"{base_url}/api/providers/{provider_name}/channels/{channel_id}/stream/proxied/index.mpd"

                        # Add M3U entry
                        m3u_content += f'#EXTINF:-1 tvg-id="{channel_id}"{epg_id_attr}{chno} tvg-logo="{channel_logo}" group-title="{provider_label}",{channel_name}\n'
                        m3u_content += "#KODIPROP:inputstream=inputstream.adaptive\n"
                        m3u_content += f"{stream_url}\n"

                except Exception as provider_err:
                    logger.warning(
                        f"Failed to process subscribed channels for '{provider_name}': {str(provider_err)}"
                    )
                    continue

            response.content_type = "audio/x-mpegurl; charset=utf-8"
            response.headers["Content-Disposition"] = (
                'attachment; filename="playlist_subscribed_proxied.m3u8"'
            )
            return m3u_content

        except Exception as api_err:
            logger.error(f"API Error in /api/m3u/subscribed/proxied: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}

    @app.route("/api/m3u/subscribed/generate")
    def generate_m3u_subscribed():
        """Force regenerate subscribed M3U playlist"""
        try:
            # Clear cache and regenerate
            cache_file = "playlist_subscribed.m3u"
            service.vfs.delete(cache_file)  # Delete if exists

            # Call the subscribed M3U endpoint which will regenerate
            return get_m3u_subscribed()

        except Exception as api_err:
            logger.error(f"API Error in /api/m3u/subscribed/generate: {str(api_err)}")
            response.status = 500
            return {"error": f"Internal server error: {str(api_err)}"}