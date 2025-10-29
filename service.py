#!/usr/bin/env python3
import os
import sys
import threading
from datetime import datetime
import xbmc
import xbmcaddon
import json
from bottle import Bottle, run, request, response, redirect, HTTPResponse
from urllib.parse import urlencode, parse_qsl

# Get addon settings
ADDON = xbmcaddon.Addon()
ADDON_PATH = ADDON.getAddonInfo('path')
LIB_PATH = os.path.join(ADDON_PATH, 'lib')
sys.path.insert(0, LIB_PATH)

try:
    from streaming_providers import get_configured_manager
    from streaming_providers.base.models import StreamingChannel
    from streaming_providers.base.utils import logger, VFS, MPDRewriter, MPDCacheManager
except ImportError as import_err:
    xbmc.log(f"Ultimate Backend: Critical import failed - {str(import_err)}", xbmc.LOGERROR)
    raise


class UltimateService:
    def __init__(self):
        self.app = Bottle()
        try:
            self.manager = get_configured_manager()
            logger.info("Manager initialized successfully")
        except Exception as init_err:
            logger.error(f"Failed to initialize manager - {str(init_err)}")
            raise

        # Initialize VFS for M3U caching
        self.vfs = VFS(addon_subdir="m3u_cache")
        logger.info(f"VFS initialized for M3U caching: {self.vfs.base_path}")

        self.mpd_cache = MPDCacheManager()
        logger.info(f"MPD cache initialized: {self.mpd_cache.vfs.base_path}")

        self.setup_routes()

    def _get_proxied_manifest(self, provider: str, channel_id: str) -> str:
        """
        Get proxied and rewritten MPD manifest for a channel.
        Uses cache when available and valid.

        Args:
            provider: Provider name
            channel_id: Channel ID

        Returns:
            Rewritten MPD content as string
        """
        country = request.query.get('country')

        # Try cache first
        cached_mpd = self.mpd_cache.get(provider, channel_id)
        if cached_mpd:
            response.content_type = 'application/dash+xml; charset=utf-8'
            return cached_mpd

        # Cache miss - fetch and rewrite
        logger.info(f"Cache miss for {provider}/{channel_id}, fetching manifest")

        # Get original manifest URL
        manifest_url = self.manager.get_channel_manifest(
            provider_name=provider,
            channel_id=channel_id,
            country=country
        )

        if not manifest_url:
            response.status = 404
            response.content_type = 'application/json'
            return json.dumps(
                {'error': f'Manifest not available for channel "{channel_id}" from provider "{provider}"'})

        # Get provider's HTTP manager
        http_manager = self.manager.get_provider_http_manager(provider)
        if not http_manager:
            logger.error(f"No HTTP manager found for provider '{provider}'")
            response.status = 502
            response.content_type = 'application/json'
            return json.dumps({'error': f'Provider "{provider}" not configured properly'})

        # Fetch manifest via proxy
        try:
            logger.debug(f"Fetching manifest via proxy: {manifest_url}")
            manifest_response = http_manager.get(manifest_url, operation="manifest")

            # Extract cache TTL from response headers
            ttl = MPDRewriter.extract_cache_ttl(manifest_response.headers)

            # Also check MPD's own update period as fallback
            mpd_ttl = MPDRewriter.extract_mpd_update_period(manifest_response.text)
            if mpd_ttl and mpd_ttl < ttl:
                ttl = mpd_ttl
                logger.debug(f"Using MPD minimumUpdatePeriod as TTL: {ttl}s")

            # Rewrite MPD URLs to point to proxy
            base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
            rewriter = MPDRewriter(base_url, provider)
            rewritten_mpd = rewriter.rewrite_mpd(manifest_response.text, manifest_url)

            # Cache the rewritten MPD
            self.mpd_cache.set(
                provider=provider,
                channel_id=channel_id,
                mpd_content=rewritten_mpd,
                ttl=ttl,
                original_url=manifest_url
            )

            # Return rewritten MPD
            response.content_type = 'application/dash+xml; charset=utf-8'
            return rewritten_mpd

        except Exception as fetch_err:
            logger.error(f"Failed to fetch manifest via proxy: {fetch_err}")
            response.status = 502
            response.content_type = 'application/json'
            return json.dumps({'error': f'Failed to fetch manifest via proxy: {str(fetch_err)}'})

    def setup_routes(self):
        @self.app.route('/api/providers')
        def list_providers():
            try:
                providers = self.manager.list_providers()
                default_country = ADDON.getSetting('default_country') or 'DE'
                return {
                    'providers': providers,
                    'default_country': default_country
                }
            except Exception as api_err:
                logger.error(f"API Error in /api/providers: {str(api_err)}")
                response.status = 500
                return {'error': str(api_err)}

        @self.app.route('/api/providers/<provider>/channels')
        def get_channels(provider):
            try:
                channels = self.manager.get_channels(
                    provider_name=provider,
                    fetch_manifests=request.query.get('fetch_manifests', 'false').lower() == 'true',
                    country=request.query.get('country')
                )
                return {
                    'provider': provider,
                    'country': self.manager.get_provider(provider).country if self.manager.get_provider(
                        provider) else 'DE',
                    'channels': [c.to_dict() for c in channels]
                }
            except Exception as api_err:
                logger.error(f"API Error in /api/providers/{provider}: {str(api_err)}")
                response.status = 500
                return {'error': str(api_err)}

        @self.app.route('/api/providers/<provider>/channels/<channel_id>/manifest')
        def get_channel_manifest(provider, channel_id):
            """
            Get channel manifest. If provider uses proxy, returns rewritten MPD content.
            Otherwise returns manifest URL as JSON.
            """
            try:
                # Check if provider needs proxy
                if self.manager.needs_proxy(provider):
                    # Proxy mode: return rewritten MPD content
                    return self._get_proxied_manifest(provider, channel_id)
                else:
                    # Direct mode: return manifest URL as JSON (existing behavior)
                    manifest_url = self.manager.get_channel_manifest(
                        provider_name=provider,
                        channel_id=channel_id,
                        country=request.query.get('country')
                    )

                    if not manifest_url:
                        response.status = 404
                        return {'error': f'Manifest not available for channel "{channel_id}" from provider "{provider}"'}

                    return {
                        'provider': provider,
                        'channel_id': channel_id,
                        'manifest_url': manifest_url
                    }

            except ValueError as val_err:
                logger.error(f"API Error in /api/providers/{provider}/channels/{channel_id}/manifest: {str(val_err)}")
                response.status = 404
                return {'error': str(val_err)}
            except Exception as api_err:
                logger.error(f"API Error in /api/providers/{provider}/channels/{channel_id}/manifest: {str(api_err)}")
                response.status = 500
                return {'error': f'Internal server error: {str(api_err)}'}

        @self.app.route('/api/providers/<provider>/channels/<channel_id>/stream')
        def get_channel_stream(provider, channel_id):
            """
            Returns HTTP 302 redirect to the actual manifest or rewritten manifest endpoint.
            This allows players to use this endpoint directly as a stream URL.
            """
            try:
                # Check if provider needs proxy
                if self.manager.needs_proxy(provider):
                    # Proxy mode: redirect to our manifest endpoint which serves rewritten MPD
                    country = request.query.get('country')
                    manifest_endpoint = f"/api/providers/{provider}/channels/{channel_id}/manifest"
                    if country:
                        manifest_endpoint += f"?country={country}"

                    logger.debug(f"Redirecting to proxied manifest endpoint: {manifest_endpoint}")
                    redirect(manifest_endpoint)
                else:
                    # Direct mode: redirect to original manifest URL
                    manifest_url = self.manager.get_channel_manifest(
                        provider_name=provider,
                        channel_id=channel_id,
                        country=request.query.get('country')
                    )

                    if not manifest_url:
                        response.status = 404
                        return {
                            'error': f'Manifest not available for channel "{channel_id}" from provider "{provider}"'}

                    logger.debug(f"Redirecting to manifest: {manifest_url}")
                    redirect(manifest_url)

            except HTTPResponse:
                # Re-raise HTTPResponse - this is how Bottle handles redirects
                raise
            except ValueError as val_err:
                logger.error(f"API Error in /api/providers/{provider}/channels/{channel_id}/stream: {str(val_err)}")
                response.status = 404
                return {'error': str(val_err)}
            except Exception as api_err:
                logger.error(f"API Error in /api/providers/{provider}/channels/{channel_id}/stream: {str(api_err)}")
                response.status = 500
                return {'error': f'Internal server error: {str(api_err)}'}

        @self.app.route('/api/proxy/<provider>/<encoded_url:path>')
        def proxy_media_segment(provider, encoded_url):
            """
            Proxy media segments through provider's HTTP manager.
            Decodes base64 URL and appends any template suffix, then fetches via configured proxy.

            URL format: /api/proxy/<provider>/<base64_encoded_base_url>/<optional_template_path>
            Example: /api/proxy/joyn_ch/aHR0cHM6Ly9jZG4uZXhhbXBsZS5jb20vcGF0aA==/segment-123.m4s
            """
            try:
                # Split the encoded_url into base64 part and optional suffix
                # The first path segment is the base64-encoded base URL
                # Everything after that is the template path (already resolved by client)
                parts = encoded_url.split('/', 1)
                base64_part = parts[0]
                template_suffix = parts[1] if len(parts) > 1 else ''

                # Decode the base URL
                try:
                    base_url = MPDRewriter.decode_url(base64_part)
                except Exception as decode_err:
                    logger.error(f"Failed to decode proxy URL: {decode_err}")
                    response.status = 400
                    return {'error': 'Invalid encoded URL'}

                # Reconstruct the full URL
                # If there's a template suffix, append it to the base URL
                if template_suffix:
                    # Ensure proper joining (base_url might or might not end with /)
                    if base_url.endswith('/'):
                        original_url = base_url + template_suffix
                    else:
                        original_url = base_url + '/' + template_suffix
                else:
                    original_url = base_url

                logger.debug(f"Proxy request for {provider}:")
                logger.debug(f"  Base64 part: {base64_part[:50]}...")
                logger.debug(f"  Decoded base: {base_url}")
                logger.debug(f"  Template suffix: {template_suffix}")
                logger.debug(f"  Final URL: {original_url}")

                # Get provider's HTTP manager
                http_manager = self.manager.get_provider_http_manager(provider)
                if not http_manager:
                    logger.error(f"No HTTP manager found for provider '{provider}'")
                    response.status = 404
                    return {'error': f'Provider "{provider}" not found or not configured'}

                # Check if proxy is configured
                if not http_manager.config.proxy_config:
                    logger.error(f"Provider '{provider}' has no proxy configured")
                    response.status = 502
                    return {'error': f'Provider "{provider}" has no proxy configured'}

                logger.info(f"Fetching media segment via proxy for {provider}: {original_url[:100]}...")

                # Fetch via proxy using 'manifest' operation
                proxy_response = http_manager.get(original_url, operation="manifest")

                logger.info(f"Successfully fetched segment, size: {len(proxy_response.content)} bytes")

                # Set response headers from proxied response
                response.content_type = proxy_response.headers.get('Content-Type', 'application/octet-stream')

                # Add Content-Length if available
                if 'Content-Length' in proxy_response.headers:
                    response.headers['Content-Length'] = proxy_response.headers['Content-Length']

                # Copy other potentially useful headers
                for header in ['Cache-Control', 'ETag', 'Last-Modified']:
                    if header in proxy_response.headers:
                        response.headers[header] = proxy_response.headers[header]

                # Return the content directly
                return proxy_response.content

            except Exception as proxy_err:
                logger.error(f"Proxy error for {provider}: {str(proxy_err)}", exc_info=True)
                response.status = 502
                return {'error': f'Proxy failed: {str(proxy_err)}'}

        @self.app.route('/api/providers/<provider>/channels/<channel_id>/pssh')
        def get_channel_pssh(provider, channel_id):
            try:
                # Get the manifest URL first
                manifest_url = self.manager.get_channel_manifest(
                    provider_name=provider,
                    channel_id=channel_id,
                    country=request.query.get('country')
                )

                if not manifest_url:
                    response.status = 404
                    return {'error': f'Manifest not available for channel "{channel_id}" from provider "{provider}"'}

                # Extract PSSH data from the manifest
                pssh_data_list = self.manager.extract_pssh_from_manifest(manifest_url)

                if not pssh_data_list:
                    response.status = 404
                    return {
                        'error': f'No PSSH data found in manifest for channel "{channel_id}" from provider "{provider}"'}

                # Convert PSSH data to dictionary format for JSON response
                pssh_list = []
                for pssh_data in pssh_data_list:
                    if hasattr(pssh_data, 'to_dict'):
                        pssh_list.append(pssh_data.to_dict())
                    else:
                        # Fallback for basic PSSH data structure
                        pssh_dict = {
                            'pssh': getattr(pssh_data, 'pssh', str(pssh_data)) if hasattr(pssh_data, 'pssh') else str(
                                pssh_data),
                            'system_id': getattr(pssh_data, 'system_id', None),
                            'key_id': getattr(pssh_data, 'key_id', None) if hasattr(pssh_data, 'key_id') else None
                        }
                        # Remove None values
                        pssh_dict = {k: v for k, v in pssh_dict.items() if v is not None}
                        pssh_list.append(pssh_dict)

                return {
                    'provider': provider,
                    'channel_id': channel_id,
                    'manifest_url': manifest_url,
                    'pssh_data': pssh_list,
                    'count': len(pssh_list)
                }

            except ValueError as val_err:
                # This handles the case where manager raises ValueError for unknown provider
                logger.error(f"API Error in /api/providers/{provider}/channels/{channel_id}/pssh: {str(val_err)}")
                response.status = 404
                return {'error': str(val_err)}
            except Exception as api_err:
                logger.error(f"API Error in /api/providers/{provider}/channels/{channel_id}/pssh: {str(api_err)}")
                response.status = 500
                return {'error': f'Internal server error: {str(api_err)}'}

        @self.app.route('/api/providers/<provider>/channels/<channel_id>/epg')
        def get_channel_epg(provider, channel_id):
            try:
                # Parse optional datetime parameters
                kwargs = {'country': request.query.get('country')}

                if request.query.get('start_time'):
                    try:
                        kwargs['start_time'] = datetime.fromisoformat(
                            request.query.get('start_time').replace('Z', '+00:00'))
                    except ValueError:
                        response.status = 400
                        return {'error': 'Invalid start_time format. Use ISO format (YYYY-MM-DDTHH:MM:SS)'}

                if request.query.get('end_time'):
                    try:
                        kwargs['end_time'] = datetime.fromisoformat(
                            request.query.get('end_time').replace('Z', '+00:00'))
                    except ValueError:
                        response.status = 400
                        return {'error': 'Invalid end_time format. Use ISO format (YYYY-MM-DDTHH:MM:SS)'}

                epg_data = self.manager.get_channel_epg(
                    provider_name=provider,
                    channel_id=channel_id,
                    **kwargs
                )

                return {
                    'provider': provider,
                    'channel_id': channel_id,
                    'epg': epg_data
                }

            except ValueError as val_err:
                # This handles the case where manager raises ValueError for unknown provider
                logger.error(f"API Error in /api/providers/{provider}/channels/{channel_id}/epg: {str(val_err)}")
                response.status = 404
                return {'error': str(val_err)}
            except Exception as api_err:
                logger.error(f"API Error in /api/providers/{provider}/channels/{channel_id}/epg: {str(api_err)}")
                response.status = 500
                return {'error': f'Internal server error: {str(api_err)}'}

        @self.app.route('/api/providers/<provider>/epg')
        def get_provider_epg_xmltv(provider):
            try:
                # Set appropriate headers for XMLTV
                response.content_type = 'application/xml; charset=utf-8'
                response.headers['Content-Disposition'] = f'attachment; filename="{provider}_epg.xml"'

                # Get the XMLTV data from the provider
                xmltv_data = self.manager.get_provider_epg_xmltv(
                    provider_name=provider,
                    country=request.query.get('country')
                )

                if not xmltv_data:
                    response.status = 404
                    return {'error': f'EPG data not available for provider "{provider}"'}

                return xmltv_data

            except ValueError as val_err:
                # Handle unknown provider
                logger.error(f"API Error in /api/providers/{provider}/epg: {str(val_err)}")
                response.status = 404
                return {'error': str(val_err)}
            except Exception as api_err:
                logger.error(f"API Error in /api/providers/{provider}/epg: {str(api_err)}")
                response.status = 500
                return {'error': f'Internal server error: {str(api_err)}'}

        @self.app.route('/api/providers/<provider>/channels/<channel_id>/drm')
        def get_channel_drm(provider, channel_id):
            try:
                drm_configs = self.manager.get_channel_drm_configs(
                    provider_name=provider,
                    channel_id=channel_id,
                    country=request.query.get('country')
                )

                return {
                    'provider': provider,
                    'channel_id': channel_id,
                    'drm_configs': [config.to_dict() if hasattr(config, 'to_dict') else config for config in
                                    drm_configs]
                }

            except ValueError as val_err:
                # This handles the case where manager raises ValueError for unknown provider
                logger.error(f"API Error in /api/providers/{provider}/channels/{channel_id}/drm: {str(val_err)}")
                response.status = 404
                return {'error': str(val_err)}
            except Exception as api_err:
                logger.error(f"API Error in /api/providers/{provider}/channels/{channel_id}/drm: {str(api_err)}")
                response.status = 500
                return {'error': f'Internal server error: {str(api_err)}'}

        @self.app.route('/api/m3u')
        def get_m3u_all():
            """
            Generates M3U playlist for all configured providers.
            Returns cached version if available, otherwise generates new one.

            Example: http://localhost:7777/api/m3u
            """
            try:
                cache_file = "playlist.m3u"

                # Try to read cached file
                cached_content = self.vfs.read_text(cache_file)

                if cached_content:
                    logger.info("Serving cached M3U playlist for all providers")
                    response.content_type = 'audio/x-mpegurl; charset=utf-8'
                    response.headers['Content-Disposition'] = 'attachment; filename="playlist.m3u8"'
                    return cached_content

                # Cache doesn't exist or is corrupt, generate new M3U
                logger.info("No valid cache found, generating M3U playlist for all providers")
                return self._generate_m3u_all(save_to_cache=True)

            except Exception as api_err:
                logger.error(f"API Error in /api/m3u: {str(api_err)}")
                response.status = 500
                return {'error': f'Internal server error: {str(api_err)}'}

        @self.app.route('/api/m3u/generate')
        def generate_m3u_all():
            """
            Forces regeneration of M3U playlist for all providers and saves to cache.

            Example: http://localhost:7777/api/m3u/generate
            """
            try:
                logger.info("Force generating M3U playlist for all providers")
                return self._generate_m3u_all(save_to_cache=True)

            except Exception as api_err:
                logger.error(f"API Error in /api/m3u/generate: {str(api_err)}")
                response.status = 500
                return {'error': f'Internal server error: {str(api_err)}'}

        @self.app.route('/api/providers/<provider>/m3u')
        def get_m3u_provider(provider):
            """
            Generates M3U playlist for a specific provider.
            Returns cached version if available, otherwise generates new one.

            Example: http://localhost:7777/api/providers/rtlplus/m3u
            """
            try:
                cache_file = f"{provider}.m3u"

                # Try to read cached file
                cached_content = self.vfs.read_text(cache_file)

                if cached_content:
                    logger.info(f"Serving cached M3U playlist for provider '{provider}'")
                    response.content_type = 'audio/x-mpegurl; charset=utf-8'
                    response.headers['Content-Disposition'] = f'attachment; filename="{provider}_playlist.m3u8"'
                    return cached_content

                # Cache doesn't exist or is corrupt, generate new M3U
                logger.info(f"No valid cache found, generating M3U playlist for provider '{provider}'")
                return self._generate_m3u_provider(provider, save_to_cache=True)

            except ValueError as val_err:
                logger.error(f"API Error in /api/providers/{provider}/m3u: {str(val_err)}")
                response.status = 404
                return {'error': str(val_err)}
            except Exception as api_err:
                logger.error(f"API Error in /api/providers/{provider}/m3u: {str(api_err)}")
                response.status = 500
                return {'error': f'Internal server error: {str(api_err)}'}

        @self.app.route('/api/providers/<provider>/m3u/generate')
        def generate_m3u_provider(provider):
            """
            Forces regeneration of M3U playlist for a specific provider and saves to cache.

            Example: http://localhost:7777/api/providers/rtlplus/m3u/generate
            """
            try:
                logger.info(f"Force generating M3U playlist for provider '{provider}'")
                return self._generate_m3u_provider(provider, save_to_cache=True)

            except ValueError as val_err:
                logger.error(f"API Error in /api/providers/{provider}/m3u/generate: {str(val_err)}")
                response.status = 404
                return {'error': str(val_err)}
            except Exception as api_err:
                logger.error(f"API Error in /api/providers/{provider}/m3u/generate: {str(api_err)}")
                response.status = 500
                return {'error': f'Internal server error: {str(api_err)}'}

        @self.app.route('/api/cache/mpd/clear')
        def clear_mpd_cache():
            """Clear all cached MPD manifests"""
            try:
                self.mpd_cache.clear_all()
                return {'success': True, 'message': 'MPD cache cleared'}
            except Exception as e:
                logger.error(f"Error clearing MPD cache: {e}")
                response.status = 500
                return {'error': str(e)}

        @self.app.route('/api/cache/mpd/clear-expired')
        def clear_expired_mpd_cache():
            """Clear expired MPD cache entries"""
            try:
                cleared = self.mpd_cache.clear_expired()
                return {'success': True, 'cleared': cleared}
            except Exception as e:
                logger.error(f"Error clearing expired MPD cache: {e}")
                response.status = 500
                return {'error': str(e)}

        @self.app.route('/api/cache/mpd/<provider>/<channel_id>')
        def get_mpd_cache_info(provider, channel_id):
            """Get cache information for a specific channel"""
            try:
                info = self.mpd_cache.get_cache_info(provider, channel_id)
                if info:
                    return {'success': True, 'cache_info': info}
                else:
                    response.status = 404
                    return {'success': False, 'message': 'No cache found'}
            except Exception as e:
                logger.error(f"Error getting cache info: {e}")
                response.status = 500
                return {'error': str(e)}

        @self.app.route('/api/cache/mpd/<provider>/<channel_id>/delete')
        def delete_mpd_cache(provider, channel_id):
            """Delete cached MPD for a specific channel"""
            try:
                self.mpd_cache.delete(provider, channel_id)
                return {'success': True, 'message': f'Cache deleted for {provider}/{channel_id}'}
            except Exception as e:
                logger.error(f"Error deleting cache: {e}")
                response.status = 500
                return {'error': str(e)}

    def _generate_m3u_all(self, save_to_cache: bool = False) -> str:
        """
        Internal method to generate M3U for all providers.

        Args:
            save_to_cache: Whether to save generated M3U to cache file

        Returns:
            M3U content as string
        """
        # Get base URL for absolute stream URLs
        base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"

        # Start M3U content
        m3u_content = "#EXTM3U\n"

        # Get all providers
        providers = self.manager.list_providers()

        for provider_name in providers:
            try:
                # Get channels for this provider
                channels = self.manager.get_channels(
                    provider_name=provider_name,
                    fetch_manifests=False
                )

                # Add each channel to M3U
                for channel in channels:
                    # Access StreamingChannel attributes directly
                    channel_id = channel.channel_id
                    channel_name = channel.name
                    channel_logo = channel.logo_url or ''

                    # Build stream URL
                    stream_url = f"{base_url}/api/providers/{provider_name}/channels/{channel_id}/stream"

                    # Add M3U entry with extended info first
                    m3u_content += f'#EXTINF:-1 tvg-logo="{channel_logo}" group-title="{provider_name}",{channel_name}\n'

                    # Get DRM configs and add KODIPROP directives
                    try:
                        drm_configs = self.manager.get_channel_drm_configs(
                            provider_name=provider_name,
                            channel_id=channel_id
                        )

                        if drm_configs:
                            # Prioritize: clearkey > widevine > playready
                            selected_drm = None
                            priority_order = ['org.w3.clearkey', 'com.widevine.alpha', 'com.microsoft.playready']

                            for priority_system in priority_order:
                                for drm in drm_configs:
                                    drm_dict = drm.to_dict() if hasattr(drm, 'to_dict') else drm
                                    if priority_system in drm_dict:
                                        selected_drm = (priority_system, drm_dict[priority_system])
                                        break
                                if selected_drm:
                                    break

                            if selected_drm:
                                drm_system, drm_data = selected_drm

                                # Add KODIPROP directives
                                m3u_content += "#KODIPROP:inputstream=inputstream.adaptive\n"
                                m3u_content += "#KODIPROP:inputstream.adaptive.manifest_type=mpd\n"

                                # Build DRM legacy string
                                drm_legacy_parts = [drm_system]

                                license_info = drm_data.get('license', {})

                                # Add license server URL or keyids
                                if drm_system == 'org.w3.clearkey' and license_info.get('keyids'):
                                    # ClearKey: format as kid:key,kid:key
                                    keyids = license_info['keyids']
                                    keys_str = ','.join([f"{kid}:{key}" for kid, key in keyids.items()])
                                    drm_legacy_parts.append(keys_str)
                                elif license_info.get('server_url'):
                                    # Widevine/PlayReady: add license server URL
                                    drm_legacy_parts.append(license_info['server_url'])

                                    # Add headers if present (URL-encoded)
                                    if license_info.get('req_headers'):
                                        req_headers = license_info['req_headers']
                                        # If req_headers is a string, try to parse it
                                        if isinstance(req_headers, str):
                                            # Assume it's already in key=value&key=value format or similar
                                            # Just ensure it's URL-encoded
                                            if '&' in req_headers or '=' in req_headers:
                                                # Parse and re-encode to ensure proper encoding
                                                try:
                                                    headers_dict = dict(parse_qsl(req_headers))
                                                    req_headers = urlencode(headers_dict)
                                                except:
                                                    # If parsing fails, use as-is
                                                    pass
                                        elif isinstance(req_headers, dict):
                                            # Convert dict to URL-encoded string
                                            req_headers = urlencode(req_headers)

                                        drm_legacy_parts.append(req_headers)

                                # Join parts with pipe separator
                                drm_legacy = '|'.join(drm_legacy_parts)
                                m3u_content += f"#KODIPROP:inputstream.adaptive.drm_legacy={drm_legacy}\n"

                    except Exception as drm_err:
                        logger.debug(f"Could not get DRM for {provider_name}/{channel_id}: {str(drm_err)}")

                    # Add stream URL
                    m3u_content += f'{stream_url}\n'

            except Exception as provider_err:
                logger.warning(f"Failed to get channels for provider '{provider_name}': {str(provider_err)}")
                continue

        # Save to cache if requested
        if save_to_cache:
            cache_file = "playlist.m3u"
            if self.vfs.write_text(cache_file, m3u_content):
                logger.info(f"M3U playlist cached to {cache_file}")
            else:
                logger.warning(f"Failed to cache M3U playlist to {cache_file}")

        # Set appropriate headers for M3U
        response.content_type = 'audio/x-mpegurl; charset=utf-8'
        response.headers['Content-Disposition'] = 'attachment; filename="playlist.m3u8"'

        return m3u_content

    def _generate_m3u_provider(self, provider: str, save_to_cache: bool = False) -> str:
        """
        Internal method to generate M3U for a specific provider.

        Args:
            provider: Provider name
            save_to_cache: Whether to save generated M3U to cache file

        Returns:
            M3U content as string
        """
        # Get base URL for absolute stream URLs
        base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"

        # Start M3U content
        m3u_content = "#EXTM3U\n"

        # Get channels for this provider
        channels = self.manager.get_channels(
            provider_name=provider,
            fetch_manifests=False
        )

        # Add each channel to M3U
        for channel in channels:
            # Access StreamingChannel attributes directly
            channel_id = channel.channel_id
            channel_name = channel.name
            channel_logo = channel.logo_url or ''

            # Build stream URL
            stream_url = f"{base_url}/api/providers/{provider}/channels/{channel_id}/stream"

            # Add M3U entry with extended info first
            m3u_content += f'#EXTINF:-1 tvg-logo="{channel_logo}" group-title="{provider}",{channel_name}\n'

            # Get DRM configs and add KODIPROP directives
            try:
                drm_configs = self.manager.get_channel_drm_configs(
                    provider_name=provider,
                    channel_id=channel_id
                )

                if drm_configs:
                    # Prioritize: clearkey > widevine > playready
                    selected_drm = None
                    priority_order = ['org.w3.clearkey', 'com.widevine.alpha', 'com.microsoft.playready']

                    for priority_system in priority_order:
                        for drm in drm_configs:
                            drm_dict = drm.to_dict() if hasattr(drm, 'to_dict') else drm
                            if priority_system in drm_dict:
                                selected_drm = (priority_system, drm_dict[priority_system])
                                break
                        if selected_drm:
                            break

                    if selected_drm:
                        drm_system, drm_data = selected_drm

                        # Add KODIPROP directives
                        m3u_content += "#KODIPROP:inputstream=inputstream.adaptive\n"
                        m3u_content += "#KODIPROP:inputstream.adaptive.manifest_type=mpd\n"

                        # Build DRM legacy string
                        drm_legacy_parts = [drm_system]

                        license_info = drm_data.get('license', {})

                        # Add license server URL or keyids
                        if drm_system == 'org.w3.clearkey' and license_info.get('keyids'):
                            # ClearKey: format as kid:key,kid:key
                            keyids = license_info['keyids']
                            keys_str = ','.join([f"{kid}:{key}" for kid, key in keyids.items()])
                            drm_legacy_parts.append(keys_str)
                        elif license_info.get('server_url'):
                            # Widevine/PlayReady: add license server URL
                            drm_legacy_parts.append(license_info['server_url'])

                            # Add headers if present (URL-encoded)
                            if license_info.get('req_headers'):
                                req_headers = license_info['req_headers']
                                # If req_headers is a string, try to parse it
                                if isinstance(req_headers, str):
                                    # Assume it's already in key=value&key=value format or similar
                                    # Just ensure it's URL-encoded
                                    if '&' in req_headers or '=' in req_headers:
                                        # Parse and re-encode to ensure proper encoding
                                        try:
                                            headers_dict = dict(parse_qsl(req_headers))
                                            req_headers = urlencode(headers_dict)
                                        except:
                                            # If parsing fails, use as-is
                                            pass
                                elif isinstance(req_headers, dict):
                                    # Convert dict to URL-encoded string
                                    req_headers = urlencode(req_headers)

                                drm_legacy_parts.append(req_headers)

                        # Join parts with pipe separator
                        drm_legacy = '|'.join(drm_legacy_parts)
                        m3u_content += f"#KODIPROP:inputstream.adaptive.drm_legacy={drm_legacy}\n"

            except Exception as drm_err:
                logger.debug(f"Could not get DRM for {provider}/{channel_id}: {str(drm_err)}")

            # Add stream URL
            m3u_content += f'{stream_url}\n'

        # Save to cache if requested
        if save_to_cache:
            cache_file = f"{provider}.m3u"
            if self.vfs.write_text(cache_file, m3u_content):
                logger.info(f"M3U playlist for '{provider}' cached to {cache_file}")
            else:
                logger.warning(f"Failed to cache M3U playlist for '{provider}' to {cache_file}")

        # Set appropriate headers for M3U
        response.content_type = 'audio/x-mpegurl; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename="{provider}_playlist.m3u8"'

        return m3u_content

def run_service():
    service = UltimateService()
    port = int(ADDON.getSetting("server_port") or 7777)
    logger.info(f"Starting server on port {port}")
    run(service.app, host='0.0.0.0', port=port, quiet=True, debug=True)


if __name__ == '__main__':
    logger.info("Starting service...")

    # Give Kodi time to initialize
    import time

    time.sleep(5)

    try:
        service_thread = threading.Thread(
            target=run_service,
            name="UltimateBackendService"
        )
        service_thread.daemon = True
        service_thread.start()

        monitor = xbmc.Monitor()
        while not monitor.abortRequested():
            if monitor.waitForAbort(5):
                break

        logger.info("Service stopped")
    except Exception as startup_err:
        logger.error(f"Failed to start - {str(startup_err)}")
        raise