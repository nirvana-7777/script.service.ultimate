#!/usr/bin/env python3
import os
import sys
import threading
from datetime import datetime
import time
import json
from bottle import Bottle, run, request, response, redirect, HTTPResponse
from urllib.parse import urlencode, parse_qsl

# Add lib path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
LIB_PATH = os.path.join(script_dir, 'lib')
if os.path.exists(LIB_PATH):
    sys.path.insert(0, LIB_PATH)

try:
    from streaming_providers import get_configured_manager
    from streaming_providers.base.models import StreamingChannel
    from streaming_providers.base.utils import logger, MPDRewriter, MPDCacheManager
    from streaming_providers.base.utils.environment import get_environment_manager, get_vfs_instance
    from streaming_providers.base.utils.environment import is_kodi_environment
    from streaming_providers.base.settings.provider_enable_manager import ProviderEnableManager
    # Add EPG Manager import
    from streaming_providers.base.epg.epg_manager import EPGManager
except ImportError as import_err:
    print(f"Ultimate Backend: Critical import failed - {str(import_err)}", file=sys.stderr)
    raise


class UltimateService:
    def __init__(self, config_dir: str = None):
        self.app = Bottle()

        # Get environment manager
        self.env_manager = get_environment_manager()

        # Override config directory if provided
        if config_dir:
            self.env_manager.set_config('profile_path', config_dir)

        # Get settings
        self.server_port = self.env_manager.get_config('server_port', 7777)
        self.default_country = self.env_manager.get_config('default_country', 'DE')

        # Initialize manager
        try:
            self.manager = get_configured_manager()
            logger.info("Manager initialized successfully")
        except Exception as init_err:
            logger.error(f"Failed to initialize manager - {str(init_err)}")
            raise

        # Initialize VFS for M3U caching
        self.vfs = get_vfs_instance(subdir="m3u_cache")
        logger.info(f"VFS initialized for M3U caching: {self.vfs.base_path}")

        self.mpd_cache = MPDCacheManager()
        logger.info(f"MPD cache initialized: {self.mpd_cache.vfs.base_path}")

        # 1. Determine EPG URL FIRST (with proper precedence)
        self.epg_url = self._determine_epg_url()
        logger.info(f"UltimateService: Final EPG URL determined: {self.epg_url}")

        # 2. Initialize EPG Manager WITH the URL
        try:
            self.epg_manager = EPGManager(self.epg_url)  # Pass the URL here
            logger.info(f"EPG Manager initialized with URL: {self.epg_url}")
        except ImportError as e:
            logger.warning(f"Could not import EPG Manager: {e}")
            self.epg_manager = None
        except Exception as e:
            logger.warning(f"Could not initialize EPG Manager: {e}")
            self.epg_manager = None

        self.setup_routes()
        self.config_html = self._load_config_html()

    def _determine_epg_url(self) -> str:
        """
        Determine EPG URL with proper precedence.
        Must match the precedence logic in EPGManager.
        """
        import os

        # 1. Environment variable (highest priority for Docker)
        env_url = os.environ.get('ULTIMATE_EPG_URL')
        if env_url and env_url.strip() and env_url != "https://example.com/epg.xml.gz":
            logger.info(f"UltimateService: Using EPG URL from environment variable: {env_url}")
            return env_url.strip()

        # 2. Try config.json via environment manager
        try:
            config_url = self.env_manager.get_config('epg_url')
            if config_url and config_url.strip() and config_url != "https://example.com/epg.xml.gz":
                logger.info(f"UltimateService: Using EPG URL from config.json: {config_url}")
                return config_url.strip()
        except Exception as e:
            logger.debug(f"UltimateService: Could not get EPG URL from environment manager: {e}")

        # 3. Try Kodi addon setting
        try:
            if is_kodi_environment():
                import xbmcaddon
                addon = xbmcaddon.Addon()
                kodi_url = addon.getSetting('epg_xml_url')
                if kodi_url and kodi_url.strip() and kodi_url != "https://example.com/epg.xml.gz":
                    logger.info(f"UltimateService: Using EPG URL from Kodi settings: {kodi_url}")
                    return kodi_url.strip()
        except Exception as e:
            logger.debug(f"UltimateService: Could not get EPG URL from Kodi settings: {e}")

        # 4. Default fallback
        default_url = "https://example.com/epg.xml.gz"
        logger.warning(f"UltimateService: No valid EPG URL found, using default: {default_url}")
        logger.warning("Please set ULTIMATE_EPG_URL environment variable!")
        return default_url

    def _load_config_html(self):
        """Load the web interface HTML template with embedded CSS and JS"""
        base_dir = os.path.dirname(os.path.abspath(__file__))
        web_dir = os.path.join(base_dir, 'resources', 'web')

        # Define file paths
        html_path = os.path.join(web_dir, 'config.html')
        css_path = os.path.join(web_dir, 'config.css')
        js_path = os.path.join(web_dir, 'config.js')

        # EPG mapping files
        epg_css_path = os.path.join(web_dir, 'epg_mapping.css')
        epg_js_path = os.path.join(web_dir, 'epg_mapping.js')
        fuzzyset_path = os.path.join(web_dir, 'lib', 'fuzzyset.js')
        debounce_path = os.path.join(web_dir, 'lib', 'debounce.js')

        try:
            # Load HTML
            with open(html_path, 'r', encoding='utf-8') as f:
                html = f.read()

            # Load CSS files
            with open(css_path, 'r', encoding='utf-8') as f:
                css = f.read()

            # Load EPG CSS
            with open(epg_css_path, 'r', encoding='utf-8') as f:
                epg_css = f.read()

            # Load JS files
            with open(js_path, 'r', encoding='utf-8') as f:
                js = f.read()

            # Load EPG JS and libraries
            with open(epg_js_path, 'r', encoding='utf-8') as f:
                epg_js = f.read()

            with open(fuzzyset_path, 'r', encoding='utf-8') as f:
                fuzzyset_js = f.read()

            with open(debounce_path, 'r', encoding='utf-8') as f:
                debounce_js = f.read()

            # Combine all CSS
            combined_css = f"{css}\n\n/* EPG Mapping CSS */\n{epg_css}"

            # Combine all JS (with proper order)
            combined_js = f"""

            /* Debounce Utility */
            {debounce_js}
            
            /* FuzzySet Library */
            {fuzzyset_js}
            
            /* Main Config JS */
            {js}
            
            /* EPG Mapping JS */
            {epg_js}
            """

            # Replace CSS in HTML
            html = html.replace('<link rel="stylesheet" href="config.css">',
                                f'<style>\n{combined_css}\n</style>')

            # Inject JavaScript before </body> tag since <script src="config.js"> was removed
            script_tag = f'<script>\n{combined_js}\n</script>'

            # Check if script tag exists in HTML (for backward compatibility)
            if '<script src="config.js"></script>' in html:
                html = html.replace('<script src="config.js"></script>', script_tag)
            else:
                # Script tag was removed, inject before </body>
                html = html.replace('</body>', f'{script_tag}\n</body>')

            return html

        except Exception as e:
            logger.error(f"Failed to load config files: {e}")
            return self._get_fallback_html()

    @staticmethod
    def _get_fallback_html():
        """Generate a minimal fallback HTML if file is not found"""
        return """
         <!DOCTYPE html>
         <html>
         <head>
             <title>Ultimate Backend Config - Fallback</title>
             <style>
                 body { font-family: Arial, sans-serif; padding: 20px; }
                 .error { color: red; }
             </style>
         </head>
         <body>
             <h1>Configuration Interface</h1>
             <p class="error">Warning: Full interface not loaded. Using basic mode.</p>
             <p><a href="/api/providers">View Providers</a></p>
             <div id="providers-container"></div>
             <script>
                 async function loadProviders() {
                     const response = await fetch('/api/providers');
                     const data = await response.json();

                     let html = '<h2>Providers</h2>';
                     data.providers.forEach(provider => {
                         html += `
                         <div style="border:1px solid #ccc; padding:10px; margin:10px 0;">
                             <h3>${provider.label}</h3>
                             <input id="user-${provider.name}" placeholder="Username">
                             <input id="pass-${provider.name}" type="password" placeholder="Password">
                             <button onclick="save('${provider.name}')">Save</button>
                         </div>`;
                     });
                     document.getElementById('providers-container').innerHTML = html;
                 }

                 async function save(provider) {
                     const creds = {
                         username: document.getElementById('user-' + provider).value,
                         password: document.getElementById('pass-' + provider).value
                     };

                     await fetch(`/api/providers/${provider}/credentials`, {
                         method: 'POST',
                         headers: {'Content-Type': 'application/json'},
                         body: JSON.stringify(creds)
                     });

                     alert('Saved');
                 }

                 loadProviders();
             </script>
         </body>
         </html>
         """

    def _get_setting(self, setting_id: str, default: str = None) -> str:
        """Get setting value from appropriate source"""
        # Try Kodi settings first if in Kodi environment
        if is_kodi_environment():
            try:
                import xbmcaddon
                addon = xbmcaddon.Addon()
                value = addon.getSetting(setting_id)
                return value if value else default
            except Exception as e:
                logger.debug(f"Could not get Kodi setting {setting_id}: {e}")

        # Fallback to environment manager config
        return self.env_manager.get_config(setting_id, default)

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

    def _generate_m3u_content(self, providers=None, save_to_cache=True, cache_filename=None):
        """
        Internal method to generate M3U content for specified providers.

        Args:
            providers: List of provider names, or None for all providers
            save_to_cache: Whether to save to cache
            cache_filename: Cache filename to use

        Returns:
            M3U content as string
        """
        # Get base URL for absolute stream URLs
        base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"

        # Start M3U content
        m3u_content = "#EXTM3U\n"

        # Determine which providers to process
        if providers is None:
            # All providers
            providers_to_process = self.manager.list_providers()
            cache_filename = cache_filename or "playlist.m3u"
        else:
            # Specific provider(s)
            providers_to_process = [providers] if isinstance(providers, str) else providers
            cache_filename = cache_filename or f"{providers_to_process[0]}.m3u"

        for provider_name in providers_to_process:
            try:
                # Get channels for this provider
                channels = self.manager.get_channels(
                    provider_name=provider_name,
                    fetch_manifests=False
                )

                # Add each channel to M3U
                for channel in channels:
                    m3u_content += self._generate_m3u_channel_entry(base_url, provider_name, channel)

            except Exception as provider_err:
                logger.warning(f"Failed to get channels for provider '{provider_name}': {str(provider_err)}")
                continue

        # Save to cache if requested
        if save_to_cache and cache_filename:
            if self.vfs.write_text(cache_filename, m3u_content):
                logger.info(f"M3U playlist cached to {cache_filename}")
            else:
                logger.warning(f"Failed to cache M3U playlist to {cache_filename}")

        return m3u_content

    def _generate_m3u_channel_entry(self, base_url, provider_name, channel):
        """
        Generate M3U entry for a single channel.

        Args:
            base_url: Base URL for stream endpoints
            provider_name: Name of the provider
            channel: StreamingChannel object

        Returns:
            M3U entry as string
        """
        entry_content = ""

        # Access StreamingChannel attributes directly
        channel_id = channel.channel_id
        channel_name = channel.name
        channel_logo = channel.logo_url or ''

        # Build stream URL
        stream_url = f"{base_url}/api/providers/{provider_name}/channels/{channel_id}/stream"

        # Get provider instance to access provider_label
        try:
            provider_instance = self.manager.get_provider(provider_name)
            provider_label = provider_instance.provider_label
        except (AttributeError, KeyError, ValueError):
            # Fallback to provider_name if provider_label is not available
            provider_label = provider_name

        # Add M3U entry with extended info first
        entry_content += f'#EXTINF:-1 tvg-id="{channel_id}" tvg-logo="{channel_logo}" group-title="{provider_label}",{channel_name}\n'

        # Get DRM configs and add KODIPROP directives
        try:
            drm_configs = self.manager.get_channel_drm_configs(
                provider_name=provider_name,
                channel_id=channel_id
            )

            if drm_configs:
                drm_directives = self._generate_drm_directives(drm_configs)
                entry_content += drm_directives

        except Exception as drm_err:
            logger.debug(f"Could not get DRM for {provider_name}/{channel_id}: {str(drm_err)}")

        # Add stream URL
        entry_content += f'{stream_url}\n'

        return entry_content

    def _generate_drm_directives(self, drm_configs):
        """
        Generate KODIPROP directives for DRM configuration.

        Args:
            drm_configs: DRM configurations as a dictionary (not list)

        Returns:
            DRM directives as string
        """
        directives = ""

        # drm_configs is now a dictionary, not a list
        if not isinstance(drm_configs, dict):
            # For backward compatibility, handle list format
            if isinstance(drm_configs, list):
                # Convert list to dict
                temp_dict = {}
                for config in drm_configs:
                    if hasattr(config, 'to_dict'):
                        temp_dict.update(config.to_dict())
                    elif isinstance(config, dict):
                        temp_dict.update(config)
                drm_configs = temp_dict
            else:
                return directives

        # Rest of the method remains the same...
        # Prioritize: clearkey > widevine > playready
        selected_drm = None
        priority_order = ['org.w3.clearkey', 'com.widevine.alpha', 'com.microsoft.playready']

        for priority_system in priority_order:
            if priority_system in drm_configs:
                selected_drm = (priority_system, drm_configs[priority_system])
                break

        if selected_drm:
            drm_system, drm_data = selected_drm

            # Add KODIPROP directives
            directives += "#KODIPROP:inputstream=inputstream.adaptive\n"

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
                    req_headers = self._process_license_headers(license_info['req_headers'])
                    if req_headers:
                        drm_legacy_parts.append(req_headers)

            # Join parts with pipe separator
            drm_legacy = '|'.join(drm_legacy_parts)
            directives += f"#KODIPROP:inputstream.adaptive.drm_legacy={drm_legacy}\n"

        return directives

    @staticmethod
    def _process_license_headers(req_headers):
        """
        Process license headers and convert to URL-encoded format.

        Args:
            req_headers: Headers in various formats (dict, JSON string, query string)

        Returns:
            URL-encoded headers string
        """
        if isinstance(req_headers, str):
            # Check if it's JSON format
            if req_headers.strip().startswith('{'):
                try:
                    # Parse JSON and convert to URL-encoded
                    headers_dict = json.loads(req_headers)
                    return urlencode(headers_dict)
                except json.JSONDecodeError:
                    # If not JSON, try to parse as query string
                    try:
                        # parse_qsl can raise ValueError if the query string is malformed
                        parsed_items = parse_qsl(req_headers)
                        headers_dict = dict(parsed_items)
                        return urlencode(headers_dict)
                    except ValueError as val_err:
                        logger.warning(f"Invalid query string format in headers: {val_err}")
                        return req_headers
                    except Exception as parse_err:
                        # Catch anything else unexpected
                        logger.warning(f"Unexpected error parsing headers: {parse_err}")
                        return req_headers
            else:
                # Assume it's already URL-encoded or query string format
                try:
                    headers_dict = dict(parse_qsl(req_headers))
                    return urlencode(headers_dict)
                except:
                    return req_headers
        elif isinstance(req_headers, dict):
            # Convert dict to URL-encoded string
            return urlencode(req_headers)
        else:
            logger.warning(f"Unsupported headers type: {type(req_headers)}")
            return str(req_headers)

    def _generate_m3u_all(self, save_to_cache: bool = False) -> str:
        """Internal method to generate M3U for all providers."""
        logger.info("Generating M3U playlist for all providers")
        m3u_content = self._generate_m3u_content(providers=None, save_to_cache=save_to_cache)

        # Set appropriate headers for M3U
        response.content_type = 'audio/x-mpegurl; charset=utf-8'
        response.headers['Content-Disposition'] = 'attachment; filename="playlist.m3u8"'

        return m3u_content

    def _generate_m3u_provider(self, provider: str, save_to_cache: bool = False) -> str:
        """Internal method to generate M3U for a specific provider."""
        logger.info(f"Generating M3U playlist for provider '{provider}'")
        m3u_content = self._generate_m3u_content(providers=provider, save_to_cache=save_to_cache)

        # Set appropriate headers for M3U
        response.content_type = 'audio/x-mpegurl; charset=utf-8'
        response.headers['Content-Disposition'] = f'attachment; filename="{provider}_playlist.m3u8"'

        return m3u_content

    def _get_proxied_catchup_manifest(self, provider: str, channel_id: str,
                                      start_time: int, end_time: int,
                                      epg_id: str = None, country: str = None) -> str:
        """
        Get proxied and rewritten MPD manifest for catchup content.
        Similar to _get_proxied_manifest but for catchup streams.
        """
        # Generate cache key that includes time parameters
        cache_key = f"{channel_id}_catchup_{start_time}_{end_time}"

        # Try cache first (with catchup-specific key)
        cached_mpd = self.mpd_cache.get(provider, cache_key)
        if cached_mpd:
            response.content_type = 'application/dash+xml; charset=utf-8'
            return cached_mpd

        logger.info(f"Cache miss for catchup {provider}/{channel_id}, fetching manifest")

        # Get catchup manifest URL
        manifest_url = self.manager.get_catchup_manifest(
            provider_name=provider,
            channel_id=channel_id,
            start_time=start_time,
            end_time=end_time,
            epg_id=epg_id,
            country=country
        )

        if not manifest_url:
            response.status = 404
            response.content_type = 'application/json'
            return json.dumps({'error': f'Catchup manifest not available'})

        # Get provider's HTTP manager
        http_manager = self.manager.get_provider_http_manager(provider)
        if not http_manager:
            logger.error(f"No HTTP manager found for provider '{provider}'")
            response.status = 502
            response.content_type = 'application/json'
            return json.dumps({'error': f'Provider "{provider}" not configured properly'})

        # Fetch manifest via proxy
        try:
            logger.debug(f"Fetching catchup manifest via proxy: {manifest_url}")
            manifest_response = http_manager.get(manifest_url, operation="manifest")

            # Extract cache TTL
            ttl = MPDRewriter.extract_cache_ttl(manifest_response.headers)
            mpd_ttl = MPDRewriter.extract_mpd_update_period(manifest_response.text)
            if mpd_ttl and mpd_ttl < ttl:
                ttl = mpd_ttl

            # Rewrite MPD URLs to point to proxy
            base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
            rewriter = MPDRewriter(base_url, provider)
            rewritten_mpd = rewriter.rewrite_mpd(manifest_response.text, manifest_url)

            # Cache the rewritten MPD with catchup-specific key
            self.mpd_cache.set(
                provider=provider,
                channel_id=cache_key,  # Use catchup-specific cache key
                mpd_content=rewritten_mpd,
                ttl=ttl,
                original_url=manifest_url
            )

            response.content_type = 'application/dash+xml; charset=utf-8'
            return rewritten_mpd

        except Exception as fetch_err:
            logger.error(f"Failed to fetch catchup manifest via proxy: {fetch_err}")
            response.status = 502
            response.content_type = 'application/json'
            return json.dumps({'error': f'Failed to fetch manifest: {str(fetch_err)}'})

    @staticmethod
    def _get_settings_manager():
        """Simple helper to get SettingsManager"""
        try:
            from streaming_providers.base.settings.settings_manager import SettingsManager
            return SettingsManager()
        except ImportError:
            # Try alternative path
            try:
                from base.settings.settings_manager import SettingsManager
                return SettingsManager()
            except ImportError as e:
                logger.error(f"Cannot import SettingsManager: {e}")
                # Re-raise with a clearer message
                raise ImportError(
                    f"SettingsManager not available. Ensure streaming_providers module is installed. Error: {e}")

    def setup_routes(self):
        @self.app.route('/api/providers')
        def list_providers():
            try:
                provider_names = self.manager.list_providers()
                default_country = self._get_setting('default_country', 'DE')

                providers_details = []
                for provider_name in provider_names:
                    provider_instance = self.manager.get_provider(provider_name)
                    if provider_instance:
                        provider_label = getattr(provider_instance, 'provider_label', provider_name)
                        country = getattr(provider_instance, 'country', default_country)
                        provider_logo = getattr(provider_instance, 'provider_logo', '')

                        # Get authentication properties
                        supported_auth_types = getattr(provider_instance, 'supported_auth_types', [])
                        preferred_auth_type = getattr(provider_instance, 'preferred_auth_type', 'unknown')
                        requires_stored_credentials = getattr(
                            provider_instance, 'requires_stored_credentials', False
                        )

                        # Check specific auth type needs
                        needs_user_creds = 'user_credentials' in supported_auth_types
                        needs_client_creds = 'client_credentials' in supported_auth_types
                        is_network_based = 'network_based' in supported_auth_types
                        is_anonymous = 'anonymous' in supported_auth_types
                        uses_device_reg = 'device_registration' in supported_auth_types
                        uses_embedded = 'embedded_client' in supported_auth_types

                        providers_details.append({
                            'name': provider_name,
                            'label': provider_label,
                            'logo': provider_logo,
                            'country': country,

                            # Core authentication properties
                            'auth': {
                                'supported_auth_types': supported_auth_types,
                                'preferred_auth_type': preferred_auth_type,
                                'requires_stored_credentials': requires_stored_credentials,

                                # Specific auth type flags for easy UI decisions
                                'needs_user_credentials': needs_user_creds,
                                'needs_client_credentials': needs_client_creds,
                                'is_network_based': is_network_based,
                                'is_anonymous': is_anonymous,
                                'uses_device_registration': uses_device_reg,
                                'uses_embedded_client': uses_embedded,

                                # Derived summary for UI
                                'needs_user_input': needs_user_creds or uses_device_reg,
                                'needs_configuration': needs_user_creds or needs_client_creds,
                                'is_automatic': is_network_based or is_anonymous or uses_embedded,
                            },

                            # Token properties
                            'primary_token_scope': getattr(provider_instance, 'primary_token_scope', None),
                            'token_scopes': getattr(provider_instance, 'token_scopes', []),
                        })

                return {
                    'providers': providers_details,
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

                # Get provider instance to check catchup support
                provider_instance = self.manager.get_provider(provider)
                provider_catchup_hours = getattr(provider_instance, 'catchup_window', 0)  # CHANGE

                # Build channel list with catchup info
                channels_data = []
                for c in channels:
                    channel_dict = c.to_dict()

                    # Add catchup hours - use channel-specific if available, else provider default
                    if hasattr(c, 'catchup_hours'):  # CHANGE
                        channel_dict['CatchupHours'] = c.catchup_hours  # CHANGE
                    else:
                        channel_dict['CatchupHours'] = provider_catchup_hours  # CHANGE

                    channels_data.append(channel_dict)

                return {
                    'provider': provider,
                    'country': provider_instance.country if provider_instance else 'DE',
                    'catchup_window_hours': provider_catchup_hours,  # CHANGE
                    'channels': channels_data
                }
            except Exception as api_err:
                logger.error(f"API Error in /api/providers/{provider}: {str(api_err)}")
                response.status = 500
                return {'error': str(api_err)}

        @self.app.route('/api/providers/<provider>/channels/<channel_id>/manifest')
        def get_channel_manifest(provider, channel_id):
            """
            Get channel manifest. Always returns JSON with manifest_url pointing to stream endpoint.
            """
            try:
                # Build the stream URL (which will handle both proxy and non-proxy)
                base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"
                stream_url = f"{base_url}/api/providers/{provider}/channels/{channel_id}/stream"

                # Add country parameter if provided
                country = request.query.get('country')
                if country:
                    stream_url += f"?country={country}"

                return {
                    'provider': provider,
                    'channel_id': channel_id,
                    'manifest_url': stream_url  # Always point to /stream endpoint
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
            Supports both live and catchup streaming.
            """
            try:
                # Get optional catchup parameters
                start_time = request.query.get('start_time')
                end_time = request.query.get('end_time')
                epg_id = request.query.get('epg_id')
                country = request.query.get('country')

                # Determine if this is a catchup request
                is_catchup = bool(start_time and end_time)

                if is_catchup:
                    logger.info(f"Catchup stream request for {provider}/{channel_id}: "
                                f"start={start_time}, end={end_time}, epg_id={epg_id}")

                    # Convert Unix timestamps to integers
                    try:
                        start_time_int = int(start_time)
                        end_time_int = int(end_time)
                    except (ValueError, TypeError):
                        response.status = 400
                        return {'error': 'Invalid start_time or end_time format'}

                    # Validate catchup is supported
                    provider_instance = self.manager.get_provider(provider)
                    catchup_hours = getattr(provider_instance, 'catchup_window', 0)  # Now in hours

                    if catchup_hours == 0:
                        response.status = 400
                        return {'error': f'Catchup not supported for provider "{provider}"'}

                    # Validate time is within catchup window (in HOURS)
                    import time
                    now = int(time.time())
                    max_age_seconds = catchup_hours * 3600  # Hours to seconds

                    if (now - start_time_int) > max_age_seconds:
                        response.status = 400
                        return {'error': f'Content outside catchup window (max {catchup_hours} hours)'}

                    # Check if provider needs proxy for catchup
                    if self.manager.needs_proxy(provider):
                        # Proxy mode: return rewritten MPD content directly
                        return self._get_proxied_catchup_manifest(
                            provider, channel_id, start_time_int, end_time_int, epg_id, country
                        )
                    else:
                        # Direct mode: get catchup manifest URL and redirect
                        manifest_url = self.manager.get_catchup_manifest(
                            provider_name=provider,
                            channel_id=channel_id,
                            start_time=start_time_int,
                            end_time=end_time_int,
                            epg_id=epg_id,
                            country=country
                        )

                        if not manifest_url:
                            response.status = 404
                            return {'error': f'Catchup manifest not available for channel "{channel_id}"'}

                        logger.debug(f"Redirecting to catchup manifest: {manifest_url}")
                        redirect(manifest_url)
                else:
                    # Live stream - existing logic
                    if self.manager.needs_proxy(provider):
                        return self._get_proxied_manifest(provider, channel_id)
                    else:
                        manifest_url = self.manager.get_channel_manifest(
                            provider_name=provider,
                            channel_id=channel_id,
                            country=country
                        )

                        if not manifest_url:
                            response.status = 404
                            return {'error': f'Manifest not available for channel "{channel_id}"'}

                        logger.debug(f"Redirecting to manifest: {manifest_url}")
                        redirect(manifest_url)

            except HTTPResponse:
                raise
            except ValueError as val_err:
                logger.error(f"API Error in stream: {str(val_err)}")
                response.status = 404
                return {'error': str(val_err)}
            except Exception as api_err:
                logger.error(f"API Error in stream: {str(api_err)}")
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
                # Parse optional parameters
                kwargs = {'country': request.query.get('country')}

                from datetime import timezone
                # Handle start_time - can be Unix timestamp (from Kodi) or datetime
                if request.query.get('start_time'):
                    start_time_str = request.query.get('start_time')
                    try:
                        # Try to parse as Unix timestamp (integer from Kodi PVR)
                        start_time_int = int(start_time_str)
                        kwargs['start_time'] = datetime.fromtimestamp(start_time_int, tz=timezone.utc)
                    except (ValueError, TypeError):
                        # Try to parse as ISO format string (for manual API calls)
                        try:
                            kwargs['start_time'] = datetime.fromisoformat(
                                start_time_str.replace('Z', '+00:00')
                            )
                        except ValueError:
                            logger.warning(f"Invalid start_time format: {start_time_str}")
                            # Continue without start_time filter
                            pass

                # Handle end_time - can be Unix timestamp or datetime
                if request.query.get('end_time'):
                    end_time_str = request.query.get('end_time')
                    try:
                        # Try to parse as Unix timestamp (integer from Kodi PVR)
                        end_time_int = int(end_time_str)
                        kwargs['end_time'] = datetime.fromtimestamp(end_time_int, tz=timezone.utc)
                    except (ValueError, TypeError):
                        # Try to parse as ISO format string (for manual API calls)
                        try:
                            kwargs['end_time'] = datetime.fromisoformat(
                                end_time_str.replace('Z', '+00:00')
                            )
                        except ValueError:
                            logger.warning(f"Invalid end_time format: {end_time_str}")
                            # Continue without end_time filter
                            pass

                # Get EPG data from manager
                epg_data = self.manager.get_channel_epg(
                    provider_name=provider,
                    channel_id=channel_id,
                    **kwargs
                )

                # Return as JSON
                response.content_type = 'application/json; charset=utf-8'
                return {
                    'provider': provider,
                    'channel_id': channel_id,
                    'epg': epg_data
                }

            except ValueError as val_err:
                # This handles the case where manager raises ValueError for unknown provider
                logger.error(f"API Error in /api/providers/{provider}/channels/{channel_id}/epg: {str(val_err)}")
                response.status = 404
                response.content_type = 'application/json; charset=utf-8'
                return {'error': str(val_err)}
            except Exception as api_err:
                logger.error(f"API Error in /api/providers/{provider}/channels/{channel_id}/epg: {str(api_err)}")
                response.status = 500
                response.content_type = 'application/json; charset=utf-8'
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
                # Get optional catchup parameters
                start_time = request.query.get('start_time')
                end_time = request.query.get('end_time')
                epg_id = request.query.get('epg_id')
                country = request.query.get('country')

                # Determine if this is a catchup request
                is_catchup = bool(start_time and end_time)

                if is_catchup:
                    logger.debug(f"Catchup DRM request for {provider}/{channel_id}: "
                                 f"epg_id={epg_id}")

                    # Convert timestamps
                    try:
                        start_time_int = int(start_time)
                        end_time_int = int(end_time)
                    except (ValueError, TypeError):
                        response.status = 400
                        return {'error': 'Invalid start_time or end_time format'}

                    # Get catchup DRM configs
                    drm_configs = self.manager.get_catchup_drm_configs(
                        provider_name=provider,
                        channel_id=channel_id,
                        start_time=start_time_int,
                        end_time=end_time_int,
                        epg_id=epg_id,
                        country=country
                    )
                else:
                    # Live DRM - existing logic
                    drm_configs = self.manager.get_channel_drm_configs(
                        provider_name=provider,
                        channel_id=channel_id,
                        country=country
                    )

                # Merge all DRM configs into a single dictionary
                merged_drm_configs = {}
                for config in drm_configs:
                    if hasattr(config, 'to_dict'):
                        config_dict = config.to_dict()
                    else:
                        config_dict = config
                    merged_drm_configs.update(config_dict)

                return {
                    'provider': provider,
                    'channel_id': channel_id,
                    'is_catchup': is_catchup,
                    'drm_configs': merged_drm_configs
                }

            except ValueError as val_err:
                logger.error(f"API Error in DRM endpoint: {str(val_err)}")
                response.status = 404
                return {'error': str(val_err)}
            except Exception as api_err:
                logger.error(f"API Error in DRM endpoint: {str(api_err)}")
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

        @self.app.route('/api/providers/<provider>/auth/status')
        def get_provider_auth_status(provider):
            """Get authentication status from provider itself"""
            try:
                # Get provider instance
                provider_instance = self.manager.get_provider(provider)
                if not provider_instance:
                    response.status = 404
                    return {'error': f'Provider {provider} not found'}

                # Get SettingsManager
                settings_manager = self._get_settings_manager()
                if not settings_manager:
                    response.status = 500
                    return {'error': 'Settings manager not available'}

                # Import and use new auth system
                from streaming_providers.base.provider.auth_context import AuthContext

                try:
                    auth_context = AuthContext(settings_manager)
                    auth_status = provider_instance.get_auth_status(auth_context)
                    return auth_status.to_dict()
                except AttributeError as attr_err:
                    logger.error(f"Provider {provider} missing required auth property: {attr_err}")
                    response.status = 501  # Not Implemented
                    return {
                        'error': f'Provider {provider} does not fully implement auth status',
                        'details': str(attr_err)
                    }
                except Exception as e:
                    logger.error(f"Error getting auth status: {e}", exc_info=True)
                    response.status = 500
                    return {'error': str(e)}

            except ImportError as import_error:
                # This happens during development if modules not created yet
                logger.warning(f"Auth modules not available: {import_error}")
                return {
                    'provider': provider,
                    'auth_state': 'not_implemented',
                    'is_ready': False,
                    'message': 'New auth system in development'
                }
            except Exception as e:
                logger.error(f"Error getting auth status for {provider}: {e}", exc_info=True)
                response.status = 500
                return {'error': f'Internal server error: {str(e)}'}

        @self.app.route('/api/providers/<provider>/credentials', method='GET')
        def get_provider_credentials(provider):
            """
            GET: Retrieve current credentials (masked for security)

            Example: GET /api/providers/joyn/credentials
            Returns: {
                "has_credentials": true,
                "credential_type": "user_password",
                "username_masked": "us***@example.com",
                "username": "user@example.com"  # Note: only included for pre-fill with user consent
            }
            """
            try:
                settings_manager = self._get_settings_manager()

                # Parse provider and country
                provider_name, country = settings_manager.parse_provider_country(provider)

                # Get credentials
                credentials = settings_manager.get_provider_credentials(provider_name, country)

                response_data = {
                    'provider': provider,
                    'has_credentials': credentials is not None,
                    'credential_type': None,
                    'username_masked': None,
                    'username': None  # We'll include this only if user explicitly allows
                }

                if credentials:
                    response_data['credential_type'] = credentials.credential_type
                    response_data['is_valid'] = credentials.validate()

                    # Get username if it exists (for user_password credentials)
                    if hasattr(credentials, 'username') and credentials.username:
                        username = credentials.username

                        # Create masked version for display
                        if '@' in username:  # Email address
                            parts = username.split('@')
                            if len(parts[0]) > 2:
                                masked = parts[0][:2] + '***@' + parts[1]
                            else:
                                masked = '***@' + parts[1]
                        else:  # Username
                            if len(username) > 4:
                                masked = username[:2] + '***' + username[-2:]
                            else:
                                masked = '***'

                        response_data['username_masked'] = masked

                        # For pre-filling forms (security consideration - you can omit this)
                        # Only include if you trust your frontend and have HTTPS
                        response_data['username'] = username

                    # Log for debugging (remove in production)
                    logger.debug(
                        f"GET credentials for {provider}: type={credentials.credential_type}, has_username={hasattr(credentials, 'username')}")

                return response_data

            except Exception as e:
                logger.error(f"GET credentials error for {provider}: {e}", exc_info=True)
                response.status = 500
                return {'error': f'Internal server error: {str(e)}'}

        @self.app.route('/api/providers/<provider>/credentials', method='POST')
        def save_provider_credentials(provider):
            """
            Save credentials for a provider via API

            Accepts JSON body with credentials:
            - User/password: {"username": "...", "password": "..."}
            - For updates: {"password": "..."} (keep existing username)
            """
            try:
                # Parse JSON body
                try:
                    credentials_data = request.json
                    logger.debug(f"Received credentials data for {provider}: {credentials_data}")
                except Exception as json_err:
                    logger.error(f"Invalid JSON in request body: {json_err}")
                    response.status = 400
                    return {'error': 'Invalid JSON in request body'}

                if not credentials_data:
                    logger.error("No credentials data provided")
                    response.status = 400
                    return {'error': 'Request body must contain credentials data'}

                # Validate it's a dictionary
                if not isinstance(credentials_data, dict):
                    logger.error(f"Credentials data is not a dict: {type(credentials_data)}")
                    response.status = 400
                    return {'error': 'Credentials data must be a JSON object'}

                # Get settings manager
                settings_manager = self._get_settings_manager()

                # Parse provider and country
                provider_name, country = settings_manager.parse_provider_country(provider)

                # Check if we have existing credentials (for partial updates)
                existing_credentials = settings_manager.get_provider_credentials(provider_name, country)

                if existing_credentials and 'username' not in credentials_data:
                    # Partial update - keep existing username, only update password
                    if hasattr(existing_credentials, 'username'):
                        credentials_data['username'] = existing_credentials.username
                    else:
                        response.status = 400
                        return {'error': 'Cannot update - existing credentials do not have username'}

                # Save credentials
                success, message = settings_manager.save_provider_credentials_from_api(
                    provider, credentials_data
                )

                logger.info(f"Save result for {provider}: success={success}, message={message}")

                if success:
                    # Reinitialize provider to pick up new credentials
                    reinit_success = self.manager.reinitialize_provider(provider)
                    if not reinit_success:
                        logger.warning(f"Failed to reinitialize provider '{provider}' after credential change")

                    response.status = 200
                    response.content_type = 'application/json; charset=utf-8'
                    return {
                        'success': True,
                        'provider': provider,
                        'message': message,
                        'action': 'updated' if existing_credentials else 'created',
                        'reinitialized': reinit_success
                    }
                else:
                    # Determine appropriate status code
                    if 'not registered' in message.lower():
                        response.status = 404
                    elif 'invalid' in message.lower() or 'validation failed' in message.lower():
                        response.status = 400
                    else:
                        response.status = 500

                    return {'error': message}

            except Exception as api_err:
                logger.error(f"API Error in POST /api/providers/{provider}/credentials: {str(api_err)}", exc_info=True)
                response.status = 500
                return {'error': f'Internal server error: {str(api_err)}'}

        @self.app.route('/api/providers/<provider>/credentials', method='DELETE')
        def delete_provider_credentials(provider):
            """
            Delete credentials for a provider via API

            Example: DELETE /api/providers/joyn_de/credentials
            """
            try:
                settings_manager = self._get_settings_manager()
                success, message = settings_manager.delete_provider_credentials_from_api(provider)

                if success:
                    # Reinitialize provider to clear any cached authentication
                    reinit_success = self.manager.reinitialize_provider(provider)
                    if not reinit_success:
                        logger.warning(f"Failed to reinitialize provider '{provider}' after credential deletion")

                    response.status = 200
                    response.content_type = 'application/json; charset=utf-8'
                    return {
                        'success': True,
                        'provider': provider,
                        'message': message,
                        'reinitialized': reinit_success
                    }
                else:
                    # Determine appropriate status code
                    if 'not registered' in message.lower():
                        response.status = 404
                    else:
                        response.status = 500

                    return {'error': message}

            except Exception as api_err:
                logger.error(f"API Error in DELETE /api/providers/{provider}/credentials: {str(api_err)}")
                response.status = 500
                return {'error': f'Internal server error: {str(api_err)}'}

        @self.app.route('/api/providers/<provider>/proxy', method='GET')
        def get_provider_proxy(provider):
            """
            Get current proxy configuration for a provider

            Example: GET /api/providers/joyn/proxy
            """
            try:
                settings_manager = self._get_settings_manager()

                # Parse provider and country
                provider_name, country = settings_manager.parse_provider_country(provider)

                # Get proxy config
                proxy_config = settings_manager.get_provider_proxy(provider_name, country)

                if proxy_config:
                    return {
                        'success': True,
                        'provider': provider,
                        'proxy_config': proxy_config.to_dict() if hasattr(proxy_config, 'to_dict') else proxy_config
                    }
                else:
                    return {
                        'success': True,
                        'provider': provider,
                        'proxy_config': None,
                        'message': 'No proxy configuration found'
                    }

            except Exception as api_err:
                logger.error(f"API Error in GET /api/providers/{provider}/proxy: {str(api_err)}")
                response.status = 500
                return {'error': f'Internal server error: {str(api_err)}'}

        @self.app.route('/api/providers/<provider>/proxy', method='POST')
        def save_provider_proxy(provider):
            """
            Save proxy configuration for a provider via API

            Accepts JSON body with proxy configuration:
            Required: {"host": "proxy.example.com", "port": 8080}
            Optional: {
                "proxy_type": "http",  # http, https, socks4, socks5
                "username": "proxyuser",
                "password": "proxypass",
                "timeout": 30,
                "verify_ssl": true,
                "scope": {
                    "api_calls": true,
                    "authentication": true,
                    "manifests": true,
                    "license": true,
                    "all": true
                }
            }

            Example: POST /api/providers/joyn_de/proxy
            Body: {"host": "proxy.example.com", "port": 8080}
            """
            try:
                # Parse JSON body
                try:
                    proxy_data = request.json
                except Exception as json_err:
                    logger.error(f"Invalid JSON in request body: {json_err}")
                    response.status = 400
                    return {'error': 'Invalid JSON in request body'}

                if not proxy_data:
                    response.status = 400
                    return {'error': 'Request body must contain proxy configuration'}

                # Validate it's a dictionary
                if not isinstance(proxy_data, dict):
                    response.status = 400
                    return {'error': 'Proxy data must be a JSON object'}

                settings_manager = self._get_settings_manager()
                success, message = settings_manager.save_provider_proxy_from_api(
                    provider, proxy_data
                )

                if success:
                    # Reinitialize provider to pick up new proxy configuration
                    reinit_success = self.manager.reinitialize_provider(provider)
                    if not reinit_success:
                        logger.warning(f"Failed to reinitialize provider '{provider}' after proxy change")

                    response.status = 200
                    response.content_type = 'application/json; charset=utf-8'
                    return {
                        'success': True,
                        'provider': provider,
                        'message': message,
                        'reinitialized': reinit_success
                    }
                else:
                    # Determine appropriate status code
                    if 'not registered' in message.lower():
                        response.status = 404
                    elif 'invalid' in message.lower() or 'validation failed' in message.lower():
                        response.status = 400
                    else:
                        response.status = 500

                    return {'error': message}

            except Exception as api_err:
                logger.error(f"API Error in POST /api/providers/{provider}/proxy: {str(api_err)}")
                response.status = 500
                return {'error': f'Internal server error: {str(api_err)}'}

        @self.app.route('/api/providers/<provider>/proxy', method='DELETE')
        def delete_provider_proxy(provider):
            """
            Delete proxy configuration for a provider via API

            Example: DELETE /api/providers/joyn_de/proxy
            """
            try:
                settings_manager = self._get_settings_manager()
                success, message = settings_manager.delete_provider_proxy_from_api(provider)

                if success:
                    # Reinitialize provider to remove proxy configuration
                    reinit_success = self.manager.reinitialize_provider(provider)  # Changed: self.manager
                    if not reinit_success:
                        logger.warning(f"Failed to reinitialize provider '{provider}' after proxy deletion")

                    response.status = 200
                    response.content_type = 'application/json; charset=utf-8'
                    return {
                        'success': True,
                        'provider': provider,
                        'message': message,
                        'reinitialized': reinit_success
                    }
                else:
                    # Determine appropriate status code
                    if 'not registered' in message.lower():
                        response.status = 404
                    else:
                        response.status = 500

                    return {'error': message}

            except Exception as api_err:
                logger.error(f"API Error in DELETE /api/providers/{provider}/proxy: {str(api_err)}")
                response.status = 500
                return {'error': f'Internal server error: {str(api_err)}'}

        @self.app.route('/api/providers/<provider>/reinitialize', method='POST')
        def reinitialize_provider(provider):
            """
            Manually reinitialize a provider (e.g., after external configuration changes)

            Example: POST /api/providers/joyn_de/reinitialize
            """
            try:
                success = self.manager.reinitialize_provider(provider)  # self.manager

                if success:
                    return {
                        'success': True,
                        'provider': provider,
                        'message': f'Provider {provider} reinitialized successfully'
                    }
                else:
                    response.status = 500
                    return {
                        'success': False,
                        'provider': provider,
                        'message': f'Failed to reinitialize provider {provider}'
                    }

            except Exception as e:
                logger.error(f"Error reinitializing provider {provider}: {e}")
                response.status = 500
                return {'error': f'Internal server error: {str(e)}'}

        # Add to service.py setup_routes()

        @self.app.route('/api/providers/enabled', method='GET')
        def get_all_enabled_status():
            """Get enabled status for all providers"""
            try:
                manager = self.manager  # ProviderManager
                enable_manager = ProviderEnableManager()  # Our new class

                all_providers = manager.list_providers()
                result = {}

                for provider in all_providers:
                    # Get current status (following precedence)
                    status = enable_manager.is_provider_enabled(provider)

                    # Get source information
                    source = enable_manager.get_enabled_source(provider)

                    result[provider] = {
                        'enabled': status,
                        'source': source,  # 'kodi', 'file', or 'default'
                        'can_modify': source != 'kodi'  # Can't modify if set in Kodi
                    }

                return {
                    'success': True,
                    'providers': result,
                    'count': len(result)
                }

            except Exception as e:
                logger.error(f"Error getting enabled status: {e}")
                response.status = 500
                return {'error': str(e)}

        @self.app.route('/api/providers/<provider>/enabled', method='GET')
        def get_provider_enabled(provider):
            """Get enabled status for specific provider"""
            try:
                # Validate provider exists
                if not self.manager.get_provider(provider):
                    response.status = 404
                    return {'error': f'Provider {provider} not found'}

                enable_manager = ProviderEnableManager()
                status = enable_manager.is_provider_enabled(provider)
                source = enable_manager.get_enabled_source(provider)

                return {
                    'success': True,
                    'provider': provider,
                    'enabled': status,
                    'source': source,
                    'can_modify': source != 'kodi'
                }

            except Exception as e:
                logger.error(f"Error getting enabled status for {provider}: {e}")
                response.status = 500
                return {'error': str(e)}

        @self.app.route('/api/providers/<provider>/enabled', method='POST')
        def set_provider_enabled(provider):
            """Set enabled status for provider (writes to file only)"""
            try:
                # Validate provider exists
                if not self.manager.get_provider(provider):
                    response.status = 404
                    return {'error': f'Provider {provider} not found'}

                # Parse request
                try:
                    data = request.json
                    if not data or 'enabled' not in data:
                        response.status = 400
                        return {'error': 'Missing "enabled" field'}

                    enabled = bool(data['enabled'])
                except ValueError:
                    response.status = 400
                    return {'error': 'Invalid JSON'}

                # Check if controlled by Kodi
                enable_manager = ProviderEnableManager()
                source = enable_manager.get_enabled_source(provider)

                if source == 'kodi':
                    response.status = 403
                    return {
                        'error': f'Provider {provider} is controlled by Kodi settings',
                        'hint': 'Change the setting in Kodi addon settings'
                    }

                # Write to file
                success = enable_manager.set_provider_enabled(provider, enabled)

                if success:
                    return {
                        'success': True,
                        'provider': provider,
                        'enabled': enabled,
                        'source': 'file',
                        'message': f'Provider {provider} {"enabled" if enabled else "disabled"} in file'
                    }
                else:
                    response.status = 500
                    return {'error': 'Failed to save setting'}

            except Exception as e:
                logger.error(f"Error setting enabled status for {provider}: {e}")
                response.status = 500
                return {'error': str(e)}

        @self.app.route('/api/config/export')
        def export_config():
            """Export all configurations as JSON"""
            try:
                settings_manager = self._get_settings_manager()

                # Use SettingsManager's export method
                export_path = settings_manager.export_all_settings()

                # Read the exported file
                with open(export_path, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)

                response.content_type = 'application/json'
                response.headers['Content-Disposition'] = f'attachment; filename="{os.path.basename(export_path)}"'
                return json.dumps(config_data, indent=2)

            except Exception as e:
                logger.error(f"Error exporting config: {e}")
                response.status = 500
                return {'error': str(e)}

        @self.app.route('/api/config/import', method='POST')
        def import_config():
            """Import configurations from JSON"""
            try:
                import_data = request.json
            except ValueError:
                response.status = 400
                return {'error': 'Invalid JSON format'}

            if not import_data:
                response.status = 400
                return {'error': 'No data provided'}

            # Validate it's a dict
            if not isinstance(import_data, dict):
                response.status = 400
                return {'error': 'Import data must be a JSON object'}

            # Create temp file
            try:
                import tempfile
                import uuid
                import json

                temp_dir = tempfile.gettempdir()
                temp_file = os.path.join(temp_dir, f'import_{uuid.uuid4()}.json')

                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(import_data, f)
            except (IOError, OSError, PermissionError) as file_err:
                logger.error(f"Failed to create temp file: {file_err}")
                response.status = 500
                return {'error': 'Failed to process import file'}

            imported_count = 0
            try:
                # Use SettingsManager to import
                settings_manager = self._get_settings_manager()

                # Import credentials
                credentials = import_data.get('providers', {})

                for provider_name, provider_data in credentials.items():
                    # Validate provider data
                    if not isinstance(provider_data, dict):
                        logger.warning(f"Skipping invalid provider data for {provider_name}")
                        continue

                    # Extract credential data if available
                    if 'credentials' in provider_data:
                        cred_data = provider_data['credentials']
                        if isinstance(cred_data, dict):
                            success, message = settings_manager.save_provider_credentials_from_api(
                                provider_name, cred_data
                            )
                            if success:
                                imported_count += 1
                                logger.info(f"Imported credentials for {provider_name}")
                            else:
                                logger.warning(f"Failed to import credentials for {provider_name}: {message}")

                    # Import proxy data if available
                    if 'proxy' in provider_data:
                        proxy_data = provider_data['proxy']
                        if isinstance(proxy_data, dict):
                            success, message = settings_manager.save_provider_proxy_from_api(
                                provider_name, proxy_data
                            )
                            if success:
                                imported_count += 1
                                logger.info(f"Imported proxy for {provider_name}")
                            else:
                                logger.warning(f"Failed to import proxy for {provider_name}: {message}")

            except Exception as process_err:
                logger.error(f"Error during import processing: {process_err}", exc_info=True)
                response.status = 500
                return {'error': f'Import failed: {str(process_err)}'}

            finally:
                # Always try to clean up temp file
                try:
                    if os.path.exists(temp_file):
                        os.remove(temp_file)
                except (FileNotFoundError, PermissionError, OSError) as cleanup_err:
                    logger.debug(f"Could not remove temp file {temp_file}: {cleanup_err}")

            return {
                'success': True,
                'imported': imported_count,
                'message': f'Imported {imported_count} configurations'
            }

        @self.app.route('/api/config/epg', method='GET')
        def get_epg_config():
            """Get current EPG configuration"""
            try:
                # Use the already imported get_environment_manager
                env_mgr = get_environment_manager()

                config = {
                    'epg_url': env_mgr.get_config('epg_url', ''),
                    'epg_cache_ttl': env_mgr.get_config('epg_cache_ttl', 86400),
                    'source': 'config.json' if env_mgr.get_config('epg_url') else 'default'
                }

                # Also check environment variable for reference
                import os
                env_epg_url = os.environ.get('ULTIMATE_EPG_URL')
                if env_epg_url:
                    config['environment_variable'] = env_epg_url

                return {
                    'success': True,
                    'config': config,
                    'epg_manager_status': 'initialized' if hasattr(self, 'epg_manager') else 'not_initialized'
                }
            except Exception as e:
                logger.error(f"API Error in /api/config/epg: {str(e)}")
                response.status = 500
                return {'error': f'Internal server error: {str(e)}'}

        @self.app.route('/api/config/epg', method='POST')
        def set_epg_config():
            """Set EPG configuration"""
            try:
                # Parse JSON body
                try:
                    epg_data = request.json
                except Exception as json_err:
                    logger.error(f"Invalid JSON in request body: {json_err}")
                    response.status = 400
                    return {'error': 'Invalid JSON in request body'}

                if not epg_data:
                    response.status = 400
                    return {'error': 'Request body must contain EPG configuration'}

                # Validate it's a dictionary
                if not isinstance(epg_data, dict):
                    response.status = 400
                    return {'error': 'EPG data must be a JSON object'}

                # Validate URL format
                epg_url = epg_data.get('epg_url', '').strip()
                if epg_url:
                    # Basic URL validation
                    if not (epg_url.startswith('http://') or epg_url.startswith('https://')):
                        response.status = 400
                        return {'error': 'EPG URL must start with http:// or https://'}

                    # Validate it's an XML/GZ file
                    if not (epg_url.endswith('.xml') or epg_url.endswith('.xml.gz') or epg_url.endswith('.gz')):
                        logger.warning(f"EPG URL doesn't end with .xml or .gz: {epg_url}")

                # Use environment manager
                env_mgr = get_environment_manager()

                # Get current config
                import os
                import json
                profile_path = env_mgr.get_config('profile_path', '')
                config_file = os.path.join(profile_path, 'config.json')
                config_data = {}

                if os.path.exists(config_file):
                    try:
                        with open(config_file, 'r', encoding='utf-8') as f:
                            config_data = json.load(f)
                    except Exception as e:
                        logger.error(f"Error reading config.json: {e}")
                        config_data = {}

                # Update with new values
                config_data['epg_url'] = epg_url

                # Optional: EPG cache TTL
                if 'epg_cache_ttl' in epg_data:
                    try:
                        ttl = int(epg_data['epg_cache_ttl'])
                        if ttl > 0:
                            config_data['epg_cache_ttl'] = ttl
                    except ValueError:
                        pass

                # Save back to config.json
                try:
                    with open(config_file, 'w', encoding='utf-8') as f:
                        json.dump(config_data, f, indent=2, ensure_ascii=False)

                    # Update environment manager cache
                    env_mgr.set_config('epg_url', epg_url)
                    if 'epg_cache_ttl' in config_data:
                        env_mgr.set_config('epg_cache_ttl', config_data['epg_cache_ttl'])

                    logger.info(f"Updated EPG configuration: URL={epg_url}")

                    return {
                        'success': True,
                        'message': 'EPG configuration updated successfully',
                        'config': {
                            'epg_url': epg_url,
                            'epg_cache_ttl': config_data.get('epg_cache_ttl', 86400)
                        }
                    }

                except Exception as e:
                    logger.error(f"Error writing config.json: {e}")
                    response.status = 500
                    return {'error': f'Failed to save configuration: {str(e)}'}

            except Exception as e:
                logger.error(f"API Error in POST /api/config/epg: {str(e)}")
                response.status = 500
                return {'error': f'Internal server error: {str(e)}'}

        @self.app.route('/api/config/epg/clear-cache', method='POST')
        def clear_epg_cache():
            """Clear EPG cache"""
            try:
                if hasattr(self, 'epg_manager') and self.epg_manager:
                    success = self.epg_manager.clear_cache()
                    if success:
                        return {'success': True, 'message': 'EPG cache cleared'}
                    else:
                        response.status = 500
                        return {'error': 'Failed to clear EPG cache'}
                else:
                    response.status = 404
                    return {'error': 'EPG manager not initialized'}
            except Exception as e:
                logger.error(f"API Error clearing EPG cache: {str(e)}")
                response.status = 500
                return {'error': f'Internal server error: {str(e)}'}

        @self.app.route('/api/config/epg/cache-info', method='GET')
        def get_epg_cache_info():
            """Get EPG cache information"""
            try:
                if hasattr(self, 'epg_manager') and self.epg_manager:
                    cache_info = self.epg_manager.get_cache_info()
                    mapping_stats = self.epg_manager.get_mapping_stats()

                    return {
                        'success': True,
                        'cache_info': cache_info,
                        'mapping_stats': mapping_stats
                    }
                else:
                    response.status = 404
                    return {'error': 'EPG manager not initialized'}
            except Exception as e:
                logger.error(f"API Error getting EPG cache info: {str(e)}")
                response.status = 500
                return {'error': f'Internal server error: {str(e)}'}

        @self.app.route('/config')
        def serve_config_ui():
            """Serve the web configuration interface"""
            response.content_type = 'text/html; charset=utf-8'
            return self.config_html

        @self.app.route("/api/epg/status", method='GET')
        def get_epg_status():
            """Get EPG configuration and cache status"""
            try:
                result = {
                    "configured": bool(self.epg_url) and self.epg_url != "https://example.com/epg.xml.gz",
                    "epg_url": self.epg_url if self.epg_url else "Not configured",
                    "cache_valid": False,
                    "cache_path": None,
                    "channel_count": 0,
                    "environment_used": False
                }

                # Check if we used the environment variable
                import os
                env_url = os.environ.get('ULTIMATE_EPG_URL')
                if env_url and env_url == self.epg_url:
                    result["environment_used"] = True

                if result["configured"] and hasattr(self, 'epg_manager') and self.epg_manager:
                    try:
                        cache = self.epg_manager.cache
                        xml_path = cache.get_cached_file_path()

                        if xml_path:
                            result["cache_valid"] = True
                            result["cache_path"] = xml_path

                            # Try to count channels
                            import xml.etree.ElementTree as ET
                            import gzip

                            def open_xml_file(file_path):
                                if file_path.endswith('.gz'):
                                    return gzip.open(file_path, 'rt', encoding='utf-8')
                                else:
                                    return open(file_path, 'r', encoding='utf-8')

                            channel_ids = set()
                            try:
                                with open_xml_file(xml_path) as xml_file:
                                    context = ET.iterparse(xml_file, events=('start',))
                                    for event, elem in context:
                                        if elem.tag == 'channel':
                                            channel_id = elem.get('id')
                                            if channel_id:
                                                channel_ids.add(channel_id)
                                        elem.clear()
                                result["channel_count"] = len(channel_ids)
                            except Exception as parse_err:
                                result["parse_error"] = str(parse_err)
                    except Exception as cache_err:
                        result["cache_error"] = str(cache_err)
                else:
                    result["hint"] = "Please configure EPG URL in Advanced settings"

                return result

            except Exception as e:
                logger.error(f"Error getting EPG status: {e}")
                response.status = 500
                return {"error": str(e)}

        @self.app.route("/api/epg/xmltv-channels", method='GET')
        def get_epg_xmltv_channels():
            """Get all unique channel IDs from EPG XML file with display names"""
            try:
                # Check if EPG manager is available
                if not hasattr(self, 'epg_manager') or not self.epg_manager:
                    response.status = 404
                    return {"error": "EPG module not available"}

                # Check if we have a valid EPG URL configured
                if not self.epg_url or self.epg_url == "https://example.com/epg.xml.gz":
                    response.status = 400
                    return {
                        "error": "EPG URL not configured",
                        "hint": "Please configure a valid EPG URL in Advanced settings",
                        "current_url": self.epg_url
                    }

                # Get the cache manager from EPG manager
                cache = self.epg_manager.cache

                logger.info(f"EPG Channels: Using URL: {self.epg_url}")

                # This will download if not cached, or return cached path
                xml_path = cache.get_or_download(self.epg_url)

                if not xml_path:
                    response.status = 404
                    return {
                        "error": f"EPG file not available from {self.epg_url}",
                        "details": "Failed to download or cache EPG file.",
                        "hint": "Check if the URL is accessible and contains valid XMLTV data."
                    }

                # Parse XML to get channel IDs and display names
                import xml.etree.ElementTree as ET
                import gzip
                import os

                if not os.path.exists(xml_path):
                    response.status = 404
                    return {"error": f"EPG file does not exist at path: {xml_path}"}

                channel_ids = []
                channel_map = {}  # Map of id -> display name

                def open_xml_file(file_path):
                    if file_path.endswith('.gz'):
                        return gzip.open(file_path, 'rt', encoding='utf-8')
                    else:
                        return open(file_path, 'r', encoding='utf-8')

                logger.info(f"Parsing EPG file: {xml_path}")
                file_size = os.path.getsize(xml_path)
                logger.info(f"EPG file size: {file_size} bytes")

                with open_xml_file(xml_path) as xml_file:
                    # Use iterparse for memory efficiency
                    context = ET.iterparse(xml_file, events=('start', 'end'))

                    current_channel_id = None
                    current_display_names = []

                    for event, elem in context:
                        if event == 'start' and elem.tag == 'channel':
                            current_channel_id = elem.get('id')
                            current_display_names = []

                        elif event == 'end' and elem.tag == 'display-name':
                            if current_channel_id and elem.text:
                                current_display_names.append(elem.text.strip())

                        elif event == 'end' and elem.tag == 'channel':
                            if current_channel_id:
                                channel_ids.append(current_channel_id)
                                # Use the first display name as the primary name
                                if current_display_names:
                                    channel_map[current_channel_id] = current_display_names[0]
                                else:
                                    channel_map[current_channel_id] = current_channel_id
                                current_channel_id = None

                        # Clear element to save memory
                        if event == 'end':
                            elem.clear()

                logger.info(f"Found {len(channel_ids)} channels in EPG")

                # Sort channels for consistent output
                sorted_channels = sorted(channel_ids)

                return {
                    "channels": sorted_channels,
                    "channel_map": channel_map,  # NEW: Map of id -> display name
                    "count": len(sorted_channels),
                    "source_url": self.epg_url,
                    "cache_path": xml_path,
                    "cache_size_bytes": file_size
                }

            except ET.ParseError as parse_err:
                logger.error(f"XML parse error in EPG file: {parse_err}")
                response.status = 500
                return {
                    "error": f"Failed to parse EPG XML file: {str(parse_err)}",
                    "hint": "The EPG file may be malformed or not valid XMLTV format."
                }
            except Exception as e:
                logger.error(f"Error getting EPG channels: {e}", exc_info=True)
                response.status = 500
                return {"error": f"Failed to process EPG file: {str(e)}"}

        @self.app.route("/api/providers/<provider>/epg-mapping", method='GET')
        def get_epg_mapping(provider):
            """Get current EPG mapping for a provider"""
            try:
                from streaming_providers.base.utils.vfs import VFS
            except ImportError:
                # If VFS is not available, return empty mapping
                return {
                    "provider": provider,
                    "mapping": {},
                    "exists": False
                }

            try:
                mapping_file = f"{provider}_epg_mapping.json"
                vfs = VFS(addon_subdir="")

                if vfs.exists(mapping_file):
                    mapping_data = vfs.read_json(mapping_file)
                    if mapping_data:
                        # The file structure is:
                        # {
                        #   "_provider_name": "...",
                        #   "channel_id": {"epg_id": "...", "name": "..."}
                        # }

                        # Extract mapping (skip internal fields starting with _)
                        internal_fields = ['_provider_name', '_created_at', '_updated_at', '_version']
                        actual_mapping = {
                            k: v for k, v in mapping_data.items()
                            if k not in internal_fields
                        }

                        logger.info(f"Loaded EPG mapping for {provider}: {len(actual_mapping)} channels")
                        logger.debug(f"Sample mappings: {list(actual_mapping.items())[:3]}")

                        return {
                            "provider": provider,
                            "mapping": actual_mapping,
                            "exists": True
                        }

                # Return empty mapping if file doesn't exist
                logger.info(f"No EPG mapping file found for {provider}")
                return {
                    "provider": provider,
                    "mapping": {},
                    "exists": False
                }

            except Exception as e:
                logger.error(f"Error getting EPG mapping for {provider}: {e}", exc_info=True)
                response.status = 500
                return {"error": f"Failed to load mapping: {str(e)}"}

        @self.app.route("/api/providers/<provider>/epg-mapping", method='POST')
        def save_epg_mapping(provider):
            """Save EPG mapping for a provider"""
            try:
                from streaming_providers.base.utils.vfs import VFS
            except ImportError:
                response.status = 500
                return {"error": "VFS module not available"}

            try:
                # Get JSON data from request body using Bottle's request object
                try:
                    mapping_data = request.json.get("mapping", {}) if request.json else {}
                except Exception as json_err:
                    logger.error(f"Invalid JSON in request body: {json_err}")
                    response.status = 400
                    return {"error": "Invalid JSON in request body"}

                # Get provider label if available
                provider_label = provider
                try:
                    provider_instance = self.manager.get_provider(provider)
                    if provider_instance:
                        provider_label = getattr(provider_instance, 'provider_label', provider)
                except:
                    pass

                # Build the file structure:
                # {
                #   "_provider_name": "Provider Label",
                #   "channel_id": {"epg_id": "...", "name": "..."}
                # }
                full_mapping = {
                    "_provider_name": provider_label
                }

                # Add each mapping entry
                for channel_id, mapping_value in mapping_data.items():
                    if isinstance(mapping_value, dict):
                        # Already has structure {"epg_id": "...", "name": "..."}
                        full_mapping[channel_id] = mapping_value
                    elif isinstance(mapping_value, str):
                        # Simple string, convert to object
                        full_mapping[channel_id] = {
                            "epg_id": mapping_value,
                            "name": ""  # Name not provided
                        }

                # Save to file
                vfs = VFS(addon_subdir="")
                mapping_file = f"{provider}_epg_mapping.json"

                success = vfs.write_json(mapping_file, full_mapping)

                if success:
                    logger.info(f"Saved EPG mapping for {provider}: {len(mapping_data)} channels")

                    # Clear mapping cache if it exists
                    try:
                        from streaming_providers.base.epg.epg_mapping import EPGMapping
                        mapping_manager = EPGMapping()
                        mapping_manager.reload_mapping(provider)
                        logger.info(f"Reloaded EPG mapping cache for {provider}")
                    except ImportError:
                        logger.debug("EPGMapping not available for cache reload")
                        pass
                    except Exception as reload_err:
                        logger.warning(f"Could not reload mapping cache: {reload_err}")

                    return {
                        "success": True,
                        "message": f"Mapping saved for {provider}",
                        "channels_mapped": len(mapping_data)
                    }
                else:
                    response.status = 500
                    return {"error": "Failed to save mapping file"}

            except Exception as e:
                logger.error(f"Error saving EPG mapping for {provider}: {e}", exc_info=True)
                response.status = 500
                return {"error": f"Failed to save mapping: {str(e)}"}

        @self.app.route('/')
        def serve_root():
            """Redirect root to config page"""
            redirect('/config')

def start_service(service_instance):
    """Start the Bottle server"""
    port = service_instance.server_port
    logger.info(f"Starting server on port {port}")

    # Determine if we should run in debug mode
    debug_mode = service_instance.env_manager.get_config('debug_mode', False)

    run(service_instance.app, host='0.0.0.0', port=port, quiet=not debug_mode, debug=debug_mode)


def run_kodi_service():
    """Run service within Kodi addon context"""
    logger.info("Starting Ultimate Backend service in Kodi mode")

    try:
        import xbmc
        import xbmcaddon
    except ImportError:
        logger.error("Kodi modules not available!")
        print("ERROR: Cannot run in Kodi mode - xbmc/xbmcaddon not available")
        return

    # Give Kodi time to initialize
    time.sleep(3)

    try:
        # Create service instance
        service = UltimateService()

        # Start service in background thread
        service_thread = threading.Thread(
            target=start_service,
            args=(service,),
            name="UltimateBackendService"
        )
        service_thread.daemon = True
        service_thread.start()

        # Monitor for Kodi shutdown
        monitor = xbmc.Monitor()
        while not monitor.abortRequested():
            if monitor.waitForAbort(5):
                break

        logger.info("Service stopped (Kodi shutdown)")
    except Exception as e:
        logger.error(f"Failed to start Kodi service: {e}")
        raise


def run_standalone_service(config_dir: str = None):
    """Run service in standalone mode"""
    logger.info("Starting Ultimate Backend service in standalone mode")

    # Create service instance
    service = UltimateService(config_dir=config_dir)

    # Print startup information
    print("=" * 60)
    print("Ultimate Backend Streaming Service")
    print("=" * 60)
    print(f"Mode: Standalone")
    print(f"Port: {service.server_port}")
    print(f"Default Country: {service.default_country}")
    print(f"Config Directory: {service.vfs.base_path}")
    print(f"Log Directory: {service.env_manager.get_config('profile_path', 'N/A')}")
    print("=" * 60)
    print(f"API Endpoints:")
    print(f"  http://localhost:{service.server_port}/api/providers")
    print(f"  http://localhost:{service.server_port}/api/m3u")
    print(f"  http://localhost:{service.server_port}/api/providers/<provider>/m3u")
    print("=" * 60)
    print("Press Ctrl+C to stop the service")
    print("=" * 60)

    try:
        start_service(service)
    except KeyboardInterrupt:
        print("\nService stopped by user")
    except Exception as e:
        print(f"Error running service: {e}")
        sys.exit(1)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Ultimate Backend Streaming Service')
    parser.add_argument('--port', type=int, help='Server port (overrides config)')
    parser.add_argument('--config-dir', help='Configuration directory')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--kodi', action='store_true', help='Force Kodi mode (requires Kodi modules)')
    parser.add_argument('--standalone', action='store_true', help='Force standalone mode')

    args = parser.parse_args()

    # Get environment manager
    env_manager = get_environment_manager()

    # Apply CLI overrides
    if args.port:
        env_manager.set_config('server_port', args.port)
        logger.info(f"Port overridden via CLI: {args.port}")

    if args.debug:
        env_manager.set_config('debug_mode', True)
        logger.info("Debug mode enabled via CLI")

    # Determine execution mode
    if args.kodi:
        logger.info("Kodi mode forced by CLI argument")
        run_kodi_service()
    elif args.standalone:
        logger.info("Standalone mode forced by CLI argument")
        run_standalone_service(config_dir=args.config_dir)
    elif is_kodi_environment():
        logger.info("Kodi environment detected, running in Kodi mode")
        run_kodi_service()
    else:
        logger.info("Running in standalone mode (default)")
        run_standalone_service(config_dir=args.config_dir)