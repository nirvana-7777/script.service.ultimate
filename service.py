#!/usr/bin/env python3
import json
import os
import sys
import threading
import time
from urllib.parse import parse_qsl, urlencode

from bottle import Bottle, redirect, request, response, run

# Add lib path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
LIB_PATH = os.path.join(script_dir, "lib")
if os.path.exists(LIB_PATH):
    sys.path.insert(0, LIB_PATH)

try:
    from streaming_providers import get_configured_manager

    # Add EPG Manager import
    from streaming_providers.base.epg.epg_manager import EPGManager
    from streaming_providers.base.models import StreamingChannel
    from streaming_providers.base.settings.provider_enable_manager import (
        ProviderEnableManager,
    )
    from streaming_providers.base.utils import MPDCacheManager, MPDRewriter, logger
    from streaming_providers.base.utils.environment import (
        get_environment_manager,
        get_vfs_instance,
        is_kodi_environment,
    )
except ImportError as import_err:
    print(
        f"Ultimate Backend: Critical import failed - {str(import_err)}", file=sys.stderr
    )
    raise


class UltimateService:
    def __init__(self, config_dir: str = None):
        self.app = Bottle()

        # Get environment manager
        self.env_manager = get_environment_manager()

        # Override config directory if provided
        if config_dir:
            self.env_manager.set_config("profile_path", config_dir)

        # Get settings
        self.server_port = self.env_manager.get_config("server_port", 7777)
        self.default_country = self.env_manager.get_config("default_country", "DE")

        # Initialize manager
        try:
            self.manager = get_configured_manager()
            logger.info("Manager initialized successfully")
        except Exception as init_err:
            logger.error(f"Failed to initialize manager - {str(init_err)}")
            raise

        # Get media proxy URL from environment variable
        self.media_proxy_url = os.environ.get("MEDIA_PROXY_URL", "").strip()
        if not self.media_proxy_url:
            logger.warning(
                "MEDIA_PROXY_URL environment variable not set - media proxy features disabled"
            )
        else:
            logger.info(f"Media proxy URL: {self.media_proxy_url}")

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
        env_url = os.environ.get("ULTIMATE_EPG_URL")
        if env_url and env_url.strip() and env_url != "https://example.com/epg.xml.gz":
            logger.info(
                f"UltimateService: Using EPG URL from environment variable: {env_url}"
            )
            return env_url.strip()

        # 2. Try config.json via environment manager
        try:
            config_url = self.env_manager.get_config("epg_url")
            if (
                config_url
                and config_url.strip()
                and config_url != "https://example.com/epg.xml.gz"
            ):
                logger.info(
                    f"UltimateService: Using EPG URL from config.json: {config_url}"
                )
                return config_url.strip()
        except Exception as e:
            logger.debug(
                f"UltimateService: Could not get EPG URL from environment manager: {e}"
            )

        # 3. Try Kodi addon setting
        try:
            if is_kodi_environment():
                import xbmcaddon

                addon = xbmcaddon.Addon()
                kodi_url = addon.getSetting("epg_xml_url")
                if (
                    kodi_url
                    and kodi_url.strip()
                    and kodi_url != "https://example.com/epg.xml.gz"
                ):
                    logger.info(
                        f"UltimateService: Using EPG URL from Kodi settings: {kodi_url}"
                    )
                    return kodi_url.strip()
        except Exception as e:
            logger.debug(
                f"UltimateService: Could not get EPG URL from Kodi settings: {e}"
            )

        # 4. Default fallback
        default_url = "https://example.com/epg.xml.gz"
        logger.warning(
            f"UltimateService: No valid EPG URL found, using default: {default_url}"
        )
        logger.warning("Please set ULTIMATE_EPG_URL environment variable!")
        return default_url

    def _load_config_html(self):
        """Load the web interface HTML template with embedded CSS and JS"""
        base_dir = os.path.dirname(os.path.abspath(__file__))
        web_dir = os.path.join(base_dir, "resources", "web")

        # Define file paths
        html_path = os.path.join(web_dir, "config.html")
        css_path = os.path.join(web_dir, "config.css")
        js_path = os.path.join(web_dir, "config.js")

        # Proxy files
        proxy_css_path = os.path.join(web_dir, "proxy.css")
        proxy_js_path = os.path.join(web_dir, "proxy.js")

        # EPG mapping files
        epg_css_path = os.path.join(web_dir, "epg_mapping.css")
        epg_js_path = os.path.join(web_dir, "epg_mapping.js")
        fuzzyset_path = os.path.join(web_dir, "lib", "fuzzyset.js")
        debounce_path = os.path.join(web_dir, "lib", "debounce.js")

        # Enable/disable files
        enable_css_path = os.path.join(web_dir, "provider_enable.css")
        enable_js_path = os.path.join(web_dir, "provider_enable.js")

        try:
            # Load HTML
            with open(html_path, "r", encoding="utf-8") as f:
                html = f.read()

            # Load CSS files
            with open(css_path, "r", encoding="utf-8") as f:
                css = f.read()

            with open(proxy_css_path, "r", encoding="utf-8") as f:
                proxy_css = f.read()

            with open(epg_css_path, "r", encoding="utf-8") as f:
                epg_css = f.read()

            with open(enable_css_path, "r", encoding="utf-8") as f:
                enable_css = f.read()

            # Load JS files
            with open(js_path, "r", encoding="utf-8") as f:
                js = f.read()

            with open(proxy_js_path, "r", encoding="utf-8") as f:
                proxy_js = f.read()

            with open(epg_js_path, "r", encoding="utf-8") as f:
                epg_js = f.read()

            with open(fuzzyset_path, "r", encoding="utf-8") as f:
                fuzzyset_js = f.read()

            with open(debounce_path, "r", encoding="utf-8") as f:
                debounce_js = f.read()

            with open(enable_js_path, "r", encoding="utf-8") as f:
                enable_js = f.read()

            # Combine all CSS (correct order: base -> proxy -> epg -> enable)
            combined_css = f"{css}\n\n/* Proxy CSS */\n{proxy_css}\n\n/* EPG Mapping CSS */\n{epg_css}\n\n/* Provider Enable/Disable CSS */\n{enable_css}"

            # Combine all JS (with proper order)
            combined_js = f"""
            /* Debounce Utility */
            {debounce_js}

            /* FuzzySet Library */
            {fuzzyset_js}

            /* Main Config JS */
            {js}

            /* Proxy Management JS */
            {proxy_js}

            /* EPG Mapping JS */
            {epg_js}

            /* Provider Enable/Disable JS */
            {enable_js}
            """

            # Replace CSS in HTML
            html = html.replace(
                '<link rel="stylesheet" href="config.css">',
                f"<style>\n{combined_css}\n</style>",
            )

            # Inject JavaScript before </body> tag
            script_tag = f"<script>\n{combined_js}\n</script>"

            if '<script src="config.js"></script>' in html:
                html = html.replace('<script src="config.js"></script>', script_tag)
            else:
                html = html.replace("</body>", f"{script_tag}\n</body>")

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

    def _get_decrypted_manifest(
        self, provider: str, channel_id: str, keyids: dict
    ) -> str:
        """
        Get rewritten MPD manifest for decrypted playback via media proxy.
        Similar to _get_proxied_manifest but adds kid/key parameters.

        Args:
            provider: Provider name
            channel_id: Channel ID
            keyids: Dictionary of kid:key pairs

        Returns:
            Rewritten MPD content as string
        """
        country = request.query.get("country")

        # Note: We don't cache decrypted manifests as they contain keys
        logger.info(f"Generating decrypted manifest for {provider}/{channel_id}")

        # Get original manifest URL
        manifest_url = self.manager.get_channel_manifest(
            provider_name=provider, channel_id=channel_id, country=country
        )

        if not manifest_url:
            response.status = 404
            response.content_type = "application/json"
            return json.dumps(
                {
                    "error": f'Manifest not available for channel "{channel_id}" from provider "{provider}"'
                }
            )

        # Get provider's HTTP manager
        http_manager = self.manager.get_provider_http_manager(provider)
        if not http_manager:
            logger.error(f"No HTTP manager found for provider '{provider}'")
            response.status = 502
            response.content_type = "application/json"
            return json.dumps(
                {"error": f'Provider "{provider}" not configured properly'}
            )

        # Fetch manifest
        try:
            logger.debug(f"Fetching manifest for decryption: {manifest_url}")
            manifest_response = http_manager.get(manifest_url, operation="manifest")

            # Get provider proxy URL if configured
            provider_proxy_url = None
            if http_manager.config.proxy_config:
                proxy_cfg = http_manager.config.proxy_config
                provider_proxy_url = (
                    f"{proxy_cfg.proxy_type}://{proxy_cfg.host}:{proxy_cfg.port}"
                )
                logger.debug(f"Provider has proxy configured: {provider_proxy_url}")

            # Rewrite MPD URLs to point to media proxy decrypt endpoint with keys
            rewriter = MPDRewriter(self.media_proxy_url, provider_proxy_url, keyids)
            rewritten_mpd = rewriter.rewrite_mpd(manifest_response.text, manifest_url)

            # Return rewritten MPD
            response.content_type = "application/dash+xml; charset=utf-8"
            return rewritten_mpd

        except Exception as fetch_err:
            logger.error(f"Failed to fetch manifest for decryption: {fetch_err}")
            response.status = 502
            response.content_type = "application/json"
            return json.dumps({"error": f"Failed to fetch manifest: {str(fetch_err)}"})

    def _get_proxied_manifest(self, provider: str, channel_id: str) -> str:
        """
        Get proxied and rewritten MPD manifest for a channel using media proxy.
        Uses cache when available and valid.

        Args:
            provider: Provider name
            channel_id: Channel ID

        Returns:
            Rewritten MPD content as string
        """
        country = request.query.get("country")

        # Try cache first
        cached_mpd = self.mpd_cache.get(provider, channel_id)
        if cached_mpd:
            response.content_type = "application/dash+xml; charset=utf-8"
            return cached_mpd

        # Cache miss - fetch and rewrite
        logger.info(f"Cache miss for {provider}/{channel_id}, fetching manifest")

        # Check if media proxy is configured
        if not self.media_proxy_url:
            response.status = 503
            response.content_type = "application/json"
            return json.dumps(
                {"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"}
            )

        # Get original manifest URL
        manifest_url = self.manager.get_channel_manifest(
            provider_name=provider, channel_id=channel_id, country=country
        )

        if not manifest_url:
            response.status = 404
            response.content_type = "application/json"
            return json.dumps(
                {
                    "error": f'Manifest not available for channel "{channel_id}" from provider "{provider}"'
                }
            )

        # Get provider's HTTP manager to fetch manifest and check proxy config
        http_manager = self.manager.get_provider_http_manager(provider)
        if not http_manager:
            logger.error(f"No HTTP manager found for provider '{provider}'")
            response.status = 502
            response.content_type = "application/json"
            return json.dumps(
                {"error": f'Provider "{provider}" not configured properly'}
            )

        # Fetch manifest via provider's HTTP manager
        try:
            logger.debug(f"Fetching manifest: {manifest_url}")
            manifest_response = http_manager.get(manifest_url, operation="manifest")

            # Extract cache TTL from response headers
            ttl = MPDRewriter.extract_cache_ttl(manifest_response.headers)

            # Also check MPD's own update period as fallback
            mpd_ttl = MPDRewriter.extract_mpd_update_period(manifest_response.text)
            if mpd_ttl and mpd_ttl < ttl:
                ttl = mpd_ttl
                logger.debug(f"Using MPD minimumUpdatePeriod as TTL: {ttl}s")

            # Get provider proxy URL if configured
            provider_proxy_url = None
            if http_manager.config.proxy_config:
                # Build proxy URL from config
                proxy_cfg = http_manager.config.proxy_config
                provider_proxy_url = (
                    f"{proxy_cfg.proxy_type}://{proxy_cfg.host}:{proxy_cfg.port}"
                )
                logger.debug(f"Provider has proxy configured: {provider_proxy_url}")

            # Rewrite MPD URLs to point to media proxy
            rewriter = MPDRewriter(self.media_proxy_url, provider_proxy_url)
            rewritten_mpd = rewriter.rewrite_mpd(manifest_response.text, manifest_url)

            # Cache the rewritten MPD
            self.mpd_cache.set(
                provider=provider,
                channel_id=channel_id,
                mpd_content=rewritten_mpd,
                ttl=ttl,
                original_url=manifest_url,
            )

            # Return rewritten MPD
            response.content_type = "application/dash+xml; charset=utf-8"
            return rewritten_mpd

        except Exception as fetch_err:
            logger.error(f"Failed to fetch manifest: {fetch_err}")
            response.status = 502
            response.content_type = "application/json"
            return json.dumps({"error": f"Failed to fetch manifest: {str(fetch_err)}"})

    def _generate_m3u_content(
        self, providers=None, save_to_cache=True, cache_filename=None
    ):
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
            providers_to_process = (
                [providers] if isinstance(providers, str) else providers
            )
            cache_filename = cache_filename or f"{providers_to_process[0]}.m3u"

        for provider_name in providers_to_process:
            try:
                # Get channels for this provider
                channels = self.manager.get_channels(
                    provider_name=provider_name, fetch_manifests=False
                )

                # Add each channel to M3U
                for channel in channels:
                    m3u_content += self._generate_m3u_channel_entry(
                        base_url, provider_name, channel
                    )

            except Exception as provider_err:
                logger.warning(
                    f"Failed to get channels for provider '{provider_name}': {str(provider_err)}"
                )
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
        channel_logo = channel.logo_url or ""

        # Build stream URL
        stream_url = (
            f"{base_url}/api/providers/{provider_name}/channels/{channel_id}/stream"
        )

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
                provider_name=provider_name, channel_id=channel_id
            )

            if drm_configs:
                drm_directives = self._generate_drm_directives(drm_configs)
                entry_content += drm_directives

        except Exception as drm_err:
            logger.debug(
                f"Could not get DRM for {provider_name}/{channel_id}: {str(drm_err)}"
            )

        # Add stream URL
        entry_content += f"{stream_url}\n"

        return entry_content

    def _generate_m3u_decrypted_content(
        self, providers=None, save_to_cache=True, cache_filename=None
    ):
        """
        Internal method to generate decrypted M3U content for specified providers.
        Only includes channels with ClearKey DRM or unencrypted channels.

        Args:
            providers: List of provider names, or None for all providers
            save_to_cache: Whether to save to cache
            cache_filename: Cache filename to use

        Returns:
            M3U content as string
        """
        # Check if media proxy is configured
        if not self.media_proxy_url:
            logger.error("Cannot generate decrypted M3U: MEDIA_PROXY_URL not set")
            return None

        # Get base URL for absolute stream URLs
        base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"

        # Start M3U content
        m3u_content = "#EXTM3U\n"

        # Determine which providers to process
        if providers is None:
            # All providers
            providers_to_process = self.manager.list_providers()
            cache_filename = cache_filename or "playlist_decrypted.m3u"
        else:
            # Specific provider(s)
            providers_to_process = (
                [providers] if isinstance(providers, str) else providers
            )
            cache_filename = (
                cache_filename or f"{providers_to_process[0]}_decrypted.m3u"
            )

        channels_included = 0
        channels_skipped = 0

        for provider_name in providers_to_process:
            try:
                # Get channels for this provider
                channels = self.manager.get_channels(
                    provider_name=provider_name, fetch_manifests=False
                )

                # Get provider instance for label and proxy config
                try:
                    provider_instance = self.manager.get_provider(provider_name)
                    provider_label = provider_instance.provider_label
                except (AttributeError, KeyError, ValueError):
                    provider_label = provider_name

                # Get provider proxy URL if configured
                http_manager = self.manager.get_provider_http_manager(provider_name)
                provider_proxy_url = None
                if http_manager and http_manager.config.proxy_config:
                    proxy_cfg = http_manager.config.proxy_config
                    provider_proxy_url = (
                        f"{proxy_cfg.proxy_type}://{proxy_cfg.host}:{proxy_cfg.port}"
                    )

                # Process each channel
                for channel in channels:
                    channel_id = channel.channel_id
                    channel_name = channel.name
                    channel_logo = channel.logo_url or ""

                    # Try to get DRM configs
                    try:
                        drm_configs = self.manager.get_channel_drm_configs(
                            provider_name=provider_name, channel_id=channel_id
                        )

                        # Check if channel has ClearKey DRM
                        has_clearkey = False
                        clearkey_data = None

                        if (
                            isinstance(drm_configs, dict)
                            and "org.w3.clearkey" in drm_configs
                        ):
                            clearkey_data = drm_configs["org.w3.clearkey"]
                            has_clearkey = True
                        elif isinstance(drm_configs, list):
                            # Legacy format - convert to dict
                            for config in drm_configs:
                                if hasattr(config, "to_dict"):
                                    config_dict = config.to_dict()
                                    if "org.w3.clearkey" in config_dict:
                                        clearkey_data = config_dict["org.w3.clearkey"]
                                        has_clearkey = True
                                        break

                        if has_clearkey and clearkey_data:
                            # Channel has ClearKey - generate decrypted entry
                            entry_content = self._generate_m3u_decrypted_channel_entry(
                                base_url=base_url,
                                provider_name=provider_name,
                                provider_label=provider_label,
                                channel=channel,
                                clearkey_data=clearkey_data,
                                provider_proxy_url=provider_proxy_url,
                            )
                            m3u_content += entry_content
                            channels_included += 1
                        elif not drm_configs or (
                            isinstance(drm_configs, dict) and len(drm_configs) == 0
                        ):
                            # Unencrypted channel - include with direct stream URL
                            stream_url = f"{base_url}/api/providers/{provider_name}/channels/{channel_id}/stream"
                            m3u_content += f'#EXTINF:-1 tvg-id="{channel_id}" tvg-logo="{channel_logo}" group-title="{provider_label}",{channel_name}\n'
                            m3u_content += f"{stream_url}\n"
                            channels_included += 1
                        else:
                            # Channel has other DRM (not ClearKey) - skip
                            channels_skipped += 1
                            logger.debug(
                                f"Skipping {provider_name}/{channel_id} - no ClearKey DRM"
                            )

                    except Exception as drm_err:
                        # Could not get DRM info - skip channel
                        logger.warning(
                            f"Could not get DRM for {provider_name}/{channel_id}: {drm_err}"
                        )
                        channels_skipped += 1
                        continue

            except Exception as provider_err:
                logger.warning(
                    f"Failed to process provider '{provider_name}': {str(provider_err)}"
                )
                continue

        logger.info(
            f"Decrypted M3U: included {channels_included} channels, skipped {channels_skipped}"
        )

        # Save to cache if requested
        if save_to_cache and cache_filename:
            if self.vfs.write_text(cache_filename, m3u_content):
                logger.info(f"Decrypted M3U playlist cached to {cache_filename}")
            else:
                logger.warning(
                    f"Failed to cache decrypted M3U playlist to {cache_filename}"
                )

        return m3u_content

    def _generate_m3u_decrypted_channel_entry(
        self,
        base_url,
        provider_name,
        provider_label,
        channel,
        clearkey_data,
        provider_proxy_url,
    ):
        """
        Generate M3U entry for a ClearKey encrypted channel with decryption URL.

        Args:
            base_url: Base URL for stream endpoints
            provider_name: Name of the provider
            provider_label: Display label for the provider
            channel: StreamingChannel object
            clearkey_data: ClearKey DRM data
            provider_proxy_url: Optional provider proxy URL

        Returns:
            M3U entry as string
        """
        entry_content = ""

        channel_id = channel.channel_id
        channel_name = channel.name
        channel_logo = channel.logo_url or ""

        # Build decrypted stream URL via media proxy
        # Format: /api/providers/{provider}/channels/{channel_id}/stream/decrypted
        stream_url = f"{base_url}/api/providers/{provider_name}/channels/{channel_id}/stream/decrypted"

        # Add M3U entry with extended info
        entry_content += f'#EXTINF:-1 tvg-id="{channel_id}" tvg-logo="{channel_logo}" group-title="{provider_label}",{channel_name}\n'

        # Add KODIPROP for inputstream.adaptive (still needed for DASH playback)
        entry_content += "#KODIPROP:inputstream=inputstream.adaptive\n"

        # Add stream URL
        entry_content += f"{stream_url}\n"

        return entry_content

    def _generate_m3u_decrypted_all(self, save_to_cache: bool = False) -> str:
        """Internal method to generate decrypted M3U for all providers."""
        logger.info("Generating decrypted M3U playlist for all providers")
        m3u_content = self._generate_m3u_decrypted_content(
            providers=None, save_to_cache=save_to_cache
        )

        if m3u_content is None:
            response.status = 503
            response.content_type = "application/json"
            return json.dumps(
                {"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"}
            )

        # Set appropriate headers for M3U
        response.content_type = "audio/x-mpegurl; charset=utf-8"
        response.headers["Content-Disposition"] = (
            'attachment; filename="playlist_decrypted.m3u8"'
        )

        return m3u_content

    def _generate_m3u_decrypted_provider(
        self, provider: str, save_to_cache: bool = False
    ) -> str:
        """Internal method to generate decrypted M3U for a specific provider."""
        logger.info(f"Generating decrypted M3U playlist for provider '{provider}'")
        m3u_content = self._generate_m3u_decrypted_content(
            providers=provider, save_to_cache=save_to_cache
        )

        if m3u_content is None:
            response.status = 503
            response.content_type = "application/json"
            return json.dumps(
                {"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"}
            )

        # Set appropriate headers for M3U
        response.content_type = "audio/x-mpegurl; charset=utf-8"
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{provider}_decrypted_playlist.m3u8"'
        )

        return m3u_content

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
                    if hasattr(config, "to_dict"):
                        temp_dict.update(config.to_dict())
                    elif isinstance(config, dict):
                        temp_dict.update(config)
                drm_configs = temp_dict
            else:
                return directives

        # Rest of the method remains the same...
        # Prioritize: clearkey > widevine > playready
        selected_drm = None
        priority_order = [
            "org.w3.clearkey",
            "com.widevine.alpha",
            "com.microsoft.playready",
        ]

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

            license_info = drm_data.get("license", {})

            # Add license server URL or keyids
            if drm_system == "org.w3.clearkey" and license_info.get("keyids"):
                # ClearKey: format as kid:key,kid:key
                keyids = license_info["keyids"]
                keys_str = ",".join([f"{kid}:{key}" for kid, key in keyids.items()])
                drm_legacy_parts.append(keys_str)
            elif license_info.get("server_url"):
                # Widevine/PlayReady: add license server URL
                drm_legacy_parts.append(license_info["server_url"])

                # Add headers if present (URL-encoded)
                if license_info.get("req_headers"):
                    req_headers = self._process_license_headers(
                        license_info["req_headers"]
                    )
                    if req_headers:
                        drm_legacy_parts.append(req_headers)

            # Join parts with pipe separator
            drm_legacy = "|".join(drm_legacy_parts)
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
            if req_headers.strip().startswith("{"):
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
                        logger.warning(
                            f"Invalid query string format in headers: {val_err}"
                        )
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
        m3u_content = self._generate_m3u_content(
            providers=None, save_to_cache=save_to_cache
        )

        # Set appropriate headers for M3U
        response.content_type = "audio/x-mpegurl; charset=utf-8"
        response.headers["Content-Disposition"] = 'attachment; filename="playlist.m3u8"'

        return m3u_content

    def _generate_m3u_provider(self, provider: str, save_to_cache: bool = False) -> str:
        """Internal method to generate M3U for a specific provider."""
        logger.info(f"Generating M3U playlist for provider '{provider}'")
        m3u_content = self._generate_m3u_content(
            providers=provider, save_to_cache=save_to_cache
        )

        # Set appropriate headers for M3U
        response.content_type = "audio/x-mpegurl; charset=utf-8"
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{provider}_playlist.m3u8"'
        )

        return m3u_content

    def _get_proxied_catchup_manifest(
        self,
        provider: str,
        channel_id: str,
        start_time: int,
        end_time: int,
        epg_id: str = None,
        country: str = None,
    ) -> str:
        """
        Get proxied and rewritten MPD manifest for catchup content using media proxy.
        Similar to _get_proxied_manifest but for catchup streams.
        """
        # Generate cache key that includes time parameters
        cache_key = f"{channel_id}_catchup_{start_time}_{end_time}"

        # Try cache first (with catchup-specific key)
        cached_mpd = self.mpd_cache.get(provider, cache_key)
        if cached_mpd:
            response.content_type = "application/dash+xml; charset=utf-8"
            return cached_mpd

        logger.info(
            f"Cache miss for catchup {provider}/{channel_id}, fetching manifest"
        )

        # Check if media proxy is configured
        if not self.media_proxy_url:
            response.status = 503
            response.content_type = "application/json"
            return json.dumps(
                {"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"}
            )

        # Get catchup manifest URL
        manifest_url = self.manager.get_catchup_manifest(
            provider_name=provider,
            channel_id=channel_id,
            start_time=start_time,
            end_time=end_time,
            epg_id=epg_id,
            country=country,
        )

        if not manifest_url:
            response.status = 404
            response.content_type = "application/json"
            return json.dumps({"error": f"Catchup manifest not available"})

        # Get provider's HTTP manager
        http_manager = self.manager.get_provider_http_manager(provider)
        if not http_manager:
            logger.error(f"No HTTP manager found for provider '{provider}'")
            response.status = 502
            response.content_type = "application/json"
            return json.dumps(
                {"error": f'Provider "{provider}" not configured properly'}
            )

        # Fetch manifest
        try:
            logger.debug(f"Fetching catchup manifest: {manifest_url}")
            manifest_response = http_manager.get(manifest_url, operation="manifest")

            # Extract cache TTL
            ttl = MPDRewriter.extract_cache_ttl(manifest_response.headers)
            mpd_ttl = MPDRewriter.extract_mpd_update_period(manifest_response.text)
            if mpd_ttl and mpd_ttl < ttl:
                ttl = mpd_ttl

            # Get provider proxy URL if configured
            provider_proxy_url = None
            if http_manager.config.proxy_config:
                proxy_cfg = http_manager.config.proxy_config
                provider_proxy_url = (
                    f"{proxy_cfg.proxy_type}://{proxy_cfg.host}:{proxy_cfg.port}"
                )
                logger.debug(f"Provider has proxy configured: {provider_proxy_url}")

            # Rewrite MPD URLs to point to media proxy
            rewriter = MPDRewriter(self.media_proxy_url, provider_proxy_url)
            rewritten_mpd = rewriter.rewrite_mpd(manifest_response.text, manifest_url)

            # Cache the rewritten MPD with catchup-specific key
            self.mpd_cache.set(
                provider=provider,
                channel_id=cache_key,  # Use catchup-specific cache key
                mpd_content=rewritten_mpd,
                ttl=ttl,
                original_url=manifest_url,
            )

            response.content_type = "application/dash+xml; charset=utf-8"
            return rewritten_mpd

        except Exception as fetch_err:
            logger.error(f"Failed to fetch catchup manifest: {fetch_err}")
            response.status = 502
            response.content_type = "application/json"
            return json.dumps({"error": f"Failed to fetch manifest: {str(fetch_err)}"})

    @staticmethod
    def _get_settings_manager():
        """Simple helper to get SettingsManager"""
        try:
            from streaming_providers.base.settings.settings_manager import (
                SettingsManager,
            )

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
                    f"SettingsManager not available. Ensure streaming_providers module is installed. Error: {e}"
                )

    def setup_routes(self):
        """Setup all routes from separate modules"""
        # Import route handlers here
        from routes.providers import setup_provider_routes
        from routes.streams import setup_stream_routes
        from routes.m3u import setup_m3u_routes
        from routes.drm import setup_drm_routes
        from routes.cache import setup_cache_routes
        from routes.config import setup_config_routes
        from routes.epg import setup_epg_routes

        # Setup routes from separate modules
        setup_provider_routes(self.app, self.manager, self)
        setup_stream_routes(self.app, self.manager, self)
        setup_m3u_routes(self.app, self.manager, self)
        setup_drm_routes(self.app, self.manager, self)
        setup_cache_routes(self.app, self.manager, self)
        setup_config_routes(self.app, self.manager, self)
        setup_epg_routes(self.app, self.manager, self)

        # Core UI routes
        @self.app.route("/config")
        def serve_config_ui():
            """Serve the web configuration interface"""
            response.content_type = "text/html; charset=utf-8"
            return self.config_html

        @self.app.route("/")
        def serve_root():
            """Redirect root to config page"""
            redirect("/config")


def start_service(service_instance):
    """Start the Bottle server"""
    port = service_instance.server_port
    logger.info(f"Starting server on port {port}")

    # Determine if we should run in debug mode
    debug_mode = service_instance.env_manager.get_config("debug_mode", False)

    run(
        service_instance.app,
        host="0.0.0.0",
        port=port,
        quiet=not debug_mode,
        debug=debug_mode,
    )


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
            target=start_service, args=(service,), name="UltimateBackendService"
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


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Ultimate Backend Streaming Service")
    parser.add_argument("--port", type=int, help="Server port (overrides config)")
    parser.add_argument("--config-dir", help="Configuration directory")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument(
        "--kodi", action="store_true", help="Force Kodi mode (requires Kodi modules)"
    )
    parser.add_argument(
        "--standalone", action="store_true", help="Force standalone mode"
    )

    args = parser.parse_args()

    # Get environment manager
    env_manager = get_environment_manager()

    # Apply CLI overrides
    if args.port:
        env_manager.set_config("server_port", args.port)
        logger.info(f"Port overridden via CLI: {args.port}")

    if args.debug:
        env_manager.set_config("debug_mode", True)
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
