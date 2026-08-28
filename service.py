#!/usr/bin/env python3
import json
import math
import os
import sys
import threading
import time
from urllib.parse import parse_qsl, urlencode
from typing import Optional
import requests

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

        self._decrypted_cache = {}  # key -> (content, expiry_ts) — memory-only, never persisted

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

        # 3. Fetch EPG aliases for tvg-epgid mapping (initialize first)
        self.epg_alias_map = {}  # Initialize to empty dict as fallback
        self._fetch_epg_aliases()  # This will update self.epg_alias_map

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

    def fetch_manifest_for_rewriter(
            self,
            provider: str,
            channel_id: str,
            manifest_url: str,
    ) -> tuple:
        """
        Fetch a manifest and collect everything MPDRewriter needs.

        Returns:
            (manifest_text, ttl, provider_proxy_url, segment_headers, effective_manifest_url)
            effective_manifest_url is the post-redirect URL (may differ from manifest_url
            if the CDN issues a 302). Always use this for MPD rewriting so that relative
            segment paths are resolved against the correct base.

        Raises:
            ValueError: if the provider HTTP manager is not available
            requests.HTTPError: if the manifest fetch fails
        """
        http_manager = self.manager.get_provider_http_manager(provider)
        if not http_manager:
            raise ValueError(f'Provider "{provider}" not configured properly (no HTTP manager)')

        # Resolve manifest headers from the provider so auth tokens etc. are sent
        provider_instance = self.manager.get_provider(provider)
        manifest_headers = (
            provider_instance.get_manifest_headers(channel_id)
            if provider_instance else {}
        )
        segment_headers = (
            provider_instance.get_segment_headers(channel_id)
            if provider_instance else {}
        )

        manifest_response = http_manager.get(
            manifest_url, headers=manifest_headers, operation="manifest"
        )
        manifest_response.raise_for_status()

        # Cache TTL: prefer HTTP Cache-Control/Expires, fall back to MPD minimumUpdatePeriod
        ttl = MPDRewriter.extract_cache_ttl(manifest_response.headers)
        mpd_ttl = MPDRewriter.extract_mpd_update_period(manifest_response.text)
        if mpd_ttl and mpd_ttl < ttl:
            ttl = mpd_ttl

        # Derive provider-side proxy URL for the media proxy to use when forwarding
        provider_proxy_url = None
        if http_manager.config.proxy_config:
            proxy_cfg = http_manager.config.proxy_config
            provider_proxy_url = (
                f"{proxy_cfg.proxy_type.value.lower()}://{proxy_cfg.host}:{proxy_cfg.port}"
            )

        return manifest_response.text, ttl, provider_proxy_url, segment_headers, manifest_response.url

    def _get_decrypted_cached(self, key: str, max_stale: int = 0) -> Optional[str]:
        entry = self._decrypted_cache.get(key)
        if not entry:
            return None
        content, expiry = entry
        now = time.time()
        if now < expiry:
            return content
        if max_stale and (now - expiry) <= max_stale:
            logger.warning(f"Serving STALE decrypted manifest for {key} ({now - expiry:.1f}s past expiry)")
            return content
        del self._decrypted_cache[key]
        return None

    def _set_decrypted_cached(self, key: str, content: str, ttl: int) -> None:
        self._decrypted_cache[key] = (content, time.time() + ttl)

    @staticmethod
    def _fetch_and_cache_manifest(fetch_fn, cache_set, cache_get_stale, *,
                                   cacheable: bool, stale_window: int, label: str) -> str:
        """
        Shared fetch -> rewrite -> cache -> stale-fallback flow.

        fetch_fn()          -> (content: str, ttl: int), raises on failure
        cache_set(content, ttl) -> None
        cache_get_stale(max_stale) -> Optional[str]

        Caller is responsible for the upfront "is it already cached" check and
        manifest_url/config validation before calling this — that keeps a warm
        cache hit from paying for a manifest_url lookup it doesn't need.
        """
        try:
            content, ttl = fetch_fn()
            if cacheable:
                cache_set(content, ttl)
            response.content_type = "application/dash+xml; charset=utf-8"
            return content
        except ValueError as e:
            # Config error (e.g. no HTTP manager) — not transient, don't mask with stale cache
            logger.error(str(e))
            response.status = 502
            response.content_type = "application/json"
            return json.dumps({"error": str(e)})
        except Exception as fetch_err:
            logger.warning(f"{label} fetch failed: {fetch_err} — checking stale cache")
            if cacheable:
                stale = cache_get_stale(stale_window)
                if stale:
                    logger.warning(f"Serving stale {label} due to fetch failure")
                    response.content_type = "application/dash+xml; charset=utf-8"
                    return stale
            logger.error(f"Failed to fetch {label}: {fetch_err}")
            response.status = 502
            response.content_type = "application/json"
            return json.dumps({"error": f"Failed to fetch manifest: {str(fetch_err)}"})

    def get_proxied_manifest(self, provider: str, channel_id: str, highest_quality_only: bool = False) -> str:
        country = request.query.get("country")

        if not highest_quality_only:
            cached_mpd = self.mpd_cache.get(provider, channel_id)
            if cached_mpd:
                response.content_type = "application/dash+xml; charset=utf-8"
                return cached_mpd

        if not self.media_proxy_url:
            response.status = 503
            response.content_type = "application/json"
            return json.dumps({"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"})

        manifest_url = self.manager.get_channel_manifest(
            provider_name=provider, channel_id=channel_id, country=country
        )
        if not manifest_url:
            response.status = 404
            response.content_type = "application/json"
            return json.dumps(
                {"error": f'Manifest not available for channel "{channel_id}" from provider "{provider}"'})

        def fetch_fn():
            manifest_text, ttl, provider_proxy_url, segment_headers, effective_url = self.fetch_manifest_for_rewriter(
                provider, channel_id, manifest_url
            )
            rewriter = MPDRewriter(
                self.media_proxy_url, provider_proxy_url, None, highest_quality_only,
                provider=provider, channel=channel_id, segment_headers=segment_headers,
            )
            return rewriter.rewrite_mpd(manifest_text, effective_url), ttl

        return self._fetch_and_cache_manifest(
            fetch_fn,
            cache_set=lambda content, ttl: self.mpd_cache.set(
                provider=provider, channel_id=channel_id, mpd_content=content, ttl=ttl, original_url=manifest_url
            ),
            cache_get_stale=lambda max_stale: self.mpd_cache.get(provider, channel_id, max_stale=max_stale),
            cacheable=not highest_quality_only,
            stale_window=15,
            label=f"manifest for {provider}/{channel_id}",
        )

    def get_proxied_catchup_manifest(self, provider: str, channel_id: str, start_time: int, end_time: int,
                                      epg_id: str = None, country: str = None) -> str:
        cache_key = f"{channel_id}_catchup_{start_time}_{end_time}"

        cached_mpd = self.mpd_cache.get(provider, cache_key)
        if cached_mpd:
            response.content_type = "application/dash+xml; charset=utf-8"
            return cached_mpd

        logger.info(f"Cache miss for catchup {provider}/{channel_id}, fetching manifest")

        if not self.media_proxy_url:
            response.status = 503
            response.content_type = "application/json"
            return json.dumps({"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"})

        manifest_url = self.manager.get_catchup_manifest(
            provider_name=provider, channel_id=channel_id, start_time=start_time, end_time=end_time,
            epg_id=epg_id, country=country,
        )
        if not manifest_url:
            response.status = 404
            response.content_type = "application/json"
            return json.dumps({"error": "Catchup manifest not available"})

        def fetch_fn():
            manifest_text, ttl, provider_proxy_url, segment_headers, effective_url = self.fetch_manifest_for_rewriter(
                provider, channel_id, manifest_url
            )
            rewriter = MPDRewriter(
                self.media_proxy_url, provider_proxy_url, None, False,
                provider=provider, channel=channel_id, segment_headers=segment_headers,
            )
            return rewriter.rewrite_mpd(manifest_text, effective_url), ttl

        return self._fetch_and_cache_manifest(
            fetch_fn,
            cache_set=lambda content, ttl: self.mpd_cache.set(
                provider=provider, channel_id=cache_key, mpd_content=content, ttl=ttl, original_url=manifest_url
            ),
            cache_get_stale=lambda max_stale: self.mpd_cache.get(provider, cache_key, max_stale=max_stale),
            cacheable=True,
            stale_window=15,
            label=f"catchup manifest for {provider}/{channel_id}",
        )

    def get_decrypted_manifest(self, provider: str, channel_id: str, keyids: dict,
                                highest_quality_only: bool = False, receiver_side: bool = False,
                                drm_variant: str = "auto") -> str:
        country = request.query.get("country")
        cache_key = f"{provider}_{channel_id}_drm_{drm_variant}"

        if not highest_quality_only:
            cached_mpd = self._get_decrypted_cached(cache_key)
            if cached_mpd:
                response.content_type = "application/dash+xml; charset=utf-8"
                return cached_mpd

        if not self.media_proxy_url:
            response.status = 503
            response.content_type = "application/json"
            return json.dumps({"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"})

        logger.info(
            f"Generating {'receiver-side clearkey' if receiver_side else 'decrypted'} manifest "
            f"for {provider}/{channel_id} (highest_quality_only={highest_quality_only}, drm_variant={drm_variant})"
        )

        manifest_url = self.manager.get_channel_manifest(
            provider_name=provider, channel_id=channel_id, country=country, drm_variant=drm_variant,
        )
        if not manifest_url:
            response.status = 404
            response.content_type = "application/json"
            return json.dumps(
                {"error": f'Manifest not available for channel "{channel_id}" from provider "{provider}"'})

        def fetch_fn():
            manifest_text, ttl, provider_proxy_url, segment_headers, effective_url = self.fetch_manifest_for_rewriter(
                provider, channel_id, manifest_url
            )
            rewriter = MPDRewriter(
                self.media_proxy_url, provider_proxy_url, keyids, highest_quality_only,
                provider=provider, channel=channel_id, clearkey_receiver_side=receiver_side,
                segment_headers=segment_headers,
            )
            rewritten_mpd = rewriter.rewrite_mpd(manifest_text, effective_url)
            return rewritten_mpd, min(ttl, 10)  # holds key material — keep exposure window short

        return self._fetch_and_cache_manifest(
            fetch_fn,
            cache_set=lambda content, ttl: self._set_decrypted_cached(cache_key, content, ttl),
            cache_get_stale=lambda max_stale: self._get_decrypted_cached(cache_key, max_stale=max_stale),
            cacheable=not highest_quality_only,
            stale_window=5,
            label=f"decrypted manifest for {provider}/{channel_id}",
        )

    def get_decrypted_catchup_manifest(self, provider: str, channel_id: str, start_time: int, end_time: int,
                                        keyids: dict, epg_id: str = None,
                                        highest_quality_only: bool = False,
                                        receiver_side: bool = False) -> str:
        country = request.query.get("country")
        cache_key = f"{provider}_{channel_id}_catchup_{start_time}_{end_time}_drm"

        if not highest_quality_only:
            cached_mpd = self._get_decrypted_cached(cache_key)
            if cached_mpd:
                response.content_type = "application/dash+xml; charset=utf-8"
                return cached_mpd

        if not self.media_proxy_url:
            response.status = 503
            response.content_type = "application/json"
            return json.dumps({"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"})

        logger.info(
            f"Generating {'receiver-side clearkey' if receiver_side else 'decrypted'} catchup manifest "
            f"for {provider}/{channel_id} "
            f"(start={start_time} end={end_time} highest_quality_only={highest_quality_only})"
        )

        manifest_url = self.manager.get_catchup_manifest(
            provider_name=provider, channel_id=channel_id, start_time=start_time, end_time=end_time,
            epg_id=epg_id, country=country,
        )
        if not manifest_url:
            response.status = 404
            response.content_type = "application/json"
            return json.dumps(
                {"error": f'Catchup manifest not available for channel "{channel_id}" from provider "{provider}"'})

        def fetch_fn():
            manifest_text, ttl, provider_proxy_url, segment_headers, effective_url = self.fetch_manifest_for_rewriter(
                provider, channel_id, manifest_url
            )
            rewriter = MPDRewriter(
                self.media_proxy_url, provider_proxy_url, keyids, highest_quality_only,
                provider=provider, channel=channel_id, clearkey_receiver_side=receiver_side,
                segment_headers=segment_headers,
            )
            rewritten_mpd = rewriter.rewrite_mpd(manifest_text, effective_url)
            return rewritten_mpd, min(ttl, 30)

        return self._fetch_and_cache_manifest(
            fetch_fn,
            cache_set=lambda content, ttl: self._set_decrypted_cached(cache_key, content, ttl),
            cache_get_stale=lambda max_stale: self._get_decrypted_cached(cache_key, max_stale=max_stale),
            cacheable=not highest_quality_only,
            stale_window=10,
            label=f"decrypted catchup manifest for {provider}/{channel_id}",
        )

    @staticmethod
    def _sort_channels(channels):
        """Sort channels by channel_number ascending; channels without a number come last."""
        return sorted(
            channels,
            key=lambda ch: (ch.channel_number is None, ch.channel_number or 0)
        )

    def _fetch_epg_aliases(self) -> None:
        """
        Fetch EPG aliases from ultimate-epg service for tvg-epgid mapping.
        Updates self.epg_alias_map with mapping of channel_id -> epg_id.
        """
        api_base_url = os.environ.get("ULTIMATE_EPG_API_URL", "").strip()

        if not api_base_url:
            logger.info("ULTIMATE_EPG_API_URL not set - tvg-epgid will not be added to M3U playlists")
            self.epg_alias_map = {}
            return

        aliases_url = f"{api_base_url.rstrip('/')}/api/v1/aliases"

        try:
            resp = requests.get(aliases_url, timeout=10)
            resp.raise_for_status()

            data = resp.json()
            aliases = data.get("aliases", [])

            # Build mapping: alias -> channel_name
            alias_map = {}
            for alias_entry in aliases:
                alias = alias_entry.get("alias")
                channel_name = alias_entry.get("channel_name")
                if alias and channel_name:
                    alias_map[alias] = channel_name

            self.epg_alias_map = alias_map
            logger.info(f"Fetched {len(alias_map)} EPG aliases from {aliases_url}")

        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to fetch EPG aliases from {aliases_url}: {e}")
            self.epg_alias_map = {}
        except Exception as e:
            logger.warning(f"Unexpected error fetching EPG aliases: {e}")
            self.epg_alias_map = {}

    def _get_epg_id(self, channel_id: str) -> Optional[str]:
        """
        Get EPG ID (channel_name) for a given channel_id from alias mapping.

        Args:
            channel_id: The channel's ID (alias from ultimate-epg)

        Returns:
            EPG ID string if found, None otherwise
        """
        if not self.epg_alias_map:
            return None
        return self.epg_alias_map.get(channel_id)

    def _build_m3u_entry_header(
            self,
            provider_name,
            channel,
            *,
            provider_label=None,
            drm_directives=None,
            include_catchup=True,
    ) -> str:
        """
        Build the #EXTINF (+ optional KODIPROP) block for one channel, without
        the trailing stream URL / playback line — callers append that
        themselves via _generate_m3u_entry or their own final line (e.g. the
        ffmpeg-piped variant, which wraps the stream URL in a pipe command
        instead of using it directly).

        Single source of truth for the EXTINF/catchup-tag/chno construction
        previously duplicated across _generate_m3u_channel_entry,
        _generate_m3u_proxied_channel_entry, and inline reimplementations in
        _generate_m3u_proxied_fast, _generate_m3u_proxied_ffmpeg_fast, and
        _generate_m3u_proxied_filtered_content's unencrypted branch.

        Args:
            provider_label: Pass explicitly when the caller already resolved
                             it once per provider (avoids a redundant
                             get_provider() lookup per channel). Falls back to
                             a fresh lookup, then provider_name, if omitted.
            drm_directives: None = look up this channel's DRM configs
                             dynamically and generate directives if any exist
                             (the historical /stream/index.mpd behavior).
                             "" = skip DRM directives entirely (known
                             unencrypted content). Any other string = insert
                             as-is (e.g. a fixed
                             "#KODIPROP:inputstream=inputstream.adaptive\\n"
                             for content already known to be ClearKey/proxied,
                             avoiding a redundant DRM lookup the caller
                             already did).
            include_catchup: False suppresses catchup attributes on the
                             EXTINF line even if the channel has a catchup
                             window — used by the ffmpeg-piped variant, which
                             is intentionally live-only (existing behavior,
                             preserved rather than changed here).
        """
        channel_id = channel.channel_id
        channel_name = channel.name
        channel_logo = channel.logo_url or ""
        chno = self._chno_attr(channel)

        epg_id = self._get_epg_id(channel_id)
        epg_id_attr = f' tvg-epgid="{epg_id}"' if epg_id else ""

        if provider_label is None:
            try:
                provider_label = self.manager.get_provider(provider_name).provider_label
            except (AttributeError, KeyError, ValueError):
                provider_label = provider_name

        entry_content = ""
        catchup_window = getattr(channel, 'catchup_hours', 0) if include_catchup else 0
        if catchup_window > 0:
            catchup_type = getattr(channel, 'catchup_type', 'append')
            catchup_source = getattr(channel, 'catchup_source', '?start_time={utc}&end_time={utcend}')
            catchup_days = math.ceil(catchup_window / 24)
            entry_content += (
                f'#EXTINF:-1 tvg-id="{channel_id}"{epg_id_attr}{chno} tvg-logo="{channel_logo}" '
                f'group-title="{provider_label}" catchup="{catchup_type}" catchup-days="{catchup_days}" '
                f'catchup-source="{catchup_source}",{channel_name}\n'
            )
        else:
            entry_content += (
                f'#EXTINF:-1 tvg-id="{channel_id}"{epg_id_attr}{chno} tvg-logo="{channel_logo}" '
                f'group-title="{provider_label}",{channel_name}\n'
            )

        if drm_directives is None:
            try:
                drm_configs = self.manager.get_channel_drm_configs(
                    provider_name=provider_name, channel_id=channel_id
                )
                if drm_configs:
                    entry_content += self._generate_drm_directives(drm_configs)
            except Exception as drm_err:
                logger.debug(
                    f"Could not get DRM for {provider_name}/{channel_id}: {str(drm_err)}"
                )
        elif drm_directives:
            entry_content += drm_directives

        return entry_content

    def _generate_m3u_entry(
            self,
            base_url,
            provider_name,
            channel,
            *,
            stream_path,
            provider_label=None,
            drm_directives=None,
            include_catchup=True,
    ) -> str:
        """
        Full M3U entry (header + trailing stream URL line) for one channel.
        See _build_m3u_entry_header for the shared header-construction logic;
        this just appends the stream URL built from stream_path.

        Args:
            stream_path: Relative path (optionally with a query string) after
                         .../channels/{channel_id}/. There's only one real
                         channel stream route now — "stream/index.mpd" — so
                         callers select behavior via query params on it, e.g.
                         "stream/index.mpd?client_drm=true" or
                         "stream/index.mpd?client_drm=false&highest_quality_only=true".
                         This function doesn't parse or validate stream_path;
                         it's appended as-is.
        """
        channel_id = channel.channel_id
        header = self._build_m3u_entry_header(
            provider_name, channel,
            provider_label=provider_label,
            drm_directives=drm_directives,
            include_catchup=include_catchup,
        )
        stream_url = f"{base_url}/api/providers/{provider_name}/channels/{channel_id}/{stream_path}"
        return header + f"{stream_url}\n"

    def _generate_m3u_proxied_fast(self, providers=None):
        """
        Fast generation of decrypted M3U content for specified providers.
        Includes ALL channels with decrypted stream URLs.
        No DRM filtering, no caching - maximum speed.

        Args:
            providers: List of provider names, or None for all providers

        Returns:
            M3U content as string
        """
        # Check if media proxy is configured
        if not self.media_proxy_url:
            logger.error("Cannot generate decrypted M3U: MEDIA_PROXY_URL not set")
            response.status = 503
            response.content_type = "application/json"
            return json.dumps(
                {"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"}
            )

        # Get base URL for absolute stream URLs
        base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"

        # Start M3U content
        m3u_content = "#EXTM3U\n"

        # Determine which providers to process
        if providers is None:
            providers_to_process = self.manager.list_providers()
        else:
            providers_to_process = (
                [providers] if isinstance(providers, str) else providers
            )

        channels_included = 0

        for provider_name in providers_to_process:
            try:
                # Get channels for this provider
                channels = self._sort_channels(
                    self.manager.get_channels(provider_name=provider_name, fetch_manifests=False)
                )

                # Get provider label
                try:
                    provider_instance = self.manager.get_provider(provider_name)
                    provider_label = provider_instance.provider_label
                except (AttributeError, KeyError, ValueError):
                    provider_label = provider_name

                # Process each channel - no DRM checks (all channels are
                # already routed through the media proxy at playback time)
                for channel in channels:
                    m3u_content += self._generate_m3u_entry(
                        base_url, provider_name, channel,
                        # client_drm=false (explicit, though it's the default).
                        # No KODIPROP line needed — the client doesn't use
                        # inputstream.adaptive at all when the server does the
                        # decrypting.
                        stream_path="stream/index.mpd?client_drm=false",
                        provider_label=provider_label,
                        drm_directives="",
                    )
                    channels_included += 1

            except Exception as provider_err:
                logger.warning(
                    f"Failed to process provider '{provider_name}': {str(provider_err)}"
                )
                continue

        logger.info(f"Fast decrypted M3U: included {channels_included} channels")

        # Set appropriate headers
        response.content_type = "audio/x-mpegurl; charset=utf-8"

        if providers and isinstance(providers, str):
            # Single provider
            response.headers["Content-Disposition"] = (
                f'attachment; filename="{providers}_proxied_playlist.m3u8"'
            )
        else:
            # All providers
            response.headers["Content-Disposition"] = (
                'attachment; filename="playlist_proxied.m3u8"'
            )

        return m3u_content

    def _generate_m3u_proxied_ffmpeg_fast(self, providers=None):
        """
        Fast generation of decrypted M3U content with ffmpeg piping for specified providers.
        Includes ALL channels with highest quality video and ffmpeg-piped stream URLs.
        No DRM filtering, no caching - maximum speed.

        Args:
            providers: List of provider names, or None for all providers

        Returns:
            M3U content as string
        """
        # Check if media proxy is configured
        if not self.media_proxy_url:
            logger.error("Cannot generate decrypted ffmpeg M3U: MEDIA_PROXY_URL not set")
            response.status = 503
            response.content_type = "application/json"
            return json.dumps(
                {"error": "Media proxy not configured (MEDIA_PROXY_URL not set)"}
            )

        # Get base URL for absolute stream URLs
        base_url = f"{request.urlparts.scheme}://{request.urlparts.netloc}"

        # Start M3U content
        m3u_content = "#EXTM3U\n"

        # Determine which providers to process
        if providers is None:
            providers_to_process = self.manager.list_providers()
        else:
            providers_to_process = (
                [providers] if isinstance(providers, str) else providers
            )

        channels_included = 0

        for provider_name in providers_to_process:
            try:
                # Get channels for this provider
                channels = self._sort_channels(
                    self.manager.get_channels(provider_name=provider_name, fetch_manifests=False)
                )

                # Get provider label
                try:
                    provider_instance = self.manager.get_provider(provider_name)
                    provider_label = provider_instance.provider_label
                except (AttributeError, KeyError, ValueError):
                    provider_label = provider_name

                # Process each channel - no DRM checks
                for channel in channels:
                    channel_id = channel.channel_id
                    channel_name = channel.name

                    # Build decrypted stream URL (ffmpeg variant with highest quality)
                    # client_drm=false matches this playlist's static KODIPROP
                    # line below (server decrypts); highest_quality_only=true
                    # replaces the old dedicated /stream/proxied/ffmpeg/ path.
                    stream_url = f"{base_url}/api/providers/{provider_name}/channels/{channel_id}/stream/index.mpd?client_drm=false&highest_quality_only=true"

                    # Build ffmpeg pipe command
                    ffmpeg_cmd = self._build_ffmpeg_pipe_command(stream_url, channel_name)

                    # Header only (EXTINF + KODIPROP) — this variant is
                    # intentionally live-only, so include_catchup=False
                    # preserves its existing behavior of never emitting
                    # catchup attributes, even for channels that support it.
                    # No KODIPROP line — client_drm=false here too (server
                    # decrypts), and the stream target is a pipe://ffmpeg
                    # command anyway, which inputstream.adaptive never touches.
                    m3u_content += self._build_m3u_entry_header(
                        provider_name, channel,
                        provider_label=provider_label,
                        drm_directives="",
                        include_catchup=False,
                    )
                    m3u_content += f"{ffmpeg_cmd}\n"

                    channels_included += 1

            except Exception as provider_err:
                logger.warning(
                    f"Failed to process provider '{provider_name}': {str(provider_err)}"
                )
                continue

        logger.info(f"Fast decrypted ffmpeg M3U: included {channels_included} channels")

        # Set appropriate headers
        response.content_type = "audio/x-mpegurl; charset=utf-8"

        if providers and isinstance(providers, str):
            # Single provider
            response.headers["Content-Disposition"] = (
                f'attachment; filename="{providers}_proxied_ffmpeg_playlist.m3u8"'
            )
        else:
            # All providers
            response.headers["Content-Disposition"] = (
                'attachment; filename="playlist_proxied_ffmpeg.m3u8"'
            )

        return m3u_content

    def _generate_m3u_proxied_filtered_content(
            self, providers=None, save_to_cache=True, cache_filename=None
    ):
        """
        Internal method to generate filtered decrypted M3U content for specified providers.
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
            cache_filename = cache_filename or "playlist_proxied_filtered.m3u"
        else:
            # Specific provider(s)
            providers_to_process = (
                [providers] if isinstance(providers, str) else providers
            )
            cache_filename = (
                    cache_filename or f"{providers_to_process[0]}_proxied_filtered.m3u"
            )

        channels_included = 0
        channels_skipped = 0

        for provider_name in providers_to_process:
            try:
                # Get channels for this provider
                channels = self._sort_channels(
                    self.manager.get_channels(provider_name=provider_name, fetch_manifests=False)
                )

                # Get provider instance for label
                try:
                    provider_instance = self.manager.get_provider(provider_name)
                    provider_label = provider_instance.provider_label
                except (AttributeError, KeyError, ValueError):
                    provider_label = provider_name

                # Process each channel
                for channel in channels:
                    channel_id = channel.channel_id

                    # Try to get DRM configs
                    try:
                        drm_configs = self.manager.get_channel_drm_configs(
                            provider_name=provider_name, channel_id=channel_id
                        )
                        drm_dict = self._drm_configs_to_dict(drm_configs)

                        # Check if channel has ClearKey DRM or is unencrypted
                        has_clearkey = "org.w3.clearkey" in drm_dict and drm_dict["org.w3.clearkey"]
                        is_unencrypted = "none" in drm_dict

                        if has_clearkey:
                            # Channel has ClearKey - generate proxied entry.
                            # include_catchup=True matches this branch's
                            # pre-consolidation behavior (the old
                            # _generate_m3u_proxied_channel_entry always
                            # included catchup tags when available).
                            # No KODIPROP line — client_drm=false, client
                            # doesn't use inputstream.adaptive.
                            m3u_content += self._generate_m3u_entry(
                                base_url, provider_name, channel,
                                stream_path="stream/index.mpd?client_drm=false",
                                provider_label=provider_label,
                                drm_directives="",
                                include_catchup=True,
                            )
                            channels_included += 1
                        elif is_unencrypted:
                            # Explicitly unencrypted channel - include with direct
                            # stream URL. include_catchup=True — previously this
                            # branch never included catchup tags, unlike the
                            # ClearKey branch above; fixed so both branches behave
                            # consistently (deliberate change, not preserved
                            # pre-consolidation behavior).
                            m3u_content += self._generate_m3u_entry(
                                base_url, provider_name, channel,
                                stream_path="stream/index.mpd",
                                provider_label=provider_label,
                                drm_directives="",
                                include_catchup=True,
                            )
                            channels_included += 1
                        else:
                            # Channel has other DRM, is inaccessible, or unknown - skip
                            channels_skipped += 1
                            logger.debug(
                                f"Skipping {provider_name}/{channel_id} - unsupported DRM or no access"
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
            f"Filtered decrypted M3U: included {channels_included} channels, skipped {channels_skipped}"
        )

        # Save to cache if requested
        if save_to_cache and cache_filename:
            if self.vfs.write_text(cache_filename, m3u_content):
                logger.info(f"Filtered decrypted M3U playlist cached to {cache_filename}")
            else:
                logger.warning(
                    f"Failed to cache filtered decrypted M3U playlist to {cache_filename}"
                )

        return m3u_content

    def _generate_m3u_content(
        self, providers=None, save_to_cache=True, cache_filename=None, no_proxy=False
    ):
        """
        Internal method to generate M3U content for specified providers.

        Args:
            providers: List of provider names, or None for all providers
            save_to_cache: Whether to save to cache
            cache_filename: Cache filename to use
            no_proxy: If True, generate entries pointing at the non-proxied stream
                      routes, and cache under a "_noproxy" suffixed filename so this
                      never collides with the normal proxied cache file.

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

        # IMPORTANT: apply the no_proxy suffix AFTER cache_filename has been
        # resolved to its default above. Doing this earlier (before the default
        # is assigned) means cache_filename is still None here and the suffix
        # never gets applied — the noproxy playlist then silently caches under
        # the SAME filename as the proxied playlist, corrupting it.
        if no_proxy:
            if "." in cache_filename:
                base_name, ext = cache_filename.rsplit(".", 1)
                cache_filename = f"{base_name}_noproxy.{ext}"
            else:
                cache_filename = f"{cache_filename}_noproxy"

        # /stream/noproxy/ and /stream/sw-drm/ no longer exist as separate
        # routes — folded into query params on the single /stream/index.mpd
        # endpoint. client_drm=true because this playlist's KODIPROP
        # directives come from a dynamic per-channel DRM lookup (see the
        # drm_directives=None call below / _build_m3u_entry_header), which
        # only makes sense if the client is the one doing the decrypting —
        # client_drm now defaults to false, so this has to be explicit or
        # every entry here would silently mismatch its own KODIPROP directives.
        stream_path = "stream/index.mpd?client_drm=true&no_proxy=true" if no_proxy else "stream/index.mpd?client_drm=true"

        for provider_name in providers_to_process:
            try:
                # Get channels for this provider
                channels = self._sort_channels(
                    self.manager.get_channels(provider_name=provider_name, fetch_manifests=False)
                )

                # Resolve provider_label once per provider instead of once per
                # channel (previously done inside _generate_m3u_channel_entry
                # on every call — same result, redundant lookups).
                try:
                    provider_label = self.manager.get_provider(provider_name).provider_label
                except (AttributeError, KeyError, ValueError):
                    provider_label = provider_name

                # Add each channel to M3U
                for channel in channels:
                    m3u_content += self._generate_m3u_entry(
                        base_url, provider_name, channel,
                        stream_path=stream_path,
                        provider_label=provider_label,
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

    def _generate_m3u_proxied_filtered_all(self, save_to_cache: bool = False) -> str:
        """Internal method to generate filtered decrypted M3U for all providers."""
        logger.info("Generating filtered decrypted M3U playlist for all providers")
        m3u_content = self._generate_m3u_proxied_filtered_content(
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
            'attachment; filename="playlist_proxied_filtered.m3u8"'
        )

        return m3u_content

    def _generate_m3u_proxied_filtered_provider(
            self, provider: str, save_to_cache: bool = False
    ) -> str:
        """Internal method to generate filtered decrypted M3U for a specific provider."""
        logger.info(f"Generating filtered decrypted M3U playlist for provider '{provider}'")
        m3u_content = self._generate_m3u_proxied_filtered_content(
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
            f'attachment; filename="{provider}_proxied_filtered_playlist.m3u8"'
        )

        return m3u_content

    @staticmethod
    def _build_ffmpeg_pipe_command(stream_url: str, channel_name: str) -> str:
        """
        Build the ffmpeg pipe:// command used by the ffmpeg-piped M3U variant.

        Extracted from _generate_m3u_proxied_ffmpeg_fast, which was the only
        caller and still is — pulled out unchanged so it's reusable/testable
        on its own, not because behavior needed to change.

        - -thread_queue_size 2048: kept large to handle demuxing multiple
          audio tracks smoothly.
        - -map 0:v:0: maps the single video stream (only one exists, since
          the upstream URL is requested with highest_quality_only=true).
        - -map 0:a?: maps all available audio tracks (channels commonly
          carry multiple, e.g. German/English AAC + AC-3); "?" makes the
          map optional so this doesn't fail if a channel has none.
        - -max_muxing_queue_size 8192: kept high to safely interleave
          multi-audio timescales.
        """
        return (
            f'pipe://ffmpeg -loglevel fatal '
            f'-fflags +genpts+igndts+discardcorrupt '
            f'-reconnect 1 -reconnect_streamed 1 -reconnect_delay_max 5 '
            f'-thread_queue_size 2048 '
            f'-re '
            f'-i "{stream_url}" '
            f'-map 0:v:0 '
            f'-map 0:a? '
            f'-c copy '
            f'-max_muxing_queue_size 8192 '
            f'-f mpegts '
            f'-muxdelay 0 -muxpreload 0 '
            f'-mpegts_flags resend_headers '
            f'-metadata service_name="{channel_name}" '
            f'-flush_packets 1 '
            f'pipe:1'
        )

    @staticmethod
    def _chno_attr(channel) -> str:
        """Return ' tvg-chno="N" ch-number="N"' when channel_number is set, else empty string."""
        chno = getattr(channel, "channel_number", None)
        return f' tvg-chno="{chno}" ch-number="{chno}"' if chno is not None else ""

    @staticmethod
    def _drm_configs_to_dict(drm_configs) -> dict:
        """
        Normalize DRM configs (list of DRMConfig/dict objects, or an
        already-merged dict) into a single dict keyed by DRM scheme.

        Shared by _generate_drm_directives and _generate_m3u_proxied_filtered_content,
        which each used to do this same list-to-dict merge independently.
        """
        if isinstance(drm_configs, dict):
            return drm_configs

        merged = {}
        if isinstance(drm_configs, list):
            for config in drm_configs:
                if hasattr(config, "to_dict"):
                    merged.update(config.to_dict())
                elif isinstance(config, dict):
                    merged.update(config)
        return merged

    def _generate_drm_directives(self, drm_configs):
        """
        Generate KODIPROP directives for DRM configuration.

        Args:
            drm_configs: DRM configurations as a dictionary (not list)

        Returns:
            DRM directives as string
        """
        directives = ""

        drm_configs = self._drm_configs_to_dict(drm_configs)
        if not drm_configs:
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

    # ── Public API for route modules ─────────────────────────────────────────────

    def get_epg_id(self, channel_id: str) -> Optional[str]:
        """Public wrapper for EPG ID lookup."""
        return self._get_epg_id(channel_id)

    def generate_m3u_all(self, save_to_cache: bool = False, no_proxy: bool = False) -> str:
        """Public wrapper for full M3U generation."""
        return self._generate_m3u_all(save_to_cache=save_to_cache, no_proxy=no_proxy)

    def generate_m3u_provider(self, provider: str, save_to_cache: bool = False, no_proxy: bool = False) -> str:
        """Public wrapper for per-provider M3U generation."""
        return self._generate_m3u_provider(provider, save_to_cache=save_to_cache, no_proxy=no_proxy)

    def generate_m3u_proxied_fast(self, providers=None) -> str:
        """Public wrapper for fast decrypted M3U generation."""
        return self._generate_m3u_proxied_fast(providers)

    def generate_m3u_proxied_ffmpeg_fast(self, providers=None) -> str:
        """Public wrapper for fast ffmpeg-decrypted M3U generation."""
        return self._generate_m3u_proxied_ffmpeg_fast(providers)

    def generate_m3u_proxied_filtered_all(self, save_to_cache: bool = False) -> str:
        """Public wrapper for filtered decrypted M3U (all providers)."""
        return self._generate_m3u_proxied_filtered_all(save_to_cache=save_to_cache)

    def generate_m3u_proxied_filtered_provider(self, provider: str, save_to_cache: bool = False) -> str:
        """Public wrapper for filtered decrypted M3U (single provider)."""
        return self._generate_m3u_proxied_filtered_provider(provider, save_to_cache=save_to_cache)

    def generate_drm_directives(self, drm_configs) -> str:
        """Public wrapper for DRM directive generation."""
        return self._generate_drm_directives(drm_configs)

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

    def _generate_m3u_all(self, save_to_cache: bool = False, no_proxy: bool = False) -> str:
        """Internal method to generate M3U for all providers."""
        logger.info(f"Generating {'no-proxy ' if no_proxy else ''}M3U playlist for all providers")
        m3u_content = self._generate_m3u_content(
            providers=None, save_to_cache=save_to_cache, no_proxy=no_proxy
        )

        # Set appropriate headers for M3U
        response.content_type = "audio/x-mpegurl; charset=utf-8"
        filename = "playlist_noproxy.m3u8" if no_proxy else "playlist.m3u8"
        response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'

        return m3u_content

    def _generate_m3u_provider(self, provider: str, save_to_cache: bool = False, no_proxy: bool = False) -> str:
        """Internal method to generate M3U for a specific provider."""
        logger.info(f"Generating {'no-proxy ' if no_proxy else ''}M3U playlist for provider '{provider}'")
        m3u_content = self._generate_m3u_content(
            providers=provider, save_to_cache=save_to_cache, no_proxy=no_proxy
        )

        # Set appropriate headers for M3U
        response.content_type = "audio/x-mpegurl; charset=utf-8"
        filename = f"{provider}_playlist_noproxy.m3u8" if no_proxy else f"{provider}_playlist.m3u8"
        response.headers["Content-Disposition"] = (
            f'attachment; filename="{filename}"'
        )

        return m3u_content

    @staticmethod
    def get_settings_manager():
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

        # Add request logging hooks
        @self.app.hook('before_request')
        def log_request():
            request._start_time = time.time()
            logger.info(
                f"→ {request.method} {request.path} from {request.remote_addr} (User-Agent: {request.headers.get('User-Agent', 'unknown')[:50]})")

        @self.app.hook('after_request')
        def log_response():
            logger.info(
                f"← {request.method} {request.path} → {response.status_code} (took {time.time() - getattr(request, '_start_time', time.time()):.2f}s)")

        # Import route handlers here
        from routes.providers import setup_provider_routes
        from routes.streams import setup_stream_routes
        from routes.m3u import setup_m3u_routes
        from routes.drm import setup_drm_routes
        from routes.cache import setup_cache_routes
        from routes.config import setup_config_routes
        from routes.epg import setup_epg_routes
        from routes.events import setup_events_routes
        from routes.vod import setup_vod_routes
        from routes.recordings import setup_recordings_routes
        from routes.timers import setup_timers_routes
        from routes.bookmarks import setup_bookmarks_routes
        from routes.favorites import setup_favorites_routes
        from routes.docs import setup_docs_routes

        # Setup routes from separate modules
        setup_provider_routes(self.app, self.manager, self)
        setup_stream_routes(self.app, self.manager, self)
        setup_m3u_routes(self.app, self.manager, self)
        setup_drm_routes(self.app, self.manager, self)
        setup_cache_routes(self.app, self.manager, self)
        setup_config_routes(self.app, self.manager, self)
        setup_epg_routes(self.app, self.manager, self)
        setup_events_routes(self.app, self.manager, self)
        setup_vod_routes(self.app, self.manager)
        setup_recordings_routes(self.app, self.manager, self)
        setup_timers_routes(self.app, self.manager, self)
        setup_bookmarks_routes(self.app, self.manager, self)
        setup_favorites_routes(self.app, self.manager, self)
        setup_docs_routes(self.app, self.manager, self)

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