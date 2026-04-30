# streaming_providers/providers/rtlplus/provider.py
import json
import time
from datetime import datetime
from typing import ClassVar, Dict, List, Optional, Tuple
from ..lib_drmtoday import  create_drmtoday_configs

import requests

from ...base.models import DRMConfig, StreamingChannel, Event
from ...base.models.proxy_models import ProxyConfig
from ...base.provider import StreamingProvider
from ...base.utils import logger
from .auth import RTLPlusAuthenticator
from .constants import RTLPlusConfig, RTLPlusDefaults
from .vod_manager import RTLPlusVodManager
from .channel_manager import RTLPlusChannelManager
from .event_manager import RTLPlusEventManager

_MANIFEST_CACHE_TTL = 86400  # 1 day in seconds for VOD/events


class RTLPlusProvider(StreamingProvider):
    # Provider constants
    PROVIDER_LABEL: ClassVar[str] = "RTL+"
    PROVIDER_LOGO: ClassVar[str] = RTLPlusDefaults.RTLPLUS_LOGO
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = [
        "client_credentials",
        "user_credentials",
    ]

    def __init__(
            self,
            country: str = "DE",
            config: Optional[Dict] = None,
            proxy_config: Optional[ProxyConfig] = None,
    ):
        super().__init__(country)

        # Initialize configuration
        self.rtl_config = RTLPlusConfig(config)

        # Setup HTTP manager
        self.http_manager = self._setup_http_manager(
            provider_name="rtlplus",
            proxy_config=proxy_config,
            user_agent=self.rtl_config.user_agent,
            timeout=self.rtl_config.timeout,
        )

        # Initialize authenticator
        self.authenticator = RTLPlusAuthenticator(
            client_version=self.rtl_config.client_version,
            device_id=self.rtl_config.device_id,
            proxy_config=proxy_config,
            http_manager=self.http_manager,
        )

        self.http_manager = self._share_http_manager_with_authenticator(self.authenticator)

        # Layout cache (shared across all layout types)
        self._layout_cache: Dict[str, Tuple[Dict, float]] = {}
        self.LAYOUT_CACHE_TTL = RTLPlusDefaults.LAYOUT_CACHE_TTL

        # Try authentication
        try:
            self.bearer_token = self.authenticator.get_bearer_token()
            logger.debug("RTL+ authentication successful during initialization")

            # Ensure a profile is selected for user-authenticated sessions
            if self.authenticator.has_user_credentials():
                self.authenticator.ensure_profile_selected()

        except Exception as e:
            logger.warning(f"RTL+ could not authenticate during initialization: {e}")
            self.bearer_token = None

        # Initialize managers
        self._vod_manager = RTLPlusVodManager(self)
        self.channel_manager = RTLPlusChannelManager(self)
        self.event_manager = RTLPlusEventManager(self)

        # Manifest cache for VOD/events
        self._manifest_cache: Dict[str, tuple] = {}

    @property
    def provider_name(self) -> str:
        return "rtlplus"

    @property
    def provider_label(self) -> str:
        return "RTL+"

    @property
    def provider_logo(self) -> str:
        return self.PROVIDER_LOGO

    @property
    def uses_dynamic_manifests(self) -> bool:
        return False

    @property
    def implements_epg(self) -> bool:
        return False

    @property
    def supported_auth_types(self) -> List[str]:
        return ["user_credentials"]

    # --------------------------------------------------------------------------
    # Common Layout Methods
    # --------------------------------------------------------------------------

    def fetch_layout(
            self,
            layout_type: str,
            content_id: str,
            block_page: int = None,
            nb_pages: int = None,
            location: str = None,
            force_refresh: bool = False,
    ) -> Optional[Dict]:
        """
        Fetch any layout (live/video/folder/program/block) with caching.

        Args:
            layout_type: 'live', 'video', 'folder', 'program', 'block', 'alias' (for root/home)
            content_id: The ID (seo for live, clip_id for video, folder_id for folder,
                       or 'home'/'root' for alias layouts)
            block_page: Page number for blocks (default 1)
            nb_pages: Number of pages to request (default 2)
            location: x-location header value (auto-generated if not provided)
            force_refresh: Ignore cache

        Returns:
            Layout JSON or None
        """
        if block_page is None:
            block_page = RTLPlusDefaults.DEFAULT_BLOCK_PAGE
        if nb_pages is None:
            nb_pages = RTLPlusDefaults.DEFAULT_NB_PAGES

        cache_key = f"{layout_type}:{content_id}:{block_page}:{nb_pages}"
        now = time.time()

        if not force_refresh and cache_key in self._layout_cache:
            cached_data, cached_time = self._layout_cache[cache_key]
            if (now - cached_time) < self.LAYOUT_CACHE_TTL:
                logger.debug(f"Layout cache hit: {cache_key}")
                return cached_data

        # Get tokens
        oauth_token = self.get_user_bearer_token()
        if not oauth_token:
            try:
                oauth_token = self.authenticator.get_bearer_token()
                logger.debug("Using anonymous token for layout")
            except Exception as e:
                logger.error(f"Failed to get OAuth token for layout: {e}")
                return None

        try:
            bedrock_token = self.authenticator.get_bedrock_token()
        except Exception as e:
            logger.error(f"Failed to get Bedrock token for layout: {e}")
            return None

        # Auto-generate location header if not provided
        if location is None and layout_type in ("live", "video", "folder", "program", "alias"):
            location = f"{self.rtl_config.beta_website}{content_id}"

        # Build request - handle alias layouts specially
        if layout_type == "alias":
            # For alias layouts, the URL pattern is: {base}/alias/{content_id}/layout
            url = f"{self.rtl_config.bedrock_layout_base}/alias/{content_id}/layout"
        else:
            url = self.rtl_config.get_layout_url(layout_type, content_id)

        headers = self.rtl_config.get_layout_headers(oauth_token, bedrock_token, location)
        params = {"blockPage": block_page, "nbPages": nb_pages}

        # LOG ALL HEADERS BEING SENT
        logger.debug(f"=== FETCH LAYOUT REQUEST HEADERS ===")
        logger.debug(f"URL: {url}")
        logger.debug(f"Method: GET")
        logger.debug(f"Headers:")
        # Mask sensitive tokens for security
        safe_headers = {}
        for key, value in headers.items():
            if 'authorization' in key.lower() or 'token' in key.lower():
                safe_headers[key] = f"{value[:20]}... (truncated)" if len(value) > 20 else "***"
            else:
                safe_headers[key] = value
        logger.debug(f"{json.dumps(safe_headers, indent=2)}")
        logger.debug(f"Params: {params}")
        logger.debug(f"==================================")


        try:
            response = self.http_manager.get(
                url, headers=headers, params=params, operation="api"
            )
            response.raise_for_status()
            data = response.json()

            self._layout_cache[cache_key] = (data, now)
            logger.debug(f"Fetched {layout_type} layout for {content_id}")

            return data

        except Exception as e:
            logger.error(f"Failed to fetch {layout_type} layout for {content_id}: {e}")
            return None

    @staticmethod
    def extract_video_assets(layout_data: Dict) -> List[Dict]:
        """
        Extract video assets from a layout response.
        """
        assets = []
        blocks = layout_data.get("blocks", [])

        logger.debug(f"extract_video_assets: Found {len(blocks)} blocks")

        for block_idx, block in enumerate(blocks):
            block_type = block.get("type")
            logger.debug(f"Block {block_idx}: type={block_type}")

            if block.get("type") != "bffPaginated":
                logger.debug(f"  Skipping block {block_idx} - not bffPaginated")
                continue

            items = block.get("content", {}).get("items", [])
            logger.debug(f"  Block {block_idx} has {len(items)} items")

            for item_idx, item in enumerate(items):
                item_type = item.get("itemType")
                logger.debug(f"    Item {item_idx}: itemType={item_type}")

                if item.get("itemType") == "video":
                    video = item.get("itemContent", {}).get("video", {})
                    video_assets = video.get("assets", [])
                    logger.debug(f"      Found {len(video_assets)} assets in video item")
                    assets.extend(video_assets)
                elif item.get("itemType") == "classic":
                    # Some layouts wrap video inside classic items
                    item_content = item.get("itemContent", {})
                    video = item_content.get("video", {})
                    video_assets = video.get("assets", [])
                    logger.debug(f"      Found {len(video_assets)} assets in classic item")
                    assets.extend(video_assets)
                else:
                    logger.debug(f"      Skipping item - unknown itemType: {item_type}")

        logger.debug(f"extract_video_assets: Total assets found: {len(assets)}")
        return assets

    @staticmethod
    def _extract_items_from_block(
        layout_data: Dict,
        block_type: str = None,
        item_type: str = None
    ) -> List[Dict]:
        """
        Extract items from layout blocks with optional filtering.

        Args:
            layout_data: Layout JSON
            block_type: Filter blocks by type (e.g., 'bffPaginated')
            item_type: Filter items by itemType (e.g., 'classic', 'video')

        Returns:
            List of item dictionaries
        """
        items = []
        blocks = layout_data.get("blocks", [])

        for block in blocks:
            if block_type and block.get("type") != block_type:
                continue

            block_items = block.get("content", {}).get("items", [])
            for item in block_items:
                if item_type and item.get("itemType") != item_type:
                    continue
                items.append(item)

        return items

    @staticmethod
    def _get_pagination_info(layout_data: Dict, block_id: str = None) -> Dict:
        """
        Extract pagination info from layout or specific block.
        """
        if block_id:
            for block in layout_data.get("blocks", []):
                if block.get("id") == block_id or block.get("blockId") == block_id:
                    return block.get("content", {}).get("pagination", {})

        # Fallback: look for pagination at top level
        return layout_data.get("pagination", {})

    def extract_best_manifest_url(
        self,
        assets: List[Dict],
        preferred_quality: str = None,
        preferred_format: str = None,
    ) -> Optional[str]:
        """
        Extract the best manifest URL from assets based on preferences.
        """
        quality = preferred_quality or next(iter(self.rtl_config.preferred_qualities), "hd")
        format_pref = preferred_format or next(iter(self.rtl_config.preferred_formats), "dashcenc")

        # Try exact match
        for asset in assets:
            if (asset.get("quality") == quality and
                    asset.get("format") == format_pref):
                manifest_url = asset.get("path") or asset.get("reference")
                if manifest_url:
                    return manifest_url

        # Try format + quality, any DRM
        for asset in assets:
            if asset.get("quality") == quality and asset.get("format") == format_pref:
                manifest_url = asset.get("path") or asset.get("reference")
                if manifest_url:
                    return manifest_url

        # Try by preferred formats/qualities
        for fmt in self.rtl_config.preferred_formats:
            for qual in self.rtl_config.preferred_qualities:
                for asset in assets:
                    if asset.get("format") == fmt and asset.get("quality") == qual:
                        manifest_url = asset.get("path") or asset.get("reference")
                        if manifest_url:
                            return manifest_url

        # Last resort: any asset with a path
        for asset in assets:
            manifest_url = asset.get("path") or asset.get("reference")
            if manifest_url:
                return manifest_url

        return None

    def resolve_redirect(self, url: str) -> str:
        """
        Resolve HTTP redirects to get final manifest URL.
        """
        if not url:
            return url

        try:
            response = self.http_manager.head(
                url,
                headers={"User-Agent": self.rtl_config.user_agent},
                follow_redirects=False,
                timeout=10
            )
            if 300 <= response.status_code < 400:
                location = response.headers.get("location")
                if location:
                    logger.debug(f"Resolved redirect: {url} -> {location}")
                    return location
        except Exception as e:
            logger.debug(f"Redirect resolution failed: {e}")

        return url

    def invalidate_layout_cache(self, cache_key: str = None):
        """Invalidate layout cache for a specific key or all keys."""
        if cache_key:
            self._layout_cache.pop(cache_key, None)
        else:
            self._layout_cache.clear()

    # --------------------------------------------------------------------------
    # Authentication Helpers
    # --------------------------------------------------------------------------

    def _get_rtlplus_authenticated_headers(self) -> Dict[str, str]:
        from ...base.auth.base_auth import TokenAuthLevel

        try:
            current_level = self.authenticator.get_current_token_level()
            force_upgrade = (
                self.authenticator.has_user_credentials()
                and current_level != TokenAuthLevel.USER_AUTHENTICATED
            )
            bearer_token = self.authenticator.get_bearer_token(force_upgrade=force_upgrade)
        except Exception as e:
            logger.error(f"Failed to get bearer token: {e}")
            raise

        return self.rtl_config.get_api_headers(access_token=bearer_token)

    # --------------------------------------------------------------------------
    # Linear TV Channels
    # --------------------------------------------------------------------------

    def get_channels(self, **kwargs) -> List[StreamingChannel]:
        """
        Get list of available linear TV channels from EPG grid.
        """
        try:
            channels = self.channel_manager.get_channels_as_streaming_channel_list()
            self.channels = channels
            return channels
        except Exception as e:
            logger.error(f"Error fetching RTL+ channels: {e}")
            return []

    # --------------------------------------------------------------------------
    # Events
    # --------------------------------------------------------------------------

    def get_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kwargs,
    ) -> List[Event]:
        """
        Fetch upcoming / live RTL+ events from the Bedrock layout API.
        """
        folder_id = kwargs.get("folder_id", "6")  # Default to Sport folder
        return self.event_manager.get_events(
            folder_id=folder_id,
            start_time=start_time,
            end_time=end_time,
            force_refresh=kwargs.get("force_refresh", False),
        )

    # --------------------------------------------------------------------------
    # VOD
    # --------------------------------------------------------------------------

    def get_vod_category(self, content_id: str = "", **kwargs):
        return self._vod_manager.get_vod_category(content_id=content_id, **kwargs)

    # --------------------------------------------------------------------------
    # Manifest & DRM (Unified)
    # --------------------------------------------------------------------------

    def get_manifest(self, content_id: str, **kwargs) -> Optional[str]:
        """
        Get manifest URL for content.

        Supports:
        - Linear TV channels (via channel_manager)
        - VOD clips (via layout extraction)
        - Events (via event_manager)
        """
        # Try linear TV channel first
        if self._is_linear_tv_channel(content_id):
            return self.channel_manager.get_best_manifest_url(content_id)

        # Try as event (folder) - event_manager will return manifest if available
        if content_id.isdigit() and int(content_id) > 0:
            manifest = self.event_manager.get_manifest_for_event(content_id)
            if manifest:
                return manifest

        # Fall back to VOD/event manifest extraction
        return self._get_manifest_vod_or_event(content_id, **kwargs)

    @staticmethod
    def _is_linear_tv_channel(content_id: str) -> bool:
        """Determine if content_id refers to a linear TV channel."""
        # VOD clips have patterns like "clip_123456" or contain "clip"
        if "clip_" in content_id or content_id.startswith("clip"):
            return False

        # Also check for common VOD patterns
        if content_id.startswith("rrn:") or "/" in content_id:
            return False

        # Event folder IDs are digits
        if content_id.isdigit():
            return False

        return (
                ":" not in content_id
                and not content_id.startswith("rrn:")
                and not content_id.startswith("/")
                and not content_id.startswith("http")
        )

    def _get_manifest_vod_or_event(self, content_id: str, **kwargs) -> Optional[str]:
        """Original manifest logic for VOD/events using layout extraction."""
        try:
            manifest_data = self._fetch_manifest_data(content_id)
            if manifest_data is None:
                return None

            quality_preference = ["dashhd", "dashfree", "dashsd"]

            for quality in quality_preference:
                for stream in manifest_data:
                    if stream.get("name") == quality:
                        sources = stream.get("sources", [])
                        non_yospace_sources = [s for s in sources if not s.get("isYospace", False)]

                        if non_yospace_sources:
                            selected_url = non_yospace_sources[0].get("url")
                            logger.info(f"RTL+ Selected Manifest URL: {selected_url}")
                            return selected_url

            for stream in manifest_data:
                sources = stream.get("sources", [])
                if sources:
                    fallback_url = sources[0].get("url")
                    logger.info(f"RTL+ Using Fallback Manifest URL: {fallback_url}")
                    return fallback_url

            logger.warning("RTL+ No valid manifest URL found in response")
            return None

        except requests.RequestException as e:
            logger.error(f"RTL+ Manifest HTTP Error: {str(e)}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"RTL+ Manifest JSON Parse Error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"RTL+ Manifest Unexpected Error: {str(e)}")
            return None

    def _get_drm_vod_or_event(self, content_id: str, **kwargs) -> List[DRMConfig]:
        """
        Get DRM configuration for VOD/event content using layout extraction.
        """
        # Fetch layout for the content
        layout = self.fetch_layout(
            layout_type="video",
            content_id=content_id,
            location=f"{self.rtl_config.beta_website}{content_id}"
        )

        if not layout:
            logger.error(f"Failed to fetch layout for VOD/event content_id: {content_id}")
            return []

        # Use the common DRM extraction method
        return self.get_drm_for_content(layout)

    def get_drm_for_content(self, layout_data: Dict) -> List[DRMConfig]:
        """
        Extract DRM configuration from layout data.
        """
        # Ensure profile is selected for user-authenticated sessions
        if self.authenticator.has_user_credentials():
            if not self.authenticator.ensure_profile_selected():
                logger.warning("Failed to select profile for DRM request")

        assets = self.extract_video_assets(layout_data)

        if not assets:
            logger.debug("No video assets found in layout")
            return []

        # Priority: delta provider dashcenc format (best quality)
        target_asset = None

        # First try: delta + dashcenc + hd quality
        for asset in assets:
            if (asset.get("provider") == "delta" and
                    asset.get("format") == "dashcenc" and
                    asset.get("quality") == "hd"):
                target_asset = asset
                logger.debug("Found delta/dashcenc/hd asset")
                break

        # Fallback: delta + dashcenc + any quality
        if not target_asset:
            for asset in assets:
                if asset.get("provider") == "delta" and asset.get("format") == "dashcenc":
                    target_asset = asset
                    logger.debug(f"Fallback to delta/dashcenc/{asset.get('quality', 'unknown')} asset")
                    break

        # Last resort: any dashcenc asset
        if not target_asset:
            for asset in assets:
                if asset.get("format") == "dashcenc":
                    target_asset = asset
                    logger.debug(f"Last resort: {asset.get('provider', 'unknown')}/dashcenc asset")
                    break

        if not target_asset:
            logger.warning("No suitable DRM asset found")
            return []

        # Extract contentId from the selected asset
        drm_info = target_asset.get("drm", {})
        drm_config = drm_info.get("config", {})
        content_id = drm_config.get("contentId")

        if not content_id:
            logger.error("No contentId in asset DRM config")
            return []

        try:
            uid = self.authenticator.get_user_id_from_token()
            if not uid:
                logger.error("No user ID available for DRM")
                return []

            # Get upfront token (works for both Widevine and PlayReady)
            upfront_token = self.authenticator.get_upfront_token(
                content_id=content_id,
                uid=uid,
            )

            if not upfront_token:
                logger.error(f"Failed to get upfront token for {content_id}")
                return []

            # Use the shared DRMToday factory to create both configs
            drm_configs = create_drmtoday_configs(
                upfront_token=upfront_token,
                origin=self.rtl_config.beta_website.rstrip("/"),
                referer=self.rtl_config.beta_website,
                user_agent=self.rtl_config.user_agent,
                playready_user_agent=RTLPlusDefaults.PLAYREADY_USER_AGENT,  # Edge for PlayReady
            )

            logger.info(f"Built {len(drm_configs)} DRM configs (Widevine + PlayReady)")
            return drm_configs

        except Exception as e:
            logger.error(f"Failed to get DRM: {e}")
            return []

    def get_drm(self, content_id: str, **kwargs) -> List[DRMConfig]:
        """
        Get DRM configuration for content.

        Supports:
        - Linear TV channels (via channel_manager)
        - VOD clips (via layout extraction)
        - Events (via event_manager)
        """
        # Try linear TV channel first
        if self._is_linear_tv_channel(content_id):
            return self.channel_manager.get_drm_config_for_channel(content_id)

        # Try as event (folder)
        if content_id.isdigit() and int(content_id) > 0:
            drm_configs = self.event_manager.get_drm_for_event(content_id)
            if drm_configs:
                return drm_configs

        # Fall back to VOD DRM extraction
        # This will also handle VOD clips and any other content types
        drm_configs = self._get_drm_vod_or_event(content_id, **kwargs)
        if drm_configs:
            return drm_configs

        # If we get here, no DRM config could be found for any content type
        logger.error(
            f"No DRM configuration found for content_id: {content_id} (not a valid channel, event, or VOD item)")
        return []

    def _fetch_manifest_data(self, content_id: str) -> Optional[list]:
        """Fetch raw manifest data for VOD/events, with cache."""
        now = time.monotonic()
        cached = self._manifest_cache.get(content_id)
        if cached is not None:
            data, ts = cached
            if (now - ts) < _MANIFEST_CACHE_TTL:
                logger.debug(f"RTL+ Manifest cache hit for {content_id}")
                return data

        # TODO: This legacy endpoint may eventually be migrated to Bedrock
        manifest_url = f"https://stus.player.streamingtech.de/watch-playout-variants/{content_id}?platform=web"

        headers = {"X-Auth-Token": self.authenticator.get_bearer_token()}
        response = self.http_manager.get(manifest_url, operation="manifest", headers=headers)
        response.raise_for_status()
        data = response.json()

        self._manifest_cache[content_id] = (data, now)
        return data

    def get_user_bearer_token(self) -> Optional[str]:
        """Get a user-authenticated bearer token, upgrading if necessary. Returns None if impossible."""
        from ...base.auth.base_auth import TokenAuthLevel

        current_level = self.authenticator.get_current_token_level()
        logger.debug(
            f"get_user_bearer_token: current_level={current_level}, has_user_credentials={self.authenticator.has_user_credentials()}")

        if current_level == TokenAuthLevel.USER_AUTHENTICATED:
            # Ensure profile is selected
            self.authenticator.ensure_profile_selected()
            return self.authenticator.get_bearer_token()

        if self.authenticator.has_user_credentials():
            token = self.authenticator.get_bearer_token(force_upgrade=True)
            if self.authenticator.get_current_token_level() == TokenAuthLevel.USER_AUTHENTICATED:
                self.authenticator.ensure_profile_selected()
                return token

        return None