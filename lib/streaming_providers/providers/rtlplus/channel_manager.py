# streaming_providers/providers/rtlplus/channel_manager.py
"""
RTL+ Linear TV Channel Manager

Handles all linear TV (live channel) functionality:
- Fetching channel layouts
- Extracting stream assets
- Manifest URL discovery
- DRM configuration
- Channel listing from EPG grid
"""

from typing import List, Optional, Dict, Any
import json
import time
from datetime import date

from ...base.models import Channel, DRMConfig, DRMSystem, LicenseConfig
from ...base.utils.logger import logger


class RTLPlusChannelManager:
    """
    Manages linear TV channels for RTL+.

    Uses the authenticator for all token management.
    """

    # Cache TTL for channel layouts (5 minutes)
    _CHANNEL_LAYOUT_CACHE_TTL = 300

    def __init__(self, provider):
        self._provider = provider
        self._layout_cache: Dict[str, tuple] = {}  # seo -> (data, timestamp)

    @property
    def cfg(self):
        return self._provider.rtl_config

    @property
    def http(self):
        return self._provider.http_manager

    @property
    def auth(self):
        return self._provider.authenticator

    # --------------------------------------------------------------------------
    # Channel Listing (EPG Grid)
    # --------------------------------------------------------------------------

    def get_channels(self, nb_pages: int = 3) -> List[Dict[str, Any]]:
        """
        Get list of all linear TV channels from the EPG grid endpoint.
        """
        try:
            oauth_token = self.auth.get_bearer_token()
            if not oauth_token:
                logger.error("No OAuth token available")
                return []

            # Get Bedrock token - no parameters needed
            bedrock_token = self.auth.get_bedrock_token()
            if not bedrock_token:
                logger.error("Failed to obtain Bedrock token")
                return []
        except Exception as e:
            logger.error(f"Failed to obtain tokens for channel listing: {e}")
            return []

        url = self.cfg.get_epg_grid_url()
        location = "https://plus.rtl.de/tv-programm"
        headers = self.cfg.get_bedrock_layout_headers(oauth_token, bedrock_token, location)

        today = date.today().isoformat()
        params = {"day": today, "nbPages": nb_pages}

        try:
            response = self.http.get(url, headers=headers, params=params, operation="api")
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            logger.error(f"Failed to fetch EPG grid: {e}")
            return []

        channels = []
        content = data.get("content", {})
        items = content.get("items", [])

        for item in items:
            if item.get("itemType") == "epg":
                item_content = item.get("itemContent", {})
                channel_data = item_content.get("channel", {})
                action = item_content.get("action", {})
                target = action.get("target", {})
                value_layout = target.get("value_layout", {})

                channel = {
                    "id": channel_data.get("id"),
                    "title": channel_data.get("title"),
                    "seo": value_layout.get("seo"),  # e.g., "rtl", "vox"
                    "slug": value_layout.get("id"),  # e.g., "rtlde_rtl", "rtlde_vox"
                    "logo_id": channel_data.get("image", {}).get("id"),
                    "channel_type": "BROADCAST",
                }
                channels.append(channel)
                logger.debug(f"Found channel: {channel['title']} (slug: {channel['slug']}, seo: {channel['seo']})")

        logger.info(f"Found {len(channels)} channels from EPG grid")
        return channels

    def get_channels_as_streaming_channel_list(self, nb_pages: int = 3) -> List[Channel]:
        """
        Get channels as Channel objects for the provider interface.
        """
        channels = self.get_channels(nb_pages=nb_pages)
        streaming_channels = []

        for ch in channels:
            # Get the slug - this is the content_id for manifest fetching
            content_id = ch.get("slug")  # e.g., "rtlde_rtl"
            seo = ch.get("seo")  # e.g., "rtl"
            title = ch.get("title")
            logo_id = ch.get("logo_id")

            logger.debug(f"Processing channel: title='{title}', slug='{content_id}', seo='{seo}'")

            if not content_id:
                logger.warning(f"Channel {title} has no slug, skipping")
                continue

            # Create channel with proper content_id
            streaming_channel = Channel.create_live_channel(
                name=title,
                channel_id=content_id,  # This sets content_id
                provider=self._provider.provider_name,
            )

            # Set logo URL
            streaming_channel.logo_url = self._resolve_image_url(logo_id)

            # Store SEO in manifest_script for fallback lookups
            # This allows get_manifest to work with either slug or seo
            if seo:
                streaming_channel.manifest_script = seo

            logger.debug(
                f"Created channel: name={title}, id={streaming_channel.content_id}, manifest_script={streaming_channel.manifest_script}")

            streaming_channels.append(streaming_channel)

        logger.info(f"Returning {len(streaming_channels)} channels with IDs")
        return streaming_channels

    @staticmethod
    def _resolve_image_url(image_id: str) -> str:
        """Resolve image ID to actual URL."""
        if not image_id:
            return ""
        return f"https://images.rtl.de/{image_id}?format=webp&width=200"

    # --------------------------------------------------------------------------
    # Channel Layout & Stream Assets
    # --------------------------------------------------------------------------

    def fetch_channel_layout(self, channel_seo: str, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Fetch the complete layout JSON for a linear TV channel with caching.
        """
        now = time.time()

        if not force_refresh:
            cached = self._layout_cache.get(channel_seo)
            if cached and (now - cached[1]) < self._CHANNEL_LAYOUT_CACHE_TTL:
                logger.debug(f"Using cached layout for {channel_seo}")
                return cached[0]

        oauth_token = self.auth.get_bearer_token()

        # Get Bedrock token - no parameters needed
        bedrock_token = self.auth.get_bedrock_token()

        url = self.cfg.get_bedrock_layout_url(channel_seo=channel_seo)
        location = f"https://plus.rtl.de/{channel_seo}/live"
        headers = self.cfg.get_bedrock_layout_headers(oauth_token, bedrock_token, location)

        params = {"blockPage": 1, "nbPages": 2}

        response = self.http.get(url, headers=headers, params=params, operation="api")
        response.raise_for_status()

        data = response.json()
        self._layout_cache[channel_seo] = (data, now)
        return data

    def extract_stream_assets(self, channel_seo: str) -> List[Dict[str, Any]]:
        """Extract all stream assets from a channel's layout."""
        layout = self.fetch_channel_layout(channel_seo)

        blocks = layout.get("blocks", [])
        for block in blocks:
            if block.get("type") == "bffPaginated":
                items = block.get("content", {}).get("items", [])
                for item in items:
                    if item.get("itemType") == "video":
                        video = item.get("itemContent", {}).get("video", {})
                        assets = video.get("assets", [])
                        if assets:
                            logger.debug(f"Found {len(assets)} assets for channel {channel_seo}")
                            return assets

        logger.warning(f"No stream assets found for channel {channel_seo}")
        return []

    def invalidate_layout_cache(self, channel_seo: str = None):
        """Invalidate layout cache for a specific channel or all channels."""
        if channel_seo:
            self._layout_cache.pop(channel_seo, None)
        else:
            self._layout_cache.clear()

    # --------------------------------------------------------------------------
    # Channel ID Normalization
    # --------------------------------------------------------------------------

    @staticmethod
    def _normalize_channel_identifier(channel_id: str) -> str:
        """
        Normalize a channel identifier to the SEO name used in layouts.

        Accepts either:
        - Slug: "rtlde_rtl" -> returns "rtl"
        - SEO: "rtl" -> returns "rtl"
        """
        if channel_id.startswith("rtlde_"):
            # Convert slug to seo
            normalized = channel_id.replace("rtlde_", "")
            logger.debug(f"Normalized slug '{channel_id}' to seo '{normalized}'")
            return normalized
        return channel_id

    # --------------------------------------------------------------------------
    # Manifest & DRM
    # --------------------------------------------------------------------------

    def get_best_manifest_url(
            self,
            channel_id: str,
            preferred_quality: str = None,
            preferred_format: str = None,
            preferred_drm_type: str = None,
    ) -> Optional[str]:
        """
        Get the best manifest URL for a channel based on preferences.

        Args:
            channel_id: Can be either slug (rtlde_rtl) or seo (rtl)
            preferred_quality
            preferred_format
            preferred_drm_type
        """
        # Normalize the channel identifier to SEO name
        channel_seo = self._normalize_channel_identifier(channel_id)

        assets = self.extract_stream_assets(channel_seo)

        quality_pref = preferred_quality or next(iter(self.cfg.preferred_qualities), "hd")
        format_pref = preferred_format or next(iter(self.cfg.preferred_formats), "dashcenc")
        drm_pref = preferred_drm_type or next(iter(self.cfg.preferred_drm_types), "hardware")

        # Try exact match
        for asset in assets:
            if (asset.get("quality") == quality_pref and
                    asset.get("format") == format_pref and
                    asset.get("drm", {}).get("type") == drm_pref):
                manifest_url = asset.get("path") or asset.get("reference")
                if manifest_url:
                    logger.info(f"Found exact match manifest for {channel_seo}")
                    return manifest_url

        # Try format + quality, any DRM
        for asset in assets:
            if asset.get("quality") == quality_pref and asset.get("format") == format_pref:
                manifest_url = asset.get("path") or asset.get("reference")
                if manifest_url:
                    logger.info(f"Found format/quality match manifest for {channel_seo}")
                    return manifest_url

        # Fallback to any asset from preferred formats
        for fmt in self.cfg.preferred_formats:
            for qual in self.cfg.preferred_qualities:
                for asset in assets:
                    if asset.get("format") == fmt and asset.get("quality") == qual:
                        manifest_url = asset.get("path") or asset.get("reference")
                        if manifest_url:
                            logger.info(f"Found fallback manifest for {channel_seo}")
                            return manifest_url

        # Last resort: any manifest URL
        for asset in assets:
            manifest_url = asset.get("path") or asset.get("reference")
            if manifest_url:
                logger.warning(f"Using last-resort manifest for {channel_seo}")
                return manifest_url

        logger.error(f"No manifest URL found for channel {channel_seo}")
        return None

    def get_drm_config_for_channel(
            self,
            channel_id: str,
            preferred_quality: str = None,
    ) -> List[DRMConfig]:
        """
        Get DRM configuration for a linear TV channel (Widevine only for now).
        """
        # Normalize the channel identifier to SEO name
        channel_seo = self._normalize_channel_identifier(channel_id)

        assets = self.extract_stream_assets(channel_seo)

        quality = preferred_quality or next(iter(self.cfg.preferred_qualities), "hd")

        drm_configs = []

        # Process DASH (Widevine) - this is the primary DRM
        for asset in assets:
            if asset.get("format") == "dashcenc" and asset.get("quality") == quality:
                drm_info = asset.get("drm", {})
                drm_config = drm_info.get("config", {})
                content_id = drm_config.get("contentId")

                if not content_id:
                    logger.warning(f"No contentId in DRM config for {channel_seo}")
                    continue

                try:
                    uid = self.auth.get_user_id_from_token()
                    if not uid:
                        logger.error(f"No user ID available for DRM on {channel_seo}")
                        continue

                    # Get upfront token - no extra parameters needed
                    upfront_token = self.auth.get_upfront_token(
                        content_id=content_id,
                        uid=uid,
                    )

                    license_url = self.cfg.drmtoday_license_url
                    headers = self.cfg.get_drm_license_headers(upfront_token)

                    drm_configs.append(DRMConfig(
                        system=DRMSystem.WIDEVINE,
                        priority=3,
                        license=LicenseConfig(
                            server_url=license_url,
                            req_headers=json.dumps(headers),
                            req_data="{CHA-RAW}",
                            use_http_get_request=False,
                        ),
                    ))
                    logger.debug(f"Added Widevine DRM for {channel_seo}")
                except Exception as e:
                    logger.error(f"Failed to get Widevine DRM for {channel_seo}: {e}")
                break  # Only need one DASH asset

        logger.info(f"Built {len(drm_configs)} DRM configs for {channel_seo}")
        return drm_configs

    # --------------------------------------------------------------------------
    # Channel Info Helpers
    # --------------------------------------------------------------------------

    def get_channel_info(self, channel_id: str) -> Optional[Dict[str, Any]]:
        """Get basic channel information from the layout."""
        channel_seo = self._normalize_channel_identifier(channel_id)
        try:
            layout = self.fetch_channel_layout(channel_seo)
            entity = layout.get("entity", {})
            metadata = entity.get("metadata", {})
            return {
                "id": entity.get("id"),
                "type": entity.get("type"),
                "title": metadata.get("title"),
                "code": metadata.get("code"),
                "seo": layout.get("parent", {}).get("seo"),
            }
        except Exception as e:
            logger.error(f"Failed to get channel info for {channel_id}: {e}")
            return None

    def get_current_program(self, channel_id: str) -> Optional[Dict[str, Any]]:
        """Get currently playing program info for a channel."""
        channel_seo = self._normalize_channel_identifier(channel_id)
        try:
            layout = self.fetch_channel_layout(channel_seo)

            blocks = layout.get("blocks", [])
            for block in blocks:
                if block.get("type") == "bffPaginated":
                    items = block.get("content", {}).get("items", [])
                    for item in items:
                        if item.get("itemType") == "video":
                            content = item.get("itemContent", {})
                            progress = content.get("progressBar", {})
                            video = content.get("video", {})
                            progress_data = video.get("progress", {})

                            return {
                                "title": content.get("title"),
                                "episode_title": content.get("extraTitle"),
                                "description": content.get("description"),
                                "progress_percent": progress.get("progressValue"),
                                "start_time": progress_data.get("startTitle"),
                                "end_time": progress_data.get("endTitle"),
                                "live": progress_data.get("live", {}),
                            }
            return None
        except Exception as e:
            logger.error(f"Failed to get current program for {channel_id}: {e}")
            return None