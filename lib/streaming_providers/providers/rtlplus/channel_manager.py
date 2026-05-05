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
from datetime import date

from ...base.models import Channel, DRMConfig
from ...base.utils.logger import logger


class RTLPlusChannelManager:
    """
    Manages linear TV channels for RTL+.

    Uses the authenticator for all token management.
    """

    def __init__(self, provider):
        self._provider = provider

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

                # Extract channel info
                channel_data = item_content.get("channel", {})
                title = channel_data.get("title")
                logo_id = channel_data.get("image", {}).get("id")

                # Extract action target for IDs
                action = item_content.get("action", {})
                target = action.get("target", {})

                # Handle "lock" wrapper — API wraps targets in a lock when consent is required
                if target.get("type") == "lock":
                    target = target.get("value_lock", {}).get("originalTarget", {})

                value_layout = target.get("value_layout", {})

                slug = value_layout.get("id")  # e.g., "rtlde_rtl"
                seo = value_layout.get("seo")  # e.g., "rtl"

                logger.debug(f"Extracted: title='{title}', slug='{slug}', seo='{seo}', logo_id='{logo_id}'")

                if slug is None:
                    # Try alternative path - sometimes the ID might be directly in itemContent
                    alt_id = item_content.get("id")
                    if alt_id:
                        slug = alt_id
                        logger.debug(f"Using alternative id: {slug}")

                if not slug:
                    logger.warning(f"Could not extract slug for channel '{title}', skipping")
                    continue

                channel = {
                    "id": channel_data.get("id"),
                    "title": title,
                    "seo": seo,
                    "slug": slug,
                    "logo_id": logo_id,
                    "channel_type": "BROADCAST",
                }
                channels.append(channel)

        logger.info(f"Found {len(channels)} channels from EPG grid")

        # Log first few channels for debugging
        for ch in channels[:3]:
            logger.debug(f"Channel: {ch['title']} -> slug={ch['slug']}, seo={ch['seo']}")

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
                channel_id=content_id,
                provider=self._provider.provider_name,
            )

            # Set logo URL
            streaming_channel.logo_url = self._resolve_image_url(logo_id)

            # Store SEO in manifest_script for fallback lookups
            if seo:
                streaming_channel.manifest_script = seo

            logger.debug(f"Created channel: name={title}, id={streaming_channel.content_id}, "
                        f"manifest_script={streaming_channel.manifest_script}")

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
    # Manifest & DRM (using provider's common methods)
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
        """
        token = self._provider.get_user_bearer_token()
        if not token:
            logger.error("User authentication required for linear TV stream, not authenticated")
            return None

        # Ensure profile is selected
        if not self.auth.ensure_profile_selected():
            logger.error("Failed to select profile for channel stream")
            return None

        channel_seo = self._normalize_channel_identifier(channel_id)

        # Use provider's common layout fetching
        layout = self._provider.fetch_layout(
            layout_type="live",
            content_id=channel_seo,
            location=f"{self.cfg.base_website}{channel_seo}/live"
        )

        if not layout:
            return None

        # Extract assets using common method
        assets = self._provider.extract_video_assets(layout)

        # Extract best manifest URL using common method
        return self._provider.extract_best_manifest_url(assets, preferred_quality, preferred_format)

    def get_drm_config_for_channel(self, channel_id: str) -> List[DRMConfig]:
        """
        Get DRM configuration for a linear TV channel.
        """
        channel_seo = self._normalize_channel_identifier(channel_id)

        # Use provider's common layout fetching
        layout = self._provider.fetch_layout(
            layout_type="live",
            content_id=channel_seo,
            location=f"{self.cfg.base_website}{channel_seo}/live"
        )

        if not layout:
            return []

        # Delegate to provider's common DRM method
        return self._provider.get_drm_for_content(layout)

    # --------------------------------------------------------------------------
    # Channel Info Helpers
    # --------------------------------------------------------------------------

    def get_channel_info(self, channel_id: str) -> Optional[Dict[str, Any]]:
        """Get basic channel information from the layout."""
        channel_seo = self._normalize_channel_identifier(channel_id)

        layout = self._provider.fetch_layout(
            layout_type="live",
            content_id=channel_seo,
            location=f"{self.cfg.base_website}{channel_seo}/live"
        )

        if not layout:
            return None

        entity = layout.get("entity", {})
        metadata = entity.get("metadata", {})
        return {
            "id": entity.get("id"),
            "type": entity.get("type"),
            "title": metadata.get("title"),
            "code": metadata.get("code"),
            "seo": layout.get("parent", {}).get("seo"),
        }

    def get_current_program(self, channel_id: str) -> Optional[Dict[str, Any]]:
        """Get currently playing program info for a channel."""
        channel_seo = self._normalize_channel_identifier(channel_id)

        layout = self._provider.fetch_layout(
            layout_type="live",
            content_id=channel_seo,
            location=f"{self.cfg.base_website}{channel_seo}/live"
        )

        if not layout:
            return None

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