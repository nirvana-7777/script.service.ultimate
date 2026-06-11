# streaming_providers/base/manager.py
"""
Main ProviderManager as a facade coordinating all operations.
Maintains backward compatibility while delegating to specialized classes.
"""

from typing import Any, Dict, List, Optional

from .catchup_operations import CatchupOperations
from .channel_operations import ChannelOperations
from .drm_operations import DRMOperations
from .epg_operations import EPGOperations
from .event_operations import EventOperations
from .vod_operations import VodOperations
from .recording_operations import RecordingOperations
from .timer_operations import TimerOperations
from .bookmark_operations import BookmarkOperations
from .favorite_operations import FavoriteOperations
from .models import StreamingChannel
from .models.bookmark import Bookmark, ContentType
from .models.favorite import FavoriteType, Favorite
from .provider_registry import ProviderRegistry
from .subscription_operations import SubscriptionOperations
from .utils.logger import logger


class ProviderManager:
    """
    Facade coordinating all provider-related operations.
    Maintains backward compatibility while delegating to specialized classes.
    """

    def __init__(self):
        # Core components
        self.registry = ProviderRegistry()

        # Specialized operations
        self.channel_ops = ChannelOperations(self.registry)
        self.epg_ops = EPGOperations(self.registry)
        self.drm_ops = DRMOperations(self.registry)
        self.catchup_ops = CatchupOperations(self.registry, self.drm_ops)
        self.subscription_ops = SubscriptionOperations(self.registry)
        self.event_ops = EventOperations(self.registry)
        self.vod_ops = VodOperations(self.registry)
        self.recording_ops = RecordingOperations(self.registry)
        self.timer_ops = TimerOperations(self.registry)
        self.bookmark_ops = BookmarkOperations(self.registry)
        self.favorite_ops = FavoriteOperations(self.registry)

        # Backward compatibility - expose managers directly
        self.drm_plugin_manager = self.drm_ops.drm_plugin_manager
        self.epg_manager = self.epg_ops.epg_manager

        # Legacy compatibility - expose providers dict
        self.providers = self.registry.providers
        self.provider_metadata = self.registry.provider_metadata

        logger.info("ProviderManager: Initialized with modular architecture")

    # ==========================================================================
    # REGISTRY OPERATIONS (delegate to ProviderRegistry)
    # ==========================================================================

    def discover_all_providers(self, default_country: str = "DE") -> List[str]:
        return self.registry.discover_all_providers(default_country)

    def discover_providers(self, country: str = "DE", detected_providers: Dict = None) -> List[str]:
        """Legacy method for backward compatibility."""
        if not self.registry.provider_metadata:
            self.registry.discover_all_providers(country)
        return self.registry.get_enabled_providers()

    def rediscover_providers(self, country: str = "DE") -> List[str]:
        """
        Re-scan for new providers, particularly useful for dynamically added M3U playlists.

        Args:
            country: Country code for provider discovery

        Returns:
            List of all discovered provider names
        """
        logger.info(f"ProviderManager: Re-discovering providers for country '{country}'...")
        discovered = self.registry.discover_all_providers(country)
        logger.info(f"ProviderManager: Re-discovery complete. Found {len(discovered)} providers")
        return discovered

    def get_provider(self, provider_name: str):
        return self.registry.get_provider(provider_name)

    def set_provider_enabled(self, provider_name: str, enabled: bool) -> bool:
        return self.registry.set_provider_enabled(provider_name, enabled)

    def get_all_providers_metadata(self) -> List[Dict[str, Any]]:
        return self.registry.get_all_providers_metadata()

    def reinitialize_provider(self, provider_name: str) -> bool:
        return self.registry.reinitialize_provider(provider_name)

    def reinitialize_providers(self, provider_names: List[str]) -> Dict[str, bool]:
        return {name: self.registry.reinitialize_provider(name) for name in provider_names}

    def reinitialize_all_providers(self) -> Dict[str, bool]:
        enabled = self.registry.get_enabled_providers()
        return self.reinitialize_providers(enabled)

    def list_providers(self) -> List[str]:
        return self.registry.list_providers()

    def list_all_providers(self) -> List[str]:
        return self.registry.list_all_providers()

    def clear_providers(self):
        self.registry.clear_providers()

    @staticmethod
    def get_provider_class(provider_name: str):
        """Get provider class from AVAILABLE_PROVIDERS registry."""
        from streaming_providers import AVAILABLE_PROVIDERS

        # Remove country suffix if present
        base_name = provider_name
        if "_" in provider_name:
            name_parts = provider_name.rsplit("_", 1)
            if len(name_parts[1]) in (2, 3) and name_parts[1].isalpha():
                base_name = name_parts[0]

        return AVAILABLE_PROVIDERS.get(base_name)

    # ==========================================================================
    # CHANNEL OPERATIONS (delegate to ChannelOperations)
    # ==========================================================================

    def get_channels(
            self, provider_name: str, fetch_manifests: bool = False, **kwargs
    ) -> List[StreamingChannel]:
        return self.channel_ops.get_channels(provider_name, fetch_manifests, **kwargs)

    def get_channel_manifest(self, provider_name: str, channel_id: str, **kwargs) -> Optional[str]:
        return self.channel_ops.get_channel_manifest(provider_name, channel_id, **kwargs)

    def get_all_channels(
            self, fetch_manifests: bool = True, **kwargs
    ) -> Dict[str, List[StreamingChannel]]:
        return self.channel_ops.get_all_channels(fetch_manifests, **kwargs)

    # ==========================================================================
    # EPG OPERATIONS (delegate to EPGOperations)
    # ==========================================================================

    def get_channel_epg(self, provider_name: str, channel_id: str, **kwargs) -> List[Dict]:
        return self.epg_ops.get_channel_epg(provider_name, channel_id, **kwargs)

    def get_provider_epg_xmltv(self, provider_name: str, **kwargs) -> Optional[str]:
        return self.epg_ops.get_provider_epg_xmltv(provider_name, **kwargs)

    def clear_epg_cache(self) -> bool:
        return self.epg_ops.clear_epg_cache()

    def reload_epg_mapping(self) -> bool:
        return self.epg_ops.reload_epg_mapping()

    def get_epg_cache_info(self) -> Optional[Dict]:
        return self.epg_ops.get_epg_cache_info()

    def get_epg_mapping_stats(self) -> Dict:
        return self.epg_ops.get_epg_mapping_stats()

    def has_epg_mapping(self, provider_name: str, channel_id: str) -> bool:
        return self.epg_ops.has_epg_mapping(provider_name, channel_id)

    # ==========================================================================
    # DRM OPERATIONS (delegate to DRMOperations)
    # ==========================================================================

    def get_channel_drm_configs(self, provider_name: str, channel_id: str, **kwargs) -> List:
        return self.drm_ops.get_content_drm_configs(provider_name, channel_id, **kwargs)

    def list_drm_plugins(self) -> Dict:
        return self.drm_ops.list_drm_plugins()

    def clear_drm_plugins(self):
        self.drm_ops.clear_drm_plugins()

    # ==========================================================================
    # CATCHUP OPERATIONS (delegate to CatchupOperations)
    # ==========================================================================

    def get_catchup_manifest(
            self,
            provider_name: str,
            channel_id: str,
            start_time: int,
            end_time: int,
            epg_id: Optional[str] = None,
            country: Optional[str] = None,
    ) -> Optional[str]:
        return self.catchup_ops.get_catchup_manifest(
            provider_name, channel_id, start_time, end_time, epg_id, country
        )

    def get_catchup_drm_configs(
            self,
            provider_name: str,
            channel_id: str,
            start_time: int,
            end_time: int,
            epg_id: Optional[str] = None,
            country: Optional[str] = None,
            drm_variant: Optional[str] = None,
    ) -> List:
        return self.catchup_ops.get_catchup_drm_configs(
            provider_name, channel_id, start_time, end_time, epg_id, country, drm_variant=drm_variant
        )

    def get_catchup_window(self, provider_name: str, channel_id: Optional[str] = None) -> int:
        return self.catchup_ops.get_catchup_window(provider_name, channel_id)

    def supports_catchup(self, provider_name: str) -> bool:
        return self.catchup_ops.supports_catchup(provider_name)

    def get_all_catchup_capabilities(self) -> Dict[str, Dict]:
        return self.catchup_ops.get_all_catchup_capabilities()

    # ==========================================================================
    # EVENT OPERATIONS (delegate to EventOperations)
    # ==========================================================================

    def get_events(
        self,
        provider_name: str,
        start_time=None,
        end_time=None,
    ):
        return self.event_ops.get_events(provider_name, start_time, end_time)

    def get_all_events(self, start_time=None, end_time=None):
        return self.event_ops.get_all_events(start_time, end_time)

    def get_event_manifest(self, provider_name: str, event_id: str, **kwargs) -> Optional[str]:
        return self.event_ops.get_event_manifest(provider_name, event_id, **kwargs)

    def get_event_drm_configs(self, provider_name: str, event_id: str, **kwargs) -> List:
        return self.drm_ops.get_content_drm_configs(provider_name, event_id, **kwargs)

    # ==========================================================================
    # VOD OPERATIONS (delegate to VodOperations)
    # ==========================================================================

    def get_vod_node(
        self,
        provider_name: str,
        content_id: str = "",
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kwargs,
    ) -> dict:
        return self.vod_ops.get_vod_node(
            provider_name,
            content_id=content_id,
            cursor=cursor,
            page_size=page_size,
            **kwargs,
        )

    def get_vod_manifest(self, provider_name: str, vod_id: str, **kwargs):
        return self.vod_ops.get_vod_manifest(provider_name, vod_id, **kwargs)

    def get_vod_drm_configs(self, provider_name: str, vod_id: str, **kwargs) -> list:
        return self.drm_ops.get_content_drm_configs(provider_name, vod_id, **kwargs)

    def get_all_vod_roots(self) -> dict:
        return self.vod_ops.get_all_vod_roots()

    def search_vod(
            self,
            provider_name: str,
            query: str,
            cursor: Optional[str] = None,
            page_size: int = 24,
            **kwargs,
    ) -> dict:
        """Search VOD catalogue of a single provider."""
        return self.vod_ops.search_vod(
            provider_name,
            query=query,
            cursor=cursor,
            page_size=page_size,
            **kwargs,
        )

    # Keep this for searching across all providers
    def search_all_vod(self, query: str, **kwargs) -> dict:
        """Search VOD across all providers."""
        return self.vod_ops.search_all_vod(query, **kwargs)

    # ==========================================================================
    # RECORDING OPERATIONS (delegate to RecordingOperations)
    # ==========================================================================

    def get_recordings(
            self,
            provider_name: str,
            include_deleted: bool = False,
    ):
        return self.recording_ops.get_recordings(
            provider_name, include_deleted=include_deleted
        )

    def get_all_recordings(self, include_deleted: bool = False):
        return self.recording_ops.get_all_recordings(
            include_deleted=include_deleted
        )

    def get_recording_manifest(
            self, provider_name: str, recording_id: str, **kwargs
    ) -> Optional[str]:
        return self.recording_ops.get_recording_manifest(
            provider_name, recording_id, **kwargs
        )

    def get_recording_drm_configs(
            self, provider_name: str, recording_id: str, **kwargs
    ) -> List:
        # Reuses the same DRM resolution path as channels, events, and VOD.
        return self.drm_ops.get_content_drm_configs(
            provider_name, recording_id, **kwargs
        )

    def delete_recording(
            self, provider_name: str, recording_id: str, **kwargs
    ) -> None:
        return self.recording_ops.delete_recording(
            provider_name, recording_id, **kwargs
        )

    # ==========================================================================
    # TIMER OPERATIONS (delegate to TimerOperations)
    # ==========================================================================

    def get_timer_types(self, provider_name: str) -> List:
        return self.timer_ops.get_timer_types(provider_name)

    def get_all_timer_types(self) -> Dict[str, List]:
        return self.timer_ops.get_all_timer_types()

    def get_timers(
            self,
            provider_name: str,
            include_inactive: bool = False,
    ) -> List:
        return self.timer_ops.get_timers(
            provider_name, include_inactive=include_inactive
        )

    def get_all_timers(self, include_inactive: bool = False) -> Dict[str, List]:
        return self.timer_ops.get_all_timers(include_inactive=include_inactive)

    def get_timer(self, provider_name: str, client_index: int):
        return self.timer_ops.get_timer(provider_name, client_index)

    def add_timer(self, provider_name: str, timer, **kwargs):
        return self.timer_ops.add_timer(provider_name, timer, **kwargs)

    def update_timer(self, provider_name: str, timer, **kwargs):
        return self.timer_ops.update_timer(provider_name, timer, **kwargs)

    def delete_timer(
            self,
            provider_name: str,
            client_index: int,
            force_delete: bool = False,
            **kwargs,
    ) -> None:
        return self.timer_ops.delete_timer(
            provider_name, client_index, force_delete=force_delete, **kwargs
        )

    # ==========================================================================
    # BOOKMARK OPERATIONS (delegate to BookmarkOperations)
    # ==========================================================================

    def get_bookmarks(
            self,
            provider_name: str,
            content_type: Optional[ContentType] = None,
            include_completed: bool = False,
            include_stale: bool = False,
            max_age_hours: int = 720,
    ) -> List[Bookmark]:
        """
        Get bookmarks from a specific provider.

        Args:
            provider_name: Name of the provider to query.
            content_type: Optional filter by content type.
            include_completed: If True, include completed bookmarks.
            include_stale: If True, include stale bookmarks.
            max_age_hours: Maximum age before a bookmark is considered stale.

        Returns:
            List of Bookmark objects.

        Raises:
            ValueError: If the provider is not found or disabled.
        """
        return self.bookmark_ops.get_bookmarks(
            provider_name,
            content_type=content_type,
            include_completed=include_completed,
            include_stale=include_stale,
            max_age_hours=max_age_hours,
        )

    def get_bookmark(
            self, provider_name: str, content_id: str
    ) -> Optional[Bookmark]:
        """
        Get a specific bookmark by content ID from a provider.

        Args:
            provider_name: Name of the provider.
            content_id: Content identifier.

        Returns:
            Bookmark object if found, None otherwise.

        Raises:
            ValueError: If the provider is not found or disabled.
        """
        return self.bookmark_ops.get_bookmark(provider_name, content_id)

    def update_bookmark(
            self,
            provider_name: str,
            content_id: str,
            content_type: ContentType,
            position_seconds: int,
            duration_seconds: Optional[int] = None,
            title: Optional[str] = None,
            **kwargs,
    ) -> Optional[Bookmark]:
        """
        Update or create a bookmark for a specific content.

        Args:
            provider_name: Name of the provider.
            content_id: Content identifier.
            content_type: Type of content being bookmarked.
            position_seconds: Playback position in seconds (0 = start, -1 = completed).
            duration_seconds: Total duration of the content (optional).
            title: Content title for caching (optional).
            **kwargs: Additional metadata (thumbnail_url, series_title, etc.).

        Returns:
            Updated Bookmark object, or None if provider doesn't support bookmarks.

        Raises:
            ValueError: If the provider is not found or disabled.
            RuntimeError: If the provider rejects the update.
        """
        return self.bookmark_ops.update_bookmark(
            provider_name,
            content_id,
            content_type,
            position_seconds,
            duration_seconds=duration_seconds,
            title=title,
            **kwargs,
        )

    def delete_bookmark(
            self, provider_name: str, content_id: str
    ) -> bool:
        """
        Delete a bookmark from a specific provider.

        Args:
            provider_name: Name of the provider.
            content_id: Content identifier.

        Returns:
            True if deleted, False if bookmark didn't exist or provider doesn't support.

        Raises:
            ValueError: If the provider is not found or disabled.
            RuntimeError: If the provider refuses deletion.
        """
        return self.bookmark_ops.delete_bookmark(provider_name, content_id)

    def mark_bookmark_completed(
            self,
            provider_name: str,
            content_id: str,
            content_type: ContentType,
            duration_seconds: Optional[int] = None,
            title: Optional[str] = None,
            **kwargs,
    ) -> Optional[Bookmark]:
        """
        Mark a content as completed (watched to end).

        Args:
            provider_name: Name of the provider.
            content_id: Content identifier.
            content_type: Type of content.
            duration_seconds: Total duration (optional).
            title: Content title (optional).
            **kwargs: Additional metadata.

        Returns:
            Updated Bookmark with position set to -1, or None if not supported.

        Raises:
            ValueError: If the provider is not found or disabled.
        """
        return self.bookmark_ops.mark_completed(
            provider_name,
            content_id,
            content_type,
            duration_seconds=duration_seconds,
            title=title,
            **kwargs,
        )

    def get_all_bookmarks(
            self,
            content_type: Optional[ContentType] = None,
            include_completed: bool = False,
            include_stale: bool = False,
            max_age_hours: int = 720,
    ) -> Dict[str, List[Bookmark]]:
        """
        Get bookmarks from all enabled providers.

        Args:
            content_type: Optional filter by content type.
            include_completed: If True, include completed bookmarks.
            include_stale: If True, include stale bookmarks.
            max_age_hours: Maximum age for stale detection.

        Returns:
            Dict mapping provider name → list of Bookmark objects.
            Failed providers are represented by an '_errors' key.
        """
        return self.bookmark_ops.get_all_bookmarks(
            content_type=content_type,
            include_completed=include_completed,
            include_stale=include_stale,
            max_age_hours=max_age_hours,
        )

    def get_all_bookmarks_flat(
            self,
            content_type: Optional[ContentType] = None,
            include_completed: bool = False,
            include_stale: bool = False,
            max_age_hours: int = 720,
            sort_by: str = "last_updated",
    ) -> List[Bookmark]:
        """
        Get all bookmarks as a flat list sorted by the specified field.

        Args:
            content_type: Optional filter by content type.
            include_completed: If True, include completed bookmarks.
            include_stale: If True, include stale bookmarks.
            max_age_hours: Maximum age for stale detection.
            sort_by: Sort field ('last_updated', 'created_at', 'title', 'provider').

        Returns:
            Flat list of Bookmark objects sorted by sort_by.

        Raises:
            ValueError: If sort_by is not a recognised field.
        """
        return self.bookmark_ops.get_all_bookmarks_flat(
            content_type=content_type,
            include_completed=include_completed,
            include_stale=include_stale,
            max_age_hours=max_age_hours,
            sort_by=sort_by,
        )

    def delete_all_bookmarks_for_content(
            self,
            content_id: str,
            provider_filter: Optional[List[str]] = None,
    ) -> Dict[str, bool]:
        """
        Delete bookmarks for a specific content ID across all providers.

        Useful when content is removed from a provider.

        Args:
            content_id: Content identifier to delete.
            provider_filter: Optional list of provider names to restrict deletion.

        Returns:
            Dict mapping provider name → True if deleted, False if not found.
        """
        return self.bookmark_ops.delete_all_bookmarks_for_content(
            content_id, provider_filter=provider_filter
        )

    def cleanup_stale_bookmarks(
            self,
            max_age_hours: int = 720,
            dry_run: bool = True,
            provider_filter: Optional[List[str]] = None,
    ) -> Dict[str, int]:
        """
        Remove bookmarks older than max_age_hours.

        Args:
            max_age_hours: Age threshold in hours (default 720 = 30 days).
            dry_run: If True, only report what would be deleted without actually deleting.
            provider_filter: Optional list of provider names to restrict cleanup.

        Returns:
            Dict mapping provider name → number of bookmarks deleted (or would-be deleted).
        """
        return self.bookmark_ops.cleanup_stale_bookmarks(
            max_age_hours=max_age_hours,
            dry_run=dry_run,
            provider_filter=provider_filter,
        )

    def get_bookmark_stats(self, max_age_hours: int = 720) -> Dict[str, Any]:
        """
        Get statistics about bookmarks across all providers.

        Args:
            max_age_hours: Age threshold used for staleness classification.

        Returns:
            Dictionary with counts by status, content type, and provider.
        """
        return self.bookmark_ops.get_bookmark_stats(max_age_hours=max_age_hours)

    def validate_bookmarks(
            self, provider_name: str, auto_fix: bool = False
    ) -> Dict[str, Any]:
        """
        Validate all bookmarks from a provider and optionally fix common issues.

        Args:
            provider_name: Name of the provider.
            auto_fix: If True, attempt to fix fixable issues.

        Returns:
            Dictionary with validation results (total, errors, warnings, fixed).
        """
        return self.bookmark_ops.validate_bookmarks(provider_name, auto_fix=auto_fix)

    # ==========================================================================
    # Favorite OPERATIONS (delegate to FavoriteOperations)
    # ==========================================================================

    def get_favorites(
            self,
            provider_name: str,
            favorite_type: Optional[FavoriteType] = None,
    ) -> List[Favorite]:
        """Get favorites from a specific provider."""
        return self.favorite_ops.get_favorites(provider_name, favorite_type)

    def add_favorite(
            self,
            provider_name: str,
            content_id: str,
            favorite_type: FavoriteType,
            title: Optional[str] = None,
            **kwargs,
    ) -> Optional[Favorite]:
        """Add a favorite."""
        return self.favorite_ops.add_favorite(
            provider_name, content_id, favorite_type, title, **kwargs
        )

    def remove_favorite(
            self, provider_name: str, content_id: str
    ) -> bool:
        """Remove a favorite."""
        return self.favorite_ops.remove_favorite(provider_name, content_id)

    def get_all_favorites(
            self,
            favorite_type: Optional[FavoriteType] = None,
    ) -> Dict[str, List[Favorite]]:
        """Get favorites from all enabled providers."""
        return self.favorite_ops.get_all_favorites(favorite_type)

    def is_favorited(
            self, provider_name: str, content_id: str
    ) -> bool:
        """Check if content is favorited."""
        return self.favorite_ops.is_favorited(provider_name, content_id)

    # ==========================================================================
    # SUBSCRIPTION OPERATIONS (delegate to SubscriptionOperations)
    # ==========================================================================

    def get_subscription_status(self, provider_name: str, **kwargs):
        return self.subscription_ops.get_subscription_status(provider_name, **kwargs)

    def get_subscribed_channels(self, provider_name: str, **kwargs):
        return self.subscription_ops.get_subscribed_channels(provider_name, **kwargs)

    def get_available_packages(self, provider_name: str, **kwargs):
        return self.subscription_ops.get_available_packages(provider_name, **kwargs)

    def is_channel_accessible(self, provider_name: str, channel_id: str, **kwargs):
        return self.subscription_ops.is_channel_accessible(provider_name, channel_id, **kwargs)

    # ==========================================================================
    # UTILITY METHODS (remain in ProviderManager as helpers)
    # ==========================================================================

    def get_provider_http_manager(self, provider_name: str):
        """Get HTTP manager for a specific provider."""
        provider = self.get_provider(provider_name)
        if not provider:
            logger.warning(f"ProviderManager: Provider '{provider_name}' not found")
            return None

        http_manager = provider.http_manager
        if not http_manager:
            logger.warning(f"ProviderManager: Provider '{provider_name}' has no HTTP manager")
            return None

        logger.debug(f"ProviderManager: Retrieved HTTP manager for '{provider_name}'")
        return http_manager

    def needs_proxy(self, provider_name: str) -> bool:
        """Check if a provider needs proxy support."""
        http_manager = self.get_provider_http_manager(provider_name)
        if not http_manager:
            return False

        has_proxy = http_manager.config.proxy_config is not None
        logger.debug(
            f"ProviderManager: Provider '{provider_name}' {'requires' if has_proxy else 'does not require'} proxy"
        )
        return has_proxy

    def get_provider_choices(self) -> Dict[int, str]:
        """
        Get numbered provider choices for user selection.
        Includes an 'all' option as the last choice.
        """
        enabled_providers = self.registry.get_enabled_providers()
        choices = {i + 1: name for i, name in enumerate(enabled_providers)}
        choices[len(choices) + 1] = "all"
        return choices

    def get_selected_providers(self, choices_input: str) -> List[str]:
        """
        Convert user input string to list of provider names.

        Args:
            choices_input: Comma-separated string of choice numbers

        Returns:
            List of selected provider names
        """
        available = self.registry.get_enabled_providers()

        if not available:
            logger.warning("ProviderManager: No enabled providers available for selection")
            return []

        selected = []
        for choice in choices_input.split(","):
            choice = choice.strip()
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(available):
                    selected.append(available[idx])
                elif idx == len(available):  # 'all' option
                    selected = available.copy()
                    break

        result = selected if selected else available
        logger.debug(
            f"ProviderManager: Selected {len(result)} providers from input '{choices_input}'"
        )
        return result

    # ==========================================================================
    # LEGACY COMPATIBILITY METHODS
    # ==========================================================================

    def _extract_pssh_from_manifest(self, manifest_url: str) -> List:
        """
        Extract PSSH data from a manifest URL.
        Kept for backward compatibility but delegated to DRMOperations.
        """
        return self.drm_ops._extract_pssh_from_manifest(manifest_url)