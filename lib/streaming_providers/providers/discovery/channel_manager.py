# streaming_providers/providers/discovery/channel_manager.py
"""
Discovery+ Channel Manager

Handles CMS channel extraction, distribution channel parsing,
and CMS navigation route discovery from the /home response graph.
"""
from typing import Dict, List, Optional

from ...base.models import StreamingChannel
from ...base.utils.logger import logger

from .constants import (
    CMS_INCLUDE_PARAMS,
    CMS_PAGE_SIZE,
    CMS_ROUTE_SPORT_SCHEDULE,
)
from .models import DiscoveryChannel


class DiscoveryChannelManager:
    """
    Manages channel extraction and CMS route discovery for Discovery+.

    Responsibilities:
    - Fetching and parsing distribution channels from the CMS /home route
    - Maintaining the ``_channels_cache`` (channel_id → DiscoveryChannel)
    - Discovering and caching navigation routes from the /home response graph
      into ``_cms_routes`` (route_id → label)

    Both caches are owned by the provider and passed in by reference so that
    the event manager and playback manager can share them without coupling
    directly to this class.
    """

    def __init__(
            self,
            provider,  # DiscoveryProvider — avoid circular import with a late reference
            channels_cache: Dict[str, DiscoveryChannel],
            cms_routes: Dict[str, str],
    ):
        self._provider = provider
        self._channels_cache = channels_cache
        self._cms_routes = cms_routes

    # =========================================================================
    # Public interface
    # =========================================================================

    def fetch_channels(
            self,
            fetch_manifests: bool = False,
            populate_streaming_data: bool = True,
    ) -> List[StreamingChannel]:
        """
        Fetch available channels from the Discovery+ CMS /home route.

        Populates ``_channels_cache`` with DiscoveryChannel objects and
        refreshes ``_cms_routes`` from the navigation graph embedded in the
        same response (avoiding a second round-trip).

        Args:
            fetch_manifests: Whether to immediately populate streaming data.
            populate_streaming_data: Whether to populate streaming data.

        Returns:
            List of StreamingChannel objects.
        """
        try:
            headers = self._provider.get_auth_headers()
            url = self._provider.authenticator.cms_home_endpoint
            params = {
                "include": CMS_INCLUDE_PARAMS,
                "decorators": "viewingHistory,isFavorite,contentAction,badges",
                "page[items.size]": CMS_PAGE_SIZE,
            }

            response = self._provider.http_manager.get(
                url,
                operation="cms",
                headers=headers,
                params=params,
            )
            response.raise_for_status()
            data = response.json()

            # Refresh CMS route cache from this /home response.
            refreshed = self._discover_cms_routes(data)
            if refreshed:
                self._cms_routes.clear()
                self._cms_routes.update(refreshed)
                logger.debug(
                    f"CMS routes refreshed: {list(self._cms_routes.keys())}"
                )

            # Extract channels and populate the shared cache
            discovery_channels = self._extract_distribution_channels(data)
            self._channels_cache.clear()
            self._channels_cache.update(
                {ch.channel_id: ch for ch in discovery_channels}
            )

            # Convert to StreamingChannel objects
            streaming_channels = [
                ch.to_streaming_channel(self._provider.provider_name)
                for ch in discovery_channels
            ]

            logger.info(
                f"Found {len(streaming_channels)} distribution channels"
            )

            if fetch_manifests and populate_streaming_data and streaming_channels:
                streaming_channels = (
                    self._provider.playback_manager.populate_streaming_data(
                        streaming_channels
                    )
                )

            return streaming_channels

        except Exception as e:
            logger.error(f"Error fetching channels: {e}")
            return []

    def init_cms_routes(self) -> None:
        """
        Fetch ``/home`` and populate ``_cms_routes`` eagerly.

        Called once at the end of ``DiscoveryProvider.__init__`` so route
        discovery is complete before any call to ``get_events()`` or
        ``get_channels()``.  Failures are caught and logged — the provider
        remains usable and ``get_events()`` will fall back to
        ``CMS_ROUTE_SPORT_SCHEDULE``.
        """
        try:
            headers = self._provider.get_auth_headers()
            url = self._provider.authenticator.cms_home_endpoint
            params = {
                "include": CMS_INCLUDE_PARAMS,
                "decorators": "viewingHistory,isFavorite,contentAction,badges",
                "page[items.size]": CMS_PAGE_SIZE,
            }
            response = self._provider.http_manager.get(
                url,
                operation="cms",
                headers=headers,
                params=params,
            )
            response.raise_for_status()
            data = response.json()
            routes = self._discover_cms_routes(data)
            self._cms_routes.update(routes)
            if routes:
                logger.debug(
                    f"CMS routes discovered at init: {list(self._cms_routes.keys())}"
                )
            else:
                logger.warning(
                    "CMS route discovery returned no routes — "
                    f"get_events() will fall back to '{CMS_ROUTE_SPORT_SCHEDULE}'"
                )
        except Exception as e:
            logger.warning(f"Could not discover CMS routes at init: {e}")

    # =========================================================================
    # CMS route discovery
    # =========================================================================

    @staticmethod
    def _discover_cms_routes(data: dict) -> Dict[str, str]:
        """
        Parse a /home CMS response and return a map of all navigation routes.

        The /home response contains a ``data.relationships.navigationLinks``
        array whose entries are resolved via the top-level ``included`` list.
        Each resolved node has ``attributes.url`` (e.g. ``"/sports"``) and
        ``attributes.label`` (localised display name).

        Returns:
            dict mapping route_id → label, e.g.
            ``{"sports": "Sport", "channels": "Kanäle", "home": "Home"}``
            Returns an empty dict if the navigation graph is absent.
        """
        included_by_id: Dict[str, dict] = {
            f"{item['type']}:{item['id']}": item
            for item in data.get("included", [])
            if item.get("id") and item.get("type")
        }
        nav_refs = (
            data.get("data", {})
                .get("relationships", {})
                .get("navigationLinks", {})
                .get("data", [])
        )
        if not nav_refs:
            logger.debug(
                "_discover_cms_routes: no navigationLinks found in /home response"
            )
            return {}

        routes: Dict[str, str] = {}
        for ref in nav_refs:
            key = f"{ref.get('type', 'link')}:{ref['id']}"
            node = included_by_id.get(key, {})
            attrs = node.get("attributes", {})
            url_path = attrs.get("url", "").lstrip("/")
            route_id = url_path or ref["id"]
            label = attrs.get("label", route_id)
            routes[route_id] = label

        return routes

    # =========================================================================
    # Channel extraction helpers
    # =========================================================================

    def _extract_distribution_channels(
            self, data: Dict
    ) -> List[DiscoveryChannel]:
        """
        Extract distributionChannel objects from a CMS response.

        Args:
            data: Parsed JSON response from the CMS home route.

        Returns:
            List of DiscoveryChannel objects.
        """
        channels = []

        included_by_id: Dict[str, dict] = {}
        for item in data.get("included", []):
            item_id = item.get("id")
            item_type = item.get("type")
            if item_id and item_type:
                included_by_id[f"{item_type}:{item_id}"] = item

        for item in data.get("included", []):
            if item.get("type") == "distributionChannel":
                channel = self._create_discovery_channel_from_distribution(
                    item, included_by_id
                )
                if channel:
                    channels.append(channel)

        return channels

    @staticmethod
    def _create_discovery_channel_from_distribution(
            distribution_data: Dict,
            included_by_id: Dict,
    ) -> Optional[DiscoveryChannel]:
        """
        Create a DiscoveryChannel from a distributionChannel CMS object.

        Args:
            distribution_data: The distributionChannel item from the CMS.
            included_by_id: Lookup dict of all included items (``type:id`` → item).

        Returns:
            DiscoveryChannel instance, or None if the data is invalid.
        """
        try:
            discovery_channel = DiscoveryChannel.from_distribution_data(
                distribution_data, included_by_id
            )
            logger.debug(
                f"Created channel: {discovery_channel.name} "
                f"(edit_id: {discovery_channel.edit_id})"
            )
            return discovery_channel
        except Exception as e:
            logger.error(
                f"Error creating channel from distribution data: {e}"
            )
            return None