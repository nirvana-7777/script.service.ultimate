# streaming_providers/providers/rtlplus/event_manager.py
"""
RTL+ Event Manager

Handles fetching future/live events from Bedrock layout API.
Uses the homepage's "Diese Live-Events erwarten euch" block as primary source.
Follows non-sequential pagination (1 → 3 → 6 → ...) as returned by the API.
"""

import json
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Set

from ...base.models.event import Event, EventStatus
from ...base.utils.logger import logger
from ...base.models import DRMConfig
from .layout_helpers import unwrap_target, parse_german_datetime, extract_thumbnail


class RTLPlusEventManager:
    """
    Manages fetching events (live streams, upcoming sports) for RTL+.

    Uses the Bedrock layout API to fetch folder pages and paginated blocks.
    Pagination follows the nextPage values exactly as returned by the API,
    which may be non-sequential (1 → 3 → 6 → ...).
    """

    # Block titles that indicate live stream content
    LIVE_STREAM_BLOCK_TITLES = [
        "Diese Live-Events erwarten euch",  # Primary block on homepage
        "Sport im Live-Stream",
        "UEFA Europa & Conference League | Live",
        "Live-Stream",
        "Live Events",
    ]

    # Sport type mapping
    SPORT_TYPES = {
        "Fußball": "Football",
        "Motorsport": "Motorsports",
        "MMA": "MMA",
        "NFL": "American Football",
        "Europa League": "Football",
        "Conference League": "Football",
        "Bundesliga": "Football",
    }

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
    # Public API
    # --------------------------------------------------------------------------

    def get_events(
            self,
            folder_id: str = "6",
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            force_refresh: bool = False,
            max_pages: int = 20,
    ) -> List[Event]:
        """
        Fetch all future/live events.

        Primary source is the homepage's "Diese Live-Events erwarten euch" block.
        Falls back to specific folder if homepage fails.

        Returns empty list if no events are found.
        """
        all_events: List[Event] = []

        # PRIMARY: Fetch from homepage (has all events in one block)
        try:
            home_events = self._fetch_events_from_homepage(force_refresh, max_pages)
            if home_events:
                all_events.extend(home_events)
                logger.info(f"Fetched {len(home_events)} events from homepage")
        except Exception as e:
            logger.warning(f"Failed to fetch events from homepage: {e}")

        # If no events from homepage, try fallback
        if not all_events:
            try:
                logger.debug(f"Falling back to folder {folder_id} for events")
                layout = self._provider.fetch_layout(
                    layout_type="folder",
                    content_id=folder_id,
                    force_refresh=force_refresh,
                )
                if layout:
                    folder_events = self._extract_events_from_layout(layout)
                    all_events.extend(folder_events)
            except Exception as e:
                logger.warning(f"Failed to fetch events from folder {folder_id}: {e}")

        # Filter by time range
        filtered_events = self._filter_by_time(all_events, start_time, end_time)

        # Sort chronologically
        filtered_events.sort(key=lambda e: e.start_time if e.start_time else datetime.max)

        logger.info(f"Returning {len(filtered_events)} events after filtering")
        return filtered_events

    def get_manifest_for_event(self, event_id: str) -> Optional[str]:
        """
        Get manifest URL for an event.

        Args:
            event_id: The event folder ID (e.g., "95" for Freiburg vs Braga)

        Returns:
            Manifest URL if available, None otherwise
        """
        layout = self._provider.fetch_layout(layout_type="folder", content_id=event_id)
        if not layout:
            logger.debug(f"No folder layout found for event {event_id}")
            return None

        # First try: Extract manifest from the folder's solo block
        manifest = self._extract_manifest_from_folder_layout(layout)
        if manifest:
            logger.debug(f"Found manifest in folder layout for event {event_id}")
            return manifest

        # Second try: Extract video assets directly from layout
        assets = self._provider.extract_video_assets(layout)
        if assets:
            manifest_url = self._provider.extract_best_manifest_url(assets)
            if manifest_url:
                logger.debug(f"Found manifest from assets for event {event_id}")
                return manifest_url

        logger.debug(f"No manifest found for event {event_id}")
        return None

    def get_drm_for_event(self, event_id: str) -> List[DRMConfig]:
        """
        Get DRM configuration for an event.

        Args:
            event_id: The event folder ID

        Returns:
            List of DRMConfig objects
        """
        layout = self._provider.fetch_layout(layout_type="folder", content_id=event_id)
        if not layout:
            return []

        return self._provider.get_drm_for_content(layout)

    # --------------------------------------------------------------------------
    # Homepage Event Fetching (Primary Source)
    # --------------------------------------------------------------------------

    def _fetch_events_from_homepage(self, force_refresh: bool = False, max_pages: int = 20) -> List[Event]:
        """
        Fetch events from the homepage's "Diese Live-Events erwarten euch" block.

        This is the primary source because it contains ALL live events in one
        paginated block, unlike folder views which only show one event.

        Pagination follows the nextPage values exactly as returned by the API.
        The API uses non-sequential page numbers (1 → 3 → 6 → ...).
        """
        home_layout = self._provider.fetch_layout(
            layout_type="alias",
            content_id="home",
            location=f"{self._provider.rtl_config.base_website}",
            force_refresh=force_refresh,
        )

        if not home_layout:
            logger.warning("Failed to fetch home layout for events")
            return []

        live_block = self._find_live_events_block(home_layout)
        if not live_block:
            logger.debug("No live events block found on homepage")
            return []

        block_id = live_block.get("id")
        if not block_id:
            logger.warning("Live events block missing 'id' field")
            return []

        all_events: List[Event] = []
        # visited_pages guards against an infinite loop if the API ever returns
        # a nextPage value that points back to a page we already fetched.
        visited_pages: Set[int] = set()

        # Process first page (already loaded in home_layout)
        initial_items = live_block.get("content", {}).get("items", [])
        all_events.extend(self._extract_events_from_items(initial_items))
        visited_pages.add(1)

        # Get pagination info from first page
        pagination = live_block.get("content", {}).get("pagination", {})
        next_page = pagination.get("nextPage")  # Will be 3, not 2!
        pages_fetched = 1

        logger.debug(f"Live events block: total={pagination.get('totalItems', 0)}, next_page={next_page}")

        # Follow nextPage links exactly as returned by API.
        # The API skips many page numbers (e.g. 1 → 3 → 6 → 9), so we must
        # never assume the next page number — always use the value from the
        # pagination response.
        while next_page and next_page not in visited_pages and pages_fetched < max_pages:
            visited_pages.add(next_page)
            logger.debug(f"Fetching page {next_page} of live events block")

            page_data = self._provider.fetch_block_page(
                block_id=block_id,
                page=next_page,
                nb_pages=3,
                service_id="rtlplus_root",
            )

            if not page_data:
                logger.warning(f"Failed to fetch page {next_page} for block {block_id}")
                break

            items = page_data.get("content", {}).get("items", [])
            all_events.extend(self._extract_events_from_items(items))
            pages_fetched += 1

            pagination = page_data.get("content", {}).get("pagination", {})
            next_page = pagination.get("nextPage")

        logger.info(f"Fetched {len(all_events)} events from {pages_fetched} pages")
        return all_events

    def _find_live_events_block(self, layout: Dict) -> Optional[Dict]:
        """
        Find the live events block in homepage layout.

        Prefers an exact match on "Diese Live-Events erwarten euch", then
        falls back to any block whose title contains a known pattern.
        """
        fallback: Optional[Dict] = None

        for block in layout.get("blocks", []):
            if block.get("type") != "bffPaginated":
                continue

            # Get block_title safely - it might be None
            block_title = None
            analytics = block.get("analytics", {})
            if analytics:
                tealium = analytics.get("tealium", {})
                if tealium:
                    block_title = tealium.get("block_title")

            # Skip if block_title is None
            if block_title is None:
                continue

            # Exact match — return immediately
            if block_title == "Diese Live-Events erwarten euch":
                logger.debug(f"Found live events block (exact): '{block_title}'")
                return block

            # Partial match — keep as fallback, continue looking for exact
            if fallback is None:
                for pattern in self.LIVE_STREAM_BLOCK_TITLES:
                    if pattern.lower() in block_title.lower():
                        logger.debug(f"Found potential live block (partial): '{block_title}'")
                        fallback = block
                        break

        return fallback

    # --------------------------------------------------------------------------
    # Layout Extraction Helpers
    # --------------------------------------------------------------------------

    def _extract_events_from_layout(self, layout: Dict) -> List[Event]:
        """Extract events from any layout by scanning all bffPaginated blocks."""
        all_events: List[Event] = []

        for block in layout.get("blocks", []):
            if block.get("type") != "bffPaginated":
                continue

            items = block.get("content", {}).get("items", [])
            all_events.extend(self._extract_events_from_items(items))

        return all_events

    # --------------------------------------------------------------------------
    # Event Extraction from Items
    # --------------------------------------------------------------------------

    def _extract_events_from_items(self, items: List[Dict]) -> List[Event]:
        """
        Extract Event objects from block items.

        Each item represents a live event with:
        - highlight: "Fußball • Do., 07.05.26, 20:30 Uhr"
        - action.target.value_layout: contains folder_id for the event
        """
        events: List[Event] = []
        current_time = datetime.now()

        for item in items:
            if item.get("itemType") != "classic":
                continue

            item_content = item.get("itemContent", {})
            highlight = item_content.get("highlight", "")

            if not highlight:
                continue

            # Parse the date from highlight, falling back to description
            event_date = parse_german_datetime(highlight)
            if not event_date:
                description = item_content.get("description", "")
                if description:
                    event_date = parse_german_datetime(description)
            if not event_date:
                continue

            # Determine status early so we can decide whether to keep the event
            status = self._determine_event_status(event_date, highlight)

            # Exclude events that have already ended (not live and started > 3 h ago)
            if status == EventStatus.ENDED:
                continue

            # Extract title
            title = item_content.get("title") or self._extract_title_from_highlight(highlight)
            if not title:
                title = "Unknown Event"

            # Unwrap the action target (handles lock-wrapped targets transparently)
            action = item_content.get("action", {})
            target = unwrap_target(action.get("target", {}))
            value_layout = target.get("value_layout", {})
            folder_id = value_layout.get("id")

            # Fallback to itemContent.id if folder_id not found
            if not folder_id:
                folder_id = item_content.get("id")

            if not folder_id:
                logger.debug(f"Skipping event with no folder_id: {title}")
                continue

            sport = self._extract_sport_type(highlight)

            event = Event(
                name=title,
                content_id=folder_id,
                provider=self._provider.provider_name,
                start_time=event_date,
                end_time=None,  # End time not provided in this response
                status=status,
                logo_url=extract_thumbnail(item_content),
                genre=sport,
                venue=item_content.get("details") or item_content.get("extraDetails"),
                description=item_content.get("description"),
            )

            # Store additional metadata for later manifest resolution
            event.manifest_script = json.dumps({
                "folder_id": folder_id,
                "seo": value_layout.get("seo"),
                "highlight": highlight,
                "title": title,
            })

            events.append(event)

        return events

    def _extract_manifest_from_folder_layout(self, layout: Dict) -> Optional[str]:
        """
        Extract manifest URL from a folder layout (live event detail page).

        The folder layout has a Solo block with a "Live ansehen" button.
        The target points to a live player, which we need to fetch.
        """
        for block in layout.get("blocks", []):
            if block.get("type") != "bffPaginated":
                continue

            for item in block.get("content", {}).get("items", []):
                item_content = item.get("itemContent", {})
                action = item_content.get("action", {})
                target = unwrap_target(action.get("target", {}))
                value_layout = target.get("value_layout", {})

                # The target type "live" points to the player
                if value_layout.get("type") == "live":
                    live_event_id = value_layout.get("id")
                    if live_event_id:
                        return self._get_manifest_from_live_event(live_event_id)

        return None

    def _get_manifest_from_live_event(self, live_event_id: str) -> Optional[str]:
        """
        Get manifest from live event player page.

        Args:
            live_event_id: The live event ID (e.g., "rtlde_event3")
        """
        live_layout = self._provider.fetch_layout(
            layout_type="live",
            content_id=live_event_id,
            location=f"{self._provider.rtl_config.base_website}{live_event_id}",
        )

        if live_layout:
            assets = self._provider.extract_video_assets(live_layout)
            if assets:
                return self._provider.extract_best_manifest_url(assets)

        return None

    # --------------------------------------------------------------------------
    # Date / Status / Sport Helpers
    # --------------------------------------------------------------------------

    @staticmethod
    def _determine_event_status(event_date: datetime, highlight: str) -> EventStatus:
        """
        Determine if event is live, upcoming, or ended.

        Uses both the date/time and the presence of "Live" in the highlight text.
        """
        now = datetime.now()

        # Explicit "Live" label in the metadata takes priority
        if "live" in highlight.lower():
            return EventStatus.LIVE

        # Event started within the last 3 hours → treat as live
        if event_date <= now and event_date >= now - timedelta(hours=3):
            return EventStatus.LIVE

        if event_date > now:
            return EventStatus.SCHEDULED

        return EventStatus.ENDED

    @staticmethod
    def _extract_title_from_highlight(highlight: str) -> str:
        """Extract event title from highlight text when no separate title exists."""
        import re
        parts = highlight.split("•")
        if len(parts) >= 2:
            middle = parts[1].strip()
            date_match = re.search(r"\d{2}\.\d{2}\.\d{2}", middle)
            if date_match:
                title = middle[:date_match.start()].strip()
                if title:
                    return title
        return highlight

    def _extract_sport_type(self, highlight: str) -> str:
        """Extract sport type from highlight."""
        sport_part = highlight.split("•")[0].strip()
        for german, english in self.SPORT_TYPES.items():
            if german in sport_part:
                return english
        return sport_part or "Sport"

    # --------------------------------------------------------------------------
    # Time Filtering
    # --------------------------------------------------------------------------

    @staticmethod
    def _filter_by_time(
        events: List[Event],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> List[Event]:
        """Filter events by time range."""
        if not start_time and not end_time:
            return events

        filtered = []
        for event in events:
            if start_time and event.start_time and event.start_time < start_time:
                continue
            if end_time and event.start_time and event.start_time > end_time:
                continue
            filtered.append(event)

        return filtered

    # --------------------------------------------------------------------------
    # Cache Management
    # --------------------------------------------------------------------------

    def invalidate_cache(self, folder_id: Optional[str] = None):
        """Invalidate the layout cache."""
        if folder_id:
            cache_key = f"folder:{folder_id}:1:2"
            self._provider.invalidate_layout_cache(cache_key)
        else:
            self._provider.invalidate_layout_cache()