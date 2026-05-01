# streaming_providers/providers/rtlplus/event_manager.py
"""
RTL+ Event Manager

Handles fetching future/live events from Bedrock layout API.
Replaces legacy GraphQL-based event fetching.
"""

import json
import re
from datetime import datetime
from typing import List, Optional, Dict

from ...base.models.event import Event, EventStatus
from ...base.utils.logger import logger
from ...base.models import DRMConfig


class RTLPlusEventManager:
    """
    Manages fetching events (live streams, upcoming sports) for RTL+.

    Uses the Bedrock layout API to fetch folder pages and paginated blocks.
    """

    # Block titles that indicate live stream content
    LIVE_STREAM_BLOCK_TITLES = [
        "Sport im Live-Stream",
        "UEFA Europa & Conference League | Live",
        "Live-Stream",
        "Live Events",
    ]

    # Date parsing patterns (German)
    DATE_PATTERNS = [
        r"(\d{2})\.(\d{2})\.(\d{2}),\s*(\d{2}):(\d{2})\s*Uhr",
        r"(\d{2})\.(\d{2})\.(\d{2})\s+(\d{2}):(\d{2})",
        r"(\d{2})\.(\d{2})\.(\d{2})",  # Just date, no time
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
    ) -> List[Event]:
        """
        Fetch all future/live events from the specified folder.

        Args:
            folder_id: The folder ID (default "6" for Sport im Überblick)
            start_time: Filter events that end after this time
            end_time: Filter events that start before this time
            force_refresh: Ignore cache and fetch fresh data

        Returns:
            List of Event objects (scheduled or live)
        """
        all_events: List[Event] = []

        # Step 1: Fetch folder layout using provider's common method
        layout = self._fetch_folder_layout(folder_id, force_refresh)
        if not layout:
            logger.error(f"Failed to fetch folder layout for {folder_id}")
            return []

        # Step 2: Identify live stream blocks
        live_blocks = self._identify_live_stream_blocks(layout)
        if not live_blocks:
            logger.debug(f"No live stream blocks found in folder {folder_id}")
            return []

        logger.info(f"Found {len(live_blocks)} live stream blocks")

        # Step 3: Fetch all pages from each block
        for block in live_blocks:
            block_events = self._fetch_all_block_pages(block, force_refresh)
            all_events.extend(block_events)

        # Step 4: Filter by time range
        filtered_events = self._filter_by_time(all_events, start_time, end_time)

        # Step 5: Sort chronologically
        filtered_events.sort(key=lambda e: e.start_time if e.start_time else datetime.max)

        logger.info(f"Returning {len(filtered_events)} future events from {len(all_events)} total")
        return filtered_events

    def get_manifest_for_event(self, event_id: str) -> Optional[str]:
        """
        Get manifest URL for an event.

        Args:
            event_id: The event folder ID (e.g., "76")

        Returns:
            Manifest URL if available from the folder layout, None otherwise
        """
        layout = self._fetch_folder_layout(event_id)
        if not layout:
            return None

        # Extract video assets from the layout
        assets = self._provider.extract_video_assets(layout)

        if not assets:
            logger.debug(f"No video assets found in event folder {event_id}")
            return None

        # Extract best manifest URL
        manifest_url = self._provider.extract_best_manifest_url(assets)
        if manifest_url:
            logger.debug(f"Found manifest for event {event_id}: {manifest_url}")
            return manifest_url

        return None

    def get_drm_for_event(self, event_id: str) -> List[DRMConfig]:
        """
        Get DRM configuration for an event.
        """
        layout = self._fetch_folder_layout(event_id)
        if not layout:
            return []

        # Delegate to provider's common DRM method
        return self._provider.get_drm_for_content(layout)

    # --------------------------------------------------------------------------
    # Internal Methods
    # --------------------------------------------------------------------------

    def _fetch_folder_layout(self, folder_id: str, force_refresh: bool = False) -> Optional[Dict]:
        """Fetch folder layout using provider's common method."""
        return self._provider.fetch_layout(
            layout_type="folder",
            content_id=folder_id,
            force_refresh=force_refresh,
        )

    def _fetch_block_page(self, block_id: str, page: int, nb_pages: int = 3) -> Optional[Dict]:
        """Fetch a specific page of a block using provider's common method."""
        return self._provider.fetch_layout(
            layout_type="block",
            content_id=block_id,
            block_page=page,
            nb_pages=nb_pages,
        )

    def _identify_live_stream_blocks(self, layout: Dict) -> List[Dict]:
        """
        Identify blocks that contain live stream events.

        Returns:
            List of block dictionaries that likely contain future events
        """
        blocks = layout.get("blocks", [])
        live_blocks = []

        for block in blocks:
            block_type = block.get("type")
            if block_type != "bffPaginated":
                continue

            block_title = block.get("analytics", {}).get("tealium", {}).get("block_title", "")

            # Check if block title matches live stream patterns
            is_live_block = any(
                title_pattern.lower() in block_title.lower()
                for title_pattern in self.LIVE_STREAM_BLOCK_TITLES
            )

            if is_live_block:
                logger.debug(f"Identified live block: '{block_title}'")
                live_blocks.append(block)
                continue

            # Alternative: Check if ANY item in the block has a future date
            items = block.get("content", {}).get("items", [])
            for item in items:
                highlight = item.get("itemContent", {}).get("highlight", "")
                if highlight and self._is_future_date(highlight):
                    logger.debug(f"Block '{block_title}' contains future dates, including")
                    live_blocks.append(block)
                    break

        return live_blocks

    def _fetch_all_block_pages(self, block: Dict, force_refresh: bool = False) -> List[Event]:
        """
        Fetch all pages of a paginated block and extract events.
        """
        all_events: List[Event] = []
        block_id = block.get("id")
        if not block_id:
            logger.warning("Block missing 'id' field")
            return []

        # Get pagination info from initial block data
        pagination = block.get("content", {}).get("pagination", {})
        total_items = pagination.get("totalItems", 0)
        items_per_page = pagination.get("itemsPerPage", 4)
        next_page = pagination.get("nextPage")

        logger.debug(f"Block {block_id}: total={total_items}, per_page={items_per_page}, next_page={next_page}")

        # Process the initial page
        initial_items = block.get("content", {}).get("items", [])
        current_page_events = self._extract_events_from_items(initial_items)
        all_events.extend(current_page_events)

        # Determine current page based on items count
        current_page = 1
        if total_items > 0 and items_per_page > 0:
            # Rough estimate: if we have more items than items_per_page, we might be on page 2
            if len(initial_items) > items_per_page:
                current_page = 2

        # Fetch remaining pages
        while next_page and next_page > current_page:
            current_page = next_page
            page_data = self._fetch_block_page(block_id, next_page, force_refresh)
            if not page_data:
                logger.warning(f"Failed to fetch page {next_page} for block {block_id}")
                break

            items = page_data.get("content", {}).get("items", [])
            page_events = self._extract_events_from_items(items)
            all_events.extend(page_events)

            # Get next_page from the response
            pagination = page_data.get("content", {}).get("pagination", {})
            next_page = pagination.get("nextPage")

            # Safety: prevent infinite loops
            if current_page > 50:
                logger.warning(f"Reached page limit (50) for block {block_id}")
                break

        logger.debug(f"Block {block_id}: fetched {len(all_events)} events from {current_page} pages")
        return all_events

    def _extract_events_from_items(self, items: List[Dict]) -> List[Event]:
        """
        Extract Event objects from block items.
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

            # Parse the date from highlight
            event_date = self._parse_date_from_highlight(highlight)
            if not event_date:
                # Some items might have date in description
                description = item_content.get("description", "")
                if description:
                    event_date = self._parse_date_from_highlight(description)
                if not event_date:
                    continue

            # Only include future events (or currently live)
            if event_date < current_time:
                continue

            # Extract event data - use itemContent.id which is the content_id for manifest
            content_id = item_content.get("id")
            title = item_content.get("title")

            if not content_id:
                continue

            if not title:
                # Try to extract title from highlight
                title = self._extract_title_from_highlight(highlight)

            if not title:
                title = "Unknown Event"

            # Determine status (live if within next 3 hours, else scheduled)
            status = EventStatus.LIVE if self._is_currently_live(event_date) else EventStatus.SCHEDULED

            # Extract sport type
            sport = self._extract_sport_type(highlight)

            # Get action target (for potential folder navigation)
            action = item_content.get("action", {})
            target = action.get("target", {})

            # Build event
            event = Event(
                name=title,
                content_id=content_id,
                provider=self._provider.provider_name,
                start_time=event_date,
                end_time=None,  # End time not provided in this response
                status=status,
                logo_url=self._extract_image_url(item_content),
                genre=sport,
                venue=item_content.get("details") or item_content.get("extraDetails"),
                description=item_content.get("description"),
            )

            # Store additional metadata in manifest_script for later use
            manifest_data = {
                "folder_id": target.get("value_layout", {}).get("id"),
                "seo": target.get("value_layout", {}).get("seo"),
                "highlight": highlight,
                "title": title,
            }
            event.manifest_script = json.dumps(manifest_data)

            events.append(event)

        return events

    # --------------------------------------------------------------------------
    # Date Parsing Helpers
    # --------------------------------------------------------------------------

    def _parse_date_from_highlight(self, highlight: str) -> Optional[datetime]:
        """
        Parse German date format from highlight string.

        Examples:
            "Fußball • Sa., 02.05.26, 20:00 Uhr"
            "Motorsport • Fr., 15.05.26, 13:10 Uhr"
            "Motorsport \u2022 Sa., 16.05.26, 14:15 Uhr"
            "Motorsport • Do., 14.05.26, 13:10 Uhr"
        """
        for pattern in self.DATE_PATTERNS:
            match = re.search(pattern, highlight)
            if match:
                groups = match.groups()
                if len(groups) >= 3:
                    day = int(groups[0])
                    month = int(groups[1])
                    year = int(groups[2])
                    hour = int(groups[3]) if len(groups) > 3 else 0
                    minute = int(groups[4]) if len(groups) > 4 else 0

                    # Assume 20XX for years like '26'
                    if year < 100:
                        year = 2000 + year

                    try:
                        return datetime(year, month, day, hour, minute)
                    except ValueError:
                        continue

        return None

    def _is_future_date(self, highlight: str) -> bool:
        """Check if the highlight contains a future date."""
        event_date = self._parse_date_from_highlight(highlight)
        if not event_date:
            return False
        return event_date > datetime.now()

    @staticmethod
    def _is_currently_live(event_date: datetime) -> bool:
        """Check if an event is currently live (within 3 hours of start)."""
        now = datetime.now()
        # Consider event "live" if it started within the last 3 hours
        # and hasn't been passed by more than 30 minutes
        return event_date <= now <= (event_date.replace(hour=event_date.hour + 3))

    @staticmethod
    def _extract_title_from_highlight(highlight: str) -> str:
        """Extract event title from highlight text when no separate title exists."""
        # Remove sport prefix and date
        parts = highlight.split("•")
        if len(parts) >= 2:
            # Everything between the first bullet and the date
            middle = parts[1].strip()
            # Remove date part
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

    @staticmethod
    def _extract_image_url(item_content: Dict) -> Optional[str]:
        """Extract image URL from item content."""
        image = item_content.get("image", {})
        if not image:
            return None

        # Try to get the best available ratio
        ratio_prefs = ["16:9", "3:1", "1:1"]
        for ratio in ratio_prefs:
            image_id = image.get("idsByRatio", {}).get(ratio)
            if image_id:
                return f"https://images.rtl.de/{image_id}?format=webp&width=400"

        # Fallback to direct ID
        image_id = image.get("id")
        if image_id:
            return f"https://images.rtl.de/{image_id}?format=webp&width=400"

        return None

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
            if start_time and event.end_time and event.end_time < start_time:
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
            cache_key = f"folder:{folder_id}:1:2"  # Match _fetch_layout cache key format
            self._provider.invalidate_layout_cache(cache_key)
        else:
            self._provider.invalidate_layout_cache()