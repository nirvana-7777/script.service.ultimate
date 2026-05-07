# streaming_providers/providers/rtlplus/vod_manager.py
"""
RTL+ VOD Manager

Handles Video on Demand content using the Bedrock layout API.
Follows the same patterns as channel_manager and event_manager.

Manifest and DRM resolution is always delegated to the central
provider.get_manifest() / provider.get_drm() methods, which own
the upfront-token flow and all format/quality selection logic.
"""

import json
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Union, Tuple
from zoneinfo import ZoneInfo  # Python 3.9+; fallback to pytz if needed

from ...base.models.vod import VodCategory, VodItem
from ...base.models import DRMConfig
from ...base.utils.logger import logger
from .constants import RTLPlusDefaults

FOLDER_NAMES = {
    "4": "Filme",
    "3": "Serien",
    "1": "Reality & Shows",
    "148": "Kids",
    "165": "Anime",
    "6": "Sport",
}


class RTLPlusVodManager:
    """
    Manages VOD content for RTL+.

    Navigation hierarchy:
        root
        └── folder_<id>        (Bedrock folder, e.g. folder_3 = Serien)
            └── program_<id>   (program layout → seasons or direct video)
                ├── month_<block_id>  (monthly archive selector)
                │   └── episodes (via block fetch)
                ├── season_<block_id> (numbered season selector)
                │   └── episodes (via block fetch)
                └── clip_id           (video layout, playable)

    Manifest and DRM for playable items are always resolved through
    the provider's central get_manifest() / get_drm() methods.
    """

    def __init__(self, provider):
        self._provider = provider

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    @property
    def cfg(self):
        return self._provider.rtl_config

    @property
    def http(self):
        return self._provider.http_manager

    @property
    def auth(self):
        return self._provider.authenticator

    # ------------------------------------------------------------------
    # Public API (VodOperations interface)
    # ------------------------------------------------------------------

    def get_vod_category(
            self,
            content_id: str = "",
            cursor: Optional[str] = None,
            page_size: int = 24,
            **kwargs,
    ) -> Dict[str, Any]:
        """
        Return the children of a VOD node.

        Supported content_id formats:
        - ""                       → root
        - "folder_<id>"            → Bedrock folder
        - "program_<id>"           → program/series (handles movies, numbered seasons, monthly archives)
        - "season_<id>"            → numbered season block (Staffel 1, 2, etc.)
        - "month_<block_id>"       → monthly archive block (2026-05, 2026-04, etc.)
        - "clip_<id>"              → direct clip (playable item)
        - "program_<id>/clip_<id>" → explicit program+clip path
        """
        # Handle combined paths like "program_68137/clip_1417600"
        if "/" in content_id:
            parts = content_id.split("/")
            if len(parts) == 2 and parts[0].startswith("program_") and parts[1].startswith("clip_"):
                clip_id = parts[1]
                program_id = parts[0][8:]  # Remove "program_" prefix

                vod_item = self._get_direct_clip_item(clip_id, program_id, **kwargs)
                if vod_item:
                    return {"entries": [vod_item], "next_cursor": None, "total": 1}

                content_id = clip_id

        # Handle direct clip ID
        if content_id.startswith("clip_"):
            vod_item = self.get_vod_item_info(content_id)
            if vod_item:
                return {"entries": [vod_item], "next_cursor": None, "total": 1}
            return {"entries": [], "next_cursor": None, "total": 0}

        # Handle month block (monthly episode archives)
        if content_id.startswith("month_"):
            block_id = content_id[6:]  # Remove "month_" prefix
            return self._get_block_episodes(block_id, cursor, page_size, block_type="month")

        # Handle numbered season block
        if content_id.startswith("season_"):
            block_id = content_id[7:]  # Remove "season_" prefix
            return self._get_block_episodes(block_id, cursor, page_size, block_type="season")

        # Handle episodes_current_ prefix (special cursor for current month preview)
        if content_id.startswith("episodes_current_"):
            program_id = content_id.replace("episodes_current_", "")
            return self._get_current_episodes_preview(program_id, cursor, page_size)

        if not content_id:
            return self._get_root_category()

        if content_id.startswith("folder_"):
            folder_id = content_id[7:]
            return self._get_folder_contents(folder_id, cursor, page_size)

        if content_id.startswith("program_"):
            program_id = content_id[8:]
            slug = kwargs.get("slug")
            return self._get_program_contents(program_id, cursor, page_size, slug=slug)

        # Bare numeric ID → treat as program (backward compatibility)
        if content_id.isdigit():
            return self._get_program_contents(content_id, cursor, page_size)

        logger.warning(f"Unrecognised VOD content_id format: {content_id!r}")
        return {"entries": [], "next_cursor": None, "total": 0}

    def _get_block_episodes(
            self,
            block_id: str,
            cursor: Optional[str] = None,
            page_size: int = 24,
            block_type: str = "block"
    ) -> Dict[str, Any]:
        """
        Fetch episodes from a block (works for both numbered seasons and monthly archives).

        Args:
            block_id: The block ID (e.g., "c7916bb9-d111-49db-9a99-ab40ef6413da_39638")
            cursor: Page number (1-indexed)
            page_size: Number of items per page (unused, API controls this)
            block_type: Type of block for logging ("season" or "month")
        """
        page = 1
        if cursor:
            try:
                page = int(cursor)
            except ValueError:
                page = 1

        layout = self._provider.fetch_layout(
            layout_type="block",
            content_id=block_id,
            block_page=page,
            nb_pages=RTLPlusDefaults.DEFAULT_BLOCK_NB_PAGES,
        )

        if not layout:
            logger.error(f"Failed to fetch {block_type} block layout for {block_id}")
            return {"entries": [], "next_cursor": None, "total": 0}

        episodes: List[VodItem] = []
        for item in layout.get("content", {}).get("items", []):
            vod_item = self._extract_vod_item_from_block_item(item)
            if vod_item:
                episodes.append(vod_item)

        pagination = layout.get("content", {}).get("pagination", {})
        total = pagination.get("totalItems", len(episodes))
        next_page = pagination.get("nextPage")
        next_cursor = str(next_page) if next_page else None

        logger.debug(f"Fetched {len(episodes)}/{total} episodes from {block_type} block (page {page})")

        return {
            "entries": episodes,
            "next_cursor": next_cursor,
            "total": total,
        }

    def _get_current_episodes_preview(self, program_id: str, cursor: Optional[str] = None, page_size: int = 24) -> Dict[
        str, Any]:
        """Get paginated current episodes for the program preview."""
        seo = f"p_{program_id}"
        location = f"{self.cfg.base_website}{seo}-p_{program_id}"
        layout = self._provider.fetch_layout(
            layout_type="program",
            content_id=program_id,
            location=location,
        )
        if not layout:
            return {"entries": [], "next_cursor": None, "total": 0}

        _, current_episodes = self._extract_season_selector_with_episodes(layout)
        if not current_episodes:
            return {"entries": [], "next_cursor": None, "total": 0}

        page = int(cursor) if cursor and cursor.isdigit() else 1
        paginated, next_cursor = self._paginate_episodes(current_episodes, page, page_size)
        return {"entries": paginated, "next_cursor": next_cursor, "total": len(current_episodes)}

    def _get_direct_clip_item(self, clip_id: str, program_id: Optional[str] = None, **kwargs) -> Optional[VodItem]:
        """
        Fetch a direct clip item by its clip_id.
        This is used when we have a path like program_68137/clip_1417600.
        """
        layout = self._provider.fetch_layout(
            layout_type="video",
            content_id=clip_id,
            location=f"{self.cfg.base_website}{clip_id}",
        )

        if not layout:
            logger.warning(f"Failed to fetch layout for direct clip {clip_id}")
            # Fallback: create a basic VodItem with what we know
            return VodItem(
                name=kwargs.get("item_name", f"Video {clip_id}"),
                content_id=clip_id,
                provider=self._provider.provider_name,
                mode="vod",
                content_type="VOD",
            )

        vod_item = self._extract_vod_item_from_layout(layout, clip_id)

        if not vod_item:
            vod_item = self._extract_vod_item_from_layout_items(layout, clip_id)

        return vod_item

    def _extract_vod_item_from_layout_items(self, layout: Dict, clip_id: str) -> Optional[VodItem]:
        """Extract VodItem from layout items (fallback method)."""
        for block in layout.get("blocks", []):
            if block.get("type") != "bffPaginated":
                continue
            for item in block.get("content", {}).get("items", []):
                if item.get("itemType") != "classic":
                    continue

                item_content = item.get("itemContent", {})
                action = item_content.get("action", {})
                target = action.get("target", {})

                # Handle lock-wrapped targets
                if target.get("type") == "lock":
                    target = target.get("value_lock", {}).get("originalTarget", {})

                value_layout = target.get("value_layout", {})

                if value_layout.get("type") == "video" and value_layout.get("id") == clip_id:
                    vod_item = self._extract_vod_item_from_block_item(item)
                    if vod_item:
                        return vod_item

                # Also check direct itemContent
                if item_content.get("type") == "video" and item_content.get("id") == clip_id:
                    return VodItem.create_episode(
                        name=item_content.get("title", clip_id),
                        content_id=clip_id,
                        provider=self._provider.provider_name,
                        season_number=-1,
                        episode_number=-1,
                    )
        return None

    def get_vod_item_info(self, clip_id: str) -> Optional[VodItem]:
        """
        Return metadata for a single playable clip.
        Does NOT fetch manifest/DRM — callers use get_manifest/get_drm for that.
        """
        layout = self._provider.fetch_layout(
            layout_type="video",
            content_id=clip_id,
            location=f"{self.cfg.base_website}{clip_id}",
        )
        if not layout:
            return None
        return self._extract_vod_item_from_layout(layout, clip_id)

    def get_manifest_for_video(self, clip_id: str) -> Optional[str]:
        """Resolve the playback manifest URL for a VOD clip."""
        return self._provider.get_manifest(clip_id)

    def get_drm_for_video(self, clip_id: str) -> List[DRMConfig]:
        """Resolve DRM configuration (Widevine + PlayReady) for a VOD clip."""
        return self._provider.get_drm(clip_id)

    # ------------------------------------------------------------------
    # Root category — parsed from home layout
    # ------------------------------------------------------------------

    def _get_root_category(self) -> Dict[str, Any]:
        try:
            folder_categories = []
            program_categories = []
            future_events_count = 0

            layout = self._provider.fetch_layout(
                layout_type="alias",
                content_id="home",
                location=f"{self.cfg.base_website}",
            )

            if not layout:
                logger.warning("Failed to fetch home layout for VOD root; returning empty")
                return {"entries": [], "next_cursor": None, "total": 0}

            for block in layout.get("blocks", []):
                if block.get("type") != "bffPaginated":
                    continue

                content = block.get("content")
                if not content:
                    continue

                items = content.get("items")
                if not items:
                    continue

                for item in items:
                    if not item:
                        continue

                    item_content = item.get("itemContent")
                    if not item_content:
                        continue

                    # Skip future events
                    if self._is_future_event(item_content):
                        future_events_count += 1
                        continue

                    cat = self._extract_vod_category_from_block_item(item)
                    if cat:
                        if cat.content_id.startswith("folder_"):
                            folder_categories.append(cat)
                        else:
                            program_categories.append(cat)
                        continue

                    vod_item = self._extract_vod_item_from_block_item(item)
                    if vod_item:
                        program_categories.append(vod_item)

            # Combine: folders first, then programs
            entries = folder_categories + program_categories

            if future_events_count > 0:
                logger.info(f"Filtered out {future_events_count} future events from VOD root")

            logger.info(
                f"Found {len(entries)} entries in root VOD category "
                f"({len(folder_categories)} folders, {len(program_categories)} programs)"
            )

            return {
                "entries": entries,
                "next_cursor": None,
                "total": len(entries),
            }
        except Exception as e:
            logger.error(f"Error in _get_root_category: {e}", exc_info=True)
            return {"entries": [], "next_cursor": None, "total": 0}

    # ------------------------------------------------------------------
    # Folder → program listing
    # ------------------------------------------------------------------

    def _get_folder_contents(
            self,
            folder_id: str,
            cursor: Optional[str] = None,
            page_size: int = 24,
    ) -> Dict[str, Any]:
        """
        Return the programs/sub-folders inside a Bedrock folder.
        Items that carry a video asset are surfaced as VodItem;
        everything else becomes a VodCategory for further navigation.
        """
        layout = self._provider.fetch_layout(
            layout_type="folder",
            content_id=folder_id,
        )
        if not layout:
            return {"entries": [], "next_cursor": None, "total": 0}

        entries: List[Union[VodCategory, VodItem]] = []
        for block in layout.get("blocks", []):
            if block.get("type") != "bffPaginated":
                continue
            for item in block.get("content", {}).get("items", []):
                if self._item_has_video_assets(item):
                    vod_item = self._extract_vod_item_from_block_item(item)
                    if vod_item:
                        entries.append(vod_item)
                else:
                    cat = self._extract_vod_category_from_block_item(item)
                    if cat:
                        entries.append(cat)

        return {"entries": entries, "next_cursor": None, "total": len(entries)}

    # ------------------------------------------------------------------
    # Program contents (handles movies, numbered seasons, monthly archives)
    # ------------------------------------------------------------------

    def _get_program_contents(
            self,
            program_id: str,
            cursor: Optional[str] = None,
            page_size: int = 24,
            slug: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Get program contents - handles movies, series with season selectors.
        """
        seo = slug or f"p_{program_id}"
        location = f"{self.cfg.base_website}{seo}-p_{program_id}"

        layout = self._provider.fetch_layout(
            layout_type="program",
            content_id=program_id,
            location=location,
        )

        if not layout:
            logger.error(f"Failed to fetch layout for program {program_id}")
            return {"entries": [], "next_cursor": None, "total": 0}

        # FIRST: Check for monthly archive selector (series with monthly episodes)
        season_selector, current_episodes = self._extract_season_selector_with_episodes(layout)
        if season_selector:
            logger.debug(f"Found monthly selector with {len(season_selector)} months for program {program_id}")
            return self._handle_series_response(program_id, season_selector, current_episodes, cursor, page_size)

        # SECOND: Check for numbered seasons (traditional series with Staffel 1, 2, etc.)
        numbered_seasons = self._extract_seasons_from_layout(layout)
        if numbered_seasons:
            logger.debug(f"Found {len(numbered_seasons)} numbered seasons for program {program_id}")
            return self._handle_numbered_seasons_response(numbered_seasons, cursor, page_size)

        # THIRD: No seasons found - this is likely a movie or direct video
        movie_item = self._find_direct_video_in_layout(layout, is_series=False)
        if movie_item:
            # Enhance movie metadata from layout
            layout_title = (
                    layout.get("entity", {}).get("metadata", {}).get("title")
                    or layout.get("seo", {}).get("title")
            )
            if layout_title and layout_title != movie_item.name:
                movie_item.name = layout_title
            if not movie_item.logo_url:
                movie_item.logo_url = self._extract_thumbnail_from_layout(layout)
            if not movie_item.description:
                movie_item.description = (
                        layout.get("entity", {}).get("metadata", {}).get("description")
                        or layout.get("seo", {}).get("description")
                )
            return {"entries": [movie_item], "next_cursor": None, "total": 1}

        # FOURTH: Fallback - look for direct episodes
        direct_episodes = self._extract_direct_episodes_from_layout(layout)
        if direct_episodes:
            page = int(cursor) if cursor and cursor.isdigit() else 1
            paginated, next_cursor = self._paginate_episodes(direct_episodes, page, page_size)
            return {"entries": paginated, "next_cursor": next_cursor, "total": len(direct_episodes)}

        logger.warning(f"No content found for program {program_id}")
        return {"entries": [], "next_cursor": None, "total": 0}

    def _handle_series_response(self, program_id: str, season_selector: List[VodCategory],
                                current_episodes: List[VodItem], cursor: Optional[str],
                                page_size: int) -> Dict[str, Any]:
        """Handle series response with monthly selector."""
        entries = season_selector

        # If a cursor is provided, it might be for pagination of current episodes
        if cursor and cursor.startswith("episodes:"):
            page = int(cursor.split(":")[1]) if ":" in cursor else 1
            paginated_episodes, next_cursor = self._paginate_episodes(current_episodes, page, page_size)
            return {
                "entries": paginated_episodes,
                "next_cursor": next_cursor,
                "total": len(current_episodes),
            }

        # First load - show selector and optionally first page of current episodes
        if current_episodes and len(current_episodes) > 0:
            current_month_name = self._get_current_month_name()
            if current_month_name:
                preview_category = VodCategory(
                    name=f"Aktuelle Folgen ({current_month_name})",
                    content_id=f"episodes_current_{program_id}",
                    provider=self._provider.provider_name,
                    child_count=len(current_episodes),
                )
                entries = [preview_category] + entries

        next_cursor = None
        if len(current_episodes) > page_size:
            next_cursor = "episodes:2"

        return {
            "entries": entries,
            "next_cursor": next_cursor,
            "total": len(season_selector) + (1 if current_episodes else 0),
        }

    @staticmethod
    def _handle_numbered_seasons_response(numbered_seasons: List[VodCategory],
                                          cursor: Optional[str], page_size: int) -> Dict[str, Any]:
        """Handle series response with numbered seasons."""
        start = 0
        if cursor:
            try:
                start = int(cursor)
            except ValueError:
                start = 0

        page = numbered_seasons[start: start + page_size]
        next_cursor = str(start + page_size) if (start + page_size) < len(numbered_seasons) else None
        return {"entries": page, "next_cursor": next_cursor, "total": len(numbered_seasons)}

    def _extract_season_selector_with_episodes(self, layout: Dict) -> Tuple[List[VodCategory], List[VodItem]]:
        logger.debug("Starting _extract_season_selector_with_episodes")
        seasons = []
        current_episodes = []

        for block_idx, block in enumerate(layout.get("blocks", [])):
            logger.debug(f"Processing block {block_idx}, type: {block.get('type')}")

            if block.get("type") != "bffPaginated":
                logger.debug(f"Skipping block {block_idx} - not bffPaginated")
                continue

            alt_content = block.get("alternativeContent")
            logger.debug(f"Block {block_idx} alt_content type: {type(alt_content)}")

            # CRITICAL FIX: Check if alt_content is a dict before calling .get()
            if alt_content and isinstance(alt_content, dict) and alt_content.get("selectorTemplateId") == "Selector":
                logger.debug(f"Found Selector block {block_idx}")

                # SAFEGUARD: concurrentBlocks might be None
                concurrent_blocks = alt_content.get("concurrentBlocks")
                logger.debug(f"concurrentBlocks type: {type(concurrent_blocks)}")

                if concurrent_blocks and isinstance(concurrent_blocks, list):
                    for cb_idx, cb in enumerate(concurrent_blocks):
                        if not cb or not isinstance(cb, dict):
                            continue

                        month_title = cb.get("title")
                        block_id = cb.get("id")

                        if month_title and block_id:
                            total_episodes = (
                                cb.get("content", {})
                                .get("pagination", {})
                                .get("totalItems", 0)
                            )

                            seasons.append(VodCategory(
                                name=month_title,
                                content_id=f"month_{block_id}",
                                provider=self._provider.provider_name,
                                child_count=total_episodes,
                            ))
                            logger.debug(f"Added month: {month_title}")

                # Extract current month episodes
                items = block.get("content", {}).get("items", [])
                logger.debug(f"Processing {len(items)} items for current episodes")

                for item_idx, item in enumerate(items):
                    if not item or not isinstance(item, dict):
                        continue
                    vod_item = self._extract_vod_item_from_block_item(item)
                    if vod_item:
                        current_episodes.append(vod_item)
                        logger.debug(f"Added episode {item_idx}: {vod_item.name}")

                break  # Found the selector block, no need to continue

        logger.debug(f"Returning {len(seasons)} seasons, {len(current_episodes)} episodes")
        return seasons, current_episodes

    def _extract_seasons_from_layout(self, layout: Dict) -> List[VodCategory]:
        """Extract numbered seasons from a program layout."""
        seasons: List[VodCategory] = []

        for block in layout.get("blocks", []):
            if block.get("type") != "bffPaginated":
                continue

            # Check for concurrent blocks (season selector)
            alternative_content = block.get("alternativeContent")

            # CRITICAL FIX: Check if alternative_content is a dict
            if alternative_content and isinstance(alternative_content, dict):
                # Skip if this is a monthly selector
                if alternative_content.get("selectorTemplateId") == "Selector":
                    continue

                concurrent_blocks = alternative_content.get("concurrentBlocks")
                if concurrent_blocks and isinstance(concurrent_blocks, list):
                    for idx, cb in enumerate(concurrent_blocks):
                        if not cb or not isinstance(cb, dict):
                            continue

                        season_title = cb.get("title", f"Staffel {idx + 1}")
                        block_id = cb.get("id")

                        if block_id:
                            seasons.append(VodCategory(
                                name=season_title,
                                content_id=f"season_{block_id}",
                                provider=self._provider.provider_name,
                                description=None,
                                child_count=(
                                    cb.get("content", {})
                                    .get("pagination", {})
                                    .get("totalItems", 0)
                                ),
                            ))

            # Check if block itself is a season selector
            tealium = block.get("analytics", {}).get("tealium", {})
            if tealium.get("template_name") == "SelectorCardListM":
                block_id = block.get("id")
                if block_id:
                    seasons.append(VodCategory(
                        name=(
                            block.get("content", {})
                            .get("title", {})
                            .get("short", "Alle Staffeln")
                        ),
                        content_id=f"season_{block_id}",
                        provider=self._provider.provider_name,
                        child_count=(
                            block.get("content", {})
                            .get("pagination", {})
                            .get("totalItems", 0)
                        ),
                    ))

        return seasons

    def _find_direct_video_in_layout(self, layout: Dict, is_series: bool = False) -> Optional[VodItem]:
        """
        Find a direct playable video item in a program layout.

        Args:
            layout: The program layout
            is_series: If True, skip Jumbotron blocks (for series)
                       If False, include Jumbotron blocks (for movies)
        """
        if not layout or not isinstance(layout, dict):
            return None

        for block_idx, block in enumerate(layout.get("blocks", [])):
            if not block or not isinstance(block, dict):
                continue

            # For series, skip Jumbotron blocks (they're just promos)
            if is_series:
                block_analytics = block.get("analytics", {})
                tealium = block_analytics.get("tealium", {})
                if tealium.get("template_name") == "Jumbotron":
                    logger.debug(f"Skipping Jumbotron block {block_idx} (is_series=True)")
                    continue

            # Skip selector blocks
            alt_content = block.get("alternativeContent", {})
            if alt_content and alt_content.get("selectorTemplateId") == "Selector":
                continue

            # Skip season selectors
            block_analytics = block.get("analytics", {})
            tealium = block_analytics.get("tealium", {})
            if tealium.get("template_name") == "SelectorCardListM":
                continue

            # Collect items from standard content location
            content = block.get("content", {})
            items = list(content.get("items", []) or []) if isinstance(content, dict) else []

            # Also check alternativeContent for concurrent blocks
            if isinstance(alt_content, dict):
                for cb in alt_content.get("concurrentBlocks", []):
                    if isinstance(cb, dict):
                        cb_items = cb.get("content", {}).get("items", [])
                        if cb_items:
                            items.extend(cb_items)

            for item in items:
                if not item or not isinstance(item, dict):
                    continue
                if item.get("itemType") != "classic":
                    continue

                item_content = item.get("itemContent")
                if not item_content or not isinstance(item_content, dict):
                    continue

                # Check for video in action target
                action = item_content.get("action", {})
                if isinstance(action, dict):
                    target = action.get("target", {})
                    if isinstance(target, dict):
                        # Handle lock-wrapped targets
                        if target.get("type") == "lock":
                            lock_value = target.get("value_lock", {})
                            if isinstance(lock_value, dict):
                                target = lock_value.get("originalTarget", {})

                        value_layout = target.get("value_layout", {})
                        if isinstance(value_layout, dict) and value_layout.get("type") == "video":
                            vod_item = self._extract_vod_item_from_block_item(item)
                            if vod_item:
                                clip_id = value_layout.get("id")
                                if clip_id:
                                    vod_item.content_id = clip_id
                                return vod_item

                # Check direct itemContent type
                if item_content.get("type") == "video":
                    clip_id = item_content.get("id")
                    if clip_id:
                        vod_item = VodItem.create_episode(
                            name=item_content.get("title", clip_id),
                            content_id=clip_id,
                            provider=self._provider.provider_name,
                            season_number=-1,
                            episode_number=-1,
                        )
                        vod_item.description = item_content.get("description")
                        vod_item.logo_url = self._extract_thumbnail(item_content)
                        return vod_item

        return None

    def _extract_direct_episodes_from_layout(self, layout: Dict) -> List[VodItem]:
        """
        Extract episodes directly from layout (when there's no season selector).
        """
        episodes = []

        for block in layout.get("blocks", []):
            if block.get("type") != "bffPaginated":
                continue

            # Skip blocks with selectors (they're handled separately)
            if block.get("alternativeContent", {}).get("selectorTemplateId") == "Selector":
                continue

            # Skip numbered season selectors
            tealium = block.get("analytics", {}).get("tealium", {})
            if tealium.get("template_name") == "SelectorCardListM":
                continue

            for item in block.get("content", {}).get("items", []):
                vod_item = self._extract_vod_item_from_block_item(item)
                if vod_item:
                    episodes.append(vod_item)

        return episodes

    # ------------------------------------------------------------------
    # Season block → episodes (legacy, kept for compatibility)
    # ------------------------------------------------------------------

    def _get_season_episodes(
            self,
            season_block_id: str,
            cursor: Optional[str] = None,
            page_size: int = 24,
    ) -> Dict[str, Any]:
        """
        Return VodItem per episode in a season block.
        cursor is the Bedrock page number (1-based).
        """
        return self._get_block_episodes(season_block_id, cursor, page_size, block_type="season")

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_block_id_from_url(block_id: str) -> str:
        """
        Extract the clean block ID from a full block identifier.

        Examples:
        - "page_69fc6d41bb2c28.53532699--c7916bb9-d111-49db-9a99-ab40ef6413da_39638"
          -> "c7916bb9-d111-49db-9a99-ab40ef6413da_39638"
        - "c7916bb9-d111-49db-9a99-ab40ef6413da_39638" -> unchanged
        """
        if "--" in block_id:
            return block_id.split("--")[-1]
        return block_id

    @staticmethod
    def _get_current_month_name() -> Optional[str]:
        """Get the current month name in German (e.g., 'Mai 2026') for UI display."""
        try:
            # Use Europe/Berlin timezone for correct month rollover
            now = datetime.now(ZoneInfo("Europe/Berlin"))
            months = {
                1: "Januar", 2: "Februar", 3: "März", 4: "April",
                5: "Mai", 6: "Juni", 7: "Juli", 8: "August",
                9: "September", 10: "Oktober", 11: "November", 12: "Dezember"
            }
            return f"{months[now.month]} {now.year}"
        except Exception as e:
            logger.warning(f"Could not get current month name: {e}")
            return None

    @staticmethod
    def _paginate_episodes(episodes: List[VodItem], page: int, page_size: int) -> Tuple[List[VodItem], Optional[str]]:
        """
        Paginate a list of episodes.

        Returns:
            tuple: (paginated_episodes, next_cursor)
        """
        start_idx = (page - 1) * page_size

        if start_idx >= len(episodes):
            return [], None

        paginated = episodes[start_idx:start_idx + page_size]
        next_cursor = str(page + 1) if start_idx + page_size < len(episodes) else None

        return paginated, next_cursor

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------

    def _extract_vod_item_from_layout(
            self, layout: Dict, clip_id: str
    ) -> Optional[VodItem]:
        """Build a VodItem from a full video layout (detail view)."""
        assets = self._provider.extract_video_assets(layout)
        if not assets:
            return None

        entity = layout.get("entity", {})
        metadata = entity.get("metadata", {})
        parent = layout.get("parent", {})
        video_meta = layout.get("seo", {}).get("video", {})

        vod_item = VodItem.create_episode(
            name=metadata.get("title", clip_id),
            content_id=clip_id,
            provider=self._provider.provider_name,
            season_number=video_meta.get("season", -1),
            episode_number=video_meta.get("episode", -1),
        )
        vod_item.description = metadata.get("description")
        vod_item.logo_url = self._extract_thumbnail_from_layout(layout)
        vod_item.duration_seconds = video_meta.get("duration")
        vod_item.genre = parent.get("seo", "")
        vod_item.series_title = parent.get("name")

        if any(a.get("drm") for a in assets):
            vod_item.use_cdm = True
            vod_item.cdm_type = "widevine"

        return vod_item

    def _extract_vod_item_from_block_item(self, item: Dict) -> Optional[VodItem]:
        # Early validation
        if not item:
            logger.warning("_extract_vod_item_from_block_item: item is None")
            return None

        if not isinstance(item, dict):
            logger.warning(f"_extract_vod_item_from_block_item: item is {type(item)}, not dict")
            return None

        if item.get("itemType") != "classic":
            return None

        item_content = item.get("itemContent")
        if not item_content:
            logger.debug("_extract_vod_item_from_block_item: no itemContent")
            return None

        if not isinstance(item_content, dict):
            logger.warning(f"_extract_vod_item_from_block_item: item_content is {type(item_content)}")
            return None

        # Try to get video reference from action target first
        action = item_content.get("action", {})
        target = action.get("target", {})
        value_layout = target.get("value_layout", {})

        # Also check for lock-wrapped targets
        if target.get("type") == "lock":
            target = target.get("value_lock", {}).get("originalTarget", {})
            value_layout = target.get("value_layout", {})

        clip_id = None
        program_id = None
        program_slug = None

        if value_layout.get("type") == "video":
            clip_id = value_layout.get("id")
            parent = value_layout.get("parent", {})
            program_id = parent.get("id")
            program_slug = parent.get("seo")
        elif item_content.get("type") == "video":
            clip_id = item_content.get("id")

        # Try alternative action locations
        if not clip_id:
            for action_key in ("onClickAction", "primaryAction", "secondaryAction"):
                alt_action = item_content.get(action_key, {})
                if isinstance(alt_action, dict):
                    alt_target = alt_action.get("target", {})
                    if isinstance(alt_target, dict):
                        alt_value = alt_target.get("value_layout", {})
                        if isinstance(alt_value, dict) and alt_value.get("type") == "video":
                            clip_id = alt_value.get("id")
                            parent = alt_value.get("parent", {})
                            program_id = parent.get("id")
                            program_slug = parent.get("seo")
                            if clip_id:
                                break

        if not clip_id:
            return None

        # Get name with fallback
        title = item_content.get("title") or ""
        extra_title = item_content.get("extraTitle") or ""

        if title and extra_title:
            full_title = f"{title} - {extra_title}"
        elif title:
            full_title = title
        elif extra_title:
            full_title = extra_title
        else:
            highlight = item_content.get("highlight", "")
            if highlight:
                full_title = highlight.split("•")[0].strip() if "•" in highlight else highlight
            else:
                full_title = f"Unbekanntes Video ({clip_id})"

        highlight = item_content.get("highlight", "")
        season_number: Optional[int] = None
        episode_number: Optional[int] = None

        if highlight:
            season_match = re.search(r"Staffel\s*(\d+)", highlight, re.IGNORECASE)
            if season_match:
                season_number = int(season_match.group(1))
            else:
                season_match = re.search(r"S(\d+)", highlight, re.IGNORECASE)
                if season_match:
                    season_number = int(season_match.group(1))

            episode_match = re.search(r"Folge\s*(\d+)", highlight, re.IGNORECASE)
            if episode_match:
                episode_number = int(episode_match.group(1))
            else:
                episode_match = re.search(r"E(\d+)", highlight, re.IGNORECASE)
                if episode_match:
                    episode_number = int(episode_match.group(1))

        vod_item = VodItem.create_episode(
            name=full_title,
            content_id=clip_id,
            provider=self._provider.provider_name,
            season_number=season_number if season_number is not None else -1,
            episode_number=episode_number if episode_number is not None else -1,
        )
        vod_item.description = item_content.get("description")
        vod_item.logo_url = self._extract_thumbnail(item_content)
        vod_item.duration_seconds = self._extract_duration(item_content)
        vod_item.progress = item_content.get("progress", 0)

        # Store program context for manifest fetching
        if program_id or program_slug:
            vod_item.manifest_script = json.dumps({
                "program_id": program_id,
                "program_slug": program_slug,
                "clip_id": clip_id
            })

        return vod_item

    def _extract_vod_category_from_block_item(self, item: Dict) -> Optional[VodCategory]:
        """Build a VodCategory from a list/block item (folder or program row)."""
        if not item or item.get("itemType") != "classic":
            return None

        item_content = item.get("itemContent")
        if not item_content:
            return None

        action = item_content.get("action", {})
        target = action.get("target", {})

        # Handle lock-wrapped targets
        if target.get("type") == "lock":
            target = target.get("value_lock", {}).get("originalTarget", {})

        value_layout = target.get("value_layout", {})

        layout_type = value_layout.get("type")
        if layout_type not in ("folder", "program"):
            return None

        content_id = value_layout.get("id")
        if not content_id:
            return None

        # Store with type prefix for clarity
        if layout_type == "folder":
            content_id = f"folder_{content_id}"
        elif layout_type == "program":
            content_id = f"program_{content_id}"

        seo_slug = value_layout.get("seo") or ""

        name = item_content.get("title")

        if not name and layout_type == "folder":
            if content_id in FOLDER_NAMES:
                name = FOLDER_NAMES[content_id]
            else:
                seo = value_layout.get("seo", "")
                name = seo.replace("-", " ").title() if seo else f"Kategorie {content_id}"
        elif not name:
            name = item_content.get("extraTitle") or item_content.get("highlight")
            if name and "•" in str(name):
                name = name.split("•")[0].strip()

        if not name:
            name = f"Unbekannt {layout_type}"

        return VodCategory(
            name=name,
            content_id=content_id,
            provider=self._provider.provider_name,
            logo_url=self._extract_thumbnail(item_content),
            description=item_content.get("description") or item_content.get("highlight"),
        )

    @staticmethod
    def _item_has_video_assets(item: Dict) -> bool:
        """True when a block item directly carries playable video assets."""
        return bool(
            item.get("itemContent", {})
            .get("video", {})
            .get("assets")
        )

    # ------------------------------------------------------------------
    # Thumbnail / duration helpers (pure, no I/O)
    # ------------------------------------------------------------------

    @staticmethod
    def _build_image_url(image_id: str) -> str:
        """Build a signed Bedrock CDN image URL.

        Hash formula: SHA1("/v2/images/{id}/raw?{params}" + IMAGE_SIGNING_KEY)
        Note: path_and_query starts with /{id}/raw since IMAGE_BASE_URL already
        contains /v2/images — the full signed path is /v2/images/{id}/raw?{params}.
        This is a keyed hash (secret-suffix construction), verified against
        three known-good URLs from network traces.
        """
        import hashlib
        from .constants import RTLPlusDefaults
        suffix = f"/{image_id}/raw?{RTLPlusDefaults.IMAGE_PARAMS}"
        signed_path = f"/v2/images{suffix}"
        image_hash = hashlib.sha1(
            (signed_path + RTLPlusDefaults.IMAGE_SIGNING_KEY).encode()
        ).hexdigest()
        return f"{RTLPlusDefaults.IMAGE_BASE_URL}{suffix}&hash={image_hash}"

    @classmethod
    def _extract_thumbnail(cls, item_content: Dict) -> Optional[str]:
        image = item_content.get("image", {})
        if not image:
            return None
        for ratio in ("16:9", "3:1", "1:1", "2:3"):
            image_id = image.get("idsByRatio", {}).get(ratio)
            if image_id:
                return cls._build_image_url(image_id)
        image_id = image.get("id")
        if image_id:
            return cls._build_image_url(image_id)
        return None

    @classmethod
    def _extract_thumbnail_from_layout(cls, layout: Dict) -> Optional[str]:
        image_id = layout.get("seo", {}).get("image", {}).get("id")
        if image_id:
            return cls._build_image_url(image_id)
        return None

    @staticmethod
    def _extract_duration(item_content: Dict) -> Optional[int]:
        """Parse HH:MM:SS from progressBar.endTitle → seconds."""
        end_title = item_content.get("progressBar", {}).get("endTitle", "")
        if end_title:
            parts = end_title.split(":")
            if len(parts) == 3:
                try:
                    return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
                except ValueError:
                    pass
        return None

    @staticmethod
    def _is_future_event(item_content: Dict) -> bool:
        """Check if item is a future event (should be excluded from VOD)."""
        highlight = item_content.get("highlight", "")
        if not highlight:
            return False

        date_patterns = [
            r"(\d{2})\.(\d{2})\.(\d{2}),?\s*(\d{2}):(\d{2})",  # DD.MM.YY, HH:MM
            r"(\d{2})\.(\d{2})\.(\d{2})\s+(\d{2}):(\d{2})",  # DD.MM.YY HH:MM
        ]

        for pattern in date_patterns:
            match = re.search(pattern, highlight)
            if match:
                day, month, year, hour, minute = map(int, match.groups())
                if year < 100:
                    year = 2000 + year
                try:
                    event_date = datetime(year, month, day, hour, minute)
                    if event_date > datetime.now():
                        return True
                except ValueError:
                    continue
        return False

    @staticmethod
    def _is_event_item(item_content: Dict) -> bool:
        """Check if item is an event (vs regular VOD content)."""
        highlight = item_content.get("highlight", "")
        if not highlight:
            return False

        has_datetime = bool(re.search(r"\d{2}\.\d{2}\.\d{2}", highlight))

        action = item_content.get("action", {})
        target = action.get("target", {})
        value_layout = target.get("value_layout", {})

        # Events are typically folders, not programs or videos
        return has_datetime and value_layout.get("type") == "folder"

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def invalidate_cache(self, content_id: Optional[str] = None) -> None:
        """
        Invalidate cached layouts for the given node, or everything.

        content_id uses the same prefix conventions as get_vod_category.
        """
        if not content_id:
            self._provider.invalidate_layout_cache()
            return

        if content_id.startswith("program_"):
            program_id = content_id[len("program_"):]
            cache_key = (
                f"program:{program_id}"
                f":{RTLPlusDefaults.DEFAULT_BLOCK_PAGE}"
                f":{RTLPlusDefaults.DEFAULT_NB_PAGES}"
            )
            self._provider.invalidate_layout_cache(cache_key)
            # Also invalidate current episodes cache
            self._provider.invalidate_layout_cache(f"program:{program_id}:current_episodes")

        elif content_id.startswith("season_"):
            season_id = content_id[len("season_"):].split("?")[0]
            cache_key = (
                f"block:{season_id}"
                f":{RTLPlusDefaults.DEFAULT_BLOCK_PAGE}"
                f":{RTLPlusDefaults.DEFAULT_BLOCK_NB_PAGES}"
            )
            self._provider.invalidate_layout_cache(cache_key)

        elif content_id.startswith("month_"):
            month_id = content_id[len("month_"):].split("?")[0]
            cache_key = (
                f"block:{month_id}"
                f":{RTLPlusDefaults.DEFAULT_BLOCK_PAGE}"
                f":{RTLPlusDefaults.DEFAULT_BLOCK_NB_PAGES}"
            )
            self._provider.invalidate_layout_cache(cache_key)

        elif content_id.startswith("folder_"):
            folder_id = content_id[len("folder_"):]
            cache_key = (
                f"folder:{folder_id}"
                f":{RTLPlusDefaults.DEFAULT_BLOCK_PAGE}"
                f":{RTLPlusDefaults.DEFAULT_NB_PAGES}"
            )
            self._provider.invalidate_layout_cache(cache_key)

        else:
            # Unknown prefix — wipe everything rather than silently doing nothing
            self._provider.invalidate_layout_cache()