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
from .layout_helpers import (
    unwrap_target,
    parse_german_datetime,
    build_image_url,
    extract_thumbnail,
    extract_thumbnail_from_layout,
)

FOLDER_NAMES = {
    "4": "Filme",
    "3": "Serien",
    "1": "Reality & Shows",
    "148": "Kids",
    "165": "Anime",
    "6": "Sport",
    "55": "Themenwelten",
}


class RTLPlusVodManager:
    """
    Manages VOD content for RTL+.

    Navigation hierarchy:
        root
        └── folder_<id>        (Bedrock folder, e.g. folder_3 = Serien)
            └── program_<id>   (program layout → seasons or direct video)
                ├── month_<program_id>::<block_id>  (monthly archive selector)
                │   └── episodes (via /program/{id}/block/{block_id} fetch)
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
        - "month_<program_id>::<block_id>" → monthly archive block (2026-05, 2026-04, etc.)
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

        # Handle month block (monthly episode archives) - NEW FORMAT with program_id
        if content_id.startswith("month_"):
            rest = content_id[6:]  # Remove "month_" prefix
            if "::" in rest:
                program_id, block_id = rest.split("::", 1)
                return self._get_program_block_episodes(program_id, block_id, cursor, page_size)
            # Legacy fallback (shouldn't occur after fix)
            return self._get_block_episodes(rest, cursor, page_size, block_type="month")

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

    def _get_program_block_episodes(
        self,
        program_id: str,
        block_id: str,
        cursor: Optional[str] = None,
        page_size: int = 24,
    ) -> Dict[str, Any]:
        """
        Fetch episodes from a month block using the /program/{id}/block/{block_id} endpoint.
        The block_id must be the full page_... ID from concurrentBlocks.
        """
        page = 1
        if cursor:
            try:
                page = int(cursor)
            except ValueError:
                page = 1

        oauth_token = self._provider.get_user_bearer_token() or self.auth.get_bearer_token()
        if not oauth_token:
            logger.error("No OAuth token available for program block episodes")
            return {"entries": [], "next_cursor": None, "total": 0}

        bedrock_token = self.auth.get_bedrock_token()
        if not bedrock_token:
            logger.error("No Bedrock token available for program block episodes")
            return {"entries": [], "next_cursor": None, "total": 0}

        location = f"{self.cfg.base_website}p_{program_id}-p_{program_id}"

        url = f"{self.cfg.bedrock_layout_base}/program/{program_id}/block/{block_id}"
        params = {
            "nbPages": RTLPlusDefaults.DEFAULT_BLOCK_NB_PAGES,
            "page": page,
        }
        headers = self.cfg.get_layout_headers(oauth_token, bedrock_token, location)

        try:
            response = self.http.get(url, headers=headers, params=params, operation="api")
            response.raise_for_status()
            layout = response.json()
        except Exception as e:
            logger.error(f"Failed to fetch program block {block_id} for program {program_id}: {e}")
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

        logger.debug(f"Fetched {len(episodes)}/{total} episodes from program {program_id} block {block_id} (page {page})")
        return {"entries": episodes, "next_cursor": next_cursor, "total": total}

    def _get_block_episodes(
            self,
            block_id: str,
            cursor: Optional[str] = None,
            page_size: int = 24,
            block_type: str = "block"
    ) -> Dict[str, Any]:
        """
        Fetch episodes from a block (works for numbered seasons).

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

        # Use generic block endpoint for numbered seasons
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

        _, current_episodes = self._extract_season_selector_with_episodes(layout, program_id)
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
                target = unwrap_target(action.get("target", {}))
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

            # Keep only the hardcoded folders, in the order they are defined in FOLDER_NAMES.
            folder_by_id = {
                cat.content_id[len("folder_"):]: cat
                for cat in folder_categories
                if cat.content_id.startswith("folder_")
            }
            # Inject any FOLDER_NAMES entries missing from the home layout (e.g. Themenwelten,
            # which lives in a submenu and is not surfaced on the home page).
            for folder_id, folder_name in FOLDER_NAMES.items():
                if folder_id not in folder_by_id:
                    folder_by_id[folder_id] = VodCategory(
                        name=folder_name,
                        content_id=f"folder_{folder_id}",
                        provider=self._provider.provider_name,
                    )
                    logger.debug(f"Injected missing root folder: {folder_name} (id={folder_id})")
            entries = [
                folder_by_id[folder_id]
                for folder_id in FOLDER_NAMES
                if folder_id in folder_by_id
            ]

            if future_events_count > 0:
                logger.info(f"Filtered out {future_events_count} future events from VOD root")

            logger.info(
                f"Found {len(entries)} entries in root VOD category "
                f"(restricted to {len(FOLDER_NAMES)} hardcoded folders, "
                f"{len(program_categories)} programs discarded)"
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
        """
        layout = self._provider.fetch_layout(
            layout_type="folder",
            content_id=folder_id,
        )

        if not layout or not isinstance(layout, dict):
            logger.error(f"Invalid layout for folder {folder_id}")
            return {"entries": [], "next_cursor": None, "total": 0}

        entries: List[Union[VodCategory, VodItem]] = []

        for block in layout.get("blocks", []):
            if block.get("type") != "bffPaginated":
                continue

            # Skip blocks without items
            items = block.get("content", {}).get("items", [])
            if not items:
                continue

            for item in items:
                if not item or item.get("itemType") != "classic":
                    continue

                item_content = item.get("itemContent")
                if not item_content:
                    continue

                # Check if this item has a valid action target
                action = item_content.get("action")
                if not action:
                    # Skip items without actions (like banner images)
                    continue

                target = unwrap_target(action.get("target", {}))
                value_layout = target.get("value_layout", {})

                # Skip if no valid layout type
                if not value_layout.get("type"):
                    continue

                # Try to extract as VodItem first (if it has video assets)
                if self._item_has_video_assets(item):
                    vod_item = self._extract_vod_item_from_block_item(item)
                    if vod_item:
                        entries.append(vod_item)
                else:
                    # Extract as category (folder or program)
                    cat = self._extract_vod_category_from_block_item(item)
                    if cat:
                        entries.append(cat)

        # Deduplicate by content_id, preserving first occurrence
        seen_ids: set = set()
        unique_entries = []
        for e in entries:
            if e.content_id not in seen_ids:
                seen_ids.add(e.content_id)
                unique_entries.append(e)
        entries = unique_entries

        entries.sort(key=lambda e: (e.name or "").lower())
        logger.info(f"Folder {folder_id} returned {len(entries)} entries (alphabetically sorted)")
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
        season_selector, current_episodes = self._extract_season_selector_with_episodes(layout, program_id)

        # SECOND: Check for numbered seasons (plain CardListM blocks not in the selector).
        # Always run — some programs have BOTH a monthly selector AND separate numbered
        # season blocks (e.g. Staffel 13/14 sitting outside the dropdown).
        numbered_seasons = self._extract_seasons_from_layout(layout, program_id)

        if season_selector or numbered_seasons:
            # Merge: selector entries first, then any numbered seasons not already present.
            seen = {c.content_id for c in season_selector}
            for s in numbered_seasons:
                if s.content_id not in seen:
                    season_selector.append(s)
                    seen.add(s.content_id)

            logger.debug(
                f"Found {len(season_selector)} total season entries for program {program_id} "
                f"({len(numbered_seasons)} from plain blocks)"
            )
            return self._handle_series_response(program_id, season_selector, current_episodes, cursor, page_size)

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
                movie_item.logo_url = extract_thumbnail_from_layout(layout)
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

    def _extract_seasons_from_layout(self, layout: Dict, program_id: Optional[str] = None) -> List[VodCategory]:
        """Extract numbered seasons from a program layout.

        All season content_ids use the ``month_{program_id}::`` prefix so they
        are routed to ``_get_program_block_episodes`` (the /program/{id}/block/{block_id}
        endpoint), which is the only endpoint that reliably returns episodes for
        both selector-based and plain CardListM season blocks.
        """
        seasons: List[VodCategory] = []
        seen_content_ids: set = set()

        for block in layout.get("blocks", []):
            if block.get("type") != "bffPaginated":
                continue

            tealium = block.get("analytics", {}).get("tealium", {})
            template_name = tealium.get("template_name")

            # Path 1: Plain CardListM block with a "Staffel N" title.
            # These are individual season blocks (one block per season) rather
            # than a selector wrapping concurrent blocks.
            if template_name == "CardListM":
                block_title = None
                content_title = block.get("content", {}).get("title", {})
                if isinstance(content_title, dict):
                    block_title = content_title.get("short") or content_title.get("long")
                if not block_title:
                    block_title = tealium.get("block_title")

                if block_title and "Staffel" in block_title:
                    block_id = block.get("id") or block.get("blockId")
                    if block_id:
                        clean_id = self._extract_block_id_from_url(block_id)
                        candidate_id = (
                            f"month_{program_id}::{clean_id}"
                            if program_id
                            else f"season_{clean_id}"
                        )
                        if candidate_id not in seen_content_ids:
                            total_items = (
                                block.get("content", {})
                                .get("pagination", {})
                                .get("totalItems", 0)
                            )
                            logger.debug(
                                f"Found plain CardListM season block: {block_title!r} "
                                f"(raw_id={block_id}, clean_id={clean_id}, total_items={total_items})"
                            )
                            seasons.append(VodCategory(
                                name=block_title,
                                content_id=candidate_id,
                                provider=self._provider.provider_name,
                                description=None,
                                child_count=total_items,
                            ))
                            seen_content_ids.add(candidate_id)
                continue  # Block fully handled; skip selector logic below.

            # Path 2: Block with alternativeContent containing concurrentBlocks
            # (season selector wrapping multiple season blocks).
            alternative_content = block.get("alternativeContent")
            if alternative_content and isinstance(alternative_content, dict):
                # Skip monthly archive selectors — handled by _extract_season_selector_with_episodes.
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
                            clean_id = self._extract_block_id_from_url(block_id)
                            candidate_id = (
                                f"month_{program_id}::{clean_id}"
                                if program_id
                                else f"season_{clean_id}"
                            )
                            if candidate_id not in seen_content_ids:
                                seasons.append(VodCategory(
                                    name=season_title,
                                    content_id=candidate_id,
                                    provider=self._provider.provider_name,
                                    description=None,
                                    child_count=(
                                        cb.get("content", {})
                                        .get("pagination", {})
                                        .get("totalItems", 0)
                                    ),
                                ))
                                seen_content_ids.add(candidate_id)

            # Path 3: Block is itself a season selector (SelectorCardListM).
            # Only reached when alternativeContent is absent or non-dict, so
            # there is no overlap with Path 2.
            elif template_name == "SelectorCardListM":
                block_id = block.get("id") or block.get("blockId")
                if block_id:
                    clean_id = self._extract_block_id_from_url(block_id)
                    candidate_id = (
                        f"month_{program_id}::{clean_id}"
                        if program_id
                        else f"season_{clean_id}"
                    )
                    if candidate_id not in seen_content_ids:
                        seasons.append(VodCategory(
                            name=(
                                block.get("content", {})
                                .get("title", {})
                                .get("short", "Alle Staffeln")
                            ),
                            content_id=candidate_id,
                            provider=self._provider.provider_name,
                            description=None,
                            child_count=(
                                block.get("content", {})
                                .get("pagination", {})
                                .get("totalItems", 0)
                            ),
                        ))
                        seen_content_ids.add(candidate_id)

        # Sort seasons by number (Staffel 1, 2, 3...); unnamed/unnumbered go last.
        def get_season_number(cat: VodCategory) -> int:
            match = re.search(r"Staffel\s*(\d+)", cat.name, re.IGNORECASE)
            return int(match.group(1)) if match else 999

        seasons.sort(key=get_season_number)

        return seasons

    @staticmethod
    def _handle_series_response(program_id: str, season_selector: List[VodCategory],
                                current_episodes: List[VodItem], cursor: Optional[str],
                                page_size: int) -> Dict[str, Any]:
        """Handle series response with monthly selector.

        Layout returned to the caller:
          1. Current-month episodes inlined as VodItems (no extra navigation step).
          2. Season VodCategories sorted ascending by season number (Staffel 1, 2, …).

        The legacy "Aktuelle Folgen" VodCategory / episodes_current_ cursor path is
        intentionally removed: the episodes are already present at the top level so
        there is no need for an extra folder or a separate pagination cursor.
        """
        # Sort seasons ascending (Staffel 1, Staffel 2, …); unnamed entries go last.
        def _season_number(cat: VodCategory) -> int:
            m = re.search(r"Staffel\s*(\d+)", cat.name or "", re.IGNORECASE)
            return int(m.group(1)) if m else 999

        sorted_seasons = sorted(season_selector, key=_season_number)

        # Inline current episodes at the top, then season folders below.
        entries: List = list(current_episodes) + sorted_seasons

        return {
            "entries": entries,
            "next_cursor": None,
            "total": len(entries),
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

    def _extract_season_selector_with_episodes(self, layout: Dict, program_id: Optional[str] = None) -> Tuple[List[VodCategory], List[VodItem]]:
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

                            # Store with program_id for proper endpoint routing
                            content_id = f"month_{program_id}::{block_id}" if program_id else f"month_{block_id}"
                            seasons.append(VodCategory(
                                name=month_title,
                                content_id=content_id,
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
                    target = unwrap_target(action.get("target", {}))
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
                        vod_item.logo_url = extract_thumbnail(item_content)
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
        vod_item.logo_url = extract_thumbnail_from_layout(layout)
        vod_item.duration_seconds = video_meta.get("duration")
        vod_item.genre = parent.get("seo", "")
        vod_item.series_title = parent.get("name")

        if any(a.get("drm") for a in assets):
            vod_item.use_cdm = True
            vod_item.cdm_type = "widevine"

        return vod_item

    def _extract_vod_item_from_block_item(self, item: Dict) -> Optional[VodItem]:
        # Early validation
        if not item or not isinstance(item, dict) or item.get("itemType") != "classic":
            return None

        item_content = item.get("itemContent")
        if not item_content or not isinstance(item_content, dict):
            return None

        # Unwrap lock-wrapped targets
        action = item_content.get("action", {})
        target = unwrap_target(action.get("target", {}))
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
                    alt_target = unwrap_target(alt_action.get("target", {}))
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

        # Extract all available metadata
        series_title = item_content.get("title") or ""
        extra_title = item_content.get("extraTitle") or ""
        highlight = item_content.get("highlight", "")
        description = item_content.get("description", "")
        extra_details = item_content.get("extraDetails", "")

        # Episode title sourced from image.caption when available, falling back to
        # extraTitle. image.caption often carries the specific episode name even
        # when extraTitle is absent.
        image = item_content.get("image", {}) or {}
        episode_title = image.get("caption") or extra_title

        # Parse season and episode numbers from highlight and extraDetails
        season_number: Optional[int] = None
        episode_number: Optional[int] = None
        air_date_str: Optional[str] = None
        year_str: Optional[str] = None

        def parse_season_episode(text: str) -> None:
            """Extract season/episode numbers into outer scope variables.
            Only writes if not already populated, so higher-priority fields
            (highlight) are never overwritten by lower-priority ones (extraDetails)."""
            nonlocal season_number, episode_number

            if not text:
                return

            if season_number is None:
                season_match = re.search(r"Staffel\s*(\d+)", text, re.IGNORECASE)
                if not season_match:
                    # Word-boundary anchor prevents false positives like "SD" or "S-Bahn"
                    season_match = re.search(r"\bS(\d+)\b", text, re.IGNORECASE)
                if season_match:
                    season_number = int(season_match.group(1))

            if episode_number is None:
                episode_match = re.search(r"Folge\s*(\d+)", text, re.IGNORECASE)
                if not episode_match:
                    episode_match = re.search(r"\bE(\d+)\b", text, re.IGNORECASE)
                if not episode_match:
                    episode_match = re.search(r"\bTeil\s*(\d+)\b", text, re.IGNORECASE)
                if episode_match:
                    episode_number = int(episode_match.group(1))

        # Parse highlight first (highest priority)
        if highlight:
            parse_season_episode(highlight)

            date_match = re.search(r"(\d{2})\.(\d{2})\.(\d{2,4})", highlight)
            if date_match:
                day, month, year = date_match.groups()
                if len(year) == 2:
                    year = f"20{year}"
                air_date_str = f"{day}.{month}.{year}"

        # Fall back to extraDetails for season/episode if highlight didn't provide them
        if extra_details and (season_number is None or episode_number is None):
            parse_season_episode(extra_details)

        # Extract broadcast year from extraDetails (e.g. "1991 • 22 Min.").
        # Anchored to plausible broadcast years to avoid matching clip IDs or
        # duration fragments.
        if extra_details and not year_str:
            year_match = re.search(r"\b(19|20)\d{2}\b", extra_details)
            if year_match:
                year_str = year_match.group(0)

        # Build the display name based on content type
        display_name = None

        # Case 1: Has episode title (from image.caption or extraTitle)
        if episode_title:
            if season_number and episode_number:
                display_name = f"{episode_title} (S{season_number:02d}/E{episode_number:02d})"
            elif episode_number:
                display_name = f"{episode_title} (E{episode_number:02d})"
            elif air_date_str:
                display_name = f"{episode_title} - {air_date_str}"
            else:
                display_name = episode_title
                # Append year only for standalone/movie content — for a named series
                # every episode would share the same year, adding no disambiguation value
                if year_str and not series_title:
                    display_name = f"{display_name} ({year_str})"

        # Case 2: No episode title, but parsed episode/season numbers
        elif highlight and (season_number or episode_number):
            if season_number and episode_number:
                display_name = f"Staffel {season_number} • Folge {episode_number}"
            elif episode_number:
                display_name = f"Folge {episode_number}"
            else:
                parts = highlight.split("•")
                display_name = " • ".join(parts[1:]).strip() if len(parts) >= 2 else highlight

            if air_date_str and air_date_str not in display_name:
                display_name = f"{display_name} - {air_date_str}"

        # Case 3: Has date only (daily shows like news, talk shows)
        elif air_date_str:
            if series_title:
                display_name = f"{series_title} - {air_date_str}"
            elif highlight:
                series_part = highlight.split("•")[0].strip()
                display_name = f"{series_part} - {air_date_str}"
            else:
                display_name = air_date_str

        # Case 4: Short description (movies where description is the plot synopsis)
        elif description and len(description) < 100 and "•" not in description:
            display_name = description

        # Case 5: Series title with movie vs. episodic disambiguation
        elif series_title:
            if season_number or episode_number:
                # Episodic content without a clean title: slice the highlight
                if highlight and "•" in highlight:
                    parts = highlight.split("•")
                    display_name = " • ".join(parts[1:]).strip()
                else:
                    display_name = highlight or series_title
            else:
                # No episode indicators — treat as a movie or standalone clip
                display_name = series_title

        else:
            # Ultimate fallback
            display_name = highlight or f"Unbekanntes Video ({clip_id})"

        # Normalise whitespace and strip stray punctuation introduced by concatenation
        if display_name:
            display_name = re.sub(r'\s+', ' ', display_name).strip(' -–—•\t\r\n')

        # Create the VodItem
        vod_item = VodItem.create_episode(
            name=display_name,
            content_id=clip_id,
            provider=self._provider.provider_name,
            season_number=season_number if season_number is not None else -1,
            episode_number=episode_number if episode_number is not None else -1,
        )

        # Store additional metadata
        vod_item.series_title = series_title or None
        vod_item.episode_title = episode_title or None
        vod_item.description = description or highlight or extra_details
        vod_item.logo_url = extract_thumbnail(item_content)
        vod_item.duration_seconds = self._extract_duration(item_content)
        vod_item.progress = item_content.get("progress", 0)

        if air_date_str:
            vod_item.air_date = air_date_str

        if year_str:
            vod_item.year = int(year_str)

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
        target = unwrap_target(action.get("target", {}))
        value_layout = target.get("value_layout", {})

        layout_type = value_layout.get("type")
        if layout_type not in ("folder", "program"):
            return None

        content_id = value_layout.get("id")
        if not content_id:
            return None

        # Store the raw ID for folder name mapping (before adding prefix)
        raw_id = content_id

        # Add prefix for content_id
        if layout_type == "folder":
            content_id = f"folder_{content_id}"
        elif layout_type == "program":
            content_id = f"program_{content_id}"

        seo_slug = value_layout.get("seo") or ""

        # Extract name with priority order
        name = item_content.get("title")

        if not name and layout_type == "folder":
            # FIX: Use raw_id (without "folder_" prefix) to check FOLDER_NAMES
            if raw_id in FOLDER_NAMES:
                name = FOLDER_NAMES[raw_id]
            else:
                # Try image caption as fallback (API provides good names here)
                image = item_content.get("image", {})
                if image.get("caption"):
                    name = image.get("caption")
                else:
                    # Fallback to SEO slug
                    name = seo_slug.replace("-", " ").title() if seo_slug else f"Kategorie {raw_id}"
        elif not name:
            # For programs or when title is missing
            name = item_content.get("extraTitle") or item_content.get("highlight")
            if name and "•" in str(name):
                name = name.split("•")[0].strip()

        if not name:
            name = f"Unbekannt {layout_type}"

        return VodCategory(
            name=name,
            content_id=content_id,
            provider=self._provider.provider_name,
            logo_url=extract_thumbnail(item_content),
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

    # build_image_url and extract_thumbnail are re-exported here as classmethods
    # for any callers that still reference them via the class (e.g. tests).
    # New code should import directly from layout_helpers.

    @classmethod
    def _build_image_url(cls, image_id: str) -> str:
        return build_image_url(image_id)

    @classmethod
    def _extract_thumbnail(cls, item_content: Dict) -> Optional[str]:
        return extract_thumbnail(item_content)

    @classmethod
    def _extract_thumbnail_from_layout(cls, layout: Dict) -> Optional[str]:
        return extract_thumbnail_from_layout(layout)

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
        event_date = parse_german_datetime(highlight)
        return event_date is not None and event_date > datetime.now()

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
            rest = content_id[6:]
            block_id = rest.split("::", 1)[-1] if "::" in rest else rest.split("?")[0]
            cache_key = (
                f"block:{block_id}"
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