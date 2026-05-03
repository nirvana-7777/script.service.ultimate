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
from typing import Dict, Any, List, Optional, Union

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
                └── season_<block_id>  (block layout → episodes)
                    └── clip_id        (video layout, playable)

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

        content_id conventions
        ----------------------
        ""                       → root
        "folder_<id>"            → Bedrock folder
        "program_<id>"           → program/series
        "season_<id>"            → season block
        "program_<id>/clip_<id>" → direct clip (playable item)
        "clip_<id>"              → direct clip (playable item)
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

        if not content_id:
            return self._get_root_category()

        if content_id.startswith("folder_"):
            folder_id = content_id[7:]
            return self._get_folder_contents(folder_id, cursor, page_size)

        if content_id.startswith("program_"):
            program_id = content_id[8:]
            slug = kwargs.get("slug")
            return self._get_program_contents(program_id, cursor, page_size, slug=slug)

        if content_id.startswith("season_"):
            season_id = content_id[7:]
            return self._get_season_episodes(season_id, cursor, page_size)

        # Bare numeric ID → treat as program (backward compatibility)
        if content_id.isdigit():
            return self._get_program_contents(content_id, cursor, page_size)

        logger.warning(f"Unrecognised VOD content_id format: {content_id!r}")
        return {"entries": [], "next_cursor": None, "total": 0}

    def _get_direct_clip_item(self, clip_id: str, program_id: Optional[str] = None, **kwargs) -> Optional[VodItem]:
        """
        Fetch a direct clip item by its clip_id.
        This is used when we have a path like program_68137/clip_1417600.
        """
        layout = self._provider.fetch_layout(
            layout_type="video",
            content_id=clip_id,
            location=f"{self.cfg.beta_website}{clip_id}",
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
            location=f"{self.cfg.beta_website}{clip_id}",
        )
        if not layout:
            return None
        return self._extract_vod_item_from_layout(layout, clip_id)

    def get_manifest_for_video(self, clip_id: str) -> Optional[str]:
        """
        Resolve the playback manifest URL for a VOD clip.

        Delegates entirely to provider.get_manifest(), which owns
        format/quality selection and redirect resolution.
        """
        return self._provider.get_manifest(clip_id)

    def get_drm_for_video(self, clip_id: str) -> List[DRMConfig]:
        """
        Resolve DRM configuration (Widevine + PlayReady) for a VOD clip.

        Delegates entirely to provider.get_drm(), which owns the
        upfront-token fetch, asset selection, and DRMConfig construction.
        """
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
                location=f"{self.cfg.beta_website}",
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
    # Program contents (handles both movies and series)
    # ------------------------------------------------------------------

    def _get_program_contents(
            self,
            program_id: str,  # "68137" (numeric)
            cursor: Optional[str] = None,
            page_size: int = 24,
            slug: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        program_id format: "68137" (numeric)
        """
        seo = slug or f"p_{program_id}"
        location = f"{self.cfg.beta_website}{seo}-p_{program_id}"

        layout = self._provider.fetch_layout(
            layout_type="program",
            content_id=program_id,
            location=location,
        )

        if not layout:
            logger.error(f"Failed to fetch layout for program {program_id}")
            return {"entries": [], "next_cursor": None, "total": 0}

        if not isinstance(layout, dict):
            logger.error(f"Unexpected layout type for program {program_id}: {type(layout)}")
            return {"entries": [], "next_cursor": None, "total": 0}

        blocks = layout.get("blocks") or []

        # FIRST: Check if this is a movie (direct playable video)
        movie_item = self._find_direct_video_in_layout(layout)
        if movie_item:
            # The item-level title is often a generic category label (e.g. "Film").
            # Prefer the authoritative title from the program layout metadata.
            layout_title = (
                layout.get("entity", {}).get("metadata", {}).get("title")
                or layout.get("seo", {}).get("title")
            )
            if layout_title:
                movie_item.name = layout_title
            # Enrich thumbnail and description from layout metadata if missing
            if not movie_item.logo_url:
                movie_item.logo_url = self._extract_thumbnail_from_layout(layout)
            if not movie_item.description:
                movie_item.description = (
                    layout.get("entity", {}).get("metadata", {}).get("description")
                    or layout.get("seo", {}).get("description")
                )
            return {
                "entries": [movie_item],
                "next_cursor": None,
                "total": 1,
            }

        # SECOND: Look for seasons (series)
        seasons = self._extract_seasons_from_layout(layout)

        if seasons:
            start = 0
            if cursor:
                try:
                    start = int(cursor)
                except ValueError:
                    start = 0

            page = seasons[start: start + page_size]
            next_cursor = str(start + page_size) if (start + page_size) < len(seasons) else None
            return {"entries": page, "next_cursor": next_cursor, "total": len(seasons)}

        logger.warning(f"No seasons or movie found for program {program_id}")
        return {"entries": [], "next_cursor": None, "total": 0}

    def _find_direct_video_in_layout(self, layout: Dict) -> Optional[VodItem]:
        """
        Find a direct playable video item in a program layout.
        Searches through ALL blocks and items without filtering by template.
        """
        if not layout or not isinstance(layout, dict):
            return None

        for block in layout.get("blocks", []):
            if not block or not isinstance(block, dict):
                continue

            # Collect items from standard content location
            content = block.get("content", {})
            items = list(content.get("items", []) or []) if isinstance(content, dict) else []

            # Also check alternativeContent for concurrent blocks
            alt_content = block.get("alternativeContent", {})
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

                item_content = item.get("itemContent", {})
                if not item_content or not isinstance(item_content, dict):
                    continue

                action = item_content.get("action", {})
                if isinstance(action, dict):
                    target = action.get("target", {})
                    if isinstance(target, dict):
                        value_layout = target.get("value_layout", {})
                        if isinstance(value_layout, dict) and value_layout.get("type") == "video":
                            vod_item = self._extract_vod_item_from_block_item(item)
                            if vod_item:
                                clip_id = value_layout.get("id")
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
                        )
                        vod_item.description = item_content.get("description")
                        vod_item.logo_url = self._extract_thumbnail(item_content)
                        return vod_item

                # Check alternative action locations
                for action_key in ("onClickAction", "primaryAction", "secondaryAction"):
                    alt_action = item_content.get(action_key, {})
                    if isinstance(alt_action, dict):
                        alt_target = alt_action.get("target", {})
                        if isinstance(alt_target, dict):
                            alt_value = alt_target.get("value_layout", {})
                            if isinstance(alt_value, dict) and alt_value.get("type") == "video":
                                vod_item = self._extract_vod_item_from_block_item(item)
                                if vod_item:
                                    clip_id = alt_value.get("id")
                                    if clip_id:
                                        vod_item.content_id = clip_id
                                    return vod_item

        return None

    def _extract_seasons_from_layout(self, layout: Dict) -> List[VodCategory]:
        """
        Extract seasons from a program layout.
        Looks for both concurrentBlocks (season selector) and block-level seasons.
        """
        seasons: List[VodCategory] = []

        for block in layout.get("blocks", []):
            if block.get("type") != "bffPaginated":
                continue

            # Check for concurrent blocks (season selector)
            alternative_content = block.get("alternativeContent")
            if alternative_content:
                for cb in alternative_content.get("concurrentBlocks", []):
                    season_title = cb.get("title", "Unbekannte Staffel")
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

    # ------------------------------------------------------------------
    # Season block → episodes
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
        page = 1
        if cursor:
            try:
                page = int(cursor)
            except ValueError:
                page = 1

        layout = self._provider.fetch_layout(
            layout_type="block",
            content_id=season_block_id,
            block_page=page,
            nb_pages=RTLPlusDefaults.DEFAULT_BLOCK_NB_PAGES,
        )
        if not layout:
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

        return {"entries": episodes, "next_cursor": next_cursor, "total": total}

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
            season_number=video_meta.get("season"),
            episode_number=video_meta.get("episode"),
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
        """Build a VodItem from a list/block item (episode row)."""
        if not item or item.get("itemType") != "classic":
            return None

        item_content = item.get("itemContent")
        if not item_content:
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

        Hash formula: SHA1("/v2/images/{id}/raw?{params}" + signing_key)
        """
        import hashlib
        from .constants import RTLPlusDefaults
        path_and_query = f"/v2/images/{image_id}/raw?{RTLPlusDefaults.IMAGE_PARAMS}"
        image_hash = hashlib.sha1(
            (path_and_query + RTLPlusDefaults.IMAGE_SIGNING_KEY).encode()
        ).hexdigest()
        return f"{RTLPlusDefaults.IMAGE_BASE_URL}{path_and_query}&hash={image_hash}"

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

        from datetime import datetime

        date_patterns = [
            r"(\d{2})\.(\d{2})\.(\d{2}),?\s*(\d{2}):(\d{2})",  # DD.MM.YY, HH:MM
            r"(\d{2})\.(\d{2})\.(\d{2})\s+(\d{2}):(\d{2})",    # DD.MM.YY HH:MM
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

        elif content_id.startswith("season_"):
            season_id = content_id[len("season_"):].split("?")[0]
            cache_key = (
                f"block:{season_id}"
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