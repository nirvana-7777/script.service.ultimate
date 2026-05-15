# streaming_providers/providers/rtlplus/favorite_manager.py
"""
RTL+ Favorite Manager

Handles program bookmarks (favorites) using the Bedrock layout API and
bookmark endpoints. Follows the same pattern as vod_manager, channel_manager,
and event_manager.
"""

from typing import Dict, List, Optional

from ...base.models.favorite import Favorite, FavoriteType
from ...base.utils.logger import logger
from .layout_helpers import unwrap_target, extract_thumbnail


# Block/item type identifiers from the RTL+ Bedrock layout API.
# Update these constants if the API schema changes.
_BLOCK_TYPE_PAGINATED = "bffPaginated"
_TEMPLATE_NAME_BOOKMARKS = "PortraitList"
_ITEM_TYPE_CLASSIC = "classic"
_CONTENT_TYPE_PROGRAM = "program"

# Maximum number of pages to fetch when paginating bookmarks.
# Each page contains up to 8 items; 10 pages = up to 80 bookmarks.
_MAX_BOOKMARK_PAGES = 10


class RTLPlusFavoriteManager:
    """
    Manages favorite/bookmarked programs for RTL+.

    Favorites are program-level bookmarks (not clip-level). The user can
    bookmark entire shows/series, which appear in the "Meine gemerkten Inhalte"
    section of the RTL+ frontend.

    API Endpoints:
    - GET: /frontspace/bookmarks/layout (via Bedrock layout system)
    - PUT: https://users.rtlde.bedrock.tech/v4/rtlde/m6group_web/bookmark
    """

    def __init__(self, provider):
        self._provider = provider

    # --------------------------------------------------------------------------
    # Convenience accessors
    # --------------------------------------------------------------------------

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

    def get_favorites(self, **kwargs) -> List[Favorite]:
        """
        Get all bookmarked programs for the authenticated user.

        Paginates through all available pages (up to _MAX_BOOKMARK_PAGES)
        to ensure the full bookmark list is returned.

        Returns:
            List of Favorite objects (programs only, not clips)
        """
        if not self.auth.has_user_credentials():
            logger.warning("RTL+ get_favorites: No user credentials, returning empty list")
            return []

        oauth_token = self._provider.get_user_bearer_token()
        if not oauth_token:
            logger.warning("RTL+ get_favorites: No valid user token")
            return []

        try:
            favorites = self._fetch_all_favorites()
            logger.info(f"RTL+ get_favorites: Found {len(favorites)} bookmarked programs")
            return favorites

        except Exception as e:
            logger.error(f"RTL+ get_favorites failed: {e}", exc_info=True)
            return []

    def add_favorite(
        self,
        content_id: str,
        favorite_type: FavoriteType,
        title: Optional[str] = None,
        **kwargs,
    ) -> Optional[Favorite]:
        """
        Add a program to user's bookmarks.

        Args:
            content_id: Numeric program ID (e.g., "10438")
            favorite_type: Should be FavoriteType.PROGRAM
            title: Program title (optional, for caching)

        Returns:
            Favorite object if successful, None otherwise
        """
        if not self.auth.has_user_credentials():
            logger.error("RTL+ add_favorite: No user credentials")
            return None

        if favorite_type != FavoriteType.PROGRAM:
            logger.warning(
                f"RTL+ add_favorite: Only PROGRAM type supported, got {favorite_type}"
            )
            return None

        if not content_id.isdigit():
            logger.error(
                f"RTL+ add_favorite: content_id must be numeric program ID, got '{content_id}'"
            )
            return None

        success = self._call_bookmark_api(content_id, subscribed=True)
        if not success:
            return None

        # Invalidate cache so subsequent get_favorites() calls reflect the change.
        self.invalidate_cache()

        return Favorite.create(
            provider=self._provider.provider_name,
            content_id=content_id,
            favorite_type=FavoriteType.PROGRAM,
            title=title,
        )

    def remove_favorite(self, content_id: str, **kwargs) -> None:
        """
        Remove a program from user's bookmarks.

        Args:
            content_id: Numeric program ID (e.g., "10438")

        Raises:
            KeyError: If content_id is not a valid numeric program ID
            RuntimeError: If the API call fails or user has no credentials
        """
        if not self.auth.has_user_credentials():
            raise RuntimeError("RTL+ remove_favorite: No user credentials")

        if not content_id.isdigit():
            raise KeyError(
                f"Invalid content_id format: '{content_id}' (expected numeric program ID)"
            )

        # Attempt the removal directly; _call_bookmark_api will return False
        # if the program wasn't bookmarked or the request fails.
        success = self._call_bookmark_api(content_id, subscribed=False)
        if not success:
            raise RuntimeError(f"Failed to remove bookmark for program {content_id}")

        # Invalidate cache so subsequent get_favorites() calls reflect the change.
        self.invalidate_cache()

    def is_favorited(self, content_id: str, favorites: Optional[List[Favorite]] = None) -> bool:
        """
        Check if a specific program is bookmarked.

        Args:
            content_id: Numeric program ID
            favorites: Optional pre-fetched favorites list. Pass this when
                       checking multiple items to avoid redundant API calls.

        Returns:
            True if bookmarked, False otherwise
        """
        if favorites is None:
            favorites = self.get_favorites()
        return any(f.content_id == content_id for f in favorites)

    # --------------------------------------------------------------------------
    # Private helper methods
    # --------------------------------------------------------------------------

    def _fetch_all_favorites(self) -> List[Favorite]:
        """
        Fetch all bookmarked programs by paginating through layout pages.

        Stops early when a page returns no items or when _MAX_BOOKMARK_PAGES
        is reached.

        Returns:
            Combined list of Favorite objects from all pages
        """
        all_favorites: List[Favorite] = []

        for page in range(1, _MAX_BOOKMARK_PAGES + 1):
            layout = self._fetch_bookmarks_layout(block_page=page)
            if not layout:
                if page == 1:
                    logger.warning("RTL+ _fetch_all_favorites: Failed to fetch page 1")
                break

            page_favorites = self._extract_favorites_from_layout(layout)
            if not page_favorites:
                # No items on this page — we've exhausted the list.
                break

            all_favorites.extend(page_favorites)
            logger.debug(
                f"RTL+ _fetch_all_favorites: page {page} returned {len(page_favorites)} items "
                f"(total so far: {len(all_favorites)})"
            )

        return all_favorites

    def _fetch_bookmarks_layout(self, block_page: int = 1) -> Optional[Dict]:
        """
        Fetch a single page of the bookmarks layout from the Bedrock API.

        Args:
            block_page: 1-based page index to fetch

        Returns:
            Layout dict or None if the request failed
        """
        oauth_token = self._provider.get_user_bearer_token()
        if not oauth_token:
            logger.error("RTL+ _fetch_bookmarks_layout: No OAuth token")
            return None

        try:
            bedrock_token = self.auth.get_bedrock_token()
        except Exception as e:
            logger.error(f"RTL+ _fetch_bookmarks_layout: Failed to get Bedrock token: {e}")
            return None

        if not bedrock_token:
            logger.error("RTL+ _fetch_bookmarks_layout: No Bedrock token")
            return None

        url = f"{self.cfg.bedrock_layout_base}/frontspace/bookmarks/layout"
        location = self.cfg.base_website

        headers = self.cfg.get_layout_headers(oauth_token, bedrock_token, location)
        params = {
            "blockPage": block_page,
            "nbPages": 1,  # Fetch one page at a time for correct pagination.
        }

        try:
            response = self.http.get(url, headers=headers, params=params, operation="api")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"RTL+ _fetch_bookmarks_layout: Request failed (page {block_page}): {e}")
            return None

    def _extract_favorites_from_layout(self, layout: Dict) -> List[Favorite]:
        """
        Extract Favorite objects from a bookmarks layout page.

        Looks for blocks with:
        - type = "bffPaginated"
        - analytics.tealium.template_name = "PortraitList"
        - items with itemType = "classic" and action.target.value_layout.type = "program"
        """
        favorites = []

        blocks = layout.get("blocks", [])
        for block in blocks:
            if block.get("type") != _BLOCK_TYPE_PAGINATED:
                continue

            tealium = block.get("analytics", {}).get("tealium", {})
            if tealium.get("template_name") != _TEMPLATE_NAME_BOOKMARKS:
                continue

            items = block.get("content", {}).get("items", [])
            for item in items:
                if item.get("itemType") != _ITEM_TYPE_CLASSIC:
                    continue

                favorite = self._extract_favorite_from_item(item)
                if favorite:
                    favorites.append(favorite)

        return favorites

    def _extract_favorite_from_item(self, item: Dict) -> Optional[Favorite]:
        """
        Extract a single Favorite from a layout item.

        Expected structure (from RTL+ API):
        {
            "itemContent": {
                "title": "Let's Dance",
                "description": "...",
                "image": {...},
                "action": {
                    "target": {
                        "value_layout": {
                            "type": "program",
                            "id": "10438",
                            "seo": "lets-dance"
                        }
                    }
                },
                "bookmark": {"id": "10438", "state": true, "type": "program"}
            }
        }
        """
        item_content = item.get("itemContent", {})
        if not item_content:
            return None

        action = item_content.get("action", {})
        target = unwrap_target(action.get("target", {}))
        value_layout = target.get("value_layout", {})

        if value_layout.get("type") != _CONTENT_TYPE_PROGRAM:
            return None

        program_id = value_layout.get("id")
        if not program_id:
            return None

        title = item_content.get("title", "")
        description = item_content.get("description", "")
        thumbnail_url = extract_thumbnail(item_content)

        bookmark = item_content.get("bookmark", {})
        if not bookmark.get("state", False):
            logger.debug(f"Item {program_id} has bookmark.state=false, skipping")
            return None

        favorite = Favorite.create(
            provider=self._provider.provider_name,
            content_id=program_id,
            favorite_type=FavoriteType.PROGRAM,
            title=title,
        )
        favorite.description = description
        favorite.thumbnail_url = thumbnail_url

        return favorite

    def _call_bookmark_api(self, program_id: str, subscribed: bool) -> bool:
        """
        Call the Bedrock bookmark API to add/remove a favorite.

        Args:
            program_id: Numeric program ID (e.g., "10438")
            subscribed: True to add, False to remove

        Returns:
            True if successful, False otherwise
        """
        oauth_token = self._provider.get_user_bearer_token()
        if not oauth_token:
            logger.error("RTL+ _call_bookmark_api: No OAuth token")
            return False

        url = f"{self.cfg.users_base_url}/bookmark"
        payload = {
            "entityId": program_id,
            "entityType": _CONTENT_TYPE_PROGRAM,
            "subscribed": subscribed,
        }

        headers = {
            "Authorization": f"Bearer {oauth_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            response = self.http.put(
                url,
                headers=headers,
                json=payload,
                operation="api",
            )
            response.raise_for_status()

            result = response.json()
            logger.debug(f"RTL+ bookmark API subscribed={subscribed}: {result}")

            if "subscribed" not in result:
                logger.warning(
                    f"RTL+ _call_bookmark_api: Response missing 'subscribed' field "
                    f"for program {program_id}. Full response: {result}"
                )
                return False

            return result["subscribed"] == subscribed

        except Exception as e:
            logger.error(f"RTL+ _call_bookmark_api failed for program {program_id}: {e}")
            return False

    def invalidate_cache(self) -> None:
        """
        Invalidate the bookmarks layout cache.

        Called automatically after add_favorite() and remove_favorite() to
        ensure subsequent get_favorites() calls return fresh data.
        Can also be called manually if needed.
        """
        cache_key = "bookmarks:layout:*"
        self._provider.invalidate_layout_cache(cache_key)