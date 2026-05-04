# streaming_providers/providers/hrti/vod_manager.py
"""
HRTi VOD Manager - Handles all VOD catalogue operations.

This module contains all VOD-specific logic including:
- Catalogue structure navigation
- Series/season/episode hierarchy
- Special collections (Watch Later, Editor's Choice)
- VOD item parsing and conversion to VodCategory/VodItem
"""

import json
from typing import Dict, List, Optional, Union

from ...base.models.vod import VodCategory, VodItem
from ...base.utils.logger import logger
from .constants import HRTiDefaults


class HRTiVodManager:
    """
    Manages HRTi VOD operations.

    Content ID encoding:
    - ""                           → root catalogue structure
    - "catalogue:{ref_id}"         → items in category (paginated)
    - "series:{ref_id}"            → seasons of a series
    - "season:{series_id}:{season_id}" → episodes of a season
    - "details:{ref_id}"           → single VOD item details
    - "special:watch_later"        → user's watch later list
    - "special:editors_choice"     → editor's picks
    """

    def __init__(self, provider):
        """
        Initialize VOD manager.

        Args:
            provider: HRTiProvider instance (for http_manager, authenticator, config)
        """
        self.provider = provider
        self._config = provider.hrti_config
        self._http_manager = provider.http_manager
        self._authenticator = provider.authenticator

    # --------------------------------------------------------------------------
    # Public API (called by provider.get_vod_category)
    # --------------------------------------------------------------------------

    def get_category(
            self,
            content_id: str = "",
            cursor: Optional[str] = None,
            page_size: int = 24
    ) -> Union[List, Dict]:
        """
        Get VOD category children.

        Args:
            content_id: Opaque node identifier (see encoding above)
            cursor: Pagination cursor (page number as string)
            page_size: Items per page

        Returns:
            - For paginated endpoints: Dict with entries, next_cursor, total
            - For non-paginated: List of VodCategory/VodItem
        """
        if not content_id:
            return self._fetch_catalogue_structure()

        # Parse content_id format
        if content_id.startswith("catalogue:"):
            ref_id = content_id[10:]
            return self._fetch_catalogue_items(ref_id, cursor, page_size)

        elif content_id.startswith("series:"):
            series_id = content_id[7:]
            return self._fetch_series_seasons(series_id)

        elif content_id.startswith("season:"):
            # Format: season:{series_id}:{season_id}
            parts = content_id[7:].split(":", 1)
            if len(parts) == 2:
                series_id, season_id = parts
                return self._fetch_season_episodes(series_id, season_id)
            return []

        elif content_id.startswith("details:"):
            ref_id = content_id[8:]
            item = self._fetch_vod_details(ref_id)
            return [item] if item else []

        elif content_id == "special:watch_later":
            return self._fetch_watch_later()

        elif content_id == "special:editors_choice":
            return self._fetch_editors_choice()

        logger.warning(f"Unknown VOD content_id format: {content_id}")
        return []

    # --------------------------------------------------------------------------
    # API Headers Helper
    # --------------------------------------------------------------------------

    def _get_headers(self, referer_path: str = "/videostore") -> Dict[str, str]:
        """
        Get authenticated headers for VOD API calls.

        Args:
            referer_path: Path part of referer URL (e.g., "/videostore", "/watch_later")
        """
        headers = {
            "deviceid": self._authenticator.get_device_id(),
            "devicetypeid": self._config.device_reference_id,
            "ipaddress": self._authenticator.get_ip_address(),
            "operatorreferenceid": self._config.operator_reference_id,
            "origin": self._config.base_website,
            "referer": f"{self._config.base_website}{referer_path}",
            "User-Agent": self._config.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        # Add authorization if token exists
        if self._authenticator._current_token:
            token = self._authenticator._current_token.access_token
            if token:
                headers["authorization"] = f"Client {token}"

        return headers

    def _post(self, endpoint_key: str, payload: Dict, referer_path: str = "/videostore") -> Optional[Dict]:
        """
        Make authenticated POST request to HRTi API.

        Args:
            endpoint_key: Key in api_endpoints dict
            payload: Request payload
            referer_path: Path for referer header

        Returns:
            Response Result object or None on error
        """
        try:
            url = self._config.api_endpoints.get(endpoint_key)
            if not url:
                logger.error(f"Unknown endpoint key: {endpoint_key}")
                return None

            headers = self._get_headers(referer_path)

            response = self._http_manager.post(
                url,
                operation="api",
                headers=headers,
                data=json.dumps(payload),
            )
            response.raise_for_status()

            data = response.json()
            result = data.get("Result")

            if result is None:
                logger.debug(f"No Result in response for {endpoint_key}")

            return result

        except Exception as e:
            logger.error(f"Error calling {endpoint_key}: {e}")
            return None

    # --------------------------------------------------------------------------
    # Catalogue Methods
    # --------------------------------------------------------------------------

    def _fetch_catalogue_structure(self) -> List[VodCategory]:
        """
        Fetch root catalogue structure from GetCatalogueStructure.

        Returns:
            List of top-level VodCategory nodes
        """
        result = self._post("catalogue_structure", {}, "/videostore")

        if not result or not isinstance(result, list):
            logger.warning("No catalogue structure returned from HRTi")
            return []

        categories = []
        for node in result:
            category = self._parse_catalogue_node(node)
            if category:
                categories.append(category)

        logger.info(f"Retrieved {len(categories)} root VOD categories from HRTi")
        return categories

    def _parse_catalogue_node(self, node: Dict) -> Optional[VodCategory]:
        """
        Parse a catalogue structure node into a VodCategory.

        Expected node structure from GetCatalogueStructure:
        {
            "ReferenceId": "123",
            "Name": "Filmovi",
            "Description": "Movies and feature films",
            "SortOrder": 1,
            "ChildCount": 42,
            "Icon": "https://..."
        }
        """
        try:
            ref_id = node.get("ReferenceId")
            name = node.get("Name", "")

            if not ref_id or not name:
                logger.debug(f"Skipping catalogue node - missing ReferenceId or Name")
                return None

            return VodCategory(
                name=name,
                content_id=f"catalogue:{ref_id}",
                provider=self.provider.provider_name,
                logo_url=node.get("Icon"),
                description=node.get("Description"),
                child_count=node.get("ChildCount"),
            )

        except Exception as e:
            logger.error(f"Error parsing catalogue node: {e}")
            return None

    def _fetch_catalogue_items(
            self,
            ref_id: str,
            cursor: Optional[str] = None,
            page_size: int = 24
    ) -> Dict:
        """
        Fetch paginated catalogue items from GetCatalogue.

        Args:
            ref_id: Catalogue reference ID
            cursor: Page number as string (1-indexed, None = page 1)
            page_size: Items per page

        Returns:
            Dict with entries, next_cursor, total
        """
        # Parse page number from cursor
        page = 1
        if cursor:
            try:
                page = int(cursor)
                if page < 1:
                    page = 1
            except ValueError:
                logger.warning(f"Invalid cursor value: {cursor}, using page 1")

        # Clamp page to max
        if page > HRTiDefaults.MAX_VOD_PAGES:
            logger.warning(f"Page {page} exceeds max {HRTiDefaults.MAX_VOD_PAGES}")
            return {"entries": [], "next_cursor": None, "total": None}

        payload = {
            "ReferenceId": ref_id,
            "ItemsPerPage": page_size,
            "PageNumber": page,
        }

        result = self._post("catalogue", payload, "/videostore")

        if not result:
            return {"entries": [], "next_cursor": None, "total": None}

        # Parse items
        items = result.get("Items", [])
        total_count = result.get("TotalCount")
        has_more = result.get("HasMore", False)

        entries = []
        for item in items:
            parsed = self._parse_catalogue_item(item)
            if parsed:
                entries.append(parsed)

        # Determine next cursor
        next_cursor = None
        if has_more and entries and page < HRTiDefaults.MAX_VOD_PAGES:
            next_cursor = str(page + 1)

        logger.debug(
            f"Retrieved {len(entries)} items for catalogue {ref_id} "
            f"(page {page}, total {total_count}, has_more {has_more})"
        )

        return {
            "entries": entries,
            "next_cursor": next_cursor,
            "total": total_count,
        }

    def _parse_catalogue_item(self, item: Dict) -> Optional[Union[VodCategory, VodItem]]:
        """
        Parse a catalogue item into either VodCategory or VodItem.

        An item is a category if it has ChildCount > 0.
        An item is a series if it has SeriesReferenceId.
        Otherwise it's a playable VOD item.
        """
        try:
            # Check if it's a category (has children)
            child_count = item.get("ChildCount", 0)
            if child_count > 0:
                return VodCategory(
                    name=item.get("Name", ""),
                    content_id=f"catalogue:{item.get('ReferenceId')}",
                    provider=self.provider.provider_name,
                    logo_url=item.get("Icon"),
                    description=item.get("Description"),
                    child_count=child_count,
                )

            # Check if it's a series
            series_ref_id = item.get("SeriesReferenceId")
            if series_ref_id:
                return VodCategory(
                    name=item.get("Name", ""),
                    content_id=f"series:{series_ref_id}",
                    provider=self.provider.provider_name,
                    logo_url=item.get("Icon"),
                    description=item.get("Description"),
                    child_count=item.get("SeasonCount"),
                )

            # Otherwise it's a playable VOD item
            return self._parse_vod_item(item)

        except Exception as e:
            logger.error(f"Error parsing catalogue item: {e}")
            return None

    # --------------------------------------------------------------------------
    # Series, Seasons, Episodes
    # --------------------------------------------------------------------------

    def _fetch_series_seasons(self, series_ref_id: str) -> List[VodCategory]:
        """
        Get seasons for a series from GetSeasons.

        Args:
            series_ref_id: Series reference ID

        Returns:
            List of VodCategory nodes (one per season)
        """
        payload = {"SeriesReferenceId": series_ref_id}
        result = self._post("seasons", payload, "/videostore")

        if not result or not isinstance(result, list):
            logger.warning(f"No seasons returned for series {series_ref_id}")
            return []

        seasons = []
        for season in result:
            season_name = season.get("Name")
            if not season_name:
                season_num = season.get("SeasonNumber")
                season_name = f"Season {season_num}" if season_num else "Unknown Season"

            category = VodCategory(
                name=season_name,
                content_id=f"season:{series_ref_id}:{season.get('ReferenceId')}",
                provider=self.provider.provider_name,
                logo_url=season.get("Icon"),
                description=season.get("Description"),
                child_count=season.get("EpisodeCount"),
            )
            seasons.append(category)

        logger.info(f"Retrieved {len(seasons)} seasons for series {series_ref_id}")
        return seasons

    def _fetch_season_episodes(
            self,
            series_ref_id: str,
            season_ref_id: str
    ) -> List[VodItem]:
        """
        Get episodes for a season from GetEpisodes.

        Args:
            series_ref_id: Series reference ID
            season_ref_id: Season reference ID

        Returns:
            List of VodItem objects (episodes)
        """
        payload = {
            "SeriesReferenceId": series_ref_id,
            "SeasonReferenceId": season_ref_id,
        }
        result = self._post("episodes", payload, "/videostore")

        if not result or not isinstance(result, list):
            logger.warning(f"No episodes returned for season {season_ref_id}")
            return []

        episodes = []
        for episode in result:
            vod_item = self._parse_vod_item(episode)
            if vod_item:
                # Ensure series context is set
                vod_item.series_id = series_ref_id
                episodes.append(vod_item)

        logger.info(
            f"Retrieved {len(episodes)} episodes for season {season_ref_id} "
            f"of series {series_ref_id}"
        )
        return episodes

    # --------------------------------------------------------------------------
    # VOD Item Details
    # --------------------------------------------------------------------------

    def _fetch_vod_details(self, ref_id: str) -> Optional[VodItem]:
        """
        Fetch detailed metadata for a specific VOD item.

        Args:
            ref_id: VOD item reference ID

        Returns:
            VodItem with complete metadata
        """
        payload = {"ReferenceId": ref_id}
        result = self._post("vod_details", payload, "/videostore")

        if not result:
            logger.warning(f"No details returned for VOD item {ref_id}")
            return None

        return self._parse_vod_item(result)

    def _parse_vod_item(self, item: Dict) -> Optional[VodItem]:
        """
        Parse HRTi VOD item into VodItem.

        Expected fields from HRTi API:
        - ReferenceId: string
        - Title: string
        - Description: string (short)
        - DescriptionLong: string (long)
        - OriginalTitle: string
        - Duration / DurationSec: int
        - ReleaseYear: int
        - Rating: string (e.g., "PG-13")
        - Genre: string (primary)
        - Genres: list
        - Cast: list
        - Director: string
        - Season: int (for episodes)
        - EpisodeNr: int (for episodes)
        - SeriesReferenceId: string
        - SeriesTitle: string
        - ImageUrl: string
        - ImageLandscape: string
        - TrailerUrl: string
        - VideoType: string ("CLIP" = highlight, "MOVIE", "EPISODE", "STANDALONE_EVENT")
        - StreamingURL: string (manifest URL)
        """
        try:
            ref_id = item.get("ReferenceId")
            title = item.get("Title", "")

            if not ref_id or not title:
                logger.debug(f"Skipping VOD item - missing ReferenceId or Title")
                return None

            # Parse duration (could be Duration or DurationSec)
            duration = item.get("DurationSec") or item.get("Duration")
            if duration:
                try:
                    duration = int(duration)
                except (ValueError, TypeError):
                    duration = None

            # Parse genres (handle both list of dicts and list of strings)
            genres = item.get("Genres")
            if isinstance(genres, list):
                genres = [
                    g.get("Name") if isinstance(g, dict) else str(g)
                    for g in genres if g
                ]
                genres = [g for g in genres if g]  # Filter empty
            elif isinstance(genres, str):
                genres = [genres] if genres else None

            # Parse cast (handle both list of dicts and list of strings)
            cast = item.get("Cast")
            if isinstance(cast, list):
                cast = [
                    c.get("Name") if isinstance(c, dict) else str(c)
                    for c in cast if c
                ]
                cast = [c for c in cast if c]  # Filter empty
            elif isinstance(cast, str):
                cast = [cast] if cast else None

            # Determine content type and highlight status
            video_type = item.get("VideoType", "")
            is_highlight = video_type == "CLIP"

            # Determine content_type for VodItem
            if video_type == "EPISODE":
                content_type = "SERIES"
            elif video_type == "MOVIE":
                content_type = "MOVIE"
            else:
                content_type = "VOD"

            # Prefer landscape image if available
            logo_url = item.get("ImageLandscape") or item.get("ImageUrl")

            vod_item = VodItem(
                name=title,
                content_id=ref_id,
                provider=self.provider.provider_name,
                logo_url=logo_url,
                description=item.get("Description"),
                long_description=item.get("DescriptionLong"),
                original_title=item.get("OriginalTitle"),
                duration_seconds=duration,
                release_year=item.get("ReleaseYear"),
                rating=item.get("Rating"),
                genre=item.get("Genre"),
                genres=genres,
                cast=cast,
                director=item.get("Director"),
                season_number=item.get("Season"),
                episode_number=item.get("EpisodeNr"),
                series_id=item.get("SeriesReferenceId"),
                series_title=item.get("SeriesTitle"),
                trailer_url=item.get("TrailerUrl"),
                is_highlight=is_highlight,
                content_type=content_type,
                manifest_script=item.get("StreamingURL"),  # For dynamic manifest
            )

            logger.debug(f"Parsed VOD item: {title} ({ref_id})")
            return vod_item

        except Exception as e:
            logger.error(f"Error parsing VOD item: {e}")
            return None

    # --------------------------------------------------------------------------
    # Special Collections
    # --------------------------------------------------------------------------

    def _fetch_watch_later(self) -> List[VodItem]:
        """
        Get user's watch later list from GetWatchLater.

        Requires authenticated user (non-anonymous).

        Returns:
            List of VodItem objects
        """
        result = self._post("watch_later", {}, "/watch_later")

        if not result or not isinstance(result, list):
            logger.debug("No watch later items returned (may require user auth)")
            return []

        items = []
        for item in result:
            vod_item = self._parse_vod_item(item)
            if vod_item:
                items.append(vod_item)

        logger.info(f"Retrieved {len(items)} items from watch later")
        return items

    def _fetch_editors_choice(self) -> List[VodItem]:
        """
        Get editor's picks from GetEditorsChoice.

        Returns:
            List of VodItem objects
        """
        result = self._post("editors_choice", {}, "/editors_choice")

        if not result or not isinstance(result, list):
            logger.debug("No editor's choice items returned")
            return []

        items = []
        for item in result:
            vod_item = self._parse_vod_item(item)
            if vod_item:
                items.append(vod_item)

        logger.info(f"Retrieved {len(items)} items from editor's choice")
        return items

    # --------------------------------------------------------------------------
    # Helper Methods for Provider
    # --------------------------------------------------------------------------

    def get_vod_streaming_url(self, content_id: str) -> Optional[str]:
        """
        Get streaming URL for a VOD item.

        This is called by provider.get_manifest() when content_type="vod".

        Args:
            content_id: VOD item reference ID

        Returns:
            Streaming URL or None
        """
        # First try to get from stored channel data (if already loaded)
        if hasattr(self.provider, 'channels') and self.provider.channels:
            for channel in self.provider.channels:
                if channel.content_id == content_id and channel.manifest_script:
                    return channel.manifest_script

        # Otherwise fetch details
        details = self._fetch_vod_details(content_id)
        if details and details.manifest_script:
            return details.manifest_script

        return None

    def get_vod_session_data(self, content_id: str) -> Optional[Dict]:
        """
        Get session data for VOD playback (used for DRM).

        Args:
            content_id: VOD item reference ID

        Returns:
            Session data dict or None
        """
        try:
            session_data = self._authenticator.authorize_session(
                content_type="vod",
                content_ref_id=content_id,
                content_drm_id=f"{content_id}_drm",
                video_store_ids=None,
                channel_id=None,
                start_time=None,
                end_time=None,
            )
            return session_data
        except Exception as e:
            logger.error(f"Error getting VOD session data for {content_id}: {e}")
            return None