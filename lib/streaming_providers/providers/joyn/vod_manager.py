# streaming_providers/providers/joyn/vod_manager.py
# -*- coding: utf-8 -*-
"""
Joyn VOD Manager - Handles VOD catalogue operations via GraphQL
Supports deep navigation and authenticated requests
"""

import hashlib
import json
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from ...base.models.content import ContentType, StreamingMode
from ...base.models.vod import VodCategory, VodItem
from ...base.utils.logger import logger
from .constants import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_REQUEST_TIMEOUT,
    JOYN_CLIENT_VERSION,
    JOYN_GRAPHQL_BASE_HEADERS,
    JOYN_USER_AGENT,
)
from .models import PlaybackRestrictedException

# ============================================================================
# GraphQL Query Hashes for VOD
# ============================================================================

VOD_GRAPHQL_HASHES = {
    "NAVIGATION": "818622ff5afe143664241034ba0c537650ec9a2eeae4d568830b47d8de605b7e",
    "LANDING_PAGE": "5838ac6b328cda91a70da264d5be09d4735cf95de8d9ee00cec60e77fcc3df08",
    "LANDING_BLOCKS": "1655591f83b0dc1508ad4d52c5f37f72d410f48ad08c3e5f2de8622f86a21c68",
    "GET_ME_STATE": "55ebb3812b45628017ee6c7f36f0b88a94e9778b9f11ad8a6fc05849182c07ec",
    "LIVE_LANE": "51659c62d4e4a6628d1e512190a3b0659486478b12be494875bef5a83dcb79ed",
    "HERO_RESUME": "d3b7e480f593ba4866598f8cfe95185b3e400fcff112c026dc4e1b5ad4b0d537",
    "COLLECTION_QUERY": "bdf4e08de65351750eefb2165a58af50c9e4b3526b78cd75e2066df2bc7ec8d8",
    # --- NEW: captured from browser network tab ---
    "PAGE_OVERVIEW_GENRE": "37ba6d0dde470df3f8999d49bcd24bc5c72b8e7192768026d82447c664c6ab7f",
    "SEASON": "ee2396bb1b7c9f800e5cefd0b341271b7213fceb4ebe18d5a30dab41d703009f",
    # TODO: Capture these hashes from network tab to enable Search and Details
    "SEARCH": "",
    "CONTENT_DETAILS": "",
}

GRAPHQL_OPERATIONS = {
    "NAVIGATION": "Navigation",
    "LANDING_PAGE": "LandingPageClient",
    "LANDING_BLOCKS": "LandingBlocks",
    "GET_ME_STATE": "GetMeState",
    "LIVE_LANE": "LiveLane",
    "HERO_RESUME": "HeroLandingResumePositionsWithToken",
    "COLLECTION_QUERY": "PageOverviewCollectionQuery",
    # --- NEW ---
    "PAGE_OVERVIEW_GENRE": "PageOverviewGenre",
    "SEASON": "Season",
    "SEARCH": "Search",
    "CONTENT_DETAILS": "PageDetail",
}


class JoynVodManager:
    """
    Joyn VOD Manager using GraphQL API
    """

    def __init__(self, provider):
        self.provider = provider
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl: int = 300

        self._query_hashes = VOD_GRAPHQL_HASHES
        self._operations = GRAPHQL_OPERATIONS

        self._user_state = None
        self._has_plus = False

        logger.info(f"[JoynVodManager] Initialised for country={provider.country}")

    # ========================================================================
    # PROPERTIES
    # ========================================================================

    @property
    def http_manager(self):
        return self.provider.http_manager

    @property
    def country(self) -> str:
        return self.provider.country

    @property
    def platform(self) -> str:
        return self.provider.platform

    @property
    def distribution_tenant(self) -> str:
        return self.provider.distribution_tenant

    @property
    def implements_vod(self) -> bool:
        return True

    # ========================================================================
    # CACHING
    # ========================================================================

    def _get_cached_data(self, key: str, fetch_func: Callable, force_refresh: bool = False) -> Any:
        if not force_refresh:
            cached = self._cache.get(key)
            if cached and (time.time() - cached["timestamp"] < self._cache_ttl):
                return cached["data"]
        data = fetch_func()
        self._cache[key] = {"timestamp": time.time(), "data": data}
        return data

    @staticmethod
    def _video_config_fingerprint(video_config: Optional[Dict]) -> str:
        if not video_config:
            return "default"
        normalized = json.dumps(video_config, sort_keys=True, separators=(",", ":"))
        return hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:12]

    # ========================================================================
    # HEADER / URL BUILDING
    # ========================================================================

    def _get_graphql_headers(self, authenticated: bool = False) -> Dict[str, str]:
        headers = JOYN_GRAPHQL_BASE_HEADERS.copy()
        headers.update({
            "joyn-client-version": JOYN_CLIENT_VERSION,
            "joyn-country": self.country.upper(),
            "joyn-distribution-tenant": self.distribution_tenant,
            "joyn-platform": self.platform,
            "joyn-user-state": "code=R_A" if authenticated else "code=A_A",
        })
        if authenticated and self.provider.bearer_token:
            headers["Authorization"] = f"Bearer {self.provider.bearer_token}"
        return headers

    @staticmethod
    def _build_graphql_url(operation_name: str, query_hash: str, variables: Optional[Dict] = None) -> str:
        base_url = "https://api.joyn.de/graphql"
        params = {
            "operationName": operation_name,
            "enable_user_location": "true",
            "watch_assistant_variant": "true",
        }
        if variables:
            params["variables"] = json.dumps(variables, separators=(',', ':'))
        extensions = {"persistedQuery": {"version": 1, "sha256Hash": query_hash}}
        params["extensions"] = json.dumps(extensions, separators=(',', ':'))
        query_string = "&".join(f"{k}={urllib.parse.quote(v)}" for k, v in params.items())
        return f"{base_url}?{query_string}"

    # ========================================================================
    # PATH / ID CLASSIFICATION HELPERS
    # ========================================================================

    @staticmethod
    def _is_block_id(content_id: str) -> bool:
        return ":" in content_id or content_id.startswith("block-")

    @staticmethod
    def _is_season_id(content_id: str) -> bool:
        """Season IDs start with c_ (e.g. c_p0f8glcsxkb)."""
        return content_id.startswith("c_")

    @staticmethod
    def _is_genre_path(path: str) -> bool:
        return "/genre/" in path

    @staticmethod
    def _is_series_path(path: str) -> bool:
        return path.startswith("/serien/") and "/genre/" not in path

    @staticmethod
    def _is_movie_path(path: str) -> bool:
        return path.startswith("/filme/") and "/genre/" not in path

    # ========================================================================
    # NAVIGATION
    # ========================================================================

    def get_navigation(self) -> Dict[str, Any]:
        try:
            url = self._build_graphql_url(
                operation_name=self._operations["NAVIGATION"],
                query_hash=self._query_hashes["NAVIGATION"],
            )
            headers = self._get_graphql_headers(authenticated=False)
            response = self.http_manager.get(url, operation="vod_navigation", headers=headers,
                                             timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status()
            return response.json().get("data") or {}
        except Exception as e:
            logger.error(f"Error fetching navigation: {e}")
            return {}

    def get_navigation_tree(self) -> List[Dict[str, Any]]:
        return self.get_navigation().get("navigation", [])

    def get_navigation_categories(self, parent_title: Optional[str] = None) -> List[VodCategory]:
        nav_items = self.get_navigation_tree()
        categories = []

        for nav_item in nav_items:
            title = nav_item.get("title", "")
            url = nav_item.get("url")
            items = nav_item.get("items", [])

            if parent_title and title != parent_title:
                continue

            if items:
                for sub_item in items:
                    sub_title = sub_item.get("title", "")
                    sub_url = sub_item.get("url", "")
                    categories.append(VodCategory(
                        content_id=sub_url or sub_title,
                        name=sub_title,
                        description=f"{title} - {sub_title}",
                        provider="joyn",
                        fetch_url=sub_url,
                        details_url=sub_url,
                    ))
            elif url:
                categories.append(VodCategory(
                    content_id=url,
                    name=title,
                    description=title,
                    provider="joyn",
                    fetch_url=url,
                    details_url=url,
                ))
        return categories

    def get_mediatheken_brands(self) -> List[VodCategory]:
        try:
            nav = self.get_navigation()
            mediatheken_data = nav.get("mediatheken", {}).get("blocks", [])
            categories = []
            for block in mediatheken_data:
                for asset in block.get("assets", []):
                    if asset.get("__typename") == "Brand":
                        categories.append(VodCategory(
                            content_id=asset.get("id", ""),
                            name=asset.get("title", "Unknown"),
                            logo_url=asset.get("logo", {}).get("url"),
                            description=f"{asset.get('title')} Mediathek",
                            provider="joyn",
                            fetch_url=asset.get("path"),
                            details_url=asset.get("path"),
                        ))
            return categories
        except Exception as e:
            logger.error(f"Error fetching mediatheken: {e}")
            return []

    # ========================================================================
    # GENRE PAGE  (NEW — uses PageOverviewGenre, not LandingPageClient)
    # ========================================================================

    def get_genre_page(
            self, path: str, first: int = 32, offset: int = 0, authenticated: bool = True
    ) -> Dict[str, Any]:
        """Fetch a genre overview page using the PageOverviewGenre operation."""
        try:
            if not path.startswith("/"):
                path = f"/{path}"

            variables = {"first": first, "path": path, "offset": offset}
            url = self._build_graphql_url(
                operation_name=self._operations["PAGE_OVERVIEW_GENRE"],
                query_hash=self._query_hashes["PAGE_OVERVIEW_GENRE"],
                variables=variables,
            )
            headers = self._get_graphql_headers(authenticated=authenticated)
            response = self.http_manager.get(url, operation="vod_genre_page", headers=headers,
                                             timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status()
            data = response.json()

            if "errors" in data:
                logger.warning(f"GraphQL errors in genre page: {data['errors']}")
                return {}

            return (data.get("data") or {}).get("page", {})
        except Exception as e:
            logger.error(f"Error fetching genre page {path}: {e}")
            return {}

    def _get_genre_items(
            self, path: str, authenticated: bool = True, **kwargs
    ) -> List[Union[VodCategory, VodItem]]:
        page = self.get_genre_page(
            path=path,
            authenticated=authenticated,
            first=kwargs.get("first", 32),
            offset=kwargs.get("offset", 0),
        )
        items: List[Union[VodCategory, VodItem]] = []
        for block in page.get("blocks", []):
            for asset in block.get("assets", []):
                item = self._parse_asset(asset)
                if item:
                    items.append(item)
        return items

    # ========================================================================
    # SEASON EPISODES  (NEW — uses Season operation)
    # ========================================================================

    def get_season_episodes(
            self,
            season_id: str,
            first: int = 20,
            offset: int = 0,
            license_filter: str = "FREE",
            authenticated: bool = True,
    ) -> Dict[str, Any]:
        """Fetch episodes for a season using the Season operation."""
        try:
            variables = {
                "id": season_id,
                "first": first,
                "licenseFilter": license_filter,
                "offset": offset,
            }
            url = self._build_graphql_url(
                operation_name=self._operations["SEASON"],
                query_hash=self._query_hashes["SEASON"],
                variables=variables,
            )
            headers = self._get_graphql_headers(authenticated=authenticated)
            response = self.http_manager.get(url, operation="vod_season", headers=headers,
                                             timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status()
            data = response.json()

            if "errors" in data:
                logger.warning(f"GraphQL errors in season query: {data['errors']}")
                return {}

            return (data.get("data") or {}).get("season", {})
        except Exception as e:
            logger.error(f"Error fetching season {season_id}: {e}")
            return {}

    def _get_season_items(
            self, season_id: str, authenticated: bool = True, **kwargs
    ) -> List[Union[VodCategory, VodItem]]:
        """Browse episodes of a season. Fetches both FREE and SVOD, deduplicates."""
        all_episodes: List[VodItem] = []
        seen_ids: set = set()

        for lic_filter in ["FREE", "SVOD"]:
            season_data = self.get_season_episodes(
                season_id=season_id,
                license_filter=lic_filter,
                authenticated=authenticated,
                first=kwargs.get("first", 20),
                offset=kwargs.get("offset", 0),
            )
            for ep in season_data.get("episodes", []):
                ep_id = ep.get("id")
                if ep_id and ep_id not in seen_ids:
                    seen_ids.add(ep_id)
                    item = self._parse_episode_asset(ep)
                    if item:
                        all_episodes.append(item)

        # Sort by episode number
        all_episodes.sort(key=lambda x: (x.episode_number or 9999))
        return all_episodes

    # ========================================================================
    # COLLECTION QUERY
    # ========================================================================

    def get_collection(self, block_id: str, first: int = 32, offset: int = 0, authenticated: bool = True) -> Dict[
        str, Any]:
        try:
            variables = {"first": first, "offset": offset, "blockId": block_id,
                         "hasToken": authenticated and bool(self.provider.bearer_token)}
            url = self._build_graphql_url(
                operation_name=self._operations["COLLECTION_QUERY"],
                query_hash=self._query_hashes["COLLECTION_QUERY"],
                variables=variables,
            )
            headers = self._get_graphql_headers(authenticated=authenticated)
            response = self.http_manager.get(url, operation="vod_collection", headers=headers,
                                             timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            if "errors" in data:
                logger.warning(f"GraphQL errors in collection query: {data['errors']}")
                return {"assets": [], "total": 0}
            block = (data.get("data") or {}).get("block", {})
            return {
                "assets": block.get("assets", []),
                "headline": block.get("headline", ""),
                "id": block.get("id"),
                "typename": block.get("__typename"),
                "total": len(block.get("assets", [])),
            }
        except Exception as e:
            logger.error(f"Error fetching collection {block_id}: {e}")
            return {"assets": [], "total": 0}

    def get_collection_items(self, block_id: str, first: int = 32, offset: int = 0, authenticated: bool = True) -> List[
        Union[VodCategory, VodItem]]:
        result = self.get_collection(block_id, first, offset, authenticated)
        items = []
        for asset in result.get("assets", []):
            item = self._parse_asset(asset)
            if item:
                items.append(item)
        return items

    # ========================================================================
    # LANDING PAGE
    # ========================================================================

    def get_landing_page(self, path: str = "/neu-beliebt", variation: str = "Default", authenticated: bool = True) -> \
    Dict[str, Any]:
        try:
            if not path.startswith("/"):
                path = f"/{path}"
            variables = {"path": path, "variation": variation}
            url = self._build_graphql_url(
                operation_name=self._operations["LANDING_PAGE"],
                query_hash=self._query_hashes["LANDING_PAGE"],
                variables=variables,
            )
            headers = self._get_graphql_headers(authenticated=authenticated)
            response = self.http_manager.get(url, operation="vod_landing_page", headers=headers,
                                             timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            if "errors" in data:
                logger.warning(f"GraphQL errors in landing page: {data['errors']}")
                return {}
            return (data.get("data") or {}).get("page", {})
        except Exception as e:
            logger.error(f"Error fetching landing page {path}: {e}")
            return {}

    def get_landing_blocks(self, block_ids: List[str], authenticated: bool = True) -> Dict[str, Any]:
        try:
            variables = {"ids": block_ids}
            url = self._build_graphql_url(
                operation_name=self._operations["LANDING_BLOCKS"],
                query_hash=self._query_hashes["LANDING_BLOCKS"],
                variables=variables,
            )
            headers = self._get_graphql_headers(authenticated=authenticated)
            response = self.http_manager.get(url, operation="vod_blocks", headers=headers,
                                             timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status()
            return response.json().get("data", {})
        except Exception as e:
            logger.error(f"Error fetching landing blocks: {e}")
            return {}

    # ========================================================================
    # USER STATE
    # ========================================================================

    def get_user_state(self, force_refresh: bool = False) -> Dict[str, Any]:
        def fetch_state():
            try:
                url = self._build_graphql_url(
                    operation_name=self._operations["GET_ME_STATE"],
                    query_hash=self._query_hashes["GET_ME_STATE"],
                    variables={},
                )
                headers = self._get_graphql_headers(authenticated=True)
                response = self.http_manager.get(url, operation="vod_user_state", headers=headers,
                                                 timeout=DEFAULT_REQUEST_TIMEOUT)
                response.raise_for_status()
                data = response.json()
                if "errors" in data:
                    logger.warning(f"GraphQL errors in user state: {data['errors']}")
                    return {}
                state = (data.get("data") or {}).get("me", {})
                subs = state.get("subscriptionsData", {})
                config = subs.get("config", {})
                self._has_plus = config.get("hasActivePlus", False)
                return state
            except Exception as e:
                logger.error(f"Error fetching user state: {e}")
                return {}

        self._user_state = self._get_cached_data("user_state", fetch_state, force_refresh)
        return self._user_state

    def has_plus_subscription(self) -> bool:
        self.get_user_state()
        return self._has_plus

    def get_user_state_code(self) -> str:
        state = self.get_user_state()
        return state.get("state", "code=R_A")

    # ========================================================================
    # VOD CATEGORY — MAIN ENTRY POINT  (FIXED ROUTING)
    # ========================================================================

    def get_vod_category(
            self, content_id: str = "", authenticated: bool = True, **kwargs
    ) -> List[Union[VodCategory, VodItem]]:
        try:
            # --- Root: show navigation categories ---
            if not content_id or content_id == "/":
                return self.get_navigation_categories()

            # --- Block ID (paginated collection) ---
            if self._is_block_id(content_id):
                return self.get_collection_items(
                    block_id=content_id,
                    first=kwargs.get("first", 32),
                    offset=kwargs.get("offset", 0),
                    authenticated=authenticated,
                )

            # --- Season ID (starts with c_) → fetch episodes ---
            if self._is_season_id(content_id):
                return self._get_season_items(content_id, authenticated, **kwargs)

            # --- Normalize path ---
            path = content_id if content_id.startswith("/") else f"/{content_id}"

            # --- Genre page (uses PageOverviewGenre, NOT LandingPageClient) ---
            if self._is_genre_path(path):
                return self._get_genre_items(path, authenticated, **kwargs)

            # --- Series / Movie / Collection landing page ---
            return self._get_page_items(path, authenticated, **kwargs)
        except Exception as e:
            logger.error(f"Error getting VOD category: {e}")
            return []

    # ========================================================================
    # PAGE ITEMS PARSER  (FIXED — handles blocks without __typename)
    # ========================================================================

    def _get_page_items(
            self, path: str, authenticated: bool = True, **kwargs
    ) -> List[Union[VodCategory, VodItem]]:
        if not path.startswith("/"):
            path = f"/{path}"

        page = self.get_landing_page(path=path, authenticated=authenticated)
        items: List[Union[VodCategory, VodItem]] = []

        for block in page.get("blocks", []):
            block_type = block.get("__typename")
            block_id = block.get("id")

            if block_type == "StandardLane" and block_id:
                if kwargs.get("fetch_more", False):
                    items.extend(self.get_collection_items(
                        block_id=block_id,
                        first=kwargs.get("first", 32),
                        offset=kwargs.get("offset", 0),
                        authenticated=authenticated,
                    ))
                else:
                    for asset in block.get("assets", []):
                        item = self._parse_asset(asset)
                        if item:
                            items.append(item)

            elif block_type in ["HeroLane", "FeaturedLane"]:
                for asset in block.get("assets", []):
                    item = self._parse_asset(asset)
                    if item:
                        items.append(item)

            elif block_type == "GenreLane":
                for asset in block.get("assets", []):
                    if asset.get("__typename") == "GenreItem":
                        items.append(VodCategory(
                            content_id=asset.get("path", asset.get("id", "")),
                            name=asset.get("title", ""),
                            logo_url=asset.get("genreImage", {}).get("url"),
                            description=f"Genre: {asset.get('title', '')}",
                            provider="joyn",
                            fetch_url=asset.get("path"),
                        ))

            # --- NEW: handle blocks WITHOUT __typename (genre overview pages,
            #     series detail pages, etc.) — just parse assets directly ---
            elif not block_type and block.get("assets"):
                for asset in block.get("assets", []):
                    item = self._parse_asset(asset)
                    if item:
                        items.append(item)

        return items

    # ========================================================================
    # ASSET PARSING
    # ========================================================================

    def _parse_asset(self, asset: Dict[str, Any]) -> Optional[Union[VodCategory, VodItem]]:
        typename = asset.get("__typename")
        asset_id = asset.get("id", "")
        title = asset.get("title", "Unknown")

        if typename in ["Series", "Movie"]:
            return self._parse_content_asset(asset)
        elif typename == "Episode":
            return self._parse_episode_asset(asset)
        elif typename == "Season":
            # --- NEW: parse Season as a browseable category ---
            return VodCategory(
                content_id=asset_id,
                name=f"Staffel {asset.get('number', '')}".strip(),
                logo_url=asset.get("primaryImage", {}).get("url") or asset.get("iconicImage", {}).get("url"),
                description=asset.get("title", title),
                provider="joyn",
                fetch_url=asset_id,
            )
        elif typename == "Brand":
            return VodCategory(
                content_id=asset_id, name=title,
                logo_url=asset.get("logo", {}).get("url"),
                description=f"{title} Mediathek", provider="joyn",
                fetch_url=asset.get("path"),
            )
        elif typename == "GenreItem":
            return VodCategory(
                content_id=asset.get("path", asset_id), name=title,
                logo_url=asset.get("genreImage", {}).get("url"),
                description=f"Genre: {title}", provider="joyn",
                fetch_url=asset.get("path"),
            )
        elif "watchNext" in asset:
            watch_next = asset.get("watchNext", {})
            if watch_next:
                asset_data = watch_next.get("asset", {})
                if asset_data:
                    return self._parse_asset(asset_data)
        return None

    # ========================================================================
    # CONTENT ASSET PARSER  (FIXED — series use path, movies use video ID)
    # ========================================================================

    def _parse_content_asset(self, asset: Dict[str, Any]) -> Optional[VodItem]:
        typename = asset.get("__typename", "")
        asset_id = asset.get("id", "")
        title = asset.get("title", "Unknown")
        path = asset.get("path", "")

        primary_image = asset.get("primaryImage", {})
        hero_portrait = asset.get("heroPortrait", {})
        iconic_image = asset.get("iconicImage", {})
        image_url = primary_image.get("url") or hero_portrait.get("url") or iconic_image.get("url")

        genres = [g.get("name", "") for g in asset.get("genres", []) if g.get("name")]
        min_age = asset.get("ageRating", {}).get("minAge")

        license_types = asset.get("licenseTypes", [])
        is_free = "AVOD" in license_types or "FREE" in license_types
        is_premium = "SVOD" in license_types or "PLUS" in license_types

        # --- FIX: For Series, use the path as content_id so the user can
        #     browse into it (get_vod_category receives the path).
        #     For Movies, use the video ID if available (for direct playback).
        if typename == "Series":
            content_id = path or asset_id
        else:
            # Movie — prefer video ID for direct playback
            video_id = asset.get("video", {}).get("id")
            content_id = video_id or asset_id

        item = VodItem(
            name=title,
            content_id=content_id,
            provider="joyn",
            logo_url=image_url,
            mode=StreamingMode.VOD,
            content_type=ContentType.SERIES if typename == "Series" else ContentType.MOVIE,
            description=asset.get("description", ""),
            country=self.country,
            duration_seconds=asset.get("duration") or asset.get("video", {}).get("duration"),
            genres=genres or None,
            genre=genres[0] if genres else None,
            series_title=title if typename == "Series" else None,
            rating=f"FSK {min_age}" if min_age is not None else None,
        )

        if is_free:
            item.set_free()
        elif is_premium:
            item.set_subscription(tiers=["PLUS"])

        return item

    # ========================================================================
    # EPISODE ASSET PARSER  (FIXED — correct field names, video ID as content_id)
    # ========================================================================

    def _parse_episode_asset(self, asset: Dict[str, Any]) -> Optional[VodItem]:
        episode_id = asset.get("id", "")
        title = asset.get("title", "Unknown Episode")
        series_data = asset.get("series", {})
        season_data = asset.get("season", {})
        video_data = asset.get("video", {})

        # --- FIX: Use video ID (a_…) as content_id for playback.
        #     The entitlement API requires a video/asset ID, not an episode ID.
        video_id = video_data.get("id", "")
        content_id = video_id or episode_id

        genres = [g.get("name", "") for g in asset.get("genres", []) if g.get("name")]
        license_types = asset.get("licenseTypes", [])
        is_free = "AVOD" in license_types or "FREE" in license_types
        is_premium = "SVOD" in license_types or "PLUS" in license_types

        # --- FIX: field is "number", not "episodeNumber" ---
        ep_number = asset.get("number")
        season_number = season_data.get("seasonNumber")

        description = ""
        if series_data.get("title"):
            description = f"Staffel {season_number}, Episode {ep_number} – {title}"

        item = VodItem(
            name=title,
            content_id=content_id,
            provider="joyn",
            mode=StreamingMode.VOD,
            content_type=ContentType.SERIES,
            description=description,
            country=self.country,
            logo_url=asset.get("primaryImage", {}).get("url"),
            duration_seconds=video_data.get("duration"),
            genres=genres or None,
            genre=genres[0] if genres else None,
            season_number=season_number,
            episode_number=ep_number,
            series_id=series_data.get("id"),
            series_title=series_data.get("title"),
        )

        if is_free:
            item.set_free()
        elif is_premium:
            item.set_subscription(tiers=["PLUS"])

        return item

    # ========================================================================
    # SEARCH & DETAILS (stubs)
    # ========================================================================

    def search(self, query: str, cursor: Optional[str] = None, page_size: int = 24, **kwargs) -> Dict[str, Any]:
        logger.warning("Search GraphQL hash not configured. Search is currently disabled.")
        return {"items": [], "next_cursor": None, "total": 0}

    def get_content_details(self, content_id: str, authenticated: bool = True) -> Optional[Dict[str, Any]]:
        logger.warning("Content Details GraphQL hash not configured. Details fetching is currently disabled.")
        return None

    # ========================================================================
    # VOD PLAYBACK  (FIXED — validates content_id is a video ID)
    # ========================================================================

    def get_vod_manifest(self, content_id: str, video_config: Optional[Dict] = None, **kwargs) -> Optional[str]:
        result = self._get_vod_manifest_and_drm(
            content_id, video_config, max_retries=kwargs.get("max_retries", DEFAULT_MAX_RETRIES)
        )
        return result.get("manifest_url") if result else None

    def get_vod_drm(self, content_id: str, video_config: Optional[Dict] = None, **kwargs) -> List[Any]:
        result = self._get_vod_manifest_and_drm(
            content_id, video_config, max_retries=kwargs.get("max_retries", DEFAULT_MAX_RETRIES)
        )
        return result.get("drm_configs", []) if result else []

    def get_vod_manifest_with_headers(
            self, content_id: str, video_config: Optional[Dict] = None, **kwargs
    ) -> Tuple[Optional[str], Dict[str, str]]:
        result = self._get_vod_manifest_and_drm(
            content_id, video_config, max_retries=kwargs.get("max_retries", DEFAULT_MAX_RETRIES)
        )
        if result and result.get("manifest_url"):
            headers = {
                "Authorization": f"Bearer {result.get('entitlement_token', '')}",
                "Accept": "application/json",
                "User-Agent": JOYN_USER_AGENT,
            }
            return result["manifest_url"], headers
        return None, {}

    def _resolve_video_id(self, content_id: str) -> Optional[str]:
        """
        Resolve any content ID to a video/asset ID (a_…) for playback.

        ID prefix convention (Joyn):
          a_ = video / asset  (what the entitlement API expects)
          b_ = episode
          c_ = season
          d_ = series
        """
        if content_id.startswith("a_"):
            return content_id

        if content_id.startswith("b_"):
            # Episode ID — would need an episode detail query to resolve.
            # In practice, _parse_episode_asset already stores the video ID (a_)
            # as content_id, so this path should not be hit.
            logger.error(
                f"Episode ID '{content_id}' passed to manifest. "
                "The episode parser should have used the video ID instead."
            )
            return None

        if content_id.startswith("d_"):
            logger.error(
                f"Series ID '{content_id}' passed to manifest. "
                "Series are not directly playable — browse to an episode first."
            )
            return None

        if content_id.startswith("c_"):
            logger.error(
                f"Season ID '{content_id}' passed to manifest. "
                "Seasons are not directly playable — browse to an episode first."
            )
            return None

        # Paths or unknown formats
        logger.error(f"Cannot resolve '{content_id}' to a video ID.")
        return None

    def _get_vod_manifest_and_drm(
            self,
            content_id: str,
            video_config: Optional[Dict] = None,
            max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch manifest and DRM config.

        CRITICAL: content_id must be a video/asset ID (starts with a_).
        Series IDs (d_), season IDs (c_), and episode IDs (b_) are NOT accepted
        by the entitlement API and will cause 'ENT_ASSET_NOT_AVAILABLE' errors.
        """
        # --- FIX: Resolve to video ID before anything else ---
        video_id = self._resolve_video_id(content_id)
        if not video_id:
            logger.error(
                f"VOD manifest aborted for '{content_id}': not a valid video ID. "
                "Pass an episode's video ID (a_…) instead."
            )
            return None

        cache_key = f"vod_playlist_{video_id}_{self._video_config_fingerprint(video_config)}"
        cached = self._cache.get(cache_key)
        if cached and (time.time() - cached["timestamp"] < self._cache_ttl):
            return cached["data"]

        from .channel_manager import create_video_payload, build_signature
        from ...base.models import DRMConfig, DRMSystem, LicenseConfig
        from .constants import DRM_REQUEST_HEADERS

        for attempt in range(max_retries):
            try:
                entitlement_token = self.provider.channel_manager.get_entitlement_token(
                    content_id=video_id, content_type="VOD"
                )
                video_payload = create_video_payload(video_config)
                signature = build_signature(entitlement_token, video_payload)

                url = f"https://api.vod-prd.s.joyn.de/v1/vod/{video_id}/playlist?signature={signature}"
                headers = {
                    "Authorization": f"Bearer {entitlement_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "User-Agent": JOYN_USER_AGENT,
                }

                response = self.http_manager.post(
                    url, operation="vod_playlist", headers=headers,
                    data=video_payload, timeout=DEFAULT_REQUEST_TIMEOUT,
                )
                response.raise_for_status()
                playlist_data = response.json()

                manifest_url = playlist_data.get("manifestUrl")
                if not manifest_url:
                    continue

                result = {
                    "manifest_url": manifest_url,
                    "entitlement_token": entitlement_token,
                    "streaming_format": playlist_data.get("streamingFormat", "dash"),
                }

                license_url = playlist_data.get("licenseUrl")
                if license_url:
                    drm_config = DRMConfig(
                        system=DRMSystem.WIDEVINE,
                        priority=1,
                        license=LicenseConfig(
                            server_url=license_url,
                            server_certificate=playlist_data.get("certificateUrl"),
                            req_headers=json.dumps({
                                "User-Agent": JOYN_USER_AGENT,
                                "Content-Type": DRM_REQUEST_HEADERS["Content-Type"],
                            }),
                            req_data="{CHA-RAW}",
                            use_http_get_request=False,
                        ),
                    )
                    result["drm_configs"] = [drm_config]
                else:
                    result["drm_configs"] = []

                self._cache[cache_key] = {"timestamp": time.time(), "data": result}
                return result

            except PlaybackRestrictedException as e:
                logger.warning(f"VOD playback restricted for {video_id}: {e}")
                return None
            except Exception as e:
                logger.warning(f"VOD attempt {attempt + 1}/{max_retries} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(1)

        logger.error(f"VOD failed for {video_id} after {max_retries} attempts")
        return None

    def clear_cache(self):
        self._cache.clear()
        self._user_state = None
        logger.debug("VOD cache cleared")