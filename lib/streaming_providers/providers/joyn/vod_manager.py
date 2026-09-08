# streaming_providers/providers/joyn/vod_manager.py
# -*- coding: utf-8 -*-
"""
Joyn VOD Manager - Handles VOD catalogue operations via GraphQL
Supports deep navigation and authenticated requests
"""

import hashlib
import json
import re
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
    "PAGE_OVERVIEW_GENRE": "37ba6d0dde470df3f8999d49bcd24bc5c72b8e7192768026d82447c664c6ab7f",
    "SEASON": "ee2396bb1b7c9f800e5cefd0b341271b7213fceb4ebe18d5a30dab41d703009f",
    "MOVIE_DETAIL": "9ae6bcd8c45a5e350438d1cc415a022fe053e938c93438509f60ae3abb425fa7",
    "PLAYABLE_ASSET": "e2db6e6f9090f14848d3989920a1342f6813099c65ee7faef1e334f23e390970",
    "SEARCH": "",
}

GRAPHQL_OPERATIONS = {
    "NAVIGATION": "Navigation",
    "LANDING_PAGE": "LandingPageClient",
    "LANDING_BLOCKS": "LandingBlocks",
    "GET_ME_STATE": "GetMeState",
    "LIVE_LANE": "LiveLane",
    "HERO_RESUME": "HeroLandingResumePositionsWithToken",
    "COLLECTION_QUERY": "PageOverviewCollectionQuery",
    "PAGE_OVERVIEW_GENRE": "PageOverviewGenre",
    "SEASON": "Season",
    "MOVIE_DETAIL": "PageMovieDetailStatic",
    "PLAYABLE_ASSET": "PlayableAssetWithToken",
    "SEARCH": "Search",
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

    # ========================================================================
    # GENRE PAGE
    # ========================================================================

    def get_genre_page(self, path: str, first: int = 32, offset: int = 0, authenticated: bool = True) -> Dict[str, Any]:
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

    def _get_genre_items(self, path: str, authenticated: bool = True, **kwargs) -> List[Union[VodCategory, VodItem]]:
        page = self.get_genre_page(path=path, authenticated=authenticated, first=kwargs.get("first", 32),
                                   offset=kwargs.get("offset", 0))
        items: List[Union[VodCategory, VodItem]] = []
        for block in page.get("blocks", []):
            for asset in block.get("assets", []):
                item = self._parse_asset(asset)
                if item:
                    items.append(item)
        return items

    # ========================================================================
    # SERIES / MOVIE DETAIL PAGE (HTML FALLBACK)
    # ========================================================================

    def _extract_page_json(self, html: str) -> Optional[Dict[str, Any]]:
        """Extract the Next.js RSC page payload (initialData) embedded in series/movie detail HTML."""
        match = re.search(
            r'self\.__next_f\.push\(\[1,\s*"a:(\[.*?\])\\n"\]\)', html, re.DOTALL
        )
        if not match:
            return None
        try:
            raw = match.group(1).encode().decode("unicode_escape")
            data = json.loads(raw)
            # data[3] is the props dict; ["initialData"]["page"] holds the series/movie object
            return data[3]["initialData"]["page"]
        except (json.JSONDecodeError, UnicodeDecodeError, IndexError, KeyError, TypeError) as e:
            logger.warning(f"Failed to parse embedded page JSON: {e}")
            return None

    def _get_series_items_fallback(self, path: str, authenticated: bool = True, **kwargs) -> List[
        Union[VodCategory, VodItem]]:
        """Series detail pages: parse the season/episode data Next.js already embeds server-side."""
        url = f"https://www.joyn.de{path}"
        headers = {
            "User-Agent": JOYN_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        }
        try:
            response = self.http_manager.get(
                url, operation="vod_series_html", headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            html = response.text

            page = self._extract_page_json(html)
            if not page:
                logger.warning(f"No embedded page JSON found for {path} (html_len={len(html)})")
                return []

            series = page.get("series", {})
            all_seasons = series.get("allSeasons") or series.get("freeSeasons") or []

            if not all_seasons:
                logger.warning(f"No seasons in embedded data for {path}")
                return []

            all_seasons = sorted(all_seasons, key=lambda s: s.get("number") or 9999)

            if len(all_seasons) == 1:
                items = []
                for ep in all_seasons[0].get("episodes", []):
                    item = self._parse_episode_asset(ep)
                    if item:
                        items.append(item)
                items.sort(key=lambda x: (x.episode_number or 9999))
                return items

            items = []
            for s in all_seasons:
                items.append(VodCategory(
                    content_id=s["id"],
                    name=f"Staffel {s.get('number', '')}".strip(),
                    provider="joyn",
                    fetch_url=s["id"],
                ))
            return items

        except Exception as e:
            logger.error(f"Error fetching series HTML for {path}: {e}")
            return []

    def get_movie_detail(self, path: str, authenticated: bool = True) -> Dict[str, Any]:
        try:
            if not path.startswith("/"):
                path = f"/{path}"
            variables = {"path": path}
            url = self._build_graphql_url(
                operation_name=self._operations["MOVIE_DETAIL"],
                query_hash=self._query_hashes["MOVIE_DETAIL"],
                variables=variables,
            )
            headers = self._get_graphql_headers(authenticated=authenticated)
            response = self.http_manager.get(url, operation="vod_movie_detail", headers=headers,
                                             timeout=DEFAULT_REQUEST_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            if "errors" in data:
                logger.warning(f"GraphQL errors in movie detail: {data['errors']}")
                return {}
            return (data.get("data") or {}).get("page", {}).get("movie", {})
        except Exception as e:
            logger.error(f"Error fetching movie detail {path}: {e}")
            return {}

    def _get_movie_items_fallback(self, path: str, authenticated: bool = True, **kwargs) -> List[VodItem]:
        """Movie detail pages, via GraphQL — no HTML scraping needed."""
        movie = self.get_movie_detail(path, authenticated=authenticated)
        if not movie:
            logger.warning(f"No movie data found for {path}")
            return []
        item = self._parse_content_asset(movie)
        return [item] if item else []

    # ========================================================================
    # SEASON EPISODES
    # ========================================================================

    def get_season_episodes(self, season_id: str, first: int = 20, offset: int = 0, license_filter: str = "FREE",
                            authenticated: bool = True) -> Dict[str, Any]:
        try:
            variables = {"id": season_id, "first": first, "licenseFilter": license_filter, "offset": offset}
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

    def _get_season_items(self, season_id: str, authenticated: bool = True, **kwargs) -> List[
        Union[VodCategory, VodItem]]:
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

    def _get_page_items(self, path: str, authenticated: bool = True, **kwargs) -> List[Union[VodCategory, VodItem]]:
        page = self.get_landing_page(path=path, authenticated=authenticated)
        items: List[Union[VodCategory, VodItem]] = []

        for block in page.get("blocks", []):
            block_type = block.get("__typename")
            block_id = block.get("id")

            if block_type == "StandardLane" and block_id:
                if kwargs.get("fetch_more", False):
                    items.extend(self.get_collection_items(
                        block_id=block_id, first=kwargs.get("first", 32), offset=kwargs.get("offset", 0),
                        authenticated=authenticated,
                    ))
                else:
                    for asset in block.get("assets", []):
                        item = self._parse_asset(asset)
                        if item:
                            items.append(item)

            elif block_type in ["HeroLane", "FeaturedLane", "GenreLane"] or not block_type:
                for asset in block.get("assets", []):
                    item = self._parse_asset(asset)
                    if item:
                        items.append(item)

        return items

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

    # ========================================================================
    # VOD CATEGORY — MAIN ENTRY POINT
    # ========================================================================

    def get_vod_category(self, content_id: str = "", authenticated: bool = True, **kwargs) -> List[
        Union[VodCategory, VodItem]]:
        try:
            if not content_id or content_id == "/":
                return self.get_navigation_categories()

            if self._is_block_id(content_id):
                return self.get_collection_items(block_id=content_id, first=kwargs.get("first", 32),
                                                 offset=kwargs.get("offset", 0), authenticated=authenticated)

            if self._is_season_id(content_id):
                return self._get_season_items(content_id, authenticated, **kwargs)

            path = content_id if content_id.startswith("/") else f"/{content_id}"

            if self._is_genre_path(path):
                return self._get_genre_items(path, authenticated, **kwargs)

            if self._is_series_path(path):
                return self._get_series_items_fallback(path, authenticated, **kwargs)

            if self._is_movie_path(path):
                return self._get_movie_items_fallback(path, authenticated, **kwargs)

            return self._get_page_items(path, authenticated, **kwargs)
        except Exception as e:
            logger.error(f"Error getting VOD category: {e}")
            return []

    # ========================================================================
    # ASSET PARSING
    # ========================================================================

    def _parse_asset(self, asset: Dict[str, Any]) -> Optional[Union[VodCategory, VodItem]]:
        typename = asset.get("__typename")
        asset_id = asset.get("id", "")
        title = asset.get("title", "Unknown")
        path = asset.get("path", "")

        # SERIES = Category (not playable)
        if typename == "Series":
            return VodCategory(
                content_id=path or asset_id,  # Use path for navigation
                name=title,
                logo_url=asset.get("primaryImage", {}).get("url") or asset.get("iconicImage", {}).get("url"),
                description=asset.get("description", ""),
                provider="joyn",
                fetch_url=path or asset_id,  # This will be used to fetch seasons
                child_count=None,
                details_url=path,
            )

        # MOVIE = Playable item (VodItem)
        elif typename == "Movie":
            video_id = asset.get("video", {}).get("id")
            content_id = video_id or asset_id
            item = self._parse_content_asset(asset)
            if item:
                item.content_id = content_id  # Ensure we use the video ID for manifest
            return item

        # EPISODE = Playable item (VodItem)
        elif typename == "Episode":
            return self._parse_episode_asset(asset)

        # SEASON = Category (not playable)
        elif typename == "Season":
            season_num = asset.get("number", "")
            name = f"Staffel {season_num}".strip() if season_num else title
            return VodCategory(
                content_id=asset_id,  # Season ID (e.g., c_piuczpyg0ld)
                name=name,
                logo_url=asset.get("primaryImage", {}).get("url") or asset.get("iconicImage", {}).get("url"),
                description=title,
                provider="joyn",
                fetch_url=asset_id,  # This will be used to fetch episodes
                child_count=None,
                details_url=None,
            )

        # Other types...
        elif typename == "Brand":
            return VodCategory(
                content_id=asset_id,
                name=title,
                logo_url=asset.get("logo", {}).get("url"),
                description=f"{title} Mediathek",
                provider="joyn",
                fetch_url=asset.get("path"),
            )

        elif typename == "GenreItem":
            return VodCategory(
                content_id=asset.get("path", asset_id),
                name=title,
                logo_url=asset.get("genreImage", {}).get("url"),
                description=f"Genre: {title}",
                provider="joyn",
                fetch_url=asset.get("path"),
            )

        return None

    def _parse_content_asset(self, asset: Dict[str, Any]) -> Optional[VodItem]:
        """Parse movie/playable content into VodItem"""
        typename = asset.get("__typename", "")

        # Only handle Movies here, Series should be handled by _parse_asset as VodCategory
        if typename != "Movie":
            return None

        asset_id = asset.get("id", "")
        title = asset.get("title", "Unknown")
        path = asset.get("path", "")

        image_url = asset.get("primaryImage", {}).get("url") or asset.get("heroPortrait", {}).get("url") or asset.get(
            "iconicImage", {}).get("url")
        genres = [g.get("name", "") for g in asset.get("genres", []) if g.get("name")]
        min_age = asset.get("ageRating", {}).get("minAge")
        license_types = asset.get("licenseTypes", [])
        is_free = "AVOD" in license_types or "FREE" in license_types
        is_premium = "SVOD" in license_types or "PLUS" in license_types

        video_id = asset.get("video", {}).get("id")
        content_id = video_id or asset_id

        item = VodItem(
            name=title,
            content_id=content_id,
            provider="joyn",
            logo_url=image_url,
            mode=StreamingMode.VOD,
            content_type=ContentType.MOVIE,
            description=asset.get("description", ""),
            country=self.country,
            duration_seconds=asset.get("duration") or asset.get("video", {}).get("duration"),
            genres=genres or None,
            genre=genres[0] if genres else None,
            rating=f"FSK {min_age}" if min_age is not None else None,
        )

        if is_free:
            item.set_free()
        elif is_premium:
            item.set_subscription(tiers=["PLUS"])

        return item

    def _parse_episode_asset(self, asset: Dict[str, Any]) -> Optional[VodItem]:
        asset_id = asset.get("id", "")
        title = asset.get("title", "Unknown Episode")
        series_data = asset.get("series", {})
        season_data = asset.get("season", {})
        video_data = asset.get("video", {})

        # Use the video ID (a_xxxxx) as content_id for manifest requests
        video_id = video_data.get("id", "")
        content_id = video_id or asset_id

        genres = [g.get("name", "") for g in asset.get("genres", []) if g.get("name")]
        license_types = asset.get("licenseTypes", [])
        is_free = "AVOD" in license_types or "FREE" in license_types
        is_premium = "SVOD" in license_types or "PLUS" in license_types

        ep_number = asset.get("number")
        season_number = season_data.get("seasonNumber")

        description = f"Staffel {season_number}, Episode {ep_number} – {title}" if series_data.get("title") else ""

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
    # VOD PLAYBACK
    # ========================================================================

    def get_vod_manifest(self, content_id: str, video_config: Optional[Dict] = None, **kwargs) -> Optional[str]:
        result = self._get_vod_manifest_and_drm(content_id, video_config,
                                                max_retries=kwargs.get("max_retries", DEFAULT_MAX_RETRIES))
        return result.get("manifest_url") if result else None

    def get_vod_drm(self, content_id: str, video_config: Optional[Dict] = None, **kwargs) -> List[Any]:
        result = self._get_vod_manifest_and_drm(content_id, video_config,
                                                max_retries=kwargs.get("max_retries", DEFAULT_MAX_RETRIES))
        return result.get("drm_configs", []) if result else []

    def get_vod_manifest_with_headers(self, content_id: str, video_config: Optional[Dict] = None, **kwargs) -> Tuple[
        Optional[str], Dict[str, str]]:
        result = self._get_vod_manifest_and_drm(content_id, video_config,
                                                max_retries=kwargs.get("max_retries", DEFAULT_MAX_RETRIES))
        if result and result.get("manifest_url"):
            headers = {
                "Authorization": f"Bearer {result.get('entitlement_token', '')}",
                "Accept": "application/json",
                "User-Agent": JOYN_USER_AGENT,
            }
            return result["manifest_url"], headers
        return None, {}

    def get_playable_asset(self, asset_id: str, authenticated: bool = True) -> Dict[str, Any]:
        """
        Fetch a single playable asset (Movie/Episode) by its b_/c_/d_ id.
        Returns the `asset` object including its `video.id` (a_…) which is
        required for the vod-prd playlist endpoint.
        """
        try:
            url = self._build_graphql_url(
                operation_name=self._operations["PLAYABLE_ASSET"],
                query_hash=self._query_hashes["PLAYABLE_ASSET"],
                variables={"id": asset_id},
            )
            headers = self._get_graphql_headers(authenticated=authenticated)
            response = self.http_manager.get(
                url, operation="vod_playable_asset", headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
            if "errors" in data:
                logger.warning(f"GraphQL errors in PlayableAssetWithToken for {asset_id}: {data['errors']}")
                return {}
            return (data.get("data") or {}).get("asset", {}) or {}
        except Exception as e:
            logger.error(f"Error fetching playable asset {asset_id}: {e}")
            return {}

    def _resolve_video_id(self, content_id: str) -> Optional[str]:
        # Already a video id
        if content_id.startswith("a_"):
            return content_id

        # Catalog asset id (movie/episode) -> resolve via PlayableAssetWithToken
        if content_id.startswith(("b_", "c_", "d_")):
            cache_key = f"video_id::{content_id}"
            cached = self._cache.get(cache_key)
            if cached and (time.time() - cached["timestamp"] < self._cache_ttl):
                return cached["data"]

            asset = self.get_playable_asset(content_id, authenticated=True)
            video_id = (asset.get("video") or {}).get("id")
            if not video_id:
                logger.error(
                    f"Cannot resolve '{content_id}' to a video ID "
                    f"(PlayableAssetWithToken returned no video.id)."
                )
                return None

            self._cache[cache_key] = {"timestamp": time.time(), "data": video_id}
            logger.debug(f"Resolved {content_id} -> {video_id}")
            return video_id

        logger.error(f"Cannot resolve '{content_id}' to a video ID (unknown prefix).")
        return None

    def _get_vod_manifest_and_drm(self, content_id: str, video_config: Optional[Dict] = None,
                                  max_retries: int = DEFAULT_MAX_RETRIES) -> Optional[Dict[str, Any]]:
        video_id = self._resolve_video_id(content_id)
        if not video_id:
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
                entitlement_token = self.provider.channel_manager.get_entitlement_token(content_id=video_id,
                                                                                        content_type="VOD")
                video_payload = create_video_payload(video_config)
                signature = build_signature(entitlement_token, video_payload)

                url = f"https://api.vod-prd.s.joyn.de/v1/asset/{video_id}/playlist?signature={signature}"
                headers = {
                    "Authorization": f"Bearer {entitlement_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "User-Agent": JOYN_USER_AGENT,
                }

                response = self.http_manager.post(url, operation="vod_playlist", headers=headers, data=video_payload,
                                                  timeout=DEFAULT_REQUEST_TIMEOUT)
                response.raise_for_status()
                playlist_data = response.json()

                # --- LOG THE JSON RESPONSE ---
                logger.info(f"=== VOD PLAYLIST API RESPONSE for {video_id} ===")
                logger.info(json.dumps(playlist_data, indent=2))
                logger.info(f"=============================================")
                # -----------------------------

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