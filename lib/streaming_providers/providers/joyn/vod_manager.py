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

    def _get_series_items_fallback(self, path: str, authenticated: bool = True, **kwargs) -> List[
        Union[VodCategory, VodItem]]:
        """Fallback for series detail pages by fetching HTML and extracting season IDs."""
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

            # Extract all season IDs (c_...)
            matches = re.findall(r'["\'](c_[a-z0-9]+)["\']', html)
            season_ids = set(matches)

            if not season_ids:
                logger.warning(f"No season IDs found in HTML for {path}")
                return []

            seasons_meta = []
            for season_id in season_ids:
                # Fetch season metadata to get the number
                # We use first=1 to be lightweight, we just need the number
                season_data = self.get_season_episodes(season_id, first=1, license_filter="FREE",
                                                       authenticated=authenticated)
                if not season_data:
                    season_data = self.get_season_episodes(season_id, first=1, license_filter="SVOD",
                                                           authenticated=authenticated)

                if season_data:
                    seasons_meta.append({
                        "id": season_id,
                        "number": season_data.get("number"),
                    })

            # Sort by season number
            seasons_meta.sort(key=lambda s: s["number"] or 9999)

            # If only one season, return episodes directly
            if len(seasons_meta) == 1:
                return self._get_season_items(seasons_meta[0]["id"], authenticated)

            # Otherwise, return seasons as categories
            items = []
            for s in seasons_meta:
                items.append(VodCategory(
                    content_id=s["id"],
                    name=f"Staffel {s['number']}",
                    provider="joyn",
                    fetch_url=s["id"],
                ))
            return items

        except Exception as e:
            logger.error(f"Error fetching series HTML fallback for {path}: {e}")
            return []

    def _get_movie_items_fallback(self, path: str, authenticated: bool = True, **kwargs) -> List[VodItem]:
        """Fallback for movie detail pages by fetching HTML and extracting video ID."""
        url = f"https://www.joyn.de{path}"
        headers = {
            "User-Agent": JOYN_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        }
        try:
            response = self.http_manager.get(
                url, operation="vod_movie_html", headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            html = response.text

            # Extract video ID (a_...)
            matches = re.findall(r'["\'](a_[a-z0-9]+)["\']', html)
            video_ids = list(set(matches))

            if not video_ids:
                return []

            # Return the first video ID as a VodItem
            return [VodItem(
                name=path.split("/")[-1].replace("-", " ").title(),
                content_id=video_ids[0],
                provider="joyn",
                mode=StreamingMode.VOD,
                content_type=ContentType.MOVIE,
                country=self.country,
            )]
        except Exception as e:
            logger.error(f"Error fetching movie HTML fallback for {path}: {e}")
            return []

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

        if typename in ["Series", "Movie"]:
            return self._parse_content_asset(asset)
        elif typename == "Episode":
            return self._parse_episode_asset(asset)
        elif typename == "Season":
            season_num = asset.get("number", "")
            name = f"Staffel {season_num}".strip() if season_num else title
            return VodCategory(
                content_id=asset_id,
                name=name,
                logo_url=asset.get("primaryImage", {}).get("url") or asset.get("iconicImage", {}).get("url"),
                description=title,
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
        return None

    def _parse_content_asset(self, asset: Dict[str, Any]) -> Optional[VodItem]:
        typename = asset.get("__typename", "")
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

        if typename == "Series":
            content_id = path or asset_id
        else:
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

    def _parse_episode_asset(self, asset: Dict[str, Any]) -> Optional[VodItem]:
        episode_id = asset.get("id", "")
        title = asset.get("title", "Unknown Episode")
        series_data = asset.get("series", {})
        season_data = asset.get("season", {})
        video_data = asset.get("video", {})

        video_id = video_data.get("id", "")
        content_id = video_id or episode_id

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

    def _resolve_video_id(self, content_id: str) -> Optional[str]:
        if content_id.startswith("a_"):
            return content_id
        if content_id.startswith(("b_", "c_", "d_")):
            logger.error(f"Cannot resolve '{content_id}' to a video ID. Pass an episode's video ID (a_…) instead.")
            return None
        logger.error(f"Cannot resolve '{content_id}' to a video ID.")
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

                url = f"https://api.vod-prd.s.joyn.de/v1/vod/{video_id}/playlist?signature={signature}"
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