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

    # ============================================================================
    # PROPERTIES - Delegate to provider
    # ============================================================================

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

    # ============================================================================
    # CACHING HELPER
    # ============================================================================

    def _get_cached_data(self, key: str, fetch_func: Callable, force_refresh: bool = False) -> Any:
        """Generic TTL cache wrapper."""
        if not force_refresh:
            cached = self._cache.get(key)
            if cached and (time.time() - cached["timestamp"] < self._cache_ttl):
                return cached["data"]

        data = fetch_func()
        self._cache[key] = {"timestamp": time.time(), "data": data}
        return data

    @staticmethod
    def _video_config_fingerprint(video_config: Optional[Dict]) -> str:
        """
        Stable short hash of video_config so the manifest/DRM cache can't
        return one config's result for a different config's request.
        """
        if not video_config:
            return "default"
        normalized = json.dumps(video_config, sort_keys=True, separators=(",", ":"))
        return hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:12]

    # ============================================================================
    # HEADER BUILDING - Matched exactly to web logs
    # ============================================================================

    def _get_graphql_headers(self, authenticated: bool = False) -> Dict[str, str]:
        """Get headers for GraphQL requests."""
        # Use the base headers from constants to avoid magic string duplication
        headers = JOYN_GRAPHQL_BASE_HEADERS.copy()
        headers.update({
            "joyn-client-version": JOYN_CLIENT_VERSION,
            "joyn-country": self.country.upper(),
            "joyn-distribution-tenant": self.distribution_tenant,
            "joyn-platform": self.platform,
            # R_A = Registered Account (logged in), A_A = Anonymous Account
            "joyn-user-state": "code=R_A" if authenticated else "code=A_A",
        })

        if authenticated and self.provider.bearer_token:
            headers["Authorization"] = f"Bearer {self.provider.bearer_token}"

        return headers

    @staticmethod
    def _build_graphql_url(
        operation_name: str,
        query_hash: str,
        variables: Optional[Dict] = None,
    ) -> str:
        """Build GraphQL URL with persisted query"""
        base_url = "https://api.joyn.de/graphql"

        params = {
            "operationName": operation_name,
            "enable_user_location": "true",
            "watch_assistant_variant": "true",
        }

        if variables:
            params["variables"] = json.dumps(variables, separators=(',', ':'))

        extensions = {
            "persistedQuery": {
                "version": 1,
                "sha256Hash": query_hash,
            }
        }
        params["extensions"] = json.dumps(extensions, separators=(',', ':'))

        query_string = "&".join(
            f"{key}={urllib.parse.quote(value)}"
            for key, value in params.items()
        )

        return f"{base_url}?{query_string}"

    # ============================================================================
    # NAVIGATION / DEEP TREE
    # ============================================================================

    def get_navigation(self) -> Dict[str, Any]:
        """Get the main navigation structure"""
        try:
            url = self._build_graphql_url(
                operation_name=self._operations["NAVIGATION"],
                query_hash=self._query_hashes["NAVIGATION"],
            )
            headers = self._get_graphql_headers(authenticated=False)

            response = self.http_manager.get(
                url, operation="vod_navigation", headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            # FIX: Use `or {}` to handle {"data": null} safely
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

    # ============================================================================
    # COLLECTION QUERY - Paginated Browsing
    # ============================================================================

    def get_collection(
        self, block_id: str, first: int = 32, offset: int = 0, authenticated: bool = True
    ) -> Dict[str, Any]:
        try:
            variables = {
                "first": first, "offset": offset, "blockId": block_id,
                "hasToken": authenticated and bool(self.provider.bearer_token),
            }
            url = self._build_graphql_url(
                operation_name=self._operations["COLLECTION_QUERY"],
                query_hash=self._query_hashes["COLLECTION_QUERY"],
                variables=variables,
            )
            headers = self._get_graphql_headers(authenticated=authenticated)

            response = self.http_manager.get(
                url, operation="vod_collection", headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()

            if "errors" in data:
                logger.warning(f"GraphQL errors in collection query: {data['errors']}")
                return {"assets": [], "total": 0}

            # FIX: Use `or {}` to handle {"data": null} safely
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

    def get_collection_items(
        self, block_id: str, first: int = 32, offset: int = 0, authenticated: bool = True
    ) -> List[Union[VodCategory, VodItem]]:
        result = self.get_collection(block_id, first, offset, authenticated)
        items = []
        for asset in result.get("assets", []):
            item = self._parse_asset(asset)
            if item:
                items.append(item)
        return items

    # ============================================================================
    # LANDING PAGE & GENRES
    # ============================================================================

    def get_landing_page(
            self, path: str = "/neu-beliebt", variation: str = "Default", authenticated: bool = True
    ) -> Dict[str, Any]:
        try:
            # FIX: Ensure path starts with '/'
            if not path.startswith("/"):
                path = f"/{path}"

            variables = {"path": path, "variation": variation}
            url = self._build_graphql_url(
                operation_name=self._operations["LANDING_PAGE"],
                query_hash=self._query_hashes["LANDING_PAGE"],
                variables=variables,
            )
            headers = self._get_graphql_headers(authenticated=authenticated)

            response = self.http_manager.get(
                url, operation="vod_landing_page", headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()

            if "errors" in data:
                logger.warning(f"GraphQL errors in landing page: {data['errors']}")
                return {}

            # FIX: Use `or {}` to handle {"data": null} safely
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

            response = self.http_manager.get(
                url, operation="vod_blocks", headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            return response.json().get("data", {})
        except Exception as e:
            logger.error(f"Error fetching landing blocks: {e}")
            return {}

    # ============================================================================
    # USER STATE / SUBSCRIPTION
    # ============================================================================

    def get_user_state(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Get user state including subscription status, utilizing TTL cache."""

        def fetch_state():
            try:
                url = self._build_graphql_url(
                    operation_name=self._operations["GET_ME_STATE"],
                    query_hash=self._query_hashes["GET_ME_STATE"],
                    variables={},
                )
                headers = self._get_graphql_headers(authenticated=True)
                response = self.http_manager.get(
                    url, operation="vod_user_state", headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT
                )
                response.raise_for_status()
                data = response.json()

                if "errors" in data:
                    logger.warning(f"GraphQL errors in user state: {data['errors']}")
                    return {}

                # FIX: Use `or {}` to handle {"data": null} safely
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

    # ============================================================================
    # VOD CATEGORY - Main entry point for browsing
    # ============================================================================

    def get_vod_category(
        self, content_id: str = "", authenticated: bool = True, **kwargs
    ) -> List[Union[VodCategory, VodItem]]:
        try:
            if not content_id or content_id == "/":
                return self.get_navigation_categories()

            if self._is_block_id(content_id):
                return self.get_collection_items(
                    block_id=content_id,
                    first=kwargs.get("first", 32),
                    offset=kwargs.get("offset", 0),
                    authenticated=authenticated,
                )

            return self._get_page_items(content_id, authenticated, **kwargs)
        except Exception as e:
            logger.error(f"Error getting VOD category: {e}")
            return []

    @staticmethod
    def _is_block_id(content_id: str) -> bool:
        """Joyn block IDs are formatted as 'page_id:hash' (e.g., '411:abc123def...')."""
        return ":" in content_id or content_id.startswith("block-")

    def _get_page_items(
            self, path: str, authenticated: bool = True, **kwargs
    ) -> List[Union[VodCategory, VodItem]]:
        # FIX: Normalize path to start with '/' as Joyn's GraphQL router requires it
        if not path.startswith("/"):
            path = f"/{path}"

        page = self.get_landing_page(path=path, authenticated=authenticated)
        items = []

        for block in page.get("blocks", []):
            block_type = block.get("__typename")
            block_id = block.get("id")

            if block_type == "StandardLane" and block_id:
                if kwargs.get("fetch_more", False):
                    items.extend(self.get_collection_items(
                        block_id=block_id, first=kwargs.get("first", 32),
                        offset=kwargs.get("offset", 0), authenticated=authenticated,
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
        return items

    # ============================================================================
    # ASSET PARSING
    # ============================================================================

    def _parse_asset(self, asset: Dict[str, Any]) -> Optional[Union[VodCategory, VodItem]]:
        typename = asset.get("__typename")
        asset_id = asset.get("id", "")
        title = asset.get("title", "Unknown")

        if typename in ["Series", "Movie"]:
            return self._parse_content_asset(asset)
        elif typename == "Episode":
            return self._parse_episode_asset(asset)
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

    def _parse_content_asset(self, asset: Dict[str, Any]) -> Optional[VodItem]:
        """Parse Series or Movie asset into VodItem, mapping fields explicitly."""
        asset_id = asset.get("id", "")
        title = asset.get("title", "Unknown")

        # NOTE: "path" (asset.get("path", "")) is intentionally not attached below —
        # VodItem has no field to hold it (see accompanying note). Restore it here
        # once a field exists on VodItem, rather than passing an invalid kwarg.

        primary_image = asset.get("primaryImage", {})
        hero_portrait = asset.get("heroPortrait", {})
        iconic_image = asset.get("iconicImage", {})
        image_url = primary_image.get("url") or hero_portrait.get("url") or iconic_image.get("url")

        genres = [g.get("name", "") for g in asset.get("genres", []) if g.get("name")]
        min_age = asset.get("ageRating", {}).get("minAge")

        license_types = asset.get("licenseTypes", [])
        is_free = "AVOD" in license_types or "FREE" in license_types
        is_premium = "SVOD" in license_types or "PLUS" in license_types

        item = VodItem(
            name=title,
            content_id=asset_id,
            provider="joyn",
            logo_url=image_url,
            mode=StreamingMode.VOD,
            content_type=ContentType.SERIES if asset.get("__typename") == "Series" else ContentType.MOVIE,
            description=asset.get("description", ""),
            country=self.country,
            duration_seconds=asset.get("duration") or asset.get("video", {}).get("duration"),
            genres=genres or None,
            genre=genres[0] if genres else None,
            series_title=title if asset.get("__typename") == "Series" else None,
            rating=f"FSK {min_age}" if min_age is not None else None,
        )

        # Utilize Content's pricing model instead of a metadata dict
        if is_free:
            item.set_free()
        elif is_premium:
            item.set_subscription(tiers=["PLUS"])

        return item

    def _parse_episode_asset(self, asset: Dict[str, Any]) -> Optional[VodItem]:
        """Parse Episode asset into VodItem, mapping fields explicitly."""
        episode_id = asset.get("id", "")
        title = asset.get("title", "Unknown Episode")
        series_data = asset.get("series", {})

        # NOTE: "path" (asset.get("path", "")) is intentionally not attached below —
        # same reason as in _parse_content_asset above.

        genres = [g.get("name", "") for g in asset.get("genres", []) if g.get("name")]
        license_types = asset.get("licenseTypes", [])
        is_free = "AVOD" in license_types or "FREE" in license_types
        is_premium = "SVOD" in license_types or "PLUS" in license_types

        item = VodItem(
            name=title,
            content_id=episode_id,
            provider="joyn",
            mode=StreamingMode.VOD,
            content_type=ContentType.SERIES,
            description=f"Episode {asset.get('episodeNumber')} of {series_data.get('title')}" if series_data.get("title") else "",
            country=self.country,
            duration_seconds=asset.get("video", {}).get("duration"),
            genres=genres or None,
            genre=genres[0] if genres else None,
            season_number=asset.get("season", {}).get("seasonNumber"),
            episode_number=asset.get("episodeNumber"),
            series_id=series_data.get("id"),
            series_title=series_data.get("title"),
        )

        if is_free:
            item.set_free()
        elif is_premium:
            item.set_subscription(tiers=["PLUS"])

        return item

    # ============================================================================
    # SEARCH & DETAILS (Stubs - require unmapped GraphQL hashes)
    # ============================================================================

    def search(self, query: str, cursor: Optional[str] = None, page_size: int = 24, **kwargs) -> Dict[str, Any]:
        """
        Search VOD catalogue.
        TODO: The REST API is deprecated. We must capture the GraphQL Search hash
              from the network tab to activate this.
        """
        logger.warning("Search GraphQL hash not configured. Search is currently disabled.")
        return {"items": [], "next_cursor": None, "total": 0}

    def get_content_details(self, content_id: str, authenticated: bool = True) -> Optional[Dict[str, Any]]:
        """
        Get detailed metadata for a VOD item.
        TODO: The REST API is deprecated. We must capture the GraphQL PageDetail hash
              from the network tab to activate this.
        """
        logger.warning("Content Details GraphQL hash not configured. Details fetching is currently disabled.")
        return None

    # ============================================================================
    # VOD PLAYBACK METHODS (With Caching)
    # ============================================================================

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

    def _get_vod_manifest_and_drm(
        self,
        content_id: str,
        video_config: Optional[Dict] = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> Optional[Dict[str, Any]]:
        """
        Fetch manifest and DRM config. Cached for 5 minutes to prevent
        duplicate round trips when manifest and DRM are requested sequentially
        for the *same* content_id + video_config combination.
        """
        cache_key = f"vod_playlist_{content_id}_{self._video_config_fingerprint(video_config)}"
        cached = self._cache.get(cache_key)
        if cached and (time.time() - cached["timestamp"] < self._cache_ttl):
            return cached["data"]

        from .channel_manager import create_video_payload, build_signature
        from ...base.models import DRMConfig, DRMSystem, LicenseConfig
        from .constants import DRM_REQUEST_HEADERS

        for attempt in range(max_retries):
            try:
                entitlement_token = self.provider.channel_manager.get_entitlement_token(
                    content_id=content_id, content_type="VOD"
                )
                video_payload = create_video_payload(video_config)
                signature = build_signature(entitlement_token, video_payload)

                url = f"https://api.vod-prd.s.joyn.de/v1/vod/{content_id}/playlist?signature={signature}"
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

                # Cache the successful result
                self._cache[cache_key] = {"timestamp": time.time(), "data": result}
                return result

            except PlaybackRestrictedException as e:
                logger.warning(f"VOD playback restricted for {content_id}: {e}")
                return None
            except Exception as e:
                logger.warning(f"VOD attempt {attempt + 1}/{max_retries} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(1)

        logger.error(f"VOD failed for {content_id} after {max_retries} attempts")
        return None

    def clear_cache(self):
        """Clear all cached data"""
        self._cache.clear()
        self._user_state = None
        logger.debug("VOD cache cleared")