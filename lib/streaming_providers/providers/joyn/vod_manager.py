# streaming_providers/providers/joyn/vod_manager.py
# -*- coding: utf-8 -*-
"""
Joyn VOD Manager — browseable catalogue (GraphQL) and playback.

Collaborators (constructor contract, README §6.0):

    required (keyword-only):
        http_manager, auth, country, config
    declared extras (keyword-only):
        entitlement  — the shared JoynEntitlement helper; the VOD manager is
                       the second consumer (the first is JoynChannelManager),
                       which is why it lives in its own collaborator and not
                       on a sibling manager (README §5.1). v1 reached it via
                       provider.channel_manager.get_entitlement_token.

Return types: `get_vod_category` and `search_vod` return `VodPage`. V1 returned
a bare list and a dict respectively — both of which the base tolerates at
runtime (`normalize_vod_result`), but the ABC says `VodPage`, and the migration
brief commits to it (README §6.2, trap 33).

Content-id grammar (opaque to the base):
    a_…      Joyn "video" asset id — the id the playlist endpoint wants
    b_/c_/d_ catalog ids: movies (b_), seasons (c_), episodes (d_)
    block-…  lazyBlocks from a landing page; also anything with ":" in it
    /path    browsable HTML/GraphQL paths — /serien, /filme, /serien/<slug>, …

`handles_content_id` implements the prefilter that v1 had as
`JoynProvider._is_vod_content`. It is pure (no I/O): a prefix / character
check, called on every router attempt.

Errors follow the v2 contract: "not mine" is decided by `handles_content_id`
(the router never asks this manager about a live id) — once a VOD id is here,
only a result or a typed failure is valid. Typed `ProviderError`s (AuthError,
RateLimitError, GeoBlockError, EntitlementError, NotFoundError, ...) ALWAYS
propagate unchanged; only untyped exceptions are wrapped in `ServerError`.
Only `ServerError`s are retried.
"""

import functools
import json
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Union

from ...base.errors import NotFoundError, ProviderError, ServerError
from ...base.managers import VodManager
from ...base.models import DRMConfig
from ...base.models.content import ContentType, StreamingMode
from ...base.models.vod import VodCategory, VodItem
from ...base.utils.logger import logger
from ...base.utils.transport import transport_errors
from ...base.vod import VodPage
from .drm import build_widevine_config
from .ids import is_vod_id
from .signing import build_signature, create_video_payload, video_config_fingerprint
from .constants import (
    CONTENT_TYPE_VOD,
    DEFAULT_MAX_RETRIES,
    DEFAULT_REQUEST_TIMEOUT,
    JOYN_GRAPHQL_BASE_URL,
    JOYN_STREAMING_ENDPOINTS,
    JOYN_USER_AGENT,
)
from .models import (
    JoynEntitlementError,
    PlaybackRestrictedException,
    SubscriptionRequiredException,
)

# ============================================================================
# GraphQL query hashes (VOD-specific; live hashes live in constants.py)
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
    # Recovered from the legacy addon's const.py (SEARCH.HASH) — not captured
    # independently from live traffic like the hashes above, so keep an eye on
    # this if Joyn ever rotates persisted-query hashes.
    "SEARCH": "bb2bab6cbe17321d7eddd5006e7f40765faedd79790b193a59d83f4640694856",
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
    # Legacy const.py names this operation "SearchQ", not "Search".
    "SEARCH": "SearchQ",
}


def ttl_cache(ttl_seconds: int = 300):
    """
    Simple TTL cache decorator for methods.

    Cache storage lives PER INSTANCE (in self.__dict__), not in the decorator's
    closure. A closure-level cache dict would be shared across every
    JoynVodManager instance (one per country/account), which would leak one
    account's cached state into another's, and would also keep every instance
    alive forever since the dict holds a strong reference to `self` as part of
    the cache key.

    A `force_refresh=True` kwarg bypasses the cached value for that call and
    repopulates the cache.
    """
    def decorator(func):
        cache_attr = f"_ttl_cache_{func.__name__}"

        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            force_refresh = kwargs.pop("force_refresh", False)
            cache: Dict[Any, Dict[str, Any]] = self.__dict__.setdefault(cache_attr, {})
            key = (args, frozenset(kwargs.items()))

            if not force_refresh:
                cached = cache.get(key)
                if cached and (time.time() - cached["timestamp"] < ttl_seconds):
                    return cached["data"]

            data = func(self, *args, **kwargs)
            cache[key] = {"timestamp": time.time(), "data": data}
            return data

        wrapper.cache_attr = cache_attr
        return wrapper
    return decorator


class JoynVodManager(VodManager):
    """
    Joyn VOD manager using the GraphQL API (browse) and the vod-prd playlist
    endpoint (playback). No `self.provider` accesses — every collaborator is
    either one of the four required ones or an explicit keyword-only extra.
    """

    # Root-menu paths we surface from the live Navigation API; anything else
    # is filtered out so Live TV (handled by the channel manager) and unrelated
    # blocks do not end up in the VOD root. Add new paths here as Joyn adds
    # them under these sections — the whitelist is deliberate, not incidental.
    ALLOWED_NAV_PATHS = {
        "/neu-beliebt", "/serien", "/filme", "/sport", "/news",
        "/mediatheken", "/collections/sendung-im-tv-verpasst",
    }

    # Fallback used if the live Navigation response is empty or does not match
    # the expected shape. Fail open to a known-good static menu rather than
    # ship an empty VOD root.
    _STATIC_NAV_FALLBACK = [
        {"url": "/neu-beliebt", "title": "Neu & Beliebt"},
        {"url": "/serien", "title": "Serien"},
        {"url": "/filme", "title": "Filme"},
        {"url": "/sport", "title": "Sport"},
        {"url": "/news", "title": "News & Doku"},
        {"url": "/mediatheken", "title": "Mediatheken"},
        {"url": "/collections/sendung-im-tv-verpasst", "title": "Sendung im TV verpasst?"},
    ]

    def __init__(
        self,
        *,
        http_manager: Any,
        auth: Any,
        country: str,
        config: Any,
        entitlement: Any,
    ):
        super().__init__(
            http_manager=http_manager, auth=auth, country=country, config=config
        )
        self._entitlement = entitlement   # extra AFTER super(), never passed to it

        # Per-instance caches. Provider-owned dicts are used only where the
        # cache must survive credentials changes and be cleared by the
        # provider; the VOD cache is self-contained and cleared by
        # clear_cache(), which the provider calls from set_user_credentials
        # (if/when that exists).
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl: int = 300

        self._query_hashes = VOD_GRAPHQL_HASHES
        self._operations = GRAPHQL_OPERATIONS

        self._user_state: Optional[Dict[str, Any]] = None
        self._has_plus = False

        logger.info(f"[JoynVodManager] Initialised for country={self.country}")

    # ========================================================================
    # CAPABILITY / ROUTING
    # ========================================================================

    def handles_content_id(self, content_id: str) -> bool:
        """
        Cheap, pure prefilter — the router asks this on every attempt, so it
        must not do I/O.

        Mirrors v1's `JoynProvider._is_vod_content`:
          * a_/b_/c_/d_ prefixed asset ids
          * block-<n> lazy-block ids
          * any path containing "/" (browsable routes)
          * any id containing ":" (v1 block-id grammar)
        Live channel ids are bare slugs like "sat1-de" and do not match.
        """
        return is_vod_id(content_id)   # the same function the channel manager negates

    # ========================================================================
    # CACHING
    # ========================================================================

    def clear_cache(self) -> None:
        """Called by the provider when credentials change."""
        self._cache.clear()
        self.__dict__.pop(type(self).get_user_state.cache_attr, None)
        self._user_state = None
        logger.debug("VOD cache cleared")

    # ========================================================================
    # HEADER / URL BUILDING
    # ========================================================================

    def _get_graphql_headers(self, authenticated: bool = False) -> Dict[str, str]:
        """
        GraphQL headers via the shared config.

        `authenticated=True` means "this is a user-scoped query (user state,
        search, season under an account)" — we then ask the session for a
        token and set joyn-user-state=code=R_A. When False, the query is
        anonymous and the reference client sends A_A.
        """
        token: Optional[str] = None
        if authenticated:
            # RAISES a typed error if no session can be had (README §8) instead of
            # silently degrading to an anonymous request.
            token = self.auth.get_access_token()
        return self.config.graphql_headers(
            token=token, authenticated=token is not None
        )

    @staticmethod
    def _build_graphql_url(
        operation_name: str,
        query_hash: str,
        variables: Optional[Dict] = None,
    ) -> str:
        base_url = JOYN_GRAPHQL_BASE_URL
        params = {
            "operationName": operation_name,
            "enable_user_location": "true",
            "watch_assistant_variant": "true",
        }
        if variables:
            params["variables"] = json.dumps(variables, separators=(",", ":"))
        extensions = {"persistedQuery": {"version": 1, "sha256Hash": query_hash}}
        params["extensions"] = json.dumps(extensions, separators=(",", ":"))
        query_string = "&".join(
            f"{k}={urllib.parse.quote(v)}" for k, v in params.items()
        )
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
        with transport_errors("vod_navigation", "Joyn"):
            url = self._build_graphql_url(
                operation_name=self._operations["NAVIGATION"],
                query_hash=self._query_hashes["NAVIGATION"],
            )
            headers = self._get_graphql_headers(authenticated=False)
            response = self.http_manager.get(
                url,
                operation="vod_navigation",
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            return response.json().get("data") or {}

    def get_navigation_tree(self) -> List[Dict[str, Any]]:
        return self.get_navigation().get("navigation", [])

    def get_navigation_categories(
        self, parent_title: Optional[str] = None
    ) -> List[VodCategory]:
        """
        Root menu.

        Two sources of entries:
          * whitelisted paths from the live Navigation API (kept in
            ALLOWED_NAV_PATHS so Live TV and unrelated blocks stay out)
          * two synthetic genre directories that Joyn does not list itself

        If the live response does not yield a whitelisted entry at all
        (upstream empty or shape changed), fall back to a static menu rather
        than ship an empty root.
        """
        categories: List[VodCategory] = []

        nav_data = self.get_navigation()
        nav_entries = nav_data.get("navigation", []) if isinstance(nav_data, dict) else []

        for block in nav_entries:
            if not isinstance(block, dict):
                continue
            path = block.get("path")
            title = block.get("title", "")
            if path in self.ALLOWED_NAV_PATHS:
                categories.append(VodCategory(
                    content_id=path,
                    name=title or path,
                    description=title or path,
                    provider="joyn",
                    fetch_url=path,
                    details_url=path,
                ))

        if not categories:
            logger.warning(
                "Joyn navigation response didn't yield any whitelisted categories; "
                "falling back to the static VOD root menu"
            )
            for page in self._STATIC_NAV_FALLBACK:
                categories.append(VodCategory(
                    content_id=page["url"],
                    name=page["title"],
                    description=page["title"],
                    provider="joyn",
                    fetch_url=page["url"],
                    details_url=page["url"],
                ))

        # Genre directories are synthetic — always appended.
        categories.append(VodCategory(
            content_id="/serien/genre", name="Serien Genres", description="Serien Genres",
            provider="joyn", fetch_url="/serien/genre", details_url="/serien/genre",
        ))
        categories.append(VodCategory(
            content_id="/filme/genre", name="Filme Genres", description="Filme Genres",
            provider="joyn", fetch_url="/filme/genre", details_url="/filme/genre",
        ))

        return categories

    def get_genres_from_navigation(self, media_type: Optional[str] = None) -> List[VodCategory]:
        """Parse seriesGenre and movieGenre from the Navigation API response."""
        nav_data = self.get_navigation()
        categories: List[VodCategory] = []

        types_to_fetch = [media_type] if media_type else ["seriesGenre", "movieGenre"]

        for mt in types_to_fetch:
            genre_data = nav_data.get(mt, {})
            for block in genre_data.get("blocks", []):
                for asset in block.get("assets", []):
                    if asset.get("__typename") == "GenreItem":
                        categories.append(VodCategory(
                            content_id=asset.get("path", asset.get("id")),
                            name=asset.get("title", ""),
                            logo_url=asset.get("genreImage", {}).get("url"),
                            description=f"Genre: {asset.get('title')}",
                            provider="joyn",
                            fetch_url=asset.get("path"),
                            details_url=asset.get("path"),
                        ))
        return categories

    # ========================================================================
    # GENRE PAGE
    # ========================================================================

    def get_genre_page(
        self,
        path: str,
        first: int = 32,
        offset: int = 0,
        authenticated: bool = True,
    ) -> Dict[str, Any]:
        with transport_errors(f"vod_genre_page {path}", "Joyn"):
            if not path.startswith("/"):
                path = f"/{path}"
            variables = {"first": first, "path": path, "offset": offset}
            url = self._build_graphql_url(
                operation_name=self._operations["PAGE_OVERVIEW_GENRE"],
                query_hash=self._query_hashes["PAGE_OVERVIEW_GENRE"],
                variables=variables,
            )
            headers = self._get_graphql_headers(authenticated=authenticated)
            response = self.http_manager.get(
                url, operation="vod_genre_page", headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()

        if "errors" in data:
            logger.warning(f"GraphQL errors in genre page: {data['errors']}")
            return {}
        return (data.get("data") or {}).get("page", {})

    def _get_genre_items(
        self,
        path: str,
        authenticated: bool = True,
        **kwargs,
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
    # SERIES / MOVIE DETAIL
    # ========================================================================

    def _extract_page_json(self, html: str) -> Optional[Dict[str, Any]]:
        """Extract the Next.js RSC page payload (initialData) embedded in detail HTML."""
        match = re.search(
            r'self\.__next_f\.push\(\[1,\s*"a:(\[.*?\])\\n"\]\)', html, re.DOTALL
        )
        if not match:
            return None
        try:
            raw = match.group(1).encode().decode("unicode_escape")
            data = json.loads(raw)
            return data[3]["initialData"]["page"]
        except (json.JSONDecodeError, UnicodeDecodeError, IndexError, KeyError, TypeError) as e:
            logger.warning(f"Failed to parse embedded page JSON: {e}")
            return None

    def _get_series_items_fallback(
        self,
        path: str,
        authenticated: bool = True,
        **kwargs,
    ) -> List[Union[VodCategory, VodItem]]:
        """Series detail pages: parse the season/episode data Next.js already embeds server-side."""
        url = f"https://www.joyn.de{path}"
        headers = {
            "User-Agent": JOYN_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        }
        with transport_errors(f"vod_series_html {path}", "Joyn"):
            response = self.http_manager.get(
                url, operation="vod_series_html", headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
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

        items: List[Union[VodCategory, VodItem]] = []
        for s in all_seasons:
            items.append(VodCategory(
                content_id=s["id"],
                name=f"Staffel {s.get('number', '')}".strip(),
                provider="joyn",
                fetch_url=s["id"],
            ))
        return items

    def get_movie_detail(self, path: str, authenticated: bool = True) -> Dict[str, Any]:
        with transport_errors(f"vod_movie_detail {path}", "Joyn"):
            if not path.startswith("/"):
                path = f"/{path}"
            variables = {"path": path}
            url = self._build_graphql_url(
                operation_name=self._operations["MOVIE_DETAIL"],
                query_hash=self._query_hashes["MOVIE_DETAIL"],
                variables=variables,
            )
            headers = self._get_graphql_headers(authenticated=authenticated)
            response = self.http_manager.get(
                url, operation="vod_movie_detail", headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()

        if "errors" in data:
            logger.warning(f"GraphQL errors in movie detail: {data['errors']}")
            return {}
        return (data.get("data") or {}).get("page", {}).get("movie", {})

    def _get_movie_items_fallback(
        self,
        path: str,
        authenticated: bool = True,
        **kwargs,
    ) -> List[VodItem]:
        movie = self.get_movie_detail(path, authenticated=authenticated)
        if not movie:
            logger.warning(f"No movie data found for {path}")
            return []
        item = self._parse_content_asset(movie)
        return [item] if item else []

    # ========================================================================
    # SEASON EPISODES
    # ========================================================================

    def get_season_episodes(
        self,
        season_id: str,
        first: int = 20,
        offset: int = 0,
        license_filter: str = "FREE",
        authenticated: bool = True,
    ) -> Dict[str, Any]:
        with transport_errors(f"vod_season {season_id}", "Joyn"):
            variables = {
                "id": season_id, "first": first,
                "licenseFilter": license_filter, "offset": offset,
            }
            url = self._build_graphql_url(
                operation_name=self._operations["SEASON"],
                query_hash=self._query_hashes["SEASON"],
                variables=variables,
            )
            headers = self._get_graphql_headers(authenticated=authenticated)
            response = self.http_manager.get(
                url, operation="vod_season", headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()

        if "errors" in data:
            logger.warning(f"GraphQL errors in season query: {data['errors']}")
            return {}
        return (data.get("data") or {}).get("season", {})

    def _get_season_items(
        self,
        season_id: str,
        authenticated: bool = True,
        **kwargs,
    ) -> List[Union[VodCategory, VodItem]]:
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

    def get_collection(
        self,
        block_id: str,
        first: int = 32,
        offset: int = 0,
        authenticated: bool = True,
    ) -> Dict[str, Any]:
        with transport_errors(f"vod_collection {block_id}", "Joyn"):
            has_token = authenticated and self.auth.ensure()
            variables = {
                "first": first, "offset": offset, "blockId": block_id,
                "hasToken": has_token,
            }
            url = self._build_graphql_url(
                operation_name=self._operations["COLLECTION_QUERY"],
                query_hash=self._query_hashes["COLLECTION_QUERY"],
                variables=variables,
            )
            headers = self._get_graphql_headers(authenticated=authenticated)
            response = self.http_manager.get(
                url, operation="vod_collection", headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
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

    def get_collection_items(
        self,
        block_id: str,
        first: int = 32,
        offset: int = 0,
        authenticated: bool = True,
    ) -> List[Union[VodCategory, VodItem]]:
        result = self.get_collection(block_id, first, offset, authenticated)
        items: List[Union[VodCategory, VodItem]] = []
        for asset in result.get("assets", []):
            item = self._parse_asset(asset)
            if item:
                items.append(item)
        return items

    # ========================================================================
    # LANDING PAGE
    # ========================================================================

    def get_landing_page(
        self,
        path: str = "/neu-beliebt",
        variation: str = "Default",
        authenticated: bool = True,
    ) -> Dict[str, Any]:
        with transport_errors(f"vod_landing_page {path}", "Joyn"):
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
                url, operation="vod_landing_page", headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()

        if "errors" in data:
            logger.warning(f"GraphQL errors in landing page: {data['errors']}")
            return {}
        return (data.get("data") or {}).get("page", {})

    def _get_page_items(
        self,
        path: str,
        authenticated: bool = True,
        **kwargs,
    ) -> List[Union[VodCategory, VodItem]]:
        page = self.get_landing_page(path=path, authenticated=authenticated)
        items: List[Union[VodCategory, VodItem]] = []

        def process_block(block: Dict[str, Any]):
            block_type = block.get("__typename")
            block_id = block.get("id")

            if block_type == "StandardLane" and block_id:
                if block.get("assets"):
                    for asset in block.get("assets", []):
                        item = self._parse_asset(asset)
                        if item:
                            items.append(item)
                else:
                    items.extend(self.get_collection_items(
                        block_id=block_id,
                        first=kwargs.get("first", 32),
                        offset=kwargs.get("offset", 0),
                        authenticated=authenticated,
                    ))
            elif block_type in [
                "HeroLane", "FeaturedLane", "GenreLane", "LiveLane",
                "ChannelLane", "BigTeaserLane", "RecoForYouLane",
            ] or not block_type:
                for asset in block.get("assets", []):
                    item = self._parse_asset(asset)
                    if item:
                        items.append(item)

        for block in page.get("blocks", []):
            process_block(block)
        for block in page.get("lazyBlocks", []):
            process_block(block)

        return items

    # ========================================================================
    # USER STATE
    # ========================================================================

    @ttl_cache(ttl_seconds=300)
    def get_user_state(self) -> Dict[str, Any]:
        # force_refresh=True bypasses the cache for one call; the decorator
        # strips it before the call reaches this function.
        with transport_errors("vod_user_state", "Joyn"):
            url = self._build_graphql_url(
                operation_name=self._operations["GET_ME_STATE"],
                query_hash=self._query_hashes["GET_ME_STATE"],
                variables={},
            )
            headers = self._get_graphql_headers(authenticated=True)
            response = self.http_manager.get(
                url, operation="vod_user_state", headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()

        if "errors" in data:
            logger.warning(f"GraphQL errors in user state: {data['errors']}")
            return {}
        state = (data.get("data") or {}).get("me", {})
        subs = state.get("subscriptionsData", {})
        config = subs.get("config", {})
        self._has_plus = config.get("hasActivePlus", False)
        self._user_state = state
        return state

    def has_plus_subscription(self) -> bool:
        self.get_user_state()
        return self._has_plus

    # ========================================================================
    # VOD CATEGORY — MAIN ENTRY POINT (returns VodPage)
    # ========================================================================

    def get_vod_category(
        self,
        content_id: str = "",
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kwargs,
    ) -> VodPage:
        """
        Return one page of the VOD catalogue.

        Pagination: Joyn pages by numeric offset, exposed as the opaque `cursor`
        string. Only the endpoints that really honour `offset` are pageable —
        block ids (collections) and genre paths. A full page there yields
        `next_cursor = offset + len(entries)`. Everything else (navigation,
        genre directories, season, series, movie, landing pages) returns its
        complete list with `next_cursor=None`, using the helpers' own default
        sizes (as v1 did): season episodes are fetched per licence filter, and
        landing pages apply the offset per block, so a single offset cannot page
        them without duplicating items.

        Typed ProviderErrors propagate unchanged; only untyped exceptions become
        ServerError.
        """
        offset = self._parse_offset(cursor)
        first = kwargs.get("first")
        try:
            entries = self._get_vod_category_entries(
                content_id=content_id,
                cursor=cursor,
                page_size=page_size,
                authenticated=True,
                **kwargs,
            )
        except ProviderError:
            raise
        except Exception as exc:
            logger.error(f"Joyn VOD category failed for {content_id!r}: {exc}")
            raise ServerError(f"Joyn VOD category failed for {content_id!r}") from exc

        entries = list(entries)
        next_cursor = None
        if self._is_pageable(content_id):
            effective_first = first if first is not None else page_size
            if len(entries) >= effective_first:
                next_cursor = str(offset + len(entries))
        return VodPage(entries=entries, next_cursor=next_cursor, total=None)

    @staticmethod
    def _parse_offset(cursor: Optional[str]) -> int:
        if cursor is None:
            return 0
        try:
            return int(cursor)
        except (TypeError, ValueError):
            logger.warning(f"Joyn: ignoring non-numeric cursor {cursor!r}")
            return 0

    def _is_pageable(self, content_id: str) -> bool:
        """True only for endpoints that honour `offset` (see get_vod_category)."""
        if not content_id or content_id == "/":
            return False
        if content_id in ("/serien/genre", "/filme/genre"):
            return False
        if self._is_block_id(content_id):
            return True
        if self._is_season_id(content_id):
            return False
        path = content_id if content_id.startswith("/") else f"/{content_id}"
        return self._is_genre_path(path)

    def _get_vod_category_entries(
        self,
        content_id: str,
        cursor: Optional[str],
        page_size: int,
        authenticated: bool,
        **kwargs,
    ) -> List[Union[VodCategory, VodItem]]:
        """
        The v1 body of `get_vod_category`, unchanged in dispatch order; only
        the `cursor` / `page_size` plumbing is new (was `first` / `offset` in
        kwargs before; kept here for compatibility with callers that still
        pass `first`/`offset`, which we honour over `page_size` if present).
        """
        explicit_first = kwargs.pop("first", None)
        offset = kwargs.pop("offset", 0)
        if cursor is not None:
            offset = self._parse_offset(cursor)

        # Pageable endpoints get page_size; the others keep the helpers' own
        # defaults (32 / 20) so a smaller page_size cannot truncate them silently.
        first = explicit_first
        if first is None and self._is_pageable(content_id):
            first = page_size
        paging: Dict[str, Any] = {"offset": offset}
        if first is not None:
            paging["first"] = first

        if not content_id or content_id == "/":
            return self.get_navigation_categories()

        # 1. Genre directories
        if content_id in ("/serien/genre", "/filme/genre"):
            media_type = "seriesGenre" if "serien" in content_id else "movieGenre"
            return self.get_genres_from_navigation(media_type=media_type)

        # 2. Block ids
        if self._is_block_id(content_id):
            return self.get_collection_items(
                block_id=content_id, authenticated=authenticated, **paging,
            )

        # 3. Season ids
        if self._is_season_id(content_id):
            return self._get_season_items(content_id, authenticated, **paging)

        path = content_id if content_id.startswith("/") else f"/{content_id}"

        # 4. Specific genre paths
        if self._is_genre_path(path):
            return self._get_genre_items(path, authenticated, **paging)

        # 5. Specific series paths
        if self._is_series_path(path):
            return self._get_series_items_fallback(path, authenticated, **paging)

        # 6. Specific movie paths
        if self._is_movie_path(path):
            return self._get_movie_items_fallback(path, authenticated, **paging)

        # 7. Landing page fallback
        return self._get_page_items(path, authenticated, **paging)

    # ========================================================================
    # SEARCH (returns VodPage)
    # ========================================================================

    def search_vod(
        self,
        query: str,
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kwargs,
    ) -> VodPage:
        """
        Search the VOD catalogue.

        Query hash, operation name ("SearchQ") and variable names
        (`text` / `first` / `offset`) come from the legacy addon's const.py,
        not from a captured live request against this GraphQL endpoint — the
        original modern implementation guessed `query` instead of `text`,
        which is why search failed outright. If Joyn changes this endpoint's
        shape, this is the first place to check.

        Pagination: numeric offset, advanced by page_size on a full page.
        Returned as the opaque `next_cursor` string; callers pass it back as
        `cursor`.
        """
        query_hash = self._query_hashes.get("SEARCH", "")
        if not query_hash:
            raise ServerError("Joyn SEARCH persisted query hash is not configured.")

        offset = 0
        if cursor:
            try:
                offset = int(cursor)
            except (TypeError, ValueError):
                logger.warning(f"Joyn: ignoring non-numeric search cursor {cursor!r}")
                offset = 0

        try:
            variables: Dict[str, Any] = {
                "text": query,
                "first": page_size,
                "offset": offset,
            }
            url = self._build_graphql_url(
                operation_name=self._operations["SEARCH"],
                query_hash=query_hash,
                variables=variables,
            )
            headers = self._get_graphql_headers(authenticated=True)
            response = self.http_manager.get(
                url, operation="vod_search", headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
        except ProviderError:
            raise
        except Exception as exc:
            logger.error(f"Joyn VOD search failed for query={query!r}: {exc}")
            raise ServerError(f"Joyn VOD search failed for query={query!r}") from exc

        if "errors" in data:
            logger.warning(f"GraphQL errors in search for query={query!r}: {data['errors']}")
            return VodPage(entries=[], next_cursor=None, total=0)

        result = (data.get("data") or {}).get("search", {}) or {}
        assets = result.get("assets") or result.get("results") or []

        items: List[Union[VodCategory, VodItem]] = []
        for asset in assets:
            item = self._parse_asset(asset)
            if item:
                items.append(item)

        next_cursor = str(offset + len(assets)) if len(assets) == page_size else None
        return VodPage(
            entries=items,
            next_cursor=next_cursor,
            total=result.get("total", len(items)),
        )

    # ========================================================================
    # ASSET PARSING
    # ========================================================================

    def _parse_asset(self, asset: Dict[str, Any]) -> Optional[Union[VodCategory, VodItem]]:
        typename = asset.get("__typename")
        asset_id = asset.get("id", "")
        title = asset.get("title", "Unknown")
        path = asset.get("path", "")

        if typename == "Series":
            return VodCategory(
                content_id=path or asset_id,
                name=title,
                logo_url=asset.get("primaryImage", {}).get("url")
                          or asset.get("iconicImage", {}).get("url"),
                description=asset.get("description", ""),
                provider="joyn",
                fetch_url=path or asset_id,
                child_count=None,
                details_url=path,
            )

        if typename == "Movie":
            video_id = asset.get("video", {}).get("id")
            content_id = video_id or asset_id
            item = self._parse_content_asset(asset)
            if item:
                item.content_id = content_id
            return item

        if typename == "Episode":
            return self._parse_episode_asset(asset)

        if typename == "Season":
            season_num = asset.get("number", "")
            name = f"Staffel {season_num}".strip() if season_num else title
            return VodCategory(
                content_id=asset_id,
                name=name,
                logo_url=asset.get("primaryImage", {}).get("url")
                          or asset.get("iconicImage", {}).get("url"),
                description=title,
                provider="joyn",
                fetch_url=asset_id,
                child_count=None,
                details_url=None,
            )

        if typename == "Brand":
            return VodCategory(
                content_id=asset_id,
                name=title,
                logo_url=asset.get("logo", {}).get("url"),
                description=f"{title} Mediathek",
                provider="joyn",
                fetch_url=asset.get("path"),
            )

        if typename == "GenreItem":
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
        """Parse movie/playable content into VodItem."""
        typename = asset.get("__typename", "")
        if typename != "Movie":
            return None

        asset_id = asset.get("id", "")
        title = asset.get("title", "Unknown")

        image_url = (
            asset.get("primaryImage", {}).get("url")
            or asset.get("heroPortrait", {}).get("url")
            or asset.get("iconicImage", {}).get("url")
        )
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

        video_id = video_data.get("id", "")
        content_id = video_id or asset_id

        genres = [g.get("name", "") for g in asset.get("genres", []) if g.get("name")]
        license_types = asset.get("licenseTypes", [])
        is_free = "AVOD" in license_types or "FREE" in license_types
        is_premium = "SVOD" in license_types or "PLUS" in license_types

        ep_number = asset.get("number")
        season_number = season_data.get("seasonNumber")

        description = (
            f"Staffel {season_number}, Episode {ep_number} – {title}"
            if series_data.get("title") else ""
        )

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

    def get_vod_manifest(
        self,
        content_id: str,
        video_config: Optional[Dict] = None,
        **kwargs,
    ) -> Optional[str]:
        """
        Return the manifest URL for a VOD content id, or raise.

        Reached only after the router confirmed the id is VOD
        (`handles_content_id`), so `None` ("not mine") is not a valid outcome:
          * an id that cannot be resolved to a playable video -> NotFoundError
          * a playlist without manifestUrl after all retries   -> ServerError
          * rights / auth / transport problems                 -> their typed error
        """
        result = self._get_vod_manifest_and_drm(
            content_id, video_config,
            max_retries=kwargs.get("max_retries", DEFAULT_MAX_RETRIES),
        )
        return result["manifest_url"]

    def get_vod_drm(
        self,
        content_id: str,
        video_config: Optional[Dict] = None,
        **kwargs,
    ) -> List[DRMConfig]:
        result = self._get_vod_manifest_and_drm(
            content_id, video_config,
            max_retries=kwargs.get("max_retries", DEFAULT_MAX_RETRIES),
        )
        return result["drm_configs"]

    def get_playable_asset(self, asset_id: str, authenticated: bool = True) -> Dict[str, Any]:
        """
        Fetch a single playable asset (Movie/Episode) by its b_/c_/d_ id.
        Returns the `asset` object including its `video.id` (a_…).
        """
        with transport_errors(f"vod_playable_asset {asset_id}", "Joyn"):
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
            logger.warning(
                f"GraphQL errors in PlayableAssetWithToken for {asset_id}: {data['errors']}"
            )
            return {}
        return (data.get("data") or {}).get("asset", {}) or {}

    def get_content_details(
        self,
        content_id: str,
        authenticated: bool = True,
        **kwargs,
    ) -> Optional[VodItem]:
        """
        Full details for a single playable item by its b_/c_/d_ id.
        Called by `provider.get_vod_item_details()`, which serialises the
        result with VodItem.to_dict() (inherited from Content).
        """
        if content_id.startswith("a_"):
            logger.debug(f"Skipping PlayableAssetWithToken for video ID {content_id}")
            return None

        asset = self.get_playable_asset(content_id, authenticated=authenticated)
        if not asset:
            logger.warning(f"No asset data found for content_id={content_id}")
            return None

        typename = asset.get("__typename")
        if typename == "Episode":
            return self._parse_episode_asset(asset)
        return self._parse_content_asset(asset)

    def _resolve_video_id(self, content_id: str) -> Optional[str]:
        if content_id.startswith("a_"):
            return content_id

        if content_id.startswith(("b_", "c_", "d_")):
            cache_key = f"video_id:{content_id}"
            cached = self._cache.get(cache_key)
            if cached and (time.time() - cached["timestamp"] < self._cache_ttl):
                return cached["data"]

            asset = self.get_playable_asset(content_id, authenticated=True)
            video_id = (asset.get("video") or {}).get("id")
            if not video_id:
                logger.error(
                    f"Cannot resolve {content_id!r} to a video ID "
                    f"(PlayableAssetWithToken returned no video.id)."
                )
                return None

            self._cache[cache_key] = {"timestamp": time.time(), "data": video_id}
            return video_id

        logger.error(f"Cannot resolve {content_id!r} to a video ID (unknown prefix).")
        return None

    def _get_vod_manifest_and_drm(
        self,
        content_id: str,
        video_config: Optional[Dict] = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> Optional[Dict[str, Any]]:
        """
        Shared workhorse for get_vod_manifest and get_vod_drm.

        Retries ONLY transient failures (ServerError / untyped network errors)
        with a one-second sleep. Every other typed ProviderError — rights
        (PlaybackRestricted, SubscriptionRequired), AuthError, RateLimitError,
        GeoBlockError, NotFoundError — is permanent for this call: it propagates
        immediately and unchanged (retrying gains nothing, risks rate limits, and
        flattening it into ServerError would hide the reason from callers).

        Entitlement comes from `self._entitlement` (the shared helper);
        headers come from `self.config.*`; the session's token comes from
        `self.auth.get_access_token()` — none of these touch the provider.
        """
        video_id = self._resolve_video_id(content_id)
        if not video_id:
            raise NotFoundError(f"Joyn: cannot resolve {content_id!r} to a playable video")

        cache_key = f"vod_playlist:{video_id}:{video_config_fingerprint(video_config)}"
        cached = self._cache.get(cache_key)
        if cached and (time.time() - cached["timestamp"] < self._cache_ttl):
            return cached["data"]

        last_exc: Optional[Exception] = None

        for attempt in range(max_retries):
            try:
                entitlement_token = self._entitlement.get_entitlement_token(
                    content_id=video_id, content_type=CONTENT_TYPE_VOD
                )
                video_payload = create_video_payload(video_config)
                signature = build_signature(entitlement_token, video_payload)

                url = (
                    JOYN_STREAMING_ENDPOINTS["ASSET_PLAYLIST"].format(asset_id=video_id)
                    + f"?signature={signature}"
                )
                headers = self.config.api_headers(entitlement_token)

                response = self.http_manager.post(
                    url,
                    operation="vod_playlist",
                    headers=headers,
                    data=video_payload,
                    timeout=DEFAULT_REQUEST_TIMEOUT,
                )
                response.raise_for_status()
                playlist_data = response.json()

                logger.debug(
                    f"VOD playlist response for {video_id}: "
                    f"{json.dumps(playlist_data, separators=(',', ':'))}"
                )

                manifest_url = playlist_data.get("manifestUrl")
                if not manifest_url:
                    last_exc = ServerError(
                        f"VOD playlist for {video_id} had no manifestUrl"
                    )
                    logger.warning(
                        f"VOD attempt {attempt + 1}/{max_retries} for {video_id}: "
                        f"no manifestUrl in response"
                    )
                    if attempt < max_retries - 1:
                        time.sleep(1)
                    continue

                result: Dict[str, Any] = {
                    "manifest_url": manifest_url,
                    "entitlement_token": entitlement_token,
                    "streaming_format": playlist_data.get("streamingFormat", "dash"),
                    "drm_configs": [],
                }

                license_url = playlist_data.get("licenseUrl")
                if license_url:
                    result["drm_configs"] = [build_widevine_config(
                        self.config, license_url, playlist_data.get("certificateUrl")
                    )]

                self._cache[cache_key] = {"timestamp": time.time(), "data": result}
                return result

            except PlaybackRestrictedException:
                # Permanent, account-level restriction — propagate.
                raise
            except SubscriptionRequiredException as exc:
                # Permanent, account-level; log the diagnostic (does the
                # account hold Plus?) and propagate.
                try:
                    has_plus = self.has_plus_subscription()
                except Exception:   # diagnostics must never mask the real SubscriptionRequired
                    has_plus = None
                logger.warning(
                    f"VOD {video_id} requires a subscription this account "
                    f"doesn't hold (hasActivePlus={has_plus}): {exc}"
                )
                raise
            except JoynEntitlementError:
                # Any other entitlement-shaped failure is also permanent for
                # this content; do not waste retries on it.
                raise
            except Exception as exc:
                if isinstance(exc, ProviderError) and not isinstance(exc, ServerError):
                    raise   # typed and not transient: never retry, never flatten
                last_exc = exc
                logger.warning(f"VOD attempt {attempt + 1}/{max_retries} failed: {exc}")
                if attempt < max_retries - 1:
                    time.sleep(1)

        logger.error(f"VOD failed for {video_id} after {max_retries} attempts")
        if last_exc is not None:
            raise ServerError(f"VOD failed for {video_id}: {last_exc}") from last_exc
        raise ServerError(f"VOD failed for {video_id}: no attempt was made (max_retries={max_retries})")
        return None