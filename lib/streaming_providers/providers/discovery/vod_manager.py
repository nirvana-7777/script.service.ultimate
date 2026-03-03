# streaming_providers/providers/discovery/vod_manager.py
"""
Discovery+ VOD Manager

Implements get_vod_category(path) for the DiscoveryProvider.

Tree structure
--------------
[]                          → 4 root VodCategories (Sports, Genres, Franchises, Editorial)
["/sports"]                 → VodCategory per sport (content_id = "/sports/{alternateId}")
["/sports/alpine-skiing"]   → VodItem per video  (content_id = edit.id)
["/genre"]                  → VodCategory per genre taxonomyNode
["/genre/true-crime"]       → VodCategory per show
["/show/{uuid}"]            → VodItem per episode video
["/franchise"]              → VodCategory per franchise show
["/editorial"]              → VodCategory per editorial taxonomyNode
["/editorial/binge"]        → VodCategory per show
...

Every non-root level works identically:
  1. Treat content_id as a CMS route path.
  2. GET /cms/routes{path} — the response contains the full page object and
     all included items; no second fetch is needed.
  3. Swap data → the page object from included so _parse_page sees a
     standard page structure.
  4. Parse included items and dispatch on type.

Root is the only special case — it returns four hardcoded bucket categories.
"""

from typing import Dict, List, Optional, Union

from ...base.models.vod import VodCategory, VodItem
from ...base.utils.logger import logger

# ---------------------------------------------------------------------------
# CMS base URL (same subdomain as the sports.txt sample URL)
# ---------------------------------------------------------------------------
_CMS_BASE = "https://default.any-any.prd.api.discoveryplus.com"

# ---------------------------------------------------------------------------
# Collections to read on a show page (episode rails only)
# ---------------------------------------------------------------------------
_EPISODE_ALIAS_KEYWORDS = ("episode",)

# ---------------------------------------------------------------------------
# Root buckets — the four top-level VOD sections
# ---------------------------------------------------------------------------
_ROOT_BUCKETS = [
    ("/sports",    "Sports"),
    ("/genre",     "Genres"),
    ("/franchise", "Franchises"),
    ("/editorial", "Editorial"),
]


class DiscoveryVodManager:
    """
    Handles VOD browsing for Discovery+.

    Instantiated and owned by DiscoveryProvider.
    Requires a reference to the provider so it can reuse
    get_auth_headers() and http_manager.
    """

    def __init__(self, provider):
        self._provider = provider

    # ------------------------------------------------------------------
    # Public entry point — called by DiscoveryProvider.get_vod_category
    # ------------------------------------------------------------------

    def get_vod_category(
        self, category_path: List[str], **kwargs
    ) -> List[Union[VodCategory, VodItem]]:
        """
        Return the children of the VOD node identified by *path*.

        path is a list of content_id strings as returned by previous calls,
        e.g. [] → root, ["/sports"] → sport list, ["/sports/alpine-skiing"] → items.

        Only the *last* element matters for fetching; earlier elements are
        kept by the base VodOperations path-resolver but not used here.
        """
        if not category_path:
            return self._root()

        route = category_path[-1]
        return self._fetch_children(route)

    # ------------------------------------------------------------------
    # Root
    # ------------------------------------------------------------------

    @staticmethod
    def _root() -> List[VodCategory]:
        return [
            VodCategory(
                name=label,
                content_id=route,
                provider="discovery",
            )
            for route, label in _ROOT_BUCKETS
        ]

    # ------------------------------------------------------------------
    # Generic page fetch + parse
    # ------------------------------------------------------------------

    def _fetch_children(
        self, route: str
    ) -> List[Union[VodCategory, VodItem]]:
        """
        Resolve a CMS route path and parse its children.

        The /cms/routes response already contains the full page object and
        all included items — no second /cms/pages fetch is needed.
        """
        try:
            route_data = self._resolve_route(route)
            page_data = self._route_to_page_data(route_data, route)
            return self._parse_page(page_data)
        except Exception as e:
            logger.error(f"DiscoveryVodManager: failed to fetch '{route}': {e}")
            return []

    def _resolve_route(self, route: str) -> dict:
        """
        GET /cms/routes{route} → full JSON:API response.

        Returns the raw response dict (data + included).  The caller is
        responsible for extracting the page object via _route_to_page_data.
        """
        url = f"{_CMS_BASE}/cms/routes{route}"
        params = {
            "include": "default",
        }
        response = self._provider.http_manager.get(
            url,
            operation="vod_resolve_route",
            headers=self._provider.get_auth_headers(),
            params=params,
        )
        response.raise_for_status()
        data = response.json()

        page_id = (
            data.get("data", {})
                .get("relationships", {})
                .get("target", {})
                .get("data", {})
                .get("id")
        )
        if not page_id:
            raise ValueError(f"No page_id in route response for '{route}'")
        logger.debug(f"DiscoveryVodManager: route '{route}' → page '{page_id}'")

        return data

    @staticmethod
    def _route_to_page_data(route_data: dict, route: str) -> dict:
        """
        The /cms/routes response has data.type == "route".  _parse_page
        expects data to be the page object so it can walk
        data.relationships.items.

        This method swaps data to the actual page object found in included,
        leaving included intact so the full index is available to the parser.
        """
        included: List[dict] = route_data.get("included", [])
        index: Dict[str, dict] = {obj["id"]: obj for obj in included}

        # The route's target relationship points to the page id
        page_id = (
            route_data.get("data", {})
                      .get("relationships", {})
                      .get("target", {})
                      .get("data", {})
                      .get("id")
        )
        page_obj = index.get(page_id)
        if not page_obj:
            raise ValueError(
                f"Page object '{page_id}' not found in route included for '{route}'"
            )

        return {
            "data": page_obj,
            "included": included,
        }

    # ------------------------------------------------------------------
    # Page parser
    # ------------------------------------------------------------------

    def _parse_page(
        self, data: dict
    ) -> List[Union[VodCategory, VodItem]]:
        """
        Parse a CMS page response into VodCategory / VodItem entries.

        Strategy:
          - Build an id→object index from `included`.
          - Collect relevant collectionItems (episode-only filter on show pages).
          - Dispatch each item on the type of its relationship target.
        """
        included: List[dict] = data.get("included", [])
        index: Dict[str, dict] = {obj["id"]: obj for obj in included}

        # Collect all collections on this page (via pageItems)
        page_obj = data.get("data", {})
        page_item_ids = [
            pi["id"]
            for pi in page_obj.get("relationships", {})
                               .get("items", {})
                               .get("data", [])
        ]
        page_items = [index[pid] for pid in page_item_ids if pid in index]

        # Each pageItem points to a collection
        collections: List[dict] = []
        for pi in page_items:
            col_ref = (
                pi.get("relationships", {})
                  .get("collection", {})
                  .get("data", {})
            )
            if col_ref and col_ref.get("id") in index:
                collections.append(index[col_ref["id"]])

        # Decide which collections to read
        is_show_page = self._is_show_page(collections)
        if is_show_page:
            collections = [
                c for c in collections
                if any(
                    kw in c.get("attributes", {}).get("alias", "")
                    for kw in _EPISODE_ALIAS_KEYWORDS
                )
            ]
            logger.debug(
                f"DiscoveryVodManager: show page — using "
                f"{len(collections)} episode collection(s)"
            )

        # Collect all collectionItem ids from selected collections
        col_item_ids: List[str] = []
        for col in collections:
            for ci_ref in (
                col.get("relationships", {})
                   .get("items", {})
                   .get("data", [])
            ):
                col_item_ids.append(ci_ref["id"])

        # Resolve nested collection items (collectionItem → collection → items)
        col_item_ids = self._expand_nested_collections(
            col_item_ids, index, is_show_page
        )

        # Dispatch
        results: List[Union[VodCategory, VodItem]] = []
        seen_ids: set = set()

        for ci_id in col_item_ids:
            ci = index.get(ci_id)
            if not ci:
                continue
            rel = ci.get("relationships", {})

            if "video" in rel:
                video_id = rel["video"]["data"]["id"]
                if video_id in seen_ids:
                    continue
                seen_ids.add(video_id)
                video = index.get(video_id)
                if video:
                    item = self._video_to_vod_item(video, index)
                    if item:
                        results.append(item)

            elif "show" in rel:
                show_id = rel["show"]["data"]["id"]
                if show_id in seen_ids:
                    continue
                seen_ids.add(show_id)
                show = index.get(show_id)
                if show:
                    cat = self._show_to_vod_category(show, index)
                    if cat:
                        results.append(cat)

            elif "taxonomyNode" in rel:
                node_id = rel["taxonomyNode"]["data"]["id"]
                if node_id in seen_ids:
                    continue
                seen_ids.add(node_id)
                node = index.get(node_id)
                if node:
                    cat = self._taxonomy_node_to_vod_category(node, index)
                    if cat:
                        results.append(cat)

            # "collection" nested refs are handled by _expand_nested_collections
            # Everything else (channel, creditGroup, …) is silently skipped.

        logger.debug(
            f"DiscoveryVodManager: parsed {len(results)} children "
            f"({'show page' if is_show_page else 'category page'})"
        )
        return results

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_show_page(collections: List[dict]) -> bool:
        """
        A page is treated as a show page if any collection alias contains
        'episode'.  This drives the episode-only filter.
        """
        return any(
            "episode" in c.get("attributes", {}).get("alias", "")
            for c in collections
        )

    @staticmethod
    def _expand_nested_collections(
        col_item_ids: List[str],
        index: Dict[str, dict],
        is_show_page: bool,
    ) -> List[str]:
        """
        Some collectionItems point to another collection rather than direct
        content (e.g. the tab-group pattern).  Expand one level of nesting.
        Non-collection items are passed through unchanged.
        """
        expanded: List[str] = []
        for ci_id in col_item_ids:
            ci = index.get(ci_id)
            if not ci:
                continue
            rel = ci.get("relationships", {})
            if "collection" in rel:
                nested_col_id = rel["collection"]["data"]["id"]
                nested_col = index.get(nested_col_id)
                if nested_col:
                    alias = nested_col.get("attributes", {}).get("alias", "")
                    # On show pages skip nested collections that aren't episodes
                    if is_show_page and not any(
                        kw in alias for kw in _EPISODE_ALIAS_KEYWORDS
                    ):
                        continue
                    for nested_ci_ref in (
                        nested_col.get("relationships", {})
                                  .get("items", {})
                                  .get("data", [])
                    ):
                        expanded.append(nested_ci_ref["id"])
            else:
                expanded.append(ci_id)
        return expanded

    @staticmethod
    def _resolve_route_url(
        obj: dict, index: Dict[str, dict]
    ) -> Optional[str]:
        """
        Follow obj → relationships.routes[0] → route.attributes.url
        Returns the canonical URL string or None.
        """
        route_refs = (
            obj.get("relationships", {})
               .get("routes", {})
               .get("data", [])
        )
        for ref in route_refs:
            route = index.get(ref["id"])
            if route and route.get("attributes", {}).get("canonical", False):
                return route["attributes"].get("url")
        # Fall back to first route if none is canonical
        for ref in route_refs:
            route = index.get(ref["id"])
            if route:
                return route["attributes"].get("url")
        return None

    @staticmethod
    def _pick_image(
        obj: dict, index: Dict[str, dict], preferred_kind: str = "default"
    ) -> Optional[str]:
        """Return the src of the first image matching preferred_kind, else first image."""
        image_refs = (
            obj.get("relationships", {})
               .get("images", {})
               .get("data", [])
        )
        fallback_src = None
        for ref in image_refs:
            img = index.get(ref["id"])
            if not img:
                continue
            src = img.get("attributes", {}).get("src")
            if not src:
                continue
            if fallback_src is None:
                fallback_src = src
            if img.get("attributes", {}).get("kind") == preferred_kind:
                return src
        return fallback_src

    # ------------------------------------------------------------------
    # Object → VOD model converters
    # ------------------------------------------------------------------

    def _video_to_vod_item(
        self, video: dict, index: Dict[str, dict]
    ) -> Optional[VodItem]:
        """
        Convert a video JSON:API object to a VodItem.
        content_id = edit.id  (the playback identifier).
        """
        edit_ref = (
            video.get("relationships", {})
                 .get("edit", {})
                 .get("data", {})
        )
        edit_id = edit_ref.get("id") if edit_ref else None
        if not edit_id:
            logger.debug(
                f"DiscoveryVodManager: video '{video.get('id')}' has no edit — skipping"
            )
            return None

        attrs = video.get("attributes", {})

        # Duration: edit has duration_ms; fall back to video attrs
        edit_obj = index.get(edit_id, {})
        duration_ms = edit_obj.get("attributes", {}).get("duration")
        duration_seconds = int(duration_ms / 1000) if duration_ms else None

        return VodItem.create_episode(
            name=attrs.get("name", ""),
            content_id=edit_id,
            provider="discovery",
            season_number=attrs.get("seasonNumber"),
            episode_number=attrs.get("episodeNumber"),
            description=attrs.get("description") or attrs.get("longDescription"),
            logo_url=self._pick_image(video, index, "default"),
            duration_seconds=duration_seconds,
        )

    def _show_to_vod_category(
        self, show: dict, index: Dict[str, dict]
    ) -> Optional[VodCategory]:
        """
        Convert a show JSON:API object to a VodCategory.
        content_id = canonical route URL (e.g. /show/{uuid}).
        """
        route_url = self._resolve_route_url(show, index)
        if not route_url:
            logger.debug(
                f"DiscoveryVodManager: show '{show.get('id')}' has no route — skipping"
            )
            return None

        attrs = show.get("attributes", {})
        return VodCategory(
            name=attrs.get("name", ""),
            content_id=route_url,
            provider="discovery",
            description=attrs.get("description") or attrs.get("longDescription"),
            logo_url=self._pick_image(show, index, "default"),
        )

    def _taxonomy_node_to_vod_category(
        self, node: dict, index: Dict[str, dict]
    ) -> Optional[VodCategory]:
        """
        Convert a taxonomyNode JSON:API object to a VodCategory.
        content_id = canonical route URL (e.g. /sports/alpine-skiing).
        """
        route_url = self._resolve_route_url(node, index)
        if not route_url:
            logger.debug(
                f"DiscoveryVodManager: taxonomyNode '{node.get('id')}' "
                "has no route — skipping"
            )
            return None

        attrs = node.get("attributes", {})
        return VodCategory(
            name=attrs.get("name", ""),
            content_id=route_url,
            provider="discovery",
            logo_url=self._pick_image(node, index, "default"),
        )