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
# Root bucket prefixes — used to group taxonomy nodes from the home endpoint
# into labelled top-level categories.
#
# /sports, /genre, /franchise, /editorial do NOT exist as CMS routes —
# calling them directly returns 404.  The real browsable categories live one
# level deeper (e.g. /genre/true-crime, /franchise/gold-rush).
# We discover them by fetching /home and collecting all taxonomyNode routes
# that start with one of these prefixes.
# ---------------------------------------------------------------------------
_ROOT_PREFIXES = [
    ("/sports",    "Sports"),
    ("/genre",     "Genres"),
    ("/franchise", "Franchises"),
    ("/editorial", "Editorial"),
]

# Home endpoint — used to discover the actual top-level categories
_HOME_ROUTE = "/home"


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
            self, content_id: str = "", **kwargs
    ) -> List[Union[VodCategory, VodItem]]:
        """
        Return the children of the VOD node identified by *content_id*.

        content_id is a single opaque token — the CMS route path returned by
        a previous call (e.g. "/sports", "/sports/nordic-combined").
        Empty string → root.
        """
        if not content_id:
            return self._root()

        # Restore leading slash stripped by Bottle's :path wildcard.
        if "/" in content_id and not content_id.startswith("/") and ":" not in content_id:
            content_id = "/" + content_id

        logger.debug(f"DiscoveryVodManager: get_vod_category({content_id!r})")
        return self._fetch_children(content_id)

    # ------------------------------------------------------------------
    # Root — dynamically discovered from the /home endpoint
    # ------------------------------------------------------------------

    def _root(self) -> List[VodCategory]:
        """
        Return top-level VOD categories by fetching /home and extracting all
        taxonomyNode routes grouped under the known prefixes.

        Discovery+ does not expose /genre, /franchise, or /editorial as
        valid CMS routes — those paths return 404.  The actual browsable
        top-level categories (e.g. /genre/true-crime, /franchise/gold-rush)
        are embedded in the /home response as taxonomyNode objects with
        canonical route URLs.  We collect them here so the rest of the tree
        can use real content_ids that resolve correctly.

        Falls back to an empty list (with a logged error) if the home fetch
        fails, so callers always receive a list.
        """
        try:
            home_data = self._resolve_route(_HOME_ROUTE)
        except Exception as e:
            logger.error(f"DiscoveryVodManager: failed to fetch home route: {e}")
            return []

        included: List[dict] = home_data.get("included", [])
        index: Dict[str, dict] = {obj["id"]: obj for obj in included}

        # Build a map of route-URL → (alternateId, localisedName) from all
        # taxonomyNode objects present in the home response.
        # A single taxonomyNode may have multiple route refs; we walk all of
        # them so we don't miss canonical vs non-canonical variants.
        route_url_to_node_attrs: Dict[str, dict] = {}
        for obj in included:
            if obj.get("type") != "taxonomyNode":
                continue
            attrs = obj.get("attributes", {})
            for ref in obj.get("relationships", {}).get("routes", {}).get("data", []):
                route_obj = index.get(ref["id"])
                if not route_obj:
                    continue
                url = route_obj.get("attributes", {}).get("url", "")
                if url:
                    route_url_to_node_attrs[url] = attrs

        # Group discovered URLs under each root prefix and deduplicate.
        results: List[VodCategory] = []
        seen_urls: set = set()

        for prefix, label in _ROOT_PREFIXES:
            # Collect all URLs that belong to this prefix
            children: List[VodCategory] = []
            for url, attrs in sorted(route_url_to_node_attrs.items()):
                if not url.startswith(prefix + "/"):
                    continue
                if url in seen_urls:
                    continue
                seen_urls.add(url)

                # Use alternateId as the canonical name (matches URL slug exactly),
                # falling back to the last path segment or the localised display name.
                alternate_id = attrs.get("alternateId", "").strip()
                segment = url.rstrip("/").rsplit("/", 1)[-1]
                name = alternate_id or segment or attrs.get("name", "")

                children.append(
                    VodCategory(
                        name=name,
                        content_id=url,
                        provider="discovery",
                        description=attrs.get("name") or None,
                    )
                )

            # Only emit the group entry when we actually found children.
            # (Sports is fetched differently and always has entries; the others
            # depend on what the home page exposes for this territory.)
            results.extend(children)
            logger.debug(
                f"DiscoveryVodManager: root — '{label}' has {len(children)} categories"
            )

        return results

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
            "decorators": "viewingHistory,isFavorite,contentAction,badges",
            "page[items.size]": "100",
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
            _visited: Optional[set] = None,
    ) -> List[str]:
        """
        Some collectionItems point to another collection rather than direct
        content (e.g. the tab-group → tab → grid pattern).

        Recursively expands collection refs until only content items remain.
        A visited set prevents infinite loops on circular references.
        Non-collection items are passed through unchanged.
        """
        if _visited is None:
            _visited = set()

        expanded: List[str] = []
        for ci_id in col_item_ids:
            if ci_id in _visited:
                continue
            _visited.add(ci_id)

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
                    nested_ids = [
                        ref["id"]
                        for ref in nested_col.get("relationships", {})
                        .get("items", {})
                        .get("data", [])
                    ]
                    # Recurse to handle arbitrarily deep nesting
                    expanded.extend(
                        DiscoveryVodManager._expand_nested_collections(
                            nested_ids, index, is_show_page, _visited
                        )
                    )
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

        Name is built as "name — secondaryTitle" when secondaryTitle is present
        so that sibling broadcasts of the same event (e.g. different feeds or
        gender groups) produce distinct slugs and avoid collisions.
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

        # Only finished content is eligible for VOD.
        # videoType == "LIVE" means the event is upcoming or ongoing — skip it.
        # "STANDALONE_EVENT" → full past broadcast; "CLIP" → highlight reel.
        video_type = attrs.get("videoType", "")
        if video_type == "LIVE":
            logger.debug(
                f"DiscoveryVodManager: video '{video.get('id')}' is LIVE — skipping"
            )
            return None

        is_highlight = video_type == "CLIP"

        # Duration: edit has duration_ms; fall back to video attrs
        edit_obj = index.get(edit_id, {})
        duration_ms = edit_obj.get("attributes", {}).get("duration")
        duration_seconds = int(duration_ms / 1000) if duration_ms else None

        # Build a display name that is unique across sibling broadcasts.
        # Discovery+ often has multiple feeds for the same event (e.g. different
        # language channels or gender groups) that share the same `name`.
        # Appending secondaryTitle (e.g. "Weltcup | Frauen") disambiguates them
        # and prevents slug collisions in the backend.
        base_name = attrs.get("name", "")
        secondary = attrs.get("secondaryTitle", "")
        name = f"{base_name} — {secondary}" if secondary else base_name

        return VodItem.create_episode(
            name=name,
            content_id=edit_id,
            provider="discovery",
            season_number=attrs.get("seasonNumber"),
            episode_number=attrs.get("episodeNumber"),
            description=attrs.get("description") or attrs.get("longDescription"),
            logo_url=self._pick_image(video, index, "default"),
            duration_seconds=duration_seconds,
            is_highlight=is_highlight,
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

        The category name is set to the node's alternateId rather than its
        localised display name.  The backend derives URL slugs from the name,
        so using the alternateId (which matches the URL path segment exactly,
        e.g. "nordic-combined") ensures that slug resolution works correctly
        across all locales.  The localised name is preserved in description
        so that UI layers can still display it when desired.
        """
        route_url = self._resolve_route_url(node, index)
        if not route_url:
            logger.debug(
                f"DiscoveryVodManager: taxonomyNode '{node.get('id')}' "
                "has no route — skipping"
            )
            return None

        attrs = node.get("attributes", {})

        # Prefer alternateId as the canonical name used for slug matching.
        # Fall back to the last path segment of the route URL, and finally
        # to the localised display name if neither is available.
        alternate_id = attrs.get("alternateId", "").strip()
        route_segment = route_url.rstrip("/").rsplit("/", 1)[-1]
        name = alternate_id or route_segment or attrs.get("name", "")

        return VodCategory(
            name=name,
            content_id=route_url,
            provider="discovery",
            # Surface the localised display name as description so UI layers
            # can render it in the user's language when needed.
            description=attrs.get("name") or None,
            logo_url=self._pick_image(node, index, "default"),
        )