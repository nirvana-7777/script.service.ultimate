# streaming_providers/providers/movetv/vod_manager.py
"""
MoveTV VOD Manager

Handles all VOD-related API interactions for the MoveTV / MTS provider:
  - get_vod_filters()      → available content types, categories, catalogs, tags, sort options
  - get_vod_items()        → paginated catalogue listing with filtering / sorting
  - get_all_vod_items()    → transparent pagination helper
  - get_page_components()  → homepage / page layout (ordered list of component descriptors)
  - get_component_items()  → items inside a single carousel / banner component
  - get_vod_item()         → (stub — implement when detail endpoint is logged)
  - get_vod_category()     → (stub — implement when browse endpoint is logged)

The manager is intentionally decoupled from the provider class so that
provider.py only needs a single delegation call per public VOD method.

Minimal provider.py wiring:
    from .vod_manager import MoveTvVodManager

    class MoveTvProvider(StreamingProvider):
        def __init__(self, ...):
            ...
            self._vod = MoveTvVodManager(self)

        # --- VOD catalogue ---
        def get_vod_filters(self):              return self._vod.get_vod_filters()
        def get_vod_items(self, **kw):          return self._vod.get_vod_items(**kw)
        def get_all_vod_items(self, **kw):      return self._vod.get_all_vod_items(**kw)

        # --- Homepage / pages ---
        def get_page_components(self, page_id): return self._vod.get_page_components(page_id)
        def get_component_items(self, cid):     return self._vod.get_component_items(cid)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from ...base.utils.logger import logger
from ...base.models.vod import VodCategory, VodItem
from .constants import MoveTVConfig

if TYPE_CHECKING:
    from .provider import MoveTVProvider


# ---------------------------------------------------------------------------
# Filter / metadata dataclasses
# ---------------------------------------------------------------------------

@dataclass
class VodContentType:
    """A content-type entry from /vod/filters (e.g. Film, Serija)."""
    content_type_id: int
    name: str
    adult: Optional[bool] = None

    def to_dict(self) -> Dict:
        return {"contentTypeId": self.content_type_id, "name": self.name, "adult": self.adult}


@dataclass
class VodCatalog:
    """A catalog / channel-package entry from /vod/filters."""
    catalog_id: int
    name: str
    adult: bool = False

    def to_dict(self) -> Dict:
        return {"catalogId": self.catalog_id, "name": self.name, "adult": self.adult}


@dataclass
class VodTag:
    """A tag entry from /vod/filters (FILM, SERIJA, SPORT, ...)."""
    tag_id: int
    name: str
    adult: Optional[bool] = None

    def to_dict(self) -> Dict:
        return {"tagId": self.tag_id, "name": self.name, "adult": self.adult}


@dataclass
class VodSortType:
    """A sort-type entry from /vod/filters."""
    sort: str           # API sort key, e.g. "newest", "az"
    name: str           # Human-readable label
    adult: Optional[bool] = None

    def to_dict(self) -> Dict:
        return {"sort": self.sort, "name": self.name, "adult": self.adult}


@dataclass
class VodFilters:
    """
    Aggregated result of POST /api/v2/content/vod/filters.

    All lists may be empty when the API returns nothing or auth fails --
    callers should treat them as best-effort metadata.
    """
    content_types: List[VodContentType] = field(default_factory=list)
    categories: List[VodCategory] = field(default_factory=list)
    catalogs: List[VodCatalog] = field(default_factory=list)
    tags: List[VodTag] = field(default_factory=list)
    sort_types: List[VodSortType] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "contentTypes": [ct.to_dict() for ct in self.content_types],
            "categories": [c.to_dict() for c in self.categories],
            "catalogs": [cat.to_dict() for cat in self.catalogs],
            "tags": [t.to_dict() for t in self.tags],
            "sortTypes": [s.to_dict() for s in self.sort_types],
        }


@dataclass
class VodPage:
    """Paginated result of POST /api/v2/content/vod/get/all."""
    items: List[VodItem]
    current_page: int
    has_next_page: bool

    def to_dict(self) -> Dict:
        return {
            "items": [item.to_dict() for item in self.items],
            "currentPage": self.current_page,
            "hasNextPage": self.has_next_page,
        }


# ---------------------------------------------------------------------------
# Homepage / page dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PageComponentChild:
    """
    The hasChildren block on a PageComponent -- hints at a sub-navigation link.
    children_type 0 / children_id 0 means no drill-down is available.
    """
    children_type: int = 0
    children_id: int = 0
    button_title: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "childrenType": self.children_type,
            "childrenId": self.children_id,
            "buttonTitle": self.button_title,
        }


@dataclass
class PageComponent:
    """
    A single row / section descriptor from POST /api/v2/content/page/get.

    Not directly playable -- fetch the actual items by calling
    get_component_items(component_id).

    Key fields:
        component_id      -- pass to get_component_items() to load content
        item_type_id      -- hint about the kind of items inside
                             (1=live, 2=movie, 3=series, 5=series-card)
        component_type    -- layout hint (6=rail, 15=banner, ...)
        length            -- expected number of items in the component
        title             -- section heading shown in the UI (may be None)
        background        -- optional full-bleed background image path
    """
    component_id: int
    component_design_id: int
    item_type_id: int
    component_type: int
    length: int
    adult: bool = False
    title: Optional[str] = None
    background_color: Optional[str] = None
    background: Optional[str] = None
    margin_top: int = 0
    margin_bottom: int = 0
    has_children: PageComponentChild = field(default_factory=PageComponentChild)

    @property
    def background_url(self) -> Optional[str]:
        return MoveTVConfig.build_image_url(self.background)

    def to_dict(self) -> Dict:
        return {
            "componentId": self.component_id,
            "componentDesignId": self.component_design_id,
            "itemTypeId": self.item_type_id,
            "componentType": self.component_type,
            "length": self.length,
            "adult": self.adult,
            "title": self.title,
            "backgroundColor": self.background_color,
            "backgroundUrl": self.background_url,
            "marginTop": self.margin_top,
            "marginBottom": self.margin_bottom,
            "hasChildren": self.has_children.to_dict(),
        }


@dataclass
class ComponentItem:
    """
    A single card returned by POST /api/v2/content/component/get.

    Covers all item types (live, movie, series) in one dataclass.
    Type-specific fields are None when not applicable.

    item_type_id maps to MoveTVConfig.ITEM_TYPE_* constants:
        1 = live channel
        2 = movie (playable leaf)
        3 = series (has seasons/episodes -- use get_vod_item for details)
    """
    item_id: int
    title: str
    item_type_id: int
    provider: str

    # Optional description (present in component items, absent in /vod/get/all)
    description: Optional[str] = None

    # Visual
    logo_url: Optional[str] = None          # poster preferred; falls back to background
    background_url: Optional[str] = None
    original_title_logo_url: Optional[str] = None
    square_logo_url: Optional[str] = None
    poster_mark_url: Optional[str] = None

    # Metadata from the meta block
    imdb_rating: Optional[float] = None
    release_year: Optional[int] = None
    duration_seconds: Optional[int] = None  # movieDuration
    age_rating: Optional[int] = None        # FSK / parental rating as integer
    subscribed: bool = False
    adult: bool = False
    audio_only: bool = False

    # Live channel back-references (item_type_id == 1 only)
    live_id: Optional[int] = None
    live_name: Optional[str] = None
    live_icon: Optional[str] = None

    # Trailer
    trailer_id: Optional[int] = None

    # Series / season context (non-zero when parentId != 0)
    parent_id: int = 0

    def to_dict(self) -> Dict:
        return {
            "itemId": self.item_id,
            "title": self.title,
            "itemTypeId": self.item_type_id,
            "provider": self.provider,
            "description": self.description,
            "logoUrl": self.logo_url,
            "backgroundUrl": self.background_url,
            "originalTitleLogoUrl": self.original_title_logo_url,
            "squareLogoUrl": self.square_logo_url,
            "posterMarkUrl": self.poster_mark_url,
            "imdbRating": self.imdb_rating,
            "releaseYear": self.release_year,
            "durationSeconds": self.duration_seconds,
            "ageRating": self.age_rating,
            "subscribed": self.subscribed,
            "adult": self.adult,
            "audioOnly": self.audio_only,
            "liveId": self.live_id,
            "liveName": self.live_name,
            "trailerId": self.trailer_id,
            "parentId": self.parent_id,
        }

    def as_vod_item(self) -> Optional[VodItem]:
        """
        Convert to a VodItem for consumers that work with the base model.
        Returns None for live-channel cards (item_type_id == ITEM_TYPE_LIVE).
        """
        if self.item_type_id == MoveTVConfig.ITEM_TYPE_LIVE:
            return None

        content_type = (
            "SERIES"
            if self.item_type_id in (
                MoveTVConfig.ITEM_TYPE_SERIES,
                MoveTVConfig.ITEM_TYPE_SERIES_CARD,
            )
            else "MOVIE"
        )

        return VodItem(
            name=self.title,
            content_id=str(self.item_id),
            provider=self.provider,
            logo_url=self.logo_url,
            content_type=content_type,
            mode="vod",
            description=self.description,
            duration_seconds=self.duration_seconds,
            release_year=self.release_year,
        )


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

class MoveTvVodManager:
    """
    Handles all VOD API calls for the MoveTV provider.

    Accesses the parent provider only through well-defined attributes:
        provider.http_manager           -- shared HTTPManager instance
        provider.authenticator          -- for get_bearer_token()
        provider.customer_profile_id    -- injected into every POST body
        provider.provider_name          -- used in log messages
    """

    def __init__(self, provider: "MoveTVProvider") -> None:
        self._provider = provider

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @property
    def _http(self):
        """Shortcut to the provider's HTTP manager (asserted to exist)."""
        mgr = self._provider.http_manager
        if mgr is None:
            raise RuntimeError(
                "MoveTvVodManager: HTTP manager is not initialised. "
                "Call provider.authenticate() / provider.setup() first."
            )
        return mgr

    def _auth_headers(self) -> Dict[str, str]:
        """Build the standard headers for every MoveTV API call."""
        token = self._provider.authenticator.get_bearer_token()
        return MoveTVConfig.get_api_headers(token)

    def _base_payload(self) -> Dict[str, Any]:
        """Common POST body fields included in every VOD request."""
        return {
            "customerProfileId": self._provider.customer_profile_id,
            "lang": MoveTVConfig.DEFAULT_LANG,
            "appVersion": MoveTVConfig.APP_VERSION,
        }

    def _post(self, url: str, payload: Dict[str, Any]) -> Dict:
        """
        Execute a POST request and return the parsed JSON body.
        Raises on network / JSON errors after logging them.
        """
        try:
            response = self._http.post(url, json=payload, headers=self._auth_headers())
            return response.json()
        except Exception as exc:
            logger.error(f"{self._provider.provider_name}: POST {url} failed -- {exc}")
            raise

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    def _parse_filters(self, data: Dict) -> VodFilters:
        content = data.get("content", {})

        content_types = [
            VodContentType(
                content_type_id=ct["contentTypeId"],
                name=ct["name"],
                adult=ct.get("adult"),
            )
            for ct in content.get("contentTypes", [])
        ]

        categories = [
            VodCategory(
                name=cat["name"],
                content_id=str(cat["categoryId"]),
                provider=self._provider.provider_name,
            )
            for cat in content.get("categories", [])
        ]

        catalogs = [
            VodCatalog(
                catalog_id=c["catalogId"],
                name=c["name"],
                adult=bool(c.get("adult")),
            )
            for c in content.get("catalogs", [])
        ]

        tags = [
            VodTag(tag_id=t["tagId"], name=t["name"], adult=t.get("adult"))
            for t in content.get("tags", [])
        ]

        sort_types = [
            VodSortType(sort=s["sort"], name=s["name"], adult=s.get("adult"))
            for s in content.get("sortTypes", [])
        ]

        return VodFilters(
            content_types=content_types,
            categories=categories,
            catalogs=catalogs,
            tags=tags,
            sort_types=sort_types,
        )

    def _parse_vod_page(self, data: Dict, fallback_page: int) -> VodPage:
        """
        Parse a paginated /vod/get/all response.

        Each item is a lightweight catalogue card -- full metadata (duration,
        cast, manifest URL) requires a separate detail call via get_vod_item().
        """
        items: List[VodItem] = []

        for raw in data.get("content", []):
            picture = raw.get("picture") or {}
            trailer = raw.get("trailer") or {}

            logo_url = MoveTVConfig.build_image_url(
                picture.get("poster") or picture.get("background")
            )

            sub_type = raw.get("contentSubTypeId")
            content_type = (
                "SERIES"
                if sub_type == MoveTVConfig.CONTENT_SUB_TYPE_SERIES
                else "MOVIE"
            )

            trailer_url: Optional[str] = None
            if trailer.get("trailerId"):
                trailer_url = (
                    f"{MoveTVConfig.API_BASE_URL}/api/v2/content/trailer/"
                    f"{trailer['trailerId']}"
                )

            items.append(
                VodItem(
                    name=raw["title"],
                    content_id=str(raw["contentId"]),
                    provider=self._provider.provider_name,
                    logo_url=logo_url,
                    content_type=content_type,
                    mode="vod",
                    trailer_url=trailer_url,
                    description=(
                        f"IMDB: {raw['vodImdbRating']}"
                        if raw.get("vodImdbRating")
                        else None
                    ),
                )
            )

        return VodPage(
            items=items,
            current_page=data.get("currentPage") or fallback_page,
            has_next_page=bool(data.get("nextPage")),
        )

    @staticmethod
    def _parse_page_components(data: Dict) -> List[PageComponent]:
        """Parse the ordered component list from /content/page/get."""
        components: List[PageComponent] = []

        for raw in data.get("content", []):
            hc_raw = raw.get("hasChildren") or {}
            has_children = PageComponentChild(
                children_type=hc_raw.get("childrenType", 0),
                children_id=hc_raw.get("childrenId", 0),
                button_title=hc_raw.get("buttonTitle"),
            )
            components.append(
                PageComponent(
                    component_id=raw["componentId"],
                    component_design_id=raw["componentDesignId"],
                    item_type_id=raw["itemTypeId"],
                    component_type=raw["componentType"],
                    length=raw["length"],
                    adult=bool(raw.get("adult", 0)),
                    title=raw.get("componentTitle"),
                    background_color=raw.get("backgroundColor"),
                    background=raw.get("background"),
                    margin_top=raw.get("marginTop", 0),
                    margin_bottom=raw.get("marginBottom", 0),
                    has_children=has_children,
                )
            )

        return components

    def _parse_component_items(self, data: Dict) -> List[ComponentItem]:
        """Parse the item cards from /content/component/get."""
        items: List[ComponentItem] = []

        for raw in data.get("content", []):
            picture = raw.get("picture") or {}
            meta = raw.get("meta") or {}
            trailer = raw.get("trailer") or {}

            logo_url = MoveTVConfig.build_image_url(
                picture.get("poster") or picture.get("icon") or picture.get("background")
            )

            items.append(
                ComponentItem(
                    item_id=raw["itemId"],
                    title=raw["title"],
                    item_type_id=raw["itemTypeId"],
                    provider=self._provider.provider_name,
                    description=raw.get("description"),
                    logo_url=logo_url,
                    background_url=MoveTVConfig.build_image_url(picture.get("background")),
                    original_title_logo_url=MoveTVConfig.build_image_url(
                        picture.get("originalTitleLogo")
                    ),
                    square_logo_url=MoveTVConfig.build_image_url(picture.get("squareLogo")),
                    poster_mark_url=MoveTVConfig.build_image_url(picture.get("posterMark")),
                    imdb_rating=meta.get("vodImdbRating"),
                    release_year=meta.get("vodYear"),
                    duration_seconds=meta.get("movieDuration"),
                    age_rating=meta.get("rating"),
                    subscribed=bool(meta.get("subscribed")),
                    adult=bool(meta.get("adult")),
                    audio_only=bool(meta.get("audioOnly")),
                    live_id=meta.get("liveId"),
                    live_name=meta.get("liveName"),
                    live_icon=meta.get("liveIcon"),
                    trailer_id=trailer.get("trailerId"),
                    parent_id=raw.get("parentId", 0),
                )
            )

        return items

    # ------------------------------------------------------------------
    # Public API -- VOD catalogue
    # ------------------------------------------------------------------

    def get_vod_filters(self) -> VodFilters:
        """
        Fetch available VOD filter metadata.

        Calls:
            POST /api/v2/content/vod/filters
            Body: { customerProfileId, lang, appVersion }

        Returns:
            VodFilters with content_types, categories, catalogs, tags, sort_types.
        """
        url = MoveTVConfig.vod_filters_url()
        logger.debug(f"{self._provider.provider_name}: Fetching VOD filters")

        data = self._post(url, self._base_payload())

        if not data.get("success"):
            logger.warning(f"{self._provider.provider_name}: VOD filters -- success=false")
            return VodFilters()

        filters = self._parse_filters(data)
        logger.info(
            f"{self._provider.provider_name}: VOD filters -- "
            f"{len(filters.content_types)} content types, "
            f"{len(filters.categories)} categories, "
            f"{len(filters.catalogs)} catalogs, "
            f"{len(filters.tags)} tags"
        )
        return filters

    def get_vod_items(
        self,
        page: int = 1,
        sort: str = "newest",
        tag_id: Optional[int] = None,
        category_id: Optional[int] = None,
        catalog_id: Optional[int] = None,
        content_type_id: Optional[int] = None,
        search_query: Optional[str] = None,
    ) -> VodPage:
        """
        Fetch a paginated list of VOD items with optional filtering.

        Calls:
            POST /api/v2/content/vod/get/all
            Body: {
                customerProfileId, lang, appVersion,
                page, sort,
                tagId?,          # 1=FILM  2=SERIJA  3=DOKUMENTARNI  4=MUZIKA  5=SPORT  6=PODKAST
                categoryId?,     # e.g. 117=AKCIONI  152=DRAMA
                catalogId?,      # e.g. 662=APOLLON  693=HBO OD
                contentTypeId?,  # 2=Film  5=Serija
                search?          # free-text (unconfirmed -- extend when logged)
            }

        Args:
            page:             1-based page number (default 1).
            sort:             Sort key from VodFilters.sort_types (default "newest").
            tag_id:           Filter by tag ID.
            category_id:      Filter by genre/category ID.
            catalog_id:       Filter by catalog/package ID.
            content_type_id:  Filter by content type ID.
            search_query:     Free-text search string.

        Returns:
            VodPage(items, current_page, has_next_page).
        """
        url = MoveTVConfig.vod_get_all_url()
        payload: Dict[str, Any] = {**self._base_payload(), "page": page, "sort": sort}

        # Only include filter keys that were explicitly provided --
        # omitting them returns all content.
        if tag_id is not None:
            payload["tagId"] = tag_id
        if category_id is not None:
            payload["categoryId"] = category_id
        if catalog_id is not None:
            payload["catalogId"] = catalog_id
        if content_type_id is not None:
            payload["contentTypeId"] = content_type_id
        if search_query:
            payload["search"] = search_query

        logger.debug(
            f"{self._provider.provider_name}: VOD get/all "
            f"page={page} sort={sort} "
            f"tag={tag_id} cat={category_id} catalog={catalog_id}"
        )

        data = self._post(url, payload)

        if not data.get("success"):
            logger.warning(f"{self._provider.provider_name}: VOD get/all -- success=false")
            return VodPage(items=[], current_page=page, has_next_page=False)

        vod_page = self._parse_vod_page(data, fallback_page=page)
        logger.info(
            f"{self._provider.provider_name}: VOD page {vod_page.current_page} -- "
            f"{len(vod_page.items)} items, next={vod_page.has_next_page}"
        )
        return vod_page

    def get_all_vod_items(
        self,
        sort: str = "newest",
        tag_id: Optional[int] = None,
        category_id: Optional[int] = None,
        catalog_id: Optional[int] = None,
        content_type_id: Optional[int] = None,
        max_pages: Optional[int] = None,
    ) -> List[VodItem]:
        """
        Convenience wrapper that transparently paginates through all pages.

        Args:
            sort:             Sort key (default "newest").
            tag_id:           Filter by tag ID.
            category_id:      Filter by genre/category ID.
            catalog_id:       Filter by catalog/package ID.
            content_type_id:  Filter by content type ID.
            max_pages:        Hard cap on pages fetched (None = no limit).

        Returns:
            Flat list of VodItem objects across all pages.
        """
        all_items: List[VodItem] = []
        page = 1

        while True:
            vod_page = self.get_vod_items(
                page=page,
                sort=sort,
                tag_id=tag_id,
                category_id=category_id,
                catalog_id=catalog_id,
                content_type_id=content_type_id,
            )
            all_items.extend(vod_page.items)

            if not vod_page.has_next_page:
                break
            if max_pages is not None and page >= max_pages:
                logger.debug(
                    f"{self._provider.provider_name}: VOD pagination capped at {max_pages} pages"
                )
                break
            page += 1

        logger.info(
            f"{self._provider.provider_name}: VOD full fetch -- "
            f"{len(all_items)} items across {page} page(s)"
        )
        return all_items

    # ------------------------------------------------------------------
    # Public API -- Homepage / page layout
    # ------------------------------------------------------------------

    def get_page_components(self, page_id: int) -> List[PageComponent]:
        """
        Fetch the ordered layout descriptor for a homepage / tab page.

        Each PageComponent represents one row / banner in the UI -- it describes
        *what* is in each section but not the individual items themselves.
        Call get_component_items(component.component_id) to load the actual cards.

        Calls:
            POST /api/v2/content/page/get
            Body: { customerProfileId, lang, appVersion, page: <page_id> }

        Args:
            page_id:  Numeric page identifier (e.g. 13 for the VOD home tab).

        Returns:
            Ordered list of PageComponent descriptors.
            Note: currentPage / nextPage are always null for this endpoint --
            all components for the requested page arrive in a single response.
        """
        url = MoveTVConfig.page_get_url()
        payload = {**self._base_payload(), "page": page_id}

        logger.debug(
            f"{self._provider.provider_name}: Fetching page components page_id={page_id}"
        )

        data = self._post(url, payload)

        if not data.get("success"):
            logger.warning(
                f"{self._provider.provider_name}: page/get page_id={page_id} -- success=false"
            )
            return []

        components = self._parse_page_components(data)
        logger.info(
            f"{self._provider.provider_name}: Page {page_id} -- {len(components)} components"
        )
        return components

    def get_component_items(self, component_id: int) -> List[ComponentItem]:
        """
        Fetch the individual content cards for a single page component / carousel.

        Richer than /vod/get/all cards -- description, age rating, release year,
        duration, and per-item subscription status are all present in the meta block.

        Calls:
            POST /api/v2/content/component/get
            Body: { customerProfileId, lang, appVersion, componentId: <component_id> }

        Args:
            component_id:  ID taken from PageComponent.component_id.

        Returns:
            List of ComponentItem objects (may mix live / movie / series cards).
            Use ComponentItem.as_vod_item() to convert non-live cards to VodItem.
        """
        url = MoveTVConfig.component_get_url()
        payload = {**self._base_payload(), "componentId": component_id}

        logger.debug(
            f"{self._provider.provider_name}: Fetching component items "
            f"component_id={component_id}"
        )

        data = self._post(url, payload)

        if not data.get("success"):
            logger.warning(
                f"{self._provider.provider_name}: component/get "
                f"id={component_id} -- success=false"
            )
            return []

        items = self._parse_component_items(data)
        logger.info(
            f"{self._provider.provider_name}: Component {component_id} -- {len(items)} items"
        )
        return items

    # ------------------------------------------------------------------
    # Stubs for endpoints not yet logged
    # ------------------------------------------------------------------

    def get_vod_item(self, content_id: str, **kwargs) -> Optional[VodItem]:
        """
        Fetch full metadata for a single VOD item (manifest, cast, DRM config, ...).

        Not yet implemented -- log the browser request when clicking a title
        to play it, then implement here.  Expected pattern:
            POST /api/v2/content/vod/get/{content_id}
            or  /api/v2/content/vod/details  { contentId, ... }
        """
        logger.warning(
            f"{self._provider.provider_name}: get_vod_item({content_id}) -- "
            "not yet implemented; log the detail/play endpoint to add support."
        )
        return None

    def get_vod_category(
        self, path_ids: List[str], **kwargs
    ) -> List[Union[VodCategory, VodItem]]:
        """
        Fetch children of a VOD category node (seasons, episodes, ...).

        Not yet implemented -- log the browser request when drilling into a
        series or category, then implement here.
        """
        logger.warning(
            f"{self._provider.provider_name}: get_vod_category({path_ids}) -- "
            "not yet implemented; log the browse/drill-down endpoint to add support."
        )
        return []