# streaming_providers/providers/movetv/vod_manager.py
"""
move.tv VOD manager (browse only -- the API has no logged VOD playback yet).

  Catalogue (provider-specific, delegated 1:1 by the provider as in v1):
    get_vod_filters()      -> VodFilters
    get_vod_items(...)     -> VodListing (page / has_next_page)
    get_all_vod_items(...) -> List[VodItem] (pages transparently)
    get_page_components()  -> homepage layout descriptors
    get_component_items()  -> cards of one carousel

  VodManager contract (README §6.2):
    get_vod_category(content_id, cursor, page_size) -> VodPage
        ""                      root  -> content types ("content_type_<ct>")
        "content_type_<ct>"     -> categories          ("category_<ct>_<cat>")
        "category_<ct>_<cat>"   -> items; cursor = next page number, only while
                                   the API says has_next_page (the endpoint
                                   honours `page`); the page size is fixed by
                                   the API, page_size is ignored
    get_vod_manifest -> None, handles_content_id -> False: there is no VOD
    playback, so no id is ever routed here (ids.py).

!! The four parsers below (_parse_filters, _parse_vod_page,
!! _parse_page_components, _parse_component_items) were `pass` in the v1 file
!! that was supplied for the migration. They now raise NotImplementedYetError
!! instead of returning None. Paste the real bodies back in before enabling
!! VOD (MoveTVProvider.VOD_BROWSE_ENABLED).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ...base.errors import BadRequestError, NotImplementedYetError
from ...base.managers import VodManager
from ...base.models.vod import VodCategory, VodItem
from ...base.utils.logger import logger
from ...base.vod import VodPage
from .api import api_post
from .constants import MoveTVConfig
from .ids import category_node, content_type_node, parse_vod_node

_NAME = MoveTVConfig.PROVIDER_NAME

_MISSING_PARSER = (
    "move.tv: {name} has no implementation (the file supplied for the "
    "migration contained only a placeholder); restore the v1 parser body."
)


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
class VodListing:
    """Paginated result of POST /api/v2/content/vod/get/all.

    (v1 name: VodPage -- renamed, it collided with the base VodPage that
    get_vod_category returns.)"""
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

class MoveTvVodManager(VodManager):
    """VOD browse for move.tv. The four standard collaborators only: no
    reference to the provider (v1 took `provider`)."""

    # ------------------------------------------------------------------
    # Routing / playback (none)
    # ------------------------------------------------------------------
    def handles_content_id(self, content_id: str) -> bool:
        return False                      # no VOD playback: never routed

    def get_vod_manifest(self, content_id: str, **kw: Any) -> Optional[str]:
        return None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _post(self, url: str, extra: Dict[str, Any], *, what: str) -> Dict:
        """POST with the common VOD fields (customerProfileId, lang, appVersion),
        re-read from the session on every attempt (token refresh safe)."""
        return api_post(
            self.http_manager, self.auth, url,
            lambda info: {
                "customerProfileId": info["customer_profile_id"],
                "lang": self.config.DEFAULT_LANG,
                "appVersion": self.config.APP_VERSION,
                **extra,
            },
            what=what, operation="api",
        )

    # ------------------------------------------------------------------
    # Parsing helpers -- BODIES MISSING IN THE SUPPLIED v1 FILE (see docstring)
    # ------------------------------------------------------------------
    def _parse_filters(self, data: Dict) -> VodFilters:
        raise NotImplementedYetError(_MISSING_PARSER.format(name="_parse_filters"))

    def _parse_vod_page(self, data: Dict, fallback_page: int) -> VodListing:
        raise NotImplementedYetError(_MISSING_PARSER.format(name="_parse_vod_page"))

    @staticmethod
    def _parse_page_components(data: Dict) -> List[PageComponent]:
        raise NotImplementedYetError(_MISSING_PARSER.format(name="_parse_page_components"))

    def _parse_component_items(self, data: Dict) -> List[ComponentItem]:
        raise NotImplementedYetError(_MISSING_PARSER.format(name="_parse_component_items"))

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
        logger.debug(f"{_NAME}: Fetching VOD filters")

        data = self._post(url, {}, what="VOD filters")

        if not data.get("success"):
            logger.warning(f"{_NAME}: VOD filters -- success=false")
            return VodFilters()

        filters = self._parse_filters(data)
        logger.info(
            f"{_NAME}: VOD filters -- "
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
    ) -> VodListing:
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
            VodListing(items, current_page, has_next_page).
        """
        url = MoveTVConfig.vod_get_all_url()
        payload: Dict[str, Any] = {"page": page, "sort": sort}

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
            f"{_NAME}: VOD get/all "
            f"page={page} sort={sort} "
            f"tag={tag_id} cat={category_id} catalog={catalog_id}"
        )

        data = self._post(url, payload, what=f"VOD page {page}")

        if not data.get("success"):
            logger.warning(f"{_NAME}: VOD get/all -- success=false")
            return VodListing(items=[], current_page=page, has_next_page=False)

        vod_page = self._parse_vod_page(data, fallback_page=page)
        logger.info(
            f"{_NAME}: VOD page {vod_page.current_page} -- "
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
                    f"{_NAME}: VOD pagination capped at {max_pages} pages"
                )
                break
            page += 1

        logger.info(
            f"{_NAME}: VOD full fetch -- "
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
        payload = {"page": page_id}

        logger.debug(
            f"{_NAME}: Fetching page components page_id={page_id}"
        )

        data = self._post(url, payload, what=f"page {page_id}")

        if not data.get("success"):
            logger.warning(
                f"{_NAME}: page/get page_id={page_id} -- success=false"
            )
            return []

        components = self._parse_page_components(data)
        logger.info(
            f"{_NAME}: Page {page_id} -- {len(components)} components"
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
        payload = {"componentId": component_id}

        logger.debug(
            f"{_NAME}: Fetching component items "
            f"component_id={component_id}"
        )

        data = self._post(url, payload, what=f"component {component_id}")

        if not data.get("success"):
            logger.warning(
                f"{_NAME}: component/get "
                f"id={component_id} -- success=false"
            )
            return []

        items = self._parse_component_items(data)
        logger.info(
            f"{_NAME}: Component {component_id} -- {len(items)} items"
        )
        return items

    # ------------------------------------------------------------------
    # VodManager: browse tree
    # ------------------------------------------------------------------
    def get_vod_category(
        self,
        content_id: str = "",
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kw: Any,
    ) -> VodPage:
        node = parse_vod_node(content_id)          # BadRequestError on a foreign id

        if node[0] == "root":
            filters = self.get_vod_filters()
            entries = [
                VodCategory(
                    name=ct.name,
                    content_id=content_type_node(ct.content_type_id),
                    provider=_NAME,
                )
                for ct in filters.content_types
            ]
            logger.info(f"{_NAME}: VOD root -> {len(entries)} content types")
            return VodPage(entries=entries)

        content_type_id = node[1]
        filters = self.get_vod_filters()
        content_type = next(
            (ct for ct in filters.content_types if ct.content_type_id == content_type_id), None
        )
        if content_type is None:
            logger.warning(f"{_NAME}: unknown content type {content_type_id}")
            return VodPage()

        if node[0] == "content_type":
            entries = []
            for category in filters.categories:
                if not str(category.content_id).isdigit():
                    logger.warning(f"{_NAME}: skipping category with non-numeric id: {category}")
                    continue
                entries.append(
                    VodCategory(
                        name=category.name,
                        content_id=category_node(content_type_id, category.content_id),
                        provider=_NAME,
                    )
                )
            logger.info(f"{_NAME}: VOD content type '{content_type.name}' -> {len(entries)} categories")
            return VodPage(entries=entries)

        # node[0] == "category": items, paged by the API's `page`
        try:
            page = int(cursor) if cursor else 1
        except ValueError:
            raise BadRequestError(f"move.tv: invalid VOD cursor {cursor!r}")
        listing = self.get_vod_items(
            page=page,
            sort="newest",
            tag_id=self.config.TAG_ID_BY_CONTENT_TYPE_NAME.get(content_type.name),
            category_id=node[2],
            content_type_id=content_type_id,
        )
        next_cursor = str(listing.current_page + 1) if listing.has_next_page else None
        logger.info(f"{_NAME}: VOD category {node[2]} page {page} -> {len(listing.items)} items")
        return VodPage(entries=list(listing.items), next_cursor=next_cursor)