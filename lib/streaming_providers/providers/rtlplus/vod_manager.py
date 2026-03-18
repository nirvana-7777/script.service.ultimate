# streaming_providers/providers/rtlplus/vod_manager.py
"""
RTL+ VOD Manager

Implements get_vod_category(path) for RTLPlusProvider.

Tree structure
--------------
TopicWorlds branch  (series/shows by topic)
  []                                               → root: TopicWorld VodCategories
                                                     + Movies root + Series root
  ["<topic_rrn>"]                                  → Format/Movie items within a TopicWorld
  ["<topic_rrn>", "<format_rrn>"]                  → Season VodCategories
  ["<topic_rrn>", "<format_rrn>", "<season_key>"]  → Episode VodItems

Movies branch  (OverviewPage, elementType=MOVIE)
  ["movies-genre:/video-tv/filme"]                 → Genre VodCategories
  ["movies-genre:/video-tv/filme",
   "movies-genre:/video-tv/filme/genre/action"]    → Movie VodItems (paginated)

Series branch  (OverviewPage, elementType=SERIES)
  ["series-genre:/video-tv/serien"]                → Genre VodCategories
  ["series-genre:/video-tv/serien",
   "series-genre:/video-tv/serien/genre/drama"]    → Series VodItems (paginated)

content_id conventions
-----------------------
- TopicWorlds:  rrn:multipurpose:internal:page:topic-world  (or similar)  → VodCategory
- Formats:      rrn:watch:videohub:format:{id}                             → VodCategory
- Season key:   "season:{discriminator}@{format_rrn}"  (synthetic)        → VodCategory
                discriminator = ordinal string for ORDINAL, YYYYMM for ANNUAL
- Episodes:     rrn:watch:videohub:episode:{id}                            → VodItem
- Movies:       rrn:watch:videohub:movie:{id}                              → VodItem
- Movie root:   "/video-tv/filme"                                          → VodCategory
- Movie genre:  "/video-tv/filme/genre/<slug>"                             → VodCategory
- Series root:  "/video-tv/serien"                                         → VodCategory
- Series genre: "/video-tv/serien/genre/<slug>"                            → VodCategory

Stream resolution
-----------------
provider.get_manifest(content_id) / provider.get_drm(content_id) handle VOD
RRNs via WatchPlayerConfigV3 (GraphQL) and the Wurstland config endpoint.
This manager never performs stream or DRM fetches directly.

GraphQL note
-------------
RTL+ uses persisted queries exclusively.  All operation names and hashes live
in RTLPlusGraphQL so this file contains zero magic strings.
Partial-data (valueCompletion) responses are handled defensively throughout.
"""

import calendar
from typing import List, Optional, Union

from ...base.models.vod import VodCategory, VodItem
from ...base.utils.logger import logger
from .constants import RTLPlusConfig, RTLPlusDefaults, RTLPlusGraphQL


class RTLPlusVodManager:
    """
    Handles VOD browsing for RTL+.

    Instantiated and owned by RTLPlusProvider.  Requires a reference to the
    provider so it can reuse _get_rtlplus_authenticated_headers() and
    http_manager.
    """

    def __init__(self, provider):
        self._provider = provider

    # ------------------------------------------------------------------
    # Convenience shorthands
    # ------------------------------------------------------------------

    @property
    def _cfg(self) -> RTLPlusConfig:
        return self._provider.rtl_config

    @property
    def _graphql_url(self) -> str:
        return self._cfg.graphql_endpoint

    def _headers(self) -> dict:
        return self._provider._get_rtlplus_authenticated_headers()

    # ------------------------------------------------------------------
    # Public entry point — called by provider.get_vod_category()
    # ------------------------------------------------------------------

    def get_vod_category(
        self, content_id: str = "", **kwargs
    ) -> List[Union[VodCategory, VodItem]]:
        """
        Return the children of the VOD node identified by *content_id*.

        content_id is a single opaque token — never split by the caller.
        Dispatch is by prefix:

            ""                              → root
            "/video-tv/filme"               → movies branch
            "/video-tv/serien"              → series branch
            "/video-tv/shows"               → shows branch
            "rrn:watch:videohub:format:*"   → list seasons for format
            "rrn:watch:videohub:season:*"   → list episodes for season
            "rrn:multipurpose:*"            → list formats for topic world
            "movies-genre:*"                → movie genre items
            "series-genre:*"                → series genre items
            "season:*"                      → episodes for season key
        """
        if not content_id:
            return self._list_root()

        # Restore leading slash stripped by Bottle's :path wildcard for
        # watch-path style IDs (e.g. "video-tv/filme" → "/video-tv/filme").
        # Opaque IDs (rrn:, lane:, season: …) never start with "/" anyway.
        if "/" in content_id and not content_id.startswith("/") and ":" not in content_id:
            content_id = "/" + content_id

        if content_id.startswith(RTLPlusDefaults.VOD_MOVIES_ROOT_WATCH_PATH):
            return self._dispatch_movies([content_id])

        if content_id.startswith(RTLPlusDefaults.VOD_SERIES_ROOT_WATCH_PATH):
            return self._dispatch_series([content_id])

        if content_id.startswith(RTLPlusDefaults.VOD_SHOWS_ROOT_WATCH_PATH):
            return self._dispatch_shows([content_id])

        if content_id.startswith("rrn:watch:videohub:format:"):
            return self._list_seasons(content_id)

        if content_id.startswith("rrn:watch:videohub:season:"):
            return self._list_episodes_for_season(content_id)

        if content_id.startswith("rrn:"):
            return self._list_formats_for_topic(content_id)

        if content_id.startswith("movies-genre:") or content_id.startswith("series-genre:"):
            return self._dispatch_movies([content_id]) if content_id.startswith("movies-genre:")                 else self._dispatch_series([content_id])

        if content_id.startswith("season:"):
            # season:<format_rrn>/<season_key> — encoded as a single token
            # e.g. "season:rrn:watch:videohub:format:123/s1"
            rest = content_id[len("season:"):]
            if "/" in rest:
                format_rrn, season_key = rest.split("/", 1)
                return self._list_episodes(format_rrn, season_key)

        logger.warning(f"RTLPlusVodManager: unrecognised content_id: {content_id!r}")
        return []

    # ------------------------------------------------------------------
    # Depth 0 — root
    # ------------------------------------------------------------------

    def _list_root(self) -> List[Union[VodCategory, VodItem]]:
        """
        Return the top-level VOD nodes:
          1. Synthetic "Filme" VodCategory  → gates the movies-by-genre branch.
          2. Synthetic "Serien" VodCategory → gates the series-by-genre branch.
          3. All TopicWorld VodCategories   → shows/sports/etc. by topic.
        """
        results: List[Union[VodCategory, VodItem]] = [
            VodCategory(
                name="Filme",
                content_id=RTLPlusDefaults.VOD_MOVIES_ROOT_WATCH_PATH,
                provider="rtlplus",
                description="Filme & Dokumentationen auf RTL+",
            ),
            VodCategory(
                name="Serien",
                content_id=RTLPlusDefaults.VOD_SERIES_ROOT_WATCH_PATH,
                provider="rtlplus",
                description="Serien auf RTL+",
            ),
            VodCategory(
                name="Shows",
                content_id=RTLPlusDefaults.VOD_SHOWS_ROOT_WATCH_PATH,
                provider="rtlplus",
                description="Shows auf RTL+",
            ),
        ]
        results.extend(self._list_topic_worlds())
        logger.debug(f"RTLPlusVodManager: _list_root() → {len(results)} nodes")
        return results

    # ------------------------------------------------------------------
    # Movies branch dispatcher
    # ------------------------------------------------------------------

    def _dispatch_movies(
        self, category_path: List[str]
    ) -> List[Union[VodCategory, VodItem]]:
        depth = len(category_path)
        if depth == 1:
            # The normaliser may have collapsed e.g. ["video-tv","filme","genre","action"]
            # into a single element ["/video-tv/filme/genre/action"].  Detect this by
            # checking whether the path already contains "/genre/".
            genre_prefix = RTLPlusDefaults.VOD_MOVIES_ROOT_WATCH_PATH + "/genre/"
            if category_path[0].startswith(genre_prefix):
                genre_slug = category_path[0][len(genre_prefix):].split("/")[0]
                return self._list_overview_page_items(
                    element_type=RTLPlusDefaults.VOD_ELEMENT_TYPE_MOVIE,
                    genre_slug=genre_slug,
                )
            genres = self._list_genres(
                root_watch_path=RTLPlusDefaults.VOD_MOVIES_ROOT_WATCH_PATH,
                genre_slugs=RTLPlusDefaults.VOD_MOVIE_GENRE_SLUGS,
            )
            items = self._list_overview_page_items(
                element_type=RTLPlusDefaults.VOD_ELEMENT_TYPE_MOVIE,
            )
            return genres + items
        if depth == 2:
            genre_slug = category_path[1].rsplit("/", 1)[-1]
            return self._list_overview_page_items(
                element_type=RTLPlusDefaults.VOD_ELEMENT_TYPE_MOVIE,
                genre_slug=genre_slug,
            )
        logger.warning(f"RTLPlusVodManager: movies path too deep: {category_path!r}")
        return []

    # ------------------------------------------------------------------
    # Series branch dispatcher
    # ------------------------------------------------------------------

    def _dispatch_series(
        self, category_path: List[str]
    ) -> List[Union[VodCategory, VodItem]]:
        depth = len(category_path)
        if depth == 1:
            # Same collapsed-path case as _dispatch_movies: detect a full genre URL.
            genre_prefix = RTLPlusDefaults.VOD_SERIES_ROOT_WATCH_PATH + "/genre/"
            if category_path[0].startswith(genre_prefix):
                genre_slug = category_path[0][len(genre_prefix):].split("/")[0]
                return self._list_overview_page_items(
                    element_type=RTLPlusDefaults.VOD_ELEMENT_TYPE_SERIES,
                    genre_slug=genre_slug,
                )
            genres = self._list_genres(
                root_watch_path=RTLPlusDefaults.VOD_SERIES_ROOT_WATCH_PATH,
                genre_slugs=RTLPlusDefaults.VOD_SERIES_GENRE_SLUGS,
            )
            items = self._list_overview_page_items(
                element_type=RTLPlusDefaults.VOD_ELEMENT_TYPE_SERIES,
            )
            return genres + items
        if depth == 2:
            genre_slug = category_path[1].rsplit("/", 1)[-1]
            return self._list_overview_page_items(
                element_type=RTLPlusDefaults.VOD_ELEMENT_TYPE_SERIES,
                genre_slug=genre_slug,
            )
        logger.warning(f"RTLPlusVodManager: series path too deep: {category_path!r}")
        return []

    # ------------------------------------------------------------------
    # Shows branch dispatcher
    # ------------------------------------------------------------------

    def _dispatch_shows(
        self, category_path: List[str]
    ) -> List[Union[VodCategory, VodItem]]:
        depth = len(category_path)
        if depth == 1:
            genre_prefix = RTLPlusDefaults.VOD_SHOWS_ROOT_WATCH_PATH + "/genre/"
            if category_path[0].startswith(genre_prefix):
                genre_slug = category_path[0][len(genre_prefix):].split("/")[0]
                return self._list_overview_page_items(
                    element_type=RTLPlusDefaults.VOD_ELEMENT_TYPE_SHOW,
                    genre_slug=genre_slug,
                )
            genres = self._list_genres(
                root_watch_path=RTLPlusDefaults.VOD_SHOWS_ROOT_WATCH_PATH,
                genre_slugs=RTLPlusDefaults.VOD_SHOW_GENRE_SLUGS,
            )
            items = self._list_overview_page_items(
                element_type=RTLPlusDefaults.VOD_ELEMENT_TYPE_SHOW,
            )
            return genres + items
        if depth == 2:
            genre_slug = category_path[1].rsplit("/", 1)[-1]
            return self._list_overview_page_items(
                element_type=RTLPlusDefaults.VOD_ELEMENT_TYPE_SHOW,
                genre_slug=genre_slug,
            )
        logger.warning(f"RTLPlusVodManager: shows path too deep: {category_path!r}")
        return []

    # ------------------------------------------------------------------
    # Shared genre list  (movies + series, depth 1 of each branch)
    # ------------------------------------------------------------------

    def _list_genres(
        self,
        root_watch_path: str,
        genre_slugs: List[str],
    ) -> List[VodCategory]:
        """
        Build VodCategory nodes for each genre under *root_watch_path*.

        Each slug is validated via SeoUrlData which also provides the
        localised German title from the breadcrumb.  Invalid slugs are
        silently skipped.
        """
        results: List[VodCategory] = []
        for slug in genre_slugs:
            watch_path = f"{root_watch_path}/genre/{slug}"
            title = self._resolve_watch_path_title(watch_path)
            if title is None:
                logger.debug(
                    f"RTLPlusVodManager: genre slug '{slug}' did not resolve, skipping"
                )
                continue
            results.append(
                VodCategory(
                    name=title,
                    content_id=watch_path,
                    provider="rtlplus",
                )
            )
        logger.debug(
            f"RTLPlusVodManager: _list_genres({root_watch_path}) → {len(results)} genres"
        )
        return results

    def _resolve_watch_path_title(self, watch_path: str) -> Optional[str]:
        """
        Call SeoUrlData to verify a watch-path and return its leaf breadcrumb title.

        Returns the localised title string on success, None if the path is
        invalid or the query fails.

        Response shape (confirmed from live data):
            data.urlDataByWatchPath.hierarchy.entries[-1].metadata.breadcrumbTitle
        """
        data = self._graphql_get(RTLPlusGraphQL.seo_url_data(watch_path))
        if not data:
            return None
        try:
            entries = data["data"]["urlDataByWatchPath"]["hierarchy"]["entries"]
            if not entries:
                return None
            return entries[-1].get("metadata", {}).get("breadcrumbTitle") or None
        except (KeyError, TypeError, IndexError):
            return None

    # ------------------------------------------------------------------
    # Shared OverviewPage item list  (movies + series, depth 2)
    # ------------------------------------------------------------------

    def _list_overview_page_items(
        self,
        element_type: str,
        genre_slug: Optional[str] = None,
    ) -> List[Union[VodCategory, VodItem]]:
        """
        Paginate OverviewPage for an element type, optionally filtered by genre.

        element_type: RTLPlusDefaults.VOD_ELEMENT_TYPE_MOVIE  or  …SERIES
        genre_slug:   e.g. "drama", "action" — omit for unfiltered (all items)

        Series items at this level are returned as VodCategory nodes (each
        wraps a Format RRN) so the caller can drill into seasons/episodes via
        the existing TopicWorlds branch at depth 1+.  Movie items are returned
        as VodItems directly.
        """
        results: List[Union[VodCategory, VodItem]] = []
        seen: set = set()
        offset = 0
        limit = RTLPlusDefaults.VOD_OVERVIEW_PAGE_LIMIT

        while True:
            params = RTLPlusGraphQL.overview_page(
                element_type=element_type,
                genres=[genre_slug] if genre_slug else None,
                offset=offset,
                limit=limit,
            )
            data = self._graphql_get(params)
            if not data:
                break

            # Response key varies: live data uses "watchOverviewPage"
            page = (
                data.get("data", {}).get("watchOverviewPage")
                or data.get("data", {}).get("overviewPage")
                or data.get("data", {}).get("OverviewPage")
                or {}
            )
            items = page.get("items") or page.get("elements") or []

            for node in items:
                if not node:
                    continue
                node_id = node.get("id", "")
                if not node_id or node_id in seen:
                    continue
                seen.add(node_id)

                try:
                    if element_type == RTLPlusDefaults.VOD_ELEMENT_TYPE_MOVIE:
                        vod = self._movie_to_item(node)
                        if vod:
                            results.append(vod)
                    else:
                        # Series → VodCategory so the user can drill to seasons
                        cat = self._format_to_category(node)
                        if cat:
                            results.append(cat)
                except Exception as _node_err:
                    import traceback as _tb
                    logger.error(
                        "RTLPlusVodManager: node parse error (%r) node=%r\n%s"
                        % (_node_err, node, _tb.format_exc())
                    )

            page_info = page.get("pageInfo") or page.get("pagination") or {}
            has_next = (
                page_info.get("hasNextPage")
                or (page_info.get("total", 0) > offset + limit)
            )
            if not has_next:
                break
            offset += limit

        logger.debug(
            f"RTLPlusVodManager: _list_overview_page_items"
            f"({element_type}, genre={genre_slug}) → {len(results)} items"
        )
        return results

    # ------------------------------------------------------------------
    # Depth 0 (series) — TopicWorlds
    # ------------------------------------------------------------------

    def _list_topic_worlds(self) -> List[VodCategory]:
        """
        Fetch all TopicWorlds.  Each becomes a VodCategory whose content_id
        is its server RRN, passed back as category_path[0] at depth 1.

        Response shape: data.topicWorldsV2.elements[]
        Pagination:     data.topicWorldsV2.pageInfo.hasNextPage
        """
        results: List[VodCategory] = []
        seen: set = set()
        offset = 0
        take = 100

        while True:
            data = self._graphql_get(RTLPlusGraphQL.topic_worlds(take=take, offset=offset))
            if not data:
                break

            payload = data.get("data", {}).get("topicWorldsV2", {})
            elements = payload.get("elements", [])

            for world in elements:
                if not world:
                    continue
                cat = self._topic_world_to_category(world)
                if cat and cat.content_id not in seen:
                    seen.add(cat.content_id)
                    results.append(cat)

            page_info = payload.get("pageInfo", {})
            if not page_info.get("hasNextPage", False):
                break
            offset += take

        logger.debug(f"RTLPlusVodManager: _list_topic_worlds() → {len(results)} worlds")
        return results

    # ------------------------------------------------------------------
    # Depth 1 (series) — Formats / Movies within a TopicWorld
    # ------------------------------------------------------------------

    def _list_formats_for_topic(
        self, topic_rrn: str
    ) -> List[Union[VodCategory, VodItem]]:
        """
        Return the content items of a TopicWorld.

        We re-fetch TopicWorlds and locate the matching world, then iterate
        its content items which may be Format or Movie nodes.
        """
        data = self._graphql_get(RTLPlusGraphQL.topic_worlds(take=100, offset=0))
        if not data:
            return []

        worlds = data.get("data", {}).get("topicWorldsV2", {}).get("elements", [])
        target = next(
            (w for w in worlds if w and w.get("id") == topic_rrn), None
        )
        if not target:
            logger.warning(
                f"RTLPlusVodManager: TopicWorld '{topic_rrn}' not found"
            )
            return []

        items = (
            target.get("content", {}).get("items", [])
            or target.get("items", [])
        )

        results: List[Union[VodCategory, VodItem]] = []
        seen: set = set()

        for item in items:
            if not item:
                continue
            if item.get("__typename") == "Movie":
                vod = self._movie_to_item(item)
                if vod and vod.content_id not in seen:
                    seen.add(vod.content_id)
                    results.append(vod)
            else:
                cat = self._format_to_category(item)
                if cat and cat.content_id not in seen:
                    seen.add(cat.content_id)
                    results.append(cat)

        logger.debug(
            f"RTLPlusVodManager: _list_formats_for_topic({topic_rrn}) "
            f"→ {len(results)} items"
        )
        return results

    # ------------------------------------------------------------------
    # Season RRN → Episodes  (SeasonWithFormatAndEpisodes)
    # ------------------------------------------------------------------

    def _list_episodes_for_season(self, season_rrn: str) -> List[VodItem]:
        """
        Fetch episodes for a season identified directly by its RRN.
        Uses SeasonWithFormatAndEpisodes (paginated).
        Response shape: data.season.episodes[]
        """
        results: List[VodItem] = []
        seen: set = set()
        offset = 0
        limit = 48

        while True:
            data = self._graphql_get(
                RTLPlusGraphQL.season_with_episodes(season_rrn, offset=offset, limit=limit)
            )
            if not data:
                break

            season = data.get("data", {}).get("season", {}) or {}
            episodes = season.get("episodes", [])

            for ep in episodes:
                if not ep:
                    continue
                ep_id = ep.get("id", "")
                if not ep_id or ep_id in seen:
                    continue
                seen.add(ep_id)
                vod = self._episode_to_item(ep)
                if vod:
                    results.append(vod)

            # SeasonWithFormatAndEpisodes doesn't paginate via pageInfo;
            # stop when we receive fewer items than requested.
            if len(episodes) < limit:
                break
            offset += limit

        logger.debug(
            f"RTLPlusVodManager: _list_episodes_for_season({season_rrn}) "
            f"→ {len(results)} episodes"
        )
        return results

    # ------------------------------------------------------------------
    # Depth 2 (series) — Seasons for a Format
    # ------------------------------------------------------------------

    def _list_seasons(self, format_rrn: str) -> List[VodCategory]:
        """Fetch seasons using MRE first, falling back to the Format query."""
        # Primary: MRE
        data = self._graphql_get(RTLPlusGraphQL.mre(format_rrn))
        seasons = self._extract_seasons_from_mre(data) if data else []

        # Fallback: Format detail
        if not seasons:
            logger.debug(
                f"RTLPlusVodManager: MRE empty → Format fallback for '{format_rrn}'"
            )
            data = self._graphql_get(RTLPlusGraphQL.format(format_rrn))
            seasons = self._extract_seasons_from_format(data) if data else []

        results: List[VodCategory] = []
        for node in seasons:
            if not node:
                continue
            cat = self._season_to_category(node, format_rrn)
            if cat:
                results.append(cat)

        logger.debug(
            f"RTLPlusVodManager: _list_seasons({format_rrn}) → {len(results)} seasons"
        )
        return results

    @staticmethod
    def _extract_seasons_from_mre(data: dict) -> list:
        d = data.get("data", {})
        return (
            d.get("mre", {}).get("seasons", {}).get("items", [])
            or d.get("mre", {}).get("seasons", [])
            or d.get("format", {}).get("seasons", {}).get("items", [])
            or []
        )

    @staticmethod
    def _extract_seasons_from_format(data: dict) -> list:
        d = data.get("data", {})
        fmt = d.get("format", {}) or d.get("Format", {}) or {}
        seasons = fmt.get("seasons", [])
        # seasons may be a list directly or {"items": [...]}
        if isinstance(seasons, dict):
            seasons = seasons.get("items", [])
        return seasons or []

    # ------------------------------------------------------------------
    # Depth 3 (series) — Episodes for a Season
    # ------------------------------------------------------------------

    def _list_episodes(self, format_rrn: str, season_key: str) -> List[VodItem]:
        """
        Fetch episodes for a Season.

        season_key format: "season:{discriminator}@{format_rrn}"
        discriminator = ordinal string (ORDINAL) or YYYYMM (ANNUAL)
        """
        discriminator = season_key.split("@")[0].replace("season:", "")

        data = self._graphql_get(RTLPlusGraphQL.mre(format_rrn))
        episodes_raw = (
            self._extract_episodes_from_mre(data, discriminator) if data else []
        )

        if not episodes_raw:
            logger.debug(
                f"RTLPlusVodManager: MRE episodes empty → Format fallback for '{format_rrn}'"
            )
            data = self._graphql_get(RTLPlusGraphQL.format(format_rrn))
            episodes_raw = (
                self._extract_episodes_from_format(data, discriminator) if data else []
            )

        results: List[VodItem] = []
        seen: set = set()
        for ep in episodes_raw:
            if not ep:
                continue
            vod = self._episode_to_item(ep)
            if vod and vod.content_id not in seen:
                seen.add(vod.content_id)
                results.append(vod)

        logger.debug(
            f"RTLPlusVodManager: _list_episodes({format_rrn}, {season_key}) "
            f"→ {len(results)} episodes"
        )
        return results

    @staticmethod
    def _extract_episodes_from_mre(data: dict, discriminator: str) -> list:
        d = data.get("data", {})
        mre = d.get("mre", {}) or {}

        seasons = (
            mre.get("seasons", {}).get("items", [])
            or mre.get("seasons", [])
        )
        for season in seasons:
            if not season:
                continue
            if RTLPlusVodManager._season_matches(season, discriminator):
                return (
                    season.get("episodes", {}).get("items", [])
                    or season.get("episodes", [])
                )

        all_eps = mre.get("episodes", {}).get("items", []) or mre.get("episodes", [])
        return RTLPlusVodManager._filter_episodes_by_season(all_eps, discriminator)

    @staticmethod
    def _extract_episodes_from_format(data: dict, discriminator: str) -> list:
        d = data.get("data", {})
        fmt = d.get("format", {}) or d.get("Format", {}) or {}

        seasons = fmt.get("seasons", {}).get("items", []) or fmt.get("seasons", [])
        for season in seasons:
            if not season:
                continue
            if RTLPlusVodManager._season_matches(season, discriminator):
                return (
                    season.get("episodes", {}).get("items", [])
                    or season.get("episodes", [])
                )

        all_eps = fmt.get("episodes", {}).get("items", []) or fmt.get("episodes", [])
        return RTLPlusVodManager._filter_episodes_by_season(all_eps, discriminator)

    @staticmethod
    def _season_matches(season: dict, discriminator: str) -> bool:
        ordinal = str(season.get("ordinal", ""))
        year = season.get("year", 0)
        month = season.get("month", 0)
        annual = f"{year}{month:02d}" if year else ""
        return ordinal == discriminator or annual == discriminator

    @staticmethod
    def _filter_episodes_by_season(episodes: list, discriminator: str) -> list:
        result = []
        for ep in episodes:
            if not ep:
                continue
            ep_season = ep.get("episodeSeason", {}) or {}
            season_data = ep_season.get("season", {}) or {}
            season_type = ep_season.get("seasonType", "ORDINAL")

            if season_type == "ORDINAL":
                if str(season_data.get("ordinal", "")) == discriminator:
                    result.append(ep)
            elif season_type == "ANNUAL":
                year = season_data.get("year", 0)
                month = season_data.get("month", 0)
                annual = f"{year}{month:02d}" if year else ""
                if annual == discriminator:
                    result.append(ep)
        return result

    # ------------------------------------------------------------------
    # Node → VodModel converters
    # ------------------------------------------------------------------

    @staticmethod
    def _topic_world_to_category(node: dict) -> Optional[VodCategory]:
        rrn = node.get("id", "")
        title = node.get("title", "")
        if not rrn or not title:
            return None

        image = node.get("image", {}) or {}
        logo_url = image.get("thumbnail") or image.get("logo")

        return VodCategory(
            name=title,
            content_id=rrn,
            provider="rtlplus",
            logo_url=logo_url,
            description=(
                node.get("descriptionV2")
                or node.get("emptyFormatText")
                or node.get("description")
            ),
        )

    @staticmethod
    def _format_to_category(node: dict) -> Optional[VodCategory]:
        rrn = node.get("id", "")
        title = node.get("title", "")
        if not rrn or not title:
            return None
        wi = node.get("watchImages") or {}
        logo_url = (
            (wi.get("artworkLandscape") or {}).get("absoluteUri")
            or (wi.get("artworkPortrait") or {}).get("absoluteUri")
        )
        return VodCategory(
            name=title,
            content_id=rrn,
            provider="rtlplus",
            logo_url=logo_url,
            description=(
                node.get("descriptionV2")
                or node.get("emptyFormatText")
                or node.get("description")
            ),
            child_count=node.get("numberOfSeasons"),
        )

    @staticmethod
    def _season_to_category(node: dict, format_rrn: str) -> Optional[VodCategory]:
        season_type = node.get("seasonType") or node.get("type", "ORDINAL")
        season_data = node.get("season", node)

        title = node.get("title") or node.get("titleOverride")
        discriminator: Optional[str] = None

        if season_type == "ORDINAL":
            ordinal = season_data.get("ordinal") or node.get("ordinal")
            if ordinal is None:
                return None
            discriminator = str(ordinal)
            if not title:
                override = season_data.get("titleOverride") or node.get("titleOverride")
                title = override or f"Staffel {ordinal}"

        elif season_type == "ANNUAL":
            year = season_data.get("year") or node.get("year")
            month = season_data.get("month") or node.get("month")
            if not year:
                return None
            discriminator = f"{year}{month:02d}" if month else str(year)
            if not title:
                title = (
                    f"{calendar.month_name[month]} {year}" if month else str(year)
                )
        else:
            server_id = node.get("id", "")
            if not server_id:
                return None
            discriminator = server_id
            title = title or server_id

        # Prefer the real season RRN when available (from Format.seasons[].id)
        # so the client can pass it back and route via _list_episodes_for_season.
        # Fall back to synthetic key for MRE nodes that lack an explicit id.
        season_rrn = node.get("id", "")
        content_id = season_rrn if season_rrn.startswith("rrn:watch:videohub:season:") else f"season:{discriminator}@{format_rrn}"

        return VodCategory(
            name=title,
            content_id=content_id,
            provider="rtlplus",
            child_count=node.get("numberOfEpisodes"),
        )

    @staticmethod
    def _episode_to_item(node: dict) -> Optional[VodItem]:
        rrn = node.get("id", "")
        title = node.get("title", "")
        if not rrn or not title:
            return None

        ep_season = node.get("episodeSeason", {}) or {}
        season_data = ep_season.get("season", {}) or {}
        season_type = ep_season.get("seasonType", "ORDINAL")

        if season_type == "ORDINAL":
            season_number = season_data.get("ordinal")
        elif season_type == "ANNUAL":
            year = season_data.get("year", 0)
            month = season_data.get("month", 0)
            season_number = year * 100 + month if year else None
        else:
            season_number = None

        wi = node.get("watchImages") or {}
        logo_url = (
            (wi.get("default") or {}).get("absoluteUri")
            or (wi.get("portrait") or {}).get("absoluteUri")
        )

        vod = VodItem.create_episode(
            name=title,
            content_id=rrn,
            provider="rtlplus",
            season_number=season_number,
            episode_number=node.get("number"),
            logo_url=logo_url,
            duration_seconds=node.get("durationInSecondsV2"),
        )
        if node.get("tier") == "PREMIUM":
            vod.use_cdm = True
            vod.cdm_type = "widevine"
        return vod

    @staticmethod
    def _movie_to_item(node: dict) -> Optional[VodItem]:
        rrn = node.get("id", "")
        title = node.get("title", "")
        if not rrn or not title:
            return None

        wi = node.get("watchImages") or {}
        logo_url = (
            (wi.get("artworkLandscape") or {}).get("absoluteUri")
            or (wi.get("artworkPortrait") or {}).get("absoluteUri")
        )
        genres = node.get("genres", [])

        vod = VodItem.create_movie(
            name=title,
            content_id=rrn,
            provider="rtlplus",
            logo_url=logo_url,
            duration_seconds=node.get("durationInSecondsV2"),
            release_year=node.get("productionYear"),
            genre=genres[0] if genres else None,
            description=(
                node.get("descriptionV2")
                or node.get("emptyFormatText")
                or node.get("description")
            ),
        )
        if node.get("tier") == "PREMIUM":
            vod.use_cdm = True
            vod.cdm_type = "widevine"
        return vod

    # ------------------------------------------------------------------
    # RRN normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _to_format_rrn(value: str) -> str:
        """Normalise a format identifier (full RRN, numeric ID, or slug) to a full RRN."""
        if value.startswith("rrn:"):
            return value
        if value.isdigit():
            return f"rrn:watch:videohub:format:{value}"
        tail = value.rsplit("-", 1)[-1]
        if tail.isdigit():
            return f"rrn:watch:videohub:format:{tail}"
        return value

    # ------------------------------------------------------------------
    # GraphQL helper
    # ------------------------------------------------------------------

    def _graphql_get(self, params: dict) -> Optional[dict]:
        """
        Execute a GraphQL GET against the RTL+ CDN gateway.
        GraphQL-level errors are logged as debug; callers receive partial data.
        """
        try:
            response = self._provider.http_manager.get(
                self._graphql_url,
                operation="vod_graphql",
                params=params,
                headers=self._headers(),
            )
            response.raise_for_status()
            data = response.json()

            for err in data.get("errors", []):
                logger.debug(
                    f"RTLPlusVodManager: GraphQL "
                    f"[{err.get('extensions', {}).get('code', '?')}] "
                    f"{err.get('message', '')}"
                )
            return data

        except Exception as e:
            logger.error(
                f"RTLPlusVodManager: request failed "
                f"(op={params.get('operationName', '?')}): {e}"
            )
            return None