# streaming_providers/providers/discovery/event_manager.py
"""
Discovery+ Event Manager

Handles sport schedule and live event fetching from the Discovery+ CMS.
Supports two parse paths:
  1. /sports — airing items directly in ``included`` (fast path)
  2. /sport-schedule — items nested inside a collection (legacy fallback)
"""
from datetime import datetime, timezone
from typing import ClassVar, Dict, List, Optional

from ...base.models import Event, EventStatus
from ...base.utils.logger import logger

from .constants import (
    AIRING_BADGE_LIVE,
    AIRING_BADGE_UP_NEXT,
    AIRING_BADGE_UPCOMING_LEGACY,
    AIRING_ITEM_TYPE,
    CMS_INCLUDE_PARAMS,
    CMS_ROUTE_SPORT_SCHEDULE,
    CMS_ROUTE_SPORTS,
)


class DiscoveryEventManager:
    """
    Manages event (sport schedule) fetching for Discovery+.

    Responsibilities:
    - Dynamic CMS route selection from the cached ``_cms_routes`` map
    - Airing-based event parsing (``/sports`` route — fast path)
    - Collection-based event traversal (``/sport-schedule`` — legacy fallback)
    - Taxonomy relationship resolution (genre, competition, venue, …)

    The shared ``_channels_cache`` and ``_cms_routes`` dicts are owned by the
    provider and passed in so the manager can look up channel names and pick
    the right route without coupling to the provider itself.
    """

    # Route preference order — first matching discovered route wins.
    # ``sport-schedule`` (paginated full schedule, ~300 events) is preferred
    # over ``sports`` (featured/current airings only, ~14 events).
    _EVENT_ROUTE_PREFERENCE: ClassVar[tuple] = (
        CMS_ROUTE_SPORT_SCHEDULE,   # "sport-schedule" — full paginated schedule
        CMS_ROUTE_SPORTS,           # "sports"         — featured airings only (fallback)
    )
    # Generic keyword scan used when neither preferred route is discovered
    _EVENT_ROUTE_KEYWORDS: ClassVar[tuple] = ("schedule", "sport", "live", "event")

    def __init__(self, provider, channels_cache: Dict, cms_routes: Dict):
        self._provider = provider
        self._channels_cache = channels_cache
        self._cms_routes = cms_routes

    # =========================================================================
    # Public interface
    # =========================================================================

    def fetch_events(
            self,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **kwargs,
    ) -> List[Event]:
        """
        Fetch events from the Discovery+ schedule.

        **Route selection** (no ``route_id`` kwarg supplied):
          Calls ``_select_event_route()`` which prefers a route discovered
          dynamically from the ``/home`` navigation graph (populated by
          ``get_channels()``).  Falls back to ``CMS_ROUTE_SPORT_SCHEDULE``
          if no suitable route is found.

        **Parse paths** (determined by the selected route's response shape):
          1. ``/sports`` — ``airing`` items appear directly in ``included``
             (fast path, ``_parse_airing_events()``).
          2. ``/sport-schedule`` — items are nested inside a collection
             (legacy fallback, ``_fetch_events_via_collection()``).
          The fast path is attempted first; if no ``airing`` items are found
          the method retries with ``CMS_ROUTE_SPORT_SCHEDULE``.

        Args:
            start_time: Optional start time filter.
            end_time: Optional end time filter.
            **kwargs: Additional parameters including:
                - route_id: Override the CMS route (bypasses dynamic selection).
                - page_size: Number of items per page (collection path only).

        Returns:
            List of Event objects.
        """
        events = []

        try:
            headers = self._provider.get_auth_headers()

            route_id = kwargs.get("route_id") or self._select_event_route()

            # Build the CMS route URL
            base_url = self._provider.authenticator.cms_home_endpoint
            if base_url.endswith("/home"):
                url = base_url.replace("/home", f"/{route_id}")
            else:
                url = (
                    f"https://default.any-{self._provider.authenticator.home_market}"
                    f".{self._provider.authenticator.env}.api.discoveryplus.com"
                    f"/cms/routes/{route_id}"
                )

            params = {
                "include": CMS_INCLUDE_PARAMS,
                "decorators": "viewingHistory,isFavorite,contentAction,badges",
                "page[items.size]": kwargs.get("page_size", 10),
            }
            if start_time:
                params["filter[from]"] = start_time.isoformat()
            if end_time:
                params["filter[to]"] = end_time.isoformat()

            logger.debug(f"Fetching events route: {url}")
            response = self._provider.http_manager.get(
                url,
                operation="cms",
                headers=headers,
                params=params,
            )
            response.raise_for_status()
            data = response.json()

            # ------------------------------------------------------------------
            # Fast path: /sports route returns airing items directly in included
            # ------------------------------------------------------------------
            airing_items = [
                item for item in data.get("included", [])
                if item.get("type") == AIRING_ITEM_TYPE
            ]

            if airing_items:
                logger.debug(
                    f"Found {len(airing_items)} airing items in /sports route — "
                    "using direct airing parse path"
                )
                events = self._parse_airing_events(
                    airing_items, start_time, end_time
                )
                logger.info(f"Found {len(events)} events (airing path)")
                return events

            # ------------------------------------------------------------------
            # Slow path: collection-based traversal (legacy /sport-schedule shape)
            # ------------------------------------------------------------------
            if route_id == CMS_ROUTE_SPORTS:
                logger.debug(
                    "No airing items on /sports route — falling back to "
                    f"/{CMS_ROUTE_SPORT_SCHEDULE} collection path"
                )
                return self.fetch_events(
                    start_time=start_time,
                    end_time=end_time,
                    route_id=CMS_ROUTE_SPORT_SCHEDULE,
                    **{k: v for k, v in kwargs.items() if k != "route_id"},
                )

            events = self._fetch_events_via_collection(
                data=data,
                headers=headers,
                start_time=start_time,
                end_time=end_time,
                **kwargs,
            )
            logger.info(f"Found {len(events)} events (collection path)")

        except Exception as e:
            logger.error(f"Error fetching events: {e}")

        return events

    # =========================================================================
    # Route selection
    # =========================================================================

    def _select_event_route(self) -> str:
        """
        Return the best event-producing CMS route from ``_cms_routes``.

        Preference order:
          1. ``CMS_ROUTE_SPORT_SCHEDULE`` — full paginated schedule (~300 events).
          2. ``CMS_ROUTE_SPORTS``         — featured/current airings only (~14).
          3. First discovered route matching a keyword in
             ``_EVENT_ROUTE_KEYWORDS`` (generic fallback for unknown layouts).
          4. ``CMS_ROUTE_SPORT_SCHEDULE`` hard-coded constant when
             ``_cms_routes`` is empty (e.g. ``get_channels()`` hasn't been
             called yet).
        """
        for preferred in self._EVENT_ROUTE_PREFERENCE:
            if preferred in self._cms_routes:
                logger.debug(
                    f"_select_event_route: selected preferred route '{preferred}'"
                )
                return preferred

        for keyword in self._EVENT_ROUTE_KEYWORDS:
            match = next(
                (r for r in self._cms_routes if keyword in r.lower()), None
            )
            if match:
                logger.debug(
                    f"_select_event_route: selected '{match}' via keyword '{keyword}'"
                )
                return match

        logger.debug(
            f"_select_event_route: no event route found in "
            f"{list(self._cms_routes.keys())!r}, "
            f"falling back to '{CMS_ROUTE_SPORT_SCHEDULE}'"
        )
        return CMS_ROUTE_SPORT_SCHEDULE

    # =========================================================================
    # Airing-based event parsing  (/sports route — fast path)
    # =========================================================================

    def _parse_airing_events(
            self,
            airing_items: List[Dict],
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
    ) -> List[Event]:
        """
        Parse a list of ``airing`` objects from the /sports CMS route into
        ``Event`` instances.

        The /sports route places ``airing`` items directly in the top-level
        ``included`` array.  Each airing carries:

        - ``attributes.scheduleStart / scheduleEnd``  — ISO-8601 UTC timestamps
        - ``attributes.name``                          — episode/event title
        - ``attributes.showName``                      — parent show name
        - ``attributes.description / secondaryTitle``  — optional metadata
        - ``attributes.episodeNumber / seasonNumber``  — episode metadata
        - ``relationships.badges``                     — live / up-next status
        - ``relationships.distributionChannel``        — links to channel cache

        Badge → EventStatus mapping:
          AIRING_BADGE_LIVE     ("live")                   → EventStatus.LIVE
          AIRING_BADGE_UP_NEXT  ("release-state-up-next")  → EventStatus.UPCOMING
          (fallback clock-based logic handles ENDED / LIVE for unlabelled items)

        Args:
            airing_items: List of airing dicts from ``data["included"]``.
            start_time:   Optional lower bound filter (inclusive).
            end_time:     Optional upper bound filter (inclusive).

        Returns:
            List of Event objects, optionally filtered by time window.
        """
        events: List[Event] = []
        now_utc = datetime.now(timezone.utc)

        for airing in airing_items:
            try:
                attributes = airing.get("attributes", {})
                relationships = airing.get("relationships", {})

                # ---- schedule times -----------------------------------------
                start_dt, end_dt = self._parse_schedule_times(attributes)

                # ---- optional caller-supplied time window filter -------------
                if start_time and end_dt and end_dt < start_time:
                    continue
                if end_time and start_dt and start_dt > end_time:
                    continue

                # ---- event status from badges --------------------------------
                status = self._resolve_badge_status(
                    relationships, now_utc, start_dt, end_dt
                )

                # ---- channel lookup -----------------------------------------
                channel_name: Optional[str] = None
                dist_channel_ref = (
                    relationships.get("distributionChannel", {}).get("data", {})
                )
                dist_channel_id = (
                    dist_channel_ref.get("id") if dist_channel_ref else None
                )
                if dist_channel_id:
                    cached = self._channels_cache.get(dist_channel_id)
                    if cached:
                        channel_name = cached.name
                    else:
                        logger.debug(
                            f"distributionChannel {dist_channel_id} not in cache "
                            f"for airing '{attributes.get('name')}'"
                        )

                # ---- build Event --------------------------------------------
                event = Event(
                    name=attributes.get("name", "Unknown Event"),
                    content_id=airing.get("id", ""),
                    provider=self._provider.provider_name,
                    logo_url=None,
                    mode="live" if status == EventStatus.LIVE else "vod",
                    session_manifest=False,
                    manifest_script=None,
                    cdm=None,
                    content_type="AIRING",
                    description=attributes.get("description", ""),
                    genre=None,
                    language="de",
                    country=self._provider.country.upper(),
                    start_time=start_dt,
                    end_time=end_dt,
                    status=status,
                    subtitle=attributes.get("secondaryTitle"),
                    original_name=attributes.get("showName"),
                    competition=None,
                    venue=None,
                    gender=None,
                    discipline=None,
                    age_category=None,
                    master_event=None,
                    channel=channel_name,
                )
                events.append(event)

            except Exception as e:
                logger.error(
                    f"Error processing airing item {airing.get('id')}: {e}"
                )
                continue

        return events

    # =========================================================================
    # Legacy collection-based event fetching  (/sport-schedule route)
    # =========================================================================

    def _fetch_events_via_collection(
            self,
            data: Dict,
            headers: Dict,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **kwargs,
    ) -> List[Event]:
        """
        Traverse the legacy collection-based CMS shape to extract events.

        This implements the original multi-hop traversal:
          route data → target page → page items → collection →
          paginated collection items → video attributes

        Args:
            data: Parsed JSON from the initial CMS route request.
            headers: Auth headers for subsequent requests.
            start_time: Optional lower bound filter.
            end_time: Optional upper bound filter.
            **kwargs: Forwarded kwargs (page_size, etc.).

        Returns:
            List of Event objects.
        """
        events: List[Event] = []

        included_by_id: Dict[str, Dict] = {
            f"{item.get('type')}:{item.get('id')}": item
            for item in data.get("included", [])
            if item.get("id") and item.get("type")
        }

        # Find the target page from the route
        route_data = data.get("data", {})
        target_ref = (
            route_data.get("relationships", {})
            .get("target", {})
            .get("data")
        )
        if not target_ref:
            logger.error(
                "No target page found in route response (collection path)"
            )
            return events

        page_key = f"{target_ref.get('type')}:{target_ref.get('id')}"
        page = included_by_id.get(page_key)
        if not page:
            logger.error(
                "Target page not found in included items (collection path)"
            )
            return events

        # Find the collection from page items
        page_items = (
            page.get("relationships", {}).get("items", {}).get("data", [])
        )
        collection_id = None
        for page_item_ref in page_items:
            page_item_key = (
                f"{page_item_ref.get('type')}:{page_item_ref.get('id')}"
            )
            page_item = included_by_id.get(page_item_key)
            if page_item:
                collection_ref = (
                    page_item.get("relationships", {})
                    .get("collection", {})
                    .get("data")
                )
                if collection_ref:
                    collection_id = collection_ref.get("id")
                    break

        if not collection_id:
            logger.error("No collection found in page (collection path)")
            return events

        # Paginate through the collection
        collection_url = (
            f"{self._provider.authenticator.cms_collections_endpoint}"
            f"/{collection_id}"
        )
        current_page = 1

        while True:
            collection_params = {
                "include": "default",
                "decorators": "viewingHistory,isFavorite,contentAction,badges",
                "page[items.size]": kwargs.get("page_size", 30),
                "page[items.number]": current_page,
            }

            logger.debug(
                f"Fetching schedule collection page {current_page}: "
                f"{collection_url}"
            )
            collection_response = self._provider.http_manager.get(
                collection_url,
                operation="cms",
                headers=headers,
                params=collection_params,
            )
            collection_response.raise_for_status()
            collection_data = collection_response.json()

            page_included: Dict[str, Dict] = {
                f"{item.get('type')}:{item.get('id')}": item
                for item in collection_data.get("included", [])
                if item.get("id") and item.get("type")
            }

            items = (
                collection_data.get("data", {})
                .get("relationships", {})
                .get("items", {})
                .get("data", [])
            )

            meta = collection_data.get("meta", {})
            total_pages = meta.get("itemsTotalPages", 1)
            logger.debug(
                f"Fetched collection page {current_page}/{total_pages} "
                f"({len(items)} items)"
            )

            for item_ref in items:
                try:
                    item_key = (
                        f"{item_ref.get('type')}:{item_ref.get('id')}"
                    )
                    collection_item = page_included.get(item_key)
                    if not collection_item:
                        continue

                    video_ref = (
                        collection_item.get("relationships", {})
                        .get("video", {})
                        .get("data")
                    )
                    if not video_ref:
                        continue

                    video_key = (
                        f"{video_ref.get('type')}:{video_ref.get('id')}"
                    )
                    video_data = page_included.get(video_key)
                    if not video_data:
                        continue

                    attributes = video_data.get("attributes", {})
                    relationships = video_data.get("relationships", {})

                    if attributes.get("materialType") != "EVENT":
                        continue

                    # ---- status from badges ----------------------------------
                    now_utc = datetime.now(timezone.utc)
                    status = EventStatus.SCHEDULED
                    badge_refs = relationships.get("badges", {}).get("data", [])
                    badge_ids = {b.get("id") for b in badge_refs}

                    if AIRING_BADGE_LIVE in badge_ids:
                        status = EventStatus.LIVE
                    elif (
                        AIRING_BADGE_UP_NEXT in badge_ids
                        or AIRING_BADGE_UPCOMING_LEGACY in badge_ids
                    ):
                        status = EventStatus.SCHEDULED

                    for badge_ref in badge_refs:
                        overlay_key = (
                            f"{badge_ref.get('type')}:{badge_ref.get('id')}"
                        )
                        overlay = page_included.get(overlay_key, {})
                        if overlay.get("id") == "live:default":
                            status = EventStatus.LIVE
                            break

                    # ---- schedule times -------------------------------------
                    start_dt, end_dt = self._parse_schedule_times(attributes)

                    # Clock-based status refinement
                    if status != EventStatus.LIVE and start_dt and end_dt:
                        _start = (
                            start_dt if start_dt.tzinfo
                            else start_dt.replace(tzinfo=timezone.utc)
                        )
                        _end = (
                            end_dt if end_dt.tzinfo
                            else end_dt.replace(tzinfo=timezone.utc)
                        )
                        if now_utc > _end:
                            status = EventStatus.ENDED
                        elif _start <= now_utc <= _end:
                            status = EventStatus.LIVE

                    # ---- logo -----------------------------------------------
                    logo_url = None
                    image_refs = relationships.get("images", {}).get("data", [])
                    if image_refs:
                        image_key = (
                            f"{image_refs[0].get('type')}:{image_refs[0].get('id')}"
                        )
                        image = page_included.get(image_key, {})
                        img_attrs = image.get("attributes", {})
                        logo_url = img_attrs.get("src") or img_attrs.get("url")

                    # ---- edit ID for streaming --------------------------------
                    edit_ref = (
                        relationships.get("edit", {}).get("data", {})
                    )
                    edit_id = edit_ref.get("id") if edit_ref else None

                    # ---- taxonomy lookups -----------------------------------
                    genre = self._resolve_taxonomy(
                        relationships, "txSports", page_included
                    )
                    competition = self._resolve_taxonomy(
                        relationships, "txCompetition", page_included
                    )
                    venue = self._resolve_taxonomy(
                        relationships, "txEvent", page_included
                    )
                    gender_val = self._resolve_taxonomy(
                        relationships, "txGender", page_included
                    )
                    gender = (
                        gender_val
                        if gender_val and gender_val != "."
                        else None
                    )
                    discipline_val = self._resolve_taxonomy(
                        relationships, "txDiscipline", page_included
                    )
                    discipline = (
                        discipline_val
                        if discipline_val and discipline_val != "."
                        else None
                    )
                    age_val = self._resolve_taxonomy(
                        relationships, "txAge", page_included
                    )
                    age_category = (
                        age_val if age_val and age_val != "." else None
                    )
                    master_event = self._resolve_taxonomy(
                        relationships, "txMaster-sporting-event", page_included
                    )

                    # ---- primary channel ------------------------------------
                    channel_name = None
                    channel_ref = (
                        relationships.get("primaryChannel", {}).get("data")
                    )
                    if channel_ref:
                        channel_key = (
                            f"{channel_ref.get('type')}:{channel_ref.get('id')}"
                        )
                        channel_node = page_included.get(channel_key, {})
                        channel_name = (
                            channel_node.get("attributes", {}).get("name")
                        )

                    # ---- language from audio tracks -------------------------
                    audio_tracks = attributes.get("audioTracks", [])
                    language = "de"
                    if audio_tracks:
                        if "Deutsch" in audio_tracks:
                            language = "de"
                        elif "Englisch" in audio_tracks:
                            language = "en"

                    event = Event(
                        name=attributes.get("name", "Unknown Event"),
                        content_id=video_data.get("id", ""),
                        provider=self._provider.provider_name,
                        logo_url=logo_url,
                        mode=(
                            "live"
                            if attributes.get("videoType") == "LIVE"
                            else "vod"
                        ),
                        session_manifest=True,
                        manifest_script=(
                            f"editid={edit_id}" if edit_id else None
                        ),
                        cdm=f"editid={edit_id}" if edit_id else None,
                        content_type="EVENT",
                        description=attributes.get("description", ""),
                        genre=genre,
                        language=language,
                        country=self._provider.country.upper(),
                        start_time=start_dt,
                        end_time=end_dt,
                        status=status,
                        subtitle=attributes.get("secondaryTitle"),
                        original_name=attributes.get("originalName"),
                        competition=competition,
                        venue=venue,
                        gender=gender,
                        discipline=discipline,
                        age_category=age_category,
                        master_event=master_event,
                        channel=channel_name,
                    )
                    events.append(event)

                except Exception as e:
                    logger.error(f"Error processing collection item: {e}")
                    continue

            if current_page >= total_pages:
                break
            current_page += 1

        return events

    # =========================================================================
    # Shared parsing helpers
    # =========================================================================

    @staticmethod
    def _parse_schedule_times(
            attributes: Dict,
    ):
        """
        Extract and parse scheduleStart / scheduleEnd from an attributes dict.

        Returns:
            Tuple of (start_dt, end_dt), either of which may be None.
        """
        start_dt: Optional[datetime] = None
        end_dt: Optional[datetime] = None

        for attr_key, target in (
            ("scheduleStart", "start_dt"),
            ("scheduleEnd", "end_dt"),
        ):
            raw = attributes.get(attr_key)
            if raw:
                try:
                    parsed = datetime.fromisoformat(
                        raw.replace("Z", "+00:00")
                    )
                    if target == "start_dt":
                        start_dt = parsed
                    else:
                        end_dt = parsed
                except (ValueError, TypeError):
                    pass

        return start_dt, end_dt

    @staticmethod
    def _resolve_badge_status(
            relationships: Dict,
            now_utc: datetime,
            start_dt: Optional[datetime],
            end_dt: Optional[datetime],
    ) -> EventStatus:
        """
        Derive EventStatus from badge relationships, falling back to clock logic.

        Badge priority: explicit "live" wins over "up-next"; clock-based logic
        is applied when neither badge is present.
        """
        badge_refs = relationships.get("badges", {}).get("data", [])
        badge_ids = {b.get("id") for b in badge_refs}

        if AIRING_BADGE_LIVE in badge_ids:
            return EventStatus.LIVE
        if (
            AIRING_BADGE_UP_NEXT in badge_ids
            or AIRING_BADGE_UPCOMING_LEGACY in badge_ids
        ):
            return EventStatus.SCHEDULED

        if start_dt and end_dt:
            _start = (
                start_dt if start_dt.tzinfo
                else start_dt.replace(tzinfo=timezone.utc)
            )
            _end = (
                end_dt if end_dt.tzinfo
                else end_dt.replace(tzinfo=timezone.utc)
            )
            if now_utc > _end:
                return EventStatus.ENDED
            if _start <= now_utc <= _end:
                return EventStatus.LIVE

        return EventStatus.SCHEDULED

    @staticmethod
    def _resolve_taxonomy(
            relationships: Dict,
            key: str,
            included: Dict,
    ) -> Optional[str]:
        """
        Resolve a single taxonomy relationship to its ``attributes.name`` value.

        Args:
            relationships: The ``relationships`` dict from a video/event item.
            key: Relationship key, e.g. ``"txSports"``, ``"txCompetition"``.
            included: Per-page included lookup (``type:id`` → item).

        Returns:
            The ``attributes.name`` string, or ``None`` if not found.
        """
        refs = relationships.get(key, {}).get("data", [])
        if not refs:
            return None
        ref = refs[0]
        node = included.get(f"{ref.get('type')}:{ref.get('id')}", {})
        return node.get("attributes", {}).get("name")