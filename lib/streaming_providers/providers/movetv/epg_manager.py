# streaming_providers/providers/movetv/epg_manager.py
"""
EPG (Electronic Programme Guide) manager for the move.tv / MTS-SI provider.

Design notes
------------
* An EpgManager subclass (README §6.3): the four standard collaborators, the
  shared HTTP manager and the session (`auth`); no reference to the provider or
  the raw authenticator.
* Requests go through `api_post` (one 401 recovery, typed errors): a failed
  request RAISES instead of returning [] (v1 behaviour). "No programmes"
  (success=false, empty content) is still a valid empty result.
* get_epg accepts the generic form (start_time/end_time datetimes, as passed by
  EPGOperations) and the native form (backwards=/forwards= hours in **kw).
  EPGOperations also passes `limit=`; like v1 it is ignored.
* The v1 helper `get_channels_epg` (no callers) is gone; `get_epg_grid` is the
  batch entry point.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ...base.errors import AuthError, GeoBlockError, ProviderError, RateLimitError
from ...base.managers import EpgManager
from ...base.models.epg_models import EPGEntry, EPGFlags
from ...base.utils.logger import logger
from .api import api_post
from .constants import MoveTVConfig
from .ids import is_live_id, parse_live_id


class MoveTvEpgManager(EpgManager):
    """
    Fetches and normalises EPG data from the MoveTV API into EPGEntry
    objects (the same typed contract used by EPGOperations and the other
    providers — see streaming_providers/base/models/epg_models.py).

    Field mapping from the raw MoveTV API payload onto EPGEntry:

        epgId            -> program_id, and broadcast_id when > 0
                             (falls back to EPGEntry.encode_broadcast_id()
                             so the provider can still be recovered from
                             the broadcast_id alone for catchup lookups)
        title (cleaned)   -> title
        (raw title's S/E marker is now fully captured by season_number/
        episode_number below, so episode_name is left None — MoveTV
        doesn't provide a distinct episode subtitle)
        originalTitle     -> original_title
        epgDesc           -> description
        start / end (ms)  -> start / end (seconds)
        tagInfo.name      -> genre_description
        categories[].name -> genres (list)
        director          -> directors (single-item list)
        actor             -> cast (list, comma-split)
        producer          -> producers (list, comma-split)
        year              -> year
        rating            -> parental_rating (age/content classification,
                             e.g. 12, 0=unrestricted — not a 0-10 star score)
        picture.background-> icon
        season/episode    -> season_number / episode_number (+ IS_SERIES flag)

    Known lossy fields
    ------------------
    EPGEntry has no slots for: schedule_id, live_id, live_name, content_id,
    category_ids, category_images/genre_id (per-category numeric IDs and
    their picture objects — always null in observed data), or the
    secondary images (poster, square_logo, poster_mark,
    original_title_logo) — confirmed always null in observed MoveTV
    responses, so not wired up. These were present in the old dict-based
    return value and are now dropped. Confirm nothing else in the MoveTV
    pipeline (e.g. catchup/manifest matching) reads those keys before
    relying on this contract.
    """


    # ------------------------------------------------------------------
    # Capability
    # ------------------------------------------------------------------
    @property
    def epg_window(self) -> Tuple[int, int]:
        """(past_days, future_days) -- same as v1."""
        return self.config.EPG_WINDOW_DAYS

    def handles_channel_id(self, channel_id: str) -> bool:
        return is_live_id(channel_id)

    # ------------------------------------------------------------------
    # EPG
    # ------------------------------------------------------------------
    def get_epg(
        self,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kw: Any,
    ) -> List[EPGEntry]:
        """
        Fetch the EPG schedule for ONE live channel.

        Generic form: start_time/end_time (aware or naive-local datetimes) are
        translated to the API's backwards/forwards hour offsets around the
        window midpoint. Native form: backwards=/forwards= (hours, default 2)
        in **kw, anchored at start_time (or now). Other kwargs (limit=, ...)
        are ignored.

        Returns [] when the API has no data; raises typed errors on failures.
        """
        backwards = int(kw.get("backwards", self.config.EPG_DEFAULT_BACKWARDS_HOURS))
        forwards = int(kw.get("forwards", self.config.EPG_DEFAULT_FORWARDS_HOURS))
        content_id = parse_live_id(channel_id)          # BadRequestError if malformed
        anchor_utc, backwards, forwards = self._resolve_window(
            start_time, end_time, backwards, forwards
        )
        now_ms = int(anchor_utc.timestamp() * 1000)

        logger.debug(
            f"MoveTV EPG: Fetching channel_id={channel_id} "
            f"anchor={anchor_utc.isoformat()} "
            f"(backwards={backwards}h, forwards={forwards}h)"
        )
        data = api_post(
            self.http_manager, self.auth, self.config.epg_all_url(),
            lambda info: {
                "customerId": info["customer_id"],
                "partnerId": self.config.PARTNER_ID,
                "contentId": content_id,
                "time": now_ms,
                "backwards": backwards,
                "forwards": forwards,
                "appVersion": self.config.APP_VERSION,
            },
            what=f"EPG for channel {channel_id}", operation="api", need_profile=False,
        )
        if not data.get("success"):
            logger.warning(
                f"MoveTV EPG: API returned success=false for channel {channel_id}: {data}"
            )
            return []

        items = data.get("content") or []
        logger.debug(f"MoveTV EPG: Received {len(items)} programme(s) for channel {channel_id}")
        return self._parse_items(items, channel_id)

    def get_epg_grid(
        self,
        channel_ids: List[str],
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kw: Any,
    ) -> Dict[str, List[EPGEntry]]:
        """Batch EPG: one request per channel (no native batch endpoint).

        Auth / rate-limit / geo errors abort the whole grid (they hit every
        channel alike); any other failure of ONE channel yields [] for it, so
        one bad channel cannot take the grid down."""
        result: Dict[str, List[EPGEntry]] = {}
        for cid in channel_ids:
            if not self.handles_channel_id(cid):
                result[cid] = []
                continue
            try:
                result[cid] = self.get_epg(cid, start_time=start_time, end_time=end_time, **kw)
            except (AuthError, RateLimitError, GeoBlockError):
                raise
            except ProviderError as exc:
                logger.warning(f"MoveTV EPG: channel {cid} skipped in grid: {exc}")
                result[cid] = []
        return result

    @staticmethod
    def _resolve_window(
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        backwards: int,
        forwards: int,
    ) -> Tuple[datetime, int, int]:
        """
        Resolve the API anchor timestamp and hour offsets from whichever
        calling convention the caller used.

        The MoveTV API expects:
            time      — epoch-ms anchor point (we send UTC now or midpoint)
            backwards — integer hours before 'time' to include
            forwards  — integer hours after  'time' to include

        Translation rules
        -----------------
        Both start_time and end_time given:
            anchor    = midpoint of the window
            backwards = ceil(hours from anchor back to start_time)
            forwards  = ceil(hours from anchor forward to end_time)
            → The window the API returns will exactly cover [start_time, end_time].

        Only start_time given:
            anchor    = start_time
            backwards = backwards (caller's value, default 2)
            forwards  = forwards (caller's value, default 2)

        Only end_time given:
            anchor    = end_time
            backwards = backwards (caller's value, default 2)
            forwards  = 0

        Neither given (native backwards/forwards call):
            anchor    = utcnow()
            backwards/forwards passed through unchanged

        In all cases the anchor is normalised to UTC.

        Returns
        -------
        (anchor_utc, backwards, forwards)
        """
        def _to_utc(dt: datetime) -> datetime:
            """Attach UTC if naive, otherwise convert.

            Also accepts int/float values and treats them as Unix epoch
            seconds (or milliseconds when the value is clearly too large
            to be a seconds-since-1970 timestamp, i.e. > year 3000).
            """
            if isinstance(dt, (int, float)):
                # Heuristic: epoch-ms values are ~1 000× larger than epoch-s.
                # Year 3000 in epoch-s ≈ 32 503 680 000 — use that as the
                # cutoff to auto-detect milliseconds.
                ts = dt / 1000 if dt > 32_503_680_000 else dt
                return datetime.fromtimestamp(ts, tz=timezone.utc)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)

        if start_time is not None and end_time is not None:
            start_utc = _to_utc(start_time)
            end_utc   = _to_utc(end_time)

            if end_utc <= start_utc:
                logger.warning(
                    "MoveTV EPG: end_time is not after start_time — "
                    "falling back to defaults"
                )
                return datetime.now(tz=timezone.utc), backwards, forwards

            half_seconds = (end_utc - start_utc).total_seconds() / 2
            anchor_utc   = start_utc + (end_utc - start_utc) / 2
            backwards    = math.ceil(half_seconds / 3600)
            forwards     = backwards  # symmetric around midpoint

            logger.debug(
                f"MoveTV EPG: Translated start/end window "
                f"({start_utc.isoformat()} → {end_utc.isoformat()}) "
                f"to anchor={anchor_utc.isoformat()} "
                f"backwards={backwards}h forwards={forwards}h"
            )
            return anchor_utc, backwards, forwards

        if start_time is not None:
            anchor_utc = _to_utc(start_time)
            logger.debug(
                f"MoveTV EPG: start_time only — anchor={anchor_utc.isoformat()} "
                f"backwards={backwards}h forwards={forwards}h"
            )
            return anchor_utc, backwards, forwards

        if end_time is not None:
            anchor_utc = _to_utc(end_time)
            logger.debug(
                f"MoveTV EPG: end_time only — anchor={anchor_utc.isoformat()} "
                f"backwards={backwards}h forwards=0"
            )
            return anchor_utc, backwards, 0

        # Native backwards/forwards — anchor to now
        return datetime.now(tz=timezone.utc), backwards, forwards

    @staticmethod
    def _parse_items(
        items: List[Dict[str, Any]], channel_id: str
    ) -> List[EPGEntry]:
        """
        Normalise raw API programme objects into EPGEntry objects.

        channel_id is needed (in addition to each item's own fields) only
        as a fallback input to EPGEntry.encode_broadcast_id() for items
        that arrive without a usable epgId.

        Items that are missing start/end, or that fail EPGEntry's own
        validation (e.g. empty title after season/episode stripping), are
        logged and skipped rather than raising — matching the previous
        "skip and continue" behaviour for malformed entries.
        """
        import re

        parsed: List[EPGEntry] = []

        for item in items:
            start_ms: Optional[int] = item.get("start")
            end_ms: Optional[int] = item.get("end")

            if not start_ms or not end_ms:
                continue

            start_s = start_ms // 1000
            end_s = end_ms // 1000

            try:
                # ------------------------------------------------------------
                # Cast (split by comma)
                # ------------------------------------------------------------
                actor_raw: Optional[str] = item.get("actor")
                cast: List[str] = (
                    [a.strip() for a in actor_raw.split(",") if a.strip()]
                    if actor_raw
                    else []
                )

                producer_raw: Optional[str] = item.get("producer")
                producers: List[str] = (
                    [p.strip() for p in producer_raw.split(",") if p.strip()]
                    if producer_raw
                    else []
                )

                categories_raw: List[Dict[str, Any]] = item.get("categories") or []
                genres: List[str] = [
                    c["name"] for c in categories_raw if c.get("name")
                ]

                # ------------------------------------------------------------
                # Parse season and episode from title.
                # Supports multiple patterns:
                # - "Title S6:E2" (most common)
                # - "Title S6E2"
                # - "Title S6 E2"
                # - "Title (S6, E2)"
                # - "Title - Season 6 Episode 2"
                # ------------------------------------------------------------
                raw_title = item.get("title", "")
                title = raw_title
                season_num = None
                episode_num = None

                match = re.search(r'S(\d+):E(\d+)', title, re.IGNORECASE)
                if not match:
                    match = re.search(r'S(\d+)E(\d+)', title, re.IGNORECASE)
                if not match:
                    match = re.search(r'S(\d+)\s+E(\d+)', title, re.IGNORECASE)
                if not match:
                    match = re.search(r'\(S(\d+)[,\s]+E(\d+)\)', title, re.IGNORECASE)
                if not match:
                    match = re.search(
                        r'Season\s+(\d+)\s+Episode\s+(\d+)', title, re.IGNORECASE
                    )

                if match:
                    season_num = int(match.group(1))
                    episode_num = int(match.group(2))
                    title = re.sub(r'\s*S\d+:[Ee]\d+\s*', '', title)
                    title = re.sub(r'\s*S\d+[Ee]\d+\s*', '', title)
                    title = re.sub(r'\s*\(S\d+[,\s]+E\d+\)\s*', '', title)
                    title = re.sub(r'\s*Season\s+\d+\s+Episode\s+\d+\s*', '', title)
                    title = title.strip()

                # ------------------------------------------------------------
                # Images — only "background" maps onto EPGEntry.icon; the
                # other picture variants (poster, square_logo, poster_mark,
                # original_title_logo) have no EPGEntry field and are lost.
                # ------------------------------------------------------------
                picture = item.get("picture") or {}
                icon = MoveTVConfig.build_image_url(picture.get("background"))

                # ------------------------------------------------------------
                # Broadcast ID — prefer the API's own epgId (stable across
                # requests); fall back to the canonical provider-aware
                # encoder so catchup code can still recover the provider
                # from the broadcast_id alone (see EPGEntry.encode_broadcast_id
                # / get_provider_hash docs in epg_models.py).
                # ------------------------------------------------------------
                epg_id_raw = item.get("epgId")
                broadcast_id = (
                    int(epg_id_raw)
                    if epg_id_raw and int(epg_id_raw) > 0
                    else EPGEntry.encode_broadcast_id(
                        "movetv", channel_id, start_s
                    )
                )

                entry = EPGEntry(
                    broadcast_id=broadcast_id,
                    title=title,
                    start=start_s,
                    end=end_s,
                    program_id=str(epg_id_raw) if epg_id_raw else None,
                    description=item.get("epgDesc"),
                    episode_name=None,
                    original_title=item.get("originalTitle"),
                    year=item.get("year"),
                    icon=icon,
                    cast=cast,
                    directors=[item["director"]] if item.get("director") else [],
                    producers=producers,
                    genre_description=(item.get("tagInfo") or {}).get("name"),
                    genres=genres,
                    season_number=season_num,
                    episode_number=episode_num,
                    parental_rating=item.get("rating") or None,
                )

                if season_num is not None:
                    entry.set_flag(EPGFlags.IS_SERIES)

                parsed.append(entry)

            except Exception as exc:
                logger.warning(f"MoveTV EPG: Error parsing item: {exc} — {item}")
                continue

        return parsed