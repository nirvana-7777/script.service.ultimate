# streaming_providers/providers/movetv/epg_manager.py
"""
EPG (Electronic Programme Guide) manager for the move.tv / MTS-SI provider.

Design notes
------------
* Uses the provider's existing ``http_manager`` (via the authenticator) so
  that proxy settings, retries, and session-level headers are all inherited —
  NOT a bare ``requests.post`` call.
* Calls ``authenticator.authenticate()`` before every request so an expired
  or missing token is refreshed transparently (same pattern used by
  vod_manager.py and the live-channel fetcher).
* Timestamps are converted to UTC-aware ``datetime`` objects and formatted as
  ISO-8601 strings so downstream consumers never have to guess the timezone.
* All constants (URL, partner ID, app version, timeout) come from
  ``MoveTVConfig`` — no magic strings here.
* Time-window translation: accepts either the generic (start_time, end_time)
  contract used by EPGOperations/EPGManager, or the native (backwards,
  forwards) shorthand used by the MoveTV API directly.  Translation happens
  here so no other layer needs to know about the API's hour-relative model.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ...base.utils.logger import logger
from ...base.models.epg_models import EPGEntry, EPGFlags
from .constants import MoveTVConfig


class MoveTvEpgManager:
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
        title (raw, S/E)  -> episode_name (only when season/episode parsed)
        originalTitle     -> original_title
        epgDesc           -> description
        start / end (ms)  -> start / end (seconds)
        tagInfo.name      -> genre_description
        director          -> directors (single-item list)
        actor             -> cast (list, comma-split)
        year              -> year
        rating            -> star_rating
        picture.background-> icon
        season/episode    -> season_number / episode_number (+ IS_SERIES flag)

    Known lossy fields
    ------------------
    EPGEntry has no slots for: schedule_id, live_id, live_name, content_id,
    producer, multiple categories/category_ids/category_images, genre_id,
    or the secondary images (poster, square_logo, poster_mark,
    original_title_logo). These were present in the old dict-based return
    value and are now dropped. Confirm nothing else in the MoveTV pipeline
    (e.g. catchup/manifest matching) reads those keys before relying on
    this contract.
    """

    def __init__(self, authenticator: Any) -> None:
        """
        Parameters
        ----------
        authenticator:
            A ``MoveTVAuthenticator`` instance.  Must expose:
            - ``authenticate() -> MoveTVAuthToken``
            - ``get_session_info() -> Optional[Dict]``
            - ``http_manager`` (the shared ``HTTPManager`` instance)
        """
        self._auth = authenticator

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_channel_epg(
        self,
        channel_id: str,
        # Native form — passed directly to the API
        backwards: int = 2,
        forwards: int = 2,
        # Generic form — EPGOperations passes these via **kwargs.
        # When provided they take precedence and are translated to
        # backwards/forwards internally so nothing else has to change.
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        # Absorb any other kwargs forwarded by EPGOperations / provider.get_epg()
        # so we never raise on unknown arguments.
        **_kwargs: Any,
    ) -> List[EPGEntry]:
        """
        Fetch the EPG schedule for a single live channel.

        Accepts two calling conventions — use whichever the caller has:

        Generic (EPGOperations contract):
            get_channel_epg(channel_id, start_time=<datetime>, end_time=<datetime>)
            The absolute window is translated to the API's backwards/forwards
            hour offsets anchored to the window midpoint.

        Native (MoveTV shorthand):
            get_channel_epg(channel_id, backwards=2, forwards=4)
            Passed straight through; start_time/end_time must be None.

        Parameters
        ----------
        channel_id:
            The provider's numeric content ID for the channel (as a string).
        backwards:
            Hours of past programming to include (API default: 2).
            Ignored when start_time/end_time are provided.
        forwards:
            Hours of future programming to include (API default: 2).
            Ignored when start_time/end_time are provided.
        start_time:
            Inclusive window start (timezone-aware or naive-local datetime).
            When provided together with end_time, takes precedence over
            backwards/forwards.
        end_time:
            Inclusive window end (timezone-aware or naive-local datetime).
            When provided together with start_time, takes precedence over
            backwards/forwards.

        Returns
        -------
        List of EPGEntry objects (see ``_parse_items``), or an empty list
        on any error or for items that fail EPGEntry validation.
        """
        # ----------------------------------------------------------------
        # Step 1 — resolve the time anchor and API window parameters
        # ----------------------------------------------------------------
        anchor_utc, backwards, forwards = self._resolve_window(
            start_time, end_time, backwards, forwards
        )

        # ----------------------------------------------------------------
        # Step 2 — authenticate (no-op when token is fresh)
        # ----------------------------------------------------------------
        try:
            self._auth.authenticate()
        except Exception as exc:
            logger.error(f"MoveTV EPG: Authentication failed — {exc}")
            return []

        session = self._auth.get_session_info()
        if not session:
            logger.error(
                "MoveTV EPG: get_session_info() returned None after successful authenticate()"
            )
            return []

        customer_id = session.get("customer_id")
        auth_token  = session.get("auth_token")

        if not customer_id or not auth_token:
            logger.error(
                f"MoveTV EPG: Incomplete session — "
                f"customer_id={customer_id!r}, "
                f"auth_token={'set' if auth_token else 'missing'}"
            )
            return []

        # ----------------------------------------------------------------
        # Step 3 — build and fire the request
        # ----------------------------------------------------------------
        now_ms = int(anchor_utc.timestamp() * 1000)

        payload: Dict[str, Any] = {
            "customerId": customer_id,
            "partnerId":  MoveTVConfig.PARTNER_ID,
            "contentId":  int(channel_id),
            "time":       now_ms,
            "backwards":  backwards,
            "forwards":   forwards,
            "appVersion": MoveTVConfig.APP_VERSION,
        }
        headers = MoveTVConfig.get_api_headers(auth_token)
        url     = MoveTVConfig.epg_all_url()

        logger.debug(
            f"MoveTV EPG: Fetching channel_id={channel_id} "
            f"anchor={anchor_utc.isoformat()} "
            f"(backwards={backwards}h, forwards={forwards}h)"
        )

        try:
            response = self._auth.http_manager.post(
                url,
                json=payload,
                headers=headers,
                timeout=MoveTVConfig.TIMEOUT,
            )
            response.raise_for_status()
        except Exception as exc:
            logger.error(
                f"MoveTV EPG: Request failed for channel {channel_id} — {exc}"
            )
            return []

        # Decode JSON separately so a missing / malformed body doesn't
        # collapse into a silent "Request failed" that hides the real cause.
        try:
            data: Dict[str, Any] = response.json()
        except Exception as exc:
            logger.error(
                f"MoveTV EPG: Failed to decode JSON response for channel "
                f"{channel_id} — {exc} "
                f"(HTTP {response.status_code}, body={response.text[:200]!r})"
            )
            return []

        # The API may return a 200 with success=false, or (rarely) a null body
        # parsed as None.  Guard both cases before calling .get() on data.
        if data is None:
            logger.error(
                f"MoveTV EPG: API returned null/empty JSON body for channel {channel_id}"
            )
            return []

        if not data.get("success"):
            logger.warning(
                f"MoveTV EPG: API returned success=false for channel "
                f"{channel_id}: {data}"
            )
            return []

        items = data.get("content", [])
        logger.debug(
            f"MoveTV EPG: Received {len(items)} programme(s) for channel {channel_id}"
        )
        return self._parse_items(items, channel_id)

    def get_channels_epg(
        self,
        channel_ids: List[str],
        backwards: int = 2,
        forwards: int = 2,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, List[EPGEntry]]:
        """
        Convenience wrapper: fetch EPG for multiple channels.

        Returns a dict keyed by channel_id, each value a list of EPGEntry
        objects. Missing / failed channels are present with an empty list
        so callers don't have to guard KeyError.
        """
        result: Dict[str, List[EPGEntry]] = {}
        for cid in channel_ids:
            result[cid] = self.get_channel_epg(
                cid,
                backwards=backwards,
                forwards=forwards,
                start_time=start_time,
                end_time=end_time,
            )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

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
            backwards = 0
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
                f"backwards=0 forwards={forwards}h"
            )
            return anchor_utc, 0, forwards

        if end_time is not None:
            anchor_utc = _to_utc(end_time)
            logger.debug(
                f"MoveTV EPG: end_time only — anchor={anchor_utc.isoformat()} "
                f"backwards={backwards}h forwards=0"
            )
            return anchor_utc, backwards, 0

        # Native backwards/forwards — anchor to now
        return datetime.now(tz=timezone.utc), backwards, forwards

    def _parse_items(
        self, items: List[Dict[str, Any]], channel_id: str
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
                    episode_name=raw_title if season_num else None,
                    original_title=item.get("originalTitle"),
                    year=item.get("year"),
                    icon=icon,
                    cast=cast,
                    directors=[item["director"]] if item.get("director") else [],
                    genre_description=(item.get("tagInfo") or {}).get("name"),
                    season_number=season_num,
                    episode_number=episode_num,
                    star_rating=item.get("rating") or None,
                )

                if season_num is not None:
                    entry.set_flag(EPGFlags.IS_SERIES)

                parsed.append(entry)

            except Exception as exc:
                logger.warning(f"MoveTV EPG: Error parsing item: {exc} — {item}")
                continue

        return parsed