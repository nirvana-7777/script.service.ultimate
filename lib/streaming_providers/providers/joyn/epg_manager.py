# streaming_providers/providers/joyn/epg_manager.py
# -*- coding: utf-8 -*-
"""
Joyn EPG Manager.

Fetches the channel list + EPG in one operation (`LiveChannelsAndEpg` — the
same one the channel manager uses), parses the `epgEvents` into EPGEntry
objects, and answers the ABC methods (get_epg, get_epg_grid,
get_program_details).

Why reuse `LiveChannelsAndEpg` and not a dedicated EPG operation:
  * It is the only EPG operation we have a captured hash for. The other
    two operations in the captures (LivestreamIdByBrand, LivestreamOverview)
    return EPG ids *without* the program fields (title, start, end), so they
    cannot produce EPGEntry by themselves — they would need a third "get
    EpgEntry by id" query that we do not have a hash for.
  * It is what the reference client itself uses to render the EPG grid.
  * It works anonymously (A_A) and authenticated (R_A); the manager uses
    `auth.ensure()` so it degrades gracefully when no session is available
    (see the channel_manager docstring for the same reasoning).

epg_window
----------
The captured response for a channel spans roughly one day of events
regardless of the requested `from`/`to` window: the server pads a short
window with more events. We declare `(0, 1)` — today plus tomorrow — which
is what the response reliably covers. The window is a declaration of what
we can deliver, not an aspiration.

program_id / epg_event_id
-------------------------
Joyn sends exactly one identifier per event (`program.id`, e.g.
"stv-25_58385168525_1791700800000_..."), and it encodes both the channel
and the broadcast slot in the string itself. There is no separate
"listing guid" as Magenta2 has. EPGEntry has two slots for providers that
distinguish them; Joyn does not, so:
  * program_id  = the Joyn program.id  (this is what the provider's own
                  operations accept back)
  * epg_event_id = None                (see the EPGEntry docstring: "leave
                  as None for providers where no such distinction exists")
"""

import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from ...base.managers import EpgManager
from ...base.models.epg_models import (
    EPGEntry,
    EPGFlags,
    EPGProgramDetails,
)
from ...base.utils.logger import logger
from ...base.utils.transport import transport_errors
from .constants import (
    DEFAULT_LIVESTREAM_TYPES,
    DEFAULT_REQUEST_TIMEOUT,
    GRAPHQL_LIVE_CHANNELS_FILTER,
    GRAPHQL_MAX_RESULTS,
    GRAPHQL_OFFSET,
    MODE_LIVE,
    PROVIDER_NAME,
)
from .graphql import build_url

_PROVIDER = "Joyn"

# How far the cached channel+EPG listing is reused before we refetch.
# The listing's own server-side cache is ~50s; a slightly longer local TTL
# avoids hammering the API on a grid scroll without giving stale data.
_EPG_CACHE_TTL = 120.0


class JoynEpgManager(EpgManager):
    def __init__(
        self,
        *,
        http_manager: Any,
        auth: Any,
        country: str,
        config: Any,
    ):
        super().__init__(
            http_manager=http_manager, auth=auth, country=country, config=config
        )
        # {channel_id: [EPGEntry, ...]} plus the timestamp of the fetch
        # that produced it. Populated lazily by _all_epg().
        self._epg_by_channel: Optional[Dict[str, List[EPGEntry]]] = None
        self._epg_fetched_at: float = 0.0

    # ------------------------------------------------------------------
    # Capability / routing
    # ------------------------------------------------------------------

    @property
    def epg_window(self) -> Tuple[int, int]:
        # Past 0 days (Joyn's EPG is not historical), future 1 day (what
        # LiveChannelsAndEpg reliably returns per channel).
        return 0, 1

    def handles_channel_id(self, channel_id: str) -> bool:
        # Every channel that appears in get_channels can appear in the EPG.
        # The ABC default is `True`; overriding to document the intent.
        return True

    # ------------------------------------------------------------------
    # Public API — ABC methods
    # ------------------------------------------------------------------

    def get_epg(
        self,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kw: Any,
    ) -> List[EPGEntry]:
        events = self._all_epg().get(channel_id, [])
        return self._filter(events, start_time, end_time, kw.get("limit"))

    def get_epg_grid(
        self,
        channel_ids: List[str],
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kw: Any,
    ) -> Dict[str, List[EPGEntry]]:
        """
        Batch override. LiveChannelsAndEpg returns every channel in one
        response, so this is one query for all requested channels, not N
        queries via the ABC default (which would loop get_epg).
        """
        all_events = self._all_epg()
        limit = kw.get("limit")
        return {
            cid: self._filter(all_events.get(cid, []), start_time, end_time, limit)
            for cid in channel_ids
        }

    def get_program_details(
        self, program_id: str, **kw: Any
    ) -> Optional[EPGProgramDetails]:
        """
        Cache-search over the last fetched EPG. Joyn gives us one program id
        per event and no dedicated "get details by id" operation that we have
        a hash for, so the only source of truth available is the schedule we
        already parsed.

        Returns None if the program id is not in the current cache — the
        ABC permits this (the caller treats it as "no enrichment available").
        """
        for events in self._all_epg().values():
            for entry in events:
                if entry.program_id == program_id:
                    return self._details_from_entry(entry)
        return None

    # ------------------------------------------------------------------
    # Fetch and parse
    # ------------------------------------------------------------------

    def _all_epg(self) -> Dict[str, List[EPGEntry]]:
        """
        Fetch the channel list with EPG (LiveChannelsAndEpg) and parse it
        into {channel_id: [EPGEntry]}. Cached for _EPG_CACHE_TTL seconds;
        a second call within the TTL reuses the previous result.
        """
        now = time.time()
        if self._epg_by_channel is not None and (now - self._epg_fetched_at) < _EPG_CACHE_TTL:
            return self._epg_by_channel

        streams = self._fetch_live_streams()
        by_channel: Dict[str, List[EPGEntry]] = {}
        for stream in streams:
            cid = stream.get("id")
            if not cid:
                continue
            is_live = stream.get("type") == "LINEAR"
            events: List[EPGEntry] = []
            for ev in stream.get("epgEvents") or []:
                entry = self._parse_event(cid, ev, is_live)
                if entry is not None:
                    events.append(entry)
            # Sort by start; the API is usually already sorted but we do not
            # rely on it.
            events.sort(key=lambda e: e.start)
            by_channel[cid] = events

        self._epg_by_channel = by_channel
        self._epg_fetched_at = now
        logger.info(
            f"{_PROVIDER}: EPG fetched for {len(by_channel)} channels "
            f"({sum(len(v) for v in by_channel.values())} events)"
        )
        return by_channel

    def _fetch_live_streams(self) -> List[Dict[str, Any]]:
        """
        One GraphQL call, same operation the channel manager uses. The
        window matches the channel manager's (now .. now + 3h) — the
        server pads it, and the parsed events carry their own start/end,
        so a wider `to` would not give us more events per channel.
        """
        now_ts = int(time.time())
        variables = {
            "liveStreamGroupFilter": GRAPHQL_LIVE_CHANNELS_FILTER,
            "first": GRAPHQL_MAX_RESULTS,
            "offset": GRAPHQL_OFFSET,
            "livestreamTypes": DEFAULT_LIVESTREAM_TYPES,
            "from": now_ts,
            "to": now_ts + 3 * 3600,
        }
        url = build_url("LIVE_CHANNELS", variables)

        # EPG is served anonymously; use ensure() so a broken or absent
        # session does not block a public channel listing.
        token = None
        if self.auth.ensure():
            token = self.auth.get_access_token()
        headers = self.config.graphql_headers(
            token=token, authenticated=token is not None
        )

        with transport_errors("epg_fetch", _PROVIDER):
            response = self.http_manager.get(
                url,
                operation="api",
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
        return (data.get("data") or {}).get("liveStreams") or []

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse_event(
        self, channel_id: str, ev: Dict[str, Any], is_live_stream: bool
    ) -> Optional[EPGEntry]:
        """
        Turn one `epgEvents[]` item into an EPGEntry.

        Joyn's event wrapper sometimes carries start/end on the wrapper and
        sometimes on the embedded `program` (it varies by __typename), so
        both are checked. A missing required field returns None and the
        event is skipped — one bad event must not fail the whole listing
        (README §12.5).
        """
        program = ev.get("program") or {}
        start = program.get("startDate") or ev.get("startDate")
        end = program.get("endDate") or ev.get("endDate")
        program_id = program.get("id")
        title = program.get("title")
        if not (program_id and title and start and end):
            return None

        try:
            start_i = int(start)
            end_i = int(end)
        except (TypeError, ValueError):
            return None
        if end_i <= start_i:
            return None

        # Flags from __typename and the enclosing stream type.
        flags = EPGFlags.UNDEFINED
        if is_live_stream:
            flags |= EPGFlags.IS_LIVE
        if program.get("__typename") == "Episode" and program.get("series"):
            flags |= EPGFlags.IS_SERIES

        # `secondaryTitle` is the XMLTV-style sub-title; empty in most
        # captured entries but populated for some. `series.title` is a
        # fallback for episodes without a secondary title.
        episode_name = program.get("secondaryTitle") or None
        if not episode_name and isinstance(program.get("series"), dict):
            episode_name = program["series"].get("title") or None

        # `genres` — a list of dicts, mapped to a list of name strings.
        genres_raw = program.get("genres") or []
        genres = [g.get("name") for g in genres_raw if g.get("name")] or None

        # The poster image URL, if any.
        icon = (program.get("posterImage") or {}).get("url")

        return EPGEntry(
            broadcast_id=EPGEntry.encode_broadcast_id(
                PROVIDER_NAME, channel_id, start_i
            ),
            title=str(title),
            start=start_i,
            end=end_i,
            program_id=str(program_id),
            # epg_event_id intentionally None — see the module docstring.
            episode_name=episode_name,
            icon=icon,
            genres=genres,
            flags=flags or None,
        )

    def _details_from_entry(self, entry: EPGEntry) -> EPGProgramDetails:
        """
        Build an EPGProgramDetails from an EPGEntry we already have.

        The dedicated detail endpoint (if any) is not captured, so this is
        the only information available; it fills the shared fields
        (description, episode_name, icon, genres, flags-adjacent data) and
        leaves the rest as None. A future capture of a "details by id"
        operation would replace this with a real fetch.
        """
        return EPGProgramDetails(
            program_id=entry.program_id or "",
            description=entry.description,
            episode_name=entry.episode_name,
            icon=entry.icon,
            genres=entry.genres,
            season_number=entry.season_number,
            episode_number=entry.episode_number,
            parental_rating=entry.parental_rating,
        )

    # ------------------------------------------------------------------
    # Filtering helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _filter(
        events: List[EPGEntry],
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        limit: Optional[int],
    ) -> List[EPGEntry]:
        """
        Window filter. `start_time` / `end_time` are timezone-aware UTC
        datetimes (per the EpgManager contract); EPGEntry.start / .end
        are unix seconds. An overlap test is correct here — a program that
        starts before the window but is still airing counts as inside.
        """
        result = events
        if start_time is not None or end_time is not None:
            start_ts = int(start_time.timestamp()) if start_time is not None else 0
            end_ts = int(end_time.timestamp()) if end_time is not None else 1 << 62
            result = [e for e in result if e.end > start_ts and e.start < end_ts]
        if limit is not None and limit > 0:
            result = result[:limit]
        return result