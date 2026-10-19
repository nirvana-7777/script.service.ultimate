# streaming_providers/providers/eon/epg_manager.py
"""
Eon EPG manager (v2/events/epg?cid=<id>&date=YYYY-MM-DD).

The endpoint is DAY based, one channel per request. Observed on a Vivacom
(Europe/Sofia, UTC+3) sample: `date=2026-10-22` starts with an event at
00:15 UTC (03:15 local), i.e. the day is a UTC day selected by programme START
time. So a programme that began before 00:00 UTC and is still running is only
in the PREVIOUS day's answer: get_epg() therefore also asks for the day before
the window and filters by overlap. (One sample; verify with a channel whose
programme crosses 00:00 UTC.)

The archive is 7 days; a date beyond it answers HTTP 400. The backend clamps
to epg_window, the oldest day additionally tolerates a 400 (day boundary).
`limit=` in **kw is ignored knowingly.

Failure semantics: a failed request RAISES (session errors on every endpoint);
a day without programmes is simply []. ISOLATE_GRID_FAILURES = True so one bad
channel cannot take the grid down.
"""

import time
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from ...base.errors import BadRequestError
from ...base.managers import EpgManager
from ...base.models.epg_models import EPGEntry
from ...base.utils.logger import logger
from .constants import EonConfig, EonDefaults
from .models import EonEpgEvent

_PROVIDER = EonDefaults.PROVIDER_LABEL
_DAY = 86400


def _utc_date(ts: int) -> date:
    return datetime.fromtimestamp(ts, timezone.utc).date()


def _to_epoch(value: Optional[datetime], default: int) -> int:
    return default if value is None else int(value.timestamp())


class EonEpgManager(EpgManager):
    ISOLATE_GRID_FAILURES = True

    def __init__(
        self,
        *,
        http_manager: Any,
        auth: Any,
        country: str,
        config: EonConfig,
        api: Any,
        endpoints: Any,
    ):
        super().__init__(
            http_manager=http_manager, auth=auth, country=country, config=config
        )
        self._api = api
        self._endpoints = endpoints

    @property
    def epg_window(self) -> Tuple[int, int]:
        return EonDefaults.EPG_PAST_DAYS, EonDefaults.EPG_FUTURE_DAYS

    def get_epg(
        self,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kw: Any,
    ) -> List[EPGEntry]:
        now = int(time.time())
        past, future = self.epg_window
        oldest, newest = now - past * _DAY, now + future * _DAY

        start = _to_epoch(start_time, now - now % _DAY)
        end = _to_epoch(end_time, start + _DAY)
        start, end = max(start, oldest), min(end, newest)
        if end <= start:
            return []

        oldest_day = _utc_date(oldest)
        first_day = max(_utc_date(start) - timedelta(days=1), oldest_day)
        last_day = _utc_date(end - 1)

        events: Dict[str, EonEpgEvent] = {}
        day = first_day
        while day <= last_day:
            for event in self._fetch_day(channel_id, day, tolerate_400=(day == oldest_day)):
                events.setdefault(event.id, event)
            day += timedelta(days=1)

        entries: List[EPGEntry] = []
        for event in sorted(events.values(), key=lambda e: e.start):
            try:
                entry = event.to_entry(
                    EonDefaults.PROVIDER_NAME, channel_id,
                    self._endpoints.image_url(event.icon_path),
                )
            except ValueError as exc:       # empty title, end <= start, ...
                logger.warning(f"{_PROVIDER}: skipping invalid EPG event {event.id}: {exc!r}")
                continue
            if entry.overlaps_with(start, end):
                entries.append(entry)
        return entries

    def _fetch_day(self, channel_id: str, day: date, *, tolerate_400: bool) -> List[EonEpgEvent]:
        try:
            raw = self._api.get_json(
                EonDefaults.PATH_EPG,
                params={"cid": channel_id, "date": day.isoformat()},
                extra_headers=self.config.epg_headers(),
            )
        except BadRequestError:
            if tolerate_400:
                logger.debug(f"{_PROVIDER}: EPG day {day} is outside the archive")
                return []
            raise

        events: List[EonEpgEvent] = []
        for item in raw if isinstance(raw, list) else []:
            try:
                event = EonEpgEvent.from_api_response(item)
            except (KeyError, TypeError, AttributeError, ValueError) as exc:
                logger.warning(f"{_PROVIDER}: skipping malformed EPG event: {exc!r}")
                continue
            if event.channel_id is not None and event.channel_id != str(channel_id):
                continue
            events.append(event)
        return events