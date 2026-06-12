# streaming_providers/base/utils/mpd_event_rewriter.py
"""
MPD Event Rewriter: shifts availabilityStartTime to a target EventStream event
so players start catchup playback at the correct programme boundary.

Key design constraint
---------------------
In a DASH dynamic MPD, Event.presentationTime is an *offset* (in timescale
ticks) from availabilityStartTime — it is NOT a Unix timestamp.  All
wall-clock conversions must add availabilityStartTime to the offset.
"""

import base64
import xml.etree.ElementTree as ET
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field

from .logger import logger


@dataclass
class EventInfo:
    """One Event element from an MPD EventStream."""
    id: str
    presentation_time: int   # ticks from availabilityStartTime
    duration: int            # ticks
    timescale: int
    payload_base64: str
    decoded_payload: Dict[str, str] = field(default_factory=dict)
    title: Optional[str] = None

    def wall_clock_start(self, availability_start: datetime) -> datetime:
        """Absolute UTC start time of this event."""
        return availability_start + timedelta(seconds=self.presentation_time / self.timescale)

    def wall_clock_end(self, availability_start: datetime) -> datetime:
        """Absolute UTC end time of this event."""
        return availability_start + timedelta(
            seconds=(self.presentation_time + self.duration) / self.timescale
        )

    def duration_seconds(self) -> float:
        return self.duration / self.timescale


@dataclass(frozen=True)
class ExtractedEvents:
    """
    Result of parsing EventStream data from an MPD.

    frozen=True prevents accidental reassignment of availability_start,
    which would silently break all subsequent offset calculations.
    """
    events: List[EventInfo]
    availability_start: datetime


class MPDEventRewriter:
    """
    Rewrites a dynamic DASH MPD so playback starts at a specific EventStream
    event.

    Strategy
    --------
    Set availabilityStartTime to the event's absolute wall-clock start time
    while leaving all presentationTime values untouched.  The player's
    presentation clock then starts at time 0 == event start, so it seeks
    directly to the right buffer position without any client-side adjustment.
    """

    NAMESPACES = {
        'mpd': 'urn:mpeg:dash:schema:mpd:2011',
        'cenc': 'urn:mpeg:cenc:2013',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
    }

    EPG_SCHEME_URIS = {
        "urn:de:dtag:eit:2017",
        "urn:dvb:iptv:2014:eit",
    }

    def __init__(self) -> None:
        for prefix, uri in self.NAMESPACES.items():
            ET.register_namespace(prefix if prefix != 'mpd' else '', uri)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_events(
        self,
        mpd_content: str,
        scheme_id_uri: Optional[str] = None,
    ) -> ExtractedEvents:
        """
        Parse all EventStream events from *mpd_content*.

        Returns
        -------
        ExtractedEvents
            .events              — list of EventInfo, may be empty
            .availability_start  — parsed availabilityStartTime (UTC)

        Raises
        ------
        ValueError  if availabilityStartTime is missing or unparseable.
        """
        root = ET.fromstring(mpd_content)
        availability_start = self._parse_availability_start(root)
        events: List[EventInfo] = []

        for es in root.findall('.//mpd:EventStream', self.NAMESPACES):
            if scheme_id_uri and es.get('schemeIdUri', '') != scheme_id_uri:
                continue
            timescale = int(es.get('timescale', '10000000'))

            for ev in es.findall('mpd:Event', self.NAMESPACES):
                info = EventInfo(
                    id=ev.get('id', ''),
                    presentation_time=int(ev.get('presentationTime', '0')),
                    duration=int(ev.get('duration', '0')),
                    timescale=timescale,
                    payload_base64=ev.text or '',
                )
                if info.payload_base64:
                    info.decoded_payload = self._decode_epg_payload(info.payload_base64)
                    info.title = self._extract_title(info.decoded_payload)

                wall_start = info.wall_clock_start(availability_start)
                logger.debug(
                    f"Event {info.id}: title={info.title!r}, "
                    f"wall_start={wall_start.isoformat()}, "
                    f"duration={info.duration_seconds():.0f}s"
                )
                events.append(info)

        # Emit a single warning here rather than requiring every call site to
        # remember to validate.  The most common real-world cause is a timescale
        # mismatch between the EventStream and the encoder, not genuinely bad data.
        if events and all(e.presentation_time == 0 for e in events):
            logger.warning(
                "All events have presentationTime=0 — EventStream may be malformed "
                "or there is a timescale mismatch; catchup alignment may be incorrect"
            )

        return ExtractedEvents(events=events, availability_start=availability_start)

    @staticmethod
    def find_closest_event(
        extracted: ExtractedEvents,
        target_time: datetime,
    ) -> Tuple[Optional[EventInfo], float]:
        """
        Return (best_event, diff_seconds) where diff is the absolute distance
        between target_time and the event's wall-clock start.
        """
        if not extracted.events:
            return None, float('inf')

        best: Optional[EventInfo] = None
        best_diff = float('inf')

        for ev in extracted.events:
            diff = abs(
                (ev.wall_clock_start(extracted.availability_start) - target_time).total_seconds()
            )
            if diff < best_diff:
                best_diff = diff
                best = ev

        if best:
            logger.debug(
                f"Closest event to {target_time.isoformat()}: "
                f"{best.title!r} (diff={best_diff:.0f}s)"
            )
        return best, best_diff

    def rewrite_for_event(
        self,
        mpd_content: str,
        extracted: ExtractedEvents,
        target_event: EventInfo,
        keep_other_events: bool = False,
        force_static_if_ended: bool = True,
    ) -> str:
        """
        Rewrite *mpd_content* so the player starts at *target_event*.

        Sets availabilityStartTime = target_event.wall_clock_start() and
        preserves all presentationTime values.  Optionally removes other
        events from the EventStream to avoid confusing the player.
        """
        root = ET.fromstring(mpd_content)
        event_wall_start = target_event.wall_clock_start(extracted.availability_start)

        # --- Update MPD root attributes ---
        ast_str = event_wall_start.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
        root.set('availabilityStartTime', ast_str)
        root.set('publishTime', ast_str)
        root.set('suggestedPresentationDelay', 'PT0S')

        now = datetime.now(tz=timezone.utc)
        event_ended = now > target_event.wall_clock_end(extracted.availability_start)

        if force_static_if_ended and event_ended:
            root.set('type', 'static')
            root.set(
                'mediaPresentationDuration',
                self._seconds_to_duration(target_event.duration_seconds()),
            )
            logger.info(
                f"Event {target_event.id} ended — converting to static MPD, "
                f"duration={self._seconds_to_duration(target_event.duration_seconds())}"
            )
        else:
            root.set('type', 'dynamic')

        # --- Filter EventStream ---
        for es in root.findall('.//mpd:EventStream', self.NAMESPACES):
            if keep_other_events:
                continue
            for ev in list(es.findall('mpd:Event', self.NAMESPACES)):
                es.remove(ev)
            self._append_event(es, target_event)

        return self._serialise(root)

    def rewrite_by_buffer_offset(
        self,
        mpd_content: str,
        extracted: ExtractedEvents,
        requested_start: datetime,
        max_buffer_seconds: int = 14400,
    ) -> str:
        """
        Fallback: shift availabilityStartTime so the requested_start maps to
        presentation time 0.

        availabilityStartTime is set directly to requested_start (clamped to
        the buffer window).  The player will seek to the head of the live
        window which corresponds to the requested time.

        timeShiftBufferDepth is intentionally left at the provider's declared
        value (the full DVR window).  Adjusting it to the offset would shrink
        the seekable range to exactly the catchup point, which is the opposite
        of what a catchup UI wants.  Players that honour it (e.g.
        inputstream.adaptive) use the segment timeline for seek range anyway.
        """
        now = datetime.now(tz=timezone.utc)
        offset = (now - requested_start).total_seconds()

        if offset > max_buffer_seconds:
            logger.warning(
                f"Requested time {requested_start.isoformat()} is outside "
                f"{max_buffer_seconds // 3600}h buffer; clamping."
            )
            requested_start = now - timedelta(seconds=max_buffer_seconds)

        root = ET.fromstring(mpd_content)
        ast_str = requested_start.strftime('%Y-%m-%dT%H:%M:%S') + 'Z'
        root.set('availabilityStartTime', ast_str)
        root.set('publishTime', ast_str)
        root.set('suggestedPresentationDelay', 'PT0S')
        root.set('type', 'dynamic')

        logger.info(
            f"Buffer-offset rewrite: AST {extracted.availability_start.isoformat()} "
            f"→ {requested_start.isoformat()} (offset={offset:.0f}s)"
        )
        return self._serialise(root)

    def get_event_timeline(
        self,
        mpd_content: str,
        scheme_id_uri: Optional[str] = None,
    ) -> List[Dict]:
        """Human-readable event list for debugging."""
        extracted = self.extract_events(mpd_content, scheme_id_uri)
        timeline = []
        for ev in extracted.events:
            timeline.append({
                'id': ev.id,
                'title': ev.title,
                'wall_start': ev.wall_clock_start(extracted.availability_start).isoformat(),
                'wall_end': ev.wall_clock_end(extracted.availability_start).isoformat(),
                'duration_seconds': ev.duration_seconds(),
                'presentation_time_ticks': ev.presentation_time,
                'timescale': ev.timescale,
            })
        return sorted(timeline, key=lambda x: x['presentation_time_ticks'])

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_availability_start(root: ET.Element) -> datetime:
        raw = root.get('availabilityStartTime', '')
        if not raw:
            raise ValueError("MPD missing availabilityStartTime")
        try:
            return datetime.fromisoformat(raw.replace('Z', '+00:00'))
        except ValueError:
            raise ValueError(f"Cannot parse availabilityStartTime: {raw!r}")

    @staticmethod
    def _decode_epg_payload(payload_b64: str) -> Dict[str, str]:
        try:
            decoded = base64.b64decode(payload_b64).decode('utf-8', errors='ignore')
            result: Dict[str, str] = {}
            for part in decoded.split(','):
                if '=' not in part:
                    continue
                key, value = part.split('=', 1)
                if key == 'DES_4D':
                    try:
                        result[key] = (
                            bytes.fromhex(value)
                            .replace(b'\x00', b'')
                            .decode('utf-8', errors='ignore')
                        )
                    except (ValueError, TypeError):
                        result[key] = value
                else:
                    result[key] = value
            return result
        except Exception as e:
            logger.debug(f"EPG payload decode failed: {e}")
            return {}

    @staticmethod
    def _extract_title(payload: Dict[str, str]) -> Optional[str]:
        title = payload.get('DES_4D') or payload.get('TITLE') or payload.get('NAME')
        if title:
            title = ' '.join(title.split())
            if len(title) > 100:
                title = title[:97] + '...'
        return title or None

    @staticmethod
    def _append_event(es: ET.Element, ev: EventInfo) -> None:
        elem = ET.Element('Event', {
            'presentationTime': str(ev.presentation_time),
            'duration': str(ev.duration),
            'id': ev.id,
            'contentEncoding': 'base64',
        })
        elem.text = ev.payload_base64
        es.append(elem)

    @staticmethod
    def _seconds_to_duration(seconds: float) -> str:
        s = int(round(seconds))
        h, rem = divmod(s, 3600)
        m, sec = divmod(rem, 60)
        if h:
            return f"PT{h}H{m}M{sec}S"
        if m:
            return f"PT{m}M{sec}S"
        return f"PT{sec}S"

    @staticmethod
    def _serialise(root: ET.Element) -> str:
        text = ET.tostring(root, encoding='unicode', method='xml')
        if not text.startswith('<?xml'):
            text = '<?xml version="1.0" encoding="UTF-8"?>\n' + text
        return text


# Module-level singleton
_instance: Optional[MPDEventRewriter] = None


def get_mpd_event_rewriter() -> MPDEventRewriter:
    global _instance
    if _instance is None:
        _instance = MPDEventRewriter()
    return _instance