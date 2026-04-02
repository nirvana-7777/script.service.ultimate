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
from .constants import MoveTVConfig


class MoveTvEpgManager:
    """Fetches and normalises EPG data from the MoveTV API."""

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
    ) -> List[Dict[str, Any]]:
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
        List of normalised programme dicts (see ``_parse_items``), or an
        empty list on any error.
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
            data: Dict[str, Any] = response.json()
        except Exception as exc:
            logger.error(
                f"MoveTV EPG: Request failed for channel {channel_id} — {exc}"
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
        return self._parse_items(items)

    def get_channels_epg(
        self,
        channel_ids: List[str],
        backwards: int = 2,
        forwards: int = 2,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Convenience wrapper: fetch EPG for multiple channels.

        Returns a dict keyed by channel_id.  Missing / failed channels are
        present with an empty list so callers don't have to guard KeyError.
        """
        result: Dict[str, List[Dict[str, Any]]] = {}
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
            """Attach UTC if naive, otherwise convert."""
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

    @staticmethod
    def _ms_to_utc_str(ms: Optional[int]) -> Optional[str]:
        """
        Convert a millisecond epoch timestamp to an ISO-8601 UTC string.

        Example: 1775052120000 → '2026-04-30T12:02:00+00:00'

        Returns None when *ms* is falsy (None / 0).
        """
        if not ms:
            return None
        dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
        return dt.isoformat()

    def _parse_items(self, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Normalise raw API programme objects into a consistent internal format.

        Field mapping
        -------------
        title       ← item["title"]
        plot        ← item["epgDesc"]
        start       ← item["start"]  (ms epoch → ISO-8601 UTC)
        end         ← item["end"]    (ms epoch → ISO-8601 UTC)
        start_ms    ← item["start"]  (raw ms, kept for easy sorting / math)
        end_ms      ← item["end"]    (raw ms)
        genre       ← item["tagInfo"]["name"]  (e.g. "SERIJA", "INFO")
        categories  ← list of category name strings
        thumbnail   ← item["picture"]["background"]  (absolute URL)
        director    ← item["director"]
        cast        ← item["actor"] split on ","
        year        ← item["year"]
        rating      ← item["rating"]  (parental-advisory integer)
        epg_id      ← item["epgId"]
        schedule_id ← item["scheduleId"]
        live_id     ← item["liveId"]
        live_name   ← item["liveName"]
        """
        parsed: List[Dict[str, Any]] = []

        for item in items:
            start_ms: Optional[int] = item.get("start")
            end_ms: Optional[int]   = item.get("end")

            categories: List[str] = [
                cat["name"]
                for cat in item.get("categories", [])
                if cat.get("name")
            ]

            actor_raw: Optional[str] = item.get("actor")
            cast: List[str] = (
                [a.strip() for a in actor_raw.split(",") if a.strip()]
                if actor_raw
                else []
            )

            parsed.append(
                {
                    "epg_id":      item.get("epgId"),
                    "schedule_id": item.get("scheduleId"),
                    "live_id":     item.get("liveId"),
                    "live_name":   item.get("liveName"),
                    "title":       item.get("title"),
                    "plot":        item.get("epgDesc"),
                    "start":       self._ms_to_utc_str(start_ms),
                    "end":         self._ms_to_utc_str(end_ms),
                    "start_ms":    start_ms,
                    "end_ms":      end_ms,
                    "genre":       item.get("tagInfo", {}).get("name"),
                    "categories":  categories,
                    "rating":      item.get("rating", 0),
                    "year":        item.get("year"),
                    "director":    item.get("director"),
                    "cast":        cast,
                    "thumbnail":   MoveTVConfig.build_image_url(
                        item.get("picture", {}).get("background")
                    ),
                }
            )

        return parsed