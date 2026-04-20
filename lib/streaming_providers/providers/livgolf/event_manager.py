# streaming_providers/providers/livgolf/event_manager.py
# -*- coding: utf-8 -*-
"""
Event manager for the LIV Golf provider.

Responsibilities
----------------
* Discover the best CDN edge region from /mobii/regions.
* Fetch team-camera and group-camera stream lists for a champion (tournament).
* Rewrite manifest URLs to use the preferred regional CDN.
* Return normalised ``Event`` objects ready for the provider.

Design notes
------------
* Region selection is cached for the lifetime of the process — CDN topology
  does not change during a session.
* Stream lists are fetched fresh on every ``get_events()`` call so that live
  tournament URLs (which rotate) are always current.
* No EPG, no channels — this provider is events-only.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from ...base.models import Event
from ...base.utils.logger import logger
from .constants import (
    API_ENDPOINTS,
    CONTENT_TYPE_LIVE,
    DEFAULT_CHAMPION_ID,
    DEFAULT_REQUEST_TIMEOUT,
    FALLBACK_CDN_BASE,
    PROVIDER_NAME,
    REGION_PREFERENCE_ORDER,
    STREAMING_FORMAT_DASH,
    get_authenticated_headers,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Matches the CDN host in a mobii.com manifest URL, e.g.:
#   https://gcp-edge-us-c.mobii.com/api/video/...
_CDN_HOST_RE = re.compile(r"https://([^/]+\.mobii\.com)/")


def _rewrite_cdn(url: str, preferred_base: str) -> str:
    """
    Replace the CDN host in a mobii.com manifest URL with ``preferred_base``.

    ``preferred_base`` is the full origin, e.g. ``https://gcp-edge-eu-w.mobii.com``.
    Returns the original URL unchanged if it does not match the expected pattern.
    """
    if not url:
        return url
    return _CDN_HOST_RE.sub(preferred_base.rstrip("/") + "/", url, count=1)


# ---------------------------------------------------------------------------
# LivGolfEventManager
# ---------------------------------------------------------------------------

class LivGolfEventManager:
    """
    Fetches LIV Golf live event streams and normalises them into ``Event`` objects.

    Parameters
    ----------
    http_manager:
        The provider's shared HTTPManager instance.
    authenticator:
        ``LivGolfAuthenticator`` — used to obtain the current anonymous token.
    """

    def __init__(self, http_manager: Any, authenticator: Any) -> None:
        self._http = http_manager
        self._auth = authenticator

        # Cached preferred CDN base URL (None = not yet resolved)
        self._preferred_cdn: Optional[str] = None

        # Cache for events keyed by content_id (video_id)
        self._events_cache: Dict[str, Event] = {}

        logger.info("[LivGolfEventManager] Initialised")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_events(self, champion_id: str = DEFAULT_CHAMPION_ID) -> List[Event]:
        """
        Return all available live streams for *champion_id* as ``Event`` objects.

        Both team-camera and group-camera feeds are fetched and merged.
        Each stream becomes one Event with a DASH manifest URL rewritten to
        the closest CDN region.

        Parameters
        ----------
        champion_id:
            The LIV Golf tournament/champion identifier (default: ``"59"``).
        """
        authorization = self._auth.get_authorization_header()
        if not authorization:
            logger.error("[LivGolfEventManager] No authorization token available")
            return []

        preferred_cdn = self._get_preferred_cdn(authorization)
        headers = get_authenticated_headers(authorization)

        team_streams = self._fetch_streams(
            API_ENDPOINTS["TEAM_STREAMS"].format(champion_id=champion_id),
            headers,
            stream_kind="team",
        )
        group_streams = self._fetch_streams(
            API_ENDPOINTS["GROUP_STREAMS"].format(champion_id=champion_id),
            headers,
            stream_kind="group",
        )

        events: List[Event] = []
        new_cache: Dict[str, Event] = {}

        for stream in team_streams:
            event = self._build_event(stream, preferred_cdn, stream_kind="team")
            if event:
                events.append(event)
                new_cache[event.content_id] = event

        for stream in group_streams:
            event = self._build_event(stream, preferred_cdn, stream_kind="group")
            if event:
                events.append(event)
                new_cache[event.content_id] = event

        # Update cache with fresh results
        self._events_cache = new_cache

        logger.info(
            f"[LivGolfEventManager] champion={champion_id}: "
            f"{len(team_streams)} team + {len(group_streams)} group streams → "
            f"{len(events)} events"
        )
        return events

    def get_event(
        self, content_id: str, champion_id: str = DEFAULT_CHAMPION_ID
    ) -> Optional[Event]:
        """
        Return a single Event by its content_id.

        If the event is not in the cache, it triggers a fresh get_events() call
        to discover it.
        """
        event = self._events_cache.get(content_id)
        if event:
            return event

        logger.info(
            f"[LivGolfEventManager] Event '{content_id}' not in cache — "
            "triggering fresh fetch"
        )
        self.get_events(champion_id=champion_id)
        return self._events_cache.get(content_id)

    # ------------------------------------------------------------------
    # Region / CDN resolution
    # ------------------------------------------------------------------

    def _get_preferred_cdn(self, authorization: str) -> str:
        """
        Return the base URL for the closest CDN region.

        Result is cached after the first successful call.  Falls back to
        ``FALLBACK_CDN_BASE`` if the regions endpoint is unreachable or returns
        unexpected data.
        """
        if self._preferred_cdn:
            return self._preferred_cdn

        self._preferred_cdn = self._resolve_preferred_cdn(authorization)
        logger.info(f"[LivGolfEventManager] Preferred CDN: {self._preferred_cdn}")
        return self._preferred_cdn

    def _resolve_preferred_cdn(self, authorization: str) -> str:
        """
        Fetch /mobii/regions and select the best regional base URL according
        to ``REGION_PREFERENCE_ORDER``.
        """
        try:
            headers = get_authenticated_headers(authorization)
            response = self._http.get(
                API_ENDPOINTS["REGIONS"],
                operation="regions",
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            logger.warning(
                f"[LivGolfEventManager] Regions fetch failed, using fallback: {exc}"
            )
            return FALLBACK_CDN_BASE

        # Build a lookup: abbreviation → default uri
        region_map: Dict[str, str] = {}
        for region in data.get("uris", []):
            abbrev = region.get("abbreviation", "")
            for uri_entry in region.get("uris", []):
                if uri_entry.get("isDefault"):
                    base = uri_entry.get("uri", "").rstrip("/")
                    if base:
                        region_map[abbrev] = base
                    break

        if not region_map:
            logger.warning("[LivGolfEventManager] Empty region map, using fallback CDN")
            return FALLBACK_CDN_BASE

        # Walk the preference list and return the first available region
        for preferred in REGION_PREFERENCE_ORDER:
            if preferred in region_map:
                return region_map[preferred]

        # Fall back to the first returned region
        first_base = next(iter(region_map.values()))
        logger.warning(
            f"[LivGolfEventManager] No preferred region matched — "
            f"using first available: {first_base}"
        )
        return first_base

    # ------------------------------------------------------------------
    # Stream fetching
    # ------------------------------------------------------------------

    def _fetch_streams(
        self,
        url: str,
        headers: Dict[str, str],
        stream_kind: str,
    ) -> List[Dict[str, Any]]:
        """
        Fetch a team or group stream list from the API.

        Returns the list of stream dicts from the response, or an empty list
        on any error.
        """
        try:
            response = self._http.get(
                url,
                operation=f"streams_{stream_kind}",
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
            streams = data.get("streams", [])
            logger.debug(
                f"[LivGolfEventManager] Fetched {len(streams)} {stream_kind} streams"
            )
            return streams
        except Exception as exc:
            logger.warning(
                f"[LivGolfEventManager] Failed to fetch {stream_kind} streams: {exc}"
            )
            return []

    # ------------------------------------------------------------------
    # Event construction
    # ------------------------------------------------------------------

    def _build_event(
        self,
        stream: Dict[str, Any],
        preferred_cdn: str,
        stream_kind: str,
    ) -> Optional[Event]:
        """
        Convert a single stream dict into an ``Event``.

        Stream dicts have at least: ``id``, ``name``, ``dashUrl``, ``hlsUrl``.
        Team streams additionally carry ``teamId`` and ``livTeamId``.
        """
        video_id = stream.get("id")
        raw_name = stream.get("name", "")

        if not video_id or not raw_name:
            logger.debug(
                f"[LivGolfEventManager] Skipping stream with missing id or name: {stream}"
            )
            return None

        dash_url = stream.get("dashUrl", "")
        if not dash_url:
            logger.debug(
                f"[LivGolfEventManager] Skipping stream '{raw_name}' — no DASH URL"
            )
            return None

        # Rewrite the CDN host to the preferred region
        manifest = _rewrite_cdn(dash_url, preferred_cdn)

        # Build a human-readable name.
        # Raw names look like "Team_01" or "Group_06" — normalise them.
        label = self._format_stream_name(raw_name, stream, stream_kind)

        # Content ID doubles as the ViewLift video id — uniquely identifies the feed.
        content_id = video_id

        # team_id is useful as an external reference; omit if not present.
        team_id = stream.get("teamId")
        liv_team_id = stream.get("livTeamId")

        # Build an optional metadata note carried in manifest_script (same pattern
        # as magentaeu which stuffs chno/epgid/media there).
        meta_parts = [f"kind={stream_kind}", f"vid={video_id}"]
        if team_id is not None:
            meta_parts.append(f"team={team_id}")
        if liv_team_id is not None:
            meta_parts.append(f"liv_team={liv_team_id}")
        manifest_script = " ".join(meta_parts)

        try:
            event = Event(
                name=label,
                content_id=content_id,
                provider=PROVIDER_NAME,
                manifest=manifest,
                manifest_script=manifest_script,
                # LIV Golf streams are DRM-free
                use_cdm=False,
                cdm_type=None,
                cdm=None,
                cdm_mode="",
                streaming_format=STREAMING_FORMAT_DASH,
                content_type=CONTENT_TYPE_LIVE,
                mode="live",
                session_manifest=False,
                video="best",
                on_demand=False,
            )
            return event
        except Exception as exc:
            logger.warning(
                f"[LivGolfEventManager] Failed to construct Event for '{raw_name}': {exc}"
            )
            return None

    # ------------------------------------------------------------------
    # Naming helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_stream_name(
        raw_name: str,
        stream: Dict[str, Any],
        stream_kind: str,
    ) -> str:
        """
        Turn a raw API name like ``"Team_06"`` or ``"Group_03"`` into a
        presentable label like ``"LIV Golf – Team Feed 6"`` or
        ``"LIV Golf – Group Feed 3"``.

        For team streams the team number is replaced by the teamId where
        available, since the numeric suffix is just an ordering index.
        """
        try:
            # Extract the numeric suffix (e.g. "06" → 6)
            suffix = int(raw_name.split("_")[-1])
        except (ValueError, IndexError):
            suffix = None

        kind_label = "Team" if stream_kind == "team" else "Group"

        if stream_kind == "team":
            team_id = stream.get("teamId")
            index = team_id if team_id is not None else suffix
        else:
            index = suffix

        if index is not None:
            return f"LIV Golf – {kind_label} Feed {index}"
        return f"LIV Golf – {kind_label} Feed ({raw_name})"