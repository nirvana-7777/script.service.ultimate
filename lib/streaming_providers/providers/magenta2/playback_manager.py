# streaming_providers/providers/magenta2/playback_manager.py
# -*- coding: utf-8 -*-
"""
Routes manifest and DRM requests for the Magenta2 provider.

Responsibilities
----------------
- Serve live-channel manifests directly from the ChannelManager cache
  (avoiding a SMIL round-trip for channels already fetched by get_channels).
- Build Widevine licence URLs directly for live channels using lib_theplatform.
- Delegate VOD and recording manifest/DRM requests to SmilManager.
- Serve catchup manifests by appending ``begin``/``end`` to the cached live
  manifest URL — no separate SMIL fetch required.
- Inject ``smil_base_url`` from the recording-URL cache so callers (e.g.
  DRMOperations) only need to pass a ``content_id``.
- Resolve numeric station ids to entitled release pids for live/catchup
  requests, AFTER the live caches are populated (see "Live id resolution").

The class holds one piece of state beyond the manager/callback references:
the rate-limit timestamp guarding get_channels() re-population attempts
(see ``_LIVE_CACHE_RETRY_INTERVAL``).  All caches belong to ChannelManager.

Live id resolution
------------------
Numeric station ids must be resolved to release pids through
ChannelManager's station-to-pid map, but that map only holds entitled
RELEASE pids after get_channels() has run — before that it holds
station-metadata MEDIA pids, which the SMIL path rejects (observed as
error SMILs for live channels).  Resolution therefore happens inside
PlaybackManager, strictly after cache population (``_prepare_live_pid``),
never in the provider before the playback call.

Whether the map is safe to resolve through is signalled by
``ChannelManager.has_release_pid_map()`` (set when a get_channels() feed
load completes) — NOT by the live manifest/pid caches, which
``populate_streaming_data()`` (channel-playlist endpoint) also fills
without ever updating the station map.  Keying on the caches would let
a playlist-only population vouch for a map that still holds media pids.

SMIL is the MASTER path.  The entitled-channels feed fallback —
``ChannelManager.resolve_release_pid_via_feed`` (wrapped in
``_feed_fallback_pid``), queried with the GENERIC distribution right so
the FULL channel universe is visible — runs only AFTER the SMIL path has
failed for the resolved id (error-SMIL, no MPD / no releasePid; observed:
``UserAgentBlocked`` / "User Agent Restriction" for a Sky Sport UHD
station), never before it.  The feed carries both the release pid and the
direct CDN streamingUrl, so live manifest, DRM and catchup can be served
even without a working SMIL path — as the escape hatch, not the first
stop.  Catchup never does SMIL; there the fallback fires when no live
manifest URL is cached (see ``_build_begin_end_manifest_url``).

Catchup routing
---------------
Magenta2 catchup reuses the live DASH manifest URL with ``begin``/``end``
query parameters (basic-ISO UTC) bounding the requested programme window.  The
Broadpeak origin then serves a static, programme-bounded manifest
(mediaPresentationDuration == programme length), so no manifest rewriting
is needed.  ``end`` is clamped to now so a running programme never requests beyond
the live edge.  Example:

    Live:    https://svc45.…/zdf_hd/DASH/index.mpd?AppVersion=…
    Catchup: https://svc45.…/zdf_hd/DASH/index.mpd?AppVersion=…&begin=20261011T104300&end=20261011T111500

DRM for catchup is identical to live — the same Widevine licence URL applies —
so ``get_drm`` routes catchup requests through the same fast-path as live.

If the live manifest URL is not yet cached when a catchup request arrives,
the live caches are (re)populated before building the URL — on a pid miss
this refresh is rate-limited to one attempt per ``_LIVE_CACHE_RETRY_INTERVAL``
so an unentitled or stale id cannot storm the feed.  If no live URL is
cached even after the refresh, the entitled-channels feed fallback may
still rewrite the caches (see ``_build_begin_end_manifest_url`` /
``_feed_fallback_pid``).  SmilManager is NOT used for catchup on this
provider.
"""
import base64
import enum
import threading
import time
from typing import Callable, Dict, List, Optional
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

from ...base.models import DRMConfig
from ...base.utils.logger import logger
from ...base.utils.timestamp_converter import TimestampConverter
from .constants import CONTENT_TYPE_LIVE, MAGENTA2_FALLBACK_ACCOUNT_URI
from .endpoint_manager import EndpointManager
from .config_models import ProviderConfig
from .smil_manager import SmilManager
from .channel_manager import ChannelManager
from ..lib_theplatform import (
    extract_persona_jwt,
    build_licence_url,
    build_widevine_drm_config,
)


class _LiveCachePopulateResult(enum.Enum):
    """
    Outcome of a ``PlaybackManager._populate_live_caches()`` call.

    Tri-state so callers can distinguish "did not try" from "tried and
    failed" — both are falsy outcomes for the purposes of re-resolving
    ids, but they mean different things operationally (back off vs.
    degrade) and are logged differently by the caller.
    """

    # A fetch was attempted AND succeeded — the map/caches were refreshed,
    # so a caller may re-resolve ids against them.
    POPULATED = "populated"

    # Skipped: within _LIVE_CACHE_RETRY_INTERVAL of the last attempt
    # (shared negative cache across cold-starts, failures and pid misses).
    RATE_LIMITED = "rate-limited"

    # A fetch was attempted but raised — logged here; playback degrades
    # to the SMIL path with whatever id state exists.
    FAILED = "failed"


class PlaybackManager:
    """
    Routes manifest and DRM requests for Magenta2 content.

    Parameters
    ----------
    channel_manager:
        The provider's ChannelManager instance (owns live-manifest/pid caches).
    smil_manager:
        The provider's SmilManager instance (handles VOD / recording SMIL).
    endpoint_manager:
        Populated EndpointManager after discovery.
    provider_config:
        ProviderConfig after discovery.
    platform_config:
        Platform-specific dict from MAGENTA2_PLATFORMS. Kept for any fields
        not covered by user_agent_subscriber (subscriber_type, etc.) — no
        longer used for platform_config["user_agent"], which doesn't exist
        anymore; use user_agent_subscriber instead.
    user_agent_subscriber:
        Rendered UA (with subscriber_type suffix) — used for the live-DRM
        fast path in get_drm(), matching what SmilManager uses for its own
        (SMIL/VOD) DRM path.
    session_id / call_id_callback:
        Needed so the live-DRM fast path can send a CID header
        ("{session_id}::{call_id}"), matching the SMIL DRM path (see
        smil_manager.get_drm) and confirmed against a real ATV widevine
        capture, which shows only CID — no separate session-id header.
        call_id_callback is optional — if omitted, CID is left off entirely
        (better than sending a malformed header).
    auth_callback:
        Callable[[], str] — returns a valid persona token (Basic-auth value).
    recording_url_cache:
        Shared dict (owned by the provider) mapping content_id → manifest_script
        for recordings fetched via RecordingsManager.
    """

    # Minimum seconds between ChannelManager.get_channels() (re)population
    # attempts triggered from the playback path (cold cache, feed failure,
    # or an entitled-cache pid miss). Bounds feed traffic when callers retry
    # unentitled/stale ids — get_channels() has no negative caching of its
    # own.
    _LIVE_CACHE_RETRY_INTERVAL: float = 300.0

    def __init__(
        self,
        channel_manager: ChannelManager,
        smil_manager: Optional[SmilManager],
        endpoint_manager: Optional[EndpointManager],
        provider_config: Optional[ProviderConfig],
        platform_config: Dict,
        auth_callback: Callable[[], str],
        recording_url_cache: Dict[str, str],
        user_agent_subscriber: Optional[str] = None,
        session_id: Optional[str] = None,
        call_id_callback: Optional[Callable[[], str]] = None,
    ):
        self._channel_manager = channel_manager
        self._smil_manager = smil_manager
        self._endpoint_manager = endpoint_manager
        self._provider_config = provider_config
        self._platform_config = platform_config
        self._ensure_authenticated = auth_callback
        self._recording_url_cache = recording_url_cache
        self._ua_subscriber = user_agent_subscriber
        self._session_id = session_id
        self._call_id = call_id_callback

        # Rate-limit state for get_channels() (re)population attempts. A
        # single shared negative cache: cold-starts, failed fetches and pid
        # misses all consume the same interval. -inf so the first attempt
        # always fires regardless of process uptime (time.monotonic() can
        # be small early after boot).
        self._last_populate_attempt: float = float("-inf")
        self._populate_lock = threading.Lock()
        # One-shot warning flag for the (unsupported) case of a
        # ChannelManager without resolve_release_pid_via_feed — i.e. this
        # patched PlaybackManager running against an un-patched
        # channel_manager.py.  See _feed_fallback_pid.
        self._warned_no_feed_fallback: bool = False

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def get_manifest(
        self, content_id: str, content_type: str = CONTENT_TYPE_LIVE, **kwargs
    ) -> Optional[str]:
        """
        Return the MPD manifest URL for *content_id*.

        *content_id* may be a numeric station_id or a playback pid for
        live/catchup requests (station ids are resolved here, after the
        live caches are populated — see ``_prepare_live_pid``); VOD and
        recording ids pass through untouched.

        Routing logic
        ~~~~~~~~~~~~~
        1. **Catchup** (``start_time`` + ``end_time`` present in kwargs):
           Appends ``begin``/``end`` to the cached live manifest URL.
           No SMIL round-trip.  The live cache is (re)populated on demand.
        2. **Live** (``content_type == CONTENT_TYPE_LIVE``, no time window):
           Served directly from the ChannelManager cache when the resolved
           pid is entitled.  On a miss the request degrades to SmilManager
           — the MASTER path — with the resolved id; only if SMIL fails
           too does the entitled-channels feed fallback (generic
           distribution right, full channel universe) get the last word
           for numeric station ids: it re-resolves the station to a
           feed-sourced release pid + direct streamingUrl and serves the
           cached MPD (which may lack the SMIL path's session binding).
        3. **VOD / recordings**: Fall through to ``SmilManager.get_manifest``.
        """
        if self._is_catchup_request(kwargs):
            pid = self._prepare_live_pid(content_id)
            logger.debug(
                f"get_manifest: catchup request for {pid} "
                f"(start={kwargs['start_time']}, end={kwargs['end_time']})"
            )
            return self._build_begin_end_manifest_url(
                pid, kwargs["start_time"], kwargs["end_time"], station_id=content_id
            )

        lookup_id = content_id
        if content_type == CONTENT_TYPE_LIVE:
            lookup_id = self._prepare_live_pid(content_id)
            mpd = self._channel_manager.get_live_manifest_url(lookup_id)
            if mpd:
                logger.debug(f"get_manifest: cache hit for live channel {lookup_id}")
                return mpd
            logger.debug(
                f"get_manifest: no entitled manifest for {lookup_id} — degrading to SMIL"
            )

        if not self._smil_manager:
            raise RuntimeError("SmilManager not available")
        self._inject_smil_base_url(lookup_id, kwargs)
        result = self._smil_manager.get_manifest(lookup_id, content_type, **kwargs)

        if result is None and content_type == CONTENT_TYPE_LIVE:
            # SMIL — the master path — failed for this id.  Last resort:
            # the entitled-channels feed fallback (generic distribution
            # right, full channel universe), which carries release pid +
            # direct streamingUrl for exactly this class of failure
            # (observed: UserAgentBlocked on the selector).  Numeric
            # station ids only — a pid input cannot be re-resolved by
            # station.  _feed_fallback_pid never raises, and its vouched
            # fast-path absorbs the concurrent-refresh case (another
            # thread's successful fallback is immediately visible); a
            # rate-limited or failed fallback leaves us where SMIL did.
            fallback_pid = (
                self._feed_fallback_pid(content_id) if content_id.isdigit() else None
            )
            if fallback_pid:
                mpd = self._channel_manager.get_live_manifest_url(fallback_pid)
                if mpd:
                    logger.warning(
                        f"get_manifest: SMIL returned no MPD for {lookup_id}; using "
                        f"entitled-feed MPD for {fallback_pid} "
                        "(may lack the SMIL path's session binding)"
                    )
                    return mpd
        return result

    def get_drm(
        self, content_id: str, content_type: str = CONTENT_TYPE_LIVE, **kwargs
    ) -> List[DRMConfig]:
        """
        Return DRM configuration for *content_id*.

        Routing logic
        ~~~~~~~~~~~~~
        1. **Catchup** (``start_time`` + ``end_time`` present in kwargs):
           DRM is identical to live — same Widevine licence URL applies to the
           DVR window.  Routes through the live fast-path using the
           entitled-pid cache.  Falls back to SmilManager if the pid is not
           entitled.
        2. **Live** (``content_type == CONTENT_TYPE_LIVE``, no time window):
           For ids whose resolved pid is in the entitled-pid cache, the
           Widevine licence URL is built directly using lib_theplatform — no
           SMIL fetch needed.  If the pid is NOT in the entitled cache the
           request degrades to SmilManager — the MASTER path.  Only when
           SMIL fails as well does the entitled-channels feed fallback
           (generic distribution right) get the last word for numeric
           station ids: it vouches a feed-sourced release pid, and only a
           VOUCHEd pid is ever direct-built.  Pid-cache membership remains
           the entitlement verification for the direct licence path —
           callers cache non-empty DRM results, so an unverified releasePid
           must never be promoted here.
        3. **VOD / recordings**: Fall through to ``SmilManager.get_drm``.
        """
        lookup_id = content_id
        live_request = (
            self._is_catchup_request(kwargs) or content_type == CONTENT_TYPE_LIVE
        )
        if live_request:
            lookup_id = self._prepare_live_pid(content_id)
            if self._channel_manager.is_entitled_live_pid(lookup_id):
                if self._is_catchup_request(kwargs):
                    logger.debug(
                        f"get_drm: catchup for {lookup_id} — reusing live DRM fast-path"
                    )
                return self._build_live_drm(lookup_id)
            if self._is_catchup_request(kwargs):
                # pid not entitled — fall through to SmilManager as a best-effort.
                logger.warning(
                    f"get_drm: catchup for {lookup_id} but pid not in live cache; "
                    "falling back to SmilManager"
                )
            else:
                # Symmetric with get_manifest's degradation log, so the
                # reason a SMIL round-trip happened is visible on the DRM
                # path too. This is the deliberate veto case: pid-cache
                # membership is the entitlement verification for a direct
                # licence build (see _build_live_drm).
                logger.debug(
                    f"get_drm: {lookup_id} not in entitled pid cache — "
                    "degrading to SMIL"
                )

        if not self._smil_manager:
            raise RuntimeError("SmilManager not available")
        self._inject_smil_base_url(lookup_id, kwargs)
        try:
            drm_configs = self._smil_manager.get_drm(lookup_id, content_type, **kwargs)
        except Exception:
            # SMIL (master path) raised — last resort for numeric station
            # ids on live/catchup requests; otherwise re-raise untouched so
            # error semantics are exactly what they were without the patch.
            fallback = (
                self._post_smil_feed_fallback_drm(content_id, lookup_id)
                if live_request
                else None
            )
            if fallback:
                return fallback
            raise
        if drm_configs:
            return drm_configs
        if live_request:
            # SMIL (master path) yielded no config — same last resort.
            fallback = self._post_smil_feed_fallback_drm(content_id, lookup_id)
            if fallback:
                return fallback
        return drm_configs

    def get_catchup_manifest(
        self, content_id: str, start_time: int, end_time: int, drm_variant: Optional[str] = "auto", **kwargs
    ) -> Optional[str]:
        """
        Return a catchup manifest URL for *content_id*.

        Appends ``begin``/``end`` (the requested programme window) to the cached
        live manifest URL. The Broadpeak origin then serves a static, programme-
        bounded manifest (mediaPresentationDuration == programme length), so no
        client- or backend-side manifest rewriting is needed. ``end`` is clamped
        to now so a still-running programme does not request beyond the live edge.

        Parameters
        ----------
        content_id:
            The live channel content_id — a numeric station_id or a playback
            pid (the same key used in the live cache; station ids are
            resolved here, after cache population).
        start_time:
            Unix timestamp (seconds) of the catchup window start.
        end_time:
            Unix timestamp (seconds) of the catchup window end.
        """
        pid = self._prepare_live_pid(content_id)
        return self._build_begin_end_manifest_url(
            pid, start_time, end_time, station_id=content_id
        )

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_catchup_request(kwargs: Dict) -> bool:
        """
        Return True when *kwargs* carries both ``start_time`` and ``end_time``,
        indicating a time-shifted / catchup playback request.
        """
        return (
            kwargs.get("start_time") is not None
            and kwargs.get("end_time") is not None
        )

    def _build_begin_end_manifest_url(
        self,
        content_id: str,
        start_time: int,
        end_time: int,
        station_id: Optional[str] = None,
    ) -> Optional[str]:
        """
        Retrieve the cached live manifest URL for *content_id* and append the
        ``begin``/``end`` programme window (basic-ISO UTC). ``end`` is clamped to
        now so a running programme never requests beyond the live edge.

        *station_id* is the ORIGINAL numeric station id behind *content_id*
        (they differ when _prepare_live_pid resolved the station to a pid).
        Catchup never does SMIL, so when no live manifest URL is cached for
        *content_id*, the entitled-channels feed fallback (generic
        distribution right) is the only escalation left — it needs the
        station id, not the pid.  Callers without one keep the old
        behaviour (no fallback).

        Returns ``None`` if no manifest URL can be produced (the caller is
        responsible for cache population via ``_prepare_live_pid``).
        """
        live_url = self._channel_manager.get_live_manifest_url(content_id)
        if not live_url:
            fallback_station = (
                station_id
                if station_id and station_id.isdigit()
                else (content_id if content_id.isdigit() else None)
            )
            if fallback_station:
                # Catchup reuses the live manifest URL and never touches
                # SMIL, so the feed fallback (generic right) is the only
                # escalation when nothing is cached for this station.
                fallback_pid = self._feed_fallback_pid(fallback_station)
                if fallback_pid:
                    live_url = self._channel_manager.get_live_manifest_url(fallback_pid)
                    if live_url:
                        logger.warning(
                            f"_build_begin_end_manifest_url: no cached live manifest "
                            f"for {content_id}; using entitled-feed manifest for "
                            f"{fallback_pid} (may lack the SMIL path's session binding)"
                        )
        if not live_url:
            logger.error(
                f"_build_begin_end_manifest_url: no live manifest cached for {content_id}; "
                "cannot build catchup URL"
            )
            return None

        end_time = min(int(end_time), int(time.time()))
        begin_iso = TimestampConverter.epoch_to_iso(
            int(start_time), format_type="basic", as_utc=True
        )
        end_iso = TimestampConverter.epoch_to_iso(end_time, format_type="basic", as_utc=True)

        parsed = urlparse(live_url)
        existing: Dict[str, List[str]] = parse_qs(parsed.query, keep_blank_values=True)
        existing["begin"] = [begin_iso]
        existing["end"] = [end_iso]
        new_query = urlencode({k: v[0] for k, v in existing.items()}, safe="")
        catchup_url = urlunparse(parsed._replace(query=new_query))
        logger.debug(f"_build_begin_end_manifest_url: {content_id} → {catchup_url}")
        return catchup_url

    def _prepare_live_pid(self, content_id: str) -> str:
        """
        Resolve *content_id* to the best available live pid, with the
        ordering the live fast paths depend on.

        Ordering (the observed "error SMIL for a live channel" bug):
        ChannelManager's station-to-pid map holds station-metadata MEDIA
        pids until get_channels() runs and overwrites them with entitled
        RELEASE pids.  Resolving a numeric station_id through a pre-feed
        map therefore yields a media pid, which the SMIL path rejects.  So:
        populate first, resolve second; and on a pid miss, one rate-limited
        refresh followed by a re-resolve (a refreshed map can fix a stale
        pid, not just a cache miss).

        The map's safety signal is ``has_release_pid_map()`` (a feed load
        completed), NOT the live manifest/pid caches — those are also
        filled by populate_streaming_data (channel-playlist endpoint),
        which never updates the station map.

        This method deliberately does NOT trigger the entitled-channels
        feed fallback: SMIL is the master path, so an unvouched pid is
        returned as-is and the CALLER tries SMIL with it first.  Only a
        failed SMIL round-trip escalates to the feed fallback (the
        post-SMIL blocks in get_manifest / get_drm, and — for catchup,
        which never does SMIL — ``_build_begin_end_manifest_url``).

        Never raises: a failed feed fetch degrades to resolving against
        whatever map state exists, and callers fall through to SmilManager.
        """
        if not self._channel_manager.has_release_pid_map():
            result = self._populate_live_caches()
            if result is not _LiveCachePopulateResult.POPULATED:
                logger.debug(
                    f"_prepare_live_pid: initial population {result.value}; "
                    "the station map still pre-dates the feed"
                )
        pid = self._resolve_station_id(content_id)
        if not self._channel_manager.is_entitled_live_pid(pid):
            result = self._populate_live_caches()
            if result is _LiveCachePopulateResult.POPULATED:
                pid = self._resolve_station_id(content_id)
            elif result is _LiveCachePopulateResult.RATE_LIMITED:
                logger.debug(
                    "_prepare_live_pid: refresh rate-limited — skipping re-resolve"
                )
            else:  # FAILED
                logger.debug(
                    "_prepare_live_pid: feed fetch failed — degrading with the "
                    f"current pid ({pid})"
                )
        if pid == content_id and content_id.isdigit():
            # Explicit degraded-path signal: the live fast paths will miss
            # on a raw numeric station id (their caches are keyed by pids)
            # and SMIL will fail predictably — a numeric station id is not
            # an MPX guid. Logged here rather than relying on the SMIL
            # error to make itself understood.
            logger.debug(
                f"_prepare_live_pid: cannot resolve station id {content_id} to "
                "a release pid — skipping the live fast path for it"
            )
        return pid

    def _resolve_station_id(self, content_id: str) -> str:
        """
        Numeric station_id → release pid via the station-to-pid map;
        anything else (already a pid, or a VOD id) passes through unchanged.
        """
        if not (content_id and content_id.isdigit()):
            return content_id
        if not self._channel_manager.has_release_pid_map():
            # The map provably pre-dates any feed load (get_channels() has
            # never completed), so any mapping it holds for this station is
            # a media pid — do not resolve through it. Keyed on the
            # release-map flag, NOT on the live caches: those are also
            # filled by populate_streaming_data (channel-playlist
            # endpoint), which never touches the station map — a
            # playlist-only population must not vouch for it.
            # Debug, not warning: the failed/attempted fetch that led here
            # is already logged by _populate_live_caches, and this fires
            # once per playback request while the negative cache holds.
            logger.debug(
                f"Station map not feed-sourced yet; cannot resolve station "
                f"{content_id} to a release pid — passing the raw station id "
                "through"
            )
            return content_id
        playback_id = self._channel_manager.get_playback_id_for_station(content_id)
        if playback_id:
            logger.debug(f"Resolved station {content_id} -> pid {playback_id}")
            return playback_id
        logger.warning(
            f"Station {content_id} has no playback pid in the station map; "
            "passing the raw id through"
        )
        return content_id

    def _populate_live_caches(self) -> _LiveCachePopulateResult:
        """
        (Re)populate the live caches via ChannelManager.get_channels(),
        guarded by:

        - a shared rate limit / negative cache — at most one attempt per
          ``_LIVE_CACHE_RETRY_INTERVAL`` across cold-starts, failed fetches
          and pid misses alike, so a failing feed or a caller retrying an
          unentitled/stale id cannot storm the feed (get_channels() has no
          negative caching of its own);
        - a no-raise policy — a feed outage logs and degrades playback to
          the SMIL path instead of raising out of every live request.

        Returns ``_LiveCachePopulateResult.POPULATED`` only when a fetch
        was attempted AND succeeded (so a caller may re-resolve ids against
        the refreshed map); ``RATE_LIMITED`` when the attempt was skipped
        by the shared interval, and ``FAILED`` when the fetch raised. The
        two non-POPULATED outcomes are indistinguishable to the caller's
        control flow (neither can produce a fresher map) but are logged
        differently — rate-limiting is routine back-off, failure is a
        degradation worth its own line in _populate_live_caches.
        """
        with self._populate_lock:
            now = time.monotonic()
            if now - self._last_populate_attempt < self._LIVE_CACHE_RETRY_INTERVAL:
                return _LiveCachePopulateResult.RATE_LIMITED
            self._last_populate_attempt = now
        try:
            logger.debug(
                "Live cache cold or pid miss — (re)populating via get_channels()"
            )
            self._channel_manager.get_channels()
            return _LiveCachePopulateResult.POPULATED
        except Exception as exc:
            logger.warning(
                f"Live-cache population failed ({exc}); degrading to SMIL path"
            )
            return _LiveCachePopulateResult.FAILED

    def _feed_fallback_pid(self, station_id: str) -> Optional[str]:
        """
        Entitled-channels-feed fallback (LAST resort, post-SMIL): wrap
        ``ChannelManager.resolve_release_pid_via_feed`` for the callers
        that have already watched the SMIL master path fail —
        get_manifest / get_drm (live) and _build_begin_end_manifest_url
        (catchup).

        The wrapped method re-resolves *station_id* from the
        entitled-channels feed — served from the
        ``mpx_feed_entitledChannelsFeed`` endpoint (never a hardcoded
        URL) and queried with the GENERIC distribution right (the full
        channel universe, NOT the account's applicable rights, so
        stations outside the entitled subset remain resolvable) —
        rewrites the station->pid map and the live manifest/pid/HLS
        caches for every feed entry, and returns the vouched release
        pid.  None means the station is not in the feed, the feed could
        not be fetched, or the refetch was rate-limited; the caller then
        keeps the SMIL path's outcome.  Never raises.

        The getattr guard keeps this PlaybackManager usable against an
        un-patched ChannelManager (the fallback patch spans several
        files — channel_manager.py, constants.py, smil_manager.py and
        this one); playback then degrades exactly as before, with one
        warning instead of an AttributeError on every live request.
        """
        resolver = getattr(
            self._channel_manager, "resolve_release_pid_via_feed", None
        )
        if resolver is None:
            if not self._warned_no_feed_fallback:
                self._warned_no_feed_fallback = True
                logger.warning(
                    "ChannelManager has no resolve_release_pid_via_feed — "
                    "apply the magenta2 feed-fallback patch to "
                    "channel_manager.py to enable the playback-time fallback"
                )
            return None
        try:
            return resolver(station_id)
        except Exception as exc:  # defensive: never break live playback
            logger.warning(
                f"_feed_fallback_pid: entitled-feed fallback failed for "
                f"station {station_id}: {exc}"
            )
            return None

    def _post_smil_feed_fallback_drm(
        self, content_id: str, lookup_id: str
    ) -> Optional[List[DRMConfig]]:
        """
        Last-resort licence build for get_drm after the SMIL master path
        failed (raised or returned no config): re-resolve *content_id*
        (numeric station id only) through the entitled-channels feed
        fallback (generic distribution right) and direct-build the licence
        for the vouched release pid.

        Returns None when there is no fallback (non-numeric id, feed
        miss/failure/rate-limit, or the pid came back unvouched) — the
        caller then keeps the SMIL path's outcome (re-raise or empty
        list).  Only a VOUCHEd pid is ever built: pid-cache membership is
        the entitlement verification for the direct licence path, and
        callers cache non-empty DRM results.
        """
        if not content_id.isdigit():
            return None
        fallback_pid = self._feed_fallback_pid(content_id)
        if not fallback_pid or not self._channel_manager.is_entitled_live_pid(fallback_pid):
            return None
        logger.warning(
            f"get_drm: SMIL (master path) failed for {lookup_id}; building "
            f"licence directly from entitled-feed pid {fallback_pid} "
            "(may lack the SMIL path's session binding)"
        )
        return self._build_live_drm(fallback_pid)

    def _build_live_drm(self, content_id: str) -> List[DRMConfig]:
        """
        Build a Widevine DRMConfig directly for a live channel, bypassing SMIL.

        *content_id* must be an ENTITLED release pid — callers gate this on
        ``ChannelManager.is_entitled_live_pid`` (the entitled-feed
        verification), because a non-empty DRM result is cached upstream.
        """
        release_pid = content_id
        logger.debug(
            f"get_drm: building licence directly for live channel (releasePid: {release_pid})"
        )
        try:
            persona_token = self._ensure_authenticated()
            raw_jwt = extract_persona_jwt(persona_token)
            if not raw_jwt:
                logger.error("get_drm: failed to extract persona JWT")
                return []

            widevine_endpoint = (
                self._endpoint_manager.get_endpoint("widevine_license")
                if self._endpoint_manager
                else None
            )
            if not widevine_endpoint:
                logger.error("get_drm: no widevine_license endpoint available")
                return []

            account_uri = (
                self._provider_config.manifest.mpx.get_account_uri()
                if self._provider_config and self._provider_config.manifest
                else None
            ) or MAGENTA2_FALLBACK_ACCOUNT_URI

            licence_url = build_licence_url(
                widevine_endpoint=widevine_endpoint,
                release_pid=release_pid,
                persona_jwt=raw_jwt,
                account_uri=account_uri,
            )
            call_id = self._call_id() if self._call_id else None
            return [
                build_widevine_drm_config(
                    licence_url=licence_url,
                    # Subscriber-suffixed UA — matches what SmilManager.get_drm
                    # sends for the SMIL/VOD DRM path.
                    user_agent=self._ua_subscriber,
                    session_id=self._session_id,
                    call_id=call_id,
                )
            ]
        except Exception as exc:
            logger.error(f"get_drm: direct licence build failed for {content_id}: {exc}")
            return []

    def _inject_smil_base_url(self, content_id: str, kwargs: Dict) -> None:
        """
        If a recording manifest_script URL is cached for *content_id*, inject it
        as ``smil_base_url`` into *kwargs* so SmilManager can use it without the
        caller needing to know about it.
        """
        if "smil_base_url" not in kwargs and content_id in self._recording_url_cache:
            kwargs["smil_base_url"] = self._recording_url_cache[content_id]
            logger.debug(f"Injected smil_base_url from recording cache for {content_id}")

    @staticmethod
    def extract_persona_jwt_from_token(persona_token: str) -> Optional[str]:
        """
        Decode a Base64-encoded persona token and extract the raw JWT portion.

        The persona token format is: ``Base64(account_uri + ":" + persona_jwt)``.
        """
        try:
            decoded = base64.b64decode(persona_token).decode("utf-8")
            last_colon_index = decoded.rfind(":")
            if last_colon_index == -1:
                logger.error("No colon found in decoded persona token")
                return None
            persona_jwt = decoded[last_colon_index + 1:]
            if not persona_jwt.startswith("eyJ"):
                logger.error("Extracted token doesn't look like a JWT")
                return None
            return persona_jwt
        except Exception as e:
            logger.error(f"Error extracting persona JWT token: {e}")
            return None