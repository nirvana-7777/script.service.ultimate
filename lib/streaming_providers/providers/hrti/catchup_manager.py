# streaming_providers/providers/hrti/catchup_manager.py
"""
HRTi catchup manager (nPVR / "thepg" playback).

Flow, as observed in the web client (browser log):

  1. GetProgramme      -> programme ReferenceID for (channel, start_time)
  2. GetEpgDetails     -> FileName = https://<cdn>/hrtnpvrorigin/<REF>.smil/manifest.mpd
  3. AuthorizeSession  ContentType        "thepg"
                       ContentReferenceId <REF>                 (EPG ReferenceID)
                       ContentDrmId       "hrtnpvrorigin_<REF>.smil"
                       ChannelReferenceId <channel id>
                       StartTime/EndTime  /Date(ms)/ of the PROGRAMME
                       -> {Authorized, DrmId, SessionId}
  4. manifest = FileName, DRM = DRMToday Widevine with the upfront token built
     from the authorised session's DrmId (same as live / VOD).

ContentReferenceId / ContentDrmId are derived from FileName with the same
rule as VOD (drm.derive_vod_session_params), so no second grammar is needed.

Catchup DRM is NOT "PSSH from the manifest": the licence is bound to the
authorised thepg session, so get_catchup_drm() must return the session-bound
config itself (returning [] would send the DRM pipeline down the generic
PSSH-extraction path, which cannot produce a valid upfront token).

Return conventions (CatchupManager ABC): None when no catchup can be resolved
(no programme at start_time, no FileName); never a live-URL fallback.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from ...base.errors import EntitlementError
from ...base.managers.catchup import CatchupManager
from ...base.models import DRMConfig
from ...base.utils.logger import logger
from .constants import HRTiDefaults
from .drm import build_widevine, derive_vod_session_params

_CATCHUP_REFERER = "/live/programme"

# Programmes are looked up in [start - _LOOKBACK, start + _LOOKAHEAD]; the
# entry covering start_time is picked from the answer.
_LOOKBACK = timedelta(hours=6)
_LOOKAHEAD = timedelta(minutes=1)


def _epoch(value: Any) -> Optional[int]:
    """EPGEntry start/end -> Unix seconds (int / float / datetime tolerated)."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return int(value.timestamp())
    if isinstance(value, (int, float)):
        return int(value)
    return None


_DATE_RE = re.compile(r"/Date\((\d+)\)/")


def _wcf_epoch(value: Any) -> Optional[int]:
    """"/Date(ms)/" (GetEpgDetails TimeStart / TimeEnd) -> Unix seconds."""
    match = _DATE_RE.search(value) if isinstance(value, str) else None
    return int(match.group(1)) // 1000 if match else None


def _wcf_date(epoch_seconds: int) -> str:
    return f"/Date({int(epoch_seconds) * 1000})/"


class HRTiCatchupManager(CatchupManager):

    def __init__(
        self,
        *,
        http_manager: Any,
        auth: Any,
        country: str,
        config: Any,
        epg: Any,
        playout_cache: Optional[Dict[str, Tuple[Any, float]]] = None,
    ) -> None:
        super().__init__(
            http_manager=http_manager, auth=auth, country=country, config=config
        )
        self._epg = epg
        # Provider-owned dict, borrowed by reference (cleared on credential
        # change). Keys: "catchupres:<ch>:<start>" and "catchupsess:<ref>".
        self._playout_cache = playout_cache if playout_cache is not None else {}

    # ------------------------------------------------------------------
    # Capability
    # ------------------------------------------------------------------
    @property
    def catchup_window_hours(self) -> int:
        return self._epg.PAST_DAYS * 24

    # ------------------------------------------------------------------
    # Resolution: (channel, start_time) -> programme + FileName
    # ------------------------------------------------------------------
    def _cached(self, key: str) -> Optional[Any]:
        hit = self._playout_cache.get(key)
        if hit and (time.time() - hit[1]) < HRTiDefaults.PLAYOUT_CACHE_TTL:
            return hit[0]
        return None

    def _resolve(
        self, content_id: str, start_time: int, epg_id: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        key = f"catchupres:{content_id}:{start_time}"
        cached = self._cached(key)
        if cached is not None:
            return cached

        start_dt = datetime.fromtimestamp(start_time, tz=timezone.utc)
        entries = self._epg.get_epg(
            content_id,
            start_time=start_dt - _LOOKBACK,
            end_time=start_dt + _LOOKAHEAD,
        )

        entry = None
        if epg_id:                                   # exact id wins when it matches
            entry = next((e for e in entries if str(e.program_id) == str(epg_id)), None)
        if entry is None:
            for e in entries:
                s, en = _epoch(e.start), _epoch(e.end)
                if s is not None and en is not None and s <= start_time < en:
                    entry = e
                    break
        if entry is None or not entry.program_id:
            logger.warning(
                f"HRTi catchup: no programme on channel {content_id} at {start_time}"
            )
            return None

        raw = self._epg.get_epg_details(content_id, str(entry.program_id))
        if not raw:
            logger.warning(
                f"HRTi catchup: no EPG details for programme {entry.program_id}"
            )
            return None

        file_name = raw.get("FileName") or ""
        logger.debug(
            f"HRTi catchup: programme {entry.program_id} FileName={file_name!r} "
            f"HistoricEPG={raw.get('HistoricEPG')!r} Npvr={raw.get('Npvr')!r}"
        )
        # Do NOT gate on Npvr: it is False even for playable catchup (observed).
        # FileName is the only availability signal; FileNameStartOver is a
        # live-DVR URL (a different feature) and is deliberately not used.
        if not file_name:
            return None                              # not (yet / any longer) available

        resolved = {
            "reference_id": str(entry.program_id),
            "file_name": file_name,
            # Programme bounds exactly as the web client sends them to
            # AuthorizeSession (verified: details TimeStart/TimeEnd == the
            # request's StartTime/EndTime); the grid entry is the fallback.
            "start": _wcf_epoch(raw.get("TimeStart")) or _epoch(entry.start),
            "end": _wcf_epoch(raw.get("TimeEnd")) or _epoch(entry.end),
        }
        self._playout_cache[key] = (resolved, time.time())
        return resolved

    # ------------------------------------------------------------------
    # Authorised thepg session (shared by manifest and DRM)
    # ------------------------------------------------------------------
    def _session(self, content_id: str, resolved: Dict[str, Any]) -> Dict[str, Any]:
        ref = resolved["reference_id"]
        key = f"catchupsess:{ref}"
        cached = self._cached(key)
        if cached is not None:
            return cached

        params = derive_vod_session_params(resolved["file_name"])
        session_data = self.auth.authorize_session(
            content_type="thepg",
            content_ref_id=params.content_ref_id,
            content_drm_id=params.content_drm_id,
            video_store_ids=None,
            channel_id=content_id,
            start_time=_wcf_date(resolved["start"]),
            end_time=_wcf_date(resolved["end"]),
        )
        if not session_data.get("Authorized", False):
            raise EntitlementError(
                f"HRTi: catchup session for programme {ref} was not authorised"
            )
        session_id = session_data.get("SessionId")
        if session_id:
            self.auth.report_session_event(session_id, content_id)   # best effort
        self._playout_cache[key] = (session_data, time.time())
        return session_data

    # ------------------------------------------------------------------
    # ABC
    # ------------------------------------------------------------------
    def get_catchup_manifest(
        self,
        content_id: str,
        start_time: int,
        end_time: Optional[int] = None,     # ignored: the programme bounds come from the EPG
        epg_id: Optional[str] = None,
        **kw: Any,
    ) -> Optional[str]:
        resolved = self._resolve(content_id, int(start_time), epg_id)
        if not resolved:
            return None
        self._session(content_id, resolved)          # authorise first, like live
        return resolved["file_name"]

    def get_catchup_drm(
        self,
        content_id: str,
        start_time: int,
        end_time: Optional[int] = None,
        epg_id: Optional[str] = None,
        **kw: Any,
    ) -> List[DRMConfig]:
        resolved = self._resolve(content_id, int(start_time), epg_id)
        if not resolved:
            return []
        session_data = self._session(content_id, resolved)
        return build_widevine(
            self.config,
            self.auth.user_id,
            session_data,
            content_id,
            referer_path=_CATCHUP_REFERER,
        )

    # v1 / live send {} for manifest and segments (HEADERS_FROM_MANAGERS = False);
    # same CDN family, so keep {} -- and do not depend on auth.build_headers(),
    # which HRTiSession does not necessarily provide.
    def get_catchup_manifest_headers(self, *a: Any, **kw: Any) -> Dict[str, str]:
        return {}

    def get_catchup_segment_headers(self, *a: Any, **kw: Any) -> Dict[str, str]:
        return {}

    def clear_caches(self) -> None:
        for key in [k for k in self._playout_cache if k.startswith("catchup")]:
            self._playout_cache.pop(key, None)