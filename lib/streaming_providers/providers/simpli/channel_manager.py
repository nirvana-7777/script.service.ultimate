# streaming_providers/providers/simpli/channel_manager.py
"""
simpliTV channel manager.

Content-id grammar (authoritative for everything played through
/Player/AcquireContent):

    live:<channel codename>      live channel
    rec:<programme codename>     a recorded programme
    prog:<programme codename>    an EPG programme (replay)

All three resolve to the same AcquireContent call -- the API shares one
codename namespace between channels and programmes. The distinction is
semantic (what the caller means by the id), not mechanical.

Catchup ids (catchup:<channel>@<unix_ts>) are handled by
SimpliTVCatchupManager and rejected here, so the router can dispatch
without a wasted AcquireContent call.

Manifest and DRM are folded into this manager because both arrive in one
AcquireContent response (README: DRM shares state with the manifest step,
so it folds). The response is cached briefly so the manifest and DRM
steps of one playback share a single request.

Format selection
----------------
The AcquireContent response carries DASH (Type 9) and/or HLS (Type 2)
entries. Protected content prefers DASH (inputstream.adaptive needs it
for Widevine/PlayReady; PSSH extraction is more reliable). Unprotected
content prefers HLS, which is what the CDN has always served the addon.
prefer_dash() runs only when a protected asset offers no DASH entry.
"""

import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from ...base.errors import BadRequestError, NotFoundError
from ...base.managers import ChannelManager
from ...base.models import Channel
from ...base.models.drm_config import DRMConfig
from ...base.models.drm_systems import DRMSystem
from ...base.models.license_config import LicenseConfig
from ...base.utils.logger import logger

from .constants import SimpliTVDefaults
from .helpers import prefer_dash, transport_errors
from .logos import channel_name_from_codename, logo_for_name
from .models import SimpliTVChannel


class SimpliTVChannelManager(ChannelManager):
    """Fetches live channels, manifests and DRM for simpliTV."""

    def __init__(
        self,
        *,
        http_manager,
        auth,
        country,
        config,
        channels_cache: Optional[Dict] = None,
        playback_cache: Optional[Dict] = None,
    ):
        super().__init__(
            http_manager=http_manager,
            auth=auth,
            country=country,
            config=config,
        )
        self._channels_cache = (
            channels_cache if channels_cache is not None else {}
        )
        # codename -> (expires_at, AcquireContent response)
        self._playback_cache = (
            playback_cache if playback_cache is not None else {}
        )
        self._cache_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def handles_content_id(self, content_id: str) -> bool:
        return content_id.startswith((
            SimpliTVDefaults.LIVE_PREFIX,
            SimpliTVDefaults.RECORDING_PREFIX,
            SimpliTVDefaults.PROGRAMME_PREFIX,
        ))

    # ------------------------------------------------------------------
    # Channels
    # ------------------------------------------------------------------

    def get_channels(self, **kw) -> List[Channel]:
        """
        Return the channel list.

        The tile endpoint yields only codenames, so names and logos are
        derived locally -- see logos.py. EPG metadata is not fetched
        here; that keeps this call independent of EPG availability.

        NOTE: token is in the body (auth_body), not a header. The
        `$headers` query string is baked into channel_tiles_url().
        """
        body = self.auth.auth_body({
            "isParentalControlEnabled": "false",
            "platformCodename": self.config.platform_codename,
        })
        resp = self.http_manager.post(
            self.config.channel_tiles_url(),
            json=body,
            headers=self.config.get_api_headers(),
        )
        groups = resp.json().get("channels") or []
        tiles = groups[0].get("tiles", []) if groups else []

        channels: List[Channel] = []
        seen = set()
        for tile in tiles:
            codename = tile.get("codename")
            if not codename or codename in seen:
                continue
            seen.add(codename)
            channels.append(self._channel_from_codename(codename))
        return channels

    @staticmethod
    def _channel_from_codename(codename: str) -> SimpliTVChannel:
        name = channel_name_from_codename(codename)
        return SimpliTVChannel(
            channel_id=f"{SimpliTVDefaults.LIVE_PREFIX}{codename}",
            name=name,
            codename=codename,
            logo_url=logo_for_name(name),
        )

    # ------------------------------------------------------------------
    # Manifest
    # ------------------------------------------------------------------

    def get_channel_manifest(
        self, content_id: str, **kw
    ) -> Optional[str]:
        """
        Return the manifest for a live:, rec: or prog: content id.

        Protected content prefers DASH, unprotected content prefers
        HLS. If a protected asset has no DASH entry, prefer_dash() is
        applied to the URL that was selected.

        The returned URL does NOT contain the API token (it was only
        used for the AcquireContent request), and manifest/segment
        requests need just a User-Agent -- see
        SimpliTVConfig.get_stream_headers().
        """
        codename = codename_from_playable_id(content_id)

        # A new playback: always a fresh response (licence data may be
        # session bound); get_channel_drm then reads it from the cache.
        acquire = self.acquire_content(codename, refresh=True)

        try:
            formats = acquire["MediaFiles"][0]["Formats"]
        except (KeyError, IndexError, TypeError):
            raise NotFoundError(
                f"simpliTV: no media files in AcquireContent for "
                f"{codename!r}"
            )

        protected = bool(acquire.get("DrmInfo"))
        manifest_url, fmt_type = _select_format(formats, protected=protected)
        if not manifest_url:
            raise NotFoundError(
                f"simpliTV: no manifest URL in AcquireContent for "
                f"{codename!r}"
            )

        # Protected asset without a DASH entry: rewrite to the DASH
        # equivalent. Never applied to unprotected content.
        if protected and fmt_type != SimpliTVDefaults.FORMAT_TYPE_DASH:
            manifest_url = prefer_dash(manifest_url)
        return manifest_url

    # ------------------------------------------------------------------
    # Player request headers
    # ------------------------------------------------------------------

    def get_channel_manifest_headers(self, content_id: str, **kw) -> dict:
        """User-Agent + Origin -- see SimpliTVConfig.get_stream_headers()."""
        return self.config.get_stream_headers()

    def get_segment_headers(self, content_id: str, **kw) -> dict:
        """User-Agent + Origin: the CDN does not authenticate segments."""
        return self.config.get_stream_headers()

    # ------------------------------------------------------------------
    # DRM (folded -- shares the AcquireContent response with the manifest)
    # ------------------------------------------------------------------

    def get_channel_drm(
        self, content_id: str, **kw
    ) -> List[DRMConfig]:
        """
        Return DRM configs for a live:, rec: or prog: content id.

        Both Widevine (priority 1) and PlayReady (priority 2) are
        returned when the AcquireContent response advertises them.
        inputstream.adaptive selects whichever CDM the platform
        actually supports, so the priority ordering is safe on a
        PlayReady-only device. FairPlay is ignored: Kodi cannot play
        it.

        Reads the response cached by get_channel_manifest when it is
        still fresh, otherwise fetches it. Unprotected content returns
        [] (per the None-vs-exception rule).
        """
        codename = codename_from_playable_id(content_id)
        acquire = self.acquire_content(codename)

        drm_info = acquire.get("DrmInfo") or []
        if not drm_info:
            return []

        # Index by DrmSystem string, not position: the server may add
        # or reorder systems.
        by_system: Dict[str, dict] = {}
        for entry in drm_info:
            name = entry.get("DrmSystem")
            if name and name not in by_system:
                by_system[name] = entry

        configs: List[DRMConfig] = []

        widevine = by_system.get(SimpliTVDefaults.DRM_SYSTEM_WIDEVINE)
        if widevine and widevine.get("LicenseServerUrl"):
            configs.append(self._build_drm_config(
                system=DRMSystem.WIDEVINE,
                priority=SimpliTVDefaults.DRM_PRIORITY_WIDEVINE,
                entry=widevine,
            ))

        playready = by_system.get(SimpliTVDefaults.DRM_SYSTEM_PLAYREADY)
        if playready and playready.get("LicenseServerUrl"):
            configs.append(self._build_drm_config(
                system=DRMSystem.PLAYREADY,
                priority=SimpliTVDefaults.DRM_PRIORITY_PLAYREADY,
                entry=playready,
            ))

        return configs

    def _build_drm_config(
        self,
        *,
        system: DRMSystem,
        priority: int,
        entry: dict,
    ) -> DRMConfig:
        """
        Build one DRMConfig from a single DrmInfo entry.

        The challenge custom data is passed *raw* (base64) in the
        `drmchallengecustomdata` header, matching the browser capture.
        It is deliberately not URL-quoted here.

        UNVERIFIED: whether the host's LicenseConfig / inputstream
        .adaptive serialisation of req_headers preserves `+`, `/` and
        `=` unchanged cannot be determined from this package. Check on
        a real device (a mangled value shows up as a licence-server
        4xx); if it is altered, the quoting belongs in LicenseConfig,
        not here.

        The licence body is the raw CDM challenge, injected by ISA via
        the {CHA-RAW} placeholder (see SimpliTVDefaults.REQ_DATA_CHA_RAW).
        """
        challenge = entry.get("DrmChallengeCustomData")

        return DRMConfig(
            system=system,
            priority=priority,
            license=LicenseConfig(
                server_url=entry["LicenseServerUrl"],
                req_headers=self.config.get_license_headers(challenge),
                req_data=SimpliTVDefaults.REQ_DATA_CHA_RAW,
                use_http_get_request=False,
            ),
        )

    # ------------------------------------------------------------------
    # AcquireContent (shared with SimpliTVCatchupManager via this class)
    # ------------------------------------------------------------------

    def acquire_content(
        self, codename: str, *, refresh: bool = False
    ) -> Dict[str, Any]:
        """
        GET /Player/AcquireContent for a codename.

        The request carries the token, the device key, the platform
        codename, and a millisecond cache-buster `t=` -- all in the
        query string. There is NO `$headers` parameter on this
        endpoint.

        Responses are cached for PLAYBACK_CACHE_TTL seconds so the
        manifest and DRM steps of one playback make one request;
        refresh=True bypasses the cache (and repopulates it).
        """
        if not refresh:
            cached = self._cache_get(codename)
            if cached is not None:
                return cached

        logger.debug(
            f"simpliTV: AcquireContent {codename!r} (refresh={refresh})"
        )
        url = self.auth.with_token(
            self.config.acquire_content_url(),
            {
                "platformCodename": self.config.platform_codename,
                "deviceKey": self.auth.get_device_key(),
                "codename": codename,
                "t": int(time.time() * 1000),
            },
        )
        with transport_errors(f"AcquireContent for {codename!r}"):
            resp = self.http_manager.get(
                url, headers=self.config.get_manifest_headers()
            )
            data = resp.json()

        self._cache_put(codename, data)
        return data

    # ------------------------------------------------------------------
    # Playback cache (TTL + size bound)
    # ------------------------------------------------------------------

    def _cache_get(self, codename: str) -> Optional[Dict[str, Any]]:
        with self._cache_lock:
            item = self._playback_cache.get(codename)
            if item is None:
                return None
            expires_at, data = item
            if expires_at <= time.monotonic():
                del self._playback_cache[codename]
                return None
            return data

    def _cache_put(self, codename: str, data: Dict[str, Any]) -> None:
        now = time.monotonic()
        with self._cache_lock:
            if len(self._playback_cache) >= SimpliTVDefaults.PLAYBACK_CACHE_MAX:
                for key in [
                    k for k, (exp, _) in self._playback_cache.items()
                    if exp <= now
                ]:
                    del self._playback_cache[key]
                if len(self._playback_cache) >= SimpliTVDefaults.PLAYBACK_CACHE_MAX:
                    logger.debug(
                        "simpliTV: playback cache full of live entries, "
                        "clearing"
                    )
                    self._playback_cache.clear()
            self._playback_cache[codename] = (
                now + SimpliTVDefaults.PLAYBACK_CACHE_TTL, data,
            )


# ----------------------------------------------------------------------
# AcquireContent format selection
# ----------------------------------------------------------------------

def _select_format(
    formats: List[dict], *, protected: bool
) -> Tuple[Optional[str], Optional[int]]:
    """
    Return (manifest URL, format Type) from a Formats array.

    Protected content prefers DASH (Type 9), then HLS (Type 2).
    Unprotected content prefers HLS, then DASH. The first entry with a
    URL is a final fallback (its Type is returned as-is, possibly
    None). Array order is never assumed.
    """
    if protected:
        order = (
            SimpliTVDefaults.FORMAT_TYPE_DASH,
            SimpliTVDefaults.FORMAT_TYPE_HLS,
        )
    else:
        order = (
            SimpliTVDefaults.FORMAT_TYPE_HLS,
            SimpliTVDefaults.FORMAT_TYPE_DASH,
        )
    for wanted in order:
        for fmt in formats:
            if fmt.get("Type") == wanted and fmt.get("Url"):
                return fmt["Url"], wanted
    for fmt in formats:
        if fmt.get("Url"):
            return fmt["Url"], fmt.get("Type")
    return None, None


# ----------------------------------------------------------------------
# Content-id grammar -- module scope so every manager can import the
# parsers without circular dependencies. All raise BadRequestError on
# malformed input; the router does not catch it.
# ----------------------------------------------------------------------

def _strip_prefix(content_id: str, prefix: str, kind: str) -> str:
    if not content_id.startswith(prefix):
        raise BadRequestError(f"simpliTV: not a {kind} id: {content_id!r}")
    value = content_id[len(prefix):]
    if not value:
        raise BadRequestError(
            f"simpliTV: {kind} id missing codename: {content_id!r}"
        )
    return value


def parse_live_id(content_id: str) -> str:
    """Codename from live:<channel codename>."""
    return _strip_prefix(content_id, SimpliTVDefaults.LIVE_PREFIX, "live")


def parse_recording_id(content_id: str) -> str:
    """Programme codename from rec:<programme codename>."""
    return _strip_prefix(
        content_id, SimpliTVDefaults.RECORDING_PREFIX, "recording"
    )


def parse_programme_id(content_id: str) -> str:
    """Programme codename from prog:<programme codename>."""
    return _strip_prefix(
        content_id, SimpliTVDefaults.PROGRAMME_PREFIX, "programme"
    )


def parse_catchup_id(content_id: str):
    """
    Return (channel codename, start_ts) from catchup:<channel>@<unix_ts>.

    The @<ts> suffix is required -- a bare catchup:<channel> is a
    grammar error, not a live id in disguise.
    """
    rest = _strip_prefix(
        content_id, SimpliTVDefaults.CATCHUP_PREFIX, "catchup"
    )
    codename, sep, ts = rest.partition(SimpliTVDefaults.CATCHUP_TS_SEPARATOR)
    if not sep or not codename:
        raise BadRequestError(
            f"simpliTV: catchup id must be "
            f"catchup:<codename>{SimpliTVDefaults.CATCHUP_TS_SEPARATOR}<ts>: "
            f"{content_id!r}"
        )
    try:
        return codename, int(ts)
    except ValueError:
        raise BadRequestError(f"simpliTV: catchup ts not an int: {ts!r}")


def codename_from_playable_id(content_id: str) -> str:
    """
    Codename for a live:, rec: or prog: id (all share one namespace).

    Raises BadRequestError for any other prefix, so a malformed call
    surfaces rather than silently mis-fetching.
    """
    if content_id.startswith(SimpliTVDefaults.LIVE_PREFIX):
        return parse_live_id(content_id)
    if content_id.startswith(SimpliTVDefaults.RECORDING_PREFIX):
        return parse_recording_id(content_id)
    if content_id.startswith(SimpliTVDefaults.PROGRAMME_PREFIX):
        return parse_programme_id(content_id)
    raise BadRequestError(
        f"simpliTV: not a live/rec/prog id: {content_id!r}"
    )


def programme_codename_from_epg_id(epg_id: str) -> str:
    """
    Programme codename from whatever the host passes as epg_id: an EPG
    broadcast_id (simpli:<channel>:<start>:<programme>), a prog: id,
    or the bare programme codename.
    """
    if not epg_id:
        raise BadRequestError("simpliTV: empty epg_id")
    if epg_id.startswith(SimpliTVDefaults.BROADCAST_ID_PREFIX):
        parts = epg_id.split(":", 3)
        if len(parts) != 4 or not parts[3]:
            raise BadRequestError(
                f"simpliTV: malformed broadcast id: {epg_id!r}"
            )
        return parts[3]
    if epg_id.startswith(SimpliTVDefaults.PROGRAMME_PREFIX):
        return parse_programme_id(epg_id)
    return epg_id