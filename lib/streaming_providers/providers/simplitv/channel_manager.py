# streaming_providers/providers/simplitv/channel_manager.py
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
"""

import threading
import time
from typing import Any, Dict, List, Optional

from ...base.errors import BadRequestError, NotFoundError
from ...base.managers import ChannelManager
from ...base.models import Channel
from ...base.models.drm_models import DRMConfig, DRMSystem, LicenseConfig
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

        The tile endpoint yields only codenames (the existing addon reads
        nothing else from it, and only from the first group), so names
        and logos are derived locally -- see logos.py. EPG metadata is
        not fetched here; that keeps this call independent of EPG
        availability.
        """
        # NOTE: token is in the body (auth_body), not a header.
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

        DRM-protected streams are rewritten to DASH (what
        inputstream.adaptive needs); unprotected streams keep the HLS URL
        the API returned.

        The returned URL does NOT contain the API token (it was only used
        for the AcquireContent request), and manifest/segment requests
        need just a User-Agent -- see get_channel_manifest_headers().
        """
        codename = codename_from_playable_id(content_id)

        # A new playback: always a fresh response (licence data may be
        # session bound); get_channel_drm then reads it from the cache.
        acquire = self.acquire_content(codename, refresh=True)

        try:
            manifest_url = acquire["MediaFiles"][0]["Formats"][0]["Url"]
        except (KeyError, IndexError, TypeError):
            raise NotFoundError(
                f"simpliTV: no manifest in AcquireContent for {codename!r}"
            )

        if acquire.get("DrmInfo"):
            manifest_url = prefer_dash(manifest_url)
        return manifest_url

    # ------------------------------------------------------------------
    # Player request headers
    # ------------------------------------------------------------------
    # The base layer's method names for these hooks were not available
    # when this was written; the names below follow the review of the
    # package. If the base calls different names, rename accordingly --
    # until then these are simply unused.

    def get_channel_manifest_headers(self, content_id: str, **kw) -> dict:
        """User-Agent only -- see SimpliTVConfig.get_stream_headers()."""
        return self.config.get_stream_headers()

    def get_segment_headers(self, content_id: str, **kw) -> dict:
        """User-Agent only: the CDN does not authenticate segments."""
        return self.config.get_stream_headers()

    # ------------------------------------------------------------------
    # DRM (folded -- shares the AcquireContent response with the manifest)
    # ------------------------------------------------------------------

    def get_channel_drm(
        self, content_id: str, **kw
    ) -> List[DRMConfig]:
        """
        Return DRM for a live:, rec: or prog: content id.

        Reads the response cached by get_channel_manifest when it is
        still fresh, otherwise fetches it.
        """
        codename = codename_from_playable_id(content_id)
        acquire = self.acquire_content(codename)

        drm_info = acquire.get("DrmInfo") or []
        if not drm_info:
            # Unprotected content is not a failure: [] per the
            # None-vs-exception rule.
            return []

        wanted = (
            SimpliTVDefaults.DRM_INDEX_PLAYREADY
            if self.config.prefer_playready
            else SimpliTVDefaults.DRM_INDEX_WIDEVINE
        )
        if wanted < len(drm_info):
            index = wanted
        else:
            # Requested scheme isn't offered; some assets are
            # single-scheme, so use what is there.
            index = 0
        system = (
            DRMSystem.PLAYREADY
            if index == SimpliTVDefaults.DRM_INDEX_PLAYREADY
            else DRMSystem.WIDEVINE
        )

        entry = drm_info[index]
        license_url = entry.get("LicenseServerUrl")
        if not license_url:
            return []
        challenge = entry.get("DrmChallengeCustomData")

        return [
            DRMConfig(
                system=system,
                priority=1,
                license=LicenseConfig(
                    server_url=license_url,
                    req_headers=self.config.get_license_headers(challenge),
                    # Body = the raw CDM challenge (the addon's R{SSM}).
                    req_data="{CHA-RAW}",
                    use_http_get_request=False,
                ),
            )
        ]

    # ------------------------------------------------------------------
    # AcquireContent (shared with SimpliTVCatchupManager via this class)
    # ------------------------------------------------------------------

    def acquire_content(
        self, codename: str, *, refresh: bool = False
    ) -> Dict[str, Any]:
        """
        GET /Player/AcquireContent for a codename.

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
        # NOTE: token is in the URL (via with_token), not a header. It
        # authenticates THIS request only; the manifest URL returned in
        # the response does not carry it.
        url = self.auth.with_token(
            self.config.acquire_content_url(),
            {
                "platformCodename": self.config.platform_codename,
                "deviceKey": self.auth.get_device_key(),
                "codename": codename,
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

    The @<ts> suffix is required -- a bare catchup:<channel> is a grammar
    error, not a live id in disguise.
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
    broadcast_id (simplitv:<channel>:<start>:<programme>), a prog: id, or
    the bare programme codename.
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
