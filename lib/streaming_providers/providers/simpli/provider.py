# streaming_providers/providers/simpli/provider.py
"""
simpliTV orchestrator.

Owns shared resources (http_manager, caches, auth, managers) and
exposes the public StreamingProvider interface.

Subclasses the existing StreamingProvider. Does NOT subclass any new
base class. Authentication is lazy -- no network I/O in __init__.

Manager wiring
--------------

    channels   -> SimpliTVChannelManager     (live:, rec:, prog: ids;
                                              folded DRM)
    vod        -> None                       (no browseable catalogue)
    epg        -> SimpliTVEpgManager         (anonymous; native grid)
    recordings -> SimpliTVRecordingsManager  (list, delete, schedule)
    favorites  -> None
    bookmarks  -> None
    catchup    -> SimpliTVCatchupManager     (catchup: ids; borrows channels)
    drm        -> None                       (folded into channels)

The catchup manager is built after the channel manager because it takes
the channel manager as a collaborator. No other manager has
cross-dependencies.

Routing
-------
_route is used only by get_manifest and get_drm -- the methods whose
input is an opaque content_id with several possible owners. The channel
manager owns live:, rec: and prog:; the catchup manager owns catchup:.
For catchup: the router parses the @<ts> suffix and hands the manager a
plain (content_id, start_time, end_time=None) triple. Malformed ids
raise BadRequestError and are not swallowed.

Restart-from-beginning cannot be expressed as a manifest URL (it needs a
player-side seek), so it has its own method: get_restart().

Catchup windows
---------------
The DVR window is per-channel (AdditionalInfo.Epg_TimeshiftSeconds in
the AcquireContent response: 2h, 3h or 4h in the browser capture).
SimpliTVCatchupManager reads the per-channel value inside
get_restart_manifest. Its catchup_window_hours property returns the
conservative minimum (2h) because the ABC can only express a single
integer.
"""

from typing import Any, Callable, ClassVar, Dict, List, Optional, Tuple

from ...base.errors import NotFoundError
from ...base.managers import ChannelManager, VodManager
from ...base.models.proxy_models import ProxyConfig
from ...base.protocols import DrmManagerProtocol
from ...base.provider import StreamingProvider

from .auth import SimpliTVAuth
from .catchup_manager import SimpliTVCatchupManager
from .channel_manager import SimpliTVChannelManager, parse_catchup_id
from .constants import SimpliTVConfig, SimpliTVDefaults
from .epg_manager import SimpliTVEpgManager
from .recordings_manager import SimpliTVRecordingsManager


class SimpliTVProvider(StreamingProvider):
    """simpliTV streaming provider."""

    PROVIDER_LABEL: ClassVar[str] = "simpliTV"
    PROVIDER_LOGO: ClassVar[str] = SimpliTVDefaults.PROVIDER_LOGO
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["user_credentials"]
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = ["AT"]

    # Only "live" and "vod" narrow the folded DRM search; anything else
    # (None, "event", "catchup", a typo) tries both domains.
    _LIVE_ONLY_CONTENT_TYPES = frozenset({"live"})
    _VOD_ONLY_CONTENT_TYPES = frozenset({"vod"})

    def __init__(
        self,
        country: str = "AT",
        config: Optional[Dict] = None,
        proxy_config: Optional[ProxyConfig] = None,
        settings_manager=None,
        credentials=None,
        **kwargs,
    ):
        super().__init__(country)

        self.config = SimpliTVConfig(config or {})

        # 1. HTTP manager.
        self.http_manager = self._setup_http_manager(
            provider_name=SimpliTVDefaults.PROVIDER_NAME,
            proxy_config=proxy_config,
            user_agent=self.config.user_agent,
            timeout=self.config.timeout,
        )

        # 2. Auth (lazy -- no network call in __init__).
        self._credentials = credentials
        self.auth = self._build_auth(settings_manager)

        # 3. Provider-owned caches. Managers borrow these by reference.
        self._channels_cache: Dict = {}
        self._playback_cache: Dict = {}
        self._recordings_cache: Dict = {}

        # 4. Managers, in dependency order. Catchup needs channels.
        self.channels = self._build_channels()
        self.vod = self._build_vod()
        self.epg = self._build_epg()
        self.recordings = self._build_recordings()
        self.favorites = self._build_favorites()
        self.bookmarks = self._build_bookmarks()
        self.catchup = self._build_catchup()
        self.drm = self._build_drm()

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    def _build_auth(self, settings_manager):
        return SimpliTVAuth(
            http_manager=self.http_manager,
            country=self.country,
            settings_manager=settings_manager,
            credentials=self._credentials,
            config=self.config,
        )

    def _build_channels(self):
        return SimpliTVChannelManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.config,
            channels_cache=self._channels_cache,
            playback_cache=self._playback_cache,
        )

    def _build_vod(self):
        # No browseable VOD catalogue: content is live, catchup, or
        # recordings.
        return None

    def _build_epg(self):
        return SimpliTVEpgManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.config,
        )

    def _build_recordings(self):
        return SimpliTVRecordingsManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.config,
            recordings_cache=self._recordings_cache,
        )

    def _build_favorites(self):
        return None  # no favorites endpoint

    def _build_bookmarks(self):
        return None  # no bookmarks / resume endpoint

    def _build_catchup(self):
        if self.channels is None:
            return None
        return SimpliTVCatchupManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.config,
            channels=self.channels,
        )

    def _build_drm(self) -> Optional[DrmManagerProtocol]:
        # Folded into SimpliTVChannelManager -- the manifest and DRM
        # share one /Player/AcquireContent response.
        return None

    # ------------------------------------------------------------------
    # Capability flags
    # ------------------------------------------------------------------

    @property
    def implements_channels(self) -> bool:
        return self.channels is not None

    @property
    def implements_vod(self) -> bool:
        return self.vod is not None

    @property
    def implements_epg(self) -> bool:
        return self.epg is not None

    @property
    def implements_recordings(self) -> bool:
        return self.recordings is not None

    @property
    def implements_favorites(self) -> bool:
        return self.favorites is not None

    @property
    def implements_bookmarks(self) -> bool:
        return self.bookmarks is not None

    @property
    def implements_catchup(self) -> bool:
        return self.catchup is not None

    @property
    def implements_drm(self) -> bool:
        if self.drm is not None:
            return True
        folded_channels = (
            self.channels is not None
            and type(self.channels).get_channel_drm
            is not ChannelManager.get_channel_drm
        )
        folded_vod = (
            self.vod is not None
            and type(self.vod).get_vod_drm
            is not VodManager.get_vod_drm
        )
        return folded_channels or folded_vod

    # ------------------------------------------------------------------
    # Router
    # ------------------------------------------------------------------

    def _route(self, content_id: str, attempts: List[Tuple[Any, Callable]]):
        """
        Try managers in order, skipping those whose handles_content_id()
        rejects the id. Used only by get_manifest / get_drm.

        NotFoundError is remembered and re-raised if nobody else
        resolves the id ("existed but is gone" vs "nobody handles it").
        BadRequestError is not caught: a malformed id surfaces.
        """
        last_not_found: Optional[NotFoundError] = None
        for manager, call in attempts:
            if manager is None or not manager.handles_content_id(content_id):
                continue
            try:
                result = call(manager)
            except NotFoundError as e:
                last_not_found = e
                continue
            if result:
                return result
        if last_not_found is not None:
            raise last_not_found
        return None

    # ------------------------------------------------------------------
    # Manifest routing
    # ------------------------------------------------------------------

    def get_manifest(self, content_id: str, **kw) -> Optional[str]:
        """
        Route content_id to the right manager.

            live:<codename>              -> channel manager
            rec:<programme codename>     -> channel manager
            prog:<programme codename>    -> channel manager
            catchup:<channel>@<ts>       -> catchup manager, @<ts> parsed
                                            here into start_time. Yields a
                                            manifest only for programme
                                            replay (epg_id in kw); for
                                            restart use get_restart().
        """
        if content_id.startswith(SimpliTVDefaults.CATCHUP_PREFIX):
            if self.catchup is None:
                return None
            _, start_ts = parse_catchup_id(content_id)  # raises if bad
            return self.catchup.get_catchup_manifest(
                content_id, start_ts, None, **kw
            )

        return self._route(content_id, [
            (self.channels, lambda m: m.get_channel_manifest(
                content_id, **kw
            )),
            (self.vod, lambda m: m.get_vod_manifest(content_id, **kw)),
        ])

    def get_restart(
        self, content_id: str, start_time: int = 0, **kw
    ) -> Optional[Tuple[str, int]]:
        """
        Restart a programme from its beginning.

        Returns (live manifest URL, seek_seconds from the start of the
        channel's DVR window) or None when the programme began outside
        that window. The window is per-channel (see "Catchup windows"
        above). The caller must seek; the URL alone plays live.
        """
        if self.catchup is None:
            return None
        return self.catchup.get_restart_manifest(content_id, start_time)

    # ------------------------------------------------------------------
    # DRM routing
    # ------------------------------------------------------------------

    def get_drm(
        self,
        content_id: str,
        content_type: Optional[str] = None,
        **kw,
    ) -> List:
        """
        DRM for the given content.

        content_type is an optional narrowing hint ("live"/"vod" only;
        anything else tries both). catchup: ids go to the catchup
        manager, which forwards to the channel manager's DRM.
        """
        if self.drm is not None:
            return self.drm.get_drm_configs(
                content_id, content_type=content_type, **kw
            )

        if content_id.startswith(SimpliTVDefaults.CATCHUP_PREFIX):
            if self.catchup is None:
                return []
            _, start_ts = parse_catchup_id(content_id)  # raises if bad
            return self.catchup.get_catchup_drm(
                content_id, start_ts, None, **kw
            )

        attempts: List[Tuple[Any, Callable]] = []
        if content_type not in self._VOD_ONLY_CONTENT_TYPES:
            attempts.append(
                (self.channels, lambda m: m.get_channel_drm(
                    content_id, **kw
                ))
            )
        if content_type not in self._LIVE_ONLY_CONTENT_TYPES:
            attempts.append(
                (self.vod, lambda m: m.get_vod_drm(content_id, **kw))
            )
        return self._route(content_id, attempts) or []

    # ------------------------------------------------------------------
    # Channels
    # ------------------------------------------------------------------

    def get_channels(self, **kw):
        if self.channels is None:
            return []
        return self.channels.get_channels(**kw)