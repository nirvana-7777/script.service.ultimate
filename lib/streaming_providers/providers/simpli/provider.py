# streaming_providers/providers/simpli/provider.py
"""
simpliTV orchestrator.

Owns shared resources (http_manager, caches, auth) and builds the
managers; everything that is identical across manager-based providers
(capability flags, content-id routing, manifest/DRM/header/EPG delegation,
the legacy recordings/catchup surface) lives in ManagedProvider.

Subclasses ManagedProvider (itself a StreamingProvider). Authentication
is lazy -- no network I/O in __init__.

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
    drm        -> None                       (DRM_IN_MANAGERS = True)

The catchup manager is built after the channel manager because it takes
the channel manager as a collaborator (_init_managers builds in
dependency order). No other manager has cross-dependencies.

What stays here
---------------
Only grammar that belongs to simpliTV: the catchup:<channel>@<ts> id.
get_manifest and get_drm hand catchup: ids to the catchup manager (the
@<ts> suffix is parsed here into start_time); every other id goes to
ManagedProvider's router. Malformed ids raise BadRequestError and are not
swallowed.

Restart-from-beginning cannot be expressed as a manifest URL (it needs a
player-side seek), so it has its own method: get_restart().

Catchup windows
---------------
The DVR window is per-channel (AdditionalInfo.Epg_TimeshiftSeconds in
the AcquireContent response: 2h, 3h or 4h in the browser capture).
SimpliTVCatchupManager.catchup_window_hours is the provider-wide maximum
(what the backend's validate_catchup_request sees), and
catchup_window_for_channel() / get_restart_manifest() apply the real
per-channel value.

Headers
-------
HEADERS_FROM_MANAGERS = True: manifest and segment requests carry the
managers' headers (User-Agent + Origin, SimpliTVConfig.get_stream_headers).
The previous provider returned {} because it never overrode
get_manifest_headers, which made those manager hooks dead code. Set the
flag to False to restore the old {}.
"""

from typing import ClassVar, Dict, List, Optional, Tuple

from ...base.managed_provider import ManagedProvider
from ...base.models.proxy_models import ProxyConfig

from .auth import SimpliTVAuth
from .catchup_manager import SimpliTVCatchupManager
from .channel_manager import SimpliTVChannelManager, parse_catchup_id
from .constants import SimpliTVConfig, SimpliTVDefaults
from .epg_manager import SimpliTVEpgManager
from .recordings_manager import SimpliTVRecordingsManager

# Only the provider is public: provider discovery (streaming_providers/
# __init__.py) takes the first StreamingProvider subclass it finds in the
# package namespace, and ManagedProvider must never be that one.
__all__ = ["SimpliTVProvider"]


class SimpliTVProvider(ManagedProvider):
    """simpli streaming provider."""

    PROVIDER_LABEL: ClassVar[str] = "simpli"
    PROVIDER_LOGO: ClassVar[str] = SimpliTVDefaults.PROVIDER_LOGO
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["user_credentials"]
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = ["AT"]

    # Manifest and DRM share one /Player/AcquireContent response, so DRM is
    # served by SimpliTVChannelManager.get_channel_drm (no _build_drm()).
    DRM_IN_MANAGERS: ClassVar[bool] = True
    HEADERS_FROM_MANAGERS: ClassVar[bool] = True

    @property
    def provider_name(self) -> str:
        """Return the provider name (matches the directory / registry key)."""
        return SimpliTVDefaults.PROVIDER_NAME   # "simpli"

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

        # 4. Managers, in dependency order (catchup needs channels).
        self._init_managers()

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

    # _build_vod / _build_favorites / _build_bookmarks / _build_drm:
    # inherited (None): no catalogue, favorites, bookmarks; DRM is folded.

    # ------------------------------------------------------------------
    # catchup: ids (simpliTV-specific grammar)
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
        return super().get_manifest(content_id, **kw)

    def get_drm(
        self,
        content_id: str,
        drm_variant: Optional[str] = None,
        content_type: Optional[str] = None,
        **kw,
    ) -> List:
        """
        DRM for the given content.

        catchup: ids go to the catchup manager, which forwards to the
        channel manager's DRM (the programme's own when replaying, the
        channel's live DRM when restarting). Everything else is
        ManagedProvider's folded-DRM routing.
        """
        if content_id.startswith(SimpliTVDefaults.CATCHUP_PREFIX):
            if self.catchup is None:
                return []
            _, start_ts = parse_catchup_id(content_id)  # raises if bad
            if drm_variant is not None:
                kw["drm_variant"] = drm_variant
            configs = self.catchup.get_catchup_drm(
                content_id, start_ts, None, **kw
            )
            return self._validate_drm(content_id, configs)
        return super().get_drm(content_id, drm_variant, content_type, **kw)

    def get_restart(
        self, content_id: str, start_time: int = 0, **kw
    ) -> Optional[Tuple[str, int]]:
        """
        Restart a programme from its beginning.

        Returns (live manifest URL, seek_seconds from the start of the
        channel's DVR window) or None when the programme began outside
        that window. The window is per-channel (see "Catchup windows"
        above). The caller must seek; the URL alone plays live.
        start_time=0 means "use the @<ts> embedded in a catchup: id".
        """
        if self.catchup is None:
            return None
        return self.catchup.get_restart_manifest(content_id, start_time)
