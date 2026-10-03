# streaming_providers/providers/_template/provider.py
"""
{TODO: Provider name} orchestrator.

Owns shared resources (http_manager, caches, auth, managers) and exposes
the public StreamingProvider interface.

Subclasses the existing StreamingProvider. Does NOT subclass any new
base class. Authentication is lazy -- no network I/O in __init__.
"""

from typing import Any, Callable, ClassVar, Dict, List, Optional, Tuple

from ...base.errors import NotFoundError
from ...base.managers import ChannelManager, VodManager
from ...base.models.proxy_models import ProxyConfig
from ...base.protocols import DrmManagerProtocol
from ...base.provider import StreamingProvider
from ...base.utils.logger import logger

from .auth import YourProviderAuth
from .channel_manager import YourChannelManager
from .constants import YourConfig
# from .vod_manager import YourVodManager
# from .epg_manager import YourEpgManager
# from .drm_manager import YourDrmManager


class YourProvider(StreamingProvider):
    """{TODO: provider name} streaming provider."""

    PROVIDER_LABEL: ClassVar[str] = "TODO: display label"
    PROVIDER_LOGO: ClassVar[str] = "TODO: logo url"
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["user_credentials"]
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = ["TODO", "country", "codes"]

    def __init__(
        self,
        country: str = "TODO",
        config: Optional[Dict] = None,
        proxy_config: Optional[ProxyConfig] = None,
        settings_manager=None,
        **kwargs,
    ):
        super().__init__(country)

        config = config or {}
        self.config = YourConfig(config)

        # 1. HTTP manager.
        self.http_manager = self._setup_http_manager(
            provider_name="TODO: provider_name",
            proxy_config=proxy_config,
            user_agent=self.config.user_agent,
            timeout=self.config.timeout,
        )

        # 2. Auth (protocol, not ABC). Lazy -- no network call here.
        self.auth = self._build_auth(settings_manager)

        # 3. Provider-owned caches. Managers borrow these by reference.
        self._channels_cache: Dict = {}
        self._playback_cache: Dict = {}

        # 4. Managers.
        self.channels = self._build_channels()
        self.vod = self._build_vod()
        self.epg = self._build_epg()
        self.drm = self._build_drm()

    # ----- Factory methods -----

    def _build_auth(self, settings_manager):
        return YourProviderAuth(
            http_manager=self.http_manager,
            country=self.country,
            settings_manager=settings_manager,
        )

    def _build_channels(self):
        return YourChannelManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.config,
            channels_cache=self._channels_cache,
        )

    def _build_vod(self):
        # TODO: return YourVodManager(
        #     http_manager=self.http_manager,
        #     auth=self.auth,
        #     country=self.country,
        #     config=self.config,
        #     playback_cache=self._playback_cache,
        # )
        return None

    def _build_epg(self):
        return None

    def _build_drm(self) -> Optional[DrmManagerProtocol]:
        """
        Return a dedicated DRM manager, or None.

        Two supported architectures:

          * Dedicated manager: return a class matching DrmManagerProtocol
            here; the provider's get_drm() delegates to it.

          * Folded into managers: leave this returning None, and instead
            override get_channel_drm() on your ChannelManager and/or
            get_vod_drm() on your VodManager. The provider's get_drm()
            falls back to routing to those.

        New providers should prefer the dedicated manager (see the README
        section "DRM"). The folded style exists for providers whose DRM
        call shares significant state with the manifest step.

        See providers/_template/drm_manager.py for the four existing
        patterns (RTL+ upfront token, Magenta constructed URL, Discovery
        playbackInfo, HRTi session id).
        """
        # TODO: return YourDrmManager(
        #     http_manager=self.http_manager,
        #     auth=self.auth,
        #     country=self.country,
        #     config=self.config,
        #     # ... provider-specific collaborators
        # )
        return None

    # ----- Capability flags (derived from manager presence) -----

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
    def implements_drm(self) -> bool:
        """
        True when this provider can produce DRM configurations.

        Derived from either source of DRM:
          * a dedicated DRM manager (_build_drm returned a class), OR
          * a ChannelManager that overrides get_channel_drm, OR
          * a VodManager that overrides get_vod_drm.

        The base classes' defaults return []; we detect overrides by
        comparing the bound method against the base class's method. This
        is what makes the flag correct for the folded architecture.
        """
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

    # ----- Router -----

    def _route(self, content_id: str, attempts: List[Tuple[Any, Callable]]):
        """
        Try managers in order, using handles_content_id() to skip those
        that declare they don't handle the id.

        Distinguishes three outcomes:
          * manager returned a truthy result      -> return it
          * manager returned None / [] / falsy    -> try next manager
          * manager raised NotFoundError          -> remember it, try next

        If nobody resolved and a NotFoundError was seen, re-raise it --
        that's "the content existed in some manager's domain but is gone",
        distinct from "nobody handles this id at all" (which returns None).
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

    # ----- Public delegations -----

    def get_channels(self, **kw):
        if self.channels is None:
            return []
        return self.channels.get_channels(**kw)

    def get_manifest(self, content_id: str, **kw) -> Optional[str]:
        return self._route(content_id, [
            (self.channels, lambda m: m.get_channel_manifest(content_id, **kw)),
            (self.vod,      lambda m: m.get_vod_manifest(content_id, **kw)),
        ])

    def get_drm(
        self,
        content_id: str,
        content_type: Optional[str] = None,
        **kw,
    ) -> List:
        """
        Return DRM configuration(s) for the given content.

        content_type is an optional hint. When None (the default), the
        DRM source infers the type from its own content_id grammar --
        which is the preferred mode, since the source knows its own
        grammar better than the caller does. Callers that already know
        the type (e.g. the backend's streaming route) should pass it
        explicitly.

        If a dedicated DRM manager is configured, delegate to it. Otherwise
        fall back to per-manager DRM (channel manager's get_channel_drm,
        VOD manager's get_vod_drm) via the router.
        """
        if self.drm is not None:
            return self.drm.get_drm_configs(
                content_id,
                content_type=content_type,
                **kw,
            )
        return self._route(content_id, [
            (self.channels, lambda m: m.get_channel_drm(content_id, **kw)),
            (self.vod,      lambda m: m.get_vod_drm(content_id, **kw)),
        ]) or []