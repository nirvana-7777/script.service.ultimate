# streaming_providers/providers/_template/provider.py
"""
{TODO: Provider name} orchestrator.

Owns shared resources (http_manager, caches, auth, managers) and exposes
the public StreamingProvider interface.

Subclasses the existing StreamingProvider. Does NOT subclass any new
base class. Authentication is lazy -- no network I/O in __init__.

There are seven optional manager ABCs (channels, vod, epg, recordings,
favorites, bookmarks, catchup) plus an optional DRM manager (a protocol,
not an ABC). This template shows the shape for a provider that has
channels, VOD, and EPG. Delete the factories for capabilities you don't
have, or return None from them.

Plugin name: the registry derives it from the CLASS NAME via
`cls.__name__.lower().replace("provider", "")`. `YourProvider` becomes
"your". Name the class so that this matches your plugin directory, e.g.
`SimpliTVProvider` -> "simplitv" -> providers/simplitv/.
"""

from datetime import datetime
from typing import Any, Callable, ClassVar, Dict, List, Optional, Tuple

from ...base.errors import NotFoundError
from ...base.managers import ChannelManager, VodManager
from ...base.models.proxy_models import ProxyConfig
from ...base.protocols import DrmManagerProtocol
from ...base.provider import StreamingProvider
from ...base.utils.logger import logger
from ...base.vod import VodPage

from .auth import YourProviderAuth
from .channel_manager import YourChannelManager
from .constants import YourConfig, YourDefaults
# from .channel_manager import parse_catchup_id   # if you route catchup
# from .vod_manager import YourVodManager
# from .epg_manager import YourEpgManager
# from .recordings_manager import YourRecordingsManager
# from .favorites_manager import YourFavoritesManager
# from .bookmarks_manager import YourBookmarksManager
# from .catchup_manager import YourCatchupManager
# from .drm_manager import YourDrmManager


class YourProvider(StreamingProvider):
    """{TODO: provider name} streaming provider."""

    # ------------------------------------------------------------------
    # provider_name -- ABSTRACT, must be implemented
    # ------------------------------------------------------------------
    #
    # `provider_name` is declared as an @property @abstractmethod on
    # StreamingProvider. If this class does not override it, Python
    # raises TypeError at instantiation:
    #
    #     Can't instantiate abstract class YourProvider with abstract
    #     method provider_name
    #
    # The registry catches that exception, logs it at ERROR level, and
    # skips the provider. The symptom is a provider that is registered
    # but never appears in the UI.
    #
    # The value is the machine identifier: lowercase, no spaces, matching
    # the plugin directory name and the PROVIDER_NAME constant in
    # constants.py. Used in settings keys, log lines, and the `provider`
    # field on models. Return the constant so the two cannot drift.
    #
    # Do not delete this property. Override the return value; do not
    # replace it with a class attribute.
    @property
    def provider_name(self) -> str:
        return YourDefaults.PROVIDER_NAME

    # ------------------------------------------------------------------
    # Class metadata (read by the registry BEFORE any instance exists)
    # ------------------------------------------------------------------

    PROVIDER_LABEL: ClassVar[str] = "TODO: display label"
    PROVIDER_LOGO: ClassVar[str] = YourDefaults.PROVIDER_LOGO
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["user_credentials"]

    # ALWAYS set SUPPORTED_COUNTRIES. Never leave it at the base
    # default (an empty list), which has a specific meaning: "no
    # country concept at all." Even a single-country provider declares
    # a one-element list.
    #
    #   Single country:      ["AT"]
    #   Multi-country:       ["hr", "pl", "me", "at", "hu"]
    #   Wildcard:            ["*"]  (country discovered at runtime;
    #                               also the right answer for "not sure yet")
    #
    # See the README's "SUPPORTED_COUNTRIES is not optional" section.
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = ["TODO"]

    # Only "live" and "vod" narrow the folded DRM search; anything else
    # (None, "event", "catchup", a typo) tries both domains. See the
    # README's "content_type hint semantics".
    _LIVE_ONLY_CONTENT_TYPES = frozenset({"live"})
    _VOD_ONLY_CONTENT_TYPES = frozenset({"vod"})

    def __init__(
        self,
        country: str = "TODO",
        config: Optional[Dict] = None,
        proxy_config: Optional[ProxyConfig] = None,
        settings_manager=None,
        credentials=None,
        **kwargs,
    ):
        super().__init__(country)

        # Unknown kwargs are tolerated (the registry may pass host-level
        # extras) but never silently: a typo here is otherwise invisible.
        if kwargs:
            logger.debug(
                f"{self.provider_name}: ignoring unknown kwargs "
                f"{sorted(kwargs)}"
            )

        config = config or {}
        self.config = YourConfig(config, country=self.country)

        # 1. HTTP manager.
        self.http_manager = self._setup_http_manager(
            provider_name=self.provider_name,
            proxy_config=proxy_config,
            user_agent=self.config.user_agent,
            timeout=self.config.timeout,
        )

        # 2. Auth (lazy -- no network call in __init__).
        #
        # Providers WITHOUT auth: _build_auth returns None (accept the
        # manager base constructors' AuthProtocol warning) or a minimal
        # stub with the three token methods. See the README's
        # "Providers without auth" section.
        self._credentials = credentials
        self.auth = self._build_auth(settings_manager)

        # 3. Provider-owned caches. Managers borrow these by reference.
        #    Add caches here as the provider needs them.
        self._channels_cache: Dict = {}
        self._playback_cache: Dict = {}

        # 4. Managers, in DEPENDENCY ORDER. Every factory returns a
        #    manager or None. Catchup (and a dedicated DRM manager) may
        #    need channels/epg/vod, so they are built after them. Do not
        #    introduce cycles between managers.
        self.channels = self._build_channels()
        self.vod = self._build_vod()
        self.epg = self._build_epg()
        self.recordings = self._build_recordings()
        self.favorites = self._build_favorites()
        self.bookmarks = self._build_bookmarks()
        self.catchup = self._build_catchup()   # sees channels + epg
        self.drm = self._build_drm()

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    def _build_auth(self, settings_manager):
        """
        Return the provider's Auth instance, or None if the provider
        needs no authentication.

        `credentials=` MUST be forwarded: it is credentials source #1
        (constructor argument). The auth class falls back to the
        settings_manager and CredentialManager on its own.
        """
        return YourProviderAuth(
            http_manager=self.http_manager,
            country=self.country,
            settings_manager=settings_manager,
            credentials=self._credentials,
            config=self.config,
        )

    def _build_channels(self) -> Optional[ChannelManager]:
        """
        Return a ChannelManager, or None if the provider has no live
        channels.

        A VOD-only provider returns None here. A free linear-only
        provider returns a manager here and None from _build_vod.
        """
        return YourChannelManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.config,
            channels_cache=self._channels_cache,
        )

    def _build_vod(self) -> Optional[VodManager]:
        """
        Return a VodManager, or None if the provider has no browseable
        VOD catalogue.
        """
        # TODO: return YourVodManager(
        #     http_manager=self.http_manager,
        #     auth=self.auth,
        #     country=self.country,
        #     config=self.config,
        #     playback_cache=self._playback_cache,
        # )
        return None

    def _build_epg(self):
        """
        Return an EpgManager, or None if the provider has no EPG.

        Some providers have channels but no EPG; some have EPG but no
        channels. The two capabilities are independent.
        """
        return None

    def _build_recordings(self):
        """Return a RecordingsManager, or None."""
        return None

    def _build_favorites(self):
        """Return a FavoritesManager, or None."""
        return None

    def _build_bookmarks(self):
        """Return a BookmarksManager, or None."""
        return None

    def _build_catchup(self):
        """
        Return a CatchupManager, or None.

        Catchup usually needs the channel manager and/or the EPG manager
        as collaborators. Pass them as explicit keyword-only arguments;
        self.channels and self.epg are already built when this runs.
        """
        # TODO: return YourCatchupManager(
        #     http_manager=self.http_manager,
        #     auth=self.auth,
        #     country=self.country,
        #     config=self.config,
        #     channels=self.channels,
        #     epg=self.epg,
        # )
        return None

    def _build_drm(self) -> Optional[DrmManagerProtocol]:
        """
        Return a dedicated DRM manager, or None.

        Two supported architectures (see the README's "DRM" section):

          * Dedicated manager: return a class matching
            DrmManagerProtocol here; the provider's get_drm() delegates
            to it.

          * Folded into managers: leave this returning None, and
            override get_channel_drm() on your ChannelManager and/or
            get_vod_drm() on your VodManager. The provider's get_drm()
            falls back to routing to those.

        Rule: fold if DRM shares state with the manifest step; otherwise
        use the dedicated manager. See providers/_template/drm_manager.py
        for the four existing source patterns.
        """
        return None

    # ------------------------------------------------------------------
    # Capability flags (derived from manager presence)
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
        """
        True when this provider can produce DRM configurations.

        Derived from either source of DRM:
          * a dedicated DRM manager (_build_drm returned a class), OR
          * a ChannelManager that overrides get_channel_drm, OR
          * a VodManager that overrides get_vod_drm.

        The base classes' defaults return []; we detect overrides by
        comparing the bound method against the base class's method.
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

    # ------------------------------------------------------------------
    # Router
    # ------------------------------------------------------------------

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

        Any OTHER exception propagates. In particular BadRequestError is
        deliberately NOT caught: if a manager uses a 400 as an endpoint
        dispatch signal, override handles_content_id() on that manager
        instead of relying on try-and-catch. When both channels and vod
        exist, override handles_content_id() on both -- the default
        (True) makes the first manager see every id.
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
    # Public delegations
    #
    # The optional capabilities (recordings, favorites, bookmarks,
    # catchup) are exposed by the base layer's Provider*Mixin classes,
    # which correspond one-to-one to those managers -- no delegation is
    # needed here. Channels, VOD and EPG are delegated explicitly below.
    # VERIFY these three signatures against StreamingProvider when you
    # copy the template; remove any the base class already provides.
    # ------------------------------------------------------------------

    def get_channels(self, **kw):
        if self.channels is None:
            return []
        return self.channels.get_channels(**kw)

    def get_vod_category(
        self,
        content_id: str = "",
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kw,
    ) -> VodPage:
        if self.vod is None:
            return VodPage()
        return self.vod.get_vod_category(
            content_id, cursor=cursor, page_size=page_size, **kw
        )

    def get_epg(
        self,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kw,
    ):
        if self.epg is None:
            return []
        return self.epg.get_epg(
            channel_id, start_time=start_time, end_time=end_time, **kw
        )

    def get_manifest(self, content_id: str, **kw) -> Optional[str]:
        """
        Return the manifest URL for the given content, routing by manager.

        Route through `_route` when the manager needs only the
        content_id. Add an explicit prefix branch ABOVE `_route` when the
        manager needs parsed arguments (a timestamp, an episode index).
        One parser, in the router -- see the README's "Parsers vs.
        dispatch". Catchup is the usual example:

            # if content_id.startswith("catchup:"):
            #     parsed = parse_catchup_id(content_id)   # raises
            #     return self.catchup.get_catchup_manifest(   # BadRequestError
            #         parsed.content_id, parsed.start_time, parsed.end_time,
            #         **kw,
            #     ) if self.catchup else None

        Do NOT fall back to the live manifest when catchup fails.
        """
        return self._route(content_id, [
            (self.channels, lambda m: m.get_channel_manifest(
                content_id, **kw
            )),
            (self.vod, lambda m: m.get_vod_manifest(content_id, **kw)),
        ])

    def get_drm(
        self,
        content_id: str,
        content_type: Optional[str] = None,
        **kw,
    ) -> List:
        """
        Return DRM configuration(s) for the given content.

        content_type is an optional hint. Only "live" and "vod" narrow
        the search on the folded path; any other value (including None,
        "event", "catchup", or an unrecognized string) tries both
        domains. This is deliberate: a wrong narrowing produces a silent
        [] for protected content, which is the hardest kind of bug to
        trace. Widening on unknown input is always safe.

        If a dedicated DRM manager is configured, the hint is passed
        through unchanged and the manager decides what to do with it.
        """
        if self.drm is not None:
            return self.drm.get_drm_configs(
                content_id, content_type=content_type, **kw
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