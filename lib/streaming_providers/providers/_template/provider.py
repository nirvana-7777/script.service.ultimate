# streaming_providers/providers/_template/provider.py   (v2 template)
"""
{TODO: Provider name} orchestrator.

Owns shared resources (http_manager, caches, auth, managers) and declares
which managers exist. Everything generic -- capability flags, content_id
routing, DRM validation, header delegation, EPG delegation -- is inherited
from ManagedProvider (base/managed_provider.py), which itself subclasses
StreamingProvider, so the registry and the backend see an ordinary provider.

Authentication is lazy -- no network I/O in __init__.

What you write
--------------
  * provider_name, class metadata (PROVIDER_LABEL, ...)
  * __init__: http manager, auth, provider-owned caches, then
    ``self._init_managers()``
  * the _build_*() factories for the capabilities you have (the rest
    inherit "return None" = capability absent)
  * get_manifest / get_drm ONLY if you have provider-specific prefixes that
    need parsed arguments (catchup timestamps, ...); call super() for the rest

What you no longer write (vs. the v1 template)
----------------------------------------------
  * the eight implements_* properties
  * _route()
  * default get_manifest / get_drm routing
  * get_channels / get_epg / get_epg_grid / get_program_details delegation
  * header delegation to the managers

Plugin name: the registry derives it from the CLASS NAME via
`cls.__name__.lower().replace("provider", "")`. Keep it consistent with
provider_name (see docs/provider-v2/TODO.md, item N-1).
"""

from typing import ClassVar, Dict, List, Optional

from ...base.managed_provider import ManagedProvider
from ...base.managers import ChannelManager, VodManager
from ...base.models.proxy_models import ProxyConfig
from ...base.protocols import DrmManagerProtocol
from ...base.utils.logger import logger
from ...base.vod import VodPage

from .auth import YourProviderAuth
from .channel_manager import YourChannelManager
from .constants import YourConfig, YourDefaults
# from .vod_manager import YourVodManager
# from .epg_manager import YourEpgManager
# from .recordings_manager import YourRecordingsManager
# from .favorites_manager import YourFavoritesManager
# from .bookmarks_manager import YourBookmarksManager
# from .catchup_manager import YourCatchupManager
# from .drm_manager import YourDrmManager


class YourProvider(ManagedProvider):
    """{TODO: provider name} streaming provider."""

    # provider_name is ABSTRACT on StreamingProvider. If it is missing the
    # registry logs "Can't instantiate abstract class ..." (with traceback
    # since the registry fix) and the provider never shows up in the UI.
    # Machine identifier: lowercase, no spaces, == plugin directory ==
    # PROVIDER_NAME in constants.py.
    @property
    def provider_name(self) -> str:
        return YourDefaults.PROVIDER_NAME

    # Class metadata, read by the registry BEFORE any instance exists.
    PROVIDER_LABEL: ClassVar[str] = "TODO: display label"
    PROVIDER_LOGO: ClassVar[str] = YourDefaults.PROVIDER_LOGO
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["user_credentials"]

    # ALWAYS set SUPPORTED_COUNTRIES (never the empty base default):
    #   ["AT"] single | ["hr", "pl"] multi (one instance per country) | ["*"]
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = ["TODO"]

    # DRM architecture, declared explicitly (no override sniffing):
    #   dedicated manager -> return it from _build_drm()
    #   folded            -> set True and override get_channel_drm / get_vod_drm
    # Setting both raises ConfigurationError at construction.
    DRM_IN_MANAGERS: ClassVar[bool] = False

    # True (default): header hooks on the managers are honoured and the
    # default is auth.build_headers(). Set False to keep the legacy "{}".
    HEADERS_FROM_MANAGERS: ClassVar[bool] = True

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
        # extras) but never silently.
        if kwargs:
            logger.debug(
                f"{self.provider_name}: ignoring unknown kwargs {sorted(kwargs)}"
            )

        self.config = YourConfig(config or {}, country=self.country)

        # 1. HTTP manager.
        self.http_manager = self._setup_http_manager(
            provider_name=self.provider_name,
            proxy_config=proxy_config,
            user_agent=self.config.user_agent,
            timeout=self.config.timeout,
        )

        # 2. Auth (lazy). Providers WITHOUT auth: return None or a minimal
        #    stub (README, "Providers without auth").
        self._credentials = credentials
        self.auth = self._build_auth(settings_manager)

        # 3. Provider-owned caches; managers borrow them by reference.
        #    (Plain dicts are not thread-safe for check-then-set; see
        #    TODO item C-3.)
        self._channels_cache: Dict = {}
        self._playback_cache: Dict = {}

        # 4. Build the managers in dependency order (catchup after
        #    channels/epg). NOTE: this sets self.channels etc. to MANAGERS,
        #    shadowing the legacy list attribute; ManagedProvider overrides
        #    to_output_format() for that reason.
        self._init_managers()

    # ------------------------------------------------------------------
    # Factories -- override only the capabilities you have
    # ------------------------------------------------------------------

    def _build_auth(self, settings_manager):
        """`credentials=` MUST be forwarded (credentials source #1)."""
        return YourProviderAuth(
            http_manager=self.http_manager,
            country=self.country,
            settings_manager=settings_manager,
            credentials=self._credentials,
            config=self.config,
        )

    def _build_channels(self) -> Optional[ChannelManager]:
        return YourChannelManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.config,
            channels_cache=self._channels_cache,
        )

    def _build_vod(self) -> Optional[VodManager]:
        # TODO: return YourVodManager(http_manager=..., auth=..., country=...,
        #                             config=..., playback_cache=...)
        return None

    # _build_epg / _build_recordings / _build_favorites / _build_bookmarks /
    # _build_catchup: inherited "return None". Override to enable, e.g.
    #
    #   def _build_catchup(self):
    #       return YourCatchupManager(
    #           http_manager=self.http_manager, auth=self.auth,
    #           country=self.country, config=self.config,
    #           channels=self.channels, epg=self.epg,   # already built
    #       )

    def _build_drm(self) -> Optional[DrmManagerProtocol]:
        """Dedicated DRM manager, or None (folded / no DRM). See README "DRM"."""
        return None

    # ------------------------------------------------------------------
    # Provider-specific routing (only if you need it)
    # ------------------------------------------------------------------
    #
    # def get_manifest(self, content_id: str, **kw) -> Optional[str]:
    #     if content_id.startswith("catchup:"):
    #         parsed = parse_catchup_id(content_id)   # raises BadRequestError
    #         return self.catchup.get_catchup_manifest(
    #             parsed.content_id, parsed.start_time, parsed.end_time, **kw
    #         ) if self.catchup else None
    #     return super().get_manifest(content_id, **kw)
    #
    # Do NOT fall back to the live manifest when catchup fails.

    # ------------------------------------------------------------------
    # VOD delegation
    # ------------------------------------------------------------------
    # ManagedProvider delegates channels, EPG, manifest, headers and DRM.
    # VOD navigation is NOT delegated yet because the legacy
    # ProviderVodMixin signature has not been verified (TODO item M-2).
    # Until then providers with VOD keep this delegation themselves.

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