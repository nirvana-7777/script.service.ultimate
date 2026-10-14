# streaming_providers/providers/movetv/provider.py
"""
move.tv (MTS-SI) provider -- orchestrator only.

The provider owns the SHARED resources (config, http_manager, authenticator,
session, SourceCache) and BUILDS the managers. Capability flags, content-id
routing, manifest / header / EPG / catchup delegation are inherited from
ManagedProvider.

Managers: channels, epg, catchup (+ vod, see VOD_BROWSE_ENABLED).
No recordings / favorites / bookmarks / DRM (all clear streams).
"""

from typing import ClassVar, Dict, List, Optional

from ...base.errors import BadRequestError
from ...base.managed_provider import ManagedProvider
from ...base.models.proxy_models import ProxyConfig
from .auth import MoveTVAuthenticator
from .catchup_manager import MoveTvCatchupManager
from .api import SourceCache
from .channel_manager import MoveTvChannelManager
from .constants import MoveTVConfig
from .epg_manager import MoveTvEpgManager
from .session import MoveTvSession
from .vod_manager import MoveTvVodManager

# Only the provider is public. Provider discovery takes the FIRST
# StreamingProvider subclass found in the package namespace.
__all__ = ["MoveTVProvider"]


class MoveTVProvider(ManagedProvider):
    PROVIDER_LABEL: ClassVar[str] = MoveTVConfig.PROVIDER_LABEL
    PROVIDER_LOGO: ClassVar[str] = MoveTVConfig.PROVIDER_LOGO
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["user_credentials"]
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = list(MoveTVConfig.SUPPORTED_COUNTRIES)   # Serbia: ["RS"]

    # No DRM at all (get_drm was always []).
    DRM_IN_MANAGERS: ClassVar[bool] = False
    # The manifest request needs the per-stream X-Play-Auth header that comes with
    # the manifest URL: the managers' header hooks provide it (v1 overrode the
    # provider methods, so this is the same behaviour, now in the managers).
    HEADERS_FROM_MANAGERS: ClassVar[bool] = True

    # The four VOD parsers are placeholders in the v1 source that was supplied
    # for the migration (vod_manager.py). While False, the VOD manager is not
    # registered as a capability (v1 never exposed VOD browsing through the
    # backend either); the provider-specific get_vod_* methods below still work
    # once the parsers are restored. Flip to True afterwards.
    VOD_BROWSE_ENABLED: ClassVar[bool] = False

    @property
    def provider_name(self) -> str:
        """Must equal the directory name / registry key."""
        return MoveTVConfig.PROVIDER_NAME

    # Not delegated by ManagedProvider (v1 values kept).
    @property
    def uses_dynamic_manifests(self) -> bool:
        return True

    @property
    def requires_manifest_context(self) -> bool:
        return True

    def __init__(
        self,
        country: str = MoveTVConfig.DEFAULT_COUNTRY,
        config: Optional[Dict] = None,           # accepted for compatibility, unused (as in v1)
        proxy_config: Optional[ProxyConfig] = None,
        settings_manager=None,
    ):
        # The registry constructs providers with `country` only (pinned to "RS").
        super().__init__(country=country)
        # Credentials / sessions / proxy settings are keyed by lower-case country.
        self.country = self.country.lower()

        # 1. ONE static config (class), shared by every layer.
        self.provider_config = MoveTVConfig

        # 2. HTTP manager (proxy: ctor arg -> ProxyConfigManager -> global).
        self.http_manager = self._setup_http_manager(
            provider_name=MoveTVConfig.PROVIDER_NAME,
            proxy_config=proxy_config,
            user_agent=MoveTVConfig.USER_AGENT,
            timeout=MoveTVConfig.TIMEOUT,
        )

        # 3. Auth: the stateful authenticator (persisted session) behind a
        #    session adapter. LAZY: no network call in __init__ (v1 logged in here).
        self.authenticator = MoveTVAuthenticator(
            proxy_config=proxy_config,
            http_manager=self.http_manager,
            settings_manager=settings_manager,
        )
        self.auth = MoveTvSession(authenticator=self.authenticator, config=self.provider_config)
        self.auth.on_invalidate(self._clear_account_caches)

        # 4. Provider-owned cache, borrowed by the channel and catchup managers.
        self._source_cache = SourceCache()

        # 5. Managers. NOTE: self.channels is the ChannelManager (shadows the
        #    legacy list).
        self._init_managers()

    # ------------------------------------------------------------------
    # Manager factories
    # ------------------------------------------------------------------
    def _build_channels(self):
        return MoveTvChannelManager(
            http_manager=self.http_manager, auth=self.auth, country=self.country,
            config=self.provider_config, source_cache=self._source_cache,
        )

    def _build_vod(self):
        self._vod_catalogue = MoveTvVodManager(
            http_manager=self.http_manager, auth=self.auth, country=self.country,
            config=self.provider_config,
        )
        return self._vod_catalogue if self.VOD_BROWSE_ENABLED else None

    def _build_epg(self):
        return MoveTvEpgManager(
            http_manager=self.http_manager, auth=self.auth, country=self.country,
            config=self.provider_config,
        )

    def _build_catchup(self):
        # Build order: channels, vod, epg, ..., catchup -> both exist here.
        return MoveTvCatchupManager(
            http_manager=self.http_manager, auth=self.auth, country=self.country,
            config=self.provider_config, channels=self.channels, epg=self.epg,
            source_cache=self._source_cache,
        )

    # ------------------------------------------------------------------
    # Credential change / logout: drop everything account-specific
    # ------------------------------------------------------------------
    def _clear_account_caches(self) -> None:
        self._source_cache.clear()
        if self.channels is not None:
            self.channels.clear()
        if self.catchup is not None:
            self.catchup.clear()

    # ------------------------------------------------------------------
    # Provider-specific grammar: catchup arguments on the manifest-headers call
    # ------------------------------------------------------------------
    def get_manifest_headers(self, content_id: str, **kw) -> Dict[str, str]:
        """v1 treated a headers request carrying start_time as a catchup request.
        (ManagedProvider routes only get_segment_headers that way.)"""
        if self.catchup is not None and kw.get("start_time") is not None:
            rest = dict(kw)
            try:
                start = int(rest.pop("start_time"))
            except (TypeError, ValueError):
                raise BadRequestError(f"move.tv: invalid start_time {kw.get('start_time')!r}")
            return self.catchup.get_catchup_manifest_headers(
                content_id, start,
                end_time=rest.pop("end_time", None),
                epg_id=rest.pop("epg_id", None),
                **rest,
            )
        return super().get_manifest_headers(content_id, **kw)

    # ------------------------------------------------------------------
    # Provider-specific VOD catalogue (v1 surface, delegated 1:1)
    # ------------------------------------------------------------------
    def get_vod_filters(self):
        return self._vod_catalogue.get_vod_filters()

    def get_vod_items(self, page: int = 1, sort: str = "newest", tag_id=None, category_id=None,
                      catalog_id=None, content_type_id=None, search_query=None):
        return self._vod_catalogue.get_vod_items(
            page=page, sort=sort, tag_id=tag_id, category_id=category_id,
            catalog_id=catalog_id, content_type_id=content_type_id, search_query=search_query,
        )

    def get_all_vod_items(self, sort: str = "newest", tag_id=None, category_id=None,
                          catalog_id=None, content_type_id=None, max_pages=None):
        return self._vod_catalogue.get_all_vod_items(
            sort=sort, tag_id=tag_id, category_id=category_id, catalog_id=catalog_id,
            content_type_id=content_type_id, max_pages=max_pages,
        )

    def get_page_components(self, page_id: int):
        return self._vod_catalogue.get_page_components(page_id)

    def get_component_items(self, component_id: int):
        return self._vod_catalogue.get_component_items(component_id)