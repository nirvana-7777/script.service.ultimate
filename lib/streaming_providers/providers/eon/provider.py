# streaming_providers/providers/eon/provider.py
"""
Eon provider -- orchestrator only.

The provider owns the SHARED resources (config, http_manager, endpoints,
auth, api, catalog, caches) and BUILDS the managers. Everything identical
across providers is inherited from ManagedProvider.

Eon is a white-label platform: `config["brand"]` (vivacom, nova, sbb,
telemach, telemach-hr, telemach-si) picks the operator, `config["platform"]`
("web" / "androidtv") the client identity. Geo-unblocking users also need
Kodi's global proxy: the CDN requests are made by inputstream.adaptive, which
does not use the backend's ProxyConfig.
"""

from typing import ClassVar, Dict, List, Optional

from ...base.managed_provider import ManagedProvider
from ...base.models.proxy_models import ProxyConfig
from .api import EonApi
from .auth import EonAuth, EonStore
from .bootstrap import EonCatalog, EonEndpoints
from .catchup_manager import EonCatchupManager
from .channel_manager import EonChannelManager
from .constants import EonConfig, EonDefaults
from .epg_manager import EonEpgManager

__all__ = ["EonProvider"]


class EonProvider(ManagedProvider):
    PROVIDER_LABEL: ClassVar[str] = EonDefaults.PROVIDER_LABEL
    PROVIDER_LOGO: ClassVar[str] = EonDefaults.PROVIDER_LOGO
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["user_credentials"]
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = list(EonDefaults.SUPPORTED_COUNTRIES)

    # Eon streams are clear HLS: no DRM anywhere.
    DRM_IN_MANAGERS: ClassVar[bool] = False
    # CDN requests need the browser / smart-TV UA the channel manager returns.
    HEADERS_FROM_MANAGERS: ClassVar[bool] = True
    # The backend's clear-HLS check fetches the first variant playlist of the
    # master. The addon resolves variant URIs WITHOUT inheriting the master's
    # query (it carries the encrypted payload), and plays fine, so variant URIs
    # are self-sufficient: do not append the master query to them.
    inherit_manifest_query_on_segments: ClassVar[bool] = False

    @property
    def provider_name(self) -> str:
        return EonDefaults.PROVIDER_NAME

    def __init__(
        self,
        country: str = "BG",
        config: Optional[Dict] = None,
        proxy_config: Optional[ProxyConfig] = None,
        store: Optional[EonStore] = None,
    ):
        super().__init__(country=country)
        self.country = self.country.lower()

        # 1. ONE config object, shared by every layer.
        self.provider_config = EonConfig(config or {})

        # 2. HTTP manager.
        self.http_manager = self._setup_http_manager(
            provider_name=EonDefaults.PROVIDER_NAME,
            proxy_config=proxy_config,
            user_agent=self.provider_config.user_agent,
            timeout=self.provider_config.timeout,
        )

        # 3. Lazy collaborators: no network in __init__.
        self.endpoints = EonEndpoints(
            http_manager=self.http_manager, config=self.provider_config
        )
        self.auth = EonAuth(
            http_manager=self.http_manager, config=self.provider_config,
            endpoints=self.endpoints, store=store,
        )
        self.api = EonApi(
            http_manager=self.http_manager, auth=self.auth,
            endpoints=self.endpoints, config=self.provider_config,
        )
        self.catalog = EonCatalog(api=self.api, config=self.provider_config)

        # 4. Provider-owned caches, borrowed by managers by reference.
        self._url_cache: Dict = {}

        # 5. Managers. NOTE: self.channels is now the ChannelManager.
        self._init_managers()

    def _build_channels(self):
        return EonChannelManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.provider_config,
            api=self.api,
            endpoints=self.endpoints,
            catalog=self.catalog,
            url_cache=self._url_cache,
        )

    def _build_epg(self):
        return EonEpgManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.provider_config,
            api=self.api,
            endpoints=self.endpoints,
        )

    def _build_catchup(self):
        # Needs the channel manager (it mints the signed URL): built after it.
        return EonCatchupManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.provider_config,
            channels=self.channels,
        )

    # ------------------------------------------------------------------
    # Credentials API for the settings UI
    # ------------------------------------------------------------------
    def set_user_credentials(self, username: str, password: str) -> bool:
        """Store credentials and log in once; True on success."""
        from types import SimpleNamespace

        self.auth.set_credentials(SimpleNamespace(username=username, password=password))
        self._url_cache.clear()
        self.catalog.invalidate()
        try:
            self.auth.get_access_token()
        except Exception:
            return False
        return True