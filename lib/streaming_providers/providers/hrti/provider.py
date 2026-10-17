# streaming_providers/providers/hrti/provider.py
"""
HRTi provider -- orchestrator only.

Owns the SHARED resources (ONE config, http_manager, authenticator + session,
caches) and builds the managers; everything generic (capability flags,
content-id routing, manifest / DRM delegation, legacy surface) comes from
ManagedProvider.

Capabilities: live channels + radio, VOD, EPG (native batch GetProgramme,
per-programme GetEpgDetails enrichment; epg_window = (2, 7), v1 values
kept). A future catchup manager would take the EPG manager as a
keyword-only ``epg=`` extra (_init_managers builds epg before catchup, so
``self.epg`` is available in _build_catchup).
"""

from typing import ClassVar, Dict, List, Optional

from ...base.managed_provider import ManagedProvider
from ...base.models.proxy_models import ProxyConfig
from .auth import HRTiAuthenticator
from .channel_manager import HRTiChannelManager
from .constants import HRTiConfig, HRTiDefaults
from .epg_manager import HRTiEpgManager
from .session import HRTiSession
from .vod_manager import HRTiVodManager
from .catchup_manager import HRTiCatchupManager

# Only the provider is public (discovery takes the FIRST StreamingProvider
# subclass in the package namespace -- never export ManagedProvider).
__all__ = ["HRTiProvider"]


class HRTiProvider(ManagedProvider):
    PROVIDER_LABEL: ClassVar[str] = HRTiDefaults.PROVIDER_LABEL
    PROVIDER_LOGO: ClassVar[str] = HRTiDefaults.PROVIDER_LOGO
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["client_credentials", "user_credentials"]
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = list(HRTiDefaults.SUPPORTED_COUNTRIES)

    # Manifest and DRM share one authorised session -> DRM lives in the managers.
    DRM_IN_MANAGERS: ClassVar[bool] = True
    # v1 had no manager header hooks and sent {} for manifest/segments; the DRM
    # config carries Origin/Referer/UA itself. Decided: keep {}.
    HEADERS_FROM_MANAGERS: ClassVar[bool] = False

    @property
    def provider_name(self) -> str:
        """Must equal the directory name / registry key."""
        return HRTiDefaults.PROVIDER_NAME

    @property
    def uses_dynamic_manifests(self) -> bool:
        # v1 value (True) differs from the legacy default (False): keep.
        return True

    @property
    def provider_logo(self) -> str:
        # v1: the logo can be overridden through the config dict.
        return self.hrti_config.logo

    def __init__(
        self,
        country: str = "HR",
        config: Optional[Dict] = None,
        proxy_config: Optional[ProxyConfig] = None,
    ):
        super().__init__(country=country)
        # Registry passes UPPERCASE for single-country providers; the proxy
        # lookup keys by lowercase. NOTE: the authenticator keeps its FLAT
        # storage keys (country=None) -- existing credentials/session/device
        # id are stored without a country and must stay reachable.
        self.country = self.country.lower()

        # 1. ONE config object, shared by authenticator, session and managers.
        self.hrti_config = HRTiConfig(config)

        # 2. HTTP manager (proxy: ctor arg -> ProxyConfigManager -> global).
        self.http_manager = self._setup_http_manager(
            provider_name=HRTiDefaults.PROVIDER_NAME,
            proxy_config=proxy_config,
            user_agent=self.hrti_config.user_agent,
            timeout=self.hrti_config.timeout,
        )
        # The dynamic endpoints (env.json / config.production.json) are fetched
        # lazily through this manager on first use -- not in __init__.
        self.hrti_config.attach_http(self.http_manager)

        # 3. Auth: stateful authenticator (kept: the legacy auth mixin reads
        #    self.authenticator) + the session adapter the managers use.
        self.authenticator = HRTiAuthenticator(
            http_manager=self.http_manager, config=self.hrti_config
        )
        self.auth = HRTiSession(authenticator=self.authenticator, config=self.hrti_config)

        # 4. Provider-owned caches, borrowed by the managers by reference.
        self._playout_cache: Dict = {}
        self.auth.on_invalidate(self._clear_caches)

        # 5. Managers. self.channels is the ChannelManager (never a list).
        self._init_managers()

    def _clear_caches(self) -> None:
        self._playout_cache.clear()
        clear_channel_caches = getattr(self.channels, "clear_caches", None)
        if callable(clear_channel_caches):   # None (no live) or the pre-init legacy list: skip
            clear_channel_caches()
        # NOTE: the EPG manager's programme->channel hint map is schedule
        # data, not account-specific state -- deliberately NOT cleared here.

    # ------------------------------------------------------------------
    # Manager factories (None = capability not offered)
    # ------------------------------------------------------------------
    def _build_channels(self):
        return HRTiChannelManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.hrti_config,
            playout_cache=self._playout_cache,
        )

    def _build_vod(self):
        return HRTiVodManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.hrti_config,
            playout_cache=self._playout_cache,
        )

    def _build_epg(self):
        # Exactly the four collaborators: no playout_cache (EPG plays
        # nothing), no channels= (the provider layer fills channel_ids from
        # get_channels() when the backend passes none; the programme->channel
        # hint map inside the manager is its own state).
        return HRTiEpgManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.hrti_config,
        )

    def _build_catchup(self):
        return HRTiCatchupManager(
            http_manager=self.http_manager, auth=self.auth,
            country=self.country, config=self.hrti_config,
            epg=self.epg, playout_cache=self._playout_cache,
        )
