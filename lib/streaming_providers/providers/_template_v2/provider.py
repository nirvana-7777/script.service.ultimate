# streaming_providers/providers/example/provider.py
"""
Example provider -- orchestrator only.

The provider owns the SHARED resources (config, http_manager, auth, caches)
and BUILDS the managers. Everything identical across providers -- capability
flags, content-id routing, manifest / DRM / header / EPG delegation, the
legacy recordings / favorites / bookmarks / catchup surface -- is inherited
from ManagedProvider. Do not re-implement it here.

What belongs here:
  * identity ClassVars and provider_name
  * __init__: config -> http_manager -> auth -> caches -> _init_managers()
  * the _build_*() hooks of the managers you have (the rest return None)
  * provider-specific id grammar (override get_manifest / get_drm, call
    super() for everything else)
  * credentials API for the settings UI
What does NOT belong here: flag properties (implements_*), _route(),
get_channels(), header/EPG/DRM delegation, per-capability business logic.
"""

from typing import ClassVar, Dict, List, Optional

from ...base.managed_provider import ManagedProvider
from ...base.models.proxy_models import ProxyConfig
from .auth import ExampleAuth
from .channel_manager import ExampleChannelManager
from .constants import ExampleConfig, ExampleDefaults

# Only the provider is public. Provider discovery (streaming_providers/
# __init__.py) takes the FIRST StreamingProvider subclass it finds in the
# package namespace -- ManagedProvider must never be that one.
__all__ = ["ExampleProvider"]


class ExampleProvider(ManagedProvider):
    PROVIDER_LABEL: ClassVar[str] = ExampleDefaults.PROVIDER_LABEL
    PROVIDER_LOGO: ClassVar[str] = ExampleDefaults.PROVIDER_LOGO
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["user_credentials"]
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = list(ExampleDefaults.SUPPORTED_COUNTRIES)

    # --- The two decisions every provider MUST take explicitly -----------
    # (the contract test fails if a manager overrides the hooks but the flag
    # says otherwise)
    #
    # DRM: True  = managers implement get_channel_drm / get_vod_drm
    #              (manifest and DRM share state -- the usual case)
    #      False = no DRM, OR a dedicated object via _build_drm()
    DRM_IN_MANAGERS: ClassVar[bool] = True
    #
    # Headers: True  = manifest / segment requests carry the managers' header
    #                  hooks (default there: auth.build_headers())
    #          False = keep the legacy {} (migrating a provider whose hooks
    #                  were dead code: decide and test on a device)
    HEADERS_FROM_MANAGERS: ClassVar[bool] = True

    @property
    def provider_name(self) -> str:
        """Must equal the directory name / registry key."""
        return ExampleDefaults.PROVIDER_NAME

    def __init__(
        self,
        country: str = "DE",
        config: Optional[Dict] = None,
        proxy_config: Optional[ProxyConfig] = None,
    ):
        # StreamingProvider.__init__ takes ONLY `country` (no **kwargs);
        # the registry constructs providers with country only.
        super().__init__(country=country)

        # The registry passes UPPERCASE for single-country providers and
        # lowercase for fanned-out ones, while CredentialManager /
        # SessionManager / ProxyConfigManager key by lowercase: normalise.
        self.country = self.country.lower()

        # 1. ONE config object, shared by every layer.
        self.provider_config = ExampleConfig(config or {})

        # 2. HTTP manager (proxy: ctor arg -> ProxyConfigManager -> global).
        self.http_manager = self._setup_http_manager(
            provider_name=ExampleDefaults.PROVIDER_NAME,
            proxy_config=proxy_config,
            user_agent=self.provider_config.user_agent,
            timeout=self.provider_config.timeout,
        )

        # 3. Auth: lazy, no network in __init__.
        self.auth = ExampleAuth(
            http_manager=self.http_manager, config=self.provider_config
        )

        # 4. Provider-owned caches, borrowed by managers by reference.
        self._playout_cache: Dict = {}

        # 5. Managers, in dependency order. NOTE: self.channels is now the
        #    ChannelManager (it shadows the legacy list) -- never assign a
        #    list to it.
        self._init_managers()

    # ------------------------------------------------------------------
    # Manager factories -- return None (the default) for capabilities
    # the provider does not have. The matching implements_* flag is derived.
    # ------------------------------------------------------------------
    def _build_channels(self):
        return ExampleChannelManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.provider_config,
            playout_cache=self._playout_cache,
        )

    # OPTIONAL managers: see optional/<x>_manager.py -- each file's docstring
    # has the exact import + _build_* snippet to paste here, e.g.:
    #
    #   def _build_epg(self):
    #       return ExampleEpgManager(http_manager=self.http_manager,
    #                                auth=self.auth, country=self.country,
    #                                config=self.provider_config)
    #
    # Build order is fixed by ManagedProvider._init_managers():
    #   channels, vod, epg, recordings, favorites, bookmarks, catchup, drm
    # A manager that needs another one (catchup needs channels) reads
    # self.channels inside its _build_* method.

    # ------------------------------------------------------------------
    # Provider-specific id grammar (example, keep only if you need it)
    # ------------------------------------------------------------------
    # def get_manifest(self, content_id, **kw):
    #     if content_id.startswith("special:"):
    #         ...handle...
    #     return super().get_manifest(content_id, **kw)

    # ------------------------------------------------------------------
    # OPTIONAL -- Credentials API for the settings UI.
    # A migration PRESERVES the v1 surface and never adds to it: keep this only
    # if the v1 provider has it or `grep -rn set_user_credentials` finds callers
    # (README §9). Otherwise delete it together with its test.
    # ------------------------------------------------------------------
    def set_user_credentials(self, username: str, password: str) -> bool:
        """Store credentials and log in once; True on success."""
        from types import SimpleNamespace

        self.auth.set_credentials(SimpleNamespace(username=username, password=password))
        self._playout_cache.clear()           # ids/streams may be user-specific
        try:
            self.auth.get_access_token()
        except Exception:
            return False
        return True
