# streaming_providers/providers/joyn/provider.py
# -*- coding: utf-8 -*-
"""
Joyn provider — orchestrator only.

The provider owns the SHARED resources and BUILDS the managers. Everything
identical across providers is inherited from ManagedProvider. What stays here:

  * identity ClassVars
  * __init__ wiring: config -> http_manager -> authenticator -> session ->
    entitlement helper -> caches -> _init_managers()
  * _build_channels / _build_vod
  * _clear_caches (the session's on_invalidate hook)

Why BOTH `self.authenticator` and `self.auth` exist: `self.auth` (JoynSession) is
what the managers use. `self.authenticator` (the raw JoynAuthenticator) is kept
because ProviderAuthMixin._build_provider_headers reaches for
`self.authenticator.get_bearer_token()` directly — shared with v1 providers.
Managers never use it.

DRM_IN_MANAGERS = True: manifest and DRM come from the same /playlist call, so
both managers override get_*_drm (built by drm.build_widevine_config) and share a
playout cache with their manifest method.

HEADERS_FROM_MANAGERS = True: the CDN set differs from the API set (no bearer);
the manager header hooks return the right set per call.

Known limitations (README §18):
  * A ProxyConfig only affects Python-side HTTPManager traffic. Licence, manifest
    and segment requests are made by inputstream.adaptive inside Kodi.
  * The 7pass login flow uses its own requests session inside the authenticator.
"""

from typing import ClassVar, Dict, List, Optional

from ...base.managed_provider import ManagedProvider
from ...base.models.proxy_models import ProxyConfig

from .auth import JoynAuthenticator
from .channel_manager import JoynChannelManager
from .config import JoynConfig
from .constants import JOYN_LOGO, PROVIDER_NAME, SUPPORTED_COUNTRIES
from .entitlement import JoynEntitlement
from .session import JoynSession
from .vod_manager import JoynVodManager

# Only the provider is public. Discovery takes the FIRST StreamingProvider
# subclass in the package namespace; ManagedProvider must never appear here.
__all__ = ["JoynProvider"]


class JoynProvider(ManagedProvider):
    PROVIDER_LABEL: ClassVar[str] = "Joyn"
    PROVIDER_LOGO: ClassVar[str] = JOYN_LOGO
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = [
        "client_credentials",
        "user_credentials",
    ]
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = SUPPORTED_COUNTRIES

    # Folded DRM (see module docstring). ManagedProvider refuses this flag
    # together with a non-None _build_drm().
    DRM_IN_MANAGERS: ClassVar[bool] = True

    # Manager header hooks return the CDN set (no bearer); without this flag
    # they would be dead code and the CDN would receive the API headers.
    HEADERS_FROM_MANAGERS: ClassVar[bool] = True

    def __init__(
            self,
            country: str = "DE",
            config: Optional[JoynConfig] = None,
            proxy_config: Optional[ProxyConfig] = None,
            proxy_url: Optional[str] = None,
            config_dir: Optional[str] = None,
    ):
        super().__init__(country=country)
        self.country = self.country.lower()
        if self.country not in SUPPORTED_COUNTRIES:
            raise NotImplementedError(
                f"Joyn does not support country {country!r} "
                f"(supported: {', '.join(SUPPORTED_COUNTRIES)})"
            )

        # 1. ONE config object, shared by every layer — including the
        # authenticator. Re-derive every country-dependent field: the caller's
        # config may have been built for another country.
        if config is None:
            config = JoynConfig(country=self.country)
        else:
            config.country = self.country  # setter keeps everything in sync
        self.provider_config = config

        # 2. HTTP manager.
        self.http_manager = self._setup_http_manager(
            provider_name=PROVIDER_NAME,
            proxy_config=proxy_config,
            proxy_url=proxy_url,
            config_dir=config_dir,
            user_agent=self.provider_config.user_agent,
            timeout=self.provider_config.timeout,
            max_retries=self.provider_config.max_retries,
        )

        # 3. Auth (two attributes on purpose — see module docstring).
        self.authenticator = JoynAuthenticator(
            country=self.country,
            platform=self.provider_config.platform,
            config_dir=config_dir,
            http_manager=self.http_manager,
            proxy_config=proxy_config,  # the raw ctor argument (may be None)
            config=self.provider_config,
        )
        self.auth = JoynSession(
            authenticator=self.authenticator,
            config=self.provider_config,
            on_invalidate=self._clear_caches,
        )

        # 4. Provider-owned caches, borrowed by managers by reference.
        self._playout_cache: Dict = {}
        self._entitlement_cache: Dict = {}

        # 5. Entitlement helper, shared by both managers via keyword extra.
        self._entitlement = JoynEntitlement(
            http_manager=self.http_manager,
            auth=self.auth,
            config=self.provider_config,
            cache=self._entitlement_cache,
        )

        # 6. Managers, in dependency order. self.channels is the ChannelManager
        # from here on — never assign a list to it. No eager login: the first
        # caller that needs a token logs in through self.auth.
        self._init_managers()

    # ------------------------------------------------------------------
    # Cache lifecycle (session.on_invalidate)
    # ------------------------------------------------------------------

    def _clear_caches(self) -> None:
        """Drop everything that is specific to the account / token.

        Registered as JoynSession's on_invalidate callback, so it runs on every
        credential change. Defensive about construction order: it can only be
        invoked after __init__, but the managers are optional by design.
        """
        self._playout_cache.clear()
        entitlement = getattr(self, "_entitlement", None)
        if entitlement is not None:
            entitlement.clear()
        vod = getattr(self, "vod", None)
        if vod is not None and hasattr(vod, "clear_cache"):
            vod.clear_cache()

    # ------------------------------------------------------------------
    # Manager factories
    # ------------------------------------------------------------------

    def _build_channels(self):
        return JoynChannelManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.provider_config,
            entitlement=self._entitlement,
            playout_cache=self._playout_cache,
        )

    def _build_vod(self):
        return JoynVodManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.provider_config,
            entitlement=self._entitlement,
        )

    # No _build_epg, no _build_catchup: Joyn does not have them. A provider
    # without a capability simply has no manager.

    # ------------------------------------------------------------------
    # Provider-specific id grammar
    # ------------------------------------------------------------------
    # None the router cannot express: live ids are bare slugs, VOD ids are
    # a_/b_/c_/d_/block-<n>/paths — both managers decide through ids.is_vod_id().

    @property
    def provider_name(self) -> str:
        return PROVIDER_NAME

    # ------------------------------------------------------------------
    # Credentials API (settings UI) — deliberately NOT added
    # ------------------------------------------------------------------
    # The migration pack found no caller of set_user_credentials /
    # get_auth_details / get_last_auth_error for Joyn. If the settings UI grows
    # one: build credentials -> assign -> self.auth.invalidate() (clears memory +
    # persisted token, resets backoff, runs _clear_caches) -> ONE login -> persist
    # only on success.