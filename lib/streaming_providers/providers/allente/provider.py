# streaming_providers/providers/allente/provider.py
"""
Allente streaming provider (SE only in v1).

Owns the shared resources (config, http_manager, authenticator, session,
playout cache) and builds the managers; capability flags, routing and the
manifest / DRM / header delegation are ManagedProvider's.

Manager wiring
--------------

    channels   -> AllenteChannelManager   (channel list, playout, folded
                                           Widevine DRM)
    everything else -> None               (no VOD, EPG, recordings,
                                           favorites, bookmarks, catchup)

    DRM_IN_MANAGERS = True   manifest and DRM share one playout response
    epg_window == (0, 0)     no EPG in v1 (ManagedProvider default)

Auth model: lazy with one opportunistic eager attempt.
  * __init__ attempts auth ONLY if credentials are already stored.
  * The managers gate on AllenteSession.require(), which raises typed
    errors (AuthError / GeoBlockError / ServerError). The previous
    provider logged and returned [] / None; get_channels() now raises when
    the account cannot log in. (To restore the old behaviour override
    get_channels with a try/except ProviderError returning [].)
  * No network I/O in __init__ when credentials are not configured.

Public API kept from the previous provider (settings UI, direct callers):
  * set_user_credentials(...)  -> bool
  * get_last_auth_error()      -> Optional[Exception]
  * get_auth_details(context)  -> Dict   (AuthStatus UI, via the auth mixin)
  * get_profile(), bearer_token, entitlement_tag, channel_manager,
    _ensure_authenticated()    -> thin compatibility delegates

Registry integration:
  * ProviderMetadata derives plugin_name "allente" from the class name,
    matching provider_name and the CredentialManager/SessionManager keys.
  * For a single-country provider with exactly one supported country,
    _extract_metadata() OVERRIDES the passed-in country with
    SUPPORTED_COUNTRIES[0] — VERBATIM, i.e. UPPERCASE "SE".

COUNTRY CASE (important):
  * The framework's storage managers (CredentialManager, SessionManager,
    ProxyConfigManager) key everything by LOWERCASE country ("se").
  * The registry constructs us with UPPERCASE "SE".
  * __init__ therefore normalizes self.country to lowercase, so the
    ProxyConfigManager lookup in _setup_http_manager and the credential
    lookup in the auth mixin hit the same keys the managers store under.

Known v1 limitation: the DRM config embeds the bearer token at get_drm()
time, and inputstream.adaptive caches it for the whole playback session.
Continuous playback beyond Zulu token expiry is NOT supported; a fresh
channel zap after refresh works.
"""

from typing import ClassVar, Dict, List, Optional

from ...base.managed_provider import ManagedProvider
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger
from .auth import AllenteAuthenticator
from .channel_manager import AllenteChannelManager
from .constants import AllenteConfig, AllenteDefaults
from .models import AllenteProfile, AllenteUserCredentials
from .session import AllenteSession

# Only the provider is public: provider discovery takes the first
# StreamingProvider subclass it finds in the package namespace, and
# ManagedProvider must never be that one.
__all__ = ["AllenteProvider"]


class AllenteProvider(ManagedProvider):
    """Allente provider implementation."""

    PROVIDER_LABEL: ClassVar[str] = "Allente"
    PROVIDER_LOGO: ClassVar[str] = AllenteDefaults.ALLENTE_LOGO
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["user_credentials"]
    # Single-entry list on purpose: the registry's len==1 rule pins the
    # construction country to this entry. When NO/DK/FI are added, make
    # this multi-entry — the registry fans out allente_no/allente_dk/...
    # automatically (multi-country path, which lowercases).
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = list(AllenteDefaults.SUPPORTED_COUNTRIES)

    DRM_IN_MANAGERS: ClassVar[bool] = True
    # The MPD needs origin/referer/UA (Akamai edge); they come from
    # AllenteChannelManager.get_channel_manifest_headers().
    HEADERS_FROM_MANAGERS: ClassVar[bool] = True

    @classmethod
    def supports_country(cls, country: str) -> bool:
        """Convenience capability check (settings UI, tests). Case-insensitive."""
        return country.upper() in cls.SUPPORTED_COUNTRIES

    def __init__(
        self,
        country: str = "SE",
        config: Optional[Dict] = None,
        proxy_config: Optional[ProxyConfig] = None,
    ):
        super().__init__(country=country)

        if not self.supports_country(country):
            raise NotImplementedError(
                f"Allente is not supported in country {country!r}. "
                f"Supported: {', '.join(self.SUPPORTED_COUNTRIES)}"
            )

        # Normalize to lowercase (see COUNTRY CASE above).
        self.country = self.country.lower()

        # ONE config object, shared with the authenticator, session,
        # managers and DRM builder. No header drift between layers.
        # NOTE: the registry constructs with country only — this dict is
        # for programmatic/test construction.
        self.provider_config = AllenteConfig({
            **(config or {}),
            "country": self.country,
        })

        # _setup_http_manager: proxy resolution order is constructor arg ->
        # ProxyConfigManager("allente", "se") -> global.
        self.http_manager = self._setup_http_manager(
            provider_name=AllenteDefaults.PROVIDER_NAME,
            proxy_config=proxy_config,
            user_agent=self.provider_config.user_agent,
            timeout=self.provider_config.timeout,
        )

        self.authenticator = AllenteAuthenticator(
            config=self.provider_config,
            http_manager=self.http_manager,
            proxy_config=proxy_config,
        )
        self.session = AllenteSession(
            authenticator=self.authenticator, config=self.provider_config
        )

        # Provider-owned cache, borrowed by the channel manager.
        self._playout_cache: Dict = {}

        self._init_managers()

        # Opportunistic eager auth — ONLY if credentials are already
        # stored. Never triggers a login with empty credentials.
        if self.session.has_credentials():
            try:
                self.session.ensure()
            except Exception as exc:
                logger.info(f"Allente: pre-login skipped ({exc}); will retry on demand")

    # ------------------------------------------------------------------
    # Required abstract members / metadata
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return AllenteDefaults.PROVIDER_NAME

    @property
    def provider_label(self) -> str:
        return self.PROVIDER_LABEL

    @property
    def provider_logo(self) -> str:
        return self.PROVIDER_LOGO

    @property
    def supported_auth_types(self) -> List[str]:
        return self.SUPPORTED_AUTH_TYPES

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    def _build_channels(self):
        return AllenteChannelManager(
            http_manager=self.http_manager,
            auth=self.session,
            country=self.country,
            config=self.provider_config,
            playout_cache=self._playout_cache,
        )

    # _build_vod / epg / recordings / favorites / bookmarks / catchup /
    # drm: inherited (None). DRM is folded into the channel manager.

    # ------------------------------------------------------------------
    # Auth surface (settings UI, auth mixin, direct callers)
    # ------------------------------------------------------------------

    def _ensure_authenticated(self) -> bool:
        """Compatibility: True when logged in (never raises)."""
        return self.session.ensure()

    def _reset_auth_state(self) -> None:
        """Clear all auth-derived state (used when credentials change)."""
        self.session.reset()
        self._playout_cache.clear()  # streamIds may be user/token-specific

    def get_last_auth_error(self) -> Optional[Exception]:
        """Return the most recent auth error (for direct callers)."""
        return self.session.last_error

    def get_profile(self) -> Optional[AllenteProfile]:
        """Return the currently selected profile (populated after auth)."""
        return self.session.profile

    @property
    def bearer_token(self) -> Optional[str]:
        return self.session.bearer_token

    @property
    def entitlement_tag(self) -> Optional[str]:
        return self.session.entitlement_tag

    @property
    def channel_manager(self):
        """Compatibility alias for self.channels (the ChannelManager)."""
        return self.channels

    def get_auth_details(self, context) -> Dict:
        """
        Provider-specific auth details for the AuthStatus UI (mixin hook).

        Surfaces the last auth error (OTP required, geoblocked, WAF, bad
        credentials) and the active profile through the framework's own
        status channel. Free-form dict per the mixin contract.
        """
        return self.session.details()

    def set_user_credentials(
        self,
        username: str,
        password: str,
        country: Optional[str] = None,
    ) -> bool:
        """
        Store credentials and log in immediately (exactly one authentication).

        invalidate_token() clears BOTH the in-memory token and the persisted
        one — required, or a restart would resurrect the old-credentials
        token from storage.
        """
        creds = AllenteUserCredentials(
            username=username,
            password=password,
            country=(country or self.country).lower(),
        )
        self.authenticator.credentials = creds

        self.authenticator.invalidate_token()   # memory + persisted storage
        self._reset_auth_state()

        if not self.session.ensure():
            return False  # last_error is set (OTP, WAF, bad creds, ...)

        self.authenticator.save_credentials(creds)
        return True