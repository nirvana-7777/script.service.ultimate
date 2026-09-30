# streaming_providers/providers/allente/provider.py
"""
Allente streaming provider (SE only in v1).

Public API (implemented here):
  * get_channels()              -> List[StreamingChannel]
  * get_manifest(channel_id)    -> MPD URL (abstract in base — required)
  * get_drm(channel_id, ...)    -> List[DRMConfig] (Widevine via Zulu)
  * set_user_credentials(...)   -> bool (Kodi settings UI)
  * get_last_auth_error()       -> Optional[Exception] (direct callers)
  * get_auth_details(context)   -> Dict (AuthStatus UI, via the auth mixin)

Inherited from StreamingProvider (verified against base source — do not
re-implement):
  * get_manifest_headers() / get_segment_headers() → overridden to send
                                   origin/referer/UA. Akamai's edge rejects
                                   requests without them (Access Denied HTML page).
                                   The response advertises access-control-allow-origin:
                                    * for CORS, but the actual gate is enforced at the edge.
  * get_events()/EPG/VOD/etc.   -> mixin defaults (empty) — out of v1 scope.
  * to_output_format()/to_json()-> consume self.channels, populated by
                                   get_channels().
  * enrich_channel_data()       -> base returns None. Designated pre-playback
                                   prefetch hook (playout + DRM). If
                                   integration testing shows the player
                                   calls it, implement via
                                   _resolve_playout_cached() and patch
                                   channel.manifest with the playout URL.

Registry integration (verified against provider_registry.py):
  * ProviderMetadata derives plugin_name "allente" from the class name —
    matching provider_name and the CredentialManager/SessionManager keys.
  * For a single-country provider with exactly one supported country,
    _extract_metadata() OVERRIDES the passed-in country with
    SUPPORTED_COUNTRIES[0] — VERBATIM, i.e. UPPERCASE "SE" (a framework
    quirk; see the country normalization in __init__). create_instance()
    additionally try/excepts construction, so enumeration never crashes.

COUNTRY CASE (important):
  * The framework's storage managers (CredentialManager, SessionManager,
    ProxyConfigManager) key everything by LOWERCASE country ("se").
  * The registry constructs us with UPPERCASE "SE" (see above).
  * __init__ therefore normalizes self.country to lowercase, so the
    ProxyConfigManager lookup in _setup_http_manager and the
    AuthContext.get_credentials() lookup in the auth mixin hit the same
    keys the managers store under. Without this, a country-specific
    proxy is silently missed and stored credentials are not found.

Auth model: lazy with one opportunistic eager attempt.
  * __init__ attempts auth ONLY if credentials are already stored.
  * Every public method gates on _ensure_authenticated().
  * No network I/O in __init__ when credentials are not configured.

Known v1 limitation: the DRM config embeds the bearer token at get_drm()
time, and inputstream.adaptive caches it for the whole playback session.
Continuous playback beyond Zulu token expiry is NOT supported; a fresh
channel zap after refresh works.
"""

import time
from typing import ClassVar, Dict, List, Optional, Tuple

from ...base.models import DRMConfig, StreamingChannel
from ...base.models.proxy_models import ProxyConfig
from ...base.provider import StreamingProvider
from ...base.utils.logger import logger
from .auth import AllenteAuthenticator, AllenteOTPRequiredError
from .channel_manager import AllenteChannelManager
from .constants import AllenteConfig, AllenteDefaults
from .drm import create_allente_widevine_config
from .models import AllentePlayoutInfo, AllenteProfile, AllenteUserCredentials


class AllenteProvider(StreamingProvider):
    """Allente provider implementation."""

    PROVIDER_LABEL: ClassVar[str] = "Allente"
    PROVIDER_LOGO: ClassVar[str] = AllenteDefaults.ALLENTE_LOGO
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["user_credentials"]
    # Single-entry list on purpose: the registry's len==1 rule pins the
    # construction country to this entry. When NO/DK/FI are added, make
    # this multi-entry — the registry fans out allente_no/allente_dk/...
    # automatically (multi-country path, which lowercases).
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = list(AllenteDefaults.SUPPORTED_COUNTRIES)

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

        # Normalize to lowercase: every framework manager keys by lowercase
        # country ("se"), while the registry constructs single-country
        # providers with the UPPERCASE SUPPORTED_COUNTRIES[0] ("SE").
        # Without this, the ProxyConfigManager lookup inside
        # _setup_http_manager (country defaults to self.country) and the
        # AuthContext.get_credentials() lookup in the auth mixin both miss.
        self.country = self.country.lower()

        # ONE config object, shared with the authenticator, channel
        # manager, and DRM builder. No header drift between layers.
        # NOTE: the registry constructs with country only — this dict is
        # for programmatic/test construction. Registry-created instances
        # rely on framework config systems (CredentialManager,
        # ProxyConfigManager, settings manager).
        self.provider_config = AllenteConfig({
            **(config or {}),
            "country": self.country,
        })

        # _setup_http_manager (verified signature): proxy resolution order
        # is constructor arg -> ProxyConfigManager("allente", "se") ->
        # global. user_agent/timeout map onto RequestConfig fields.
        self.http_manager = self._setup_http_manager(
            provider_name="allente",
            proxy_config=proxy_config,
            user_agent=self.provider_config.user_agent,
            timeout=self.provider_config.timeout,
        )

        self.authenticator = AllenteAuthenticator(
            config=self.provider_config,
            http_manager=self.http_manager,
            proxy_config=proxy_config,
        )
        # No _share_http_manager_with_authenticator call: it returns the
        # authenticator's manager when one exists, and ours always does
        # (the constructor raises otherwise) — the call would be a no-op
        # returning the identical object.

        self.channel_manager = AllenteChannelManager(self)

        # Lazy-auth state (populated by _ensure_authenticated)
        self.bearer_token: Optional[str] = None
        self.entitlement_tag: Optional[str] = None
        self._profile: Optional[AllenteProfile] = None

        # Playout cache (channel_id -> (info, timestamp))
        self._playout_cache: Dict[str, Tuple[AllentePlayoutInfo, float]] = {}

        self._last_auth_error: Optional[Exception] = None

        # Opportunistic eager auth — ONLY if credentials are already
        # stored. Never triggers a login with empty credentials.
        if self.authenticator.has_user_credentials():
            try:
                self._ensure_authenticated()
            except Exception as exc:
                logger.info(f"Allente: pre-login skipped ({exc}); will retry on demand")

    # ------------------------------------------------------------------
    # Required abstract members
    # ------------------------------------------------------------------
    @property
    def provider_name(self) -> str:
        return "allente"

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
    # Auth gate — every public method calls this first
    # ------------------------------------------------------------------
    def _ensure_authenticated(self) -> bool:
        """
        Ensure we have a valid Zulu token, entitlement tag, and profile.
        Idempotent. Safe to call from any public method.

        The fast path uses the token's own is_expired (the base's property
        with its fixed 300s buffer) — the exact same check
        BaseAuthenticator.authenticate() uses in step 1, so the two can
        never disagree.
        """
        tok = self.authenticator.current_token
        if (
            self.bearer_token
            and self.entitlement_tag
            and self._profile
            and tok is not None
            and not tok.is_expired
        ):
            return True

        if not self.authenticator.has_user_credentials():
            self._last_auth_error = RuntimeError(
                "Allente: no credentials configured. "
                "Set username and password in the addon settings."
            )
            logger.warning(str(self._last_auth_error))
            return False

        try:
            # BaseAuthenticator: cached token -> refresh -> full login.
            token = self.authenticator.authenticate()

            # A persisted token from an older schema may be missing the
            # entitlement tag. authenticate() would keep returning it
            # forever, so discard it once (base invalidate_token() also
            # clears persisted storage) and force a fresh login.
            if token is not None and not getattr(token, "entitlement_tag", None):
                logger.warning(
                    "Allente: cached token missing entitlementTag — forcing re-login"
                )
                self.authenticator.invalidate_token()
                token = self.authenticator.authenticate(force_refresh=True)

            if token is None:
                self._last_auth_error = RuntimeError(
                    "Allente: authentication returned no token."
                )
                logger.error(str(self._last_auth_error))
                return False

            if getattr(token, "geoblocked", False):
                self._last_auth_error = RuntimeError(
                    f"Allente: account is geoblocked for "
                    f"{getattr(token, 'content_domain_id', 'unknown')}"
                )
                logger.error(str(self._last_auth_error))
                return False

            if not token.entitlement_tag:
                self._last_auth_error = RuntimeError(
                    "Allente: login response is missing entitlementTag — "
                    "cannot fetch channels."
                )
                logger.error(str(self._last_auth_error))
                return False

            self.bearer_token = token.access_token
            self.entitlement_tag = token.entitlement_tag

            # Lazy profile fetch (also covers restart with a restored token).
            if self._profile is None:
                self._profile = self.authenticator.ensure_profile(token)

            if not self._profile:
                self._last_auth_error = RuntimeError(
                    "Allente: no profile available for this account."
                )
                logger.error(str(self._last_auth_error))
                return False

            self._last_auth_error = None
            logger.info(
                f"Allente: authenticated (userId={token.user_id}, "
                f"profile={self._profile.id})"
            )
            return True

        except AllenteOTPRequiredError as exc:
            self._last_auth_error = exc
            logger.error(f"Allente: account requires OTP — {exc}")
            return False
        except Exception as exc:
            self._last_auth_error = exc
            logger.error(f"Allente: authentication failed — {exc}")
            return False

    def _reset_auth_state(self) -> None:
        """Clear all auth-derived state (used when credentials change)."""
        self.bearer_token = None
        self.entitlement_tag = None
        self._profile = None
        self._last_auth_error = None
        self._playout_cache.clear()  # streamIds may be user/token-specific

    def get_last_auth_error(self) -> Optional[Exception]:
        """Return the most recent auth error (for direct callers)."""
        return self._last_auth_error

    def get_profile(self) -> Optional[AllenteProfile]:
        """Return the currently selected profile (populated after auth)."""
        return self._profile

    # ------------------------------------------------------------------
    # Auth-status integration (ProviderAuthMixin hooks)
    # ------------------------------------------------------------------
    def get_auth_details(self, context) -> Dict:
        """
        Provider-specific auth details for the AuthStatus UI (mixin hook).

        Surfaces the last auth error (OTP required, geoblocked, WAF, bad
        credentials) and the active profile through the framework's own
        status channel. Free-form dict per the mixin contract.
        """
        details: Dict = {}
        if self._last_auth_error is not None:
            details["last_error"] = str(self._last_auth_error)
            details["last_error_type"] = type(self._last_auth_error).__name__
        if self._profile is not None:
            details["profile_id"] = self._profile.id
            details["profile_kids"] = self._profile.kids
        return details

    # ------------------------------------------------------------------
    # Channels
    # ------------------------------------------------------------------
    def get_channels(self, **kwargs) -> List[StreamingChannel]:
        if not self._ensure_authenticated():
            return []
        try:
            channels = self.channel_manager.get_channels_as_streaming_channels()
            self.channels = channels  # consumed by to_output_format()/to_json()
            return channels
        except Exception as exc:
            logger.error(f"Allente: get_channels failed — {exc}")
            return []

    # ------------------------------------------------------------------
    # Playout cache — get_manifest and get_drm share one call
    # ------------------------------------------------------------------
    def _resolve_playout_cached(self, channel_id: str) -> Optional[AllentePlayoutInfo]:
        now = time.time()
        cached = self._playout_cache.get(channel_id)
        if cached and (now - cached[1]) < AllenteDefaults.PLAYOUT_CACHE_TTL:
            return cached[0]
        try:
            result = self.channel_manager.resolve_playout(channel_id)
        except Exception as exc:
            logger.error(f"Allente: playout failed for {channel_id} — {exc}")
            return None
        if result:
            self._playout_cache[channel_id] = (result, now)
        return result

    # ------------------------------------------------------------------
    # Manifest
    # ------------------------------------------------------------------
    def get_manifest(self, content_id: str, **kwargs) -> Optional[str]:
        """Resolve the MPD URL for a channel (content_id = channel ID)."""
        if not self._ensure_authenticated():
            return None
        playout = self._resolve_playout_cached(content_id)
        return playout.stream_url if playout else None

    def get_manifest_headers(self, content_id: str, **kwargs) -> Dict[str, str]:
        """
        Headers for the MPD fetch.

        Akamai fronts stream-live-01.allente.tv and rejects requests without
        a whitelisted origin/referer (returns an Akamai "Access Denied"
        HTML page). The CDN also advertises access-control-allow-origin: *
        for CORS, but that is a browser-level policy — the actual gate is
        enforced at the edge based on these headers.

        We send the same origin/referer/UA the browser sends.
        """
        return {
            "origin": AllenteDefaults.TV_WEB_ORIGIN,
            "referer": AllenteDefaults.TV_WEB_REFERER,
            "user-agent": self.provider_config.user_agent,
        }

    # ------------------------------------------------------------------
    # DRM (Widevine via Zulu)
    # ------------------------------------------------------------------
    def get_drm(
        self,
        content_id: str,
        drm_variant: Optional[str] = None,
        **kwargs,
    ) -> List[DRMConfig]:
        """
        Return DRM configuration for a channel.

        drm_variant is part of the base-class contract (examples: 'auto',
        'software'). v1 accepts and ignores it — the Widevine security
        level comes from provider_config.widevine_level. Mapping variants
        to levels (software -> L3, hardware -> L1) is a v1.1 candidate and
        would also require keying the playout cache by level, since
        widevineLevel is a playout request parameter.

        NOTE: the license config embeds the CURRENT bearer token, and ISA
        reuses it for the whole playback session. Continuous playback
        across token expiry is not supported in v1.
        """
        if drm_variant:
            logger.debug(f"Allente: get_drm drm_variant={drm_variant!r} — ignored in v1")

        if not self._ensure_authenticated():
            return []

        playout = self._resolve_playout_cached(content_id)
        if not playout:
            logger.error(f"Allente: no playout info for channel {content_id}")
            return []

        if playout.drm_type != "Widevine":
            logger.warning(
                f"Allente: channel {content_id} uses {playout.drm_type}, "
                f"not Widevine. Unencrypted/other-DRM playback is not "
                f"supported in v1."
            )
            return []

        try:
            return [create_allente_widevine_config(
                cfg=self.provider_config,
                bearer_token=self.bearer_token,
                stream_id=playout.stream_id,
            )]
        except Exception as exc:
            logger.error(f"Allente: DRM config build failed for {content_id} — {exc}")
            return []

    # ------------------------------------------------------------------
    # Credentials helper (used by Kodi settings UI)
    # ------------------------------------------------------------------
    def set_user_credentials(
        self,
        username: str,
        password: str,
        country: Optional[str] = None,
    ) -> bool:
        """
        Store credentials and log in immediately (exactly one authentication).

        The base's invalidate_token() clears BOTH the in-memory token and
        the persisted one — required, or a restart would resurrect the
        old-credentials token from storage.
        """
        creds = AllenteUserCredentials(
            username=username,
            password=password,
            country=(country or self.country).lower(),
        )
        self.authenticator.credentials = creds

        self.authenticator.invalidate_token()   # base: memory + persisted storage
        self._reset_auth_state()

        if not self._ensure_authenticated():
            return False  # _last_auth_error is set (OTP, WAF, bad creds, ...)

        self.authenticator.save_credentials(creds)
        return True