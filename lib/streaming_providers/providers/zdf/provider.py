# streaming_providers/providers/zdf/provider.py
"""
ZDF provider (live TV of ZDF, ZDFneo, ZDFinfo, 3sat, phoenix, KiKA, ARTE).

Capabilities: channels only. Clear DASH streams, no account, no DRM, no EPG
(the generic XMLTV path answers EPG), no catchup.

Known limitations:
  * Streams are geo-limited to Germany; a ProxyConfig only affects the
    Python-side API calls. The manifest and segment fetches are made by
    inputstream.adaptive inside Kodi and do not use it.
  * The api-auth client tokens are public web-player tokens and may be rotated
    by ZDF (config keys api_token / list_token / app_id).
"""

from typing import ClassVar, Dict, List, Optional, Tuple

from ...base.managed_provider import ManagedProvider
from ...base.models.proxy_models import ProxyConfig
from .auth import ZdfAuth
from .channel_manager import ZdfChannelManager
from .constants import ZdfConfig, ZdfDefaults

__all__ = ["ZdfProvider"]


class ZdfProvider(ManagedProvider):
    PROVIDER_LABEL: ClassVar[str] = ZdfDefaults.PROVIDER_LABEL
    PROVIDER_LOGO: ClassVar[str] = ZdfDefaults.PROVIDER_LOGO
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = []     # no user authentication
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = list(ZdfDefaults.SUPPORTED_COUNTRIES)

    # Decision 1 (§11): clear streams, no DRM at all -> no folded DRM, no _build_drm().
    DRM_IN_MANAGERS: ClassVar[bool] = False
    # Decision 2 (§10): the manager's CDN headers (UA/Origin/Referer, no tokens)
    # are what the player must send for MPD and segments.
    HEADERS_FROM_MANAGERS: ClassVar[bool] = True

    @property
    def provider_name(self) -> str:
        return ZdfDefaults.PROVIDER_NAME

    def __init__(
        self,
        country: str = "DE",
        config: Optional[Dict] = None,
        proxy_config: Optional[ProxyConfig] = None,
    ):
        super().__init__(country=country)
        self.country = self.country.lower()
        if self.country.upper() not in ZdfDefaults.SUPPORTED_COUNTRIES:
            raise NotImplementedError(f"{ZdfDefaults.PROVIDER_LABEL}: unsupported country {country!r}")

        # 1. ONE config, shared with auth and the manager
        self.provider_config = ZdfConfig(config or {})
        # 2. HTTP
        self.http_manager = self._setup_http_manager(
            provider_name=ZdfDefaults.PROVIDER_NAME,
            proxy_config=proxy_config,
            user_agent=self.provider_config.user_agent,
            timeout=self.provider_config.timeout,
        )
        # 3. auth (static public tokens, nothing lazy to do)
        self.auth = ZdfAuth(config=self.provider_config)
        # 4. caches (provider-owned, borrowed by the manager)
        self._ptmd_cache: Dict[str, Tuple[str, float]] = {}
        # 5. managers -- must be the last line
        self._init_managers()

    def _build_channels(self) -> ZdfChannelManager:
        return ZdfChannelManager(
            http_manager=self.http_manager,
            auth=self.auth,
            country=self.country,
            config=self.provider_config,
            ptmd_cache=self._ptmd_cache,
        )
