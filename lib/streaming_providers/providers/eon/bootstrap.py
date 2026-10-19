# streaming_providers/providers/eon/bootstrap.py
"""
Lazy bootstrap data. Nothing here runs in __init__ (no network there).

EonEndpoints  -- resolves the brand's API host via the broker (v2/brands ->
                 cdnIdentifier, v1/cdninfo -> domains.baseApi[selector]).
                 Needs NO login: broker calls carry the client credentials.
EonCatalog    -- rendering profiles, streaming servers and the service-provider
                 id. These need a logged-in session, so they sit behind EonApi
                 and are cached with a TTL.

Brand resolution is by IDENTIFIER, never by list position: the broker's list
has changed before. An unknown brand falls back to the CDN the broker marks
`isDefault` (shared by the ex-Yu brands), then to the global host.
"""

import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from ...base.errors import ConfigurationError, ServerError
from ...base.utils.logger import logger
from ...base.utils.transport import transport_errors
from .constants import EonConfig, EonDefaults
from .models import EonRenderingProfile, EonServer

_PROVIDER = EonDefaults.PROVIDER_LABEL


class EonEndpoints:
    def __init__(self, *, http_manager: Any, config: EonConfig):
        self._http = http_manager
        self._config = config
        self._lock = threading.RLock()
        self._api_base: Optional[str] = None
        self._images_base: Optional[str] = None

    # ------------------------------------------------------------------
    @property
    def api_base(self) -> str:
        self._ensure()
        return self._api_base  # type: ignore[return-value]

    @property
    def images_base(self) -> str:
        """Host for logos / programme images (same CDN as the API)."""
        self._ensure()
        return self._images_base  # type: ignore[return-value]

    def _ensure(self) -> None:
        if self._api_base is None:
            with self._lock:
                if self._api_base is None:
                    self._api_base, self._images_base = self._resolve()

    def reset(self) -> None:
        """Forget the resolved host (e.g. after repeated connection failures)."""
        with self._lock:
            self._api_base = None
            self._images_base = None

    def url(self, path: str) -> str:
        return f"{self.api_base}{path}"

    def image_url(self, path: Optional[str]) -> Optional[str]:
        """Image paths start with `/`, the base ends with one: join with a
        single slash (the addon concatenated them, giving `//`)."""
        if not path:
            return None
        return self.images_base.rstrip("/") + "/" + path.lstrip("/")

    # ------------------------------------------------------------------
    def _resolve(self) -> Tuple[str, str]:
        cdn_identifier = self._brand_cdn_identifier()
        base_api = self._cdn_base_api(cdn_identifier)
        prefix = self._config.platform.api_prefix
        if base_api:
            api = f"https://api-{prefix}.{base_api}/"
            images = f"https://images-{prefix}.{base_api}/"
        else:
            # GLOBAL_HOST already ends with its own slash.
            api = f"https://api-{prefix}.{EonDefaults.GLOBAL_HOST}"
            images = f"https://images-{prefix}.{EonDefaults.GLOBAL_HOST}"
            logger.warning(f"{_PROVIDER}: no CDN base API found; using global host")
        logger.info(f"{_PROVIDER}: API host resolved ({self._config.brand})")
        return api, images

    def _broker_get(self, path: str, what: str) -> Any:
        with transport_errors(what, _PROVIDER):
            resp = self._http.get(
                EonDefaults.BROKER_URL + path,
                headers=self._config.basic_headers(),
                operation="api",
            )
            return resp.json()

    def _brand_cdn_identifier(self) -> str:
        brands = self._broker_get(EonDefaults.PATH_BRANDS, "brands")
        if not isinstance(brands, list):
            raise ServerError(f"{_PROVIDER}: brands response is not a list")
        for brand in brands:
            if isinstance(brand, dict) and brand.get("identifier") == self._config.brand_identifier:
                return brand.get("cdnIdentifier") or ""
        logger.warning(
            f"{_PROVIDER}: brand {self._config.brand_identifier!r} not in the "
            f"broker's list; using the broker's default CDN"
        )
        return ""

    def _cdn_base_api(self, cdn_identifier: str) -> str:
        cdns = self._broker_get(EonDefaults.PATH_CDNINFO, "cdninfo")
        if not isinstance(cdns, list):
            raise ServerError(f"{_PROVIDER}: cdninfo response is not a list")
        selector = self._config.platform.api_selector
        default = ""
        for cdn in cdns:
            if not isinstance(cdn, dict):
                continue
            base = ((cdn.get("domains") or {}).get("baseApi") or {}).get(selector) or ""
            if cdn_identifier and cdn.get("identifier") == cdn_identifier and base:
                return base
            if cdn.get("isDefault") and base:
                default = base
        if default:
            logger.warning(f"{_PROVIDER}: no CDN matched; using the broker's default CDN")
        return default


class EonCatalog:
    def __init__(self, *, api: Any, config: EonConfig):
        self._api = api
        self._config = config
        self._lock = threading.RLock()
        self._loaded_at = 0.0
        self._service_provider = ""
        self._profiles: Dict[int, EonRenderingProfile] = {}
        self._live_servers: List[EonServer] = []
        self._timeshift_servers: List[EonServer] = []

    def invalidate(self) -> None:
        with self._lock:
            self._loaded_at = 0.0

    # ------------------------------------------------------------------
    def _ensure(self) -> None:
        if self._loaded_at and time.time() - self._loaded_at < EonDefaults.CATALOG_TTL_SECONDS:
            return
        with self._lock:
            if self._loaded_at and time.time() - self._loaded_at < EonDefaults.CATALOG_TTL_SECONDS:
                return
            self._load()

    def _load(self) -> None:
        sp = self._api.get_json(EonDefaults.PATH_SERVICE_PROVIDER)
        service_provider = sp.get("identifier") if isinstance(sp, dict) else None
        if not service_provider:
            raise ServerError(f"{_PROVIDER}: service provider response has no identifier")

        raw_profiles = self._api.get_json(EonDefaults.PATH_PROFILES)
        if not isinstance(raw_profiles, list):
            raise ServerError(f"{_PROVIDER}: rendering profiles response is not a list")
        profiles: Dict[int, EonRenderingProfile] = {}
        for entry in raw_profiles:
            try:
                p = EonRenderingProfile.from_api_response(entry)
                profiles[p.id] = p
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning(f"{_PROVIDER}: skipping malformed rendering profile: {exc!r}")

        raw_servers = self._api.get_json(EonDefaults.PATH_SERVERS)
        if not isinstance(raw_servers, dict):
            raise ServerError(f"{_PROVIDER}: servers response is not an object")

        self._service_provider = service_provider
        self._profiles = profiles
        self._live_servers = self._parse_servers(raw_servers.get("live_servers"))
        self._timeshift_servers = self._parse_servers(raw_servers.get("timeshift_servers"))
        self._loaded_at = time.time()

    @staticmethod
    def _parse_servers(raw: Any) -> List[EonServer]:
        servers: List[EonServer] = []
        for entry in raw or []:
            try:
                servers.append(EonServer.from_api_response(entry))
            except (KeyError, TypeError) as exc:
                logger.warning(f"{_PROVIDER}: skipping malformed server entry: {exc!r}")
        return servers

    # ------------------------------------------------------------------
    @property
    def service_provider(self) -> str:
        self._ensure()
        return self._service_provider

    def best_profile(self, profile_ids: List[int], *, radio: bool) -> EonRenderingProfile:
        """Highest-bitrate profile among the channel's ids (audio bitrate for
        radio, video bitrate otherwise)."""
        self._ensure()
        best: Optional[EonRenderingProfile] = None
        best_rate = 0
        for pid in profile_ids:
            profile = self._profiles.get(pid)
            if not profile:
                continue
            rate = profile.audio_bitrate if radio else profile.video_bitrate
            if rate > best_rate:
                best, best_rate = profile, rate
        if best is None:
            raise ServerError(f"{_PROVIDER}: no usable rendering profile for ids {profile_ids}")
        return best

    def server(self, *, live: bool) -> EonServer:
        """The Nth server of the list (positional, as the addon did)."""
        self._ensure()
        servers = self._live_servers if live else self._timeshift_servers
        index = self._config.server_index
        if len(servers) < index:
            raise ServerError(
                f"{_PROVIDER}: expected at least {index} "
                f"{'live' if live else 'timeshift'} servers, got {len(servers)}"
            )
        server = servers[index - 1]
        if not server.hostname:
            raise ServerError(f"{_PROVIDER}: server #{index} has no hostname")
        return server