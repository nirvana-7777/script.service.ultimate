# streaming_providers/providers/magenta2/provider.py
# -*- coding: utf-8 -*-
"""
Magenta2 streaming provider.

This module contains only lifecycle, authentication, and the thin public API
that delegates to the domain managers:

    ChannelManager     – channel discovery, entitlement, streaming-data population
    PlaybackManager    – manifest / DRM routing (live fast-path + SMIL fallback)
    VodManager         – VOD catalogue browsing
    RecordingsManager  – nPVR recordings (list / delete / manifest)
    TimersManager      – nPVR scheduled recordings (timer CRUD)
    SmilManager        – SMIL-based manifest and DRM for VOD / recordings
    Magenta2EpgManager – EPG grid + programme-details (ThePlatform API)
"""
import hashlib
import random
import threading
import uuid
from datetime import datetime
from typing import Any, ClassVar, Dict, List, NamedTuple, Optional, Tuple, cast, Union
from urllib.parse import quote

from ...base.auth.session_manager import SessionManager
from ...base.models import DRMConfig, StreamingChannel, Event
from ...base.models.auth import AuthState
from ...base.models.epg_models import EPGEntry, EPGProgramDetails
from ...base.models.proxy_models import ProxyConfig
from ...base.network import HTTPManagerFactory, ProxyConfigManager
from ...base.provider import StreamingProvider
from ...base.utils.logger import logger
from .recordings_manager import RecordingsManager
from .timers_manager import TimersManager
from .smil_manager import SmilManager
from .vod_manager import VodManager
from .auth import Magenta2Authenticator, Magenta2Credentials, Magenta2UserCredentials
from .channel_manager import ChannelManager
from .epg_manager import Magenta2EpgManager
from .playback_manager import PlaybackManager
from .config_models import ProviderConfig
from .constants import (
    CONTENT_TYPE_LIVE,
    DEFAULT_COUNTRY,
    DEFAULT_EPG_WINDOW_HOURS,
    DEFAULT_MAX_RETRIES,
    DEFAULT_PLATFORM,
    DEFAULT_REQUEST_TIMEOUT,
    MAGENTA2_LEGACY_CLIENT_IDS,
    MAGENTA2_LOGO,
    MAGENTA2_PLATFORMS,
    SUPPORTED_COUNTRIES,
    render_user_agent,
)
from . import constants as _constants
from .discovery import DiscoveryService
from .endpoint_manager import EndpointManager
from .models import Magenta2PlaybackRestrictedException  # noqa: F401 – re-exported
from .auth_bridge import AuthBridge

# drm_variant vocabulary as documented by ProviderCatchupMixin — used only
# for the epg_id misroute warning in get_catchup_manifest().
_KNOWN_DRM_VARIANTS = ("auto", "software", "hardware")

# Key fragments that mark a dict value as secret-looking, for the
# _redact() safety net in debug_authentication().
_SENSITIVE_KEY_PARTS = (
    "token", "secret", "password", "authorization", "jwt",
    "cookie", "credential", "bearer", "key",
)

# Values that can ONLY be a legacy positional content_type argument, never a
# legitimate drm_variant — no DRM-variant vocabulary contains content-type
# tokens, so matching these has no false positives. Derived from every
# CONTENT_TYPE_* constant in .constants so a missed spelling is impossible.
_MISROUTE_DRM_VARIANT_TOKENS = frozenset(
    v.lower()
    for k, v in vars(_constants).items()
    if k.startswith("CONTENT_TYPE_") and isinstance(v, str)
)


class _ManagerBundle(NamedTuple):
    """A fully-constructed domain-manager set, published by a single
    attribute assignment so readers can never observe a mixed generation."""
    vod: VodManager
    recordings: RecordingsManager
    timers: TimersManager
    smil: SmilManager
    channel: ChannelManager
    playback: PlaybackManager
    epg: Magenta2EpgManager


class Magenta2Provider(StreamingProvider):
    """
    Magenta2 streaming provider implementation with enhanced dynamic discovery.
    """

    # ── Static metadata (StreamingProvider ClassVar contract) ──────────────
    # Readable without instantiation; the @property twins below return these
    # so there is exactly one source of truth per value.
    PROVIDER_LABEL: ClassVar[str] = "Magenta TV 2.0"
    PROVIDER_LOGO: ClassVar[str] = MAGENTA2_LOGO
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = ["network_based"]
    # RHS resolves to the module-level import from .constants (the name is
    # not yet in the class namespace at this point); list() copies it so the
    # ClassVar never aliases the mutable constants-module object.
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = list(SUPPORTED_COUNTRIES)
    implements_timers: ClassVar[bool] = True

    def __init__(
        self,
        country: str = DEFAULT_COUNTRY,
        platform: str = DEFAULT_PLATFORM,
        config_dir: Optional[str] = None,
        proxy_config: Optional[ProxyConfig] = None,
        proxy_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        super().__init__(country=country)

        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(
                f"Unsupported country: {country}. Must be one of: {SUPPORTED_COUNTRIES}"
            )

        self.platform = platform
        if platform not in MAGENTA2_PLATFORMS:
            raise ValueError(
                f"Unknown platform '{platform}'. Supported: {list(MAGENTA2_PLATFORMS.keys())}"
            )
        self.platform_config = MAGENTA2_PLATFORMS[platform]
        self.user_agent_plain = render_user_agent(platform, subscriber_suffix=False)
        self.user_agent_subscriber = render_user_agent(platform, subscriber_suffix=True)

        # session_id is fresh per process launch (matches the real client's
        # UUIDv1 wire format) but uses a RANDOM node so the host/container
        # MAC address is never embedded and never leaves the machine in
        # x-dt-session-id. Bit 40 (the multicast bit, RFC 4122) marks the
        # node as random rather than a hardware address. Accepted risk: a
        # real device's MAC has that bit clear, so a node-checking server
        # could tell — but fabricating a unicast MAC risks colliding with a
        # real device's address, which is worse.
        self.session_id = str(uuid.uuid1(node=random.getrandbits(48) | (1 << 40)))

        # ── Session persistence (shared session.json) ─────────────────────────
        # The provider needs only the SessionManager half of SettingsManager,
        # so construct it directly — the same way SettingsManager itself does
        # (SessionManager(config_dir_path)). The same `config_dir` is passed
        # to Magenta2Authenticator below, so this class, the authenticator
        # and its TokenFlowManager all resolve the SAME session.json through
        # the same VFS paths (one device_id / serial_number per installation).
        self._session_manager: SessionManager = SessionManager(config_dir)

        # device_id: read from the SAME persisted source TokenFlowManager
        # already uses (SessionManager.get_device_id), which itself
        # generates-and-persists on first call. Do NOT generate a second,
        # independent device_id here — doing so would make discovery/SMIL
        # send one device_id while the TAA/yo_digital token flow uses a
        # different one, and the server would see two "devices" for one
        # installation. get_device_id() currently persists a uuid4 — keep
        # that format; do not switch to uuid1 for this value.
        self.device_id = self._session_manager.get_device_id(
            self.provider_name, self.country
        )

        # serial_number: same load-or-generate pattern, its own persisted key.
        self.serial_number = self._get_or_create_serial_number()

        # ── Proxy ────────────────────────────────────────────────────────────
        self.proxy_config = (
            proxy_config
            or (ProxyConfig.from_url(proxy_url) if proxy_url else None)
            or self._load_proxy_from_manager(config_dir)
        )
        if self.proxy_config:
            logger.info("Using proxy configuration for Magenta2")
        else:
            logger.debug("No proxy configuration found for Magenta2")

        # ── HTTP manager ─────────────────────────────────────────────────────
        self.http_manager = HTTPManagerFactory.create_for_provider(
            provider_name="magenta2",
            proxy_config=self.proxy_config,
            user_agent=self.user_agent_plain,
            timeout=DEFAULT_REQUEST_TIMEOUT,
            max_retries=DEFAULT_MAX_RETRIES,
        )

        # ── Discovery service ────────────────────────────────────────────────
        self.discovery_service = DiscoveryService(
            platform=platform,
            device_id=self.device_id,
            session_id=self.session_id,
            http_manager=self.http_manager,
            proxy_config=self.proxy_config,
        )

        # Serializes configuration refreshes end-to-end (whole
        # refresh_configuration body). Readers never take it: the manager
        # bundle is published by a single attribute assignment.
        self._refresh_lock = threading.Lock()

        # Both are assigned concrete values by _perform_configuration_discovery()
        # before __init__ returns — or discovery raises and construction never
        # completes (fail-hard: there is no fallback configuration). cast(None)
        # is a typed sentinel so the class-level annotations stay non-Optional
        # and other methods see EndpointManager / ProviderConfig directly.
        self.endpoint_manager = cast(EndpointManager, cast(object, None))
        self.provider_config = cast(ProviderConfig, cast(object, None))

        # ── Authenticator (minimal config; updated after discovery) ──────────
        # This placeholder client_id is replaced by the server-provided
        # sam3ClientId in _configure_authenticator_from_discovery() below —
        # UNLESS the discovered config lacks a sam3_client_id, in which case
        # this legacy fallback persists (and discovery has already warned
        # that the config is incomplete). It also covers the window before
        # discovery completes; no authenticator call that depends on the
        # real client_id happens inside this constructor.
        fallback_client_id = MAGENTA2_LEGACY_CLIENT_IDS.get(
            platform, MAGENTA2_LEGACY_CLIENT_IDS[DEFAULT_PLATFORM]
        )

        if username and password:
            credentials: Union[Magenta2Credentials, Magenta2UserCredentials] = (
                Magenta2UserCredentials(
                    client_id=fallback_client_id,
                    platform=platform,
                    country=country,
                    device_id=self.device_id,
                    username=username,
                    password=password,
                )
            )
            logger.info("Using user credentials for authentication")
        else:
            credentials = Magenta2Credentials(
                client_id=fallback_client_id,
                platform=platform,
                country=country,
                device_id=self.device_id,
            )
            logger.info("Using client credentials for authentication")

        self.authenticator = Magenta2Authenticator(
            country=country,
            platform=platform,
            config_dir=config_dir,
            http_manager=self.http_manager,
            credentials=credentials,
            endpoints={},
            client_model=f"ftv-{platform}",
            device_model=f"{platform.upper()}_FTV",
            sam3_client_id=fallback_client_id,
            session_id=self.session_id,
            device_id=self.device_id,
            provider_config=None,
        )

        # ── Configuration discovery (fail-hard) ──────────────────────────────
        # _perform_configuration_discovery() logs and re-raises on failure;
        # construction never completes with a half-configured provider.
        self._perform_configuration_discovery()

        # ── Update authenticator with discovered config ───────────────────────
        self._configure_authenticator_from_discovery(self.provider_config, self.endpoint_manager)

        # ── recording content_id → manifest_script; shared with PlaybackManager ──
        # Survives refresh_configuration() rebuilds (playback cache, not config state).
        self._recording_url_cache: Dict[str, str] = {}

        # ── Auth bridge ───────────────────────────────────────────────────────
        # Constructed BEFORE the domain managers: the managers receive
        # callbacks (_ensure_authenticated, _vod_auth_headers,
        # _pvr_auth_headers) that dereference self._auth, and all of
        # AuthBridge's dependencies exist right after discovery.
        self.device_token = None
        self._auth = AuthBridge(
            authenticator=self.authenticator,
            provider_name=self.provider_name,
            country=self.country,
            platform=self.platform,
            platform_config=self.platform_config,
            provider_config=self.provider_config,
            session_id=self.session_id,
            serial_number=self.serial_number,
            user_agent_plain=self.user_agent_plain,
            user_agent_subscriber=self.user_agent_subscriber,
            generate_call_id=self._generate_call_id,
        )

        # ── Domain managers: build fully, publish in ONE assignment ──────────
        # _construct_domain_managers() assigns nothing to self; the single
        # assignment below is the atomic publish. Readers snapshot
        # self._managers (see the accessor properties and the multi-manager
        # methods) and so never observe a mixed generation.
        self._managers: _ManagerBundle = self._construct_domain_managers(
            self.endpoint_manager, self.provider_config
        )

        logger.info("Magenta2 provider initialization completed successfully")

    # ------------------------------------------------------------------ #
    # Manager accessors (single-attribute bundle)                          #
    # ------------------------------------------------------------------ #
    # self._managers is the ONLY published manager state; it is swapped in
    # a single assignment, which is atomic under the GIL. These read-only
    # properties return non-Optional types. Methods that touch MORE than
    # one manager must snapshot the bundle once instead of using several
    # properties in sequence (see get_manifest / get_drm /
    # get_catchup_manifest / get_epg_grid).

    @property
    def _vod_manager(self) -> VodManager:
        return self._managers.vod

    @property
    def _recordings_manager(self) -> RecordingsManager:
        return self._managers.recordings

    @property
    def _timers_manager(self) -> TimersManager:
        return self._managers.timers

    @property
    def _smil_manager(self) -> SmilManager:
        return self._managers.smil

    @property
    def _channel_manager(self) -> ChannelManager:
        return self._managers.channel

    @property
    def _playback_manager(self) -> PlaybackManager:
        return self._managers.playback

    @property
    def _epg_manager(self) -> Magenta2EpgManager:
        return self._managers.epg

    # ------------------------------------------------------------------ #
    # Static / utility                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _generate_uuid() -> str:
        return str(uuid.uuid4())

    def _generate_call_id(self) -> str:
        return self._generate_uuid()

    @staticmethod
    def _token_fingerprint(token: str) -> str:
        """Non-reversible correlation handle for secrets (sha256, 12 hex chars)."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]

    @classmethod
    def _redact(cls, value: Any, _key: str = "") -> Any:
        """
        Recursively replace string values under secret-looking keys with
        length + fingerprint. Over-redacts on purpose. This is a safety net
        for unaudited third-party dict output, NOT a substitute for auditing
        the sources — name-based redaction cannot catch secrets stored
        under innocent keys.
        """
        if isinstance(value, dict):
            return {k: cls._redact(v, str(k)) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [cls._redact(v, _key) for v in value]
        if isinstance(value, str) and any(p in _key.lower() for p in _SENSITIVE_KEY_PARTS):
            return f"<redacted len={len(value)} fp={cls._token_fingerprint(value)}>"
        return value

    def _get_or_create_serial_number(self) -> str:
        """
        Return a stable serial number for this installation, persisted
        across runs (mirrors SessionManager.get_device_id's load-or-generate
        pattern without adding a new public method to the shared
        SessionManager).

        NOTE: this is a load-modify-save on the shared session.json. Within
        one process it is safe (sequential init). Across processes sharing a
        config dir there is a first-run race — the same one
        SessionManager.get_device_id already has. The proper fix is a file
        lock or an atomic get-or-create in SessionManager, covering both.
        SessionManager's own save_* methods are merge-safe (verified: every
        one loads-or-{} before writing), so later token writes will NOT drop
        this key; only a direct save_session() caller passing a non-loaded
        blob could.
        """
        session_data = self._session_manager.load_session(
            self.provider_name, self.country
        ) or {}

        serial_number = session_data.get("serial_number")
        if not serial_number:
            serial_number = str(uuid.uuid4())
            session_data["serial_number"] = serial_number
            self._session_manager.save_session(
                self.provider_name, session_data, self.country
            )
            logger.debug(f"Generated new serial number: {serial_number}")
        else:
            logger.debug(f"Using existing serial number: {serial_number}")

        return serial_number

    def _load_proxy_from_manager(self, config_dir: Optional[str]) -> Optional[ProxyConfig]:
        try:
            proxy_manager = ProxyConfigManager(config_dir)
            return proxy_manager.get_proxy_config("magenta2", self.country)
        except Exception as e:
            logger.warning(f"Could not load proxy from ProxyConfigManager: {e}")
            return None

    # ------------------------------------------------------------------ #
    # Provider properties                                                  #
    # ------------------------------------------------------------------ #

    @property
    def provider_name(self) -> str:
        return "magenta2"

    @property
    def provider_label(self) -> str:
        return self.PROVIDER_LABEL

    @property
    def provider_logo(self) -> str:
        return self.PROVIDER_LOGO

    @property
    def uses_dynamic_manifests(self) -> bool:
        return False

    @property
    def epg_window(self) -> Tuple[int, int]:
        """Return EPG window as (past_days, future_days)."""
        return 7, 13  # 7 days past, 13 days future

    @property
    def implements_recordings(self) -> bool:
        return True

    @property
    def catchup_window(self) -> int:
        """
        Catchup window in HOURS — the ProviderCatchupMixin contract
        (validate_catchup_request computes max_age = catchup_window * 3600).

        Ground truth from the station feed: dt$catchupOptions.cacheDuration
        is "PT4H" (recordingPolicies.catchup.expirationOffset = 14400 s) on
        every observed station, so 4 is correct.
        """
        return 4

    @property
    def supported_auth_types(self) -> List[str]:
        return list(self.SUPPORTED_AUTH_TYPES)

    @property
    def primary_token_scope(self) -> Optional[str]:
        return "persona"

    @property
    def token_scopes(self) -> List[str]:
        return ["yo_digital", "tvhubs", "taa", "persona"]

    # ------------------------------------------------------------------ #
    # Configuration discovery                                              #
    # ------------------------------------------------------------------ #

    def _perform_configuration_discovery(self) -> None:
        """
        Run discovery and initialise EndpointManager.

        Fail-hard contract: on success, sets both self.provider_config and
        self.endpoint_manager from the live discovery result. On failure,
        logs and re-raises — __init__ does not complete. There is
        deliberately no fallback configuration: without the manifest there
        is no client_id, device token or endpoints, so a degraded instance
        would fail on every subsequent operation anyway.
        """
        logger.info("Performing Magenta2 configuration discovery")
        try:
            self.provider_config = self.discovery_service.discover_provider_config()

            if not self.provider_config or not self.provider_config.is_complete:
                # Incomplete configs are still usable for the parts that were
                # discovered. refresh_configuration() is deliberately
                # stricter: it would replace a known-good config.
                logger.warning("Configuration discovery incomplete, some features may not work")

            self.endpoint_manager = EndpointManager(self.provider_config)

            if self.provider_config and self.provider_config.manifest:
                device_token = self.provider_config.get_device_token()
                authorize_tokens_url = self.provider_config.get_authorize_tokens_url()
                if device_token:
                    logger.info(f"✓ Device token discovered (length: {len(device_token)})")
                else:
                    logger.warning("⚠️ No device token found in manifest")
                if authorize_tokens_url:
                    logger.info(f"✓ Line auth endpoint discovered: {authorize_tokens_url}")
                else:
                    logger.warning("⚠️ No authorize tokens URL found in manifest")
                if self.provider_config.manifest.mpx.account_pid:
                    logger.info(
                        f"✓ MPX account PID discovered: "
                        f"{self.provider_config.manifest.mpx.account_pid}"
                    )

            missing_endpoints = self.endpoint_manager.validate_critical_endpoints()
            if missing_endpoints:
                logger.warning(f"Missing critical endpoints: {missing_endpoints}")
            else:
                logger.info("All critical endpoints available")

            stats = self.endpoint_manager.get_stats()
            logger.info(
                f"Discovery complete: {stats['dynamic_endpoints']} dynamic endpoints, "
                f"{stats['fallback_endpoints']} fallback endpoints, "
                f"complete: {stats['is_complete']}"
            )

        except Exception as e:
            logger.error(f"Configuration discovery failed: {e}")
            raise

    def _configure_authenticator_from_discovery(
        self,
        cfg: ProviderConfig,
        endpoint_manager: EndpointManager,
    ) -> None:
        """
        Push discovered config values (client_id, models, device token, MPX
        PID, openid, endpoints, QR URL) into the authenticator and its
        TokenFlowManager. Single config-push choke point — called from
        __init__ and refresh_configuration() (including the rollback path).

        Parameters are passed explicitly (not read from self) so the type
        checker knows they are non-None.
        """
        self.authenticator.provider_config = cfg
        logger.info("✓ ProviderConfig stored in authenticator")

        if (
            hasattr(self.authenticator, "token_flow_manager")
            and self.authenticator.token_flow_manager
        ):
            self.authenticator.token_flow_manager.provider_config = cfg
            logger.info("✓ ProviderConfig stored in TokenFlowManager")

        if cfg.bootstrap.sam3_client_id:
            if hasattr(self.authenticator, "update_sam3_client_id"):
                self.authenticator.update_sam3_client_id(cfg.bootstrap.sam3_client_id)
            else:
                self.authenticator._sam3_client_id = cfg.bootstrap.sam3_client_id
            if self.authenticator.credentials:
                self.authenticator.credentials.client_id = cfg.bootstrap.sam3_client_id
            logger.debug(
                f"Updated authenticator SAM3 client ID: {cfg.bootstrap.sam3_client_id}"
            )

        if cfg.bootstrap.client_model:
            if hasattr(self.authenticator, "update_client_model"):
                self.authenticator.update_client_model(cfg.bootstrap.client_model)
            else:
                self.authenticator._client_model = cfg.bootstrap.client_model
            logger.debug(f"Updated authenticator client model: {cfg.bootstrap.client_model}")

        if cfg.bootstrap.device_model:
            if hasattr(self.authenticator, "update_device_model"):
                self.authenticator.update_device_model(cfg.bootstrap.device_model)
            else:
                self.authenticator._device_model = cfg.bootstrap.device_model
            logger.debug(f"Updated authenticator device model: {cfg.bootstrap.device_model}")

        if cfg.manifest:
            device_token = cfg.get_device_token()
            authorize_tokens_url = cfg.get_authorize_tokens_url()
            if device_token:
                self.authenticator.set_device_token(device_token, authorize_tokens_url)
                logger.debug("Device token configured in authenticator")
            if cfg.manifest.mpx.account_pid:
                self.authenticator.set_mpx_account_pid(cfg.manifest.mpx.account_pid)
                logger.debug(f"MPX account PID configured in authenticator: {cfg.manifest.mpx.account_pid}")
            if cfg.openid:
                self.authenticator.set_openid_config(cfg.openid.raw_data)

        all_endpoints = {
            name: info.url
            for name, info in endpoint_manager.get_all_endpoints().items()
        }
        if hasattr(self.authenticator, "update_dynamic_endpoints"):
            self.authenticator.update_dynamic_endpoints(all_endpoints)
            logger.info(f"✓ Updated authenticator with {len(all_endpoints)} endpoints")
        elif hasattr(self.authenticator, "update_endpoints"):
            self.authenticator.update_endpoints(all_endpoints)
            logger.info(f"✓ Updated authenticator with {len(all_endpoints)} endpoints")
        else:
            logger.warning("No public method available to update endpoints")

        # Single site for the QR-URL push (also covers refresh_configuration).
        qr_url = endpoint_manager.get_endpoint("login_qr_code")
        if qr_url and hasattr(self.authenticator, "update_sam3_qr_code_url"):
            success = self.authenticator.update_sam3_qr_code_url(qr_url)
            logger.info(
                "✓ SAM3 client updated with QR code URL"
                if success
                else "✗ Failed to update SAM3 client with QR code URL"
            )

    def _construct_domain_managers(
        self, endpoint_manager: EndpointManager, provider_config: ProviderConfig
    ) -> _ManagerBundle:
        """
        Build a fresh manager bundle against the given config.

        No instance state is mutated (no assignments to self anywhere in
        this method), so a failure here leaves the previously published
        bundle and config fully intact. It is NOT side-effect free in
        general, though: these are third-party constructors that may perform
        I/O — ChannelManager's constructor fetches station metadata
        (verified against its source) — and the returned bundle shares
        self._recording_url_cache with the previous generation by design.

        Note on cache loss: a rebuilt ChannelManager starts with cold
        _live_manifest_cache / _live_pid_cache, and its station→pid map
        holds only the station-metadata (media) pids until get_channels()
        re-runs and overwrites them with the entitled release pids. Callers
        that need warm caches should follow the publish with a
        get_channels() warmup (see refresh_configuration).
        """
        vod = VodManager(
            http_manager=self.http_manager,
            provider_name=self.provider_name,
            bootstrap=endpoint_manager.config.bootstrap,
            provider_config=endpoint_manager.config,
            session_id=self.session_id,
            serial_number=self.serial_number,
            auth_headers_callback=self._vod_auth_headers,
        )
        logger.debug("VodManager constructed")

        recordings = RecordingsManager(
            http_manager=self.http_manager,
            provider_name=self.provider_name,
            provider_config=endpoint_manager.config,
            auth_headers_callback=self._pvr_auth_headers,
        )
        logger.debug("RecordingsManager constructed")

        timers = TimersManager(
            http_manager=self.http_manager,
            provider_name=self.provider_name,
            provider_config=endpoint_manager.config,
            auth_headers_callback=self._pvr_auth_headers,
        )
        logger.debug("TimersManager constructed")

        smil = SmilManager(
            http_manager=self.http_manager,
            provider_name=self.provider_name,
            session_id=self.session_id,
            device_id=self.device_id,
            user_agent_plain=self.user_agent_plain,
            user_agent_subscriber=self.user_agent_subscriber,
            call_id_callback=self._generate_call_id,
            auth_callback=self._ensure_authenticated,
            platform_config=self.platform_config,
            endpoint_manager=endpoint_manager,
            provider_config=endpoint_manager.config,
            vod_manager=vod,
        )
        logger.debug("SmilManager constructed")

        channel = ChannelManager(
            http_manager=self.http_manager,
            provider_name=self.provider_name,
            country=self.country,
            platform_config=self.platform_config,
            session_id=self.session_id,
            serial_number=self.serial_number,
            endpoint_manager=endpoint_manager,
            provider_config=provider_config,
            auth_callback=self._ensure_authenticated,
            build_scaled_image_url_callback=self._build_scaled_image_url,
            user_agent_plain=self.user_agent_plain,
            user_agent_subscriber=self.user_agent_subscriber,
            catchup_window=self.catchup_window,
        )
        logger.debug("ChannelManager constructed")

        playback = PlaybackManager(
            channel_manager=channel,
            smil_manager=smil,
            endpoint_manager=endpoint_manager,
            provider_config=provider_config,
            platform_config=self.platform_config,
            auth_callback=self._ensure_authenticated,
            recording_url_cache=self._recording_url_cache,
            user_agent_subscriber=self.user_agent_subscriber,
            session_id=self.session_id,
            call_id_callback=self._generate_call_id,
        )
        logger.debug("PlaybackManager constructed")

        epg = Magenta2EpgManager(
            endpoint_manager=endpoint_manager,
            provider_config=endpoint_manager.config,
            http_manager=self.http_manager,
            authenticator=self.authenticator,
            fetch_details=False,  # ← Don't fetch details on schedule grid
            default_past_days=7,
            default_future_days=13,
        )
        logger.debug("EPG Manager constructed")

        return _ManagerBundle(
            vod=vod,
            recordings=recordings,
            timers=timers,
            smil=smil,
            channel=channel,
            playback=playback,
            epg=epg,
        )

    @staticmethod
    def _retire_managers(bundle: _ManagerBundle) -> None:
        """
        Release resources held by a replaced manager bundle.

        CAVEAT vs. the snapshot design: in-flight requests may still hold
        this bundle when it is retired. That is harmless while close() is a
        no-op (true today — PlaybackManager holds no state of its own,
        ChannelManager only caches), but the FIRST manager that implements
        a real close() will break those in-flight requests. When that
        happens, defer retirement instead (grace period or refcounting)
        rather than closing immediately after the swap.
        """
        for manager in bundle:
            close = getattr(manager, "close", None)
            if callable(close):
                try:
                    close()
                except Exception as e:
                    logger.warning(
                        f"Error closing retired {type(manager).__name__}: {e}"
                    )

    def get_discovery_status(self) -> Dict[str, Any]:
        """Return discovery and endpoint statistics."""
        status = self.discovery_service.get_discovery_status()
        status["endpoints"] = self.endpoint_manager.get_stats()
        return status

    def refresh_configuration(self, force: bool = False, warm: bool = True) -> bool:
        """
        Re-run configuration discovery and propagate the result everywhere.

        Concurrency: guarded by a NON-BLOCKING acquire of _refresh_lock — a
        concurrent or re-entrant refresh (e.g. warmup or an auth callback
        triggering refresh_configuration again) loses the race and returns
        False immediately instead of deadlocking.

        Failure-safe ordering:

        * Build phase — new EndpointManager and a complete manager bundle
          are constructed into locals; a failure here changes nothing.
          Caveat: the constructors (and any constructor-time callbacks) run
          against the OLD authenticator configuration and the OLD
          self.provider_config — the authenticator is reconfigured only
          after the build. Harmless unless a refresh changes auth endpoints
          or image-scaling config.
        * Raising steps first — authenticator reconfiguration and
          AuthBridge update. On failure the authenticator is re-pushed the
          PREVIOUS config, then the error propagates. Rollback caveat:
          _configure_authenticator_from_discovery only sets truthy fields,
          so the rollback restores every value the old config defined but
          cannot UNSET values that existed only in the new config (e.g. an
          openid block present only in the new manifest) — in that narrow
          case the authenticator keeps a new-only field alongside otherwise
          old state.
        * Non-raising commit — plain reference assignments plus ONE atomic
          bundle swap. Note: provider_config / endpoint_manager / _managers
          are three separate assignments, so a reader of the first two can
          momentarily see a different generation than a snapshotted bundle;
          accepted today (nothing reads them in that combination
          mid-flight). If it ever matters, move the config objects into
          _ManagerBundle.
        * Retirement — the old bundle's close() hooks fire (no-op today;
          see _retire_managers for the in-flight caveat).

        Unlike initial discovery, an INCOMPLETE result is rejected: at init
        there is nothing to lose, but a refresh must never replace a
        known-good configuration with an incomplete one.

        The warmup (warm=True) re-runs ChannelManager.get_channels() so the
        rebuilt channel manager's station→pid map holds entitled release
        pids and its live caches are populated. It is a synchronous,
        few-request operation (distribution rights + paginated entitled
        feed — ChannelManager ignores its populate_streaming /
        prefer_highest_quality parameters on this path). Pass warm=False on
        request threads or scheduler ticks and warm explicitly later; a
        failed warmup is non-fatal and leaves the provider in the same
        state as a fresh one, which PlaybackManager._ensure_live_cache
        self-heals on demand.
        """
        if not self._refresh_lock.acquire(blocking=False):
            logger.warning("Configuration refresh already in progress — skipping")
            return False
        try:
            try:
                logger.info("Refreshing provider configuration")
                new_config = self.discovery_service.discover_provider_config(force_refresh=force)

                if not (new_config and new_config.is_complete):
                    logger.warning(
                        "Configuration refresh incomplete — keeping previous configuration"
                    )
                    return False

                old_config = self.provider_config
                old_endpoints = self.endpoint_manager
                old_managers = self._managers

                # ── Build phase: nothing committed. ─────────────────────────
                new_endpoints = EndpointManager(new_config)
                bundle = self._construct_domain_managers(new_endpoints, new_config)

                # ── Raising steps first. ─────────────────────────────────────
                try:
                    self._configure_authenticator_from_discovery(new_config, new_endpoints)
                    self._auth.update_provider_config(new_config)
                except Exception:
                    logger.warning(
                        "Authenticator configuration failed mid-refresh — "
                        "rolling back to previous configuration"
                    )
                    try:
                        self._configure_authenticator_from_discovery(old_config, old_endpoints)
                        self._auth.update_provider_config(old_config)
                    except Exception as rollback_exc:
                        logger.error(f"Authenticator rollback failed: {rollback_exc}")
                    raise

                # ── Non-raising commit: plain assignments + one atomic swap. ──
                self.provider_config = new_config
                self.endpoint_manager = new_endpoints
                self._managers = bundle

                self._retire_managers(old_managers)

                # ── Warmup. ───────────────────────────────────────────────────
                if warm:
                    try:
                        self._managers.channel.get_channels()
                    except Exception as e:
                        logger.warning(
                            f"Post-refresh channel warmup failed (caches stay cold): {e}"
                        )

                logger.info("Configuration refresh successful")
                return True

            except Exception as e:
                logger.error(f"Configuration refresh failed: {e}")
                return False
        finally:
            self._refresh_lock.release()

    def register_device(self) -> bool:
        """Perform device registration / authentication."""
        try:
            logger.info("Performing device registration")
            if hasattr(self.authenticator, "perform_device_authentication"):
                success = self.authenticator.perform_device_authentication()
                if success:
                    logger.info("✓ Device registration successful")
                    return True
                else:
                    logger.warning("Device registration failed")
                    return False
            else:
                logger.warning("Device authentication not supported in current authenticator")
                return False
        except Exception as e:
            logger.error(f"Device registration failed: {e}")
            return False

    # ------------------------------------------------------------------ #
    # Authentication — thin delegates to AuthBridge                        #
    # ------------------------------------------------------------------ #

    def get_persona_token(self, force_refresh: bool = False) -> str:
        """Return a valid persona token (cached). Delegates to AuthBridge."""
        return self._auth.get_persona_token(force_refresh=force_refresh)

    def _ensure_authenticated(self) -> str:
        """Return a valid persona token (lazy auth). Delegates to AuthBridge."""
        return self._auth.ensure_authenticated()

    def clear_persona_cache(self) -> None:
        """Discard the in-memory persona token cache. Delegates to AuthBridge."""
        self._auth.clear_persona_cache()

    def _vod_auth_headers(self) -> Dict[str, str]:
        """Build auth headers for VOD endpoints. Delegates to AuthBridge."""
        return self._auth.vod_auth_headers()

    def _pvr_auth_headers(self) -> Dict[str, str]:
        """Build auth headers for nPVR endpoints. Delegates to AuthBridge."""
        return self._auth.pvr_auth_headers()

    # ------------------------------------------------------------------ #
    # Image scaling                                                        #
    # ------------------------------------------------------------------ #

    def _build_scaled_image_url(self, original_url: str) -> Optional[str]:
        """Return a scaled logo URL using the image scaling service."""
        if not original_url:
            return None
        if not self.provider_config or not self.provider_config.manifest:
            return original_url

        image_config = self.provider_config.manifest.image_config
        if not image_config.scaling_base_url or not image_config.scaling_call_parameter:
            return original_url

        call_params: Dict[str, str] = {}
        for param in image_config.scaling_call_parameter.split("&"):
            if "=" in param:
                key, value = param.split("=", 1)
                call_params[key] = value

        base_url = image_config.scaling_base_url.rstrip("/")
        # Only `src` is quoted (it is a raw URL). The manifest-provided call
        # parameters are emitted verbatim — they may already be
        # percent-encoded, and re-quoting would double-encode them.
        params = {**call_params, "x": "120", "y": "42", "ar": "keep", "src": original_url}
        query_string = "&".join(
            f"{k}={quote(v, safe='') if k == 'src' else v}" for k, v in params.items()
        )
        return f"{base_url}/iss?{query_string}"

    # ------------------------------------------------------------------ #
    # Header helpers                                                       #
    # ------------------------------------------------------------------ #

    def _get_dcm_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": self.user_agent_plain,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "x-dt-session-id": self.session_id,
            "x-dt-call-id": self._generate_call_id(),
        }

    def _get_api_headers(self, require_auth: bool = False) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "User-Agent": self.user_agent_subscriber if require_auth else self.user_agent_plain,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if require_auth:
            persona_token = self._ensure_authenticated()
            headers["Authorization"] = f"Basic {persona_token}"
        return headers

    # ------------------------------------------------------------------ #
    # Public StreamingProvider API                                         #
    # ------------------------------------------------------------------ #

    def get_dynamic_manifest_params(
        self, channel: StreamingChannel, **kwargs: Any
    ) -> Optional[str]:
        return None

    def get_channels(
        self,
        time_window_hours: int = DEFAULT_EPG_WINDOW_HOURS,
        fetch_manifests: bool = False,
        populate_streaming_data: bool = True,
        prefer_highest_quality: bool = True,
        **kwargs: Any,
    ) -> List[StreamingChannel]:
        # NOTE: prefer_highest_quality is accepted for signature stability
        # but is a documented no-op — the entitled-channels feed resolves
        # SD/HD variants server-side (one station per channel per account).
        # ChannelManager spells the flag `populate_streaming`; accept both
        # spellings so a caller passing it via **kwargs doesn't hit a
        # duplicate-keyword TypeError at the forwarding call below.
        populate_streaming = kwargs.pop("populate_streaming", populate_streaming_data)
        return self._channel_manager.get_channels(
            time_window_hours=time_window_hours,
            fetch_manifests=fetch_manifests,
            populate_streaming=populate_streaming,
            prefer_highest_quality=prefer_highest_quality,
            **kwargs,
        )

    def get_events(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        **kwargs: Any,
    ) -> List[Event]:
        return []

    @staticmethod
    def _get_playback_id(content_id: str, channel_manager: ChannelManager) -> str:
        """
        Convert station_id to playback_id if needed, using the given
        ChannelManager so the conversion and the subsequent playback call
        operate on the same manager generation.

        If content_id is numeric (station_id), convert to playback_id.
        Otherwise return as-is (already a playback_id or VOD ID).
        """
        if content_id.isdigit():
            playback_id = channel_manager.get_playback_id_for_station(content_id)
            if playback_id:
                logger.debug(f"Converted station_id {content_id} -> playback_id {playback_id}")
                return playback_id
            logger.warning(f"No playback_id found for station_id {content_id}")
            return content_id
        return content_id

    def get_manifest(
            self, content_id: str, content_type: str = CONTENT_TYPE_LIVE, **kwargs: Any
    ) -> Optional[str]:
        # Snapshot one manager generation: the station→pid conversion and
        # the playback call must not straddle a refresh swap.
        managers = self._managers
        # Convert station_id -> playback_id for live channels
        if content_type == CONTENT_TYPE_LIVE:
            content_id = self._get_playback_id(content_id, managers.channel)
        return managers.playback.get_manifest(content_id, content_type, **kwargs)

    def get_drm(
        self,
        content_id: str,
        drm_variant: Optional[str] = None,
        content_type: str = CONTENT_TYPE_LIVE,
        **kwargs: Any,
    ) -> List[DRMConfig]:
        """
        Base signature (StreamingProvider):
            get_drm(content_id, drm_variant=None, **kwargs)

        drm_variant is accepted to honor the contract but not forwarded:
        the verified PlaybackManager signature is
        get_drm(content_id, content_type=CONTENT_TYPE_LIVE, **kwargs) —
        it has no drm_variant parameter. Unknown or non-string values are
        accepted and ignored (nothing depends on them here).
        """
        if isinstance(drm_variant, str) and drm_variant.lower() in _MISROUTE_DRM_VARIANT_TOKENS:
            # This value is a content-type token, which can only be the
            # legacy positional call get_drm(cid, "vod"/"live"/"recording")
            # — it would silently route VOD content through the live path
            # and return the wrong DRM. No legitimate drm_variant ever
            # matches, so this has no false positives.
            raise ValueError(
                f"{self.provider_name}: get_drm got drm_variant={drm_variant!r}, which is a "
                f"content-type token — this looks like the legacy positional call "
                f"get_drm(content_id, content_type). Pass content_type by keyword: "
                f"get_drm(content_id, content_type={drm_variant!r})"
            )
        managers = self._managers
        # Convert station_id -> playback_id for live channels
        if content_type == CONTENT_TYPE_LIVE:
            content_id = self._get_playback_id(content_id, managers.channel)
        return managers.playback.get_drm(content_id, content_type, **kwargs)

    def get_catchup_manifest(
        self,
        content_id: str,
        start_time: int,
        end_time: int,
        epg_id: Optional[str] = None,
        drm_variant: Optional[str] = "auto",
        **kwargs: Any,
    ) -> Optional[str]:
        """
        Base signature (ProviderCatchupMixin):
            get_catchup_manifest(content_id, start_time, end_time, epg_id=None, **kwargs)

        epg_id is accepted to honor the contract but not forwarded: the
        verified PlaybackManager signature is
        get_catchup_manifest(content_id, start_time, end_time, drm_variant="auto",
        **kwargs) — drm_variant is its 4th positional, forwarded as such
        below. (PlaybackManager itself ignores start_time/end_time: Magenta2
        catchup is a DVR sliding window via dvr_window_length, not a fixed
        time-range asset.)
        """
        # _KNOWN_DRM_VARIANTS is the vocabulary documented by
        # ProviderCatchupMixin, not a guess. Warning only (not an error):
        # a misroute here still produces a correct manifest — the value is
        # simply ignored — so a loud warning is proportionate.
        if epg_id is not None and str(epg_id).lower() in _KNOWN_DRM_VARIANTS:
            logger.warning(
                f"{self.provider_name}: get_catchup_manifest got epg_id={epg_id!r}, "
                f"which looks like a drm_variant — pass drm_variant by keyword"
            )
        managers = self._managers
        content_id = self._get_playback_id(content_id, managers.channel)
        return managers.playback.get_catchup_manifest(
            content_id, start_time, end_time, drm_variant, **kwargs
        )

    def get_vod_category(
        self,
        content_id: str = "",
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kwargs: Any,
    ) -> Any:
        """Return children of a VOD node (empty string → root)."""
        return self._vod_manager.get_children(
            content_id=content_id,
            cursor=cursor,
            page_size=page_size,
            **kwargs,
        )

    def search_vod(
            self,
            query: str,
            cursor: Optional[str] = None,
            page_size: int = 24,
            **kwargs: Any,
    ) -> Any:
        """Search the VOD catalogue. Delegates to VodManager.search()."""
        return self._vod_manager.search(
            query=query,
            cursor=cursor,
            page_size=page_size,
            **kwargs,
        )

    def get_recordings(self, include_deleted: bool = False, **kwargs: Any) -> Any:
        """Return a list of Recording objects from the nPVR backend."""
        recordings = self._recordings_manager.get_recordings(
            include_deleted=include_deleted, **kwargs
        )
        for rec in recordings:
            if rec.content_id and rec.manifest_script:
                self._recording_url_cache[rec.content_id] = rec.manifest_script
        return recordings

    def delete_recording(self, recording_id: str, **kwargs: Any) -> None:
        self._recordings_manager.delete_recording(recording_id)

    def get_recording_manifest(self, recording_id: str, **kwargs: Any) -> Optional[str]:
        """Return the playback URL for a recording by ID (fresh API lookup)."""
        return self._recordings_manager.get_recording_manifest(recording_id)

    # ------------------------------------------------------------------ #
    # Timers (nPVR scheduled recordings — delegates to TimersManager)     #
    # ------------------------------------------------------------------ #

    def get_timer_types(self, **kwargs: Any) -> Any:
        """Return the timer types this provider supports."""
        return self._timers_manager.get_timer_types()

    def get_timers(self, **kwargs: Any) -> Any:
        """Return the list of currently scheduled timers."""
        return self._timers_manager.get_timers(**kwargs)

    def add_timer(self, timer: Any, **kwargs: Any) -> Any:
        """Schedule a new timer. Delegates to TimersManager.add_timer()."""
        return self._timers_manager.add_timer(timer)

    def update_timer(self, timer: Any, **kwargs: Any) -> Any:
        """Update an existing timer. Delegates to TimersManager.update_timer()."""
        return self._timers_manager.update_timer(timer)

    def delete_timer(
        self, client_index: int, force_delete: bool = False, **kwargs: Any
    ) -> None:
        """Delete/cancel a timer. Delegates to TimersManager.delete_timer()."""
        self._timers_manager.delete_timer(client_index, force_delete=force_delete)

    def get_epg(
        self,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        country: Optional[str] = None,
        **kwargs: Any,
    ) -> List[EPGEntry]:
        """
        Base signature (ProviderEpgMixin):
            get_epg(channel_id, start_time, end_time, country=None, **kwargs)

        A Magenta2Provider instance is bound to a single country at
        construction (self.country drives discovery/endpoints), so a
        differing requested country is logged — not silently ignored — and
        the instance's country is served. If Magenta2EpgManager.get_channel_epg
        ever gains a country parameter, forward it there instead.
        """
        if country and country.lower() != self.country.lower():
            logger.warning(
                f"{self.provider_name}: EPG requested for country '{country}', "
                f"but this instance is bound to '{self.country}'; "
                f"serving '{self.country}' data"
            )

        try:
            self._ensure_authenticated()
        except Exception as e:
            logger.warning(f"{self.provider_name}: Auth failed for EPG: {e}")

        return self._epg_manager.get_channel_epg(
            channel_id=channel_id,
            start_time=start_time,
            end_time=end_time,
            **kwargs,
        )

    def get_epg_grid(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        channel_ids: Optional[List[str]] = None,
        country: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, List[EPGEntry]]:
        """
        Base signature (ProviderEpgMixin):
            get_epg_grid(start_time, end_time, channel_ids, country=None, **kwargs)
        """
        if country and country.lower() != self.country.lower():
            logger.warning(
                f"{self.provider_name}: EPG grid requested for country '{country}', "
                f"but this instance is bound to '{self.country}'; "
                f"serving '{self.country}' data"
            )

        try:
            self._ensure_authenticated()
        except Exception as e:
            logger.warning(f"{self.provider_name}: Auth failed for EPG grid: {e}")

        # Snapshot one manager generation: the channel-list fallback and the
        # EPG call must not straddle a refresh swap.
        managers = self._managers

        # If channel_ids is None, pull the full channel list and use each
        # channel's station-ID-derived channel_id (the same ID space the
        # EPG manager keys its grid by — see ChannelManager / EPGEntry wiring).
        if channel_ids is None:
            channels = managers.channel.get_channels(populate_streaming=False)
            channel_ids = [ch.channel_id for ch in channels]

        return managers.epg.get_epg_grid(
            start_time=start_time,
            end_time=end_time,
            channel_ids=channel_ids,
            **kwargs,
        )

    def get_program_details(self, program_id: str, **kwargs: Any) -> Optional[EPGProgramDetails]:
        """Get detailed metadata for a single programme."""
        return self._epg_manager.get_program_details(program_id)

    # ------------------------------------------------------------------ #
    # Auth state / readiness introspection                                 #
    # ------------------------------------------------------------------ #

    def _calculate_auth_state(self, context: Any) -> AuthState:
        """Delegates to AuthBridge."""
        return self._auth.calculate_auth_state(context)

    def _calculate_readiness(self, context: Any) -> Tuple[bool, str]:
        """Delegates to AuthBridge."""
        return self._auth.calculate_readiness(context)

    def get_auth_details(self, context: Any) -> Dict[str, Any]:
        """Delegates to AuthBridge."""
        return self._auth.get_auth_details(self.token_scopes, context)

    def debug_authentication(self) -> Dict[str, Any]:
        """
        Return auth-state and token-flow diagnostic info.

        Secret handling: the provider's own token fields are length +
        sha256 fingerprint only. The third-party sections
        (token_flow_manager.get_token_status(), get_authentication_capabilities(),
        get_sam3_client_status()) run through _redact(), a name-based
        recursive redaction that replaces string values under
        secret-looking keys. That is a SAFETY NET, not a substitute for
        auditing those sources — name-based redaction cannot catch secrets
        under innocent keys. Exception reporting uses type names only,
        since messages can embed URLs or token fragments.
        """
        result: Dict[str, Any] = {
            "provider": {
                "provider_name": self.provider_name,
                "country": self.country,
                "platform": self.platform,
            }
        }

        try:
            persona_token = self.get_persona_token(force_refresh=False)
            persona_info: Dict[str, Any] = {
                "available": True,
                "length": len(persona_token),
                "fingerprint": self._token_fingerprint(persona_token),
            }
            try:
                persona_jwt = PlaybackManager.extract_persona_jwt_from_token(persona_token)
                persona_info["jwt_available"] = bool(persona_jwt)
                if persona_jwt:
                    persona_info["jwt_length"] = len(persona_jwt)
                    persona_info["jwt_fingerprint"] = self._token_fingerprint(persona_jwt)
            except Exception as e:
                persona_info["jwt_extraction_error"] = type(e).__name__
            result["persona_token"] = persona_info
        except Exception as e:
            result["persona_token"] = {"available": False, "error": type(e).__name__}

        tfm = getattr(self.authenticator, "token_flow_manager", None)
        if tfm is not None:
            result["token_flow_manager"] = {
                "available": True,
                "token_status": self._redact(tfm.get_token_status()),
            }
        else:
            result["token_flow_manager"] = {
                "available": False,
                "error": "TokenFlowManager not initialized",
            }

        if hasattr(self.authenticator, "get_authentication_capabilities"):
            result["authentication_capabilities"] = self._redact(
                self.authenticator.get_authentication_capabilities()
            )

        # Snapshot the endpoint manager so all reads see one generation.
        endpoint_manager = self.endpoint_manager
        result["endpoints"] = {
            "has_taa_auth": endpoint_manager.has_endpoint("taa_auth"),
            "has_entitlement": endpoint_manager.has_endpoint("entitlement"),
            "has_widevine_license": endpoint_manager.has_endpoint("widevine_license"),
            "has_mpx_selector": endpoint_manager.has_endpoint("mpx_selector"),
            "total_endpoints": len(endpoint_manager.get_all_endpoints()),
        }

        if hasattr(self.authenticator, "get_sam3_client_status"):
            result["sam3_client"] = self._redact(
                self.authenticator.get_sam3_client_status()
            )

        return result

    @classmethod
    def get_static_supported_countries(cls) -> List[str]:
        return list(cls.SUPPORTED_COUNTRIES)