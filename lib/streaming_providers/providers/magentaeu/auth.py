# streaming_providers/providers/magentaeu/auth.py
# -*- coding: utf-8 -*-
from __future__ import annotations

import base64
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

# Updated imports for pycryptodome
try:
    # Try pycryptodome first (Kodi script.module.pycryptodome)
    from Cryptodome.Cipher import PKCS1_OAEP
    from Cryptodome.PublicKey import RSA
except ImportError:
    # Fallback to older pycrypto naming
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.PublicKey import RSA

from ...base.auth.base_auth import BaseAuthenticator, BaseAuthToken, TokenAuthLevel
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger
from .constants import (
    API_ENDPOINTS,
    APP_VERSION,
    AUTH_FLOWS,
    AUTH_STEPS,
    BROADCASTING_STREAM_LIMITATION_APPLIES,
    CALL_TYPES,
    CHANNEL_ID,
    COUNTRY_CONFIG,
    DEFAULT_COUNTRY,
    DEFAULT_REQUEST_TIMEOUT,
    DEVICE_CONCURRENCY_PARAM,
    DEVICE_MANUFACTURER,
    DEVICE_MODEL,
    DEVICE_NAME,
    DEVICE_OS,
    DEVICE_TYPE,
    GUEST_SESSION_TTL_SECONDS,
    LOGIN_CONTEXT,
    LOGIN_TYPE,
    MANAGE_DEVICE,
    SUPPORTED_COUNTRIES,
    USER_AGENT,
    X_USER_AGENT,
    build_auth_headers,
    get_base_headers,
    get_base_url,
    get_bifrost_url,
    get_language,
)


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

class InvalidTokenError(Exception):
    """Exception for invalid JWT tokens"""
    pass


def base64url_decode(input_str: str) -> bytes:
    """Base64 URL decode"""
    padding = "=" * (4 - (len(input_str) % 4))
    return base64.urlsafe_b64decode(input_str + padding)


def decode_jwt(token: str, verify: bool = True) -> Dict[str, Any]:
    """
    Decode a JWT payload. If verify=True, raise InvalidTokenError on expiry.
    """
    try:
        header_b64, payload_b64, signature = token.split(".")
        payload_json = base64url_decode(payload_b64).decode("utf-8")
        payload = json.loads(payload_json)

        if verify and "exp" in payload:
            if payload["exp"] < time.time():
                raise InvalidTokenError(
                    f"Token expired at {payload['exp']} (now {int(time.time())})"
                )

        return payload
    except InvalidTokenError:
        raise
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InvalidTokenError(f"Invalid token format: {exc}")


def is_token_valid(token: str) -> bool:
    """
    Check if token is valid. Logs the specific rejection reason, since a
    silent False is undiagnosable in the field.
    """
    if not token:
        logger.debug("is_token_valid: empty token")
        return False
    try:
        decode_jwt(token, verify=True)
        return True
    except InvalidTokenError as exc:
        logger.debug(f"is_token_valid: rejected -- {exc}")
        return False


# ---------------------------------------------------------------------------
# Token
# ---------------------------------------------------------------------------

@dataclass
class MagentaAuthToken(BaseAuthToken):
    """Magenta TV authentication token"""

    refresh_token: Optional[str] = field(default="")
    device_id: Optional[str] = field(default="")
    session_id: Optional[str] = field(default="")
    channel_map_id: Optional[str] = field(default="")

    # Epoch time device_id/session_id were last confirmed via real cookies
    # from the startup page. 0 means "never validated" -- treated as stale
    # regardless of GUEST_SESSION_TTL_SECONDS.
    session_id_updated_at: float = field(default=0.0)

    # Access-token lifetime is on BaseAuthToken.expires_in. The refresh-token
    # lifetime is surfaced separately here because the HR login response
    # reports `refreshExpiresIn` (camelCase) and the base class's
    # needs_refresh() consults it -- so it must never be None. See
    # _create_token_from_response for the coercion.
    refresh_expires_in: int = field(default=0)

    # --- /user/account payload, cached so VOD + entitlement checks don't
    # each re-fetch it. Populated lazily by get_user_account(). ---
    account_info: Optional[Dict[str, Any]] = field(default=None)
    account_info_fetched_at: float = field(default=0.0)

    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary"""
        data: Dict[str, Any] = {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token or "",
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "issued_at": self.issued_at,
            "auth_level": (
                self.auth_level.value if self.auth_level else TokenAuthLevel.UNKNOWN.value
            ),
            "credential_type": self.credential_type or "",
        }
        if self.device_id:
            data["device_id"] = self.device_id
        if self.session_id:
            data["session_id"] = self.session_id
        if self.channel_map_id:
            data["channel_map_id"] = self.channel_map_id
        if self.session_id_updated_at:
            data["session_id_updated_at"] = self.session_id_updated_at
        if self.refresh_expires_in:
            data["refresh_expires_in"] = self.refresh_expires_in
        if self.account_info is not None:
            data["account_info"] = self.account_info
            data["account_info_fetched_at"] = self.account_info_fetched_at
        return data

    def get_jwt_claims(self) -> Optional[Dict[str, Any]]:
        """Extract JWT claims from access token (no expiry verification)."""
        try:
            if not self.access_token:
                return None
            return decode_jwt(self.access_token, verify=False)
        except Exception as exc:
            logger.debug(f"Failed to extract JWT claims: {exc}")
            return None

    # ------------------------------------------------------------------
    # Composite-JWT claim accessors.
    #
    # The HR bifrost `accessToken` is a composite JWT. Its payload embeds
    # the HAL / CTS / Persona tokens that theplatform-side services
    # (licence server, concurrency service) require:
    #
    #   dc_cts_accountId      -> CTS (theplatform) account number
    #   dc_cts_personaToken   -> RS512 JWT used as Widevine Basic-auth password
    #   dc_cts_personaId      -> persona uuid (also inside personaToken.sub)
    #   dc_tvAccountId        -> operator-side account number (e.g. HR
    #                            6000014999), distinct from dc_cts_accountId
    #
    # account_url / account_identifier come from /user/account, not the JWT.
    # ------------------------------------------------------------------

    @property
    def tv_account_id(self) -> Optional[str]:
        c = self.get_jwt_claims() or {}
        return c.get("dc_tvAccountId")

    @property
    def cts_account_id(self) -> Optional[str]:
        c = self.get_jwt_claims() or {}
        return c.get("dc_cts_accountId")

    @property
    def persona_id(self) -> Optional[str]:
        c = self.get_jwt_claims() or {}
        return c.get("dc_cts_personaId")

    @property
    def persona_jwt(self) -> Optional[str]:
        """Raw RS512 persona token (Widevine Basic-auth password)."""
        c = self.get_jwt_claims() or {}
        return c.get("dc_cts_personaToken")

    @property
    def account_uri(self) -> Optional[str]:
        """
        MPX account URI, e.g.
        http://access.auth.theplatform.com/data/Account/2709375564

        Prefers the /user/account value (`account_url`); falls back to a
        reconstruction from dc_cts_accountId. The reconstruction matches
        the shape the live web app uses, but /user/account is authoritative.
        """
        if self.account_info and self.account_info.get("account_url"):
            return self.account_info["account_url"]
        acct = self.cts_account_id
        if not acct:
            return None
        return f"http://access.auth.theplatform.com/data/Account/{acct}"

    @property
    def account_identifier(self) -> Optional[str]:
        """Bare account uuid from /user/account (`account_identifier`)."""
        if self.account_info:
            return self.account_info.get("account_identifier")
        return None

    # ------------------------------------------------------------------
    # VOD entitlement
    # ------------------------------------------------------------------

    @property
    def vod_enabled(self) -> Optional[bool]:
        """
        Whether this account is allowed to play VOD at all.

        Returns None when account_info has not been fetched yet -- callers
        MUST distinguish "unknown" from "disabled", because acting on the
        wrong one produces a false negative. The authoritative switch is
        `managed_settings["TVSOA-setting-VodEnabled"]`; individual titles
        have their own entitlement (HBO, Nova Plus, ...) which is separate.
        """
        if not self.account_info:
            return None
        ms = self.account_info.get("managed_settings") or {}
        return str(ms.get("TVSOA-setting-VodEnabled", "")).lower() == "true"

    @property
    def vod_enabled_raw(self) -> Optional[str]:
        """Raw value of the VOD-enabled managed setting, for diagnostics."""
        if not self.account_info:
            return None
        ms = self.account_info.get("managed_settings") or {}
        return ms.get("TVSOA-setting-VodEnabled")

    @property
    def entitlement_bouquets(self) -> list:
        """
        Managed-setting keys whose value is "true" and that look like
        package entitlements (e.g. "HR-package-basic-ftv"). Used by the
        provider when the actions API reports `subscribe` rather than
        `watch`, to decide whether a specific premium title is playable
        for this subscriber.
        """
        if not self.account_info:
            return []
        ms = self.account_info.get("managed_settings") or {}
        return sorted(
            k for k, v in ms.items()
            if str(v).lower() == "true" and "package" in k.lower()
        )


# ---------------------------------------------------------------------------
# Auth config
# ---------------------------------------------------------------------------

class MagentaAuthConfig:
    """Configuration for Magenta TV authentication"""

    def __init__(self, country: str, http_manager):
        self.country = country
        self.http_manager = http_manager
        self.country_config = COUNTRY_CONFIG[country]

        self.app_version = APP_VERSION
        self.device_name = DEVICE_NAME
        self.user_agent = USER_AGENT
        self.x_user_agent = X_USER_AGENT
        self.timeout = DEFAULT_REQUEST_TIMEOUT

    def get_auth_headers(
        self,
        call_type: str = CALL_TYPES["GUEST_USER"],
        flow: str = AUTH_FLOWS["START_UP"],
        step: str = AUTH_STEPS["GET_ACCESS_TOKEN"],
        device_id: Optional[str] = None,
        session_id: Optional[str] = None,
        tracking_id: Optional[str] = None,
        call_time: Optional[str] = None,
    ) -> Dict[str, str]:
        """Get authentication headers, including x-txn-id"""
        return build_auth_headers(
            country=self.country,
            device_id=device_id,
            session_id=session_id,
            flow=flow,
            step=step,
            call_type=call_type,
            tracking_id=tracking_id,
            call_time=call_time,
        )

    def encrypt_password(self, password: str) -> str:
        """
        Encrypt password using RSA public key.

        Raises rather than returning the plaintext on failure. Sending a
        plaintext credential in a login payload -- even over HTTPS -- is a
        worse outcome than failing loudly.
        """
        rsa_key = self.country_config["rsa_key"]
        if not rsa_key:
            raise RuntimeError(
                f"No RSA public key configured for country: {self.country} -- "
                f"refusing to send plaintext credentials"
            )
        try:
            key = RSA.import_key(rsa_key)
            cipher = PKCS1_OAEP.new(key)
            ciphertext = cipher.encrypt(password.encode("utf-8"))
            return base64.b64encode(ciphertext).decode()
        except Exception as exc:
            raise RuntimeError(f"Failed to encrypt password: {exc}") from exc


# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------

class MagentaAuthenticator(BaseAuthenticator):
    """Magenta TV authenticator - directly extends BaseAuthenticator"""

    # How long a /user/account response is reused before re-fetching. Long
    # enough that the VOD manager and entitlement checks within one session
    # hit the network at most once, short enough that a mid-session
    # entitlement change (package added/removed) is picked up before the
    # next playback attempt.
    ACCOUNT_INFO_TTL_SECONDS = 15 * 60  # 15 minutes

    def __init__(
        self,
        country: str = DEFAULT_COUNTRY,
        settings_manager=None,
        credentials=None,
        config_dir: Optional[str] = None,
        http_manager=None,
        proxy_config: Optional[ProxyConfig] = None,
        device_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        logger.info(f"=== MagentaAuthenticator.__init__ START ===")

        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(
                f"Unsupported country: {country}. Must be one of: {SUPPORTED_COUNTRIES}"
            )

        if http_manager is None:
            raise ValueError("http_manager is required for MagentaAuthenticator")

        self.country = country
        self._http_manager = http_manager
        self._proxy_config = proxy_config

        self._config = MagentaAuthConfig(self.country, self._http_manager)

        super().__init__(
            provider_name="magentaeu",
            settings_manager=settings_manager,
            credentials=credentials,
            country=country,
            config_dir=config_dir,
            enable_kodi_integration=True,
        )

        logger.info(f"=== MagentaAuthenticator.__init__ AFTER super().__init__ ===")

        # device_id/session_id are validated lazily by get_guest_session_ids();
        # we only make sure a token object exists to read/write into.
        if not self._current_token or not isinstance(self._current_token, MagentaAuthToken):
            self._current_token = MagentaAuthToken(
                access_token="",
                refresh_token="",
                token_type="Bearer",
                expires_in=0,
                issued_at=time.time(),
            )

        # Explicit constructor args (if the caller already knows good values)
        # take precedence, but they don't get treated as pre-validated --
        # session_id_updated_at stays at 0 so the first guest request still
        # checks them.
        if device_id:
            self._current_token.device_id = device_id
        if session_id:
            self._current_token.session_id = session_id

        logger.info(
            f"=== MagentaAuthenticator.__init__ COMPLETE - device_id/session_id "
            f"will be validated on first guest request ==="
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def auth_endpoint(self) -> str:
        """Authentication endpoint - required by BaseAuthenticator"""
        return API_ENDPOINTS["LOGIN"].format(natco=self.country)

    @property
    def current_token(self):
        return self._current_token

    @property
    def channel_map_id(self):
        if self._current_token and hasattr(self._current_token, "channel_map_id"):
            return self._current_token.channel_map_id
        return ""

    @property
    def http_manager(self):
        """Public access to HTTP manager"""
        return self._http_manager

    def get_auth_headers(self, call_type: str, flow: str, step: str) -> Dict[str, str]:
        return self._config.get_auth_headers(call_type, flow, step)

    def get_epg_headers(self) -> Dict[str, str]:
        return self.get_auth_headers("GUEST_USER", "START_UP", "EPG_CHANNEL")

    # ------------------------------------------------------------------
    # Guest session
    # ------------------------------------------------------------------

    def _initialize_guest_session(self) -> Tuple[str, str, bool]:
        """
        Visit the provider's startup page to obtain a real deviceId/sessionId
        pair from Set-Cookie, the same way a browser would.

        Returns (device_id, session_id, obtained) where obtained=False means
        we had to fall back to random UUIDs. Callers must NOT treat an
        obtained=False result as a validated, cacheable session.
        """
        try:
            startup_url = API_ENDPOINTS["STARTUP_PAGE"].format(
                base_url=get_base_url(self.country)
            )
            headers = get_base_headers()

            response = self._http_manager.get(
                startup_url,
                operation="session_init",
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )

            status = getattr(response, "status_code", None)
            device_id = ""
            session_id = ""

            if hasattr(response, "cookies"):
                cookies = response.cookies.get_dict()
                device_id = cookies.get("deviceId", "")
                session_id = cookies.get("sessionId", "")

            if device_id and session_id:
                logger.debug(
                    f"[{self.country}] Guest session established from cookies "
                    f"(status={status}) - device_id: {device_id}, session_id: {session_id}"
                )
                return device_id, session_id, True

            logger.warning(
                f"[{self.country}] Startup page (status={status}) returned no "
                f"deviceId/sessionId cookies; using unverified random fallback"
            )
            return str(uuid.uuid4()), str(uuid.uuid4()), False

        except Exception as exc:
            logger.warning(f"[{self.country}] Guest session initialization failed: {exc}")
            return str(uuid.uuid4()), str(uuid.uuid4()), False

    def get_guest_session_ids(self, force_refresh: bool = False) -> Tuple[str, str]:
        """
        Return (device_id, session_id) for guest-flow requests (channel
        list, EPG, etc). Single source of truth for every guest call site.

        Values are re-validated whenever older than GUEST_SESSION_TTL_SECONDS
        (or never validated at all -- session_id_updated_at == 0).
        """
        token = self._current_token
        device_id = ""
        session_id = ""
        updated_at = 0.0
        if isinstance(token, MagentaAuthToken):
            device_id = token.device_id or ""
            session_id = token.session_id or ""
            updated_at = token.session_id_updated_at or 0.0

        have_ids = bool(device_id and session_id)
        age = time.time() - updated_at if have_ids else float("inf")
        is_stale = age > GUEST_SESSION_TTL_SECONDS

        if have_ids and not is_stale and not force_refresh:
            return device_id, session_id

        logger.info(
            f"[{self.country}] Guest session "
            f"{'forced refresh' if force_refresh else ('stale (age=%.0fs)' % age if have_ids else 'not yet established')}"
            f" -- fetching fresh device_id/session_id"
        )
        device_id, session_id, obtained = self._initialize_guest_session()

        if not self._current_token or not isinstance(self._current_token, MagentaAuthToken):
            self._current_token = MagentaAuthToken(
                access_token="",
                refresh_token="",
                token_type="Bearer",
                expires_in=0,
                issued_at=time.time(),
            )

        self._current_token.device_id = device_id
        self._current_token.session_id = session_id

        if obtained:
            self._current_token.session_id_updated_at = time.time()
            self._save_session()
        else:
            logger.warning(
                f"[{self.country}] Guest session unverified; will retry on "
                f"next call rather than caching this pair"
            )

        return device_id, session_id

    # ------------------------------------------------------------------
    # Header / payload builders
    # ------------------------------------------------------------------

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers for authentication request - required by BaseAuthenticator"""
        device_id = ""
        session_id = ""

        if self._current_token and isinstance(self._current_token, MagentaAuthToken):
            device_id = self._current_token.device_id or ""
            session_id = self._current_token.session_id or ""

        tracking_id = str(uuid.uuid4())
        call_time = str(int(time.time() * 1000))

        return self._config.get_auth_headers(
            call_type=CALL_TYPES["GUEST_USER"],
            flow=AUTH_FLOWS["USERNAME_PASSWORD_LOGIN"],
            step=AUTH_STEPS["GET_ACCESS_TOKEN"],
            device_id=device_id,
            session_id=session_id,
            tracking_id=tracking_id,
            call_time=call_time,
        )

    def _build_auth_payload(self) -> Dict[str, Any]:
        """Build authentication payload - required by BaseAuthenticator"""
        from ...base.auth.credentials import UserPasswordCredentials

        if not self.credentials or not isinstance(self.credentials, UserPasswordCredentials):
            raise Exception("No valid credentials available")

        if not self.credentials.username or not self.credentials.password:
            raise Exception("Username and password cannot be empty")

        device_id = ""
        if self._current_token and isinstance(self._current_token, MagentaAuthToken):
            device_id = self._current_token.device_id or ""

        if not device_id:
            device_id = str(uuid.uuid4())

        encrypted_password = self._config.encrypt_password(self.credentials.password)

        return {
            "appVersion": self._config.app_version,
            "channel": {"id": CHANNEL_ID},
            "natco": self.country,
            "type": LOGIN_TYPE,
            "forceRegister": False,
            "context": LOGIN_CONTEXT,
            "device": {
                "id": device_id,
                "model": DEVICE_MODEL,
                "os": DEVICE_OS,
                "deviceName": DEVICE_MODEL,
                "manageDevice": MANAGE_DEVICE,
                "deviceType": DEVICE_TYPE,
                "deviceOS": DEVICE_OS,
                "deviceModel": self._config.x_user_agent,
                "deviceManufacturer": DEVICE_MANUFACTURER,
                "concurrencyLimitParam": DEVICE_CONCURRENCY_PARAM,
                "broadcastingStreamLimitationApplies": BROADCASTING_STREAM_LIMITATION_APPLIES,
            },
            "telekomLogin": {
                "username": self.credentials.username,
                "password": encrypted_password,
            },
        }

    # ------------------------------------------------------------------
    # Token construction
    # ------------------------------------------------------------------

    @staticmethod
    def _read_token_field(
        data: Dict[str, Any],
        camel: str,
        snake: str,
        default: Any = None,
    ) -> Any:
        """
        Read a field that may appear in either camelCase (login/refresh
        bodies) or snake_case (stored session format). is-not-None checks
        rather than truthiness so a legitimate 0 is not treated as missing.
        """
        if camel in data and data[camel] is not None:
            return data[camel]
        if snake in data and data[snake] is not None:
            return data[snake]
        return default

    def _create_token_from_response(self, response_data: Dict[str, Any]) -> BaseAuthToken:
        """Create token from API response - required by BaseAuthenticator"""

        # --- Preserve existing session data ---------------------------------
        device_id = ""
        session_id = ""
        channel_map_id = ""
        session_id_updated_at = 0.0
        existing_account_info: Optional[Dict[str, Any]] = None
        existing_account_info_fetched_at = 0.0

        # Priority 1: fields stored directly on the token blob (restored
        # sessions come through this path -- _load_session() calls
        # _create_token_from_response with the persisted dict).
        if "device_id" in response_data:
            device_id = response_data.get("device_id", "") or ""
        if "session_id" in response_data:
            session_id = response_data.get("session_id", "") or ""
        if "session_id_updated_at" in response_data:
            session_id_updated_at = response_data.get("session_id_updated_at", 0.0) or 0.0

        # account_info restore -- TTL-checked. A stale snapshot must not
        # override a real entitlement change that happened while the app
        # was closed.
        if "account_info" in response_data and response_data["account_info"] is not None:
            fetched_at = response_data.get("account_info_fetched_at", 0.0) or 0.0
            age = time.time() - fetched_at
            if age < self.ACCOUNT_INFO_TTL_SECONDS:
                existing_account_info = response_data["account_info"]
                existing_account_info_fetched_at = fetched_at
                logger.debug(
                    f"Restored persisted account_info (age={age:.0f}s)"
                )
            else:
                logger.debug(
                    f"Dropping persisted account_info: age {age:.0f}s "
                    f"exceeds TTL {self.ACCOUNT_INFO_TTL_SECONDS}s"
                )

        # Priority 2: carry forward from the current token (refresh / upgrade
        # paths -- same user, so the entitlements remain valid).
        if (not device_id or not session_id) and isinstance(
            self._current_token, MagentaAuthToken
        ):
            device_id = device_id or (self._current_token.device_id or "")
            session_id = session_id or (self._current_token.session_id or "")
            channel_map_id = self._current_token.channel_map_id or ""
            session_id_updated_at = (
                session_id_updated_at
                or self._current_token.session_id_updated_at
                or 0.0
            )
            if existing_account_info is None:
                existing_account_info = self._current_token.account_info
                existing_account_info_fetched_at = (
                    self._current_token.account_info_fetched_at or 0.0
                )

        if device_id and session_id:
            logger.debug(
                f"Creating new token with session IDs - device_id: {device_id}, "
                f"session_id: {session_id}"
            )
        else:
            logger.warning(
                "No session IDs found in response_data or current_token during "
                "token creation"
            )

        # --- Access token (required) ----------------------------------------
        access_token = self._read_token_field(
            response_data, "accessToken", "access_token"
        )
        if not access_token:
            logger.error("CRITICAL: No access token found in response data")
            logger.error(f"Available keys: {list(response_data.keys())}")
            raise Exception("No access token found in response data")

        # --- Refresh token --------------------------------------------------
        refresh_token = self._read_token_field(
            response_data, "refreshToken", "refresh_token", ""
        )

        # --- Expiries -------------------------------------------------------
        # The HR login response field is `accessExpiresIn`, NOT `expiresIn`.
        # Reading the wrong key previously caused a fallback to 3600s and a
        # refresh attempt every hour against 7-day access tokens.
        expires_in_raw = self._read_token_field(
            response_data, "accessExpiresIn", "expires_in", None
        )
        if expires_in_raw is None:
            # Older / other natco variants may use `expiresIn`.
            expires_in_raw = self._read_token_field(
                response_data, "expiresIn", "expires_in", 3600
            )
        expires_in = int(expires_in_raw)

        # refresh_expires_in must never be None -- BaseAuthToken.needs_refresh
        # does `if self.refresh_expires_in > 0:` and would raise TypeError.
        refresh_expires_in_raw = self._read_token_field(
            response_data, "refreshExpiresIn", "refresh_expires_in", None
        )
        refresh_expires_in = (
            int(refresh_expires_in_raw) if refresh_expires_in_raw is not None else 0
        )

        token_type = self._read_token_field(
            response_data, "tokenType", "token_type", "Bearer"
        )
        issued_at = response_data.get("issued_at", time.time())

        token = MagentaAuthToken(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=token_type,
            expires_in=expires_in,
            issued_at=issued_at,
            device_id=device_id,
            session_id=session_id,
            channel_map_id=channel_map_id,
            session_id_updated_at=session_id_updated_at,
            refresh_expires_in=refresh_expires_in,
            account_info=existing_account_info,
            account_info_fetched_at=existing_account_info_fetched_at,
        )

        token.auth_level = self._classify_token(token)

        logger.info(
            f"Token created: access_expires_in={expires_in}s, "
            f"refresh_expires_in={refresh_expires_in}s"
        )
        return token

    def get_fallback_credentials(self):
        """Get fallback credentials - required by BaseAuthenticator"""
        from ...base.auth.credentials import UserPasswordCredentials

        return UserPasswordCredentials(username="", password="")

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def _perform_authentication(self) -> BaseAuthToken:
        """Perform Magenta TV authentication - required by BaseAuthenticator"""
        if not self.credentials:
            raise Exception("No credentials available for authentication")

        from ...base.auth.credentials import UserPasswordCredentials

        if not isinstance(self.credentials, UserPasswordCredentials):
            raise Exception(
                f"Invalid credential type: {type(self.credentials)}. "
                f"Expected UserPasswordCredentials or MagentaCredentials"
            )

        if not self.credentials.username or not self.credentials.password:
            raise Exception("Username and password are required for authentication")

        logger.info(f"Performing Magenta TV authentication for country: {self.country}")

        # Clear any previously cached /user/account data before logging in.
        # A full login may be for a *different* user than the token we
        # currently hold -- carrying the old account_info forward would
        # serve the previous user's vod_enabled/entitlement_bouquets for up
        # to ACCOUNT_INFO_TTL_SECONDS. Refresh/upgrade paths (which reuse
        # _create_token_from_response without going through this method)
        # deliberately do NOT clear it, since those are same-user.
        if isinstance(self._current_token, MagentaAuthToken):
            self._current_token.account_info = None
            self._current_token.account_info_fetched_at = 0.0

        try:
            headers = self._get_auth_headers()
            payload = self._build_auth_payload()

            logger.debug(
                f"Authentication payload prepared for user: {self.credentials.username}"
            )

            response = self._http_manager.post(
                self.auth_endpoint,
                operation="auth",
                headers=headers,
                json_data=payload,
                timeout=self._config.timeout,
            )

            response.raise_for_status()
            token_data = response.json()

            if token_data.get("deviceLimitExceed", False):
                logger.info("Device limit exceeded, attempting token upgrade")
                token_data = self._upgrade_token(token_data["refreshToken"])

            return self._create_token_from_response(token_data)

        except Exception as exc:
            logger.error(
                f"Authentication failed for user {self.credentials.username}: {exc}"
            )
            raise

    def _upgrade_token(self, refresh_token: str) -> Dict[str, Any]:
        """Upgrade token when device limit is exceeded"""
        upgrade_url = API_ENDPOINTS["UPGRADE_TOKEN"].format(natco=self.country)

        device_id, session_id, _, _ = self._get_session_data()

        tracking_id = str(uuid.uuid4())
        call_time = str(int(time.time() * 1000))

        headers = self._config.get_auth_headers(
            call_type=CALL_TYPES["GUEST_USER"],
            flow=AUTH_FLOWS["USERNAME_PASSWORD_LOGIN"],
            step=AUTH_STEPS["UPGRADE_TOKEN"],
            device_id=device_id,
            session_id=session_id,
            tracking_id=tracking_id,
            call_time=call_time,
        )
        headers["Refresh_token"] = refresh_token

        payload = self._build_auth_payload()

        response = self._http_manager.post(
            upgrade_url,
            operation="auth_upgrade",
            headers=headers,
            json_data=payload,
            timeout=self._config.timeout,
        )

        response.raise_for_status()
        return response.json()

    def _get_session_data(self) -> Tuple[str, str, str, float]:
        """Safely get session data from current token"""
        if isinstance(self._current_token, MagentaAuthToken):
            return (
                self._current_token.device_id or "",
                self._current_token.session_id or "",
                self._current_token.channel_map_id or "",
                self._current_token.session_id_updated_at or 0.0,
            )
        return "", "", "", 0.0

    def _refresh_token(self) -> Optional[BaseAuthToken]:
        """
        Refresh Magenta TV token - override base method.

        Routes the response through _create_token_from_response() so the
        camelCase/snake_case handling, the accessExpiresIn/refreshExpiresIn
        reading, and the account-info carry-forward are done in one place.
        """
        if not self._current_token or not self._current_token.refresh_token:
            logger.debug("No valid refresh token available")
            return None

        try:
            logger.debug(f"Refreshing Magenta TV token for country: {self.country}")

            refresh_url = API_ENDPOINTS["REFRESH_TOKEN"].format(natco=self.country)

            device_id, session_id, _, _ = self._get_session_data()

            tracking_id = str(uuid.uuid4())
            call_time = str(int(time.time() * 1000))

            headers = self._config.get_auth_headers(
                call_type=CALL_TYPES["AUTH_USER"],
                flow=AUTH_FLOWS["START_UP"],
                step=AUTH_STEPS["REFRESH_TOKEN"],
                device_id=device_id,
                session_id=session_id,
                tracking_id=tracking_id,
                call_time=call_time,
            )

            headers.update(
                {
                    "Refresh_token": self._current_token.refresh_token,
                    "channel": "Tv",
                }
            )

            payload = {
                "clientVersion": APP_VERSION,
                "deviceId": device_id,
                "concurrencyLimitParam": DEVICE_CONCURRENCY_PARAM,
            }

            logger.debug(f"Refresh request - URL: {refresh_url}")

            response = self._http_manager.post(
                refresh_url,
                operation="auth_refresh",
                headers=headers,
                json_data=payload,
                timeout=self._config.timeout,
            )

            response.raise_for_status()
            token_data = response.json()

            return self._create_token_from_response(token_data)

        except Exception as exc:
            logger.warning(f"Token refresh failed: {exc}")
            if hasattr(exc, "response") and hasattr(exc.response, "text"):
                logger.error(f"Refresh response content: {exc.response.text}")
            return None

    # ------------------------------------------------------------------
    # Token classification
    # ------------------------------------------------------------------

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        """Classify Magenta TV token - required by BaseAuthenticator"""
        try:
            if not token or not token.access_token:
                return TokenAuthLevel.UNKNOWN

            if isinstance(token, MagentaAuthToken):
                claims = token.get_jwt_claims()
            else:
                try:
                    claims = decode_jwt(token.access_token, verify=False)
                except InvalidTokenError:
                    return TokenAuthLevel.UNKNOWN

            if not claims:
                return TokenAuthLevel.UNKNOWN

            if "username" in claims or "preferred_username" in claims:
                return TokenAuthLevel.USER_AUTHENTICATED

            if len(claims) <= 3:
                return TokenAuthLevel.ANONYMOUS

            return TokenAuthLevel.USER_AUTHENTICATED

        except Exception as exc:
            logger.debug(f"Error classifying token: {exc}")
            return TokenAuthLevel.UNKNOWN

    # ------------------------------------------------------------------
    # /user/account
    # ------------------------------------------------------------------

    def get_user_account(self, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Get user account information, with in-memory caching on the token.

        The response is cached for ACCOUNT_INFO_TTL_SECONDS and survives
        restarts (persisted via _save_session / restored in
        _create_token_from_response, with the TTL re-checked on restore).
        Callers that need to pick up a mid-session entitlement change can
        pass force_refresh=True.

        Side effects:
          * populates current_token.channel_map_id
          * populates current_token.account_info / account_info_fetched_at
          * persists the token
        """
        token = self._current_token
        if not isinstance(token, MagentaAuthToken):
            raise Exception("No token available to hold account info")

        if not force_refresh and token.account_info is not None:
            age = time.time() - (token.account_info_fetched_at or 0.0)
            if age < self.ACCOUNT_INFO_TTL_SECONDS:
                logger.debug(
                    f"get_user_account: serving cached account info (age={age:.0f}s)"
                )
                return token.account_info

        access_token = self.get_bearer_token()
        if access_token.startswith("Bearer "):
            access_token = access_token[7:]

        account_url = API_ENDPOINTS["USER_ACCOUNT"].format(
            bifrost_url=get_bifrost_url(self.country)
        )

        params = {
            "fresh_login": "false",
            "app_language": get_language(self.country),
            "natco_code": self.country,
        }

        device_id, session_id, _, _ = self._get_session_data()

        tracking_id = str(uuid.uuid4())
        call_time = str(int(time.time() * 1000))

        headers = self._config.get_auth_headers(
            call_type=CALL_TYPES["AUTH_USER"],
            flow=AUTH_FLOWS["START_UP"],
            step=AUTH_STEPS["GET_USER_ACCOUNT"],
            device_id=device_id,
            session_id=session_id,
            tracking_id=tracking_id,
            call_time=call_time,
        )
        headers["Bff_token"] = access_token

        response = self._http_manager.get(
            account_url,
            operation="user_account",
            headers=headers,
            params=params,
            timeout=self._config.timeout,
        )

        response.raise_for_status()
        account_data = response.json()

        if "channelMap_id" in account_data:
            token.channel_map_id = account_data["channelMap_id"]

        token.account_info = account_data
        token.account_info_fetched_at = time.time()

        ms = account_data.get("managed_settings") or {}
        logger.info(
            f"[{self.country}] account loaded: "
            f"tvAccountId={account_data.get('tvAccountId')}, "
            f"vod_enabled={ms.get('TVSOA-setting-VodEnabled')!r}, "
            f"catchup_enabled={account_data.get('catchup_enabled')}, "
            f"entitlement_bouquets="
            f"{sorted(k for k, v in ms.items() if 'package' in k.lower() and str(v).lower() == 'true')}"
        )

        self._save_session()
        return account_data