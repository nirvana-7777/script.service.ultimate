# streaming_providers/providers/magentaeu/auth.py
# -*- coding: utf-8 -*-
import base64
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

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


class InvalidTokenError(Exception):
    """Exception for invalid JWT tokens"""

    pass


def base64url_decode(input_str: str) -> bytes:
    """Base64 URL decode"""
    padding = "=" * (4 - (len(input_str) % 4))
    return base64.urlsafe_b64decode(input_str + padding)


def decode_jwt(token: str, verify: bool = True) -> Dict[str, Any]:
    """Decode JWT token"""
    try:
        header_b64, payload_b64, signature = token.split(".")
        payload_json = base64url_decode(payload_b64).decode("utf-8")
        payload = json.loads(payload_json)

        if verify and "exp" in payload:
            if payload["exp"] < time.time():
                raise InvalidTokenError("Token has expired")

        return payload
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        raise InvalidTokenError("Invalid token format")


def is_token_valid(token: str) -> bool:
    """Check if token is valid"""
    if not token:
        return False
    try:
        decode_jwt(token)
        return True
    except InvalidTokenError:
        return False


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

    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary"""
        data = {
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
        # Include session data
        if self.device_id:
            data["device_id"] = self.device_id
        if self.session_id:
            data["session_id"] = self.session_id
        if self.channel_map_id:
            data["channel_map_id"] = self.channel_map_id
        if self.session_id_updated_at:
            data["session_id_updated_at"] = self.session_id_updated_at
        return data

    def get_jwt_claims(self) -> Optional[Dict[str, Any]]:
        """Extract JWT claims from access token"""
        try:
            if not self.access_token:
                return None
            return decode_jwt(self.access_token, verify=False)
        except Exception as e:
            logger.debug(f"Failed to extract JWT claims: {e}")
            return None


class MagentaAuthConfig:
    """Configuration for Magenta TV authentication"""

    def __init__(self, country: str, http_manager):
        self.country = country
        self.http_manager = http_manager
        self.country_config = COUNTRY_CONFIG[country]

        # Application configuration
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
        device_id: str = None,
        session_id: str = None,
        tracking_id: str = None,
        call_time: str = None,
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
        """Encrypt password using RSA public key"""
        try:
            rsa_key = self.country_config["rsa_key"]
            if not rsa_key:
                logger.error(f"No RSA public key configured for country: {self.country}")
                return password

            key = RSA.import_key(rsa_key)
            cipher = PKCS1_OAEP.new(key)
            ciphertext = cipher.encrypt(password.encode("utf-8"))
            return base64.b64encode(ciphertext).decode()
        except Exception as e:
            logger.error(f"Error encrypting password: {e}")
            return password


class MagentaAuthenticator(BaseAuthenticator):
    """Magenta TV authenticator - directly extends BaseAuthenticator"""

    def __init__(
        self,
        country: str = DEFAULT_COUNTRY,
        settings_manager=None,
        credentials=None,
        config_dir: Optional[str] = None,
        http_manager=None,
        proxy_config: Optional[ProxyConfig] = None,
        device_id: Optional[str] = None,  # New parameter
        session_id: Optional[str] = None,
    ):  # New parameter

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

        # Setup config
        self._config = MagentaAuthConfig(self.country, self._http_manager)

        # Call parent init (this will load existing session if available)
        # Call parent init (this will load existing session if available)
        super().__init__(
            provider_name="magentaeu",
            settings_manager=settings_manager,
            credentials=credentials,
            country=country,
            config_dir=config_dir,
            enable_kodi_integration=True,
        )

        logger.info(f"=== MagentaAuthenticator.__init__ AFTER super().__init__ ===")

        # device_id/session_id are no longer decided once here and then
        # trusted for the token's entire lifetime -- a persisted pair could
        # be months old with no way to know it ever went invalid server-side.
        # We just make sure a token object exists to read/write into; actual
        # validation and refresh happens lazily in get_guest_session_ids(),
        # called uniformly by every guest-flow call site (channel list, EPG,
        # etc), independent of whether the user is authenticated.
        if not self._current_token or not isinstance(self._current_token, MagentaAuthToken):
            self._current_token = MagentaAuthToken(
                access_token="",
                refresh_token="",
                token_type="Bearer",
                expires_in=0,
                issued_at=time.time(),
            )

        # Explicit device_id/session_id constructor args (if the caller
        # already knows good values) still take precedence, but they don't
        # get treated as pre-validated -- session_id_updated_at is left at
        # 0 so the first get_guest_session_ids() call still checks them.
        if device_id:
            self._current_token.device_id = device_id
        if session_id:
            self._current_token.session_id = session_id

        logger.info(
            f"=== MagentaAuthenticator.__init__ COMPLETE - device_id/session_id "
            f"will be validated on first guest request ==="
        )

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

    def get_auth_headers(self, call_type: str, flow: str, step: str) -> Dict[str, str]:
        return self._config.get_auth_headers(call_type, flow, step)

    def get_epg_headers(self) -> Dict[str, str]:
        return self.get_auth_headers("GUEST_USER", "START_UP", "EPG_CHANNEL")

    @property
    def http_manager(self):
        """Public access to HTTP manager"""
        return self._http_manager

    def _initialize_guest_session(self) -> tuple[str, str, bool]:
        """
        Visit the provider's startup page to obtain a real deviceId/sessionId
        pair from Set-Cookie, the same way a browser would.

        Uses API_ENDPOINTS["STARTUP_PAGE"] rather than a hardcoded "/epg"
        path, since not every MagentaEU natco is guaranteed to serve the
        startup page at that path -- a country override only needs to change
        constants.py, not this method.

        Returns (device_id, session_id, obtained) where obtained=False means
        we had to fall back to random UUIDs. Callers must NOT treat an
        obtained=False result as a validated, cacheable session -- that's
        exactly how a permanently-invalid session got persisted before.
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

            device_id = ""
            session_id = ""

            if hasattr(response, "cookies"):
                cookies = response.cookies.get_dict()
                device_id = cookies.get("deviceId", "")
                session_id = cookies.get("sessionId", "")

            if device_id and session_id:
                logger.debug(
                    f"[{self.country}] Guest session established from cookies - "
                    f"device_id: {device_id}, session_id: {session_id}"
                )
                return device_id, session_id, True

            logger.warning(
                f"[{self.country}] Startup page returned no deviceId/sessionId "
                f"cookies; using unverified random fallback"
            )
            return str(uuid.uuid4()), str(uuid.uuid4()), False

        except Exception as e:
            logger.warning(f"[{self.country}] Guest session initialization failed: {e}")
            return str(uuid.uuid4()), str(uuid.uuid4()), False

    def get_guest_session_ids(self, force_refresh: bool = False) -> tuple[str, str]:
        """
        Return (device_id, session_id) for guest-flow requests (channel
        list, EPG, etc). This is the single source of truth for every guest
        call site -- previously each call site (get_channels(), the EPG
        manager) read current_token.device_id/session_id directly, which
        were set once at first-ever init and never re-validated, so a pair
        that went stale server-side stayed stale forever.

        Values are re-validated whenever older than GUEST_SESSION_TTL_SECONDS
        (or never validated at all -- session_id_updated_at == 0), regardless
        of whether the user is authenticated; the bearer-token lifecycle
        (_refresh_token) is separate from this guest session.
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
            # Don't stamp session_id_updated_at -- an unverified fallback
            # must not be cached as if it were a real, validated session.
            # The next call will retry instead of trusting a guess for
            # GUEST_SESSION_TTL_SECONDS.
            logger.warning(
                f"[{self.country}] Guest session unverified; will retry on "
                f"next call rather than caching this pair"
            )

        return device_id, session_id

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers for authentication request - required by BaseAuthenticator"""
        device_id = ""
        session_id = ""

        # Get session data from current token if available
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

        # Enhanced validation
        if not self.credentials.username or not self.credentials.password:
            raise Exception("Username and password cannot be empty")

        # Get device_id from current token or expect it to be provided via other means
        device_id = ""
        if self._current_token and isinstance(self._current_token, MagentaAuthToken):
            device_id = self._current_token.device_id or ""

        # If no device_id, we need to get it from the provider
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
                "username": self.credentials.username,  # Works for both types!
                "password": encrypted_password,  # Works for both types!
            },
        }

    def _create_token_from_response(self, response_data: Dict[str, Any]) -> BaseAuthToken:
        """Create token from API response - required by BaseAuthenticator"""
        # PRESERVE the existing session IDs (which follow the correct priority)
        device_id = ""
        session_id = ""
        channel_map_id = ""
        session_id_updated_at = 0.0

        # Try to get session IDs from multiple sources in priority order:

        # 1. First from the response_data itself (when loading from stored session)
        if "device_id" in response_data:
            device_id = response_data.get("device_id", "")
        if "session_id" in response_data:
            session_id = response_data.get("session_id", "")
        if "session_id_updated_at" in response_data:
            session_id_updated_at = response_data.get("session_id_updated_at", 0.0) or 0.0

        # 2. Then from current token (for new authentications)
        if (
            (not device_id or not session_id)
            and self._current_token
            and isinstance(self._current_token, MagentaAuthToken)
        ):
            device_id = self._current_token.device_id or ""
            session_id = self._current_token.session_id or ""
            channel_map_id = self._current_token.channel_map_id or ""
            session_id_updated_at = self._current_token.session_id_updated_at or 0.0

        # 3. If we found session IDs, log it
        if device_id and session_id:
            logger.debug(
                f"Creating new token with session IDs - device_id: {device_id}, session_id: {session_id}"
            )
        else:
            logger.warning(
                f"No session IDs found in response_data or current_token during token creation"
            )

        # DUAL KEY SUPPORT: Handle both camelCase (API responses) and snake_case (stored sessions)
        # Access token
        access_token = response_data.get("accessToken") or response_data.get("access_token")
        if not access_token:
            logger.error(f"CRITICAL: No access token found in response data")
            logger.error(f"Available keys: {list(response_data.keys())}")
            raise Exception("No access token found in response data")

        # Refresh token
        refresh_token = response_data.get("refreshToken") or response_data.get("refresh_token", "")

        # Expires in
        expires_in = response_data.get("expiresIn") or response_data.get("expires_in", 3600)

        # Token type
        token_type = response_data.get("tokenType") or response_data.get("token_type", "Bearer")

        # For stored sessions, issued_at might be in the data, otherwise use current time
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
        )

        # Classify token
        token.auth_level = self._classify_token(token)
        logger.debug(f"Token created successfully from {len(response_data)} data fields")

        return token

    def get_fallback_credentials(self):
        """Get fallback credentials - required by BaseAuthenticator"""
        from ...base.auth.credentials import UserPasswordCredentials

        return UserPasswordCredentials(username="", password="")

    def _perform_authentication(self) -> BaseAuthToken:
        """Perform Magenta TV authentication - required by BaseAuthenticator"""
        # Enhanced credential validation - FIXED VERSION
        if not self.credentials:
            raise Exception("No credentials available for authentication")

        # Accept both MagentaCredentials AND base UserPasswordCredentials
        from ...base.auth.credentials import UserPasswordCredentials

        if not isinstance(self.credentials, UserPasswordCredentials):
            raise Exception(
                f"Invalid credential type: {type(self.credentials)}. Expected UserPasswordCredentials or MagentaCredentials"
            )

        # Validate credential content
        if not self.credentials.username or not self.credentials.password:
            raise Exception("Username and password are required for authentication")

        logger.info(f"Performing Magenta TV authentication for country: {self.country}")

        try:
            # Perform login
            headers = self._get_auth_headers()
            payload = self._build_auth_payload()

            logger.debug(f"Authentication payload prepared for user: {self.credentials.username}")

            response = self._http_manager.post(
                self.auth_endpoint,
                operation="auth",
                headers=headers,
                json_data=payload,
                timeout=self._config.timeout,
            )

            response.raise_for_status()
            token_data = response.json()

            # Handle device limit exceeded
            if token_data.get("deviceLimitExceed", False):
                logger.info("Device limit exceeded, attempting token upgrade")
                token_data = self._upgrade_token(token_data["refreshToken"])

            return self._create_token_from_response(token_data)

        except Exception as e:
            logger.error(f"Authentication failed for user {self.credentials.username}: {e}")
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

    def _get_session_data(self) -> tuple[str, str, str, float]:
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
        """Refresh Magenta TV token - override base method"""
        if not self._current_token or not self._current_token.refresh_token:
            logger.debug("No valid refresh token available")
            return None

        try:
            logger.debug(f"Refreshing Magenta TV token for country: {self.country}")

            refresh_url = API_ENDPOINTS["REFRESH_TOKEN"].format(natco=self.country)

            device_id, session_id, channel_map_id, session_id_updated_at = self._get_session_data()

            tracking_id = str(uuid.uuid4())
            call_time = str(int(time.time() * 1000))

            # Build headers according to your working example
            headers = self._config.get_auth_headers(
                call_type=CALL_TYPES["AUTH_USER"],
                flow=AUTH_FLOWS["START_UP"],
                step=AUTH_STEPS["REFRESH_TOKEN"],
                device_id=device_id,
                session_id=session_id,
                tracking_id=tracking_id,
                call_time=call_time,
            )

            # Add the specific headers from your working example
            headers.update(
                {
                    "Refresh_token": self._current_token.refresh_token,
                    "channel": "Tv",
                }
            )

            # Build payload matching your working example
            payload = {
                "clientVersion": APP_VERSION,  # Use current APP_VERSION
                "deviceId": device_id,
                "concurrencyLimitParam": DEVICE_CONCURRENCY_PARAM,
            }

            logger.debug(f"Refresh request - URL: {refresh_url}")
            logger.debug(
                f"Refresh request - Headers: { {k: v for k, v in headers.items() if k not in ['Authorization', 'Refresh_token']} }"
            )
            logger.debug(f"Refresh request - Payload: {payload}")

            response = self._http_manager.post(
                refresh_url,
                operation="auth_refresh",
                headers=headers,
                json_data=payload,
                timeout=self._config.timeout,
            )

            response.raise_for_status()
            token_data = response.json()

            # Create new token with updated data but preserve session IDs
            new_token = MagentaAuthToken(
                access_token=token_data["accessToken"],
                refresh_token=token_data.get("refreshToken", self._current_token.refresh_token),
                token_type="Bearer",
                expires_in=token_data.get("expiresIn", 3600),
                issued_at=time.time(),
                device_id=device_id,
                session_id=session_id,
                channel_map_id=channel_map_id,
                session_id_updated_at=session_id_updated_at,
            )

            # Classify token
            new_token.auth_level = self._classify_token(new_token)
            logger.info("Token refresh successful")
            return new_token

        except Exception as e:
            logger.warning(f"Token refresh failed: {e}")
            if hasattr(e, "response") and hasattr(e.response, "text"):
                logger.error(f"Refresh response content: {e.response.text}")
            return None

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        """Classify Magenta TV token - required by BaseAuthenticator"""
        try:
            if not token or not token.access_token:
                return TokenAuthLevel.UNKNOWN

            # Only MagentaAuthToken has get_jwt_claims method
            if isinstance(token, MagentaAuthToken):
                claims = token.get_jwt_claims()
            else:
                # For BaseAuthToken, try to decode JWT manually
                try:
                    claims = decode_jwt(token.access_token, verify=False)
                except InvalidTokenError:
                    return TokenAuthLevel.UNKNOWN
                except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
                    logger.debug(f"Error decoding JWT token: {e}")
                    return TokenAuthLevel.UNKNOWN

            if not claims:
                return TokenAuthLevel.UNKNOWN

            # Magenta tokens with username in claims indicate user authentication
            if "username" in claims or "preferred_username" in claims:
                return TokenAuthLevel.USER_AUTHENTICATED

            # Anonymous tokens typically have limited claims
            if len(claims) <= 3:  # Basic claims like exp, iat, iss
                return TokenAuthLevel.ANONYMOUS

            return TokenAuthLevel.USER_AUTHENTICATED

        except Exception as e:
            logger.debug(f"Error classifying token: {e}")
            return TokenAuthLevel.UNKNOWN

    def get_user_account(self) -> Dict[str, Any]:
        """Get user account information"""
        access_token = self.get_bearer_token()

        account_url = API_ENDPOINTS["USER_ACCOUNT"].format(
            bifrost_url=get_bifrost_url(self.country)
        )

        params = {
            "fresh_login": "false",
            "app_language": get_language(self.country),
            "natco_code": self.country,
        }

        device_id = ""
        session_id = ""
        if self._current_token and isinstance(self._current_token, MagentaAuthToken):
            device_id = self._current_token.device_id or ""
            session_id = self._current_token.session_id or ""

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

        # Save channel map ID to current token
        if (
            "channelMap_id" in account_data
            and self._current_token
            and isinstance(self._current_token, MagentaAuthToken)
        ):
            self._current_token.channel_map_id = account_data["channelMap_id"]
            # Save the updated token with channel_map_id
            self._save_session()

        return account_data