# streaming_providers/providers/magenta_eu/auth.py
# -*- coding: utf-8 -*-
import uuid
import json
import base64
import time
from typing import Dict, Optional, Any
from dataclasses import dataclass, field
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from ...base.auth.base_auth import BaseAuthenticator, BaseAuthToken, TokenAuthLevel
from ...base.auth.credentials import UserPasswordCredentials
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger
from .constants import (
    SUPPORTED_COUNTRIES,
    DEFAULT_COUNTRY,
    COUNTRY_CONFIG,
    APP_VERSION,
    DEVICE_NAME,
    USER_AGENT,
    X_USER_AGENT,
    API_ENDPOINTS,
    DEFAULT_REQUEST_TIMEOUT,
    DEVICE_MODEL,
    DEVICE_TYPE,
    DEVICE_OS,
    DEVICE_MANUFACTURER,
    DEVICE_CONCURRENCY_PARAM,
    LOGIN_CONTEXT,
    LOGIN_TYPE,
    CHANNEL_ID,
    AUTH_FLOWS,
    AUTH_STEPS,
    CALL_TYPES,
    MANAGE_DEVICE,
    BROADCASTING_STREAM_LIMITATION_APPLIES,
    get_base_url,
    get_bifrost_url,
    get_natco_key,
    get_app_key,
    get_language
)


class InvalidTokenError(Exception):
    """Exception for invalid JWT tokens"""
    pass


def base64url_decode(input: str) -> bytes:
    """Base64 URL decode"""
    padding = '=' * (4 - (len(input) % 4))
    return base64.urlsafe_b64decode(input + padding)


def decode_jwt(token: str, verify: bool = True) -> Dict[str, Any]:
    """Decode JWT token"""
    try:
        header_b64, payload_b64, signature = token.split('.')
        payload_json = base64url_decode(payload_b64).decode('utf-8')
        payload = json.loads(payload_json)

        if verify and 'exp' in payload:
            if payload['exp'] < time.time():
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
class MagentaCredentials(UserPasswordCredentials):
    """Magenta TV credentials with country support"""
    country: str = DEFAULT_COUNTRY

    def validate(self) -> bool:
        """Validate credentials"""
        return bool(self.username and self.password and self.country in SUPPORTED_COUNTRIES)

    @property
    def credential_type(self) -> str:
        return "magenta_user_password"


@dataclass
class MagentaAuthToken(BaseAuthToken):
    """Magenta TV authentication token"""
    refresh_token: Optional[str] = field(default="")
    device_id: Optional[str] = field(default="")
    session_id: Optional[str] = field(default="")
    channel_map_id: Optional[str] = field(default="")

    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary"""
        data = {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token or "",
            'token_type': self.token_type,
            'expires_in': self.expires_in,
            'issued_at': self.issued_at,
            'auth_level': self.auth_level.value if self.auth_level else TokenAuthLevel.UNKNOWN.value,
            'credential_type': self.credential_type or ""
        }
        # Include session data
        if self.device_id:
            data['device_id'] = self.device_id
        if self.session_id:
            data['session_id'] = self.session_id
        if self.channel_map_id:
            data['channel_map_id'] = self.channel_map_id
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

    def get_base_headers(self) -> Dict[str, str]:
        """Get base headers for requests"""
        return {
            'User-Agent': self.user_agent,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }

    def get_auth_headers(self, call_type: str = CALL_TYPES['GUEST_USER'],
                         flow: str = AUTH_FLOWS['START_UP'],
                         step: str = AUTH_STEPS['GET_ACCESS_TOKEN'],
                         device_id: str = None, session_id: str = None) -> Dict[str, str]:
        """Get authentication headers"""
        headers = self.get_base_headers()
        headers.update({
            'X-User-Agent': self.x_user_agent,
            'X-Call-Type': call_type,
            'X-Tv-Flow': flow,
            'X-Tv-Step': step,
            'x-request-session-id': session_id or str(uuid.uuid4()),
            'x-request-tracking-id': str(uuid.uuid4()),
            'requestid': str(uuid.uuid4()),
            'Tenant': 'tv',
            'Origin': self.country_config['base_url'],
            'App_key': self.country_config['app_key'],
            'App_version': self.app_version,
            'Device-Id': device_id or str(uuid.uuid4()),
            'Device-Name': self.device_name,
        })
        return headers

    def encrypt_password(self, password: str) -> str:
        """Encrypt password using RSA public key"""
        try:
            rsa_key = self.country_config['rsa_key'],
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

    def __init__(self, country: str = DEFAULT_COUNTRY,
                 settings_manager=None,
                 credentials=None,
                 config_dir: Optional[str] = None,
                 http_manager=None,
                 proxy_config: Optional[ProxyConfig] = None):
        """
        Initialize Magenta authenticator
        """
        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(f"Unsupported country: {country}. Must be one of: {SUPPORTED_COUNTRIES}")

        if http_manager is None:
            raise ValueError("http_manager is required for MagentaAuthenticator")

        self.country = country
        self._http_manager = http_manager
        self._proxy_config = proxy_config

        # Setup config
        self._config = MagentaAuthConfig(self.country, self._http_manager)

        # NOW call parent __init__ - this will setup settings_manager and load session
        super().__init__(
            provider_name='magenta_eu',
            settings_manager=settings_manager,
            credentials=credentials,
            country=country,
            config_dir=config_dir,
            enable_kodi_integration=True
        )

        # After parent init, we can extract session data from the loaded token
        self._extract_session_data_from_token()

    def _extract_session_data_from_token(self) -> None:
        """Extract session data from the loaded token (if any)"""
        if self._current_token and isinstance(self._current_token, MagentaAuthToken):
            # Session data is already stored in the token
            logger.debug("Session data extracted from loaded token")
        else:
            # No token loaded, initialize empty session data
            logger.debug("No token loaded, session data will be initialized on first auth")

    @property
    def auth_endpoint(self) -> str:
        """Authentication endpoint - required by BaseAuthenticator"""
        return API_ENDPOINTS['LOGIN'].format(natco=self.country)

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers for authentication request - required by BaseAuthenticator"""
        device_id = ""
        session_id = ""

        # Get session data from current token if available
        if self._current_token and isinstance(self._current_token, MagentaAuthToken):
            device_id = self._current_token.device_id or ""
            session_id = self._current_token.session_id or ""

        return self._config.get_auth_headers(
            call_type=CALL_TYPES['GUEST_USER'],
            flow=AUTH_FLOWS['USERNAME_PASSWORD_LOGIN'],
            step=AUTH_STEPS['GET_ACCESS_TOKEN'],
            device_id=device_id,
            session_id=session_id
        )

    def _build_auth_payload(self) -> Dict[str, Any]:
        """Build authentication payload - required by BaseAuthenticator"""
        if not self.credentials or not isinstance(self.credentials, MagentaCredentials):
            raise Exception("No valid Magenta credentials available")

        device_id = ""
        if self._current_token and isinstance(self._current_token, MagentaAuthToken):
            device_id = self._current_token.device_id or ""

        # If no device_id, initialize session
        if not device_id:
            device_id, _ = self._initialize_session()

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
                "broadcastingStreamLimitationApplies": BROADCASTING_STREAM_LIMITATION_APPLIES
            },
            "telekomLogin": {
                "username": self.credentials.username,
                "password": encrypted_password
            }
        }

    def _create_token_from_response(self, response_data: Dict[str, Any]) -> BaseAuthToken:
        """Create token from API response - required by BaseAuthenticator"""
        # Get existing session data from current token
        device_id = ""
        session_id = ""
        channel_map_id = ""

        if self._current_token and isinstance(self._current_token, MagentaAuthToken):
            device_id = self._current_token.device_id or ""
            session_id = self._current_token.session_id or ""
            channel_map_id = self._current_token.channel_map_id or ""

        # If no device_id/session_id, initialize session
        if not device_id or not session_id:
            device_id, session_id = self._initialize_session()

        token = MagentaAuthToken(
            access_token=response_data['accessToken'],
            refresh_token=response_data.get('refreshToken', ''),
            token_type='Bearer',
            expires_in=response_data.get('expiresIn', 3600),
            issued_at=time.time(),
            device_id=device_id,
            session_id=session_id,
            channel_map_id=channel_map_id
        )

        # Classify token
        token.auth_level = self._classify_token(token)
        logger.debug(f"Token created and classified as: {token.auth_level.value}")

        return token

    def get_fallback_credentials(self):
        """Get fallback credentials - required by BaseAuthenticator"""
        # Return empty credentials as fallback
        return MagentaCredentials(username="", password="", country=self.country)

    def _initialize_session(self) -> tuple:
        """Initialize session by visiting startup page, returns (device_id, session_id)"""
        try:
            startup_url = API_ENDPOINTS['STARTUP_PAGE'].format(
                base_url=self._config.country_config['base_url']
            )

            headers = self._config.get_base_headers()
            response = self._http_manager.get(
                startup_url,
                operation='session_init',
                headers=headers,
                timeout=self._config.timeout
            )

            # Extract cookies
            device_id = ""
            session_id = ""
            if hasattr(response, 'cookies'):
                cookies = response.cookies.get_dict()
                device_id = cookies.get("deviceId", str(uuid.uuid4()))
                session_id = cookies.get("sessionId", str(uuid.uuid4()))

                logger.debug(f"Session initialized - device_id: {device_id}, session_id: {session_id}")

            return device_id, session_id

        except Exception as e:
            logger.warning(f"Session initialization failed: {e}")
            # Generate fallback IDs
            return str(uuid.uuid4()), str(uuid.uuid4())

    def _perform_authentication(self) -> BaseAuthToken:
        """Perform Magenta TV authentication - required by BaseAuthenticator"""
        if not self.credentials or not isinstance(self.credentials, MagentaCredentials):
            raise Exception("No valid Magenta credentials available")

        logger.info(f"Performing Magenta TV authentication for country: {self.country}")

        # Perform login
        headers = self._get_auth_headers()
        payload = self._build_auth_payload()

        response = self._http_manager.post(
            self.auth_endpoint,
            operation='auth',
            headers=headers,
            json_data=payload,
            timeout=self._config.timeout
        )

        response.raise_for_status()
        token_data = response.json()

        # Handle device limit exceeded
        if token_data.get("deviceLimitExceed", False):
            logger.info("Device limit exceeded, attempting token upgrade")
            token_data = self._upgrade_token(token_data['refreshToken'])

        return self._create_token_from_response(token_data)

    def _upgrade_token(self, refresh_token: str) -> Dict[str, Any]:
        """Upgrade token when device limit is exceeded"""
        upgrade_url = API_ENDPOINTS['UPGRADE_TOKEN'].format(natco=self.country)

        headers = self._config.get_auth_headers(
            call_type=CALL_TYPES['GUEST_USER'],
            flow=AUTH_FLOWS['USERNAME_PASSWORD_LOGIN'],
            step=AUTH_STEPS['UPGRADE_TOKEN']
        )
        headers['Refresh_token'] = refresh_token

        payload = self._build_auth_payload()

        response = self._http_manager.post(
            upgrade_url,
            operation='auth_upgrade',
            headers=headers,
            json_data=payload,
            timeout=self._config.timeout
        )

        response.raise_for_status()
        return response.json()

    def _refresh_token(self) -> Optional[BaseAuthToken]:
        """Refresh Magenta TV token - override base method"""
        if not self._current_token or not self._current_token.refresh_token:
            logger.debug("No valid refresh token available")
            return None

        try:
            logger.debug(f"Refreshing Magenta TV token for country: {self.country}")

            refresh_url = API_ENDPOINTS['REFRESH_TOKEN'].format(natco=self.country)

            headers = self._config.get_auth_headers(
                call_type=CALL_TYPES['AUTH_USER'],
                flow=AUTH_FLOWS['START_UP'],
                step=AUTH_STEPS['REFRESH_TOKEN']
            )
            headers['Refresh_token'] = self._current_token.refresh_token

            payload = {
                "clientVersion": self._config.app_version,
                "concurrencyLimitParam": DEVICE_CONCURRENCY_PARAM,
                "deviceId": self._current_token.device_id or ""
            }

            response = self._http_manager.post(
                refresh_url,
                operation='auth_refresh',
                headers=headers,
                json_data=payload,
                timeout=self._config.timeout
            )

            response.raise_for_status()
            token_data = response.json()

            # Create new token but preserve session data
            new_token = MagentaAuthToken(
                access_token=token_data['accessToken'],
                refresh_token=token_data.get('refreshToken', ''),
                token_type='Bearer',
                expires_in=token_data.get('expiresIn', 3600),
                issued_at=time.time(),
                device_id=self._current_token.device_id,
                session_id=self._current_token.session_id,
                channel_map_id=self._current_token.channel_map_id
            )

            # Classify token
            new_token.auth_level = self._classify_token(new_token)
            logger.info("Token refresh successful")
            return new_token

        except Exception as e:
            logger.warning(f"Token refresh failed: {e}")
            return None

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        """Classify Magenta TV token - required by BaseAuthenticator"""
        try:
            if not token or not token.access_token:
                return TokenAuthLevel.UNKNOWN

            claims = token.get_jwt_claims()
            if not claims:
                return TokenAuthLevel.UNKNOWN

            # Magenta tokens with username in claims indicate user authentication
            if 'username' in claims or 'preferred_username' in claims:
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

        account_url = API_ENDPOINTS['USER_ACCOUNT'].format(
            bifrost_url=get_bifrost_url(self.country)
        )

        params = {
            'fresh_login': 'false',
            'app_language': get_language(self.country),
            'natco_code': self.country
        }

        device_id = ""
        session_id = ""
        if self._current_token and isinstance(self._current_token, MagentaAuthToken):
            device_id = self._current_token.device_id or ""
            session_id = self._current_token.session_id or ""

        headers = self._config.get_auth_headers(
            call_type=CALL_TYPES['AUTH_USER'],
            flow=AUTH_FLOWS['START_UP'],
            step=AUTH_STEPS['GET_USER_ACCOUNT'],
            device_id=device_id,
            session_id=session_id
        )
        headers['Bff_token'] = access_token

        response = self._http_manager.get(
            account_url,
            operation='user_account',
            headers=headers,
            params=params,
            timeout=self._config.timeout
        )

        response.raise_for_status()
        account_data = response.json()

        # Save channel map ID to current token
        if 'channelMap_id' in account_data and self._current_token and isinstance(self._current_token,
                                                                                  MagentaAuthToken):
            self._current_token.channel_map_id = account_data['channelMap_id']
            # Save the updated token with channel_map_id
            self._save_session()

        return account_data