# streaming_providers/providers/magenta2/auth.py
# -*- coding: utf-8 -*-
import uuid
import time
import base64
import json
from typing import Dict, Optional, Any
from dataclasses import dataclass, field

from ...base.auth.base_oauth2_auth import BaseOAuth2Authenticator
from ...base.auth.base_auth import BaseAuthToken, TokenAuthLevel
from ...base.auth.credentials import ClientCredentials
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger

# PHASE 2 & 3: Import new components
from .sam3_client import Sam3Client
from .sso_client import SsoClient
from .taa_client import TaaClient, TaaAuthResult

from .constants import (
    SUPPORTED_COUNTRIES,
    DEFAULT_COUNTRY,
    DEFAULT_PLATFORM,
    DEFAULT_REQUEST_TIMEOUT,
    MAGENTA2_CLIENT_IDS,
    MAGENTA2_OAUTH_SCOPE,
    MAGENTA2_REDIRECT_URI,
    MAGENTA2_FALLBACK_ENDPOINTS,
    MAGENTA2_PLATFORMS,
    IDM,
    APPVERSION2,
    TAA_REQUEST_TEMPLATE,
    GRANT_TYPES,
    SSO_USER_AGENT
)


@dataclass
class Magenta2Credentials(ClientCredentials):
    """
    Magenta2-specific credentials for client credentials flow (TAA auth)
    Note: Magenta2 uses public client OAuth flow - no client_secret required
    """
    platform: str = DEFAULT_PLATFORM
    country: str = DEFAULT_COUNTRY
    device_id: Optional[str] = field(default=None)

    def __post_init__(self):
        # Magenta2 doesn't use client_secret (public client flow)
        if not hasattr(self, 'client_secret') or self.client_secret is None:
            self.client_secret = ""  # Empty string for public client

        # Set client_id from constant if not provided
        if not self.client_id:
            self.client_id = MAGENTA2_CLIENT_IDS.get(self.platform, MAGENTA2_CLIENT_IDS[DEFAULT_PLATFORM])

        # Generate device ID if not provided
        if not self.device_id:
            self.device_id = str(uuid.uuid4())

    def validate(self) -> bool:
        """Validate Magenta2 credentials"""
        if not self.client_id or not self.platform:
            return False
        if self.country not in SUPPORTED_COUNTRIES:
            return False
        return True

    def to_taa_payload(self, access_token: str, client_model: Optional[str] = None,
                       device_model: Optional[str] = None) -> Dict[str, Any]:
        """Convert to TAA authentication payload"""
        platform_config = MAGENTA2_PLATFORMS.get(self.platform, MAGENTA2_PLATFORMS[DEFAULT_PLATFORM])

        # Use provided models or fallback to platform defaults
        resolved_device_model = device_model or platform_config['device_name']
        resolved_client_model = client_model or f"ftv-{self.platform}"

        # Build keyValue string with client model if available
        key_value_parts = [
            IDM,
            APPVERSION2
        ]

        # Add client model if available
        if resolved_client_model:
            key_value_parts.append(f"ClientModelParams(id={resolved_client_model})")

        key_value_parts.extend([
            f"TokenChannelParams(id=Tv)",
            f"TokenDeviceParams(id={self.device_id}, model={resolved_device_model}, os={platform_config['firmware']})",
            "DE",
            "telekom"
        ])

        key_value = "/".join(key_value_parts)

        # Start with template and populate fields
        payload = TAA_REQUEST_TEMPLATE.copy()
        payload.update({
            "keyValue": key_value,
            "accessToken": access_token,
            "device": {
                "id": self.device_id,
                "model": resolved_device_model,
                "os": platform_config['firmware']
            }
        })

        # Add client model if available
        if resolved_client_model:
            payload["client"] = {"model": resolved_client_model}

        return payload

    @property
    def credential_type(self) -> str:
        return "magenta2_client_credentials"


@dataclass
class Magenta2UserCredentials(Magenta2Credentials):
    """
    Magenta2 user credentials for complete authentication flow
    Adds username/password support for SAM3 login
    """
    username: str = ""
    password: str = ""

    def has_user_credentials(self) -> bool:
        """Check if username/password credentials are available"""
        return bool(self.username and self.password)

    def validate_user_credentials(self) -> bool:
        """Validate user credentials"""
        return self.has_user_credentials() and len(self.username) > 0 and len(self.password) > 0

    @property
    def credential_type(self) -> str:
        return "magenta2_user_credentials"

@dataclass
class Magenta2AuthToken(BaseAuthToken):
    """
    Magenta2-specific authentication token with TAA data and persona token composition
    """
    refresh_token: Optional[str] = field(default="")
    dc_cts_persona_token: Optional[str] = field(default=None)
    persona_id: Optional[str] = field(default=None)
    account_id: Optional[str] = field(default=None)
    consumer_id: Optional[str] = field(default=None)
    tv_account_id: Optional[str] = field(default=None)
    account_token: Optional[str] = field(default=None)
    account_uri: Optional[str] = field(default=None)
    composed_persona_token: Optional[str] = field(default=None)
    token_exp: Optional[int] = field(default=None)
    sso_user_id: Optional[str] = field(default=None)
    sso_display_name: Optional[str] = field(default=None)

    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary"""
        base_dict = {
            'access_token': self.access_token,
            'refresh_token': self.refresh_token or "",
            'token_type': self.token_type,
            'expires_in': self.expires_in,
            'issued_at': self.issued_at
        }

        # Add Magenta2-specific fields
        if self.dc_cts_persona_token:
            base_dict['dc_cts_persona_token'] = self.dc_cts_persona_token
        if self.persona_id:
            base_dict['persona_id'] = self.persona_id
        if self.account_id:
            base_dict['account_id'] = self.account_id
        if self.consumer_id:
            base_dict['consumer_id'] = self.consumer_id
        if self.tv_account_id:
            base_dict['tv_account_id'] = self.tv_account_id
        if self.account_token:
            base_dict['account_token'] = self.account_token
        if self.account_uri:
            base_dict['account_uri'] = self.account_uri
        if self.composed_persona_token:
            base_dict['composed_persona_token'] = self.composed_persona_token
        if self.token_exp:
            base_dict['token_exp'] = self.token_exp
        if self.sso_user_id:
            base_dict['sso_user_id'] = self.sso_user_id
        if self.sso_display_name:
            base_dict['sso_display_name'] = self.sso_display_name

        return base_dict

    def compose_persona_token(self) -> Optional[str]:
        """
        Compose final persona token from account URI and dc_cts_persona_token
        This is the CRITICAL step matching the C++ implementation:

        C++: rawToken = accountUri + ":" + dc_cts_personaToken
             personaToken = base64_encode(rawToken)

        Format: Base64(accountUri + ":" + dc_cts_personaToken)
        Example: Base64("urn:theplatform:auth:root:mdeprod:abcd1234-5678-90ef")
        """
        if not self.account_uri or not self.dc_cts_persona_token:
            logger.warning(
                f"Cannot compose persona token - "
                f"account_uri: {bool(self.account_uri)}, "
                f"dc_cts_persona_token: {bool(self.dc_cts_persona_token)}"
            )
            return None

        try:
            # Compose: accountUri + ":" + dc_cts_persona_token
            raw_token = f"{self.account_uri}:{self.dc_cts_persona_token}"

            # Base64 encode
            self.composed_persona_token = base64.b64encode(
                raw_token.encode('utf-8')
            ).decode('utf-8')

            logger.info("✓ Persona token composed successfully")
            logger.debug(f"Account URI: {self.account_uri}")
            logger.debug(f"Composed token preview: {self.composed_persona_token[:50]}...")

            return self.composed_persona_token

        except Exception as e:
            logger.error(f"Failed to compose persona token: {e}")
            return None

    def get_jwt_claims(self) -> Optional[Dict[str, Any]]:
        """Extract JWT claims from access token for classification"""
        try:
            if not self.access_token:
                return None

            parts = self.access_token.split('.')
            if len(parts) != 3:
                return None

            payload_b64 = parts[1]
            padding = len(payload_b64) % 4
            if padding:
                payload_b64 += '=' * (4 - padding)

            payload_json = base64.b64decode(payload_b64).decode('utf-8')
            return json.loads(payload_json)

        except Exception as e:
            logger.debug(f"Failed to extract JWT claims: {e}")
            return None


class Magenta2AuthConfig:
    """Configuration object for Magenta2 authentication"""

    def __init__(self, country: str, platform: str = DEFAULT_PLATFORM,
                 endpoints: Optional[Dict[str, str]] = None,
                 client_model: Optional[str] = None,
                 device_model: Optional[str] = None):
        self.country = country
        self.platform = platform
        self.platform_config = MAGENTA2_PLATFORMS.get(platform, MAGENTA2_PLATFORMS[DEFAULT_PLATFORM])
        self.user_agent = self.platform_config['user_agent']
        self.timeout = 30
        self.endpoints = endpoints or {}
        self.client_model = client_model
        self.device_model = device_model

    def get_base_headers(self) -> Dict[str, str]:
        """Get base headers for all requests"""
        return {
            'User-Agent': self.user_agent,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def get_oauth_headers(self) -> Dict[str, str]:
        """Get headers for OAuth2 requests (use form encoding)"""
        headers = self.get_base_headers()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        return headers

    @staticmethod
    def get_sso_headers(session_id: str = None, device_id: str = None) -> Dict[str, str]:
        """Get headers for SSO requests"""
        headers = {
            'User-Agent': SSO_USER_AGENT,
            'Content-Type': 'application/json',
            'origin': 'https://web2.magentatv.de',
            'referer': 'https://web2.magentatv.de/'
        }

        if session_id:
            headers['session-id'] = session_id
        if device_id:
            headers['device-id'] = device_id

        return headers

    def get_taa_headers(self, sam3_token: str) -> Dict[str, str]:
        """Get headers for TAA requests"""
        headers = self.get_base_headers()
        headers['Authorization'] = f'Bearer {sam3_token}'
        return headers


class Magenta2Authenticator(BaseOAuth2Authenticator):
    """
    ENHANCED: Magenta2 authenticator with complete SAM3 + SSO + TAA flow
    Now supports both user credentials and client credentials flows
    """

    def __init__(self, country: str = DEFAULT_COUNTRY,
                 platform: str = DEFAULT_PLATFORM,
                 settings_manager=None,
                 credentials=None,
                 config_dir: Optional[str] = None,
                 http_manager=None,
                 proxy_config: Optional[ProxyConfig] = None,
                 endpoints: Optional[Dict[str, str]] = None,
                 client_model: Optional[str] = None,
                 device_model: Optional[str] = None,
                 sam3_client_id: Optional[str] = None,
                 session_id: Optional[str] = None,
                 device_id: Optional[str] = None):
        """
        Enhanced authenticator with complete authentication flow support
        """
        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(f"Unsupported country: {country}. Must be one of: {SUPPORTED_COUNTRIES}")

        if http_manager is None:
            raise ValueError("http_manager is required for Magenta2Authenticator")

        # Set country-specific attributes FIRST
        self.country = country
        self.platform = platform

        # Store http_manager reference
        self._http_manager = http_manager

        # Store dynamically discovered endpoints
        self._dynamic_endpoints = endpoints or {}

        # Store bootstrap parameters as instance attributes
        self._client_model = client_model
        self._device_model = device_model
        self._sam3_client_id = sam3_client_id

        # Session and device management
        self._session_id = session_id or str(uuid.uuid4())
        self._device_id = device_id or str(uuid.uuid4())

        # NEW: Store MPX account info for persona token composition
        self._mpx_account_pid: Optional[str] = None
        self._device_token: Optional[str] = None
        self._authorize_tokens_url: Optional[str] = None

        # NEW: SAM3 and SSO clients
        self._sam3_client: Optional[Sam3Client] = None
        self._sso_client: Optional[SsoClient] = None
        self._openid_config: Optional[Dict[str, Any]] = None

        # Setup Magenta2-specific config with endpoints and parameters
        self._config = Magenta2AuthConfig(
            self.country,
            self.platform,
            self._dynamic_endpoints,
            self._client_model,
            self._device_model
        )

        # Extract and cache client_id (use SAM3 client ID from bootstrap if available)
        self._client_id = self._sam3_client_id or MAGENTA2_CLIENT_IDS.get(
            self.platform,
            MAGENTA2_CLIENT_IDS[DEFAULT_PLATFORM]
        )

        # Initialize credentials if not provided
        if credentials is None:
            credentials = self.get_fallback_credentials()

        # Initialize SAM3 and SSO clients if we have the required info
        self._initialize_sam3_sso_clients()

        self._taa_client: Optional[TaaClient] = None
        self._initialize_taa_client()

        # Initialize parent
        super().__init__(
            provider_name='magenta2',
            settings_manager=settings_manager,
            credentials=credentials,
            country=country,
            config_dir=config_dir,
            enable_kodi_integration=True,
            http_manager=self._http_manager,
            proxy_config=proxy_config
        )

    def update_sam3_client_id(self, client_id: str) -> None:
        """Public method to update SAM3 client ID"""
        old_client_id = self._sam3_client_id
        self._sam3_client_id = client_id

        # Also update the SAM3 client if it exists
        if self._sam3_client:
            self._sam3_client.update_sam3_client_id(client_id)
            logger.info(f"✓ Updated SAM3 client ID: {old_client_id[:8]}... -> {client_id[:8]}...")
        else:
            logger.debug(f"Updated SAM3 client ID (no client to update yet): {client_id}")

    def update_client_model(self, client_model: str) -> None:
        """Public method to update client model"""
        self._client_model = client_model
        logger.debug(f"Updated client model: {client_model}")

    def update_device_model(self, device_model: str) -> None:
        """Public method to update device model"""
        self._device_model = device_model
        logger.debug(f"Updated device model: {device_model}")

    def update_dynamic_endpoints(self, endpoints: Dict[str, str]) -> None:
        """Public method to update dynamic endpoints"""
        self._dynamic_endpoints.update(endpoints)
        logger.debug(f"Updated dynamic endpoints with {len(endpoints)} entries")

    def update_endpoints(self, endpoints: Dict[str, str]) -> None:
        """Public method to update endpoints (alias for compatibility)"""
        self.update_dynamic_endpoints(endpoints)

    def _initialize_taa_client(self) -> None:
        """Initialize TAA client"""
        self._taa_client = TaaClient(
            http_manager=self._http_manager,
            platform=self.platform
        )
        logger.debug("TAA client initialized")

    def _initialize_sam3_sso_clients(self) -> None:
        """Initialize SAM3 and SSO clients with all endpoints"""
        try:
            # Initialize SSO client (always available)
            self._sso_client = SsoClient(
                http_manager=self._http_manager,
                session_id=self._session_id,
                device_id=self._device_id
            )

            # Initialize SAM3 client if we have client ID
            if self._sam3_client_id:
                # GET ALL ENDPOINTS
                issuer_url = None
                oauth_endpoint = None
                line_auth_endpoint = self._authorize_tokens_url  # From manifest
                backchannel_start_url = None
                qr_code_url_template = None  # NEW: Get from dynamic endpoints

                # NEW: Get QR code URL from dynamic endpoints (bootstrap)
                if 'login_qr_code' in self._dynamic_endpoints:
                    qr_code_url_template = self._dynamic_endpoints['login_qr_code']
                    logger.debug(f"QR code URL from dynamic endpoints: {qr_code_url_template}")

                if self._openid_config:
                    issuer_url = self._openid_config.get('issuer')
                    oauth_endpoint = self._openid_config.get('token_endpoint')
                    # Get backchannel from OpenID config
                    backchannel_start_url = self._openid_config.get('backchannel_auth_start')

                self._sam3_client = Sam3Client(
                    http_manager=self._http_manager,
                    session_id=self._session_id,
                    device_id=self._device_id,
                    sam3_client_id=self._sam3_client_id,
                    issuer_url=issuer_url,
                    oauth_token_endpoint=oauth_endpoint,
                    line_auth_endpoint=line_auth_endpoint,
                    backchannel_start_url=backchannel_start_url,
                    qr_code_url_template=qr_code_url_template  # PASS THE QR CODE URL
                )

                logger.info(
                    f"SAM3 client initialized - "
                    f"Issuer: {bool(issuer_url)}, "
                    f"OAuth: {bool(oauth_endpoint)}, "
                    f"Line: {bool(line_auth_endpoint)}, "
                    f"Backchannel: {bool(backchannel_start_url)}, "
                    f"QR URL: {bool(qr_code_url_template)}"
                )

        except Exception as e:
            logger.warning(f"Failed to initialize SAM3/SSO clients: {e}")

    def update_sam3_qr_code_url(self, qr_code_url: str) -> bool:
        """
        Public method to update SAM3 client with QR code URL
        Returns True if successful, False otherwise
        """
        if not self._sam3_client:
            logger.warning("Cannot update QR code URL - SAM3 client not initialized")
            return False

        # Use public method instead of direct assignment
        self._sam3_client.set_qr_code_url(qr_code_url)
        logger.info(f"✓ Updated SAM3 client with QR code URL: {qr_code_url}")
        return True

    def get_sam3_client_status(self) -> Dict[str, Any]:
        """
        Public method to get SAM3 client status for debugging
        """
        if not self._sam3_client:
            return {'initialized': False}

        # Use public method instead of accessing protected members
        return self._sam3_client.get_client_status()

    def can_use_line_auth(self) -> bool:
        """Check if line auth components are available"""
        return (
                self._device_token is not None and
                self._authorize_tokens_url is not None and
                self._sam3_client is not None
        )

    def can_use_remote_login(self) -> bool:
        """Check if remote login components are available"""
        return (
                self._sam3_client is not None and
                self._sam3_client.can_use_remote_login()
        )

    def set_mpx_account_pid(self, account_pid: str):
        """
        Set MPX account PID for account URI construction
        This is CRITICAL for persona token composition

        Args:
            account_pid: MPX account PID (e.g., 'mdeprod')
        """
        self._mpx_account_pid = account_pid
        logger.debug(f"MPX account PID set: {account_pid}")

    def set_remote_login_urls(self, qr_code_url_template: str, backchannel_start_url: str = None):
        """
        Set remote login URLs for backchannel authentication

        Args:
            qr_code_url_template: QR code URL template with {code} placeholder
            backchannel_start_url: Optional backchannel start endpoint (from OpenID)
        """
        if self._sam3_client:
            self._sam3_client.qr_code_url_template = qr_code_url_template
            if backchannel_start_url:
                self._sam3_client.backchannel_start_url = backchannel_start_url
            logger.info(f"✓ Remote login URLs configured for SAM3 client")
        else:
            logger.warning("Cannot set remote login URLs - SAM3 client not initialized")

    # PHASE 4: Enhanced device token management
    def set_device_token(self, device_token: str, authorize_tokens_url: str = None):
        """
        Enhanced device token setup with both endpoints
        """
        self._device_token = device_token
        self._authorize_tokens_url = authorize_tokens_url

        # UPDATE SAM3 CLIENT WITH LINE AUTH ENDPOINT
        if self._sam3_client and authorize_tokens_url:
            self._sam3_client.line_auth_endpoint = authorize_tokens_url
            self._sam3_client.token_endpoint = authorize_tokens_url  # Backwards compat
            logger.info(f"✓ Updated SAM3 client with line auth endpoint: {authorize_tokens_url}")

        logger.debug("Device token configured with line authentication support")

    def perform_device_authentication(self) -> bool:
        """
        PHASE 4: Perform device-based authentication using device token
        This can be called independently for device registration flows
        """
        return self._perform_line_auth()

    def validate_taa_token(self, taa_token: str) -> bool:
        """
        PHASE 4: Validate TAA token using TaaClient
        """
        if not self._taa_client:
            return False
        return self._taa_client.validate_taa_token(taa_token)

    def debug_taa_token(self, taa_token: str) -> Dict[str, Any]:
        """
        PHASE 4: Debug TAA token using TaaClient
        """
        if not self._taa_client:
            return {'error': 'TAA client not initialized'}
        return self._taa_client.debug_taa_token(taa_token)

    def get_authentication_flow_info(self) -> Dict[str, Any]:
        """
        Enhanced with TAA client info
        """
        base_info = {
            'user_credentials_available': isinstance(self.credentials, Magenta2UserCredentials) and self.credentials.has_user_credentials(),
            'client_credentials_available': True,
            'sam3_client_available': self._sam3_client is not None,
            'sso_client_available': self._sso_client is not None,
            'taa_client_available': self._taa_client is not None,
            'device_token_available': bool(self._device_token),
            'mpx_account_pid_available': bool(self._mpx_account_pid),
            'preferred_flow': 'USER' if (isinstance(self.credentials, Magenta2UserCredentials) and self.credentials.has_user_credentials()) else 'CLIENT'
        }

        # Add TAA-specific info if available
        if self._taa_client and self._current_token:
            base_info['taa_token_valid'] = self.validate_taa_token(self._current_token.access_token)

        return base_info

    def set_openid_config(self, openid_config: Dict[str, Any]):
        """
        Set OpenID configuration for SAM3 client

        Args:
            openid_config: OpenID configuration dictionary
        """
        self._openid_config = openid_config
        if self._sam3_client:
            self._sam3_client.update_endpoints(openid_config)
        logger.debug("OpenID configuration updated")

    def get_current_token(self) -> Optional[BaseAuthToken]:
        """Get the current authentication token"""
        return self._current_token

    def _get_endpoint(self, endpoint_key: str, fallback_key: str = None) -> str:
        """
        Get endpoint URL, preferring dynamically discovered ones

        Args:
            endpoint_key: Key in dynamic endpoints dict
            fallback_key: Key in MAGENTA2_FALLBACK_ENDPOINTS if dynamic lookup fails
        """
        # Try dynamic endpoint first
        if endpoint_key in self._dynamic_endpoints:
            url = self._dynamic_endpoints[endpoint_key]
            logger.debug(f"Using dynamic endpoint for {endpoint_key}: {url}")
            return url

        # Fall back to hardcoded if available
        if fallback_key and fallback_key in MAGENTA2_FALLBACK_ENDPOINTS:
            url = MAGENTA2_FALLBACK_ENDPOINTS[fallback_key]
            logger.debug(f"Using fallback endpoint for {endpoint_key}: {url}")
            return url

        raise ValueError(f"No endpoint found for {endpoint_key}")

    @property
    def oauth_client_id(self) -> str:
        """Get OAuth2 client ID"""
        return self._client_id

    @property
    def oauth_scope(self) -> str:
        """OAuth2 scopes"""
        return MAGENTA2_OAUTH_SCOPE

    @property
    def oauth_redirect_uri(self) -> str:
        """OAuth2 redirect URI"""
        return MAGENTA2_REDIRECT_URI

    @property
    def auth_endpoint(self) -> str:
        """Primary authentication endpoint - TAA flow"""
        return self._get_endpoint('taa_auth', 'TAA_AUTH')

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers for authentication request"""
        return self._config.get_base_headers()

    def _build_auth_payload(self) -> Dict[str, Any]:
        """Build authentication payload for client credentials flow"""
        if not self.credentials:
            self.credentials = self.get_fallback_credentials()

        # For initial SAM3 client credentials auth
        return {
            'client_id': self.credentials.client_id,
            'grant_type': GRANT_TYPES['CLIENT_CREDENTIALS'],
            'scope': MAGENTA2_OAUTH_SCOPE
        }

    def _create_token_from_response(self, response_data: Dict[str, Any]) -> BaseAuthToken:
        """
        ENHANCED: Create token object from API response and compose persona token
        This is where the final persona token composition happens
        """
        # Handle different response key formats
        access_token = response_data.get('access_token', response_data.get('accessToken'))
        if not access_token:
            raise ValueError("No access token in response")

        # Create token with ALL fields
        token = Magenta2AuthToken(
            access_token=access_token,
            refresh_token=response_data.get('refresh_token', response_data.get('refreshToken', '')),
            token_type=response_data.get('token_type', response_data.get('tokenType', 'Bearer')),
            expires_in=response_data.get('expires_in', response_data.get('expiresIn', 3600)),
            issued_at=response_data.get('issued_at', response_data.get('issuedAt', time.time())),

            # Magenta2-specific fields from JWT
            dc_cts_persona_token=response_data.get('dc_cts_persona_token'),
            persona_id=response_data.get('persona_id'),
            account_id=response_data.get('account_id'),
            consumer_id=response_data.get('consumer_id'),
            tv_account_id=response_data.get('tv_account_id'),
            account_token=response_data.get('account_token'),
            account_uri=response_data.get('account_uri'),
            token_exp=response_data.get('token_exp'),

            # SSO fields if available
            sso_user_id=response_data.get('sso_user_id'),
            sso_display_name=response_data.get('sso_display_name')
        )

        # CRITICAL: Compose final persona token
        if token.dc_cts_persona_token and token.account_uri:
            composed = token.compose_persona_token()
            if composed:
                logger.info("✓ Persona token successfully composed")
            else:
                logger.error("✗ Failed to compose persona token!")
        else:
            logger.warning(
                f"Cannot compose persona token - "
                f"dc_cts_persona_token: {bool(token.dc_cts_persona_token)}, "
                f"account_uri: {bool(token.account_uri)}"
            )

            # Try to construct account_uri from MPX account PID if available
            if token.dc_cts_persona_token and self._mpx_account_pid:
                logger.info(f"Attempting to construct account_uri from MPX account PID: {self._mpx_account_pid}")
                token.account_uri = f"urn:theplatform:auth:root:{self._mpx_account_pid}"
                composed = token.compose_persona_token()
                if composed:
                    logger.info("✓ Persona token composed using constructed account_uri")

        # NEW: Only classify token if it's NOT from line_auth
        if not response_data.get('auth_source') == 'line_auth':
            token.auth_level = self._classify_token(token)
            logger.debug(f"Token created and classified as: {token.auth_level.value}")
        else:
            token.auth_level = TokenAuthLevel.UNKNOWN
            logger.debug("Line auth token - skipping classification")

        # NEW: Save ONLY the access token data under 'tvhubs' scope
        scoped_token_data = {
            'access_token': token.access_token,
            'token_type': token.token_type,
            'expires_in': token.expires_in,
            'issued_at': token.issued_at
        }

        # Save scoped token (access_token under 'tvhubs' scope)
        self.settings_manager.save_scoped_token(
            self.provider_name,
            'tvhubs',
            scoped_token_data,
            self.country
        )

        # NEW: Clear the main provider-level token data (no backward compatibility)
        # Only keep refresh_token and device_id
        provider_session_data = {
            'refresh_token': token.refresh_token,
            'device_id': getattr(self, '_device_id', '')
        }

        # Save provider session data without access_token and without persona fields
        self.settings_manager.save_session(
            self.provider_name,
            provider_session_data,
            self.country
        )

        logger.info(
            "✓ Access token saved under 'tvhubs' scope, only refresh_token and device_id saved at provider level")

        return token

    def _create_token_from_combined_data(self, sso_data: Dict[str, Any], taa_data: Dict[str, Any]) -> BaseAuthToken:
        """
        NEW: Create token from combined SSO and TAA data for complete user flow
        """
        # Start with TAA data as base
        token_data = taa_data.copy()

        # Enhance with SSO data
        token_data.update({
            'sso_user_id': sso_data.get('userId'),
            'sso_display_name': sso_data.get('displayName'),
            # Use SSO persona token if TAA doesn't provide one
            'dc_cts_persona_token': taa_data.get('dc_cts_persona_token') or sso_data.get('personaToken')
        })

        return self._create_token_from_response(token_data)

    def get_fallback_credentials(self) -> Magenta2Credentials:
        """Get fallback credentials when no user credentials are available"""
        return Magenta2Credentials(
            client_id=self._client_id,
            platform=self.platform,
            country=self.country
        )

    def _perform_authentication(self) -> BaseAuthToken:
        """
        ENHANCED: Perform Magenta2 authentication with line auth priority
        """
        # NEW: Try line auth first if we have the required components
        if self._should_try_line_auth_first():
            logger.info("Attempting line authentication first (device token available)")
            try:
                return self._perform_line_auth_flow()
            except Exception as e:
                logger.warning(f"Line auth failed, falling back to standard flow: {e}")

        # Continue with existing logic
        if isinstance(self.credentials, Magenta2UserCredentials) and self.credentials.has_user_credentials():
            logger.info(f"Using complete user authentication flow for {self.provider_name}")
            return self._perform_user_authentication_flow()
        else:
            logger.info(f"Using client credentials TAA flow for {self.provider_name}")
            return self._perform_taa_flow()

    def _should_try_line_auth_first(self) -> bool:
        """Check if we should attempt line auth first"""
        return (
                self._device_token is not None and
                self._authorize_tokens_url is not None and
                self._sam3_client is not None
        )

    def _perform_line_auth_flow(self) -> BaseAuthToken:
        """
        Complete authentication flow starting with line auth with automatic remote login fallback
        """
        logger.debug("Starting line authentication flow with remote login fallback")

        # Step 1: Try line authentication first
        try:
            line_response_data = self._perform_line_auth_with_response()
            if line_response_data:
                logger.info("✓ Line auth succeeded")
                return self._process_line_auth_success(line_response_data)
        except Exception as e:
            logger.warning(f"Line auth failed: {e}")

        # Step 2: Line auth failed, try remote login fallback
        logger.info("Line auth failed, attempting remote login fallback")

        if not self._sam3_client or not self._sam3_client.can_use_remote_login():
            logger.error("Remote login not available as fallback")
            raise Exception("Line auth failed and remote login not available")

        try:
            # Perform remote login (notifier handled internally)
            remote_token_data = self._sam3_client.remote_login(
                scope="tvhubs offline_access"
            )

            if not remote_token_data:
                raise Exception("Remote login failed or timed out")

            logger.info("✓ Remote login fallback successful")

            # Process remote login token same as line auth
            return self._process_line_auth_success(remote_token_data)

        except Exception as e:
            logger.error(f"Remote login fallback failed: {e}")
            raise Exception(f"Both line auth and remote login failed: {e}")

    def _process_line_auth_success(self, line_response_data: Dict[str, Any]) -> BaseAuthToken:
        """
        Process successful line auth or remote login response
        (Extracted from original _perform_line_auth_flow)
        """
        # Check if we have SettingsManager with scoped token support
        if not hasattr(self.settings_manager, 'save_scoped_token'):
            logger.warning("SettingsManager doesn't support scoped tokens, falling back to TAA")
            raise Exception("Scoped token support not available")

        # Save the TVHUBS token
        tvhubs_token_data = {
            'access_token': line_response_data.get('access_token'),
            'token_type': line_response_data.get('token_type', 'Bearer'),
            'expires_in': line_response_data.get('expires_in', 7200),
            'issued_at': time.time()
        }

        success = self.settings_manager.save_scoped_token(
            self.provider_name,
            'tvhubs',
            tvhubs_token_data,
            self.country
        )

        if not success:
            logger.error("Failed to save TVHUBS scoped token")
            raise Exception("Failed to save TVHUBS token")

        logger.info("✓ TVHUBS access token saved from authentication")

        # Extract refresh token for token exchange
        line_refresh_token = line_response_data.get('refresh_token')
        if not line_refresh_token:
            logger.warning("No refresh token in response, using access token directly")
            return self._create_token_from_line_auth_response(line_response_data)

        # Try token exchange for TAA scope
        try:
            taa_token_data = self._exchange_refresh_token_for_taa_scope(line_refresh_token)
            if taa_token_data:
                # Save TAA token under taa scope
                self.settings_manager.save_scoped_token(
                    self.provider_name,
                    'taa',
                    taa_token_data,
                    self.country
                )
                logger.info("✓ TAA access token saved from token exchange")

                # Save the NEW refresh token at provider level
                provider_session_data = {
                    'refresh_token': taa_token_data['refresh_token'],
                    'device_id': getattr(self, '_device_id', '')
                }

                self.settings_manager.save_session(
                    self.provider_name,
                    provider_session_data,
                    self.country
                )
                logger.info("✓ Updated refresh token saved at provider level")

                # Create token object with TAA token
                token = Magenta2AuthToken(
                    access_token=taa_token_data['access_token'],
                    refresh_token=taa_token_data['refresh_token'],
                    token_type=taa_token_data['token_type'],
                    expires_in=taa_token_data['expires_in'],
                    issued_at=taa_token_data['issued_at'],
                    auth_level=TokenAuthLevel.UNKNOWN
                )
            else:
                logger.warning("Token exchange failed, using line auth token directly")
                token = self._create_token_from_line_auth_response(line_response_data)

        except Exception as e:
            logger.warning(f"Token exchange failed: {e}, using line auth token directly")
            token = self._create_token_from_line_auth_response(line_response_data)

        logger.info("✓ Authentication flow completed successfully")
        return token

    def _exchange_refresh_token_for_taa_scope(self, refresh_token: str) -> Optional[Dict[str, Any]]:
        """
        Exchange line auth refresh token for TAA-scoped tokens
        """
        try:
            logger.debug("Exchanging refresh token for TAA scope")

            # Get token endpoint and client ID
            token_endpoint = self._get_endpoint('oauth_token', 'OPENID_CONFIG')
            if token_endpoint.endswith('/.well-known/openid-configuration'):
                token_endpoint = token_endpoint.replace('/.well-known/openid-configuration', '/oauth2/tokens')

            client_id = self._sam3_client_id or self.oauth_client_id
            if not client_id:
                raise Exception("No client ID available for token exchange")

            # Build form-encoded payload
            payload = {
                'grant_type': GRANT_TYPES['REFRESH_TOKEN'],
                'refresh_token': refresh_token,
                'client_id': client_id,
                'scope': 'taa offline_access'
            }

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': self._config.user_agent
            }

            logger.debug(f"Token exchange request to: {token_endpoint}")
            logger.debug(f"Client ID: {client_id}")

            # Perform token exchange
            response = self.http_manager.post(
                token_endpoint,
                operation='token_exchange',
                headers=headers,
                data=payload,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()

            exchange_data = response.json()

            # Extract token data from response
            taa_token_data = {
                'access_token': exchange_data.get('access_token'),
                'refresh_token': exchange_data.get('refresh_token', ''),
                'token_type': exchange_data.get('token_type', 'Bearer'),
                'expires_in': exchange_data.get('expires_in', 3600),
                'issued_at': time.time()
            }

            # Validate required fields
            if not taa_token_data['access_token']:
                raise Exception("No access token in token exchange response")

            logger.info(
                f"✓ Token exchange successful: "
                f"type={taa_token_data['token_type']}, "
                f"expires_in={taa_token_data['expires_in']}"
            )

            return taa_token_data

        except Exception as e:
            logger.error(f"Token exchange for TAA scope failed: {e}")
            return None

    def _perform_line_auth_with_response(self) -> Optional[Dict[str, Any]]:
        """
        Perform line authentication and store refresh token for SAM3 requests
        """
        try:
            if not self._sam3_client:
                raise Exception("SAM3 client not initialized")

            # Perform line auth
            line_success = self._sam3_client.line_auth(self._device_token)
            if not line_success:
                return None

            # Get the response data
            response_data = self._sam3_client.get_last_line_auth_response()

            # CRITICAL: Store refresh token for SAM3 token requests
            if response_data and 'refresh_token' in response_data:
                self._line_auth_refresh_token = response_data['refresh_token']
                logger.info(f"✓ Stored refresh token from line auth for SAM3 requests")
                logger.debug(f"Refresh token preview: {self._line_auth_refresh_token[:20]}...")

            return response_data

        except Exception as e:
            logger.error(f"Line authentication failed: {e}")
            return None

    @staticmethod
    def _are_line_auth_tokens_sufficient(line_response_data: Dict[str, Any]) -> bool:
        """
        Check if line auth tokens provide enough access for our needs
        """
        if not line_response_data:
            return False

        # Check if we have a valid access token
        access_token = line_response_data.get('access_token')
        if not access_token:
            return False

        # Check if token has reasonable expiration
        expires_in = line_response_data.get('expires_in', 0)
        if expires_in < 300:  # Less than 5 minutes
            logger.warning("Line auth token expires too soon, continuing to TAA")
            return False

        # Optional: Check token type
        token_type = line_response_data.get('token_type', '').lower()
        if token_type != 'bearer':
            logger.warning(f"Line auth token type '{token_type}' not supported, continuing to TAA")
            return False

        return True

    def _create_token_from_line_auth_response(self, line_response_data: Dict[str, Any]) -> BaseAuthToken:
        """
        Create authentication token from actual line auth response data
        """
        # Use ACTUAL values from the response, not hardcoded ones
        token_data = {
            'access_token': line_response_data.get('access_token'),
            'refresh_token': line_response_data.get('refresh_token', ''),
            'token_type': line_response_data.get('token_type', 'Bearer'),  # FROM RESPONSE
            'expires_in': line_response_data.get('expires_in', 7200),  # FROM RESPONSE
            'issued_at': time.time(),
            'auth_source': 'line_auth'  # NEW: Mark as line_auth to skip classification
        }

        # Validate required fields
        if not token_data['access_token']:
            raise Exception("No access token in line auth response")

        logger.info(
            f"✓ Created token from line auth: type={token_data['token_type']}, expires_in={token_data['expires_in']}")

        # NEW: This will automatically save the access token under 'tvhubs' scope
        # and skip classification due to auth_source='line_auth'
        return self._create_token_from_response(token_data)

    def _continue_to_taa_after_line_auth(self) -> BaseAuthToken:
        """
        Continue with TAA flow when line auth tokens are insufficient
        """
        logger.debug("Continuing to TAA authentication after line auth")

        # Step 1: Get SAM3 token for TAA using established line auth session
        if not self._sam3_client:
            raise Exception("SAM3 client not initialized")

        sam3_token = self._sam3_client.get_access_token("taa")
        if not sam3_token:
            raise Exception("Could not obtain SAM3 token after line auth")

        # Step 2: Perform TAA authentication
        if not self._taa_client:
            raise Exception("TAA client not initialized")

        taa_result = self._taa_client.authenticate(
            sam3_token=sam3_token,
            device_id=self._device_id,
            client_model=self._client_model,
            device_model=None,
            taa_endpoint=self._get_endpoint('taa_auth', 'TAA_AUTH')
        )

        if taa_result.device_limit_exceeded:
            from .models import DeviceLimitExceededException
            raise DeviceLimitExceededException("Device limit exceeded for Magenta2")

        # Step 3: Create final token from TAA
        token = self._create_token_from_taa_result(taa_result)
        logger.info("✓ TAA authentication completed successfully after line auth")
        return token

    def _get_user_credentials(self) -> tuple[str, str]:
        """
        Safely get username and password from credentials
        Raises exception if user credentials are not available
        """
        if not isinstance(self.credentials, Magenta2UserCredentials):
            raise Exception("User credentials not available")

        if not self.credentials.has_user_credentials():
            raise Exception("Username/password not provided")

        return self.credentials.username, self.credentials.password

    def _perform_user_authentication_flow(self) -> BaseAuthToken:
        """
        COMPLETE USER FLOW: SAM3 → SSO → TAA
        """
        try:
            logger.debug("Starting complete Magenta2 user authentication flow")

            # Step 1: SAM3 login with username/password
            if not self._sam3_client:
                raise Exception("SAM3 client not initialized")

            # FIXED: Use safe credential access
            username, password = self._get_user_credentials()

            sam3_result = self._sam3_client.sam3_login(username, password)

            # Step 2: SSO authentication with code/state
            if not self._sso_client:
                raise Exception("SSO client not initialized")

            sso_result = self._sso_client.sso_authenticate(
                code=sam3_result['code'],
                state=sam3_result['state']
            )

            # Step 3: Get SAM3 access token for TAA scope
            sam3_taa_token = self._get_sam3_token_for_taa()

            # Step 4: Perform TAA authentication with SAM3 token
            taa_result = self._perform_taa_authentication(sam3_taa_token)

            # Step 5: Create final token with combined data
            token = self._create_token_from_combined_data(sso_result, taa_result)

            logger.info("✓ Complete user authentication flow successful")
            return token

        except Exception as e:
            logger.error(f"User authentication flow failed: {e}")
            # Fall back to TAA-only flow if user auth fails
            logger.warning("Falling back to TAA-only authentication")
            return self._perform_taa_flow()

    def _perform_taa_flow(self) -> BaseAuthToken:
        """
        Perform TAA authentication flow using dedicated TaaClient
        """
        try:
            logger.debug("Starting Magenta2 TAA authentication flow")

            # Step 1: Get SAM3 access token for TAA
            sam3_token = self._get_sam3_token()
            if not sam3_token:
                raise Exception("Could not obtain SAM3 token for TAA")

            # Step 2: Perform TAA authentication using TaaClient
            if not self._taa_client:
                raise Exception("TAA client not initialized")

            taa_result = self._taa_client.authenticate(
                sam3_token=sam3_token,
                device_id=self._device_id,
                client_model=self._client_model,
                device_model=None,
                taa_endpoint=self._get_endpoint('taa_auth', 'TAA_AUTH')
            )

            # Check for device limit
            if taa_result.device_limit_exceeded:
                from .models import DeviceLimitExceededException
                raise DeviceLimitExceededException("Device limit exceeded for Magenta2")

            # Step 3: Convert TaaAuthResult to BaseAuthToken
            token = self._create_token_from_taa_result(taa_result)
            return token

        except Exception as e:
            logger.error(f"TAA authentication flow failed: {e}")
            raise Exception(f"TAA authentication failed: {e}")

    def _create_token_from_taa_result(self, taa_result: TaaAuthResult) -> BaseAuthToken:
        """
        Create authentication token from TaaAuthResult
        """
        token_data = {
            'access_token': taa_result.access_token,
            'refresh_token': taa_result.refresh_token or "",
            'token_type': 'Bearer',
            'expires_in': 3600,  # Default, will be overridden by JWT exp if available
            'issued_at': time.time(),

            # TAA-specific fields
            'dc_cts_persona_token': taa_result.dc_cts_persona_token,
            'persona_id': taa_result.persona_id,
            'account_id': taa_result.account_id,
            'consumer_id': taa_result.consumer_id,
            'tv_account_id': taa_result.tv_account_id,
            'account_token': taa_result.account_token,
            'account_uri': taa_result.account_uri,
            'token_exp': taa_result.token_exp
        }

        # Add raw response if available
        if taa_result.raw_response:
            token_data['raw_response'] = taa_result.raw_response

        return self._create_token_from_response(token_data)

    def _perform_line_auth(self) -> bool:
        """
        PHASE 4: Device token line authentication
        Matching C++ Sam3Client::LineAuth()
        """
        try:
            if not self._device_token or not self._authorize_tokens_url:
                logger.warning("Line auth skipped - missing device token or authorize URL")
                return False

            if not self._sam3_client:
                logger.warning("Line auth skipped - SAM3 client not available")
                return False

            logger.debug("Performing line authentication with device token")

            # Use SAM3 client for line authentication
            success = self._sam3_client.line_auth(self._device_token)

            if success:
                logger.info("✓ Line authentication successful")
                return True
            else:
                logger.warning("Line authentication failed")
                return False

        except Exception as e:
            logger.error(f"Line authentication failed: {e}")
            return False

    def _get_sam3_token_for_taa(self) -> str:
        """
        ENHANCED: Get SAM3 token specifically for TAA scope in user flow
        Uses device token line authentication if available
        """
        try:
            # PHASE 4: Try line authentication first if device token is available
            if self._device_token and self._perform_line_auth():
                logger.debug("Line authentication successful, getting TAA token")
                # Now get token for TAA scope using the established session
                if self._sam3_client:
                    taa_token = self._sam3_client.get_access_token("taa")
                    if taa_token:
                        return taa_token

            # Fall back to standard client credentials
            return self._get_sam3_token()

        except Exception as e:
            logger.warning(f"Enhanced SAM3 token acquisition failed: {e}")
            return self._get_sam3_token()

    def _get_sam3_token(self) -> str:
        """
        Get SAM3 access token using discovered endpoints
        """
        try:
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': self._config.user_agent
            }

            # Determine payload based on available tokens
            if hasattr(self, '_line_auth_refresh_token') and self._line_auth_refresh_token:
                payload = {
                    'grant_type': 'refresh_token',
                    'client_id': self._sam3_client_id,
                    'refresh_token': self._line_auth_refresh_token,
                    'scope': 'taa offline_access'
                }
            else:
                payload = {
                    'grant_type': 'client_credentials',
                    'client_id': self._sam3_client_id,
                    'scope': 'taa offline_access'
                }

            # Use the existing endpoint discovery system
            token_endpoint = self._get_endpoint('oauth_token', 'OPENID_CONFIG')

            # If we got the OpenID config URL, convert it to token endpoint
            if token_endpoint.endswith('/.well-known/openid-configuration'):
                token_endpoint = token_endpoint.replace('/.well-known/openid-configuration', '/oauth2/tokens')
                logger.debug(f"Converted OpenID config URL to token endpoint: {token_endpoint}")

            logger.debug(f"SAM3 token request to: {token_endpoint}")

            # Form-encode the data
            form_data = '&'.join([f"{k}={self._url_encode(str(v))}" for k, v in payload.items()])

            response = self.http_manager.post(
                token_endpoint,
                operation='auth',
                headers=headers,
                data=form_data
            )

            if response.status_code >= 400:
                logger.error(f"SAM3 token request failed: {response.status_code}")
                logger.error(f"Response: {response.text}")
                response.raise_for_status()

            token_data = response.json()
            access_token = token_data.get('access_token')

            if not access_token:
                raise ValueError("No access token in SAM3 response")

            logger.debug("SAM3 token obtained successfully")
            return access_token

        except Exception as e:
            logger.error(f"Failed to get SAM3 token: {e}")
            raise Exception(f"SAM3 token request failed: {e}")

    @staticmethod
    def _url_encode(value: str) -> str:
        """URL encode a string"""
        from urllib.parse import quote
        return quote(value)

    def _perform_taa_authentication(self, sam3_token: str) -> Dict[str, Any]:
        """
        LEGACY: Kept for backward compatibility, now uses TaaClient internally
        """
        try:
            if not self._taa_client:
                raise Exception("TAA client not initialized")

            taa_result = self._taa_client.authenticate(
                sam3_token=sam3_token,
                device_id=self._device_id,
                client_model=self._client_model,
                device_model=None,
                taa_endpoint=self.auth_endpoint
            )

            if taa_result.device_limit_exceeded:
                from .models import DeviceLimitExceededException
                raise DeviceLimitExceededException("Device limit exceeded for Magenta2")

            # Convert to legacy format
            result = {
                'access_token': taa_result.access_token,
                'refresh_token': taa_result.refresh_token,
                'dc_cts_persona_token': taa_result.dc_cts_persona_token,
                'persona_id': taa_result.persona_id,
                'account_id': taa_result.account_id,
                'consumer_id': taa_result.consumer_id,
                'tv_account_id': taa_result.tv_account_id,
                'account_token': taa_result.account_token,
                'account_uri': taa_result.account_uri,
                'token_exp': taa_result.token_exp
            }

            if taa_result.raw_response:
                result.update(taa_result.raw_response)

            return result

        except Exception as e:
            logger.error(f"TAA authentication failed: {e}")
            raise

    def _parse_taa_jwt_complete(self, jwt_token: str) -> Dict[str, Any]:
        """
        ENHANCED: Complete JWT parsing extracting ALL required fields
        This is critical for persona token composition
        """
        try:
            parts = jwt_token.split('.')
            if len(parts) != 3:
                logger.warning("Invalid JWT format")
                return {}

            # Decode payload
            payload_b64 = parts[1]
            padding = len(payload_b64) % 4
            if padding:
                payload_b64 += '=' * (4 - padding)

            payload_json = base64.b64decode(payload_b64).decode('utf-8')
            claims = json.loads(payload_json)

            logger.debug(f"JWT claims found: {list(claims.keys())}")

            result = {}

            # Enhanced claim mappings - ALL fields from C++ implementation
            claim_mappings = {
                # Core persona token (most important!)
                'dc_cts_persona_token': [
                    'dc_cts_persona_token',
                    'personaToken',
                    'urn:telekom:ott:dc_cts_persona_token'
                ],

                # Account URI (needed for composition!)
                'account_uri': [
                    'dc_cts_account_uri',
                    'accountUri',
                    'urn:telekom:ott:dc_cts_account_uri',
                    'mpxAccountUri'
                ],

                # IDs
                'persona_id': [
                    'dc_cts_personaId',
                    'personaId',
                    'urn:telekom:ott:dc_cts_personaId'
                ],
                'account_id': [
                    'dc_cts_accountId',
                    'accountId',
                    'urn:telekom:ott:dc_cts_accountId'
                ],
                'consumer_id': [
                    'dc_cts_consumerId',
                    'consumerId',
                    'urn:telekom:ott:dc_cts_consumerId'
                ],
                'tv_account_id': [
                    'dc_tvAccountId',
                    'tvAccountId',
                    'urn:telekom:ott:dc_tvAccountId'
                ],

                # Account token
                'account_token': [
                    'dc_cts_account_token',
                    'accountToken',
                    'urn:telekom:ott:dc_cts_account_token'
                ],
            }

            # Extract all claims
            for target_key, source_keys in claim_mappings.items():
                for source_key in source_keys:
                    if source_key in claims:
                        result[target_key] = claims[source_key]
                        logger.debug(f"Extracted {target_key} from {source_key}")
                        break

            # Extract token expiration
            if 'exp' in claims:
                result['token_exp'] = claims['exp']
                logger.debug(f"Token expires at: {claims['exp']}")

            # CRITICAL CHECK: Verify we have the essential fields
            if 'dc_cts_persona_token' not in result:
                logger.error("CRITICAL: dc_cts_persona_token not found in JWT!")
                logger.debug(f"Available claims: {list(claims.keys())}")

            if 'account_uri' not in result:
                logger.warning("account_uri not found in JWT - will try to construct from MPX account PID")

                # Try to construct from MPX account PID if available
                if self._mpx_account_pid:
                    result['account_uri'] = f"urn:theplatform:auth:root:{self._mpx_account_pid}"
                    logger.info(f"✓ Constructed account_uri from MPX PID: {result['account_uri']}")
                elif 'mpxAccountPid' in claims:
                    result['account_uri'] = f"urn:theplatform:auth:root:{claims['mpxAccountPid']}"
                    logger.info(f"✓ Constructed account_uri from JWT mpxAccountPid: {result['account_uri']}")

            return result

        except Exception as e:
            logger.error(f"Failed to parse TAA JWT completely: {e}")
            return {}

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        """
        Classify Magenta2 token based on JWT claims and structure
        """
        try:
            if not token or not token.access_token:
                return TokenAuthLevel.UNKNOWN

            claims = token.get_jwt_claims() if hasattr(token, 'get_jwt_claims') else None
            if not claims:
                # If we can't parse claims, check token attributes
                if hasattr(token, 'dc_cts_persona_token') and token.dc_cts_persona_token:
                    logger.debug("Token classified as USER_AUTHENTICATED (persona token present)")
                    return TokenAuthLevel.USER_AUTHENTICATED
                logger.debug("Token classified as CLIENT_CREDENTIALS (no claims, no persona token)")
                return TokenAuthLevel.CLIENT_CREDENTIALS

            logger.debug(f"JWT claims for classification: {list(claims.keys())}")

            # Check for persona token presence - indicates user authentication
            if hasattr(token, 'dc_cts_persona_token') and token.dc_cts_persona_token:
                logger.debug("Token classified as USER_AUTHENTICATED (dc_cts_persona_token present)")
                return TokenAuthLevel.USER_AUTHENTICATED

            # Check JWT claims for user identifiers
            user_claim_keys = ['dc_cts_personaId', 'personaId', 'dc_cts_accountId', 'accountId',
                               'dc_cts_consumerId', 'consumerId', 'dc_tvAccountId', 'tvAccountId']

            for key in user_claim_keys:
                if key in claims:
                    logger.debug(f"Token classified as USER_AUTHENTICATED (found {key} in JWT)")
                    return TokenAuthLevel.USER_AUTHENTICATED

            # Check for client credentials patterns
            client_id = claims.get('client_id', claims.get('clientId', ''))
            if client_id in MAGENTA2_CLIENT_IDS.values():
                logger.debug("Token classified as CLIENT_CREDENTIALS (known client ID)")
                return TokenAuthLevel.CLIENT_CREDENTIALS

            # Default to client credentials for TAA flow
            logger.debug("Token classified as CLIENT_CREDENTIALS (default for TAA)")
            return TokenAuthLevel.CLIENT_CREDENTIALS

        except Exception as e:
            logger.error(f"Error classifying token: {e}")
            return TokenAuthLevel.UNKNOWN

    def _refresh_oauth_token(self) -> Optional[BaseAuthToken]:
        """Magenta2 token refresh implementation using HTTP manager"""
        if not self._current_token or not self._current_token.refresh_token:
            logger.debug(f"No refresh token available for {self.provider_name}")
            return None

        try:
            logger.debug(f"Refreshing OAuth2 token for {self.provider_name}")

            headers = self._config.get_oauth_headers()

            payload = {
                'grant_type': GRANT_TYPES['REFRESH_TOKEN'],
                'refresh_token': self._current_token.refresh_token,
                'client_id': self.oauth_client_id
            }

            # Use discovered token endpoint for refresh
            token_endpoint = self._get_endpoint('oauth_token', 'OPENID_CONFIG')
            if token_endpoint.endswith('/.well-known/openid-configuration'):
                token_endpoint = token_endpoint.replace('/.well-known/openid-configuration', '/oauth2/tokens')

            # USE HTTP MANAGER for token refresh
            response = self.http_manager.post(
                token_endpoint,
                operation='auth',
                headers=headers,
                data=payload
            )

            response.raise_for_status()
            new_token_data = response.json()
            refreshed_token = self._create_token_from_response(new_token_data)
            logger.info(f"OAuth2 token refresh successful for {self.provider_name}")
            return refreshed_token

        except Exception as e:
            logger.warning(f"OAuth2 token refresh failed for {self.provider_name}: {e}")
            return None

    def get_persona_token(self) -> Optional[str]:
        """
        Get the composed persona token for API calls
        Returns the Base64-encoded persona token or None
        """
        if not self._current_token:
            return None

        if isinstance(self._current_token, Magenta2AuthToken):
            # Return the composed token if available
            if self._current_token.composed_persona_token:
                return self._current_token.composed_persona_token

            # Try to compose it now if we have the components
            if self._current_token.dc_cts_persona_token and self._current_token.account_uri:
                return self._current_token.compose_persona_token()

        return None

    # Backward compatibility
    def is_authenticated(self) -> bool:
        return self._current_token is not None and not self._current_token.is_expired

    def invalidate_token(self) -> None:
        self._current_token = None
        try:
            self.settings_manager.clear_token(self.provider_name)
        except Exception:
            pass

    def debug_token_classification(self) -> Dict[str, Any]:
        """Debug method to analyze current token classification"""
        if not self._current_token:
            return {'error': 'No current token'}

        claims = self._current_token.get_jwt_claims() if hasattr(self._current_token, 'get_jwt_claims') else {}

        return {
            'token_type': type(self._current_token).__name__,
            'auth_level': self._current_token.auth_level.value,
            'is_expired': self._current_token.is_expired,
            'has_refresh': bool(self._current_token.refresh_token),
            'has_persona_token': bool(getattr(self._current_token, 'dc_cts_persona_token', None)),
            'jwt_claims_available': bool(claims),
            'key_claims': {
                'client_id': claims.get('client_id', claims.get('clientId', 'MISSING')),
                'persona_id': claims.get('dc_cts_personaId', claims.get('personaId', 'MISSING')),
                'account_id': claims.get('dc_cts_accountId', claims.get('accountId', 'MISSING')),
            } if claims else {},
            'discovered_endpoints': list(self._dynamic_endpoints.keys()),
            'bootstrap_parameters': {
                'client_model': self._client_model,
                'device_model': self._device_model,
                'sam3_client_id': self._sam3_client_id
            },
            'clients_initialized': {
                'sam3': self._sam3_client is not None,
                'sso': self._sso_client is not None
            }
        }

    # Required abstract method from BaseOAuth2Authenticator
    def _perform_oauth_authorization_code_flow(self, username: str, password: str) -> Dict[str, Any]:
        """
        OAuth2 authorization code flow - now implemented via SAM3 + SSO
        """
        try:
            # Use our complete user authentication flow
            token = self._perform_user_authentication_flow()
            return token.to_dict()
        except Exception as e:
            logger.error(f"OAuth2 authorization code flow failed: {e}")
            raise

    def get_authentication_capabilities(self) -> Dict[str, Any]:
        """
        Public method to check authentication capabilities
        """
        line_auth_available = self.can_use_line_auth()
        remote_login_available = self.can_use_remote_login()  # NEW

        return {
            'line_auth_available': line_auth_available,
            'remote_login_available': remote_login_available,  # NEW
            'user_credentials_available': isinstance(self.credentials,
                                                     Magenta2UserCredentials) and self.credentials.has_user_credentials(),
            'client_credentials_available': True,
            'preferred_flow': 'LINE_AUTH' if line_auth_available else
            'REMOTE_LOGIN' if remote_login_available else  # NEW
            'USER' if (isinstance(self.credentials,
                                  Magenta2UserCredentials) and self.credentials.has_user_credentials()) else
            'CLIENT'
        }

    def debug_authentication_state(self) -> Dict[str, Any]:
        """
        Enhanced debug method to verify complete authentication state
        """
        if not self._current_token:
            return {'error': 'No current token'}

        token = self._current_token

        return {
            'has_access_token': bool(token.access_token),
            'has_dc_cts_persona_token': bool(getattr(token, 'dc_cts_persona_token', None)),
            'has_account_uri': bool(getattr(token, 'account_uri', None)),
            'has_composed_persona_token': bool(getattr(token, 'composed_persona_token', None)),
            'persona_token_preview': getattr(token, 'composed_persona_token', '')[:50] + '...' if getattr(token, 'composed_persona_token', None) else None,
            'account_uri': getattr(token, 'account_uri', None),
            'persona_id': getattr(token, 'persona_id', None),
            'account_id': getattr(token, 'account_id', None),
            'sso_user_id': getattr(token, 'sso_user_id', None),
            'sso_display_name': getattr(token, 'sso_display_name', None),
            'token_expires_at': getattr(token, 'token_exp', None),
            'is_expired': token.is_expired,
            'auth_level': token.auth_level.value,
            'flow_used': 'USER' if getattr(token, 'sso_user_id', None) else 'CLIENT'
        }
