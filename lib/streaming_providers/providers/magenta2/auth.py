# streaming_providers/providers/magenta2/auth.py
# -*- coding: utf-8 -*-
"""
Magenta2 Authenticator - Migrated to BaseAuthenticator

This authenticator manages Magenta2's proprietary token hierarchy:
yo_digital → taa → tvhubs → line_auth/remote_login

Key components:
- TokenFlowManager: Handles hierarchical token acquisition and refresh
- SAM3Client: OAuth2 token management (tvhubs/taa scopes)
- TaaClient: TAA authentication and yo_digital token exchange
- SsoClient: SSO operations (user authentication)
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ...base.auth.base_auth import (BaseAuthenticator, BaseAuthToken,
                                    TokenAuthLevel)
from ...base.auth.credentials import ClientCredentials
from ...base.utils.logger import logger
from .constants import (APPVERSION2, DEFAULT_COUNTRY, DEFAULT_PLATFORM, IDM,
                        MAGENTA2_CLIENT_IDS, MAGENTA2_PLATFORMS,
                        SSO_USER_AGENT, SUPPORTED_COUNTRIES,
                        TAA_REQUEST_TEMPLATE)
# Import Magenta2-specific components
from .sam3_client import Sam3Client
from .sso_client import SsoClient
from .taa_client import TaaClient
from .token_flow_manager import TokenFlowManager
from .token_utils import JWTParser, PersonaTokenComposer


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
        if not hasattr(self, "client_secret") or self.client_secret is None:
            self.client_secret = ""  # Empty string for public client

        # Set client_id from constant if not provided
        if not self.client_id:
            self.client_id = MAGENTA2_CLIENT_IDS.get(
                self.platform, MAGENTA2_CLIENT_IDS[DEFAULT_PLATFORM]
            )

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

    def to_taa_payload(
        self,
        access_token: str,
        client_model: Optional[str] = None,
        device_model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Convert to TAA authentication payload"""
        platform_config = MAGENTA2_PLATFORMS.get(
            self.platform, MAGENTA2_PLATFORMS[DEFAULT_PLATFORM]
        )

        # Use provided models or fallback to platform defaults
        resolved_device_model = device_model or platform_config["device_name"]
        resolved_client_model = client_model or f"ftv-{self.platform}"

        # Build keyValue string with client model if available
        key_value_parts = [IDM, APPVERSION2]

        # Add client model if available
        if resolved_client_model:
            key_value_parts.append(f"ClientModelParams(id={resolved_client_model})")

        key_value_parts.extend(
            [
                f"TokenChannelParams(id=Tv)",
                f"TokenDeviceParams(id={self.device_id}, model={resolved_device_model}, os={platform_config['firmware']})",
                "DE",
                "telekom",
            ]
        )

        key_value = "/".join(key_value_parts)

        # Start with template and populate fields
        payload = TAA_REQUEST_TEMPLATE.copy()
        payload.update(
            {
                "keyValue": key_value,
                "accessToken": access_token,
                "device": {
                    "id": self.device_id,
                    "model": resolved_device_model,
                    "os": platform_config["firmware"],
                },
            }
        )

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
        return (
            self.has_user_credentials()
            and len(self.username) > 0
            and len(self.password) > 0
        )

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
            "access_token": self.access_token,
            "refresh_token": self.refresh_token or "",
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "issued_at": self.issued_at,
        }

        # Add Magenta2-specific fields
        if self.dc_cts_persona_token:
            base_dict["dc_cts_persona_token"] = self.dc_cts_persona_token
        if self.persona_id:
            base_dict["persona_id"] = self.persona_id
        if self.account_id:
            base_dict["account_id"] = self.account_id
        if self.consumer_id:
            base_dict["consumer_id"] = self.consumer_id
        if self.tv_account_id:
            base_dict["tv_account_id"] = self.tv_account_id
        if self.account_token:
            base_dict["account_token"] = self.account_token
        if self.account_uri:
            base_dict["account_uri"] = self.account_uri
        if self.composed_persona_token:
            base_dict["composed_persona_token"] = self.composed_persona_token
        if self.token_exp:
            base_dict["token_exp"] = self.token_exp
        if self.sso_user_id:
            base_dict["sso_user_id"] = self.sso_user_id
        if self.sso_display_name:
            base_dict["sso_display_name"] = self.sso_display_name

        return base_dict

    def compose_persona_token(self) -> Optional[str]:
        """Compose persona token from components"""
        self.composed_persona_token = PersonaTokenComposer.compose_from_components(
            account_uri=self.account_uri, dc_cts_persona_token=self.dc_cts_persona_token
        )
        return self.composed_persona_token

    def get_jwt_claims(self) -> Optional[Dict[str, Any]]:
        """Extract JWT claims from access token"""
        claims = JWTParser.parse(self.access_token)
        return claims.raw_claims if claims else None


class Magenta2AuthConfig:
    """Configuration object for Magenta2 authentication"""

    def __init__(
        self,
        country: str,
        platform: str = DEFAULT_PLATFORM,
        endpoints: Optional[Dict[str, str]] = None,
        client_model: Optional[str] = None,
        device_model: Optional[str] = None,
    ):
        self.country = country
        self.platform = platform
        self.platform_config = MAGENTA2_PLATFORMS.get(
            platform, MAGENTA2_PLATFORMS[DEFAULT_PLATFORM]
        )
        self.user_agent = self.platform_config["user_agent"]
        self.timeout = 30
        self.endpoints = endpoints or {}
        self.client_model = client_model
        self.device_model = device_model

    def get_base_headers(self) -> Dict[str, str]:
        """Get base headers for all requests"""
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def get_oauth_headers(self) -> Dict[str, str]:
        """Get headers for OAuth2 requests (use form encoding)"""
        headers = self.get_base_headers()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        return headers

    @staticmethod
    def get_sso_headers(
        session_id: str = None, device_id: str = None
    ) -> Dict[str, str]:
        """Get headers for SSO requests"""
        headers = {
            "User-Agent": SSO_USER_AGENT,
            "Content-Type": "application/json",
            "origin": "https://web2.magentatv.de",
            "referer": "https://web2.magentatv.de/",
        }

        if session_id:
            headers["session-id"] = session_id
        if device_id:
            headers["device-id"] = device_id

        return headers

    def get_taa_headers(self, sam3_token: str) -> Dict[str, str]:
        """Get headers for TAA requests"""
        headers = self.get_base_headers()
        headers["Authorization"] = f"Bearer {sam3_token}"
        return headers


class Magenta2Authenticator(BaseAuthenticator):
    """
    Magenta2 authenticator with complete SAM3 + SSO + TAA flow

    Token Hierarchy:
    1. yo_digital tokens (persona token base) - managed by TokenFlowManager
    2. taa access_token (from SAM3)
    3. tvhubs access_token (from line_auth/remote_login)
    4. Shared refresh_token (at provider level)

    Authentication Flows:
    - Line Authentication: Device token → tvhubs tokens
    - Remote Login: QR code/backchannel → tvhubs tokens
    - Token Exchange: refresh_token → taa → yo_digital
    """

    def __init__(
        self,
        country: str = DEFAULT_COUNTRY,
        platform: str = DEFAULT_PLATFORM,
        settings_manager=None,
        credentials=None,
        config_dir: Optional[str] = None,
        http_manager=None,
        endpoints: Optional[Dict[str, str]] = None,
        client_model: Optional[str] = None,
        device_model: Optional[str] = None,
        sam3_client_id: Optional[str] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        provider_config: Optional[Any] = None,
    ):
        """
        Initialize Magenta2 authenticator

        Args:
            country: Country code (e.g., 'de')
            platform: Platform identifier (e.g., 'firetv')
            settings_manager: Settings manager instance
            credentials: Optional credentials override
            config_dir: Configuration directory
            http_manager: HTTP manager for requests
            endpoints: Dynamically discovered endpoints
            client_model: Client model identifier
            device_model: Device model identifier
            sam3_client_id: SAM3 OAuth client ID
            session_id: Session identifier
            device_id: Device identifier
            provider_config: Provider configuration object
        """
        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(
                f"Unsupported country: {country}. Must be one of: {SUPPORTED_COUNTRIES}"
            )

        if http_manager is None:
            raise ValueError("http_manager is required for Magenta2Authenticator")

        # Set country-specific attributes FIRST
        self.country = country
        self.platform = platform

        # Store http_manager reference
        self._http_manager = http_manager

        # Store dynamically discovered endpoints
        self._dynamic_endpoints = endpoints or {}

        # Store bootstrap parameters
        self._client_model = client_model
        self._device_model = device_model
        self._sam3_client_id = sam3_client_id

        # Session and device management
        self._session_id = session_id or str(uuid.uuid4())
        self._device_id = device_id or str(uuid.uuid4())
        self.provider_config = provider_config

        # MPX account info for persona token composition
        self._mpx_account_pid: Optional[str] = None
        self._device_token: Optional[str] = None
        self._authorize_tokens_url: Optional[str] = None

        # SAM3 and SSO clients
        self._sam3_client: Optional[Sam3Client] = None
        self._sso_client: Optional[SsoClient] = None
        self._openid_config: Optional[Dict[str, Any]] = None

        # Setup Magenta2-specific config
        self._config = Magenta2AuthConfig(
            self.country,
            self.platform,
            self._dynamic_endpoints,
            self._client_model,
            self._device_model,
        )

        # Extract and cache client_id
        self._client_id = self._sam3_client_id or MAGENTA2_CLIENT_IDS.get(
            self.platform, MAGENTA2_CLIENT_IDS[DEFAULT_PLATFORM]
        )

        # Initialize credentials if not provided
        if credentials is None:
            credentials = self.get_fallback_credentials()

        # Initialize SAM3 and SSO clients
        self._initialize_sam3_sso_clients()

        # Initialize TAA client
        self._taa_client: Optional[TaaClient] = None
        self._initialize_taa_client()

        # Initialize parent BaseAuthenticator
        super().__init__(
            provider_name="magenta2",
            settings_manager=settings_manager,
            credentials=credentials,
            country=country,
            config_dir=config_dir,
            enable_kodi_integration=True,
        )

        # Initialize TokenFlowManager
        self.token_flow_manager: Optional[TokenFlowManager] = None
        self._initialize_token_flow_manager()

        logger.info("Magenta2 authenticator initialization completed successfully")

    # ========================================================================
    # BaseAuthenticator Required Methods
    # ========================================================================

    @property
    def auth_endpoint(self) -> str:
        """Primary authentication endpoint - TAA flow"""
        return self._get_endpoint("taa_auth", "TAA_AUTH")

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers for authentication request"""
        return self._config.get_base_headers()

    def _build_auth_payload(self) -> Dict[str, Any]:
        """Build authentication payload - not directly used in Magenta2 flow"""
        # This method is required by BaseAuthenticator but not used in our flow
        # TokenFlowManager handles all token acquisition
        return {}

    def _create_token_from_response(
        self, response_data: Dict[str, Any]
    ) -> BaseAuthToken:
        """
        Create token object from API response and compose persona token
        """
        # Handle different response key formats
        access_token = response_data.get(
            "access_token", response_data.get("accessToken")
        )
        if not access_token:
            raise ValueError("No access token in response")

        # Create token with ALL fields
        token = Magenta2AuthToken(
            access_token=access_token,
            refresh_token=response_data.get(
                "refresh_token", response_data.get("refreshToken", "")
            ),
            token_type=response_data.get(
                "token_type", response_data.get("tokenType", "Bearer")
            ),
            expires_in=response_data.get(
                "expires_in", response_data.get("expiresIn", 3600)
            ),
            issued_at=response_data.get(
                "issued_at", response_data.get("issuedAt", time.time())
            ),
            # Magenta2-specific fields from JWT
            dc_cts_persona_token=response_data.get("dc_cts_persona_token"),
            persona_id=response_data.get("persona_id"),
            account_id=response_data.get("account_id"),
            consumer_id=response_data.get("consumer_id"),
            tv_account_id=response_data.get("tv_account_id"),
            account_token=response_data.get("account_token"),
            account_uri=response_data.get("account_uri"),
            token_exp=response_data.get("token_exp"),
            # SSO fields if available
            sso_user_id=response_data.get("sso_user_id"),
            sso_display_name=response_data.get("sso_display_name"),
        )

        # Compose final persona token
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
                logger.info(
                    f"Attempting to construct account_uri from MPX account PID: {self._mpx_account_pid}"
                )
                token.account_uri = f"urn:theplatform:auth:root:{self._mpx_account_pid}"
                composed = token.compose_persona_token()
                if composed:
                    logger.info(
                        "✓ Persona token composed using constructed account_uri"
                    )

        # Classify token if it's NOT from line_auth
        if not response_data.get("auth_source") == "line_auth":
            token.auth_level = self._classify_token(token)
            logger.debug(f"Token created and classified as: {token.auth_level.value}")
        else:
            token.auth_level = TokenAuthLevel.UNKNOWN
            logger.debug("Line auth token - skipping classification")

        # Save scoped token data
        self._save_scoped_token_data(token)

        return token

    def get_fallback_credentials(self) -> Magenta2Credentials:
        """Get fallback credentials when no user credentials are available"""
        return Magenta2Credentials(
            client_id=self._client_id,
            platform=self.platform,
            country=self.country,
            device_id=self._device_id,
        )

    def _perform_authentication(self) -> BaseAuthToken:
        """
        Main authentication entry point
        Delegates to TokenFlowManager for the actual token acquisition
        """
        if not self.token_flow_manager:
            raise Exception("TokenFlowManager not initialized")

        logger.info("Performing Magenta2 authentication via TokenFlowManager")

        # Get persona token through the complete hierarchical flow
        persona_result = self.token_flow_manager.get_persona_token(force_refresh=False)

        if not persona_result.success:
            raise Exception(f"Authentication failed: {persona_result.error}")

        # Create a simplified token wrapper
        # The actual tokens are managed by TokenFlowManager in scoped storage
        token = Magenta2AuthToken(
            access_token=persona_result.persona_token,
            token_type="Basic",
            expires_in=3600,  # Default expiry
            issued_at=time.time(),
            auth_level=TokenAuthLevel.USER_AUTHENTICATED,
        )

        logger.info("✓ Magenta2 authentication successful")
        return token

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        """
        Classify Magenta2 token based on JWT claims and structure
        """
        try:
            if not token or not token.access_token:
                return TokenAuthLevel.UNKNOWN

            claims = (
                token.get_jwt_claims() if hasattr(token, "get_jwt_claims") else None
            )
            if not claims:
                # If we can't parse claims, check token attributes
                if (
                    hasattr(token, "dc_cts_persona_token")
                    and token.dc_cts_persona_token
                ):
                    logger.debug(
                        "Token classified as USER_AUTHENTICATED (persona token present)"
                    )
                    return TokenAuthLevel.USER_AUTHENTICATED
                logger.debug(
                    "Token classified as CLIENT_CREDENTIALS (no claims, no persona token)"
                )
                return TokenAuthLevel.CLIENT_CREDENTIALS

            logger.debug(f"JWT claims for classification: {list(claims.keys())}")

            # Check for persona token presence - indicates user authentication
            if hasattr(token, "dc_cts_persona_token") and token.dc_cts_persona_token:
                logger.debug(
                    "Token classified as USER_AUTHENTICATED (dc_cts_persona_token present)"
                )
                return TokenAuthLevel.USER_AUTHENTICATED

            # Check JWT claims for user identifiers
            user_claim_keys = [
                "dc_cts_personaId",
                "personaId",
                "dc_cts_accountId",
                "accountId",
                "dc_cts_consumerId",
                "consumerId",
                "dc_tvAccountId",
                "tvAccountId",
            ]

            for key in user_claim_keys:
                if key in claims:
                    logger.debug(
                        f"Token classified as USER_AUTHENTICATED (found {key} in JWT)"
                    )
                    return TokenAuthLevel.USER_AUTHENTICATED

            # Check for client credentials patterns
            client_id = claims.get("client_id", claims.get("clientId", ""))
            if client_id in MAGENTA2_CLIENT_IDS.values():
                logger.debug("Token classified as CLIENT_CREDENTIALS (known client ID)")
                return TokenAuthLevel.CLIENT_CREDENTIALS

            # Default to client credentials for TAA flow
            logger.debug("Token classified as CLIENT_CREDENTIALS (default for TAA)")
            return TokenAuthLevel.CLIENT_CREDENTIALS

        except Exception as e:
            logger.error(f"Error classifying token: {e}")
            return TokenAuthLevel.UNKNOWN

    def _refresh_token(self) -> Optional[BaseAuthToken]:
        """
        Refresh token implementation
        Delegates to TokenFlowManager for hierarchical token refresh
        """
        if not self.token_flow_manager:
            logger.warning("TokenFlowManager not initialized, cannot refresh token")
            return None

        try:
            logger.info("Refreshing Magenta2 token via TokenFlowManager")

            # Force refresh through TokenFlowManager
            persona_result = self.token_flow_manager.get_persona_token(
                force_refresh=True
            )

            if persona_result.success:
                token = Magenta2AuthToken(
                    access_token=persona_result.persona_token,
                    token_type="Basic",
                    expires_in=3600,
                    issued_at=time.time(),
                    auth_level=TokenAuthLevel.USER_AUTHENTICATED,
                )
                logger.info("✓ Token refresh successful")
                return token

            logger.warning(f"Token refresh failed: {persona_result.error}")
            return None

        except Exception as e:
            logger.warning(f"Token refresh failed: {e}")
            return None

    # ========================================================================
    # Component Initialization
    # ========================================================================

    def _initialize_sam3_sso_clients(self) -> None:
        """Initialize SAM3 and SSO clients with all endpoints"""
        try:
            # Initialize SSO client (always available)
            self._sso_client = SsoClient(
                http_manager=self._http_manager,
                session_id=self._session_id,
                device_id=self._device_id,
            )

            # Initialize SAM3 client if we have client ID
            if self._sam3_client_id:
                issuer_url = None
                oauth_endpoint = None
                line_auth_endpoint = self._authorize_tokens_url
                backchannel_start_url = None
                qr_code_url_template = None

                # Get QR code URL from dynamic endpoints
                if "login_qr_code" in self._dynamic_endpoints:
                    qr_code_url_template = self._dynamic_endpoints["login_qr_code"]
                    logger.debug(
                        f"QR code URL from dynamic endpoints: {qr_code_url_template}"
                    )

                if self._openid_config:
                    issuer_url = self._openid_config.get("issuer")
                    oauth_endpoint = self._openid_config.get("token_endpoint")
                    backchannel_start_url = self._openid_config.get(
                        "backchannel_auth_start"
                    )

                self._sam3_client = Sam3Client(
                    http_manager=self._http_manager,
                    session_id=self._session_id,
                    device_id=self._device_id,
                    sam3_client_id=self._sam3_client_id,
                    issuer_url=issuer_url,
                    oauth_token_endpoint=oauth_endpoint,
                    line_auth_endpoint=line_auth_endpoint,
                    backchannel_start_url=backchannel_start_url,
                    qr_code_url_template=qr_code_url_template,
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

    def _initialize_taa_client(self) -> None:
        """Initialize TAA client"""
        self._taa_client = TaaClient(
            http_manager=self._http_manager, platform=self.platform
        )
        logger.debug("TAA client initialized")

    def _initialize_token_flow_manager(self) -> None:
        """Initialize token flow manager after SAM3 and TAA clients are ready"""
        if self._sam3_client and self._taa_client:
            session_manager = getattr(self.settings_manager, "session_manager", None)
            if not session_manager:
                logger.error(
                    "Cannot initialize TokenFlowManager: No session_manager available"
                )
                return

            self.token_flow_manager = TokenFlowManager(
                session_manager=session_manager,
                sam3_client=self._sam3_client,
                taa_client=self._taa_client,
                provider_name=self.provider_name,
                country=self.country,
                provider_config=self.provider_config,
                line_auth_callback=self._perform_line_auth_with_response,
                remote_login_callback=self._perform_remote_login_flow,
            )
            logger.debug("TokenFlowManager initialized with auth callbacks")

    # ========================================================================
    # Public API - Token Management
    # ========================================================================

    def get_persona_token(self, force_refresh: bool = False) -> str:
        """
        Get persona token - PRIMARY authentication entry point

        This is the main method that should be called by the provider
        to get a valid persona token for API requests.

        Args:
            force_refresh: Force token refresh even if cached token is valid

        Returns:
            Base64-encoded persona token

        Raises:
            Exception: If persona token cannot be obtained
        """
        if not self.token_flow_manager:
            raise Exception("TokenFlowManager not initialized")

        persona_result = self.token_flow_manager.get_persona_token(
            force_refresh=force_refresh
        )

        if not persona_result.success:
            raise Exception(f"Failed to get persona token: {persona_result.error}")

        return persona_result.persona_token

    def get_yo_digital_token(self, force_refresh: bool = False) -> Optional[str]:
        """
        Get yo_digital access token

        Args:
            force_refresh: Force token refresh

        Returns:
            yo_digital access token or None
        """
        if not self.token_flow_manager:
            logger.warning("TokenFlowManager not initialized")
            return None

        result = self.token_flow_manager.get_yo_digital_token(force_refresh)

        if result.success:
            logger.info(f"✓ Got yo_digital token via: {result.flow_path}")
            return result.access_token
        else:
            logger.error(f"✗ Failed to get yo_digital token: {result.error}")
            return None

    # ========================================================================
    # Public API - Configuration Management
    # ========================================================================

    def update_sam3_client_id(self, client_id: str) -> None:
        """Update SAM3 client ID"""
        old_client_id = self._sam3_client_id
        self._sam3_client_id = client_id

        if self._sam3_client:
            self._sam3_client.update_sam3_client_id(client_id)
            logger.info(
                f"✓ Updated SAM3 client ID: {old_client_id[:8]}... -> {client_id[:8]}..."
            )
        else:
            logger.debug(
                f"Updated SAM3 client ID (no client to update yet): {client_id}"
            )

    def update_client_model(self, client_model: str) -> None:
        """Update client model"""
        self._client_model = client_model
        logger.debug(f"Updated client model: {client_model}")

    def update_device_model(self, device_model: str) -> None:
        """Update device model"""
        self._device_model = device_model
        logger.debug(f"Updated device model: {device_model}")

    def update_dynamic_endpoints(self, endpoints: Dict[str, str]) -> None:
        """Update dynamic endpoints"""
        self._dynamic_endpoints.update(endpoints)
        logger.debug(f"Updated dynamic endpoints with {len(endpoints)} entries")

    def update_endpoints(self, endpoints: Dict[str, str]) -> None:
        """Update endpoints (alias for compatibility)"""
        self.update_dynamic_endpoints(endpoints)

    def set_mpx_account_pid(self, account_pid: str) -> None:
        """
        Set MPX account PID for account URI construction
        This is CRITICAL for persona token composition

        Args:
            account_pid: MPX account PID (e.g., 'mdeprod')
        """
        self._mpx_account_pid = account_pid
        logger.debug(f"MPX account PID set: {account_pid}")

    def set_device_token(
        self, device_token: str, authorize_tokens_url: str = None
    ) -> None:
        """
        Enhanced device token setup with both endpoints

        Args:
            device_token: Device token for line authentication
            authorize_tokens_url: Line authentication endpoint URL
        """
        self._device_token = device_token
        self._authorize_tokens_url = authorize_tokens_url

        # Update SAM3 client with line auth endpoint
        if self._sam3_client and authorize_tokens_url:
            self._sam3_client.line_auth_endpoint = authorize_tokens_url
            self._sam3_client.token_endpoint = authorize_tokens_url  # Backwards compat
            logger.info(
                f"✓ Updated SAM3 client with line auth endpoint: {authorize_tokens_url}"
            )

        logger.debug("Device token configured with line authentication support")

    def set_openid_config(self, openid_config: Dict[str, Any]) -> None:
        """
        Set OpenID configuration for SAM3 client

        Args:
            openid_config: OpenID configuration dictionary
        """
        self._openid_config = openid_config
        if self._sam3_client:
            self._sam3_client.update_endpoints(openid_config)
        logger.debug("OpenID configuration updated")

    def set_remote_login_urls(
        self, qr_code_url_template: str, backchannel_start_url: str = None
    ) -> None:
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

    def update_sam3_qr_code_url(self, qr_code_url: str) -> bool:
        """
        Update SAM3 client with QR code URL

        Args:
            qr_code_url: QR code URL

        Returns:
            True if successful, False otherwise
        """
        if not self._sam3_client:
            logger.warning("Cannot update QR code URL - SAM3 client not initialized")
            return False

        self._sam3_client.set_qr_code_url(qr_code_url)
        logger.info(f"✓ Updated SAM3 client with QR code URL: {qr_code_url}")
        return True

    # ========================================================================
    # Public API - Authentication Capabilities
    # ========================================================================

    def can_use_line_auth(self) -> bool:
        """Check if line auth components are available"""
        return (
            self._device_token is not None
            and self._authorize_tokens_url is not None
            and self._sam3_client is not None
        )

    def can_use_remote_login(self) -> bool:
        """Check if remote login components are available"""
        return (
            self._sam3_client is not None and self._sam3_client.can_use_remote_login()
        )

    def get_authentication_capabilities(self) -> Dict[str, Any]:
        """Get authentication capabilities information"""
        line_auth_available = self.can_use_line_auth()
        remote_login_available = self.can_use_remote_login()

        return {
            "line_auth_available": line_auth_available,
            "remote_login_available": remote_login_available,
            "user_credentials_available": isinstance(
                self.credentials, Magenta2UserCredentials
            )
            and self.credentials.has_user_credentials(),
            "client_credentials_available": True,
            "preferred_flow": (
                "LINE_AUTH"
                if line_auth_available
                else (
                    "REMOTE_LOGIN"
                    if remote_login_available
                    else (
                        "USER"
                        if (
                            isinstance(self.credentials, Magenta2UserCredentials)
                            and self.credentials.has_user_credentials()
                        )
                        else "CLIENT"
                    )
                )
            ),
        }

    def get_authentication_flow_info(self) -> Dict[str, Any]:
        """Get authentication flow information"""
        base_info = {
            "user_credentials_available": isinstance(
                self.credentials, Magenta2UserCredentials
            )
            and self.credentials.has_user_credentials(),
            "client_credentials_available": True,
            "sam3_client_available": self._sam3_client is not None,
            "sso_client_available": self._sso_client is not None,
            "taa_client_available": self._taa_client is not None,
            "device_token_available": bool(self._device_token),
            "mpx_account_pid_available": bool(self._mpx_account_pid),
            "preferred_flow": (
                "USER"
                if (
                    isinstance(self.credentials, Magenta2UserCredentials)
                    and self.credentials.has_user_credentials()
                )
                else "CLIENT"
            ),
        }

        # Add TAA-specific info if available
        if self._taa_client and self._current_token:
            base_info["taa_token_valid"] = self.validate_taa_token(
                self._current_token.access_token
            )

        return base_info

    # ========================================================================
    # Device Authentication
    # ========================================================================

    def perform_device_authentication(self) -> bool:
        """
        Perform device-based authentication using device token
        This can be called independently for device registration flows

        Returns:
            True if successful, False otherwise
        """
        return self._perform_line_auth()

    def _perform_line_auth(self) -> bool:
        """
        Device token line authentication
        Matching C++ Sam3Client::LineAuth()

        Returns:
            True if successful, False otherwise
        """
        try:
            if not self._device_token or not self._authorize_tokens_url:
                logger.warning(
                    "Line auth skipped - missing device token or authorize URL"
                )
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

    def _perform_line_auth_with_response(self) -> Optional[Dict[str, Any]]:
        """
        Perform line authentication and return response data
        Used by TokenFlowManager callback

        Returns:
            Line authentication response data or None
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

            # Store refresh token for SAM3 token requests
            if response_data and "refresh_token" in response_data:
                self._line_auth_refresh_token = response_data["refresh_token"]
                logger.info(f"✓ Stored refresh token from line auth for SAM3 requests")
                logger.debug(
                    f"Refresh token preview: {self._line_auth_refresh_token[:20]}..."
                )

            return response_data

        except Exception as e:
            logger.error(f"Line authentication failed: {e}")
            return None

    def _perform_remote_login_flow(self) -> Optional[Dict[str, Any]]:
        """
        Perform remote login flow
        Used by TokenFlowManager callback

        Returns:
            Token data dict or None
        """
        if not self._sam3_client:
            return None

        try:
            return self._sam3_client.remote_login(scope="tvhubs offline_access")
        except Exception as e:
            logger.error(f"Remote login flow failed: {e}")
            return None

    # ========================================================================
    # TAA Validation and Debugging
    # ========================================================================

    def validate_taa_token(self, taa_token: str) -> bool:
        """
        Validate TAA token using TaaClient

        Args:
            taa_token: TAA token to validate

        Returns:
            True if valid, False otherwise
        """
        if not self._taa_client:
            return False
        return self._taa_client.validate_taa_token(taa_token)

    def debug_taa_token(self, taa_token: str) -> Dict[str, Any]:
        """
        Debug TAA token using TaaClient

        Args:
            taa_token: TAA token to debug

        Returns:
            Debug information dictionary
        """
        if not self._taa_client:
            return {"error": "TAA client not initialized"}
        return self._taa_client.debug_taa_token(taa_token)

    def get_sam3_client_status(self) -> Dict[str, Any]:
        """Get SAM3 client status for debugging"""
        if not self._sam3_client:
            return {"initialized": False}

        return self._sam3_client.get_client_status()

    def debug_authentication_state(self) -> Dict[str, Any]:
        """
        Enhanced debug method to verify complete authentication state

        Returns:
            Comprehensive authentication state information
        """
        if not self._current_token:
            return {"error": "No current token"}

        token = self._current_token

        return {
            "has_access_token": bool(token.access_token),
            "has_dc_cts_persona_token": bool(
                getattr(token, "dc_cts_persona_token", None)
            ),
            "has_account_uri": bool(getattr(token, "account_uri", None)),
            "has_composed_persona_token": bool(
                getattr(token, "composed_persona_token", None)
            ),
            "persona_token_preview": (
                getattr(token, "composed_persona_token", "")[:50] + "..."
                if getattr(token, "composed_persona_token", None)
                else None
            ),
            "account_uri": getattr(token, "account_uri", None),
            "persona_id": getattr(token, "persona_id", None),
            "account_id": getattr(token, "account_id", None),
            "sso_user_id": getattr(token, "sso_user_id", None),
            "sso_display_name": getattr(token, "sso_display_name", None),
            "token_expires_at": getattr(token, "token_exp", None),
            "is_expired": token.is_expired,
            "auth_level": token.auth_level.value,
            "flow_used": "USER" if getattr(token, "sso_user_id", None) else "CLIENT",
        }

    def debug_token_classification(self) -> Dict[str, Any]:
        """Debug method to analyze current token classification"""
        if not self._current_token:
            return {"error": "No current token"}

        claims = (
            self._current_token.get_jwt_claims()
            if hasattr(self._current_token, "get_jwt_claims")
            else {}
        )

        return {
            "token_type": type(self._current_token).__name__,
            "auth_level": self._current_token.auth_level.value,
            "is_expired": self._current_token.is_expired,
            "has_refresh": bool(self._current_token.refresh_token),
            "has_persona_token": bool(
                getattr(self._current_token, "dc_cts_persona_token", None)
            ),
            "jwt_claims_available": bool(claims),
            "key_claims": (
                {
                    "client_id": claims.get(
                        "client_id", claims.get("clientId", "MISSING")
                    ),
                    "persona_id": claims.get(
                        "dc_cts_personaId", claims.get("personaId", "MISSING")
                    ),
                    "account_id": claims.get(
                        "dc_cts_accountId", claims.get("accountId", "MISSING")
                    ),
                }
                if claims
                else {}
            ),
            "discovered_endpoints": list(self._dynamic_endpoints.keys()),
            "bootstrap_parameters": {
                "client_model": self._client_model,
                "device_model": self._device_model,
                "sam3_client_id": self._sam3_client_id,
            },
            "clients_initialized": {
                "sam3": self._sam3_client is not None,
                "sso": self._sso_client is not None,
                "taa": self._taa_client is not None,
            },
        }

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _get_endpoint(self, endpoint_key: str, fallback_key: str = None) -> str:
        """
        Get endpoint URL, preferring dynamically discovered ones

        Args:
            endpoint_key: Key in dynamic endpoints dict
            fallback_key: Key in fallback endpoints if dynamic lookup fails

        Returns:
            Endpoint URL

        Raises:
            ValueError: If no endpoint found
        """
        # Try dynamic endpoint first
        if endpoint_key in self._dynamic_endpoints:
            url = self._dynamic_endpoints[endpoint_key]
            logger.debug(f"Using dynamic endpoint for {endpoint_key}: {url}")
            return url

        # Fall back to hardcoded if available
        if fallback_key:
            from .constants import MAGENTA2_FALLBACK_ENDPOINTS

            if fallback_key in MAGENTA2_FALLBACK_ENDPOINTS:
                url = MAGENTA2_FALLBACK_ENDPOINTS[fallback_key]
                logger.debug(f"Using fallback endpoint for {endpoint_key}: {url}")
                return url

        raise ValueError(f"No endpoint found for {endpoint_key}")

    def _save_scoped_token_data(self, token: Magenta2AuthToken) -> None:
        """
        Save token data to scoped storage

        Saves:
        - tvhubs scope: access_token only
        - Provider level: refresh_token and device_id only
        """
        # Save ONLY the access token data under 'tvhubs' scope
        scoped_token_data = {
            "access_token": token.access_token,
            "token_type": token.token_type,
            "expires_in": token.expires_in,
            "issued_at": token.issued_at,
        }

        # Save scoped token (access_token under 'tvhubs' scope)
        self.settings_manager.save_scoped_token(
            self.provider_name, "tvhubs", scoped_token_data, self.country
        )

        # Save provider session data without access_token and without persona fields
        # Only keep refresh_token and device_id
        provider_session_data = {
            "refresh_token": token.refresh_token,
            "device_id": self._device_id,
        }

        # Save provider session data
        self.settings_manager.session_manager.save_session(
            self.provider_name, provider_session_data, self.country
        )

        logger.info(
            "✓ Access token saved under 'tvhubs' scope, only refresh_token and device_id saved at provider level"
        )

    @staticmethod
    def _url_encode(value: str) -> str:
        """URL encode a string"""
        from urllib.parse import quote

        return quote(value)

    # ========================================================================
    # Backward Compatibility Methods
    # ========================================================================

    def get_current_token(self) -> Optional[BaseAuthToken]:
        """Get the current authentication token"""
        return self._current_token

    def is_authenticated(self) -> bool:
        """Check if currently authenticated with valid token"""
        return self._current_token is not None and not self._current_token.is_expired

    def invalidate_token(self) -> None:
        """Invalidate current token"""
        self._current_token = None
        try:
            self.settings_manager.clear_token(self.provider_name, self.country)
        except Exception:
            pass
