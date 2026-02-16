# streaming_providers/providers/discovery/auth.py
"""
Discovery+ Authentication

Handles authentication for Discovery+ including anonymous and user credentials.
"""
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ...base.auth.base_auth import BaseAuthenticator, BaseAuthToken, TokenAuthLevel
from ...base.auth.credentials import ClientCredentials, UserPasswordCredentials
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger

from .constants import (
    DEFAULT_DEVICE_ID,
    DEFAULT_ENV,
    DEFAULT_REALM,
    DEFAULT_TENANT,
    DISCOVERY_BOOTSTRAP_URL,
    DISCOVERY_USER_AGENT,
    HOME_MARKET_MAPPING,
    AuthProvider,
)
from .exceptions import (
    InvalidCredentialsError,
    UnsupportedCredentialTypeError,
    EndpointDiscoveryError,
)


@dataclass
class DiscoveryAnonymousCredentials(ClientCredentials):
    """Discovery+ anonymous credentials"""

    realm: str = DEFAULT_REALM

    def validate(self) -> bool:
        """Validate anonymous credentials"""
        return bool(self.realm)

    @property
    def credential_type(self) -> str:
        return "discovery_anonymous"


@dataclass
class DiscoveryUserCredentials(UserPasswordCredentials):
    """Discovery+ user credentials"""

    provider: str = AuthProvider.USERNAME_PASSWORD.value

    def to_login_payload(self) -> Dict[str, Any]:
        """
        Convert to login payload for API request.

        Returns:
            Dictionary formatted for Discovery+ login API
        """
        return {
            "credentials": {
                "password": self.password,
                "username": self.username,
                "provider": self.provider,
            }
        }

    @property
    def credential_type(self) -> str:
        return "discovery_user"


@dataclass
class DiscoveryAuthToken(BaseAuthToken):
    """Discovery+ authentication token"""

    refresh_token: Optional[str] = field(default=None)
    realm: Optional[str] = field(default=None)
    anonymous: bool = field(default=True)
    token_id: Optional[str] = field(default=None)

    @classmethod
    def from_token_response(cls, response_data: Dict[str, Any]) -> "DiscoveryAuthToken":
        """
        Create token from API response.

        Args:
            response_data: Token response from Discovery+ API

        Returns:
            Initialized DiscoveryAuthToken
        """
        data = response_data.get("data", {})
        attributes = data.get("attributes", {})

        token = cls(
            access_token=attributes.get("token", ""),
            token_type="Bearer",
            expires_in=31536000,  # Default 1 year
            issued_at=time.time(),
            realm=attributes.get("realm"),
            anonymous=attributes.get("anonymous", True),
            token_id=data.get("id"),
        )

        # Parse JWT for more accurate expiration
        token._parse_jwt_expiration()
        return token

    def _parse_jwt_expiration(self) -> None:
        """
        Extract expiration from JWT token.

        Updates expires_in based on JWT exp claim if present.
        """
        try:
            parts = self.access_token.split(".")
            if len(parts) == 3:
                import base64
                import json

                payload_b64 = parts[1]
                # Add padding if needed
                padding = len(payload_b64) % 4
                if padding:
                    payload_b64 += "=" * (4 - padding)

                payload = json.loads(base64.b64decode(payload_b64))
                if "exp" in payload:
                    self.expires_in = payload["exp"] - self.issued_at
        except Exception:
            # If JWT parsing fails, keep default expiration
            pass

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert token to dictionary.

        Returns:
            Dictionary representation of the token
        """
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "issued_at": self.issued_at,
            "realm": self.realm,
            "anonymous": self.anonymous,
            "token_id": self.token_id,
        }


class DiscoveryAuthenticator(BaseAuthenticator):
    """
    Discovery+ authenticator with dynamic endpoint discovery.

    Supports:
    - Anonymous authentication
    - User credentials (username/password)
    - Dynamic endpoint discovery from bootstrap

    Note: Discovery+ uses simple token-based auth, not OAuth2.
    """

    def __init__(
            self,
            country: str = "de",
            settings_manager=None,
            credentials=None,
            config_dir: Optional[str] = None,
            http_manager=None,
            proxy_config: Optional[ProxyConfig] = None,
    ):
        """
        Initialize authenticator for specific country.

        Args:
            country: ISO country code (e.g., 'de', 'uk')
            settings_manager: Settings manager instance
            credentials: Authentication credentials
            config_dir: Configuration directory path
            http_manager: HTTP manager instance
            proxy_config: Proxy configuration
        """
        self.country = country
        self.home_market = HOME_MARKET_MAPPING.get(country, "emea")
        self.tenant = DEFAULT_TENANT
        self.env = DEFAULT_ENV
        self.device_id = DEFAULT_DEVICE_ID

        # Store http_manager and proxy_config BEFORE calling super().__init__
        # BaseAuthenticator doesn't accept these parameters
        self._http_manager = http_manager
        self._proxy_config = proxy_config
        self._endpoints: Dict[str, str] = {}
        self._api_groups: Dict[str, Any] = {}
        self._routing: Dict[str, Any] = {}

        # Call parent __init__ (BaseAuthenticator signature)
        super().__init__(
            provider_name="discovery",
            settings_manager=settings_manager,
            credentials=credentials,
            country=country,
            config_dir=config_dir,
            enable_kodi_integration=True,
        )

        # Discover endpoints after initialization
        self._discover_endpoints()

    @property
    def http_manager(self):
        """
        Get or create HTTP manager.

        Returns:
            HTTP manager instance

        Raises:
            RuntimeError: If HTTP manager cannot be created
        """
        if self._http_manager is not None:
            return self._http_manager

        logger.warning(
            f"No HTTP manager available for {self.provider_name}, creating one"
        )

        try:
            from ...base.network import HTTPManagerFactory

            self._http_manager = HTTPManagerFactory.create_for_provider(
                self.provider_name,
                proxy_config=self._proxy_config,
                user_agent=DISCOVERY_USER_AGENT,
                timeout=30,
            )
        except Exception as e:
            logger.error(f"Error creating HTTP manager: {e}")
            raise RuntimeError(
                f"Cannot create HTTP manager for {self.provider_name}: {e}"
            )

        return self._http_manager

    def _discover_endpoints(self) -> None:
        """
        Discover API endpoints from bootstrap.

        Raises:
            EndpointDiscoveryError: If endpoint discovery fails
        """
        try:
            logger.debug(f"Discovering endpoints for Discovery+ ({self.country})")

            response = self.http_manager.get(
                DISCOVERY_BOOTSTRAP_URL,
                operation="bootstrap",
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            # Store routing info
            self._routing = data.get("routing", {})
            self._api_groups = data.get("apiGroups", {})

            # Build endpoint map
            self._endpoints = {}
            for endpoint in data.get("endpoints", []):
                path = endpoint.get("path")
                api_group = endpoint.get("apiGroup")
                if path and api_group and api_group in self._api_groups:
                    base_url = self._build_api_url(api_group)
                    if base_url:
                        self._endpoints[path] = f"{base_url}{path}"

            logger.debug(f"Discovered {len(self._endpoints)} endpoints")

        except Exception as e:
            logger.warning(f"Failed to discover endpoints: {e}")
            # Initialize empty dicts for fallback
            self._endpoints = {}
            self._api_groups = {}
            self._routing = {}

    def _build_api_url(self, api_group: str) -> Optional[str]:
        """
        Build API URL from apiGroup template.

        Args:
            api_group: API group identifier

        Returns:
            Constructed API URL or None if template not found
        """
        if not self._api_groups or api_group not in self._api_groups:
            return None

        template = self._api_groups[api_group].get("baseUrl", "")
        if not template:
            return None

        # Replace placeholders
        replacements = {
            "{tenant}": self.tenant,
            "{homeMarket}": self.home_market,
            "{env}": self.env,
            "{domain}": "api.discoveryplus.com",
        }

        url = template
        for key, value in replacements.items():
            url = url.replace(key, value)

        return url

    def get_endpoint(self, path: str) -> Optional[str]:
        """
        Get full URL for an endpoint path.

        Args:
            path: Endpoint path (e.g., '/token')

        Returns:
            Full endpoint URL or None if not found
        """
        if not self._endpoints:
            self._discover_endpoints()
        return self._endpoints.get(path)

    @property
    def auth_endpoint(self) -> str:
        """
        Get authentication endpoint URL (required by BaseAuthenticator).

        For Discovery+, this returns the login endpoint for user auth
        or token endpoint for anonymous auth.

        Returns:
            Authentication endpoint URL
        """
        # Return login endpoint as the primary auth endpoint
        return self.login_endpoint

    @property
    def token_endpoint(self) -> str:
        """Get token endpoint URL"""
        endpoint = self.get_endpoint("/token")
        if endpoint:
            return endpoint
        return f"https://default.any-any.{self.env}.api.discoveryplus.com/token"

    @property
    def login_endpoint(self) -> str:
        """Get login endpoint URL"""
        endpoint = self.get_endpoint("/login")
        if endpoint:
            return endpoint
        bolt_any = self._build_api_url("bolt-any-homemarket")
        return (
            f"{bolt_any}/login" if bolt_any
            else "https://default.any-emea.prd.api.discoveryplus.com/login"
        )

    @property
    def playback_endpoint(self) -> str:
        """Get playback endpoint URL"""
        endpoint = self.get_endpoint("/any/playback/v1/playbackInfo")
        if endpoint:
            return endpoint
        bolt_any = self._build_api_url("bolt-any-homemarket")
        return (
            f"{bolt_any}/any/playback/v1/playbackInfo" if bolt_any
            else "https://default.any-any.prd.api.discoveryplus.com/any/playback/v1/playbackInfo"
        )

    @property
    def cms_home_endpoint(self) -> str:
        """Get CMS home endpoint URL"""
        endpoint = self.get_endpoint("/cms/routes/home")
        if endpoint:
            return endpoint
        bolt_any = self._build_api_url("bolt-any-homemarket")
        return (
            f"{bolt_any}/cms/routes/home" if bolt_any
            else "https://default.any-any.prd.api.discoveryplus.com/cms/routes/home"
        )

    @property
    def cms_collections_endpoint(self) -> str:
        """Get CMS collections endpoint URL"""
        endpoint = self.get_endpoint("/cms/collections")
        if endpoint:
            return endpoint
        bolt_any = self._build_api_url("bolt-any-homemarket")
        return (
            f"{bolt_any}/cms/collections" if bolt_any
            else "https://default.any-any.prd.api.discoveryplus.com/cms/collections"
        )

    def _get_auth_headers(self) -> Dict[str, str]:
        """
        Get headers for authentication request.

        Returns:
            Dictionary of HTTP headers
        """
        return {
            "User-Agent": DISCOVERY_USER_AGENT,
            "Accept": "application/json",
        }

    def _build_auth_payload(self) -> Dict[str, Any]:
        """
        Build authentication payload based on credential type.

        Returns:
            Authentication payload dictionary

        Raises:
            InvalidCredentialsError: If no credentials available
            UnsupportedCredentialTypeError: If credential type not supported
        """
        if not self.credentials:
            raise InvalidCredentialsError("No credentials available")

        if isinstance(self.credentials, DiscoveryAnonymousCredentials):
            return {}
        elif isinstance(self.credentials, DiscoveryUserCredentials):
            return self.credentials.to_login_payload()
        else:
            raise UnsupportedCredentialTypeError(type(self.credentials).__name__)

    def _create_token_from_response(
            self,
            response_data: Dict[str, Any]
    ) -> BaseAuthToken:
        """
        Create token object from API response.

        Args:
            response_data: Response data from authentication API

        Returns:
            Initialized token with auth level classified
        """
        token = DiscoveryAuthToken.from_token_response(response_data)
        token.auth_level = self._classify_token(token)
        return token

    def get_fallback_credentials(self) -> DiscoveryAnonymousCredentials:
        """
        Get fallback credentials (anonymous).

        Returns:
            Anonymous credentials instance
        """
        return DiscoveryAnonymousCredentials(realm=DEFAULT_REALM)

    def _perform_authentication(self) -> BaseAuthToken:
        """
        Perform authentication using appropriate flow based on credential type.

        Returns:
            Authenticated token

        Raises:
            InvalidCredentialsError: If no credentials available
            UnsupportedCredentialTypeError: If credential type not supported
        """
        if isinstance(self.credentials, DiscoveryAnonymousCredentials):
            return self._perform_anonymous_auth()
        elif isinstance(self.credentials, DiscoveryUserCredentials):
            return self._perform_user_auth()
        else:
            raise UnsupportedCredentialTypeError(type(self.credentials).__name__)

    def _perform_anonymous_auth(self) -> BaseAuthToken:
        """
        Perform anonymous authentication (GET /token?realm=bolt).

        Returns:
            Anonymous authentication token
        """
        logger.info(f"Performing anonymous authentication for {self.provider_name}")

        params = {"realm": self.credentials.realm}
        headers = self._get_auth_headers()

        response = self.http_manager.get(
            self.token_endpoint,
            operation="auth",
            headers=headers,
            params=params,
        )

        response.raise_for_status()
        token_data = response.json()
        return self._create_token_from_response(token_data)

    def _perform_user_auth(self) -> BaseAuthToken:
        """
        Perform user authentication (POST /login with credentials).

        Returns:
            User authentication token
        """
        logger.info(f"Performing user authentication for {self.provider_name}")

        headers = self._get_auth_headers()
        headers["Content-Type"] = "application/json"

        payload = self._build_auth_payload()

        response = self.http_manager.post(
            self.login_endpoint,
            operation="auth",
            headers=headers,
            json_data=payload,
        )

        response.raise_for_status()
        token_data = response.json()
        return self._create_token_from_response(token_data)

    def _refresh_token(self) -> Optional[BaseAuthToken]:
        """
        Token refresh - Discovery tokens don't support refresh, re-authenticate.

        Returns:
            None (triggers re-authentication)
        """
        logger.debug(
            f"No refresh token support for {self.provider_name}, "
            "re-authenticating"
        )
        return None

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        """
        Classify Discovery+ token based on authentication level.

        Args:
            token: Token to classify

        Returns:
            Token authentication level
        """
        if hasattr(token, "anonymous"):
            if not token.anonymous:
                return TokenAuthLevel.USER_AUTHENTICATED
        return TokenAuthLevel.ANONYMOUS

    def get_bearer_token(self, force_refresh: bool = False) -> str:
        """
        Get bearer token for API requests.

        Args:
            force_refresh: Force token refresh

        Returns:
            Bearer token string
        """
        token = self.authenticate(force_refresh=force_refresh)
        return token.bearer_token

    def is_authenticated(self) -> bool:
        """
        Check if currently authenticated with valid token.

        Returns:
            True if authenticated with valid token
        """
        return (
                self._current_token is not None and
                not self._current_token.is_expired
        )

    def invalidate_token(self) -> None:
        """Invalidate current token and clear from storage"""
        self._current_token = None
        try:
            self.settings_manager.clear_token(self.provider_name, self.country)
        except (AttributeError, KeyError, IOError, OSError):
            pass