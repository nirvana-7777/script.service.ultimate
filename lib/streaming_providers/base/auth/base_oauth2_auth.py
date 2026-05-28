# streaming_providers/base/auth/base_oauth2_auth.py
import base64
import dataclasses
import hashlib
import html
import re
import secrets
import threading
import time
import uuid
from abc import abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse

from ..models.proxy_models import ProxyConfig
from ..utils.logger import logger
from .base_auth import BaseAuthenticator, BaseAuthToken, TokenAuthLevel


@dataclass
class OIDCConfiguration:
    """
    Stores OIDC discovery configuration from .well-known/openid-configuration.

    Fields follow OpenID Connect Discovery 1.0 specification:
    https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    """
    issuer: str = ""
    authorization_endpoint: str = ""
    token_endpoint: str = ""
    userinfo_endpoint: str = ""
    jwks_uri: str = ""
    scopes_supported: List[str] = field(default_factory=list)
    grant_types_supported: List[str] = field(default_factory=list)
    response_types_supported: List[str] = field(default_factory=list)
    response_modes_supported: List[str] = field(default_factory=list)
    token_endpoint_auth_methods_supported: List[str] = field(default_factory=list)
    code_challenge_methods_supported: List[str] = field(default_factory=list)
    revocation_endpoint: Optional[str] = None
    end_session_endpoint: Optional[str] = None
    device_authorization_endpoint: Optional[str] = None
    registration_endpoint: Optional[str] = None
    introspection_endpoint: Optional[str] = None

    @classmethod
    def from_discovery_response(cls, data: Dict[str, Any]) -> 'OIDCConfiguration':
        """
        Create OIDCConfiguration from .well-known/openid-configuration response.

        Uses dataclasses.fields() (public API) for forward-compatibility.
        Unknown fields are silently ignored per OIDC spec extensibility.
        """
        valid_fields = {f.name for f in dataclasses.fields(cls)}
        filtered_data = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered_data)

    def is_complete(self) -> bool:
        """Check if essential endpoints are populated."""
        return bool(
            self.authorization_endpoint and
            self.token_endpoint and
            self.issuer
        )


class OAuth2Error(Exception):
    """
    OAuth2-specific error with structured error information.

    Intentionally separate from HTTP transport errors for clearer error handling.
    """

    def __init__(self, error: str, error_description: str = None, error_uri: str = None):
        self.error = error
        self.error_description = error_description
        self.error_uri = error_uri
        message = error
        if error_description:
            message = f"{error}: {error_description}"
        super().__init__(message)


class SessionAwareHTTPManager:
    """Wraps http_manager to provide session-like cookie handling while maintaining proxy support"""

    def __init__(self, http_manager):
        self.http_manager = http_manager
        self.cookies: Dict[str, str] = {}
        self.headers: Dict[str, str] = {}

    def get(self, url: str, **kwargs):
        """GET request with cookie handling"""
        headers = kwargs.get("headers", {}).copy()
        headers.update(self.headers)
        if self.cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])
            headers["Cookie"] = cookie_str
        kwargs["headers"] = headers
        response = self.http_manager.get(url, operation="oauth", **kwargs)
        self._update_cookies_from_response(response)
        return response

    def post(self, url: str, **kwargs):
        """POST request with cookie handling"""
        headers = kwargs.get("headers", {}).copy()
        headers.update(self.headers)
        if self.cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])
            headers["Cookie"] = cookie_str
        kwargs["headers"] = headers
        response = self.http_manager.post(url, operation="oauth", **kwargs)
        self._update_cookies_from_response(response)
        return response

    def _update_cookies_from_response(self, response):
        """Extract and update cookies from response"""
        if hasattr(response, "cookies"):
            for cookie in response.cookies:
                self.cookies[cookie.name] = cookie.value


class BaseOAuth2Authenticator(BaseAuthenticator):
    """
    Base class for OAuth2/OIDC authentication with dynamic endpoint discovery.

    Production-hardened: no silent failures, consistent endpoint handling,
    proper exception chaining, and defensive diagnostics.
    """

    def __init__(
            self,
            provider_name: str,
            settings_manager=None,
            credentials=None,
            country: Optional[str] = None,
            config_dir: Optional[str] = None,
            enable_kodi_integration: bool = True,
            proxy_config: Optional[ProxyConfig] = None,
            http_manager=None,
    ):
        super().__init__(
            provider_name,
            settings_manager,
            credentials,
            country=country,
            config_dir=config_dir,
            enable_kodi_integration=enable_kodi_integration,
        )

        self._oauth_state = None
        self._pkce_verifier = None
        self._config = None
        self._proxy_config = proxy_config
        self._auth_endpoint = None
        self._http_manager = http_manager
        self._token_expiry_buffer = 300

        # OIDC Discovery support (backward compatible - disabled by default)
        self._oidc_config: Optional[OIDCConfiguration] = None
        self._oidc_discovery_url: Optional[str] = None
        self._enable_oidc_discovery: bool = False
        self._oidc_discovery_lock = threading.Lock()
        self._oidc_discovery_timestamp: Optional[float] = None
        self._oidc_cache_ttl: int = 86400  # 24 hours

        # Telemetry
        self._oidc_discovery_failures: int = 0
        self._oidc_discovery_successes: int = 0

    @property
    def http_manager(self):
        """Safe access to http_manager"""
        if self._http_manager is not None:
            return self._http_manager
        logger.warning(f"No HTTP manager available for {self.provider_name}, creating one")
        try:
            from ...base.network import HTTPManagerFactory
            self._http_manager = HTTPManagerFactory.create_for_provider(
                self.provider_name,
                proxy_config=self._proxy_config,
                user_agent=getattr(self.config, "user_agent", "Mozilla/5.0"),
                timeout=getattr(self.config, "timeout", 30),
            )
        except Exception as e:
            logger.warning(f"Error creating HTTP manager via factory: {e}, using minimal fallback")
            self._http_manager = self._create_minimal_http_manager()
        return self._http_manager

    @http_manager.setter
    def http_manager(self, value):
        self._http_manager = value

    @property
    def config(self):
        """Config accessor - fails loudly if not initialized by subclass"""
        if self._config is not None:
            return self._config
        raise RuntimeError(
            f"Config not initialized for {self.provider_name}. "
            "Subclass must set self._config in __init__ before accessing config."
        )

    @config.setter
    def config(self, value):
        self._config = value

    @staticmethod
    def _create_minimal_http_manager():
        """Minimal HTTP manager fallback for testing only"""

        class MinimalHTTPManager:
            @staticmethod
            def get(url, operation=None, headers=None, **kwargs):
                import requests
                return requests.get(url, headers=headers, **kwargs)

            @staticmethod
            def post(url, operation=None, headers=None, data=None, **kwargs):
                import requests
                return requests.post(url, headers=headers, data=data, **kwargs)

        return MinimalHTTPManager()

    @property
    def auth_endpoint(self) -> str:
        """Get authentication endpoint"""
        if hasattr(self, "_auth_endpoint") and self._auth_endpoint:
            return self._auth_endpoint
        if hasattr(self.config, "auth_endpoint"):
            return self.config.auth_endpoint
        raise NotImplementedError("Subclass must implement auth_endpoint or set _auth_endpoint")

    @auth_endpoint.setter
    def auth_endpoint(self, value):
        self._auth_endpoint = value

    # ========================================================================
    # OIDC Discovery Support
    # ========================================================================

    def enable_oidc_discovery(self, discovery_url: str, cache_ttl: int = 86400) -> None:
        """Enable OIDC discovery with smart URL normalization"""
        normalized_url = discovery_url.rstrip('/')
        if '/.well-known/' not in normalized_url:
            normalized_url += '/.well-known/openid-configuration'
        self._oidc_discovery_url = normalized_url
        self._enable_oidc_discovery = True
        self._oidc_cache_ttl = cache_ttl
        self._oidc_config = None
        self._oidc_discovery_timestamp = None
        logger.debug(f"OIDC discovery enabled for {self.provider_name}: {normalized_url}")

    def _is_oidc_cache_valid(self) -> bool:
        """Check if cached OIDC config is still valid"""
        if not self._oidc_config or not self._oidc_discovery_timestamp:
            return False
        return (time.time() - self._oidc_discovery_timestamp) < self._oidc_cache_ttl

    def _validate_oidc_metadata(self, metadata: Dict[str, Any]) -> bool:
        """Validate required OIDC metadata fields"""
        required = ["issuer", "authorization_endpoint", "token_endpoint"]
        missing = [f for f in required if not metadata.get(f)]
        if missing:
            logger.error(f"OIDC metadata missing required fields for {self.provider_name}: {missing}")
            return False
        issuer = metadata.get("issuer", "")
        if issuer and not issuer.startswith("https://"):
            logger.warning(f"OIDC issuer uses HTTP (insecure) for {self.provider_name}: {issuer}")
        return True

    def discover_oidc_endpoints(self, force_refresh: bool = False) -> Optional[OIDCConfiguration]:
        """Discover OIDC endpoints with consolidated error handling"""
        if not self._enable_oidc_discovery or not self._oidc_discovery_url:
            return None

        if not force_refresh and self._is_oidc_cache_valid():
            return self._oidc_config

        with self._oidc_discovery_lock:
            if not force_refresh and self._is_oidc_cache_valid():
                return self._oidc_config

            try:
                headers = self.config.get_base_headers()
                response = self.http_manager.get(
                    self._oidc_discovery_url,
                    operation="oidc_discovery",
                    headers=headers,
                    timeout=getattr(self.config, "timeout", 30)
                )

                # Consolidated status logging inside single error handling block
                if response.status_code >= 400:
                    status_msg = f"OIDC discovery HTTP {response.status_code} for {self.provider_name}"
                    if response.status_code == 404:
                        logger.error(f"{status_msg} - endpoint not found: {self._oidc_discovery_url}")
                    elif response.status_code == 429:
                        retry_after = response.headers.get("Retry-After", "unknown")
                        logger.warning(f"{status_msg} - rate limited, Retry-After: {retry_after}")
                    elif response.status_code >= 500:
                        logger.warning(f"{status_msg} - transient server error, will retry")
                    # Increment failure counter and return cached if available
                    self._oidc_discovery_failures += 1
                    if self._oidc_config:
                        logger.debug(f"Using cached OIDC config for {self.provider_name}")
                        return self._oidc_config
                    return None

                discovery_data = response.json()

                if not self._validate_oidc_metadata(discovery_data):
                    logger.warning(f"OIDC metadata validation failed for {self.provider_name}")
                    self._oidc_discovery_failures += 1
                    if self._oidc_config:
                        return self._oidc_config
                    return None

                self._oidc_config = OIDCConfiguration.from_discovery_response(discovery_data)
                self._oidc_discovery_timestamp = time.time()
                self._oidc_discovery_successes += 1

                logger.info(f"OIDC discovery successful for {self.provider_name}")
                return self._oidc_config

            except Exception as e:
                exc_type = type(e).__name__
                logger.warning(f"OIDC discovery failed for {self.provider_name} ({exc_type}): {e}")
                self._oidc_discovery_failures += 1
                if self._oidc_config:
                    return self._oidc_config
                return None

    def reload_oidc_configuration(self) -> Optional[OIDCConfiguration]:
        """Force reload OIDC configuration"""
        logger.info(f"Reloading OIDC configuration for {self.provider_name}")
        self._oidc_config = None
        self._oidc_discovery_timestamp = None
        return self.discover_oidc_endpoints(force_refresh=True)

    def get_oidc_discovery_stats(self) -> Dict[str, Any]:
        """Get OIDC discovery telemetry"""
        total = self._oidc_discovery_successes + self._oidc_discovery_failures
        return {
            "successes": self._oidc_discovery_successes,
            "failures": self._oidc_discovery_failures,
            "total_attempts": total,
            "success_rate": self._oidc_discovery_successes / max(1, total),
        }

    # ========================================================================
    # Endpoint Properties
    # ========================================================================

    @property
    def oauth_authorize_endpoint(self) -> str:
        """Get OAuth2 authorization endpoint with priority resolution"""
        if self._enable_oidc_discovery:
            config = self.discover_oidc_endpoints()
            if config and config.authorization_endpoint:
                return config.authorization_endpoint
        if hasattr(self, "_authorization_endpoint") and self._authorization_endpoint:
            return self._authorization_endpoint
        if hasattr(self, "auth_endpoint") and self.auth_endpoint:
            auth_endpoint = self.auth_endpoint
            if auth_endpoint.endswith("/token"):
                return auth_endpoint.replace("/token", "/auth")
            elif "/protocol/openid-connect/token" in auth_endpoint:
                return auth_endpoint.replace("/protocol/openid-connect/token", "/protocol/openid-connect/auth")
            else:
                return "/".join(auth_endpoint.split("/")[:-1]) + "/auth"
        raise NotImplementedError(
            f"Subclass must implement oauth_authorize_endpoint or enable OIDC discovery for {self.provider_name}"
        )

    @property
    def oauth_token_endpoint(self) -> str:
        """Get OAuth2 token endpoint with priority resolution"""
        if self._enable_oidc_discovery:
            config = self.discover_oidc_endpoints()
            if config and config.token_endpoint:
                return config.token_endpoint
        if hasattr(self, "_token_endpoint") and self._token_endpoint:
            return self._token_endpoint
        return self.auth_endpoint

    @property
    def oauth_userinfo_endpoint(self) -> Optional[str]:
        """Get OIDC userinfo endpoint if available"""
        if self._enable_oidc_discovery:
            config = self.discover_oidc_endpoints()
            if config and config.userinfo_endpoint:
                return config.userinfo_endpoint
        return None

    # ========================================================================
    # Capability Detection
    # ========================================================================

    def supports_pkce(self) -> bool:
        """Check if PKCE S256 is supported via OIDC discovery"""
        if self._enable_oidc_discovery:
            config = self.discover_oidc_endpoints()
            if config and config.code_challenge_methods_supported:
                return "S256" in config.code_challenge_methods_supported
        return True

    @property
    def use_pkce(self) -> bool:
        """Allow subclasses to disable PKCE for legacy providers"""
        if hasattr(self, "_use_pkce"):
            return self._use_pkce
        return self.supports_pkce()

    def get_supported_grant_types(self) -> List[str]:
        """Get supported grant types from OIDC discovery"""
        if self._enable_oidc_discovery:
            config = self.discover_oidc_endpoints()
            if config and config.grant_types_supported:
                return config.grant_types_supported
        return ["authorization_code", "refresh_token"]

    def is_grant_type_supported(self, grant_type: str) -> bool:
        """Check if a specific grant type is supported"""
        supported = self.get_supported_grant_types()
        return grant_type in supported if supported else True

    def _should_use_json_for_token_exchange(self, **kwargs) -> bool:
        """Determine if token exchange should use JSON payload"""
        if kwargs.get("use_json") is not None:
            return bool(kwargs["use_json"])
        if self._enable_oidc_discovery:
            config = self.discover_oidc_endpoints()
            if config and config.token_endpoint_auth_methods_supported:
                if 'client_secret_post' not in config.token_endpoint_auth_methods_supported:
                    if 'application/json' in config.token_endpoint_auth_methods_supported:
                        return True
        return False

    # ========================================================================
    # Abstract Properties
    # ========================================================================

    @property
    @abstractmethod
    def oauth_client_id(self) -> str:
        pass

    @property
    @abstractmethod
    def oauth_scope(self) -> str:
        pass

    @property
    @abstractmethod
    def oauth_redirect_uri(self) -> str:
        pass

    # ========================================================================
    # PKCE Implementation
    # ========================================================================

    @staticmethod
    def generate_pkce_verifier() -> str:
        """Generate PKCE code verifier (RFC 7636)"""
        token = secrets.token_bytes(32)
        verifier = base64.urlsafe_b64encode(token).rstrip(b"=").decode("ascii")
        logger.debug(f"Generated PKCE verifier: {verifier[:10]}...")
        return verifier

    @staticmethod
    def generate_pkce_challenge(verifier: str) -> str:
        """Generate PKCE code challenge from verifier"""
        challenge = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge_b64 = base64.urlsafe_b64encode(challenge).rstrip(b"=").decode("ascii")
        logger.debug(f"Generated PKCE challenge: {challenge_b64[:10]}...")
        return challenge_b64

    # ========================================================================
    # OAuth2 State Management
    # ========================================================================

    def generate_oauth_state(self) -> str:
        """Generate secure state parameter"""
        state = str(uuid.uuid4())
        self._oauth_state = state
        return state

    @staticmethod
    def generate_oauth_nonce() -> str:
        """Generate secure nonce parameter"""
        return str(uuid.uuid4())

    @staticmethod
    def validate_oauth_state(received_state: str, original_state: str) -> bool:
        """Validate OAuth2 state parameter to prevent CSRF"""
        if not received_state or not original_state:
            logger.warning("OAuth2 state validation failed: missing state parameters")
            return False
        is_valid = received_state == original_state
        if not is_valid:
            logger.warning("OAuth2 state validation failed: state mismatch")
        return is_valid

    # ========================================================================
    # Session Management
    # ========================================================================

    def _create_oauth_session(self) -> SessionAwareHTTPManager:
        """Create a session-aware HTTP manager for OAuth flows"""
        session = SessionAwareHTTPManager(self.http_manager)
        session.headers.update({
            "User-Agent": self.config.user_agent,
            "Referer": getattr(self.config, "base_website", ""),
            "Origin": getattr(self.config, "base_website", ""),
        })
        return session

    # ========================================================================
    # Client Credentials Flow - Fix: Use oauth_token_endpoint
    # ========================================================================

    def _perform_oauth_client_credentials_flow(self) -> Dict[str, Any]:
        """
        OAuth2 client credentials flow.

        Uses oauth_token_endpoint to respect OIDC discovery.
        """
        try:
            logger.debug(f"Starting OAuth2 client credentials flow for {self.provider_name}")
            headers = self._get_auth_headers()
            data = self._build_auth_payload()

            # Use oauth_token_endpoint instead of auth_endpoint
            response = self.http_manager.post(
                self.oauth_token_endpoint, operation="auth", headers=headers, data=data
            )
            self._check_oauth_error_response(response)
            response.raise_for_status()
            token_data = response.json()
            logger.debug(f"OAuth2 client credentials flow successful for {self.provider_name}")
            return token_data
        except OAuth2Error:
            raise
        except Exception as e:
            logger.error(f"OAuth2 client credentials flow failed for {self.provider_name}: {e}")
            raise Exception(f"OAuth2 client credentials flow failed: {e}")

    # ========================================================================
    # Authorization URL Building
    # ========================================================================

    def _build_authorization_url(self, extra_params: Dict[str, Any] = None) -> tuple[str, str, str]:
        """Build authorization URL with optional PKCE"""
        state = self.generate_oauth_state()
        params = {
            "response_type": "code",
            "client_id": self.oauth_client_id,
            "redirect_uri": self.oauth_redirect_uri,
            "scope": self.oauth_scope,
            "state": state,
        }
        code_verifier = ""
        if self.use_pkce:
            code_verifier = self.generate_pkce_verifier()
            code_challenge = self.generate_pkce_challenge(code_verifier)
            params.update({
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            })
        else:
            logger.warning(f"PKCE disabled for {self.provider_name} - ensure provider supports secure flows")
        if extra_params:
            params.update(extra_params)
        authorization_url = f"{self.oauth_authorize_endpoint}?{urlencode(params)}"
        return authorization_url, state, code_verifier

    # ========================================================================
    # Authorization Code Exchange
    # ========================================================================

    def _exchange_authorization_code_for_token(
            self, authorization_code: str, code_verifier: str, state: str = None, **kwargs
    ) -> Dict[str, Any]:
        """Exchange authorization code for access token with flexible payload format"""
        try:
            logger.debug(f"Exchanging authorization code for token for {self.provider_name}")
            data = self._build_token_exchange_payload(
                authorization_code=authorization_code,
                code_verifier=code_verifier,
                state=state,
                **kwargs,
            )
            headers = self._get_token_exchange_headers(**kwargs)
            endpoint = kwargs.get('token_endpoint') or self._get_token_exchange_endpoint(**kwargs)

            # Fix: Explicit None check for boolean use_json parameter
            use_json = kwargs.get('use_json')
            if use_json is None:
                use_json = self._should_use_json_for_token_exchange(**kwargs)

            request_kwargs = {
                "operation": "auth",
                "headers": headers,
                "timeout": getattr(self.config, "timeout", 30),
            }
            if use_json:
                request_kwargs["json_data"] = data
            else:
                request_kwargs["data"] = urlencode(data).encode()

            response = self.http_manager.post(endpoint, **request_kwargs)
            self._check_oauth_error_response(response)
            response.raise_for_status()
            token_data = response.json()
            logger.debug(f"Authorization code exchange successful for {self.provider_name}")
            return token_data
        except OAuth2Error:
            raise
        except Exception as e:
            logger.error(f"Authorization code exchange failed for {self.provider_name}: {e}")
            raise Exception(f"Authorization code exchange failed: {e}")

    # ========================================================================
    # Flexible Methods for Subclass Override
    # ========================================================================

    def _build_token_exchange_payload(
            self, authorization_code: str, code_verifier: str, state: str = None, **kwargs
    ) -> Dict[str, Any]:
        """Build token exchange payload"""
        data = {
            "grant_type": "authorization_code",
            "client_id": self.oauth_client_id,
            "code": authorization_code,
            "redirect_uri": self.oauth_redirect_uri,
        }
        if self.use_pkce and code_verifier:
            data["code_verifier"] = code_verifier
        client_secret = getattr(self.credentials, "client_secret", None)
        if client_secret:
            data["client_secret"] = client_secret
        return data

    def _get_token_exchange_headers(self, **kwargs) -> Dict[str, str]:
        """Get token exchange headers with format-aware Content-Type"""
        headers = self._get_auth_headers()
        use_json = kwargs.get("use_json")
        if use_json is None:
            use_json = self._should_use_json_for_token_exchange(**kwargs)
        headers["Content-Type"] = "application/json" if use_json else "application/x-www-form-urlencoded"
        return headers

    def _get_token_exchange_endpoint(self, **kwargs) -> str:
        """Get token exchange endpoint"""
        return self.oauth_token_endpoint

    # ========================================================================
    # Generic Form-Based Login Flow - Fix: Preserve exception chain
    # ========================================================================

    def _perform_generic_form_login(
            self,
            username: str,
            password: str,
            form_selector_pattern: str,
            login_fields: Dict[str, str],
            extra_params: Dict[str, Any] = None,
            additional_form_data: Dict[str, str] = None,
    ) -> Dict[str, Any]:
        """Generic OAuth2 form-based login flow with proper exception handling"""
        auth_url, state, code_verifier = self._build_authorization_url(extra_params)
        session = self._create_oauth_session()

        # Step 1: Get login form
        auth_response = session.get(auth_url, timeout=self.config.timeout)
        auth_response.raise_for_status()

        # Step 2: Extract login form action URL
        form_matches = re.findall(form_selector_pattern, auth_response.text)
        if not form_matches:
            raise Exception(f"Could not find login form using pattern: {form_selector_pattern}")
        login_url = html.unescape(form_matches[0])

        # Step 3: Build login data
        login_data = {}
        if additional_form_data:
            login_data.update(additional_form_data)
        login_data[login_fields.get("username", "username")] = username
        login_data[login_fields.get("password", "password")] = password

        # Step 4: Submit login credentials
        login_response = session.post(
            login_url,
            data=login_data,
            timeout=self.config.timeout,
            allow_redirects=False,
        )

        # Step 5: Handle redirect
        if login_response.status_code in [302, 303]:
            redirect_url = login_response.headers.get("Location")
            if not redirect_url:
                raise Exception("No redirect URL found after login")
        else:
            if "code=" in login_response.url:
                redirect_url = login_response.url
            else:
                raise Exception(
                    f"Login did not produce expected redirect. Status: {login_response.status_code}. "
                    f"Check provider login flow implementation or credentials."
                )

        # Step 6: Validate and extract authorization code
        is_valid, error_msg, authorization_code = self.validate_authentication_response(
            redirect_url, state
        )
        if not is_valid:
            raise Exception(f"Authentication response validation failed: {error_msg}")

        # Step 7: Exchange code for token
        # Fix: Let OAuth2Error propagate; wrap other exceptions with cause chain
        try:
            return self._exchange_authorization_code_for_token(
                authorization_code=authorization_code,
                code_verifier=code_verifier,
                state=state,
            )
        except OAuth2Error:
            raise
        except Exception as e:
            raise Exception(f"OAuth2 form-based login failed: {e}") from e

    # ========================================================================
    # Token Refresh - Fix: Consistent payload encoding + correct endpoint
    # ========================================================================

    def _build_refresh_payload(self) -> Dict[str, Any]:
        """Build refresh token payload - consistent with token exchange"""
        data = {
            "grant_type": "refresh_token",
            "refresh_token": self._current_token.refresh_token,
            "client_id": self.oauth_client_id,
        }
        client_secret = getattr(self.credentials, "client_secret", None)
        if client_secret:
            data["client_secret"] = client_secret
        return data

    def _refresh_oauth_token(self) -> Optional[BaseAuthToken]:
        """
        Token refresh with consistent endpoint and payload handling.

        Uses oauth_token_endpoint to respect OIDC discovery.
        Uses consistent Content-Type logic via _should_use_json_for_token_exchange.
        """
        if not self._current_token or not self._current_token.refresh_token:
            logger.debug(f"No refresh token available for {self.provider_name}")
            return None

        try:
            logger.debug(f"Refreshing OAuth2 token for {self.provider_name}")
            data = self._build_refresh_payload()
            headers = self._get_auth_headers()

            # Apply consistent Content-Type logic
            if self._should_use_json_for_token_exchange():
                headers["Content-Type"] = "application/json"
                request_kwargs = {"json_data": data}
            else:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                request_kwargs = {"data": urlencode(data).encode()}

            # Use oauth_token_endpoint to respect OIDC discovery
            response = self.http_manager.post(
                self.oauth_token_endpoint, operation="auth", headers=headers, **request_kwargs
            )
            self._check_oauth_error_response(response)
            response.raise_for_status()
            new_token_data = response.json()
            refreshed_token = self._create_token_from_response(new_token_data)
            logger.info(f"OAuth2 token refresh successful for {self.provider_name}")
            return refreshed_token
        except OAuth2Error as e:
            logger.warning(f"OAuth2 token refresh failed for {self.provider_name}: {e}")
            return None
        except Exception as e:
            logger.warning(f"OAuth2 token refresh failed for {self.provider_name}: {e}")
            return None

    # ========================================================================
    # Error Response Handling - Fix: Clean error handling
    # ========================================================================

    @staticmethod
    def _check_oauth_error_response(response):
        """Check response for OAuth2 error - no silent swallowing"""
        if response.status_code >= 400:
            try:
                error_data = response.json()
            except ValueError:
                # Not JSON; let raise_for_status() handle it
                return
            if "error" in error_data:
                raise OAuth2Error(
                    error=error_data.get("error"),
                    error_description=error_data.get("error_description"),
                    error_uri=error_data.get("error_uri"),
                )

    # ========================================================================
    # JS Extraction Helpers - Fix: Selective exception handling
    # ========================================================================

    def _extract_from_js(
            self,
            main_page_url: str,
            js_file_pattern: str,
            content_pattern: str,
            parse_function: Optional[Callable[[str], Any]] = None,
            extract_type: str = "value",
    ) -> Optional[Any]:
        """
        Generic helper to extract content from provider's JavaScript.

        Re-raises network/transport errors; only suppresses parsing-related errors.
        """
        try:
            headers = self.config.get_base_headers()
            response = self.http_manager.get(main_page_url, operation="api", headers=headers)
            response.raise_for_status()
            js_matches = re.findall(js_file_pattern, response.text)
            if not js_matches:
                logger.warning(f"Could not find JS file using pattern: {js_file_pattern}")
                return None
            js_url = main_page_url.rstrip("/") + "/" + js_matches[-1].lstrip("/")
            js_response = self.http_manager.get(js_url, operation="api", headers=headers)
            js_response.raise_for_status()
            content_match = re.search(content_pattern, js_response.text)
            if not content_match:
                logger.warning(f"Could not find content using pattern: {content_pattern}")
                return None
            extracted = content_match.group(1)
            if parse_function:
                return parse_function(extracted)
            return extracted
        # Re-raise network/transport errors; only suppress parsing errors
        except (ConnectionError, TimeoutError, OSError) as e:
            logger.error(f"Network error extracting {extract_type} from JS for {self.provider_name}: {e}")
            raise
        except (AttributeError, ValueError, re.error) as e:
            # Parsing/regex errors are recoverable - log and return None
            logger.warning(f"Parse error extracting {extract_type} from JS for {self.provider_name}: {e}")
            return None
        except Exception as e:
            # Log unexpected errors but re-raise to avoid silent failures
            logger.error(f"Unexpected error extracting {extract_type} from JS for {self.provider_name}: {e}")
            raise

    def _extract_client_id_from_js(
            self, main_page_url: str, js_file_pattern: str, client_id_pattern: str
    ) -> Optional[str]:
        """Extract client ID from JavaScript (wrapper)"""
        return self._extract_from_js(
            main_page_url=main_page_url,
            js_file_pattern=js_file_pattern,
            content_pattern=client_id_pattern,
            extract_type="client_id",
        )

    def _extract_config_from_js(
            self,
            main_page_url: str,
            js_file_pattern: str,
            config_pattern: str,
            parse_function: Callable[[str], Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Extract config from JavaScript (wrapper)"""
        return self._extract_from_js(
            main_page_url=main_page_url,
            js_file_pattern=js_file_pattern,
            content_pattern=config_pattern,
            parse_function=parse_function,
            extract_type="config",
        )

    # ========================================================================
    # Token Upgrade Support
    # ========================================================================

    def _should_upgrade_to_user_token(self, token: BaseAuthToken) -> bool:
        """Check if token should be upgraded"""
        return self.should_upgrade_token(token)

    def _get_effective_credentials(self):
        """Get effective credentials with priority resolution"""
        from ...base.auth.credentials import UserPasswordCredentials
        stored_creds = self.settings_manager.get_provider_credentials(self.provider_name)
        if stored_creds and isinstance(stored_creds, UserPasswordCredentials):
            if stored_creds.validate():
                return stored_creds
        if self.credentials and self.credentials.validate():
            return self.credentials
        fallback = self.get_fallback_credentials()
        self.credentials = fallback
        return fallback

    def get_bearer_token(self, force_refresh: bool = False, force_upgrade: bool = False) -> str:
        """Get bearer token with automatic upgrade support"""
        logger.debug(
            f"get_bearer_token called: force_refresh={force_refresh}, force_upgrade={force_upgrade}"
        )
        current_token = self.authenticate(force_refresh=force_refresh)
        if current_token.auth_level == TokenAuthLevel.UNKNOWN:
            current_token.auth_level = self._classify_token(current_token)
            logger.debug(f"Token classified as: {current_token.auth_level.value}")

        # Cache upgrade check result to avoid duplicate calls
        should_upgrade = force_upgrade or self._should_upgrade_to_user_token(current_token)

        if should_upgrade and not force_refresh:
            upgrade_reason = "forced" if force_upgrade else "auto"
            logger.info(f"Token upgrade triggered ({upgrade_reason}) for {self.provider_name}")
            original_credentials = self.credentials
            try:
                self.credentials = self._get_effective_credentials()
                if not self.credentials or not self.credentials.validate():
                    logger.debug("No valid credentials for upgrade")
                    return current_token.bearer_token
                user_token = self._perform_authentication()
                if user_token and not user_token.is_expired:
                    user_token.auth_level = self._classify_token(user_token)
                    if user_token.is_user_authenticated():
                        logger.info("Successfully upgraded to user token")
                        self._current_token = user_token
                        self._save_session()
                        return user_token.bearer_token
                    else:
                        logger.warning(
                            f"Authentication succeeded but token is not user level: {user_token.auth_level.value}"
                        )
                        self.credentials = original_credentials
                        return current_token.bearer_token
                else:
                    logger.warning("User authentication failed, keeping current token")
                    self.credentials = original_credentials
                    return current_token.bearer_token
            except Exception as e:
                logger.error(f"Token upgrade failed: {e}")
                self.credentials = original_credentials
                return current_token.bearer_token
        return current_token.bearer_token if current_token else ""

    # ========================================================================
    # Main Authentication Flow
    # ========================================================================

    def _perform_authentication(self) -> BaseAuthToken:
        """Complete OAuth2 authentication based on credential type"""
        from ...base.auth.credentials import ClientCredentials, UserPasswordCredentials
        logger.debug(
            f"Starting OAuth2 authentication for {self.provider_name} with credential type: {type(self.credentials)}"
        )
        original_credentials = self.credentials
        try:
            if isinstance(self.credentials, UserPasswordCredentials):
                logger.info(f"Attempting OAuth2 user authentication for {self.provider_name}")
                token_data = self._perform_oauth_authorization_code_flow(
                    self.credentials.username, self.credentials.password
                )
            elif isinstance(self.credentials, ClientCredentials):
                logger.info(f"Attempting OAuth2 client credentials authentication for {self.provider_name}")
                token_data = self._perform_oauth_client_credentials_flow()
            else:
                raise Exception(f"Unsupported credential type for OAuth2: {type(self.credentials)}")
            token = self._create_token_from_response(token_data)
            logger.info(f"OAuth2 authentication successful for {self.provider_name}")
            return token
        except Exception as e:
            logger.error(f"Primary OAuth2 authentication failed for {self.provider_name}: {e}")
            if isinstance(original_credentials, UserPasswordCredentials):
                logger.info(f"User authentication failed, falling back to client credentials for {self.provider_name}")
                try:
                    self.credentials = self.get_fallback_credentials()
                    token_data = self._perform_oauth_client_credentials_flow()
                    result = self._create_token_from_response(token_data)
                    logger.info(f"Successfully fell back to client credentials for {self.provider_name}")
                    return result
                except Exception as fallback_error:
                    self.credentials = original_credentials
                    logger.error(
                        f"Fallback to client credentials also failed for {self.provider_name}: {fallback_error}")
                    raise
            else:
                raise e

    # ========================================================================
    # Token Management
    # ========================================================================

    @abstractmethod
    def _create_token_from_response(self, response_data: Dict[str, Any]) -> BaseAuthToken:
        """Create provider-specific token from OAuth2 response"""
        pass

    def _refresh_token(self) -> Optional[BaseAuthToken]:
        """Override base refresh to use manual OAuth2 refresh flow"""
        return self._refresh_oauth_token()

    # ========================================================================
    # Status and Diagnostics - Fix: Defensive endpoint access
    # ========================================================================

    def get_authentication_status(self) -> Dict[str, Any]:
        """Get comprehensive OAuth2 authentication status information"""
        status = super().get_authentication_status()

        # Wrap endpoint property access defensively to avoid triggering
        # OIDC discovery during diagnostic calls, which could hang or throw
        oauth_authorize_ep = "<unavailable>"
        oauth_token_ep = "<unavailable>"
        try:
            oauth_authorize_ep = self.oauth_authorize_endpoint
        except (NotImplementedError, RuntimeError) as e:
            oauth_authorize_ep = f"<unavailable: {type(e).__name__}>"
        try:
            oauth_token_ep = self.oauth_token_endpoint
        except (NotImplementedError, RuntimeError) as e:
            oauth_token_ep = f"<unavailable: {type(e).__name__}>"

        oauth_status = {
            "oauth_client_id": self.oauth_client_id,
            "oauth_scope": self.oauth_scope,
            "oauth_redirect_uri": self.oauth_redirect_uri,
            "oauth_authorize_endpoint": oauth_authorize_ep,
            "oauth_token_endpoint": oauth_token_ep,
            "authentication_flow": "oauth2",
            "pkce_support": self.supports_pkce(),
            "pkce_enabled": self.use_pkce,
            "proxy_support": hasattr(self, "http_manager"),
            "credential_type": type(self.credentials).__name__,
            "has_refresh_token": bool(self._current_token and self._current_token.refresh_token),
            "oidc_discovery_enabled": self._enable_oidc_discovery,
        }

        if self._enable_oidc_discovery:
            config = self._oidc_config
            oauth_status["oidc_config_cached"] = config is not None
            if config:
                oauth_status["oidc_issuer"] = config.issuer
                oauth_status["oidc_grant_types"] = config.grant_types_supported
                oauth_status["oidc_pkce_methods"] = config.code_challenge_methods_supported
            oauth_status["oidc_discovery_stats"] = self.get_oidc_discovery_stats()

        if self._current_token:
            oauth_status.update({
                "token_expires_in": self._current_token.expires_in,
                "token_issued_at": self._current_token.issued_at,
                "token_is_expired": self._current_token.is_expired,
                "token_needs_refresh": self._current_token.needs_refresh(),
            })

        status.update(oauth_status)
        return status

    # ========================================================================
    # Utility Methods
    # ========================================================================

    @staticmethod
    def extract_authorization_code_from_url(url: str) -> Optional[str]:
        """Extract authorization code from callback URL"""
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            return query_params.get("code", [None])[0]
        except Exception as e:
            logger.error(f"Error extracting authorization code from URL: {e}")
            return None

    def validate_authentication_response(
            self, url: str, original_state: str
    ) -> tuple[bool, Optional[str], Optional[str]]:
        """Validate OAuth2 authentication response"""
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            if "error" in query_params:
                error = query_params["error"][0]
                error_description = query_params.get("error_description", [""])[0]
                return False, f"{error}: {error_description}", None
            received_state = query_params.get("state", [None])[0]
            if not self.validate_oauth_state(received_state, original_state):
                return False, "State validation failed", None
            authorization_code = query_params.get("code", [None])[0]
            if not authorization_code:
                return False, "No authorization code in response", None
            return True, None, authorization_code
        except Exception as e:
            return False, f"Error processing authentication response: {e}", None

    # ========================================================================
    # Abstract Method
    # ========================================================================

    @abstractmethod
    def _perform_oauth_authorization_code_flow(
            self, username: str, password: str
    ) -> Dict[str, Any]:
        """Perform OAuth2 authorization code flow with PKCE for user login"""
        pass