# streaming_providers/providers/joyn/auth.py
# -*- coding: utf-8 -*-
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse

from ...base.auth.base_auth import BaseAuthToken, TokenAuthLevel
from ...base.auth.base_oauth2_auth import BaseOAuth2Authenticator
from ...base.auth.credentials import ClientCredentials
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger
from .constants import (
    COUNTRY_TENANT_MAPPING,
    DEFAULT_COUNTRY,
    DEFAULT_PLATFORM,
    DEFAULT_REQUEST_TIMEOUT,
    DEVICE_IDS,
    JOYN_AUTH_ENDPOINTS,
    JOYN_CLIENT_VERSION,
    JOYN_DOMAINS,
    JOYN_OAUTH_SCOPE,
    JOYN_SSO_DISCOVERY_URL,
    JOYN_USER_AGENT,
    SUPPORTED_COUNTRIES,
)


class JoynSSODiscovery:
    """Service to discover SSO endpoints dynamically"""

    def __init__(
        self,
        http_manager,
        country: str = DEFAULT_COUNTRY,
        platform: str = DEFAULT_PLATFORM,
    ):
        self.http_manager = http_manager
        self.country = country
        self.platform = platform
        self._endpoints_cache = None
        self._cache_timestamp = None
        self._cache_ttl = 3600  # 1 hour cache

    @staticmethod
    def get_fallback_endpoints() -> Dict[str, str]:
        """Fallback endpoints if discovery fails"""
        return {
            "device-login": "https://sso.joyn.de/ci",
            "device-register": "https://sso.joyn.de/cr",
            "web-login": "https://auth.7pass.de/authz-srv/authz",
            "redeem-token": "https://auth.joyn.de/auth/7pass/token",
        }

    def get_endpoints(self, force_refresh: bool = False) -> Dict[str, str]:
        """Get SSO endpoints, with caching"""
        if (
            self._endpoints_cache
            and not force_refresh
            and time.time() - self._cache_timestamp < self._cache_ttl
        ):
            return self._endpoints_cache

        try:
            params = {
                "client_id": DEVICE_IDS[self.platform],
                "client_name": self.platform,
            }

            response = self.http_manager.get(
                JOYN_SSO_DISCOVERY_URL, operation="sso_discovery", params=params
            )
            response.raise_for_status()

            self._endpoints_cache = response.json()
            self._cache_timestamp = time.time()
            logger.debug(
                f"SSO discovery successful, endpoints: {list(self._endpoints_cache.keys())}"
            )
            return self._endpoints_cache

        except Exception as e:
            # Fallback to hardcoded endpoints if discovery fails
            logger.warning(f"SSO discovery failed, using fallback: {e}")
            return self.get_fallback_endpoints()

    def get_auth_endpoint(self, auth_type: str = None) -> str:
        """Get specific auth endpoint by type"""
        # If no auth_type specified, use platform-specific login endpoint
        if auth_type is None:
            auth_type = f"{self.platform}-login"

        endpoints = self.get_endpoints()
        endpoint = endpoints.get(auth_type)
        if not endpoint:
            logger.warning(f"Auth endpoint '{auth_type}' not found, using fallback")
            fallback = self.get_fallback_endpoints()
            # Try platform-specific first, then generic web-login
            endpoint = (
                fallback.get(auth_type)
                or fallback.get(f"{self.platform}-login")
                or fallback.get("web-login", "")
            )
        return endpoint


@dataclass
class JoynCredentials(ClientCredentials):
    """
    Joyn-specific credentials for client credentials flow (anonymous auth)
    """

    client_name: str = DEFAULT_PLATFORM
    country: str = DEFAULT_COUNTRY
    distribution_tenant: Optional[str] = field(default=None)

    def __post_init__(self):
        # Set client_id from constant if not provided
        if not self.client_id:
            self.client_id = DEVICE_IDS.get(self.client_name, DEVICE_IDS[DEFAULT_PLATFORM])

        if not self.distribution_tenant and self.country in COUNTRY_TENANT_MAPPING:
            self.distribution_tenant = COUNTRY_TENANT_MAPPING[self.country]

    def validate(self) -> bool:
        """Validate Joyn credentials"""
        if not self.client_id or not self.client_name:
            return False
        if self.country not in SUPPORTED_COUNTRIES:
            return False
        return True

    def to_auth_payload(self) -> Dict[str, Any]:
        """Convert to authentication payload for Joyn's anonymous auth endpoint"""
        return {
            "client_id": self.client_id,
            "client_name": self.client_name,
            "anon_device_id": str(uuid.uuid4()),
        }

    @property
    def credential_type(self) -> str:
        return "joyn_client_credentials"


@dataclass
class JoynAuthToken(BaseAuthToken):
    """
    Joyn-specific authentication token
    """

    refresh_token: Optional[str] = field(default="")

    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary"""
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token or "",
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "issued_at": self.issued_at,
        }

    def get_jwt_claims(self) -> Optional[Dict[str, Any]]:
        """Extract JWT claims from access token for debugging and classification"""
        try:
            if not self.access_token:
                return None

            parts = self.access_token.split(".")
            if len(parts) != 3:
                return None

            import base64
            import json

            payload_b64 = parts[1]
            padding = len(payload_b64) % 4
            if padding:
                payload_b64 += "=" * (4 - padding)

            payload_json = base64.b64decode(payload_b64).decode("utf-8")
            return json.loads(payload_json)

        except Exception as e:
            logger.debug(f"Failed to extract JWT claims: {e}")
            return None


class JoynAuthConfig:
    """Configuration object for Joyn authentication with dynamic endpoints"""

    def __init__(
        self,
        country: str,
        distribution_tenant: str,
        http_manager,
        platform: str = DEFAULT_PLATFORM,
    ):
        self.country = country
        self.distribution_tenant = distribution_tenant
        self.platform = platform
        self.user_agent = JOYN_USER_AGENT
        self.timeout = DEFAULT_REQUEST_TIMEOUT
        self.http_manager = http_manager

        # Only create SSO discovery if we have http_manager
        if http_manager is not None:
            self.sso_discovery = JoynSSODiscovery(http_manager, country, platform)
        else:
            self.sso_discovery = None

    def get_token_redeem_endpoint(self) -> str:
        """Get token redemption endpoint for user login flows"""
        if self.sso_discovery:
            return self.sso_discovery.get_auth_endpoint("redeem-token")
        # Fallback if SSO discovery not available
        return JoynSSODiscovery.get_fallback_endpoints()["redeem-token"]

    def get_authorize_endpoint(self) -> str:
        """Get authorization endpoint for OAuth2 flow"""
        if self.sso_discovery:
            # Try platform-specific login endpoint first
            return self.sso_discovery.get_auth_endpoint(f"{self.platform}-login")
        # Fallback if SSO discovery not available - try platform-specific, then web-login
        fallback = JoynSSODiscovery.get_fallback_endpoints()
        return fallback.get(f"{self.platform}-login") or fallback.get("web-login", "")

    def get_base_headers(self) -> Dict[str, str]:
        """Get base headers for all requests"""
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": JOYN_DOMAINS.get(self.country, JOYN_DOMAINS["de"]),
        }

    def get_auth_headers(self) -> Dict[str, str]:
        """Get headers for authentication requests"""
        headers = self.get_base_headers()
        headers.update(
            {
                "joyn-client-version": JOYN_CLIENT_VERSION,
                "joyn-country": self.country.upper(),
                "joyn-distribution-tenant": self.distribution_tenant,
                "joyn-platform": self.platform,
                "joyn-request-id": str(uuid.uuid4()),
            }
        )
        return headers


class JoynAuthenticator(BaseOAuth2Authenticator):
    """
    Joyn authenticator using OAuth2 client credentials flow with dynamic endpoints
    """

    def __init__(
        self,
        country: str = DEFAULT_COUNTRY,
        platform: str = DEFAULT_PLATFORM,
        settings_manager=None,
        credentials=None,
        config_dir: Optional[str] = None,
        http_manager=None,
        proxy_config: Optional[ProxyConfig] = None,
    ):
        """
        Initialize authenticator for specific country
        """
        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(
                f"Unsupported country: {country}. Must be one of: {SUPPORTED_COUNTRIES}"
            )

        # Validate that http_manager is provided
        if http_manager is None:
            raise ValueError(
                "http_manager is required for JoynAuthenticator. "
                "It should be created in JoynProvider and passed to the authenticator."
            )

        # Set country-specific attributes FIRST
        self.country = country
        self.platform = platform
        self.distribution_tenant = COUNTRY_TENANT_MAPPING[country]

        # Store http_manager reference (provided by JoynProvider)
        self._http_manager = http_manager

        # Setup Joyn-specific config BEFORE super().__init__
        self._config = JoynAuthConfig(
            self.country, self.distribution_tenant, self._http_manager, self.platform
        )

        # Extract and cache client_id during initialization
        self._client_id = self._extract_client_id_from_endpoints()

        # NOW call parent __init__ - config, http_manager AND country are ready
        super().__init__(
            provider_name="joyn",
            settings_manager=settings_manager,
            credentials=credentials,
            country=country,
            config_dir=config_dir,
            enable_kodi_integration=True,
            http_manager=self._http_manager,
            proxy_config=proxy_config,
        )

    def _get_joyn_auth_headers(self) -> Dict[str, str]:
        """Get standardized Joyn authentication headers"""
        from .constants import JOYN_AUTH_HEADERS_BASE

        headers = JOYN_AUTH_HEADERS_BASE.copy()
        headers["Origin"] = f"https://www.joyn.{self.country.lower()}"
        headers.update(
            {
                "joyn-country": self.country.upper(),
                "joyn-distribution-tenant": self.distribution_tenant,
                "joyn-platform": self.platform,  # Using self.platform
                "joyn-request-id": str(uuid.uuid4()),
            }
        )
        return headers

    def _extract_client_id_from_endpoints(self) -> str:
        """Extract client_id from SSO endpoints during initialization"""
        try:
            # Get endpoints from SSO discovery
            endpoints = self._config.sso_discovery.get_endpoints()

            # Get the platform-specific login endpoint
            platform_key = f"{self.platform}-login"
            login_url = endpoints.get(platform_key)

            if not login_url:
                logger.warning(
                    f"No {platform_key} endpoint found, trying generic web-login as fallback"
                )
                login_url = endpoints.get("web-login")

            if not login_url:
                raise Exception(
                    f"No login endpoint found for platform '{self.platform}' or generic 'web-login' in SSO discovery"
                )

            # Extract client_id from the URL parameters
            parsed_url = urlparse(login_url)
            query_params = parse_qs(parsed_url.query)

            client_id = query_params.get("client_id", [None])[0]

            if not client_id:
                raise Exception("No client_id found in login endpoint")

            logger.debug(f"Extracted and cached client_id for {self.platform}: {client_id}")
            return client_id

        except Exception as e:
            logger.error(
                f"Error extracting client_id from endpoints: {e}, using fallback: {DEVICE_IDS.get(self.platform, DEVICE_IDS[DEFAULT_PLATFORM])}"
            )
            return DEVICE_IDS.get(self.platform, DEVICE_IDS[DEFAULT_PLATFORM])

    @property
    def oauth_client_id(self) -> str:
        """Get OAuth2 client ID - uses cached value from initialization"""
        return self._client_id

    @property
    def oauth_scope(self) -> str:
        """OAuth2 scopes for authorization code flow"""
        return JOYN_OAUTH_SCOPE

    @property
    def oauth_redirect_uri(self) -> str:
        """OAuth2 redirect URI - country-specific"""
        from .constants import get_oauth_redirect_uri

        return get_oauth_redirect_uri(self.country)

    @property
    def auth_endpoint(self) -> str:
        """Authentication endpoint URL - dynamic based on flow"""
        from ...base.auth.credentials import UserPasswordCredentials

        if isinstance(self.credentials, UserPasswordCredentials):
            # For authorization code flow - use token endpoint from SSO discovery
            return self._config.get_token_redeem_endpoint()
        else:
            # For client credentials flow - use anonymous endpoint
            return JOYN_AUTH_ENDPOINTS["ANONYMOUS"]

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers for authentication request"""
        return self._config.get_auth_headers()

    def _build_auth_payload(self) -> Dict[str, Any]:
        """Build authentication payload - only used for client credentials flow"""
        if not self.credentials:
            raise Exception("No credentials available")
        return self.credentials.to_auth_payload()

    def _create_token_from_response(self, response_data: Dict[str, Any]) -> BaseAuthToken:
        """Create token object from API response"""
        token = JoynAuthToken(
            access_token=response_data["access_token"],
            refresh_token=response_data.get("refresh_token", ""),
            token_type=response_data.get("token_type", "Bearer"),
            expires_in=response_data.get("expires_in", 86400),
            issued_at=response_data.get("issued_at", time.time()),
        )

        # ALWAYS classify immediately when creating from response
        token.auth_level = self._classify_token(token)
        logger.debug(f"Token created and classified as: {token.auth_level.value}")

        return token

    def get_fallback_credentials(self) -> JoynCredentials:
        """Get fallback credentials when no user credentials are available"""
        return JoynCredentials(
            client_id=self._client_id,
            client_secret="",  # Joyn doesn't use client_secret
            country=self.country,
        )

    def get_token_redeem_url(self) -> str:
        """Get token redemption URL for OAuth flows"""
        return self._config.get_token_redeem_endpoint()

    # MAIN AUTHENTICATION METHOD - UPDATED to handle both flows
    def _perform_authentication(self) -> BaseAuthToken:
        """
        Perform authentication using appropriate flow based on credential type
        """
        from ...base.auth.credentials import ClientCredentials, UserPasswordCredentials

        if isinstance(self.credentials, UserPasswordCredentials):
            # Use OAuth2 authorization code flow with PKCE
            logger.info(f"Using OAuth2 authorization code flow for {self.provider_name}")
            token_data = self._perform_oauth_authorization_code_flow(
                self.credentials.username, self.credentials.password
            )
        elif isinstance(self.credentials, ClientCredentials):
            # Use client credentials flow (anonymous auth)
            logger.info(f"Using OAuth2 client credentials flow for {self.provider_name}")
            token_data = self._perform_oauth_client_credentials_flow()
        else:
            raise Exception(
                f"Unsupported credential type for {self.provider_name}: {type(self.credentials)}"
            )

        return self._create_token_from_response(token_data)

    # Client credentials flow implementation - KEEP EXISTING
    def _perform_oauth_client_credentials_flow(self) -> Dict[str, Any]:
        """
        Client credentials flow because Joyn uses JSON instead of form data
        """
        try:
            logger.debug(f"Starting Joyn-specific OAuth2 client credentials flow")

            headers = self._get_auth_headers()
            payload = self._build_auth_payload()

            logger.debug(headers)
            logger.debug(payload)
            # Joyn expects JSON, not form-encoded data
            response = self.http_manager.post(
                self.auth_endpoint,
                operation="auth",
                headers=headers,
                json_data=payload,  # JSON instead of form data
            )

            self._check_oauth_error_response(response)
            response.raise_for_status()

            token_data = response.json()
            logger.debug(f"OAuth2 client credentials flow successful for {self.provider_name}")
            return token_data

        except Exception as e:
            logger.error(
                f"OAuth2 client credentials flow on endpoint {self.auth_endpoint} failed for {self.provider_name}: {e}"
            )
            raise Exception(f"OAuth2 client credentials flow failed: {e}")

    def _perform_two_step_verification(
        self, session, username: str, password: str, request_id: str, referer_url: str
    ) -> tuple[str, str]:
        """
        Perform the two-step verification process using constants
        Returns: (final_sub, final_status_id)
        """
        from .constants import JOYN_CIDAAS_ENDPOINTS, JOYN_USER_AGENT

        # Common headers for verification requests
        verification_headers = {
            "User-Agent": JOYN_USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": "https://signin.7pass.de",
            "Referer": referer_url,
        }

        # Step 1: Initiate password verification
        initiate_data = {
            "request_id": request_id,
            "email": username,
            "medium_id": "PASSWORD",
            "usage_type": "PASSWORDLESS_AUTHENTICATION",
            "type": "PASSWORD",
        }

        logger.debug("Step 1: Initiating password verification")
        initiate_response = session.post(
            JOYN_CIDAAS_ENDPOINTS["VERIFICATION_INITIATE"],
            json_data=initiate_data,
            headers=verification_headers,
            timeout=self._config.timeout,
        )

        logger.debug(f"Initiate response status: {initiate_response.status_code}")
        initiate_response.raise_for_status()
        initiate_result = initiate_response.json()

        if not initiate_result.get("success"):
            raise Exception(f"Password verification initiation failed: {initiate_result}")

        exchange_data = initiate_result["data"]
        exchange_id = exchange_data["exchange_id"]["exchange_id"]
        sub = exchange_data["sub"]
        status_id = exchange_data["status_id"]

        logger.debug(f"Got exchange_id: {exchange_id}, sub: {sub}, status_id: {status_id}")

        # Step 2: Authenticate with password
        authenticate_data = {
            "exchange_id": exchange_id,
            "pass_code": password,
            "sub": sub,  # Use sub from first response
            "type": "PASSWORD",
            "password": password,
        }

        logger.debug("Step 2: Authenticating with password")
        authenticate_response = session.post(
            JOYN_CIDAAS_ENDPOINTS["VERIFICATION_AUTHENTICATE"],
            json_data=authenticate_data,
            headers=verification_headers,
            timeout=self._config.timeout,
        )

        logger.debug(f"Authenticate response status: {authenticate_response.status_code}")
        authenticate_response.raise_for_status()
        authenticate_result = authenticate_response.json()

        if not authenticate_result.get("success"):
            raise Exception(f"Password authentication failed: {authenticate_result}")

        auth_exchange_data = authenticate_result["data"]
        final_sub = auth_exchange_data["sub"]  # Use sub from second response
        final_status_id = auth_exchange_data["status_id"]

        logger.debug(f"Got final sub: {final_sub}, final_status_id: {final_status_id}")
        return final_sub, final_status_id

    def _perform_final_login(
        self, session, final_sub: str, final_status_id: str, request_id: str
    ) -> bool:
        """
        Perform the final login with verification results using constants
        Returns: True if successful
        """
        from .constants import JOYN_CIDAAS_ENDPOINTS, JOYN_USER_AGENT

        login_data = {
            "sub": final_sub,
            "status_id": final_status_id,
            "verificationType": "PASSWORD",
            "requestId": request_id,
            "remember_me": "true",
        }

        login_headers = {
            "User-Agent": JOYN_USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://signin.7pass.de",
        }

        logger.debug("Step 3: Final login with verification results")
        login_response = session.post(
            JOYN_CIDAAS_ENDPOINTS["LOGIN_VERIFICATION"],
            data=urlencode(login_data).encode(),
            headers=login_headers,
            timeout=self._config.timeout,
            allow_redirects=False,
        )

        logger.debug(f"Login response status: {login_response.status_code}")
        login_response.raise_for_status()

        return login_response.status_code in [200, 302, 303]

    @staticmethod
    def _extract_authorization_code(session) -> Optional[str]:
        """
        Extract authorization code from redirect chain
        Follows redirects until we find the authorization code or reach max redirects
        """

        max_redirects = 5
        current_redirects = 0

        # Start with the current session state and follow redirects
        while current_redirects < max_redirects:
            current_redirects += 1

            # Get the current URL from session (you might need to track this)
            # For now, we'll assume we need to handle the redirect from the login response

            # Check if we have a Location header to follow
            # This is a simplified version - you'll need to adapt based on actual response

            # Check current URL for authorization code
            current_url = getattr(session, "last_url", None)  # You'd need to track this

            if current_url:
                parsed_url = urlparse(current_url)
                query_params = parse_qs(parsed_url.query)
                auth_code = query_params.get("code", [None])[0]

                if auth_code:
                    logger.debug(f"Found authorization code in URL: {auth_code}")
                    return auth_code

                # Also check fragment for SPA redirects
                if "#" in current_url:
                    fragment = current_url.split("#")[1]
                    fragment_params = parse_qs(fragment)
                    auth_code = fragment_params.get("code", [None])[0]
                    if auth_code:
                        logger.debug(f"Found authorization code in fragment: {auth_code}")
                        return auth_code

            # If no code found, try to follow redirects
            # You'll need to implement this based on how your session tracks redirects

        logger.warning(
            f"Reached max redirects ({max_redirects}) without finding authorization code"
        )
        return None

    # Authorization code flow - Joyn-specific implementation
    def _perform_oauth_authorization_code_flow(
        self, username: str, password: str
    ) -> Dict[str, Any]:
        """
        Optimized Joyn OAuth2 authorization code flow with two-step verification
        Handles both cases: existing session (direct redirect) and new login (form-based)
        """
        try:
            logger.debug("Starting optimized Joyn OAuth2 authorization code flow")

            # Step 1: Get authorization endpoint and build URL
            web_login_url = self._config.get_authorize_endpoint()
            logger.debug(f"Using authorize endpoint: {web_login_url}")

            # Build authorization URL with PKCE
            code_verifier = self.generate_pkce_verifier()
            code_challenge = self.generate_pkce_challenge(code_verifier)
            state = self.generate_oauth_state()

            params = {
                "response_type": "code",
                "client_id": self.oauth_client_id,
                "redirect_uri": self.oauth_redirect_uri,
                "scope": self.oauth_scope,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "response_mode": "query",
                "view_type": "login",
                "prompt": "consent",
                "cd1": str(uuid.uuid4()),
            }

            authorization_url = f"{web_login_url}?{urlencode(params)}"
            logger.debug(f"Built authorization URL: {authorization_url}")

            session = self._create_oauth_session()

            # Step 2: Get authorization page
            logger.debug("Fetching authorization page")
            auth_response = session.get(authorization_url, timeout=self._config.timeout)

            logger.debug(f"Authorization page response status: {auth_response.status_code}")
            logger.debug(f"Authorization page response URL: {auth_response.url}")

            auth_response.raise_for_status()

            # Step 2a: Check if we got redirected directly to callback (existing session)
            if self.oauth_redirect_uri in auth_response.url:
                logger.info("User already authenticated - extracting code from redirect")

                # Parse the redirect URL for authorization code
                parsed_url = urlparse(auth_response.url)
                query_params = parse_qs(parsed_url.query)

                auth_code = query_params.get("code", [None])[0]
                received_state = query_params.get("state", [None])[0]

                if not auth_code:
                    raise Exception("Redirect to callback but no authorization code found")

                if not self.validate_oauth_state(received_state, state):
                    raise Exception("State validation failed on direct redirect")

                logger.debug(f"Extracted authorization code from direct redirect: {auth_code}")

                # Exchange code for token
                logger.debug("Exchanging authorization code for tokens")
                token_data = self._exchange_authorization_code_for_token(
                    authorization_code=auth_code,
                    code_verifier=code_verifier,
                    state=state,
                )

                logger.debug("Joyn OAuth2 authorization code flow successful (existing session)")
                return token_data

            # Step 2b: No existing session - need to perform login
            logger.info("No existing session - performing form-based login")

            # Extract request_id from the response
            parsed_url = urlparse(auth_response.url)
            query_params = parse_qs(parsed_url.query)
            request_id = query_params.get("requestId", [None])[0]

            if not request_id:
                # Fallback: try to extract from response body
                request_id_match = re.search(
                    r'requestId["\']?\s*:\s*["\']([^"\']+)', auth_response.text
                )
                if request_id_match:
                    request_id = request_id_match.group(1)
                else:
                    raise Exception("Could not extract request_id from authorization page")

            logger.debug(f"Extracted request_id: {request_id}")

            # Step 3: Two-step verification process
            final_sub, final_status_id = self._perform_two_step_verification(
                session, username, password, request_id, auth_response.url
            )

            # Step 4: Final login with verification results
            login_success = self._perform_final_login(
                session, final_sub, final_status_id, request_id
            )

            if not login_success:
                raise Exception("Final login failed")

            # Step 5: Extract authorization code from redirect
            auth_code = self._extract_authorization_code(session)

            if not auth_code:
                raise Exception("Could not extract authorization code from login flow")

            logger.debug(f"Extracted authorization code: {auth_code}")

            # Step 6: Exchange authorization code for tokens
            logger.debug("Exchanging authorization code for tokens")
            token_data = self._exchange_authorization_code_for_token(
                authorization_code=auth_code, code_verifier=code_verifier, state=state
            )

            logger.debug("Joyn OAuth2 authorization code flow successful (form login)")
            return token_data

        except Exception as e:
            logger.error(f"Joyn OAuth2 authorization code flow failed: {e}")
            raise Exception(f"OAuth2 authorization code flow failed: {e}")

    def _build_token_exchange_payload(
        self, authorization_code: str, code_verifier: str, state: str = None, **kwargs
    ) -> Dict[str, Any]:
        """Joyn-specific token exchange payload"""
        return {
            "code": authorization_code,
            "client_id": self.oauth_client_id,
            "redirect_uri": self.oauth_redirect_uri,
            "tracking_id": str(uuid.uuid4()),
            "tracking_name": self.platform,
            "code_verifier": code_verifier,
            # No grant_type for Joyn
        }

    def _get_token_exchange_endpoint(self, **kwargs) -> str:
        """Joyn-specific token exchange endpoint"""
        token_endpoint = self._config.get_token_redeem_endpoint()
        logger.debug(f"Using dynamic token endpoint: {token_endpoint}")
        return token_endpoint

    def _get_token_exchange_headers(self, **kwargs) -> Dict[str, str]:
        return self._get_joyn_auth_headers()

    def _should_use_json_for_token_exchange(self, **kwargs) -> bool:
        """Joyn uses JSON instead of form-encoded"""
        return True

    # Refresh token - KEEP EXISTING
    def _refresh_oauth_token(self) -> Optional[BaseAuthToken]:
        """Joyn-specific token refresh implementation"""
        if not self._current_token or not self._current_token.refresh_token:
            logger.debug(f"No refresh token available for {self.provider_name}")
            return None

        try:
            logger.debug(f"Refreshing OAuth2 token for {self.provider_name}")

            # Use DEVICE_IDS directly instead of oauth_client_id
            # Joyn refresh might need the platform-specific device ID, not the OAuth client ID
            payload = {
                "client_id": DEVICE_IDS.get(self.platform, DEVICE_IDS[DEFAULT_PLATFORM]),
                "client_name": self.platform,
                "grant_type": "Bearer",  # Joyn uses 'Bearer' instead of 'refresh_token'
                "refresh_token": self._current_token.refresh_token,
            }

            headers = self._get_joyn_auth_headers()

            # Use the refresh-specific endpoint
            refresh_endpoint = JOYN_AUTH_ENDPOINTS["REFRESH"]

            logger.debug(f"Refresh payload: {payload}")
            logger.debug(f"Refresh headers: {headers}")

            response = self.http_manager.post(
                refresh_endpoint,
                operation="auth",
                headers=headers,
                json_data=payload,  # JSON format
                timeout=self._config.timeout,
            )

            # Log response for debugging
            logger.debug(f"Refresh response status: {response.status_code}")
            if response.status_code >= 400:
                logger.error(f"Refresh error response: {response.text}")

            response.raise_for_status()

            new_token_data = response.json()
            refreshed_token = self._create_token_from_response(new_token_data)
            logger.info(f"OAuth2 token refresh successful for {self.provider_name}")
            return refreshed_token

        except Exception as e:
            logger.warning(f"OAuth2 token refresh failed for {self.provider_name}: {e}")
            return None

    # Backward compatibility methods
    def is_authenticated(self) -> bool:
        """Check if currently authenticated with valid token"""
        return self._current_token is not None and not self._current_token.is_expired

    def invalidate_token(self) -> None:
        """Invalidate current token (forces re-authentication on next request)"""
        self._current_token = None
        try:
            self.settings_manager.clear_token(self.provider_name)
        except (AttributeError, KeyError, IOError, OSError):
            # AttributeError: settings_manager is None
            # KeyError: provider_name not found in settings
            # IOError/OSError: filesystem errors when clearing token
            pass

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        """
        Classify Joyn token based on JWT claims and token structure

        Args:
            token: JoynAuthToken to classify

        Returns:
            TokenAuthLevel indicating authentication level
        """
        try:
            if not token or not token.access_token:
                return TokenAuthLevel.UNKNOWN

            # Parse JWT token to extract claims
            try:
                # JWT tokens are in format: header.payload.signature
                parts = token.access_token.split(".")
                if len(parts) != 3:
                    logger.warning(f"Invalid JWT format for token classification")
                    return TokenAuthLevel.UNKNOWN

                import base64
                import json

                # Decode payload (second part)
                payload_b64 = parts[1]
                # Add padding if needed
                padding = len(payload_b64) % 4
                if padding:
                    payload_b64 += "=" * (4 - padding)

                payload_json = base64.b64decode(payload_b64).decode("utf-8")
                claims = json.loads(payload_json)

                logger.debug(
                    f"JWT claims for classification: { {k: v for k, v in claims.items() if k not in ['access_token', 'refresh_token']} }"
                )

            except Exception as e:
                logger.warning(f"Failed to parse JWT for classification: {e}")
                return TokenAuthLevel.UNKNOWN

            # Classification logic based on your analysis:

            # 1. Check jIdC prefix - most reliable indicator
            jidc = claims.get("jIdC", "")
            if jidc.startswith("JNAA-"):
                logger.debug("Token classified as CLIENT_CREDENTIALS (JNAA prefix)")
                return TokenAuthLevel.CLIENT_CREDENTIALS
            elif jidc.startswith("JNDE-"):
                logger.debug("Token classified as USER_AUTHENTICATED (JNDE prefix)")
                return TokenAuthLevel.USER_AUTHENTICATED

            # 2. Check for social_id presence - clear indicator of user authentication
            if "social_id" in claims:
                logger.debug("Token classified as USER_AUTHENTICATED (social_id present)")
                return TokenAuthLevel.USER_AUTHENTICATED

            # 3. Check client ID (cId) against known client IDs
            client_id = claims.get("cId", "")
            known_client_ids = {
                DEVICE_IDS["web"],  # Web client
                DEVICE_IDS["android"],  # Android client
                DEVICE_IDS["ios"],  # iOS client
            }

            if client_id in known_client_ids:
                logger.debug("Token classified as CLIENT_CREDENTIALS (known client ID)")
                return TokenAuthLevel.CLIENT_CREDENTIALS

            # 4. Check for anonymous device patterns in subject (sub)
            subject = claims.get("sub", "")
            if subject and len(subject) == 36:  # UUID format
                # Client credentials tokens often have UUID subjects representing the client
                # User tokens might have different patterns or include user identifiers
                logger.debug("Token classified as CLIENT_CREDENTIALS (UUID subject pattern)")
                return TokenAuthLevel.CLIENT_CREDENTIALS

            # 5. Fallback: Check token scope or other claims
            scope = claims.get("scope", "")
            if scope:
                scopes = scope.split()
                if "offline_access" in scopes and "profile" in scopes:
                    logger.debug("Token classified as USER_AUTHENTICATED (user scopes present)")
                    return TokenAuthLevel.USER_AUTHENTICATED
                elif "openid" in scopes and len(scopes) <= 2:
                    logger.debug("Token classified as CLIENT_CREDENTIALS (minimal scopes)")
                    return TokenAuthLevel.CLIENT_CREDENTIALS

            logger.warning(f"Could not definitively classify token, using UNKNOWN")
            return TokenAuthLevel.UNKNOWN

        except Exception as e:
            logger.error(f"Error classifying token: {e}")
            return TokenAuthLevel.UNKNOWN

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
            "jwt_claims_available": bool(claims),
            "key_claims": (
                {
                    "jIdC": claims.get("jIdC", "MISSING"),
                    "cId": claims.get("cId", "MISSING"),
                    "social_id": "PRESENT" if "social_id" in claims else "MISSING",
                    "sub": (
                        claims.get("sub", "MISSING")[:8] + "..." if claims.get("sub") else "MISSING"
                    ),
                    "scope": claims.get("scope", "MISSING"),
                }
                if claims
                else {}
            ),
        }
