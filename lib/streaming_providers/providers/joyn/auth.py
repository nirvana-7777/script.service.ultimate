# streaming_providers/providers/joyn/auth.py
# -*- coding: utf-8 -*-
import base64
import json
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
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_MAX_RETRIES,
    DEFAULT_PLATFORM,
    DEVICE_IDS,
    JOYN_7PASS_BASE_URL,
    JOYN_7PASS_ENDPOINTS,
    JOYN_AUTH_ENDPOINTS,
    JOYN_AUTH_HEADERS_BASE,
    JOYN_CLIENT_VERSION,
    JOYN_DOMAINS,
    JOYN_OAUTH_SCOPE,
    JOYN_USER_AGENT,
    SUPPORTED_COUNTRIES,
)


@dataclass
class JoynCredentials(ClientCredentials):
    """Joyn-specific credentials for client credentials flow (anonymous auth)"""
    client_name: str = DEFAULT_PLATFORM
    country: str = DEFAULT_COUNTRY
    distribution_tenant: Optional[str] = field(default=None)

    def __post_init__(self):
        if not self.client_id:
            self.client_id = DEVICE_IDS.get(self.client_name, DEVICE_IDS[DEFAULT_PLATFORM])
        if not self.distribution_tenant and self.country in COUNTRY_TENANT_MAPPING:
            self.distribution_tenant = COUNTRY_TENANT_MAPPING[self.country]

    def validate(self) -> bool:
        return bool(self.client_id and self.client_name and self.country in SUPPORTED_COUNTRIES)

    def to_auth_payload(self) -> Dict[str, Any]:
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
    """Joyn-specific authentication token"""
    refresh_token: Optional[str] = field(default="")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token or "",
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "issued_at": self.issued_at,
        }

    def get_jwt_claims(self) -> Optional[Dict[str, Any]]:
        """Extract JWT claims from access token for classification"""
        try:
            if not self.access_token:
                return None
            parts = self.access_token.split(".")
            if len(parts) != 3:
                return None
            payload_b64 = parts[1]
            padding = len(payload_b64) % 4
            if padding:
                payload_b64 += "=" * (4 - padding)
            payload_json = base64.b64decode(payload_b64).decode("utf-8")
            return json.loads(payload_json)
        except Exception as e:
            logger.debug(f"Failed to extract JWT claims: {e}")
            return None


class JoynAuthenticator(BaseOAuth2Authenticator):
    """
    Joyn authenticator using OIDC discovery + custom 7pass login flow.

    Production-hardened: respects base class abstractions, proper exception chains,
    consistent endpoint handling, and clean session management.
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
        # Validate inputs
        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(f"Unsupported country: {country}. Must be one of: {SUPPORTED_COUNTRIES}")
        if http_manager is None:
            raise ValueError("http_manager is required for JoynAuthenticator")

        # Store Joyn-specific attributes
        self.country = country
        self.platform = platform
        self.distribution_tenant = COUNTRY_TENANT_MAPPING[country]

        # Initialize base class first
        super().__init__(
            provider_name="joyn",
            settings_manager=settings_manager,
            credentials=credentials,
            country=country,
            config_dir=config_dir,
            enable_kodi_integration=True,
            http_manager=http_manager,
            proxy_config=proxy_config,
        )

        # Now set up the config object that the base class expects
        # Create a config object with the required methods
        class JoynConfig:
            def __init__(self, country, platform):
                self.country = country
                self.platform = platform
                self.timeout = DEFAULT_REQUEST_TIMEOUT
                self.max_retries = DEFAULT_MAX_RETRIES
                self.user_agent = JOYN_USER_AGENT
                self.base_website = JOYN_DOMAINS.get(country, JOYN_DOMAINS["de"])

            def get_base_headers(self):
                """Return base headers for HTTP requests"""
                return {
                    "User-Agent": self.user_agent,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Origin": self.base_website,
                    "joyn-client-version": JOYN_CLIENT_VERSION,
                    "joyn-country": self.country.upper(),
                    "joyn-distribution-tenant": COUNTRY_TENANT_MAPPING.get(self.country, "JOYN"),
                    "joyn-platform": self.platform,
                }

        # Create and assign the config
        self._config = JoynConfig(country, platform)

        # Now enable OIDC discovery - this will use the config's get_base_headers() method
        self.enable_oidc_discovery(JOYN_7PASS_BASE_URL)

        # Joyn's 7pass flow doesn't use PKCE
        self._use_pkce = False

        # Register with settings manager
        if settings_manager is not None:
            settings_manager.register_provider(
                "joyn",
                supports_countries=True,
                available_countries=SUPPORTED_COUNTRIES,
            )

        # Extract client ID (7pass OIDC doesn't expose app client_id; fallback to platform IDs)
        self._client_id = self._extract_or_fallback_client_id()

        # Set up fallback credentials if needed
        if self.credentials is None:
            logger.info(f"No credentials for joyn/{self.country}, using anonymous fallback")
            self.credentials = self.get_fallback_credentials()

        # Log credential type
        from ...base.auth.credentials import UserPasswordCredentials
        if isinstance(self.credentials, UserPasswordCredentials):
            logger.info(
                f"JoynAuthenticator [{self.country}]: user credentials loaded for '{self.credentials.username}'")
        else:
            logger.info(f"JoynAuthenticator [{self.country}]: using {type(self.credentials).__name__}")

    # ========================================================================
    # Required Abstract Properties
    # ========================================================================

    @property
    def oauth_client_id(self) -> str:
        return self._client_id

    @property
    def oauth_scope(self) -> str:
        return JOYN_OAUTH_SCOPE

    @property
    def oauth_redirect_uri(self) -> str:
        from .constants import get_oauth_redirect_uri
        return get_oauth_redirect_uri(self.country)

    # ========================================================================
    # Token Configuration
    # ========================================================================

    def _should_use_json_for_token_exchange(self, **kwargs) -> bool:
        """Joyn uses JSON instead of form-encoded"""
        return True

    def _build_token_exchange_payload(
            self, authorization_code: str, code_verifier: str, state: Optional[str] = None, **kwargs
    ) -> Dict[str, Any]:
        """Joyn-specific token exchange payload with tracking_id"""
        tracking_id = kwargs.get("cd1") or str(uuid.uuid4())
        return {
            "code": authorization_code,
            "client_id": self.oauth_client_id,
            "redirect_uri": self.oauth_redirect_uri,
            "tracking_id": tracking_id,
            "tracking_name": self.platform,
            "code_verifier": "",  # PKCE explicitly disabled for Joyn
        }

    def _get_token_exchange_headers(self, **kwargs) -> Dict[str, str]:
        """Joyn-specific headers for token exchange"""
        return self._get_joyn_auth_headers()

    # ========================================================================
    # Joyn-Specific Headers
    # ========================================================================

    def _get_joyn_auth_headers(self) -> Dict[str, str]:
        """Generate Joyn-specific authentication headers"""
        headers = JOYN_AUTH_HEADERS_BASE.copy()
        headers.update({
            "Origin": JOYN_DOMAINS.get(self.country, JOYN_DOMAINS["de"]),
            "joyn-country": self.country.upper(),
            "joyn-distribution-tenant": f"JOYN_{self.country.upper()}",
            "joyn-platform": self.platform,
            "joyn-request-id": str(uuid.uuid4()),
        })
        return headers

    def _get_auth_headers(self) -> Dict[str, str]:
        """Base authentication headers"""
        return {
            "User-Agent": JOYN_USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": JOYN_DOMAINS.get(self.country, JOYN_DOMAINS["de"]),
            "joyn-client-version": JOYN_CLIENT_VERSION,
            "joyn-country": self.country.upper(),
            "joyn-distribution-tenant": f"JOYN_{self.country.upper()}",
            "joyn-platform": self.platform,
            "joyn-request-id": str(uuid.uuid4()),
        }

    # ========================================================================
    # Client ID Extraction
    # ========================================================================

    def _extract_or_fallback_client_id(self) -> str:
        """
        Extract client ID. Note: 7pass OIDC discovery returns IdP metadata,
        not app-specific client_id. Safe fallback to platform device IDs.
        """
        client_id = DEVICE_IDS.get(self.platform, DEVICE_IDS[DEFAULT_PLATFORM])
        logger.debug(f"Using platform client_id: {client_id}")
        return client_id

    # ========================================================================
    # Credentials
    # ========================================================================

    def get_fallback_credentials(self) -> JoynCredentials:
        """Get fallback credentials when no user credentials are available"""
        return JoynCredentials(
            client_id=self._client_id,
            client_secret="",
            country=self.country,
        )

    def _build_auth_payload(self) -> Dict[str, Any]:
        """Build authentication payload for client credentials flow"""
        if not self.credentials:
            raise Exception("No credentials available")
        return self.credentials.to_auth_payload()

    # ========================================================================
    # Token Creation & Classification
    # ========================================================================

    def _create_token_from_response(self, response_data: Dict[str, Any]) -> BaseAuthToken:
        """Create token object from API response"""
        token = JoynAuthToken(
            access_token=response_data["access_token"],
            refresh_token=response_data.get("refresh_token", ""),
            token_type=response_data.get("token_type", "Bearer"),
            expires_in=response_data.get("expires_in", 86400),
            issued_at=response_data.get("issued_at", time.time()),
        )
        token.auth_level = self._classify_token(token)
        logger.debug(f"Token created and classified as: {token.auth_level.value}")
        return token

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        """Classify Joyn token based on JWT claims"""
        try:
            if not token or not token.access_token:
                return TokenAuthLevel.UNKNOWN

            if not isinstance(token, JoynAuthToken):
                logger.warning("Token is not a JoynAuthToken")
                return TokenAuthLevel.UNKNOWN

            claims = token.get_jwt_claims()
            if claims is None:
                logger.warning("Invalid JWT format")
                return TokenAuthLevel.UNKNOWN

            jidc = claims.get("jIdC", "")
            if jidc.startswith("JNAA-"):
                return TokenAuthLevel.CLIENT_CREDENTIALS
            elif jidc.startswith("JNDE-"):
                return TokenAuthLevel.USER_AUTHENTICATED

            if "social_id" in claims:
                return TokenAuthLevel.USER_AUTHENTICATED

            client_id = claims.get("cId", "")
            known_client_ids = {DEVICE_IDS.get("web"), DEVICE_IDS.get("android"), DEVICE_IDS.get("ios")}
            if client_id in known_client_ids:
                return TokenAuthLevel.CLIENT_CREDENTIALS

            subject = claims.get("sub", "")
            if subject and len(subject) == 36:
                return TokenAuthLevel.CLIENT_CREDENTIALS

            return TokenAuthLevel.UNKNOWN
        except Exception as e:
            logger.error(f"Error classifying token: {e}")
            return TokenAuthLevel.UNKNOWN

    # ========================================================================
    # Token Refresh
    # ========================================================================

    def _refresh_oauth_token(self) -> Optional[BaseAuthToken]:
        """
        Joyn-specific token refresh with custom endpoint and grant_type.

        Note: Joyn uses a non-standard refresh flow (grant_type: "Bearer")
        on a dedicated endpoint not exposed in OIDC discovery.
        """
        if not self._current_token or not self._current_token.refresh_token:
            logger.debug(f"No refresh token available for {self.provider_name}")
            return None

        try:
            logger.debug(f"Refreshing token for {self.provider_name}")

            payload = {
                "client_id": DEVICE_IDS.get(self.platform, DEVICE_IDS[DEFAULT_PLATFORM]),
                "client_name": self.platform,
                "grant_type": "Bearer",  # Joyn non-standard grant type
                "refresh_token": self._current_token.refresh_token,
            }

            headers = self._get_joyn_auth_headers()
            refresh_endpoint = JOYN_AUTH_ENDPOINTS["REFRESH"]

            response = self.http_manager.post(
                refresh_endpoint,
                operation="auth",
                headers=headers,
                json_data=payload,
                timeout=getattr(self.config, "timeout", 30),
            )

            # Handle 422 "Anonymous refresh token" error
            if response.status_code == 422:
                try:
                    error_body = response.json()
                    if error_body.get("data") == "Anonymous refresh token":
                        logger.debug("Refresh failed - token type mismatch, forcing re-auth")
                        return None
                except Exception:
                    pass

            response.raise_for_status()
            new_token_data = response.json()
            refreshed_token = self._create_token_from_response(new_token_data)
            logger.info(f"Token refresh successful for {self.provider_name}")
            return refreshed_token
        except Exception as e:
            logger.warning(f"Token refresh failed for {self.provider_name}: {e}")
            return None

    # ========================================================================
    # The Complex 7pass Login Flow
    # ========================================================================

    def _perform_oauth_authorization_code_flow(self, username: str, password: str) -> Dict[str, Any]:
        """
        Joyn's complex 7pass OAuth2 flow with multi-step verification.

        Uses constants for all endpoints for better maintainability.
        """
        try:
            logger.debug("Starting Joyn OAuth2 authorization code flow")

            # Use OIDC-discovered authorize endpoint
            web_login_url = self.oauth_authorize_endpoint
            logger.debug(f"Using authorize endpoint: {web_login_url}")

            # Create fresh session for clean cookie/referer state
            session = self._create_oauth_session()
            original_headers = dict(session.headers)

            # Generate OAuth state and store for later validation
            state = self.generate_oauth_state()

            # Parse URL and preserve existing params (especially cd1)
            parsed_login_url = urlparse(web_login_url)
            base_login_url = parsed_login_url._replace(query="", fragment="").geturl()
            existing_params = {
                k: v[0] for k, v in parse_qs(parsed_login_url.query).items()
            }

            # Build authorization URL (PKCE disabled for Joyn)
            params = {
                **existing_params,
                "response_type": "code",
                "client_id": self.oauth_client_id,
                "redirect_uri": self.oauth_redirect_uri,
                "scope": self.oauth_scope,
                "state": state,
                "response_mode": "query",
                "view_type": "login",
                "prompt": "consent",
            }

            authorization_url = f"{base_login_url}?{urlencode(params)}"
            logger.debug("Built authorization URL")

            # Helper for 7pass requests using managed session
            def _make_7pass_request(method: str, url: str, **kwargs):
                request_headers = kwargs.pop("headers", {}).copy()
                # Strip joyn-* headers and standard origin/referer for 7pass endpoints
                clean_headers = {k: v for k, v in request_headers.items() if not k.lower().startswith('joyn-')}
                clean_headers.update({
                    "User-Agent": JOYN_USER_AGENT,
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                })
                clean_headers.pop("Referer", None)
                clean_headers.pop("Origin", None)

                # Handle content-type if provided
                content_type = kwargs.pop("content_type", None)
                if content_type:
                    clean_headers["Content-Type"] = content_type

                allow_redirects = kwargs.pop("allow_redirects", True)

                if method.upper() == "GET":
                    return session.get(url, headers=clean_headers, timeout=30, allow_redirects=allow_redirects,
                                       **kwargs)
                else:
                    return session.post(url, headers=clean_headers, timeout=30, allow_redirects=allow_redirects,
                                        **kwargs)

            # Get authorization page
            auth_response = _make_7pass_request("GET", authorization_url, allow_redirects=True)

            # Restore Joyn headers for subsequent calls
            session.headers.clear()
            session.headers.update(original_headers)
            auth_response.raise_for_status()

            # Check for existing session (direct callback)
            if self.oauth_redirect_uri in auth_response.url:
                logger.info("User already authenticated - extracting code from redirect")
                parsed_url = urlparse(auth_response.url)
                query_params = parse_qs(parsed_url.query)

                auth_code = query_params.get("code", [None])[0]
                received_state = query_params.get("state", [None])[0]

                if not auth_code:
                    raise Exception("Redirect to callback but no authorization code found")

                if not self.validate_oauth_state(received_state, state):
                    raise Exception("State validation failed on direct redirect")

                logger.debug("Extracted authorization code from direct redirect")

                # Exchange code for token using base class method
                return self._exchange_authorization_code_for_token(
                    authorization_code=auth_code,
                    code_verifier="",  # PKCE disabled for Joyn
                    state=state,
                )

            # No existing session - perform login flow
            logger.info("No existing session - performing login-srv/login flow")

            # Extract request_id and cd1 from the signin redirect URL
            parsed_url = urlparse(auth_response.url)
            query_params = parse_qs(parsed_url.query)
            request_id = query_params.get("requestId", [None])[0]
            cd1 = query_params.get("cd1", [None])[0]

            if not request_id:
                request_id_match = re.search(
                    r'requestId[ "\']?\s*:\s*[ "\']([^ "\']+)', auth_response.text
                )
                if request_id_match:
                    request_id = request_id_match.group(1)
                else:
                    raise Exception("Could not extract request_id from authorization page")

            logger.debug(f"Extracted request_id: {request_id}, cd1: {cd1}")

            # Pre-login checks (non-fatal - continue even if they fail)
            pre_login_checks = [
                ("GET",
                 f"{JOYN_7PASS_ENDPOINTS['REGISTRATION_SETUP']}?acceptlanguage=undefined&requestId={request_id}",
                 None),
                ("POST", f"{JOYN_7PASS_ENDPOINTS['USER_CHECK_EXISTS']}/{request_id}",
                 {"email": username, "requestId": request_id}),
                ("POST", JOYN_7PASS_ENDPOINTS['VERIFICATION_CONFIGURED'],
                 {"email": username, "request_id": request_id}),
            ]

            for method, endpoint, data in pre_login_checks:
                try:
                    if method == "GET":
                        _make_7pass_request("GET", endpoint, content_type="application/json")
                    else:
                        _make_7pass_request("POST", endpoint, json=data, content_type="application/json")
                except Exception as e:
                    logger.debug(f"Pre-login check non-fatal error (continuing): {e}")

            # Submit credentials to login-srv/login
            logger.debug(f"POST credentials to login-srv/login for user: {username}")

            login_response = _make_7pass_request(
                "POST",
                JOYN_7PASS_ENDPOINTS["LOGIN"],
                data=urlencode({"username": username, "password": password, "requestId": request_id}),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                allow_redirects=True,
            )
            login_response.raise_for_status()

            final_url = login_response.url
            id_dict = parse_qs(urlparse(final_url).query)
            logger.debug(f"login-srv/login landed on: {final_url}")

            # Check for error redirect
            if "error.html" in final_url or "error_code" in final_url:
                error_match = re.search(r'error_code=(\d+)', final_url)
                error_code = error_match.group(1) if error_match else "unknown"
                raise Exception(f"Login failed with error_code={error_code}: {final_url}")

            # Handle consent flow if no code yet
            if id_dict.get("code") is None:
                sub = id_dict.get("sub", [None])[0]
                track_id = id_dict.get("track_id", [None])[0]

                if not sub or not track_id:
                    raise Exception(
                        f"login-srv/login returned neither code nor sub/track_id. URL: {final_url}"
                    )

                logger.debug(f"Accepting consent scopes for sub={sub}")
                _make_7pass_request(
                    "POST",
                    JOYN_7PASS_ENDPOINTS["CONSENT_ACCEPT"],
                    json={
                        "sub": sub,
                        "client_id": self.oauth_client_id,
                        "scopes": [{"offline_access": "denied"}],
                    },
                    content_type="application/json"
                )

                logger.debug(f"Continuing flow with track_id={track_id}")
                continue_response = _make_7pass_request(
                    "POST",
                    f"{JOYN_7PASS_ENDPOINTS['PRECHECK_CONTINUE']}/{track_id}",
                    data=b"",
                    content_type="application/x-www-form-urlencoded",
                    allow_redirects=True
                )
                continue_response.raise_for_status()

                final_url = continue_response.url
                id_dict = parse_qs(urlparse(final_url).query)
                logger.debug(f"precheck/continue landed on: {final_url}")

            # Extract authorization code
            auth_code = id_dict.get("code", [None])[0]
            if not auth_code:
                raise Exception(
                    f"Could not extract authorization code after login flow. Final URL: {final_url}"
                )

            # Pick up cd1 from the final redirect URL if not captured earlier
            if not cd1:
                cd1 = id_dict.get("cd1", [None])[0]
                if not cd1:
                    raise Exception("cd1 tracking ID missing from login flow response")

            logger.debug("Exchanging authorization code for tokens")

            # Exchange code for token using base class method
            token_data = self._exchange_authorization_code_for_token(
                authorization_code=auth_code,
                code_verifier="",  # PKCE disabled for Joyn
                state=state,
                cd1=cd1,
            )

            logger.debug("Joyn OAuth2 authorization code flow successful (login-srv flow)")
            return token_data

        except Exception as e:
            # Preserve original exception chain for debugging
            logger.error(f"Joyn OAuth2 authorization flow failed: {e}")
            raise Exception(f"Joyn OAuth2 authorization flow failed: {e}") from e

    # ========================================================================
    # Public Methods
    # ========================================================================

    def get_bearer_token(self, force_refresh: bool = False, force_upgrade: bool = False) -> str:
        """Get bearer token with automatic upgrade support"""
        return super().get_bearer_token(force_refresh=force_refresh, force_upgrade=force_upgrade)

    def is_authenticated(self) -> bool:
        """Check if currently authenticated with valid token"""
        return self._current_token is not None and not self._current_token.is_expired

    def invalidate_token(self) -> None:
        """Invalidate current token"""
        self._current_token = None
        try:
            self.settings_manager.clear_token(self.provider_name)
        except (AttributeError, KeyError, IOError, OSError):
            pass

    def debug_token_classification(self) -> Dict[str, Any]:
        """Debug method to analyze current token classification"""
        if not self._current_token:
            return {"error": "No current token"}

        claims = self._current_token.get_jwt_claims() if hasattr(self._current_token, "get_jwt_claims") else {}

        return {
            "token_type": type(self._current_token).__name__,
            "auth_level": self._current_token.auth_level.value,
            "is_expired": self._current_token.is_expired,
            "has_refresh": bool(self._current_token.refresh_token),
            "jwt_claims_available": bool(claims),
            "key_claims": {
                "jIdC": claims.get("jIdC", "MISSING"),
                "cId": claims.get("cId", "MISSING"),
                "social_id": "PRESENT" if "social_id" in claims else "MISSING",
                "sub": claims.get("sub", "MISSING")[:8] + "..." if claims.get("sub") else "MISSING",
                "scope": claims.get("scope", "MISSING"),
            } if claims else {},
        }