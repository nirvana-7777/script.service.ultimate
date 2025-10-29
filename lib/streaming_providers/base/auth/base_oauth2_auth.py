# streaming_providers/base/auth/base_oauth2_auth.py
from abc import abstractmethod
from typing import Dict, Optional, Any, Callable
import uuid
import hashlib
import base64
import secrets
import re
import html
from urllib.parse import urlencode, parse_qs, urlparse

from .base_auth import BaseAuthenticator, BaseAuthToken, TokenAuthLevel
from ..utils.logger import logger
from ..models.proxy_models import ProxyConfig


class OAuth2Error(Exception):
    """OAuth2-specific error with structured error information"""

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
        self.cookies = {}
        self.headers = {}

    def get(self, url: str, **kwargs):
        """GET request with cookie handling"""
        headers = kwargs.get('headers', {}).copy()
        headers.update(self.headers)

        # Add cookies
        if self.cookies:
            cookie_str = '; '.join([f"{k}={v}" for k, v in self.cookies.items()])
            headers['Cookie'] = cookie_str

        kwargs['headers'] = headers
        response = self.http_manager.get(url, operation='oauth', **kwargs)

        # Update cookies from response
        self._update_cookies_from_response(response)
        return response

    def post(self, url: str, **kwargs):
        """POST request with cookie handling"""
        headers = kwargs.get('headers', {}).copy()
        headers.update(self.headers)

        # Add cookies
        if self.cookies:
            cookie_str = '; '.join([f"{k}={v}" for k, v in self.cookies.items()])
            headers['Cookie'] = cookie_str

        kwargs['headers'] = headers
        response = self.http_manager.post(url, operation='oauth', **kwargs)

        # Update cookies from response
        self._update_cookies_from_response(response)
        return response

    def _update_cookies_from_response(self, response):
        """Extract and update cookies from response"""
        if hasattr(response, 'cookies'):
            for cookie in response.cookies:
                self.cookies[cookie.name] = cookie.value


class BaseOAuth2Authenticator(BaseAuthenticator):
    def __init__(self, provider_name: str, settings_manager=None, credentials=None,
                 country: Optional[str] = None,  # ADD THIS PARAMETER
                 config_dir: Optional[str] = None, enable_kodi_integration: bool = True,
                 proxy_config: Optional[ProxyConfig] = None,
                 http_manager=None):
        # Pass country to parent BaseAuthenticator
        super().__init__(
            provider_name,
            settings_manager,
            credentials,
            country=country,  # ADD THIS LINE
            config_dir=config_dir,
            enable_kodi_integration=enable_kodi_integration
        )
        self._oauth_state = None
        self._pkce_verifier = None

        # Preserve _config if subclass already set it, otherwise initialize to None
        if not hasattr(self, '_config'):
            self._config = None

        self._proxy_config = proxy_config
        self._auth_endpoint = None
        self._http_manager = http_manager
        self._token_expiry_buffer = 300

    @property
    def http_manager(self):
        """Safe access to http_manager - use provided one or create fallback"""
        if self._http_manager is not None:
            return self._http_manager

        logger.warning(f"No HTTP manager available for {self.provider_name}, creating one")

        try:
            from ...base.network import HTTPManagerFactory
            self._http_manager = HTTPManagerFactory.create_for_provider(
                self.provider_name,
                proxy_config=self._proxy_config,
                user_agent=getattr(self.config, 'user_agent', 'Mozilla/5.0'),
                timeout=getattr(self.config, 'timeout', 30)
            )
        except Exception as e:
            logger.warning(f"Error creating HTTP manager via factory: {e}, using minimal fallback")
            self._http_manager = self._create_minimal_http_manager()

        return self._http_manager

    @http_manager.setter
    def http_manager(self, value):
        """Allow setting http_manager"""
        self._http_manager = value

    @property
    def config(self):
        """Safe access to config with fallback"""
        import traceback

        if self._config is not None:
            return self._config

        # Log who's calling this before config is set
        logger.warning(f"Config accessed before initialization for {self.provider_name}")
        logger.debug(f"Call stack:\n{''.join(traceback.format_stack()[-5:])}")

        # Only create minimal config if absolutely necessary
        class MinimalConfig:
            def __init__(self):
                self.timeout = 30
                self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                self.base_website = "https://example.com"
                self.auth_endpoint = "https://auth.example.com"

            def get_base_headers(self):
                return {
                    'User-Agent': self.user_agent,
                    'Accept': 'application/json',
                }

            def get_auth_headers(self):
                return self.get_base_headers()

        self._config = MinimalConfig()
        logger.warning(f"Using minimal config for {self.provider_name} - subclass should set config")
        return self._config

    @config.setter
    def config(self, value):
        """Allow subclasses to set config"""
        self._config = value

    @staticmethod
    def _create_minimal_http_manager():
        """Create absolute minimal HTTP manager fallback"""

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
        """Get authentication endpoint - subclasses can override"""
        if hasattr(self, '_auth_endpoint') and self._auth_endpoint:
            return self._auth_endpoint

        if hasattr(self.config, 'auth_endpoint'):
            return self.config.auth_endpoint

        raise NotImplementedError("Subclass must implement auth_endpoint or set _auth_endpoint")

    @auth_endpoint.setter
    def auth_endpoint(self, value):
        """Allow setting auth_endpoint directly"""
        self._auth_endpoint = value

    # Abstract properties
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

    @property
    def oauth_authorize_endpoint(self) -> str:
        """Get OAuth2 authorization endpoint"""
        if hasattr(self, 'auth_endpoint'):
            auth_endpoint = self.auth_endpoint
        else:
            logger.warning(f"auth_endpoint not defined for {self.provider_name}, using default")
            return "https://auth.example.com/oauth2/auth"

        if auth_endpoint.endswith('/token'):
            return auth_endpoint.replace('/token', '/auth')
        elif '/protocol/openid-connect/token' in auth_endpoint:
            return auth_endpoint.replace('/token', '/auth')
        else:
            return '/'.join(auth_endpoint.split('/')[:-1]) + '/auth'

    # PKCE Implementation
    @staticmethod
    def generate_pkce_verifier() -> str:
        """Generate PKCE code verifier (RFC 7636)"""
        token = secrets.token_bytes(32)
        verifier = base64.urlsafe_b64encode(token).rstrip(b'=').decode('ascii')
        logger.debug(f"Generated PKCE verifier: {verifier}")
        return verifier

    @staticmethod
    def generate_pkce_challenge(verifier: str) -> str:
        """Generate PKCE code challenge from verifier"""
        challenge = hashlib.sha256(verifier.encode('ascii')).digest()
        challenge_b64 = base64.urlsafe_b64encode(challenge).rstrip(b'=').decode('ascii')
        logger.debug(f"Generated PKCE challenge: {challenge_b64}")
        return challenge_b64

    # OAuth2 State Management
    def generate_oauth_state(self) -> str:
        """Generate secure state parameter for OAuth2 flow"""
        state = str(uuid.uuid4())
        self._oauth_state = state
        return state

    @staticmethod
    def generate_oauth_nonce() -> str:
        """Generate secure nonce parameter for OAuth2 flow"""
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

    # Session Management
    def _create_oauth_session(self) -> SessionAwareHTTPManager:
        """Create a session-aware HTTP manager for OAuth flows"""
        session = SessionAwareHTTPManager(self.http_manager)
        session.headers.update({
            'User-Agent': self.config.user_agent,
            'Referer': getattr(self.config, 'base_website', ''),
            'Origin': getattr(self.config, 'base_website', '')
        })
        return session

    # Complete Client Credentials Flow
    def _perform_oauth_client_credentials_flow(self) -> Dict[str, Any]:
        """
        Complete manual implementation of OAuth2 client credentials flow
        Uses provider-specific headers and payload formatting
        """
        try:
            logger.debug(f"Starting OAuth2 client credentials flow for {self.provider_name}")

            headers = self._get_auth_headers()
            data = self._build_auth_payload()

            response = self.http_manager.post(
                self.auth_endpoint,
                operation='auth',
                headers=headers,
                data=data
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

    # Authorization URL Building
    def _build_authorization_url(self, extra_params: Dict[str, Any] = None) -> tuple[str, str, str]:
        """Build authorization URL with PKCE for authorization code flow"""
        code_verifier = self.generate_pkce_verifier()
        code_challenge = self.generate_pkce_challenge(code_verifier)
        state = self.generate_oauth_state()

        params = {
            'response_type': 'code',
            'client_id': self.oauth_client_id,
            'redirect_uri': self.oauth_redirect_uri,
            'scope': self.oauth_scope,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256'
        }

        if extra_params:
            params.update(extra_params)

        authorization_url = f"{self.oauth_authorize_endpoint}?{urlencode(params)}"

        return authorization_url, state, code_verifier

    # Authorization Code Exchange
    def _exchange_authorization_code_for_token(self, authorization_code: str, code_verifier: str,
                                               state: str = None, **kwargs) -> Dict[str, Any]:
        """
        Exchange authorization code for access token (PKCE flow)
        Enhanced to support provider-specific customizations
        """
        try:
            logger.debug(f"Exchanging authorization code for token for {self.provider_name}")

            # Allow subclasses to override the default payload
            data = self._build_token_exchange_payload(
                authorization_code=authorization_code,
                code_verifier=code_verifier,
                state=state,
                **kwargs
            )

            # Allow subclasses to override headers
            headers = self._get_token_exchange_headers(**kwargs)

            # Allow subclasses to override data format and endpoint
            endpoint = self._get_token_exchange_endpoint(**kwargs)
            use_json = self._should_use_json_for_token_exchange(**kwargs)

            request_kwargs = {
                'operation': 'auth',
                'headers': headers,
                'timeout': getattr(self.config, 'timeout', 30)
            }

            if use_json:
                request_kwargs['json_data'] = data
            else:
                request_kwargs['data'] = urlencode(data).encode()

            response = self.http_manager.post(
                endpoint,
                **request_kwargs
            )

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

    # New flexible methods that subclasses can override
    def _build_token_exchange_payload(self, authorization_code: str, code_verifier: str,
                                      state: str = None, **kwargs) -> Dict[str, Any]:
        """Build token exchange payload - subclasses can override for custom parameters"""
        data = {
            'grant_type': 'authorization_code',
            'client_id': self.oauth_client_id,
            'code': authorization_code,
            'redirect_uri': self.oauth_redirect_uri,
            'code_verifier': code_verifier
        }

        client_secret = getattr(self.credentials, 'client_secret', None)
        if client_secret:
            data['client_secret'] = client_secret

        return data

    def _get_token_exchange_headers(self, **kwargs) -> Dict[str, str]:
        """Get token exchange headers - subclasses can override for custom headers"""
        headers = self._get_auth_headers()

        # Ensure Content-Type is appropriate
        if kwargs.get('use_json', False) or self._should_use_json_for_token_exchange(**kwargs):
            headers['Content-Type'] = 'application/json'
        else:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'

        return headers

    def _get_token_exchange_endpoint(self, **kwargs) -> str:
        """Get token exchange endpoint - subclasses can override for custom endpoints"""
        return self.auth_endpoint

    @staticmethod
    def _should_use_json_for_token_exchange(**kwargs) -> bool:
        """Determine if token exchange should use JSON - subclasses can override"""
        return False  # Default to form-encoded for OAuth2 compliance

    # Generic Form-Based Login Flow
    def _perform_generic_form_login(
            self,
            username: str,
            password: str,
            form_selector_pattern: str,
            login_fields: Dict[str, str],
            extra_params: Dict[str, Any] = None,
            additional_form_data: Dict[str, str] = None
    ) -> Dict[str, Any]:
        """
        Generic OAuth2 form-based login flow

        Args:
            username: User's username
            password: User's password
            form_selector_pattern: Regex to find login form action URL
            login_fields: Field names mapping (e.g., {'username': 'email', 'password': 'pass'})
            extra_params: Additional authorization URL parameters
            additional_form_data: Additional form fields to submit

        Returns:
            Token data dictionary
        """
        try:
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

            login_data[login_fields.get('username', 'username')] = username
            login_data[login_fields.get('password', 'password')] = password

            # Step 4: Submit login credentials
            login_response = session.post(
                login_url,
                data=login_data,
                timeout=self.config.timeout,
                allow_redirects=False
            )

            # Step 5: Handle redirect and extract authorization code
            if login_response.status_code in [302, 303]:
                redirect_url = login_response.headers.get('Location')
                if not redirect_url:
                    raise Exception("No redirect URL found after login")
            else:
                redirect_response = session.get(login_response.url, timeout=self.config.timeout)
                redirect_url = redirect_response.url

            # Step 6: Validate and extract authorization code
            is_valid, error_msg, authorization_code = self.validate_authentication_response(redirect_url, state)
            if not is_valid:
                raise Exception(f"Authentication response validation failed: {error_msg}")

            # Step 7: Exchange code for token
            token_data = self._exchange_authorization_code_for_token(
                authorization_code=authorization_code,
                code_verifier=code_verifier,
                state=state
            )

            return token_data

        except Exception as e:
            raise Exception(f"OAuth2 form-based login failed: {e}")

    # Token Refresh
    def _refresh_oauth_token(self) -> Optional[BaseAuthToken]:
        """Complete manual token refresh implementation"""
        if not self._current_token or not self._current_token.refresh_token:
            logger.debug(f"No refresh token available for {self.provider_name}")
            return None

        try:
            logger.debug(f"Refreshing OAuth2 token for {self.provider_name}")

            data = {
                'grant_type': 'refresh_token',
                'refresh_token': self._current_token.refresh_token,
                'client_id': self.oauth_client_id,
            }

            client_secret = getattr(self.credentials, 'client_secret', None)
            if client_secret:
                data['client_secret'] = client_secret

            headers = self._get_auth_headers()
            encoded_data = urlencode(data).encode()

            response = self.http_manager.post(
                self.auth_endpoint,
                operation='auth',
                headers=headers,
                data=encoded_data
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

    # Error Response Handling
    @staticmethod
    def _check_oauth_error_response(response):
        """Check response for OAuth2 error and raise OAuth2Error if found"""
        try:
            if response.status_code >= 400:
                try:
                    error_data = response.json()
                    if 'error' in error_data:
                        raise OAuth2Error(
                            error=error_data.get('error'),
                            error_description=error_data.get('error_description'),
                            error_uri=error_data.get('error_uri')
                        )
                except (ValueError, KeyError):
                    pass
        except OAuth2Error:
            raise
        except Exception:
            pass

    # Dynamic Client ID Extraction
    def _extract_client_id_from_js(
            self,
            main_page_url: str,
            js_file_pattern: str,
            client_id_pattern: str
    ) -> Optional[str]:
        """
        Extract client ID from provider's JavaScript

        Args:
            main_page_url: URL of the main page containing script references
            js_file_pattern: Regex pattern to find the JS file URL
            client_id_pattern: Regex pattern to extract client ID from JS content

        Returns:
            Extracted client ID or None
        """
        try:
            headers = self.config.get_base_headers()

            response = self.http_manager.get(
                main_page_url,
                operation='api',
                headers=headers
            )
            response.raise_for_status()

            js_matches = re.findall(js_file_pattern, response.text)
            if not js_matches:
                logger.warning(f"Could not find JS file using pattern: {js_file_pattern}")
                return None

            js_url = main_page_url.rstrip('/') + '/' + js_matches[-1].lstrip('/')

            js_response = self.http_manager.get(js_url, operation='api', headers=headers)
            js_response.raise_for_status()

            client_id_match = re.search(client_id_pattern, js_response.text)
            if not client_id_match:
                logger.warning(f"Could not find client ID using pattern: {client_id_pattern}")
                return None

            return client_id_match.group(1)

        except Exception as e:
            logger.error(f"Error extracting client ID from JS: {e}")
            return None

    # Generic Config Extraction from JS
    def _extract_config_from_js(
            self,
            main_page_url: str,
            js_file_pattern: str,
            config_pattern: str,
            parse_function: Callable[[str], Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Generic JS config extraction

        Args:
            main_page_url: URL of the main page
            js_file_pattern: Regex to find JS file
            config_pattern: Regex to extract config section
            parse_function: Function to parse the config string into a dict

        Returns:
            Parsed configuration dictionary or None
        """
        try:
            headers = self.config.get_base_headers()

            response = self.http_manager.get(
                main_page_url,
                operation='api',
                headers=headers
            )
            response.raise_for_status()

            js_matches = re.findall(js_file_pattern, response.text)
            if not js_matches:
                return None

            js_url = main_page_url.rstrip('/') + '/' + js_matches[-1].lstrip('/')

            js_response = self.http_manager.get(js_url, operation='api', headers=headers)
            js_response.raise_for_status()

            config_match = re.search(config_pattern, js_response.text)
            if not config_match:
                return None

            config_str = config_match.group(1)
            return parse_function(config_str)

        except Exception as e:
            logger.error(f"Error extracting config from JS: {e}")
            return None

    # Token Upgrade Support
    def _should_upgrade_to_user_token(self, token: BaseAuthToken) -> bool:
        """
        Check if token should be upgraded - now uses the base class logic

        Override in subclass only if provider has specific upgrade rules
        """
        return self.should_upgrade_token(token)

    def _get_effective_credentials(self):
        """
        Get effective credentials with priority:
        1. Stored user credentials (if available)
        2. Current credentials if valid
        3. Fallback credentials
        """
        from ...base.auth.credentials import UserPasswordCredentials

        # ALWAYS check stored credentials first for user credentials
        stored_creds = self.settings_manager.get_provider_credentials(self.provider_name)
        if stored_creds and isinstance(stored_creds, UserPasswordCredentials):
            if stored_creds.validate():
                return stored_creds

        # Then use current credentials
        if self.credentials and self.credentials.validate():
            return self.credentials

        # Finally fallback
        fallback = self.get_fallback_credentials()
        self.credentials = fallback
        return fallback

    def get_bearer_token(self, force_refresh: bool = False, force_upgrade: bool = False) -> str:
        """
        Get bearer token with automatic upgrade support

        Args:
            force_refresh: Force token refresh even if not expired
            force_upgrade: Force token upgrade attempt regardless of current level

        Returns:
            Bearer token string
        """
        logger.debug(f"get_bearer_token called: force_refresh={force_refresh}, force_upgrade={force_upgrade}")

        # Get current token (authenticate if needed)
        current_token = self.authenticate(force_refresh=force_refresh)

        # Classify token if needed
        if current_token.auth_level == TokenAuthLevel.UNKNOWN:
            current_token.auth_level = self._classify_token(current_token)
            logger.debug(f"Token classified as: {current_token.auth_level.value}")

        # Check if upgrade is needed/requested
        should_upgrade = force_upgrade or self._should_upgrade_to_user_token(current_token)

        if should_upgrade and not force_refresh:
            logger.info(
                f"Token upgrade triggered (force={force_upgrade}, auto={self._should_upgrade_to_user_token(current_token)})")

            original_credentials = self.credentials

            try:
                # Get effective credentials (prioritizes stored user credentials)
                self.credentials = self._get_effective_credentials()

                if not self.credentials or not self.credentials.validate():
                    logger.debug("No valid credentials for upgrade")
                    return current_token.bearer_token

                # Perform authentication with new credentials
                user_token = self._perform_authentication()

                if user_token and not user_token.is_expired:
                    # Classify the new token
                    user_token.auth_level = self._classify_token(user_token)

                    # Verify it's actually an upgrade
                    if user_token.is_user_authenticated():
                        logger.info("Successfully upgraded to user token")
                        self._current_token = user_token
                        self._save_session()
                        return user_token.bearer_token
                    else:
                        logger.warning(
                            f"Authentication succeeded but token is not user level: {user_token.auth_level.value}")
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

    # Main Authentication Flow
    def _perform_authentication(self) -> BaseAuthToken:
        """Complete OAuth2 authentication based on credential type"""
        from ...base.auth.credentials import UserPasswordCredentials, ClientCredentials

        logger.debug(
            f"Starting OAuth2 authentication for {self.provider_name} with credential type: {type(self.credentials)}")

        original_credentials = self.credentials

        try:
            if isinstance(self.credentials, UserPasswordCredentials):
                logger.info(f"Attempting OAuth2 user authentication for {self.provider_name}")
                token_data = self._perform_oauth_authorization_code_flow(
                    self.credentials.username,
                    self.credentials.password
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
                    raise e
            else:
                raise e

    # Token Management
    @abstractmethod
    def _create_token_from_response(self, response_data: Dict[str, Any]) -> BaseAuthToken:
        """Create provider-specific token from OAuth2 response"""
        pass

    def _refresh_token(self) -> Optional[BaseAuthToken]:
        """Override base refresh to use manual OAuth2 refresh flow"""
        return self._refresh_oauth_token()

    # Status and Diagnostics
    def get_authentication_status(self) -> Dict[str, Any]:
        """Get comprehensive OAuth2 authentication status information"""
        status = super().get_authentication_status()

        oauth_status = {
            'oauth_client_id': self.oauth_client_id,
            'oauth_scope': self.oauth_scope,
            'oauth_redirect_uri': self.oauth_redirect_uri,
            'oauth_authorize_endpoint': self.oauth_authorize_endpoint,
            'authentication_flow': 'oauth2',
            'pkce_support': True,
            'proxy_support': hasattr(self, 'http_manager'),
            'credential_type': type(self.credentials).__name__,
            'has_refresh_token': bool(self._current_token and self._current_token.refresh_token),
        }

        if self._current_token:
            oauth_status.update({
                'token_expires_in': self._current_token.expires_in,
                'token_issued_at': self._current_token.issued_at,
                'token_is_expired': self._current_token.is_expired,
                'token_needs_refresh': self._current_token.needs_refresh(),
            })

        status.update(oauth_status)
        return status

    # Utility Methods
    @staticmethod
    def extract_authorization_code_from_url(url: str) -> Optional[str]:
        """Extract authorization code from callback URL"""
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            return query_params.get('code', [None])[0]
        except Exception as e:
            logger.error(f"Error extracting authorization code from URL: {e}")
            return None

    def validate_authentication_response(self, url: str, original_state: str) -> tuple[
        bool, Optional[str], Optional[str]]:
        """
        Validate OAuth2 authentication response
        Returns: (is_valid, error_message, authorization_code)
        """
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)

            if 'error' in query_params:
                error = query_params['error'][0]
                error_description = query_params.get('error_description', [''])[0]
                return False, f"{error}: {error_description}", None

            received_state = query_params.get('state', [None])[0]
            if not self.validate_oauth_state(received_state, original_state):
                return False, "State validation failed", None

            authorization_code = query_params.get('code', [None])[0]
            if not authorization_code:
                return False, "No authorization code in response", None

            return True, None, authorization_code

        except Exception as e:
            return False, f"Error processing authentication response: {e}", None

    # Abstract method for provider-specific authorization code flow
    @abstractmethod
    def _perform_oauth_authorization_code_flow(self, username: str, password: str) -> Dict[str, Any]:
        """
        Perform OAuth2 authorization code flow with PKCE for user login
        Must be implemented by subclasses for provider-specific login forms
        """
        pass