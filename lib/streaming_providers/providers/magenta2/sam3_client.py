# streaming_providers/providers/magenta2/sam3_client.py
import re
from typing import Dict, Optional, Any, List
from dataclasses import dataclass
from urllib.parse import urlparse, parse_qs

from ...base.network import HTTPManager
from ...base.utils.logger import logger
from .constants import (
    SSO_USER_AGENT,
    DEFAULT_REQUEST_TIMEOUT,
    GRANT_TYPES,
)


@dataclass
class Sam3AuthMethod:
    """SAM3 authentication method"""
    name: str
    enabled: bool = False


@dataclass
class Sam3AuthMethods:
    """Available SAM3 authentication methods"""
    password: bool = False
    code: bool = False
    line: bool = False


@dataclass
class Sam3FormField:
    """HTML form field extracted from SAM3 login pages"""
    name: str
    value: str
    type: str = "hidden"


class Sam3Client:
    """
    SAM3 authentication client implementing the complete login flow from C++ code
    """

    def __init__(self, http_manager: HTTPManager, session_id: str, device_id: str,
                 sam3_client_id: str, issuer_url: str = None,
                 oauth_token_endpoint: str = None, line_auth_endpoint: str = None,
                 backchannel_start_url: str = None, qr_code_url_template: str = None):
        """
        Initialize SAM3 client with all required endpoints
        """
        self.http_manager = http_manager
        self.session_id = session_id
        self.device_id = device_id
        self.sam3_client_id = sam3_client_id

        # STORE ALL ENDPOINTS FOR DIFFERENT AUTH FLOWS
        self.issuer_url = issuer_url  # For user auth flow (username/password)
        self.oauth_token_endpoint = oauth_token_endpoint  # For OAuth flows
        self.line_auth_endpoint = line_auth_endpoint  # For device line auth
        self.token_endpoint = line_auth_endpoint  # Backwards compatibility

        # Remote login endpoints
        self.backchannel_start_url = backchannel_start_url
        self.qr_code_url_template = qr_code_url_template

        # Other SAM3 endpoints (will be updated from OpenID config)
        self.authorization_endpoint: Optional[str] = None
        self.userinfo_endpoint: Optional[str] = None

        # Authentication state
        self.auth_methods = Sam3AuthMethods()
        self.form_fields: List[Sam3FormField] = []
        self.refresh_token: Optional[str] = None
        self.access_tokens: Dict[str, str] = {}  # scope -> token

        self.__last_line_auth_response: Optional[Dict[str, Any]] = None

        # Remote login handler (lazy initialized)
        self._remote_login_handler: Optional['RemoteLoginHandler'] = None

        logger.debug(
            f"SAM3 client initialized - "
            f"Issuer: {issuer_url}, "
            f"OAuth: {oauth_token_endpoint}, "
            f"Line: {line_auth_endpoint}, "
            f"Backchannel: {backchannel_start_url}"
        )

    # ========================================================================
    # Endpoint Resolution Helpers
    # ========================================================================

    def _get_token_endpoint(self) -> str:
        """Get the appropriate token endpoint with fallback logic"""
        return self.oauth_token_endpoint or self.token_endpoint or self.line_auth_endpoint

    def _get_line_auth_endpoint(self) -> str:
        """Get line auth endpoint with fallback"""
        return self.line_auth_endpoint or self.token_endpoint

    # ========================================================================
    # Common Token Request Method
    # ========================================================================

    def _make_token_request(self, operation: str, payload: Dict[str, Any],
                            endpoint_override: str = None) -> Dict[str, Any]:
        """
        Common method for all token requests

        Args:
            operation: Operation name for logging
            payload: Request payload (will be form-encoded)
            endpoint_override: Optional endpoint override

        Returns:
            Token response data
        """
        endpoint = endpoint_override or self._get_token_endpoint()
        if not endpoint:
            raise Exception("No token endpoint available")

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': SSO_USER_AGENT
        }

        response = self.http_manager.post(
            endpoint,
            operation=operation,
            headers=headers,
            data=payload,
            timeout=DEFAULT_REQUEST_TIMEOUT
        )
        response.raise_for_status()
        data = response.json()

        # Store refresh token if provided
        if 'refresh_token' in data:
            self.refresh_token = data['refresh_token']
            logger.debug(f"Refresh token stored/updated from {operation}")

        return data

    # ========================================================================
    # Authentication Methods Discovery
    # ========================================================================

    def discover_auth_methods(self, line_auth_url: str) -> bool:
        """
        Discover available authentication methods
        Matching C++ GetAuthMethods()
        """
        try:
            logger.debug("Discovering SAM3 authentication methods")

            headers = {
                'User-Agent': SSO_USER_AGENT,
                'Accept': 'application/json'
            }

            response = self.http_manager.get(
                line_auth_url,
                operation='auth_methods',
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()

            data = response.json()
            content = data.get('content', {})

            if 'supportedAuthenticationKinds' in content:
                auth_kinds = content['supportedAuthenticationKinds']
                for method in auth_kinds:
                    if method == GRANT_TYPES['PASSWORD']:
                        self.auth_methods.password = True
                    elif method == GRANT_TYPES['AUTH_CODE']:
                        self.auth_methods.code = True
                    elif method == GRANT_TYPES['LINE_AUTH']:
                        self.auth_methods.line = True

            logger.info(
                f"SAM3 auth methods: password={self.auth_methods.password}, "
                f"code={self.auth_methods.code}, line={self.auth_methods.line}"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to discover SAM3 auth methods: {e}")
            return False

    # ========================================================================
    # User Authentication Flow (Username/Password)
    # ========================================================================

    def sam3_login(self, username: str, password: str) -> Dict[str, str]:
        """
        Complete SAM3 login flow matching C++ Sam3Client::Sam3Login()
        """
        try:
            logger.info("Starting SAM3 login flow")

            # Step 1: Get initial authorization page
            auth_url = self._build_authorization_url()
            logger.debug(f"Step 1: Getting authorization page: {auth_url}")

            initial_response = self.http_manager.get(
                auth_url,
                operation='sam3_auth',
                headers=self._get_sso_headers(),
                timeout=DEFAULT_REQUEST_TIMEOUT,
                allow_redirects=False
            )

            # Step 2: Parse HTML and extract form fields
            self._parse_html_form_fields(initial_response.text)
            logger.debug(f"Step 2: Extracted {len(self.form_fields)} form fields")

            # Step 3: Submit username to factorx endpoint
            factorx_url = f"{self.issuer_url}/factorx" if self.issuer_url else "https://login.telekom-dienste.de/factorx"
            username_data = self._build_username_payload(username)

            logger.debug(f"Step 3: Submitting username to {factorx_url}")
            username_response = self.http_manager.post(
                factorx_url,
                operation='sam3_username',
                headers=self._get_sso_headers(),
                data=username_data,
                timeout=DEFAULT_REQUEST_TIMEOUT,
                allow_redirects=False
            )

            # Step 4: Parse response and extract updated form fields
            self._parse_html_form_fields(username_response.text)
            logger.debug(f"Step 4: Updated form fields: {len(self.form_fields)}")

            # Step 5: Submit password to factorx endpoint
            password_data = self._build_password_payload(username, password)

            logger.debug(f"Step 5: Submitting password to {factorx_url}")
            password_response = self.http_manager.post(
                factorx_url,
                operation='sam3_password',
                headers=self._get_sso_headers(),
                data=password_data,
                timeout=DEFAULT_REQUEST_TIMEOUT,
                allow_redirects=False
            )

            # Step 6: Extract authorization code from redirect
            redirect_url = password_response.headers.get('Location', '')
            logger.debug(f"Step 6: Redirect URL: {redirect_url}")

            if not redirect_url:
                # Follow redirects manually if needed
                final_response = self.http_manager.get(
                    factorx_url,
                    operation='sam3_final',
                    headers=self._get_sso_headers(),
                    timeout=DEFAULT_REQUEST_TIMEOUT,
                    allow_redirects=True
                )
                redirect_url = final_response.url

            # Step 7: Extract code and state from redirect URL
            code, state = self._extract_code_and_state(redirect_url)

            if not code or not state:
                raise Exception("Could not extract authorization code and state from redirect")

            logger.info("SAM3 login completed successfully")
            return {
                'code': code,
                'state': state,
                'redirect_url': redirect_url
            }

        except Exception as e:
            logger.error(f"SAM3 login failed: {e}")
            raise Exception(f"SAM3 login failed: {e}")

    # ========================================================================
    # Line Authentication (Device Token)
    # ========================================================================

    def get_last_line_auth_response(self) -> Optional[Dict[str, Any]]:
        """Get the last line auth response data"""
        return self.__last_line_auth_response

    def line_auth(self, device_token: str) -> bool:
        """
        Line authentication using device token
        """
        try:
            endpoint = self._get_line_auth_endpoint()
            if not endpoint:
                raise Exception("No line auth endpoint available")

            logger.debug("Performing line authentication with device token")

            payload = {
                'grant_type': GRANT_TYPES['LINE_AUTH'],
                'client_id': self.sam3_client_id,
                'token': device_token,
                'scope': 'tvhubs offline_access'
            }

            # Use common token request method
            data = self._make_token_request('line_auth', payload, endpoint)

            # Store the actual response data
            self.__last_line_auth_response = data

            if 'refresh_token' in data:
                logger.info("Line authentication successful, refresh token obtained")
                return True

            logger.warning("Line authentication succeeded but no refresh token received")
            return False

        except Exception as e:
            logger.error(f"Line authentication failed: {e}")
            return False

    # ========================================================================
    # Remote Login (Backchannel Authentication)
    # ========================================================================

    def _get_remote_login_handler(self) -> Optional['RemoteLoginHandler']:
        """
        Get or create remote login handler

        Returns:
            RemoteLoginHandler if endpoints available, None otherwise
        """
        # Return existing handler if available
        if self._remote_login_handler:
            return self._remote_login_handler

        # Check if we have required endpoints
        if not all([
            self.backchannel_start_url,
            self._get_token_endpoint(),
            self.qr_code_url_template
        ]):
            logger.debug("Remote login not available - missing endpoints")
            return None

        # Import here to avoid circular dependency
        from .remote_login_handler import RemoteLoginHandler

        # Create handler
        self._remote_login_handler = RemoteLoginHandler(
            http_manager=self.http_manager,
            sam3_client_id=self.sam3_client_id,
            backchannel_start_url=self.backchannel_start_url,
            token_endpoint=self._get_token_endpoint(),
            qr_code_url_template=self.qr_code_url_template
        )

        logger.info("✓ Remote login handler initialized")
        return self._remote_login_handler

    def can_use_remote_login(self) -> bool:
        """Check if remote login is available"""
        return self._get_remote_login_handler() is not None

    def remote_login(self, scope: str = "tvhubs offline_access") -> Optional[Dict[str, Any]]:
        """
        Perform complete remote login (backchannel auth) flow

        Args:
            scope: OAuth scopes to request

        Returns:
            Token data dict if successful, None if failed/timeout/cancelled
        """
        handler = self._get_remote_login_handler()
        if not handler:
            logger.error("Remote login not available")
            return None

        # Perform complete flow (notifier is already set in handler)
        token_data = handler.perform_complete_flow(scope)

        # Store refresh token if we got one
        if token_data and 'refresh_token' in token_data:
            self.refresh_token = token_data['refresh_token']
            logger.info("✓ Remote login successful, refresh token obtained")

        return token_data

    def get_remote_login_status(self) -> Optional[Dict[str, Any]]:
        """Get current remote login session status"""
        handler = self._get_remote_login_handler()
        if not handler:
            return None
        return handler.get_session_status()

    # ========================================================================
    # Generic Token Operations
    # ========================================================================

    def get_token(self, grant_type: str, scope: str, credential1: str = "",
                  credential2: str = "") -> str:
        """
        Generic token acquisition
        """
        try:
            logger.debug(f"Getting token with grant_type: {grant_type}, scope: {scope}")

            payload = {
                'grant_type': grant_type,
                'client_id': self.sam3_client_id
            }

            # Add credentials based on grant type
            if grant_type == GRANT_TYPES['REFRESH_TOKEN']:
                payload['refresh_token'] = credential1
                payload['scope'] = f"{scope} offline_access"
            elif grant_type == GRANT_TYPES['REMOTE_LOGIN']:
                payload['auth_req_id'] = credential1
                payload['auth_req_sec'] = credential2

            # Use common token request method
            data = self._make_token_request('get_token', payload)

            access_token = data.get('access_token')
            if not access_token:
                raise Exception("No access token in token response")

            # Store token by scope
            self.access_tokens[scope] = access_token

            logger.debug(f"Token obtained for scope: {scope}")
            return access_token

        except Exception as e:
            logger.error(f"Token acquisition failed: {e}")
            raise

    def refresh_access_token(self, scope: str) -> str:
        """
        Refresh access token
        Matching C++ Sam3Client::RefreshToken()
        """
        if not self.refresh_token:
            raise Exception("No refresh token available")

        return self.get_token(GRANT_TYPES['REFRESH_TOKEN'], scope, self.refresh_token)

    def get_access_token(self, scope: str) -> str:
        """
        Get access token for specific scope with line auth fallback
        """
        # Return cached token if available
        if scope in self.access_tokens:
            return self.access_tokens[scope]

        # Try to use line auth established session first
        if self.refresh_token:
            try:
                token = self.refresh_access_token(scope)
                if token:
                    return token
            except Exception as e:
                logger.warning(f"Token refresh failed for scope {scope}: {e}")

        # If no refresh token available, we can't get an access token
        logger.warning(f"No access token available for scope {scope} - line auth may be needed")
        return ""

    # ========================================================================
    # HTML Form Parsing Helpers
    # ========================================================================

    def _build_authorization_url(self) -> str:
        """Build authorization URL matching C++ implementation"""
        if not self.authorization_endpoint:
            # Fallback to standard URL
            return "https://login.telekom-dienste.de/oauth2/auth"

        params = {
            'client_id': self.sam3_client_id,
            'redirect_uri': 'https://web2.magentatv.de/authn/idm',
            'response_type': 'code',
            'scope': 'openid offline_access'
        }

        param_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        return f"{self.authorization_endpoint}?{param_string}"

    def _parse_html_form_fields(self, html_content: str) -> None:
        """
        Parse HTML form fields matching C++ ParseHtml()
        """
        self.form_fields.clear()

        # Look for form with id="login" or similar
        form_start = html_content.find('form id="login"')
        if form_start == -1:
            form_start = html_content.find('<form')
            if form_start == -1:
                logger.warning("No form found in HTML content")
                return

        form_end = html_content.find('</form>', form_start)
        if form_end == -1:
            logger.warning("No form end tag found")
            return

        form_html = html_content[form_start:form_end]

        # Find all hidden input fields
        pattern = r'<input[^>]*type="hidden"[^>]*name="([^"]*)"[^>]*value="([^"]*)"[^>]*>'
        matches = re.findall(pattern, form_html, re.IGNORECASE)

        for name, value in matches:
            self.form_fields.append(Sam3FormField(name=name, value=value))
            logger.debug(f"Found form field: {name} = {value}")

        # Also look for input fields without explicit type="hidden"
        pattern_all = r'<input[^>]*name="([^"]*)"[^>]*value="([^"]*)"[^>]*>'
        all_matches = re.findall(pattern_all, form_html, re.IGNORECASE)

        for name, value in all_matches:
            # Skip duplicates
            if not any(field.name == name for field in self.form_fields):
                self.form_fields.append(Sam3FormField(name=name, value=value))
                logger.debug(f"Found additional form field: {name} = {value}")

    def _build_username_payload(self, username: str) -> str:
        """Build username submission payload"""
        payload_parts = []

        # Add all hidden fields
        for field in self.form_fields:
            payload_parts.append(f"{field.name}={field.value}")

        # Add username field
        payload_parts.append(f"pw_usr={self._url_encode(username)}")
        payload_parts.append("pw_submit=")
        payload_parts.append("hidden_pwd=")

        return "&".join(payload_parts)

    def _build_password_payload(self, username: str, password: str) -> str:
        """Build password submission payload"""
        payload_parts = []

        # Add all hidden fields (they might have changed)
        for field in self.form_fields:
            payload_parts.append(f"{field.name}={field.value}")

        # Add password fields
        payload_parts.append(f"hidden_usr={self._url_encode(username)}")
        payload_parts.append(f"pw_pwd={self._url_encode(password)}")
        payload_parts.append("pw_submit=")

        return "&".join(payload_parts)

    def _extract_code_and_state(self, redirect_url: str) -> tuple[str, str]:
        """Extract code and state from redirect URL"""
        try:
            parsed = urlparse(redirect_url)
            query_params = parse_qs(parsed.query)

            code = query_params.get('code', [None])[0]
            state = query_params.get('state', [None])[0]

            if code and state:
                logger.debug(f"Extracted code: {code[:8]}..., state: {state}")
                return code, state

            # Also check fragment (#) for SPA redirects
            if '#' in redirect_url:
                fragment = redirect_url.split('#')[1]
                fragment_params = parse_qs(fragment)
                code = fragment_params.get('code', [None])[0]
                state = fragment_params.get('state', [None])[0]

            return code, state

        except Exception as e:
            logger.error(f"Failed to extract code and state from URL: {e}")
            return None, None

    @staticmethod
    def _get_sso_headers() -> Dict[str, str]:
        """Get headers for SSO requests"""
        return {
            'User-Agent': SSO_USER_AGENT,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Origin': 'https://web2.magentatv.de',
            'Referer': 'https://web2.magentatv.de/'
        }

    @staticmethod
    def _url_encode(value: str) -> str:
        """URL encode a string"""
        from urllib.parse import quote
        return quote(value)

    # ========================================================================
    # Configuration Updates
    # ========================================================================

    def update_endpoints(self, openid_config: Dict[str, Any]) -> None:
        """Update endpoints from OpenID configuration"""
        # Update issuer URL from OpenID config
        if 'issuer' in openid_config:
            self.issuer_url = openid_config['issuer']

        # Update other endpoints for user authentication flows
        self.authorization_endpoint = openid_config.get('authorization_endpoint')
        self.userinfo_endpoint = openid_config.get('userinfo_endpoint')

        # Get backchannel auth start endpoint
        if 'backchannel_auth_start' in openid_config:
            self.backchannel_start_url = openid_config['backchannel_auth_start']
            logger.debug(f"Backchannel auth endpoint from OpenID: {self.backchannel_start_url}")

        # OAuth token endpoint might be different from line auth endpoint
        if 'token_endpoint' in openid_config:
            self.oauth_token_endpoint = openid_config['token_endpoint']

        logger.debug(f"Updated SAM3 endpoints: "
                     f"issuer={self.issuer_url}, "
                     f"auth={bool(self.authorization_endpoint)}, "
                     f"oauth_token={bool(self.oauth_token_endpoint)}, "
                     f"line_auth={bool(self.line_auth_endpoint)}, "
                     f"backchannel={bool(self.backchannel_start_url)}")