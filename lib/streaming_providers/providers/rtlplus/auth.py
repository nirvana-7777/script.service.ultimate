# streaming_providers/providers/rtlplus/auth.py
import base64
import json
from typing import Any, Dict, Optional

from ...base.auth.base_auth import BaseAuthToken, TokenAuthLevel
from ...base.auth.base_oauth2_auth import BaseOAuth2Authenticator
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger
from .constants import RTLPlusConfig, RTLPlusDefaults
from .models import (RTLPlusAuthToken, RTLPlusClientCredentials,
                     RTLPlusUserCredentials)


class RTLPlusAuthenticator(BaseOAuth2Authenticator):
    def __init__(
        self,
        credentials=None,
        config_dir=None,
        client_version=None,
        device_id=None,
        proxy_config: Optional[ProxyConfig] = None,
        http_manager=None,
    ):

        # Initialize configuration FIRST
        config_dict = {}
        if client_version:
            config_dict["client_version"] = client_version
        if device_id:
            config_dict["device_id"] = device_id

        self._config = RTLPlusConfig(config_dict)
        self._client_id = None

        # Get proxy_config if not provided
        if proxy_config is None:
            from ...base.network import ProxyConfigManager

            proxy_mgr = ProxyConfigManager(config_dir)
            proxy_config = proxy_mgr.get_proxy_config("rtlplus")

        # Call parent init FIRST
        super().__init__(
            provider_name="rtlplus",
            credentials=credentials,  # Pass None if not provided
            config_dir=config_dir,
            proxy_config=proxy_config,
            http_manager=http_manager,
        )

        # NOW set default credentials if needed (after super init)
        if self.credentials is None:
            self.credentials = self._get_default_credentials()

    @property
    def auth_endpoint(self) -> str:
        """Override auth_endpoint to use our config"""
        return self.config.auth_endpoint

    # Required OAuth2 properties
    @property
    def oauth_client_id(self) -> str:
        return self._get_client_id()

    @property
    def oauth_scope(self) -> str:
        return "openid email"

    @property
    def oauth_redirect_uri(self) -> str:
        return self.config.base_website

    def _get_auth_headers(self) -> Dict[str, str]:
        """RTL+-specific authentication headers"""
        return self.config.get_auth_headers()

    def _build_auth_payload(self) -> Dict[str, Any]:
        """Build authentication payload from credentials"""
        return self.credentials.to_auth_payload()

    def _get_default_credentials(self):
        """Get default client credentials for anonymous access"""
        try:
            # Try to get dynamic credentials first
            config_creds = self._get_anonymous_credentials_from_config()
            if config_creds:
                return RTLPlusClientCredentials(
                    client_id=config_creds.get(
                        "client_id", RTLPlusDefaults.ANONYMOUS_CLIENT_ID
                    ),
                    client_secret=config_creds.get(
                        "client_secret", RTLPlusDefaults.ANONYMOUS_CLIENT_SECRET
                    ),
                )
        except Exception as e:
            logger.warning(f"Could not get dynamic credentials: {e}")

        # Fallback to default credentials
        return RTLPlusClientCredentials()

    def _create_token_from_response(
        self, response_data: Dict[str, Any]
    ) -> RTLPlusAuthToken:
        """Create RTL+-specific token from OAuth2 response"""
        import time

        return RTLPlusAuthToken(
            access_token=response_data["access_token"],
            token_type=response_data.get("token_type", "Bearer"),
            expires_in=response_data.get("expires_in", 86400),
            issued_at=response_data.get("issued_at", time.time()),
            refresh_token=response_data.get("refresh_token"),
            refresh_expires_in=response_data.get("refresh_expires_in", 0),
            not_before_policy=response_data.get("not-before-policy"),
            scope=response_data.get("scope", ""),
        )

    def get_fallback_credentials(self):
        """Get fallback credentials (anonymous client credentials)"""
        return self._get_default_credentials()

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        """
        Classify RTL+ token authentication level by decoding JWT payload

        Logic:
        - CLIENT_CREDENTIALS: isGuest=True AND clientId='anonymous-user'
        - USER_AUTHENTICATED: Has preferred_username OR email claims
        - UNKNOWN: Cannot determine or invalid token

        Args:
            token: Token to classify

        Returns:
            TokenAuthLevel indicating the authentication level
        """
        if not token or not token.access_token:
            logger.debug("RTL+ Cannot classify: No token or access token")
            return TokenAuthLevel.UNKNOWN

        try:
            # Decode JWT without verification to check the payload
            parts = token.access_token.split(".")
            if len(parts) < 2:
                logger.debug("RTL+ Cannot classify: Invalid token format")
                return TokenAuthLevel.UNKNOWN

            # Add padding if needed and decode
            payload_segment = parts[1]
            padding = 4 - len(payload_segment) % 4
            if padding != 4:
                payload_segment += "=" * padding

            payload_json = base64.b64decode(payload_segment)
            payload = json.loads(payload_json)

            # Extract relevant claims
            client_id = payload.get("clientId")
            is_guest = payload.get("isGuest", False)
            preferred_username = payload.get("preferred_username")
            email = payload.get("email")

            logger.debug(
                f"RTL+ Token JWT payload: clientId={client_id}, isGuest={is_guest}, "
                f"has_preferred_username={bool(preferred_username)}, has_email={bool(email)}"
            )

            # Check for user-authenticated token
            if preferred_username or email:
                logger.debug(
                    "RTL+ Token classified as USER_AUTHENTICATED (has user claims)"
                )
                return TokenAuthLevel.USER_AUTHENTICATED

            # Check for client credentials (anonymous) token
            if is_guest and client_id == "anonymous-user":
                logger.debug("RTL+ Token classified as CLIENT_CREDENTIALS (anonymous)")
                return TokenAuthLevel.CLIENT_CREDENTIALS

            # Cannot determine
            logger.debug("RTL+ Token classified as UNKNOWN (no matching criteria)")
            return TokenAuthLevel.UNKNOWN

        except Exception as e:
            logger.warning(f"RTL+ Error classifying token: {e}")
            return TokenAuthLevel.UNKNOWN

    def _perform_oauth_authorization_code_flow(
        self, username: str, password: str
    ) -> Dict[str, Any]:
        """
        RTL+ specific OAuth2 authorization code flow with PKCE
        Uses base class generic form login
        """
        return self._perform_generic_form_login(
            username=username,
            password=password,
            form_selector_pattern=r'<form id="rtlplus-form-login" action="([^"]*)"',
            login_fields={"username": "username", "password": "password"},
            extra_params={"prompt": "login"},
            additional_form_data={"credentialId": "", "rememberMe": "on"},
        )

    def _get_client_id(self) -> str:
        """Get client ID from RTL+ website configuration using base class method"""
        if self._client_id:
            return self._client_id

        # Use base class method for extraction
        self._client_id = self._extract_client_id_from_js(
            main_page_url=self.config.base_website,
            js_file_pattern=r'<script src="(main[A-z0-9\-\.]+\.js)"',
            client_id_pattern=r'clientId:"([^"]+)"',
        )

        if self._client_id:
            return self._client_id

        # Fallback to default if extraction failed
        logger.warning("Could not extract client ID, using default")
        return RTLPlusDefaults.CLIENT_ID

    def _get_client_version(self) -> str:
        """Get client version from RTL+ configuration"""
        if self.config.client_version != RTLPlusDefaults.CLIENT_VERSION:
            return self.config.client_version

        try:
            headers = self.config.get_base_headers()
            response = self.http_manager.get(
                self.config.config_endpoint, operation="api", headers=headers
            )
            response.raise_for_status()

            config_data = response.json()
            version = config_data.get("version", RTLPlusDefaults.CLIENT_VERSION)

            # Update config with retrieved version
            self.config.client_version = version
            return version

        except Exception as e:
            logger.error(f"Error getting client version: {e}")
            return self.config.client_version

    def _get_anonymous_credentials_from_config(self) -> Optional[Dict[str, str]]:
        """
        Extract anonymous credentials from RTL+ website configuration
        Uses base class generic config extraction
        """

        def parse_credentials(config_str: str) -> Dict[str, str]:
            """Parse anonymousCredentials config string"""
            credentials = {}
            for pair in config_str.split(","):
                if ":" in pair:
                    key, value = pair.split(":", 1)
                    key = key.strip().strip('"')
                    value = value.strip().strip('"')
                    credentials[key] = value
            return credentials

        return self._extract_config_from_js(
            main_page_url=self.config.base_website,
            js_file_pattern=r'<script src="(main[A-z0-9\-\.]+\.js)"',
            config_pattern=r"anonymousCredentials:\{([^}]+)\}",
            parse_function=parse_credentials,
        )

    # RTL+-specific credential management methods
    def set_user_credentials(
        self, username: str, password: str, client_id: Optional[str] = None
    ) -> bool:
        """
        Set RTL+ user credentials for authentication

        Args:
            username: RTL+ username/email
            password: RTL+ password
            client_id: Optional client ID for user authentication

        Returns:
            True if credentials were set and saved successfully
        """
        try:
            # Create new user credentials
            user_creds = RTLPlusUserCredentials(
                username=username, password=password, client_id=client_id
            )

            # Validate credentials
            if not user_creds.validate():
                logger.warning("Invalid user credentials provided")
                return False

            # Set as current credentials
            self.credentials = user_creds

            # Save to persistent storage
            success = self.save_credentials(user_creds)
            if success:
                logger.info("RTL+ user credentials saved successfully")
                # Invalidate current token to force re-authentication with new credentials
                self.invalidate_token()
            else:
                logger.error("Failed to save RTL+ user credentials")

            return success

        except Exception as e:
            logger.error(f"Error setting RTL+ user credentials: {e}")
            return False

    def has_user_credentials(self) -> bool:
        """
        Check if user credentials are currently set (not anonymous)

        Returns:
            True if using user credentials, False if using anonymous access
        """
        from ...base.auth.credentials import UserPasswordCredentials

        return isinstance(
            self.credentials, (RTLPlusUserCredentials, UserPasswordCredentials)
        )

    def has_stored_credentials(self) -> bool:
        """
        Check for stored RTL+ user credentials
        """
        try:
            logger.debug("RTL+ Checking for stored credentials using settings manager")
            stored_creds = self.settings_manager.get_provider_credentials(
                self.provider_name
            )

            if not stored_creds:
                logger.debug("RTL+ No stored credentials found")
                return False

            # Import the base credential types
            from ...base.auth.credentials import UserPasswordCredentials

            # Check if it's either RTLPlusUserCredentials OR base UserPasswordCredentials
            is_user_creds = isinstance(
                stored_creds, (RTLPlusUserCredentials, UserPasswordCredentials)
            )
            logger.debug(
                f"RTL+ Has stored user credentials: {is_user_creds} (type: {type(stored_creds)})"
            )

            return is_user_creds

        except Exception as e:
            logger.debug(f"RTL+ Error checking stored credentials: {e}")
            return False

    def get_authentication_status(self) -> Dict[str, Any]:
        """
        Get RTL+-specific authentication status information
        """
        status = super().get_authentication_status()

        # Add RTL+-specific information
        status.update(
            {
                "has_user_credentials": self.has_user_credentials(),
                "authentication_mode": (
                    "user" if self.has_user_credentials() else "anonymous"
                ),
                "client_version": self.config.client_version,
            }
        )

        if self.has_user_credentials() and hasattr(self.credentials, "username"):
            status["username"] = self.credentials.username

        return status
