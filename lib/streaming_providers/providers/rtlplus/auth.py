# streaming_providers/providers/rtlplus/auth.py
import base64
import json
import time
import hashlib
from typing import Any, Dict, Optional, List

from ...base.auth.base_auth import BaseAuthToken, TokenAuthLevel
from ...base.auth.base_oauth2_auth import BaseOAuth2Authenticator
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger
from .constants import RTLPlusConfig, RTLPlusDefaults
from .models import RTLPlusAuthToken, RTLPlusClientCredentials, RTLPlusUserCredentials


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

        config_dict = {}
        if client_version:
            config_dict["client_version"] = client_version
        if device_id:
            config_dict["device_id"] = device_id

        if proxy_config is None:
            from ...base.network import ProxyConfigManager

            proxy_mgr = ProxyConfigManager(config_dir)
            proxy_config = proxy_mgr.get_proxy_config("rtlplus")

        super().__init__(
            provider_name="rtlplus",
            credentials=credentials,
            config_dir=config_dir,
            proxy_config=proxy_config,
            http_manager=http_manager,
        )

        # AFTER super().__init__ so the base class can't overwrite it
        self._config = RTLPlusConfig(config_dict)
        self._client_id = None
        self._bedrock_token: Optional[str] = None
        self._bedrock_token_expiry: float = 0
        self._cached_user_id: Optional[str] = None
        self._selected_profile_id: Optional[str] = None

        self.enable_oidc_discovery(
            discovery_url=RTLPlusDefaults.AUTH_REALM_BASE,
            cache_ttl=86400  # Cache for 24 hours
        )

        if self.credentials is None:
            self.credentials = self._get_default_credentials()

    @property
    def auth_endpoint(self) -> str:
        return self.config.auth_endpoint

    @property
    def oauth_client_id(self) -> str:
        # Dynamic: refresh_token grants must be replayed against the same
        # client_id the token was originally issued under. Web login uses
        # BEDROCK_CLIENT_ID; the device/QR flow uses DEVICE_CLIENT_ID.
        # _build_refresh_payload() (base class, base_oauth2_auth.py) reads
        # this property, so keeping it dynamic is what makes refresh work
        # for both flows without overriding _build_refresh_payload().
        current = getattr(self, "_current_token", None)
        login_client = getattr(current, "login_client", None)
        return login_client or RTLPlusDefaults.BEDROCK_CLIENT_ID

    @property
    def oauth_scope(self) -> str:
        return "openid email profile"

    @property
    def oauth_redirect_uri(self) -> str:
        # Used in authorize step
        return "https://plus.rtl.de/tv-programm"

    @property
    def oauth_token_redirect_uri(self) -> str:
        # Used in the token exchange step
        return f"{self.config.base_website}silent-sso-iframe.html"

    @property
    def config(self) -> RTLPlusConfig:
        return self._config

    def _get_auth_headers(self) -> Dict[str, str]:
        return self.config.get_auth_headers()

    def _build_auth_payload(self) -> Dict[str, Any]:
        return self.credentials.to_auth_payload()

    def _get_default_credentials(self):
        try:
            config_creds = self._get_anonymous_credentials_from_config()
            if config_creds:
                return RTLPlusClientCredentials(
                    client_id=config_creds.get("client_id", RTLPlusDefaults.ANONYMOUS_CLIENT_ID),
                    client_secret=config_creds.get("client_secret", RTLPlusDefaults.ANONYMOUS_CLIENT_SECRET),
                )
        except Exception as e:
            logger.warning(f"Could not get dynamic credentials: {e}")

        return RTLPlusClientCredentials()

    def _create_token_from_response(self, response_data: Dict[str, Any]) -> RTLPlusAuthToken:
        # Carry forward login_client so refresh keeps using the right
        # client_id. Normal OAuth token responses never include this key
        # (it's our own bookkeeping); if absent, fall back to whatever
        # client issued the token being replaced.
        login_client = response_data.get("login_client")
        if not login_client:
            current = getattr(self, "_current_token", None)
            login_client = getattr(current, "login_client", None)

        return RTLPlusAuthToken(
            access_token=response_data["access_token"],
            token_type=response_data.get("token_type", "Bearer"),
            expires_in=response_data.get("expires_in", 86400),
            issued_at=response_data.get("issued_at", time.time()),
            refresh_token=response_data.get("refresh_token"),
            refresh_expires_in=response_data.get("refresh_expires_in", 0),
            not_before_policy=response_data.get("not-before-policy"),
            scope=response_data.get("scope", ""),
            login_client=login_client,
        )

    def get_current_token_level(self) -> TokenAuthLevel:
        for attr in ("token", "_token", "current_token", "_current_token", "_access_token"):
            tok = getattr(self, attr, None)
            if tok is not None:
                return self._classify_token(tok)
        return TokenAuthLevel.UNKNOWN

    def get_fallback_credentials(self):
        return self._get_default_credentials()

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        if not token or not token.access_token:
            return TokenAuthLevel.UNKNOWN

        try:
            parts = token.access_token.split(".")
            if len(parts) < 2:
                return TokenAuthLevel.UNKNOWN

            payload_segment = parts[1]
            padding = 4 - len(payload_segment) % 4
            if padding != 4:
                payload_segment += "=" * padding

            payload_json = base64.b64decode(payload_segment)
            payload = json.loads(payload_json)

            client_id = payload.get("clientId")
            is_guest = payload.get("isGuest", False)
            preferred_username = payload.get("preferred_username")
            email = payload.get("email")

            if preferred_username or email:
                return TokenAuthLevel.USER_AUTHENTICATED

            if is_guest and client_id == "anonymous-user":
                return TokenAuthLevel.CLIENT_CREDENTIALS

            return TokenAuthLevel.UNKNOWN

        except Exception as e:
            logger.warning(f"RTL+ Error classifying token: {e}")
            return TokenAuthLevel.UNKNOWN

    def _perform_oauth_authorization_code_flow(self, username: str, password: str) -> Dict[str, Any]:
        import uuid
        return self._perform_generic_form_login(
            username=username,
            password=password,
            form_selector_pattern=r'<form id="rtlplus-form-login" action="([^"]*)"',
            login_fields={"username": "username", "password": "password"},
            extra_params={
                "prompt": "login",
                "nonce": str(uuid.uuid4()),
                "claim": "sub",
                "state": '{"redirectUrl":"#"}',
                "auth_flow_type": "login",
            },
            additional_form_data={"credentialId": "", "rememberMe": "on"},
        )

    def generate_oauth_state(self) -> str:
        """RTL+ uses a fixed state value instead of a random one."""
        fixed_state = '{"redirectUrl":"#"}'
        self._oauth_state = fixed_state
        return fixed_state

    def _build_token_exchange_payload(self, authorization_code, code_verifier, state=None, **kwargs):
        token_redirect = self.oauth_redirect_uri  # Use the same as authorize step
        logger.debug(f"Token exchange redirect_uri: {token_redirect}")
        return {
            "grant_type": "authorization_code",
            "client_id": self.oauth_client_id,
            "code": authorization_code,
            "redirect_uri": token_redirect,
            "code_verifier": code_verifier,
        }

    def _get_token_exchange_headers(self, **kwargs) -> Dict[str, str]:
        headers = self._get_auth_headers()
        headers.update({
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://base.plus.rtl.de",
            "Referer": "https://base.plus.rtl.de/",
        })
        return headers

    def _get_client_id(self) -> str:
        if self._client_id:
            return self._client_id

        self._client_id = self._extract_client_id_from_js(
            main_page_url=self.config.base_website,
            js_file_pattern=r'<script src="(main[A-z0-9\-\.]+\.js)"',
            client_id_pattern=r'clientId:"([^"]+)"',
        )

        if self._client_id:
            return self._client_id

        logger.warning("Could not extract client ID, using default")
        return RTLPlusDefaults.CLIENT_ID

    def _get_client_version(self) -> str:
        if self.config.client_version != RTLPlusDefaults.CLIENT_VERSION_FALLBACK:
            return self.config.client_version

        try:
            headers = self.config.get_base_headers()
            response = self.http_manager.get(self.config.config_endpoint, operation="api", headers=headers)
            response.raise_for_status()

            config_data = response.json()
            version = config_data.get("version", RTLPlusDefaults.CLIENT_VERSION_FALLBACK)

            self.config.client_version = version
            return version

        except Exception as e:
            logger.error(f"Error getting client version: {e}")
            return self.config.client_version

    def _get_anonymous_credentials_from_config(self) -> Optional[Dict[str, str]]:
        def parse_credentials(config_str: str) -> Dict[str, str]:
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

    # --------------------------------------------------------------------------
    # Bedrock Token Management (Linear TV)
    # --------------------------------------------------------------------------

    def _get_server_timestamp(self) -> int:
        """Get current server timestamp from RTL+ time endpoint."""
        if self._config is None:
            raise RuntimeError("RTLPlusAuthenticator._config is None — object was not properly initialised")
        try:
            response = self.http_manager.get(
                self._config.time_endpoint,
                operation="api",
                headers={"User-Agent": self.config.user_agent}
            )
            data = response.json()
            return data.get("timestamp", int(time.time()))
        except Exception as e:
            logger.warning(f"Could not fetch server timestamp: {e}")
            return int(time.time())

    @staticmethod
    def _generate_auth_token(device_id: str, timestamp: int) -> str:
        """
        Generate the x-auth-token required for Bedrock API calls.

        Based on analysis, this appears to be a SHA-1 hash of device_id + timestamp.
        """
        ts_str = str(timestamp)
        data = f"{device_id}{ts_str}"
        token = hashlib.sha1(data.encode()).hexdigest()

        logger.debug(f"Generated auth token for device {device_id} at {timestamp}: {token}")
        return token

    def get_bedrock_token(self, force_refresh: bool = False) -> str:
        """Get or refresh Bedrock token, including profile ID if available."""
        if self._config is None:
            raise RuntimeError("RTLPlusAuthenticator._config is None — object was not properly initialised")
        if not force_refresh and self._bedrock_token and self._bedrock_token_expiry > time.time() + 300:
            logger.debug(f"Using cached bedrock token (expires at {self._bedrock_token_expiry})")
            return self._bedrock_token

        oauth_token = self.get_bearer_token()
        if not oauth_token:
            raise ValueError("No OAuth token available for Bedrock token request")

        user_id = self.get_user_id_from_token()
        if not user_id:
            logger.warning("No user ID available for Bedrock token request")

        timestamp = self._get_server_timestamp()
        auth_token = self._generate_auth_token(self.config.device_id, timestamp)

        logger.debug(f"Timestamp: {timestamp}, Auth token: {auth_token}")

        profile_id = self.get_selected_profile_id()
        logger.debug(f"Using profile_id: {profile_id}")

        headers = self.config.get_bedrock_token_headers(
            oauth_token=oauth_token,
            auth_token=auth_token,
            timestamp=timestamp,
            profile_id=profile_id,
            user_id=user_id,
        )

        logger.debug(
            f"Requesting Bedrock token with headers: { {k: v[:20] if 'token' in k.lower() or 'authorization' in k.lower() else v for k, v in headers.items()} }")

        response = self.http_manager.get(
            self.config.bedrock_auth_url,
            headers=headers,
            operation="api",
        )
        response.raise_for_status()

        data = response.json()
        self._bedrock_token = data.get("token")
        logger.debug(f"Bedrock token response: {data.keys() if data else 'empty'}")

        if self._bedrock_token:
            try:
                parts = self._bedrock_token.split(".")
                if len(parts) >= 2:
                    payload = parts[1]
                    padding = 4 - len(payload) % 4
                    if padding != 4:
                        payload += "=" * padding
                    decoded = json.loads(base64.b64decode(payload))
                    self._bedrock_token_expiry = decoded.get("exp", 0)
                    logger.debug(
                        f"Bedrock token obtained with profile: {decoded.get('profileid', 'none')}, expires: {self._bedrock_token_expiry}")
            except Exception as e:
                logger.debug(f"Could not decode Bedrock token expiry: {e}")
                self._bedrock_token_expiry = time.time() + 3600

        logger.debug("RTL+ Bedrock token obtained successfully")
        return self._bedrock_token

    def get_upfront_token(self, content_id: str, uid: str) -> str:
        """
        Get upfront token for DRM license acquisition.

        The upfront token is used as x-dt-auth-token when requesting
        licenses from DRMToday.
        """
        oauth_token = self.get_bearer_token()
        bedrock_token = self.get_bedrock_token()

        url = self.config.get_upfront_token_url(uid=uid, content_id=content_id)
        headers = self.config.get_upfront_token_headers(oauth_token, bedrock_token)

        response = self.http_manager.get(url, headers=headers, operation="api")
        response.raise_for_status()

        data = response.json()
        token = data.get("token")

        if not token:
            raise ValueError("No token in upfront token response")

        logger.debug(f"RTL+ Upfront token obtained for {content_id}")
        return token

    def invalidate_bedrock_token(self) -> None:
        """Invalidate cached Bedrock token"""
        self._bedrock_token = None
        self._bedrock_token_expiry = 0

    def get_user_id_from_token(self) -> Optional[str]:
        """
        Extract user ID (sub claim) from the current OAuth token.
        """
        if self._cached_user_id:
            return self._cached_user_id

        token = self.get_bearer_token()
        if not token:
            return None

        try:
            parts = token.split(".")
            if len(parts) < 2:
                return None

            payload_segment = parts[1]
            padding = 4 - len(payload_segment) % 4
            if padding != 4:
                payload_segment += "=" * padding

            payload_json = base64.b64decode(payload_segment)
            payload = json.loads(payload_json)

            # Format: f:83a2e227-f27d-4d33-a811-33ad588170c4:1052940424
            sub = payload.get("sub", "")

            if ":" in sub:
                self._cached_user_id = sub.split(":")[-1]
            else:
                self._cached_user_id = sub

            return self._cached_user_id

        except Exception as e:
            logger.warning(f"Could not extract user ID from token: {e}")
            return None

    # --------------------------------------------------------------------------
    # Credential Management
    # --------------------------------------------------------------------------

    def set_user_credentials(self, username: str, password: str, client_id: Optional[str] = None) -> bool:
        try:
            user_creds = RTLPlusUserCredentials(username=username, password=password, client_id=client_id)

            if not user_creds.validate():
                logger.warning("Invalid user credentials provided")
                return False

            self.credentials = user_creds
            success = self.save_credentials(user_creds)

            if success:
                logger.info("RTL+ user credentials saved successfully")
                self.invalidate_token()
                self.invalidate_bedrock_token()
                self._cached_user_id = None
            else:
                logger.error("Failed to save RTL+ user credentials")

            return success

        except Exception as e:
            logger.error(f"Error setting RTL+ user credentials: {e}")
            return False

    def has_user_credentials(self) -> bool:
        from ...base.auth.credentials import UserPasswordCredentials
        return isinstance(self.credentials, (RTLPlusUserCredentials, UserPasswordCredentials))

    def has_stored_credentials(self) -> bool:
        try:
            stored_creds = self.settings_manager.get_provider_credentials(self.provider_name)

            if not stored_creds:
                return False

            from ...base.auth.credentials import UserPasswordCredentials
            return isinstance(stored_creds, (RTLPlusUserCredentials, UserPasswordCredentials))

        except Exception as e:
            logger.debug(f"RTL+ Error checking stored credentials: {e}")
            return False

    def get_authentication_status(self) -> Dict[str, Any]:
        status = super().get_authentication_status()
        status.update({
            "has_user_credentials": self.has_user_credentials(),
            "authentication_mode": ("user" if self.has_user_credentials() else "anonymous"),
            "client_version": self.config.client_version,
            "has_bedrock_token": bool(self._bedrock_token),
            "has_user_id": bool(self._cached_user_id),
        })
        if self.has_user_credentials() and hasattr(self.credentials, "username"):
            status["username"] = self.credentials.username
        return status

    def get_user_profiles(self, user_id: str = None) -> List[Dict[str, Any]]:
        """
        Fetch available profiles for a user.
        """
        if not user_id:
            user_id = self.get_user_id_from_token()
            if not user_id:
                raise ValueError("No user ID available")

        oauth_token = self.get_bearer_token()
        bedrock_token = self.get_bedrock_token()

        url = self.config.get_profiles_url(user_id)
        headers = self.config.get_profiles_headers(oauth_token, bedrock_token)

        response = self.http_manager.get(url, headers=headers, operation="api")
        response.raise_for_status()
        return response.json()

    def select_profile(self, profile_id: str = None) -> bool:
        """
        Select a profile to use for this session.
        If no profile_id provided, fetches profiles and selects the first adult profile.
        """
        if not profile_id:
            user_id = self.get_user_id_from_token()
            if not user_id:
                logger.error("Cannot select profile: No user ID available")
                return False

            try:
                profiles = self.get_user_profiles(user_id)
                logger.debug(f"Fetched profiles: {profiles}")

                adult_profiles = [p for p in profiles if p.get("profile_type") == "adult"]
                if not adult_profiles:
                    logger.error("No adult profiles found")
                    return False

                profile_id = adult_profiles[0].get("uid")
                profile_username = adult_profiles[0].get("username")
                logger.info(f"Selected profile: {profile_username} (ID: {profile_id})")
            except Exception as e:
                logger.error(f"Failed to fetch/select profile: {e}")
                return False

        self._selected_profile_id = profile_id

        if hasattr(self.credentials, "profile_id"):
            self.credentials.profile_id = profile_id
            self.save_credentials(self.credentials)

        self.invalidate_bedrock_token()

        logger.info(f"Profile selected successfully: {profile_id}")
        return True

    def get_selected_profile_id(self) -> Optional[str]:
        """Get the currently selected profile ID."""
        if hasattr(self, "_selected_profile_id") and self._selected_profile_id:
            return self._selected_profile_id

        if hasattr(self.credentials, "profile_id") and self.credentials.profile_id:
            return self.credentials.profile_id

        return None

    def ensure_profile_selected(self) -> bool:
        """Ensure a profile is selected, auto-selecting if needed."""
        if self.get_selected_profile_id():
            return True

        if self.has_user_credentials():
            return self.select_profile()

        return False

    # --------------------------------------------------------------------------
    # Remote Login (Device Code / QR) — overrides base's PKCE remote login,
    # which uses a different protocol RTL+ does not support for this flow.
    # See remote_login_handler.py in this package for the implementation.
    # --------------------------------------------------------------------------

    def _perform_remote_login_flow(self) -> Dict[str, Any]:
        """
        Called automatically by the base class's authenticate_with_fallback()
        when _perform_oauth_authorization_code_flow() raises WafBlockedException.

        RTL+'s remote login is a genuine OAuth2 Device Authorization Grant
        (RFC 8628) against a dedicated TV/device client, not the PKCE
        authorization_code + callback flow the base class implements by
        default (BaseOAuth2Authenticator._perform_remote_login_flow /
        RemoteLoginManager) — that flow's redirect_uri isn't reachable
        from a phone completing the login, so it doesn't apply here.
        """
        from .remote_login_handler import RTLRemoteLoginHandler

        handler = RTLRemoteLoginHandler(
            http_manager=self.http_manager,
            device_client_id=RTLPlusDefaults.DEVICE_CLIENT_ID,
            device_auth_url=RTLPlusDefaults.DEVICE_AUTH_ENDPOINT,
            token_endpoint=RTLPlusDefaults.AUTH_ENDPOINT,
            provider_name="RTL+",
        )

        token_data = handler.perform_complete_flow()

        if not token_data:
            raise Exception("RTL+ remote login failed")

        # Tag which client issued this token so oauth_client_id /
        # _create_token_from_response can route refreshes correctly.
        token_data.setdefault("login_client", RTLPlusDefaults.DEVICE_CLIENT_ID)
        return token_data