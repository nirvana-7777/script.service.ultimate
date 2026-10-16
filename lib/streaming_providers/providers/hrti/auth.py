# streaming_providers/providers/hrti/auth.py
"""
HRTiAuthenticator -- stateful login flow (Variant B raw authenticator).

Managers never call this class; they go through HRTiSession (the AuthProtocol
adapter). The provider keeps both objects: ``self.authenticator`` for the
legacy auth mixin, ``self.auth`` (the session) for the managers.

Device identity
---------------
The device id (a UUID) is CLIENT identity, not account state: it survives
invalidate() / refresh() and is deliberately NOT cleared with the token. It
is loaded from the settings manager on startup (flat keys, country=None) and
persisted whenever a fresh one is generated or the ErrorCode-4 recovery
re-registers it (register_device -> _persist_device_id). The server-side
registration of that id can expire while the stored id lives on -- that is
ErrorCode 4, recovered reactively by api.api_post (ONE re-registration + ONE
retry, then AuthError).
"""

import json
import time
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from ...base.auth.base_auth import BaseAuthenticator, BaseAuthToken, TokenAuthLevel
from ...base.errors import AuthError, ProviderError, ServerError
from ...base.utils.logger import logger
from .api import DEVICE_SESSION_INVALID_CODE, typed_error_for
from .constants import HRTiConfig, HRTiDefaults
from .models import HRTiAuthToken, HRTiCredentials


class HRTiAuthenticator(BaseAuthenticator):
    def __init__(self, *, http_manager, config: HRTiConfig, credentials=None, config_dir=None):
        """
        ``config`` is the ONE HRTiConfig of the provider (shared with session
        and managers; never build a second one here). Storage keys stay FLAT
        (country=None): credentials, persisted session and device id of
        existing installations are stored without a country.
        """
        if http_manager is None:
            raise ValueError("http_manager is required for HRTiAuthenticator")
        self._config = config
        self._http_manager = http_manager

        # HRTi-specific state BEFORE the parent init (it loads the session)
        self._ip_address = None
        self._device_id = None
        self._user_id = None

        super().__init__(
            provider_name=HRTiDefaults.PROVIDER_NAME,
            credentials=credentials,
            country=None,
            config_dir=config_dir,
        )
        self._initialize_device()

    @property
    def config(self):
        """Safe access to config"""
        return self._config

    @property
    def http_manager(self):
        """Safe access to http_manager - required by provider"""
        if self._http_manager is None:
            # This should never happen since we validate in __init__
            raise ValueError(
                "HTTP manager not available - this should have been set during initialization"
            )
        return self._http_manager

    @http_manager.setter
    def http_manager(self, value):
        """Allow setting http_manager"""
        self._http_manager = value

    @property
    def auth_endpoint(self) -> str:
        """HRTi authentication endpoint"""
        return self.config.endpoint("grant_access")

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers specifically for authentication endpoint"""
        if not self._ip_address:
            self._get_ip_address()

        device_id = self.get_device_id()

        # Special headers for authentication endpoint with /signin referer
        headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "deviceid": device_id,
            "devicetypeid": self.config.device_reference_id,
            "ipaddress": self._ip_address,
            "operatorreferenceid": self.config.operator_reference_id,
            "origin": self.config.base_website,
            "referer": f"{self.config.base_website}/signin",
        }

        return headers

    def _get_api_headers(self, bearer_token: str = None, referer: str = None) -> Dict[str, str]:
        """Get headers for regular API endpoints with proper session support"""
        if not self._ip_address:
            self._get_ip_address()

        device_id = self.get_device_id()

        if referer is None:
            referer = f"{self.config.base_website}/login"

        headers = {
            "connection": "keep-alive",
            "User-Agent": self.config.user_agent,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "deviceid": device_id,
            "devicetypeid": self.config.device_reference_id,
            "ipaddress": self._ip_address,
            "operatorreferenceid": self.config.operator_reference_id,
            "origin": self.config.base_website,
            "referer": referer,
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
        }

        # Add authorization header with Client prefix
        if bearer_token:
            headers["authorization"] = f"Client {bearer_token}"
            logger.debug("Added authorization header to API headers")

        return headers

    def _build_auth_payload(self) -> Dict[str, Any]:
        """Build HRTi-specific authentication payload"""
        # HRTi uses specific format: {"Username":"...","Password":"...","OperatorReferenceId":"hrt"}
        if hasattr(self.credentials, "username") and hasattr(self.credentials, "password"):
            return {
                "Username": self.credentials.username,
                "Password": self.credentials.password,
                "OperatorReferenceId": self.config.operator_reference_id,
            }
        else:
            # Fallback for any other credential type
            return {
                "Username": getattr(self.credentials, "username", ""),
                "Password": getattr(self.credentials, "password", ""),
                "OperatorReferenceId": self.config.operator_reference_id,
            }

    def _create_token_from_response(self, response_data: Dict[str, Any]) -> HRTiAuthToken:
        """Create HRTi-specific token from API response"""
        result = response_data.get("Result", {})

        # Debug the response structure
        logger.debug(f"GrantAccess response Result keys: {list(result.keys())}")

        # Extract token
        access_token = result.get("Token", "")
        logger.debug(f"Extracted access_token: {'present' if access_token else 'MISSING'}")

        # Store user ID if available
        if "Customer" in result:
            self._user_id = result["Customer"].get("CustomerId", "")
            logger.debug(f"Extracted user_id: {self._user_id}")
        else:
            logger.warning("No Customer data in response")

        token = HRTiAuthToken(
            access_token=access_token,
            token_type="Client",
            expires_in=HRTiDefaults.TOKEN_LIFETIME_SECONDS,  # GrantAccess carries no lifetime
            issued_at=time.time(),
            user_id=self._user_id or "",  # Ensure user_id is never None
            valid_from=result.get("ValidFrom", ""),
            valid_to=result.get("ValidTo", ""),
        )

        # Classify the token immediately after creation
        token.auth_level = self._classify_token(token)

        logger.debug(
            f"Created HRTiAuthToken - access_token: {bool(token.access_token)}, user_id: {token.user_id}"
        )

        return token

    def get_fallback_credentials(self):
        """Get fallback credentials (anonymous access)"""
        return HRTiCredentials(
            username=HRTiDefaults.ANONYMOUS_USERNAME,
            password=HRTiDefaults.ANONYMOUS_PASSWORD,
        )

    def _perform_authentication(self) -> HRTiAuthToken:
        """Perform HRTi custom authentication flow"""
        logger.info("Starting HRTi authentication flow")

        # Step 1: Get IP address
        self._get_ip_address()

        # Step 2: Get environment configuration
        self._get_environment_config()

        # Step 3: Perform grant access
        token_data = self._perform_grant_access()

        # Step 4: Create token and SET IT AS CURRENT TOKEN
        token = self._create_token_from_response(token_data)
        self._current_token = token  # THIS IS THE CRITICAL MISSING LINE

        # Debug: Verify token is available
        logger.debug(f"Token created - access_token present: {bool(token.access_token)}")
        if not token.access_token:
            logger.warning("Token created but access_token is empty!")

        # Step 5: Register device (now with token available in self._current_token)
        self._register_device()

        # Step 6: Get content rating and profiles
        self._get_initial_data()

        logger.info(
            f"HRTi authentication successful - user_id: {token.user_id}, auth_level: {token.auth_level.value}"
        )

        # Save the session after successful authentication
        self._save_session()

        return token

    def _get_ip_address(self) -> str:
        """Get public IP address - prefer configured IP from settings, fallback to API"""
        if self._ip_address:
            return self._ip_address

        # Priority 1: Try to get configured IP from Kodi settings
        try:
            configured_ip = self._get_configured_ip_from_settings()
            if configured_ip:
                self._ip_address = configured_ip
                logger.info(f"Using configured IP address from Kodi settings: {self._ip_address}")
                return self._ip_address
        except Exception as e:
            logger.debug(f"Could not read configured IP from settings: {e}")

        # Priority 2: ask the API (endpoint resolved lazily from the dynamic config)
        try:
            logger.debug("No configured IP found, fetching from API...")
            response = self.http_manager.get(self.config.endpoint("get_ip"), operation="api")
            response.raise_for_status()
            self._ip_address = response.text.strip().strip('"')  # Remove quotes if present
            logger.info(f"Retrieved IP address from API: {self._ip_address}")
            return self._ip_address
        except Exception as e:
            # Not cached: the next call may succeed
            logger.error(f"Error getting IP address from API: {e}")
            return "0.0.0.0"

    def _get_configured_ip_from_settings(self) -> Optional[str]:
        """
        Get configured IP address from Kodi settings via settings_manager

        Returns:
            Configured IP address or None if not available
        """
        # Access settings_manager through parent class
        if not hasattr(self, "settings_manager") or not self.settings_manager:
            logger.debug("Settings manager not available for IP configuration")
            return None

        kodi_bridge = self.settings_manager.kodi_bridge
        if not kodi_bridge or not kodi_bridge.is_kodi_environment():
            logger.debug("Kodi bridge not available or not in Kodi environment")
            return None

        # Try to read IP from Kodi settings
        # HRTi doesn't use country in this implementation, pass None
        configured_ip = kodi_bridge.read_ip_address_from_kodi("hrti", None)

        if configured_ip:
            logger.debug(f"Found configured IP in Kodi settings: {configured_ip}")
            return configured_ip

        return None

    def _get_environment_config(self):
        """Dynamic endpoints (env.json / config.production.json), loaded once by
        the shared config -- also used by the managers, independent of login."""
        self.config.ensure_loaded()

    def _perform_grant_access(self) -> Dict[str, Any]:
        """Perform grant access authentication with proper headers and debugging"""
        try:
            # Ensure we have IP and device ID
            if not self._ip_address:
                self._get_ip_address()

            device_id = self.get_device_id()

            logger.debug(f"Performing grant access with username: {self.credentials.username}")
            logger.debug(f"Using device ID: {device_id}")
            logger.debug(f"Using IP address: {self._ip_address}")

            # Use auth-specific headers with /signin referer
            headers = self._get_auth_headers()
            payload = self._build_auth_payload()

            # Log the request details (safely)
            safe_headers = headers.copy()
            if "deviceid" in safe_headers:
                safe_headers["deviceid"] = f"{safe_headers['deviceid'][:8]}..."
            logger.debug(f"HRTi Auth Headers: {safe_headers}")

            safe_payload = payload.copy()
            if "Password" in safe_payload:
                safe_payload["Password"] = "***" if safe_payload["Password"] else "<empty>"
            logger.debug(f"HRTi Auth Payload: {safe_payload}")

            auth_endpoint = self.auth_endpoint  # ConfigurationError when missing

            response = self.http_manager.post(
                auth_endpoint,
                operation="auth",
                headers=headers,
                data=json.dumps(payload),
            )

            logger.debug(f"HRTi Auth Response - Status: {response.status_code}")
            response.raise_for_status()

            result = response.json()
            if "Result" not in result:
                raise AuthError(
                    "HRTi: GrantAccess response has no Result "
                    f"(ErrorCode={result.get('ErrorCode')}: {result.get('ErrorDescription')})"
                )

            customer_id = result.get("Result", {}).get("Customer", {}).get("CustomerId", "unknown")
            logger.debug(f"Grant access successful - user: {customer_id}")
            return result

        except Exception as e:
            logger.error(f"HRTi grant access failed: {e}")
            # Only fallback to anonymous if we're not already using it
            if (
                    not isinstance(self.credentials, HRTiCredentials)
                    or self.credentials.username != HRTiDefaults.ANONYMOUS_USERNAME
            ):
                logger.info("Falling back to anonymous credentials")
                self.credentials = self.get_fallback_credentials()
                return self._perform_grant_access()
            else:
                if isinstance(e, ProviderError):
                    raise
                raise ServerError(f"HRTi login failed: {e}") from e

    def _register_device(self, strict: bool = False) -> bool:
        """
        Register the device with HRTi (RegisterDevice, HSAPI endpoint).

        strict=False (login flow, step 5 of _perform_authentication): best
        effort -- every failure is logged and swallowed, a missing token is
        a warning; registration must never abort the login. Returns
        True/False (the login flow ignores it).

        strict=True (ErrorCode-4 recovery, called via register_device()):
        failures RAISE typed errors -- AuthError when there is no token to
        register with, ServerError for transport/HTTP/body-ErrorCode
        failures, ConfigurationError when the endpoint is not configured.
        The recovery ladder in api.api_post must be able to tell a FAILED
        re-registration from a successful one; swallowing here would make
        it retry the original request, get ErrorCode 4 again and raise a
        misleading AuthError while the real cause is only a warning in
        the log.
        """
        url: Optional[str] = None
        try:
            bearer_token = self._current_token.access_token if self._current_token else ""
            if not bearer_token:
                if strict:
                    raise AuthError("HRTi: no token available for device registration")
                logger.warning("No bearer token available for device registration")
                return False

            # ConfigurationError when missing (endpoint() raises, never returns
            # a falsy URL -- the old `if not register_endpoint` check was dead)
            url = self.config.endpoint("register_device")

            # Use API headers with proper authorization and referer
            headers = self._get_api_headers(bearer_token)

            # Update the referer to root path for device registration
            headers["referer"] = f"{self.config.base_website}/"

            # Add cache-control and pragma headers to match working example
            headers["cache-control"] = "no-cache"
            headers["pragma"] = "no-cache"

            payload = {
                "DeviceSerial": self._device_id,
                "DeviceReferenceId": self.config.device_reference_id,
                "IpAddress": self._ip_address,
                "ConnectionType": self.config.connection_type,
                "ApplicationVersion": self.config.application_version,
                "DrmId": self._device_id,
                "OsVersion": self.config.os_version,
                "ClientType": self.config.client_type,
            }

            logger.debug(f"HRTi Device Registration Payload: {payload}")

            response = self.http_manager.post(
                url,
                operation="api",
                headers=headers,
                data=json.dumps(payload),
            )

            logger.debug(f"Device registration response status: {response.status_code}")
            response.raise_for_status()

            result = response.json()
            error_code = result.get("ErrorCode") if isinstance(result, dict) else None
            if error_code not in (0, None):
                if strict:
                    raise ServerError(
                        f"HRTi device registration failed: [{error_code}] "
                        f"{result.get('ErrorDescription')}",
                        url=url,
                        code=str(error_code),
                    )
                logger.warning(
                    f"HRTi device registration error: [{error_code}] "
                    f"{result.get('ErrorDescription')}"
                )
                return False
            logger.debug(f"HRTi device registration successful: {result}")
            return True

        except ProviderError as e:
            # Typed error (incl. ConfigurationError from endpoint() and the
            # ServerError/AuthError raised above): fatal in the recovery
            # path, logged and swallowed in the login flow (v1 behaviour).
            if strict:
                raise
            logger.warning(f"HRTi device registration failed: {e}")
            return False
        except Exception as e:
            if strict:
                raise typed_error_for(e, url) from e
            logger.warning(f"HRTi device registration failed: {e}")
            return False

    def _get_initial_data(self):
        """Get initial content rating and profiles using API headers with proper authorization"""
        try:
            bearer_token = self._current_token.access_token if self._current_token else ""
            headers = self._get_api_headers(bearer_token)

            # Update the referer to root path for these API calls
            headers["referer"] = f"{self.config.base_website}/"

            # Get content ratings
            content_endpoint = self.config.endpoint("content_ratings")
            if content_endpoint:
                content_response = self.http_manager.post(
                    content_endpoint,
                    operation="api",
                    headers=headers,
                    data=json.dumps({}),
                )
                content_response.raise_for_status()

            # Get profiles
            profiles_endpoint = self.config.endpoint("profiles")
            if profiles_endpoint:
                profiles_response = self.http_manager.post(
                    profiles_endpoint,
                    operation="api",
                    headers=headers,
                    data=json.dumps({}),
                )
                profiles_response.raise_for_status()

            logger.debug("HRTi initial data loaded")

        except Exception as e:
            logger.debug(f"Error loading HRTi initial data: {e}")

    def _initialize_device(self):
        """Initialize or load device ID - ensure it's a proper UUID"""
        try:
            self._device_id = self.settings_manager.get_device_id(self.provider_name, self.country)
            if not self._device_id:
                self._device_id = str(uuid.uuid4())
                # A freshly generated id MUST survive the restart, otherwise
                # the device identity churns on every start and the server
                # sees a brand-new device each time. No-op + warning when the
                # settings manager has no setter (see _persist_device_id).
                self._persist_device_id()
                logger.debug(f"Generated new device ID: {self._device_id}")

            # Ensure it's a valid UUID format
            if not self._validate_uuid(self._device_id):
                logger.warning(f"Invalid device ID format, generating new one: {self._device_id}")
                self._device_id = str(uuid.uuid4())
                self._persist_device_id()

        except Exception as e:
            logger.error(f"Error initializing device ID: {e}")
            self._device_id = str(uuid.uuid4())
            self._persist_device_id()

    @staticmethod
    def _validate_uuid(uuid_string):
        """Validate UUID format"""
        try:
            uuid.UUID(uuid_string)
            return True
        except ValueError:
            return False

    def get_device_id(self) -> str:
        """Get device ID"""
        return self._device_id

    def get_ip_address(self) -> str:
        """Get IP address (cached; "0.0.0.0" fallback is not cached)."""
        return self._get_ip_address()

    def _load_session(self) -> None:
        """
        Restore the persisted token. The stored dict is FLAT (``to_dict``), so
        it is rebuilt with HRTiAuthToken.from_dict. It must NOT go through
        _create_token_from_response (the base default), which expects a
        GrantAccess response and used to produce a token with an EMPTY
        access_token and a fresh issued_at -- "valid" for 24 h and never
        refreshed.
        """
        self._current_token = None
        try:
            token_data = self.settings_manager.load_token_data(self.provider_name, self.country)
            if token_data and token_data.get("access_token"):
                token = HRTiAuthToken.from_dict(token_data)
                token.auth_level = self._classify_token(token)
                self._current_token = token
                self._user_id = token.user_id or self._user_id or ""
                logger.info("Restored persisted HRTi session")
            else:
                logger.info("No existing HRTi session found")
        except Exception as e:
            logger.error(f"Error loading HRTi session: {e}")
            self._current_token = None
            self._user_id = self._user_id or ""

    # ------------------------------------------------------------------
    # State read by HRTiSession
    # ------------------------------------------------------------------
    def get_current_token(self) -> Optional[BaseAuthToken]:
        return self._current_token

    def get_user_id(self) -> str:
        return self._user_id or ""

    def has_user_credentials(self) -> bool:
        """True when real (non-anonymous) user credentials are stored or set."""
        from ...base.auth.credentials import UserPasswordCredentials

        try:
            stored = self.settings_manager.get_provider_credentials(
                self.provider_name, self.country
            )
        except TypeError:
            stored = self.settings_manager.get_provider_credentials(self.provider_name)
        for creds in (stored, self.credentials):
            if (
                isinstance(creds, UserPasswordCredentials)
                and creds.validate()
                and creds.username != HRTiDefaults.ANONYMOUS_USERNAME
            ):
                return True
        return False

    def authorize_session(
            self,
            content_type: str,
            content_ref_id: str,
            content_drm_id: str = None,
            video_store_ids: list = None,
            channel_id: str = None,
            start_time: str = None,
            end_time: str = None,
    ) -> Dict[str, Any]:
        """Authorize a playback session. Raises typed errors (AuthError on 401,
        ServerError otherwise); returns the raw ``Result`` dict -- the caller
        checks ``Authorized``."""
        bearer_token = self._current_token.access_token if self._current_token else ""
        headers = self._get_api_headers(bearer_token)

        # Set referer based on content type
        if channel_id is None:
            headers["referer"] = f"{self.config.base_website}/videostore"
        elif content_type == "tlive":
            headers["referer"] = f"{self.config.base_website}/live/tv?channel={channel_id}"
        elif content_type == "rlive":
            headers["referer"] = f"{self.config.base_website}/live/radio"
        else:
            headers["referer"] = f"{self.config.base_website}/live/"

        payload = {
            "ContentType": content_type,
            "ContentReferenceId": content_ref_id,
            "ContentDrmId": content_drm_id or f"{content_ref_id}_drm",
            "VideostoreReferenceIds": video_store_ids,
            "ChannelReferenceId": channel_id,
            "StartTime": start_time,
            "EndTime": end_time,
        }
        logger.debug(
            f"Authorizing session - type: {content_type}, ref: {content_ref_id}, drm: {content_drm_id}"
        )

        auth_endpoint = self.config.endpoint("authorize_session")
        try:
            response = self.http_manager.post(
                auth_endpoint, operation="api", headers=headers, data=json.dumps(payload)
            )
            response.raise_for_status()
            result = response.json()
        except ProviderError:
            raise
        except Exception as exc:
            raise typed_error_for(exc, auth_endpoint) from exc

        session_result = result.get("Result")
        if not session_result:
            error_code = result.get("ErrorCode")
            if error_code == DEVICE_SESSION_INVALID_CODE:
                # Stale device session: AuthError (NOT ServerError) so that
                # HRTiSession.authorize_session's existing recovery ladder
                # (refresh = invalidate + forced login, which re-registers the
                # device inside _perform_authentication) heals it with
                # exactly one retry. Assumption to verify on device:
                # ErrorCode 4 means the same here as on the data endpoints.
                raise AuthError(
                    "HRTi: AuthorizeSession rejected the device session "
                    f"(ErrorCode {error_code}: {result.get('ErrorDescription')})"
                )
            raise ServerError(
                "HRTi: no result in AuthorizeSession response "
                f"(ErrorCode={error_code}: {result.get('ErrorDescription')})",
                url=auth_endpoint,
                code=str(error_code),
            )
        logger.debug(
            f"Session authorization result - authorized: {session_result.get('Authorized', False)}, "
            f"session_id: {session_result.get('SessionId') or session_result.get('DrmId')}"
        )
        return session_result

    def report_session_event(self, session_id: str, channel_id: str = None) -> bool:
        """Report session event (like play start)"""
        try:
            bearer_token = self._current_token.access_token if self._current_token else ""
            headers = self._get_api_headers(bearer_token)

            # Set referer based on channel
            if channel_id is None:
                headers["referer"] = f"{self.config.base_website}/videostore"
            else:
                headers["referer"] = f"{self.config.base_website}/live/tv?channel={channel_id}"

            payload = {"SessionEventId": 1, "SessionId": session_id}  # 1 = play start

            report_endpoint = self.config.endpoint("report_session")
            if not report_endpoint:
                logger.warning("No report_session endpoint configured")
                return False

            response = self.http_manager.post(
                report_endpoint,
                operation="api",
                headers=headers,
                data=json.dumps(payload),
            )
            response.raise_for_status()

            logger.debug(f"Session event reported for session {session_id}")
            return True

        except Exception as e:
            logger.warning(f"Session event reporting failed: {e}")
            return False

    @staticmethod
    def get_time_offset(hours_offset: int) -> int:
        """Get timestamp with offset in milliseconds"""
        target_time = datetime.now() + timedelta(hours=hours_offset)
        return int(target_time.timestamp() * 1000)

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        """Classify HRTi token authentication level"""
        if not token or not token.access_token:
            return TokenAuthLevel.ANONYMOUS

        # Check if it's an HRTiAuthToken and has user_id attribute
        if isinstance(token, HRTiAuthToken):
            # Check if it's an anonymous token by user_id
            if token.user_id == HRTiDefaults.ANONYMOUS_USERNAME:
                return TokenAuthLevel.ANONYMOUS

            # Check if we have user credentials available
            from ...base.auth.credentials import UserPasswordCredentials

            # Check stored credentials first
            try:
                stored_creds = self.settings_manager.get_provider_credentials(
                    self.provider_name, self.country
                )
            except TypeError:
                stored_creds = self.settings_manager.get_provider_credentials(self.provider_name)

            has_user_creds = (
                    isinstance(stored_creds, UserPasswordCredentials) and stored_creds.validate()
            )

            # Check current credentials
            if not has_user_creds:
                has_user_creds = (
                        isinstance(self.credentials, UserPasswordCredentials)
                        and self.credentials.validate()
                )

            # If we have user credentials and token has a real user_id, it's user authenticated
            if has_user_creds and token.user_id and token.user_id != HRTiDefaults.ANONYMOUS_USERNAME:
                return TokenAuthLevel.USER_AUTHENTICATED

        # Check if using anonymous credentials
        if hasattr(self.credentials, "username") and self.credentials.username == HRTiDefaults.ANONYMOUS_USERNAME:
            return TokenAuthLevel.ANONYMOUS

        # If we have user credentials, consider it user authenticated
        if (
                hasattr(self.credentials, "username")
                and self.credentials.username
                and self.credentials.username != HRTiDefaults.ANONYMOUS_USERNAME
        ):
            return TokenAuthLevel.USER_AUTHENTICATED

        return TokenAuthLevel.CLIENT_CREDENTIALS

    def should_upgrade_token(self, token: BaseAuthToken) -> bool:
        """
        Determine if token should be upgraded from anonymous to user credentials
        """
        if not token:
            return False

        # Classify token if not already classified
        if token.auth_level == TokenAuthLevel.UNKNOWN:
            token.auth_level = self._classify_token(token)

        # Check if token is anonymous and we have user credentials
        if token.auth_level == TokenAuthLevel.ANONYMOUS:
            from ...base.auth.credentials import UserPasswordCredentials

            # Check if we have stored user credentials
            try:
                stored_creds = self.settings_manager.get_provider_credentials(
                    self.provider_name, self.country
                )
            except TypeError:
                stored_creds = self.settings_manager.get_provider_credentials(self.provider_name)

            has_stored_user_creds = (
                    isinstance(stored_creds, UserPasswordCredentials) and stored_creds.validate()
            )

            # Check current credentials
            has_current_user_creds = (
                    isinstance(self.credentials, UserPasswordCredentials)
                    and self.credentials.validate()
            )

            # Upgrade if we have any user credentials
            return has_stored_user_creds or has_current_user_creds

        return False

    def get_bearer_token(self, force_refresh: bool = False, force_upgrade: bool = False) -> str:
        """
        Get bearer token with automatic upgrade from anonymous to user credentials
        """
        logger.debug(
            f"HRTi get_bearer_token: force_refresh={force_refresh}, force_upgrade={force_upgrade}"
        )

        # Get current token (authenticate if needed)
        current_token = self.authenticate(force_refresh=force_refresh)

        # Check if upgrade is needed/requested
        should_upgrade = force_upgrade or self.should_upgrade_token(current_token)

        if should_upgrade:
            logger.info(
                f"HRTi token upgrade triggered (force={force_upgrade}, should_upgrade={self.should_upgrade_token(current_token)})"
            )

            # Store original credentials at the beginning
            original_credentials = self.credentials

            try:
                # Get user credentials from settings manager
                try:
                    user_creds = self.settings_manager.get_provider_credentials(
                        self.provider_name, self.country
                    )
                except TypeError:
                    user_creds = self.settings_manager.get_provider_credentials(self.provider_name)

                if not user_creds or not user_creds.validate():
                    logger.debug("No valid user credentials available for upgrade")
                    return current_token.bearer_token

                # Switch to user credentials
                self.credentials = user_creds

                # Perform authentication with user credentials
                logger.info("Performing authentication with user credentials for upgrade")
                user_token = self._perform_authentication()

                if user_token and not user_token.is_expired:
                    # Verify it's actually a user token (not anonymous)
                    user_token.auth_level = self._classify_token(user_token)

                    if user_token.auth_level == TokenAuthLevel.USER_AUTHENTICATED:
                        logger.info("Successfully upgraded to user token")
                        self._current_token = user_token
                        self._save_session()
                        return user_token.bearer_token
                    else:
                        logger.warning(
                            "Authentication succeeded but token is still anonymous level"
                        )
                        self.credentials = original_credentials
                        return current_token.bearer_token
                else:
                    logger.warning("User authentication failed during upgrade")
                    self.credentials = original_credentials
                    return current_token.bearer_token

            except Exception as e:
                logger.error(f"Token upgrade failed: {e}")
                # Restore original credentials on failure
                self.credentials = original_credentials
                return current_token.bearer_token

        return current_token.bearer_token if current_token else ""

    def _refresh_token(self) -> Optional[BaseAuthToken]:
        """Refresh HRTi token - reauthenticate since it's custom auth"""
        logger.info("Refreshing HRTi token via reauthentication")
        try:
            return self._perform_authentication()
        except Exception as e:
            logger.error(f"HRTi token refresh failed: {e}")
            return None

    # ------------------------------------------------------------------
    # ErrorCode-4 recovery (called through HRTiSession.reregister_device)
    # ------------------------------------------------------------------
    def register_device(self, force: bool = False) -> None:
        """
        Public, targeted device re-registration -- the ErrorCode-4 recovery
        path. Called ONLY through HRTiSession.reregister_device (which locks
        and dedupes concurrent callers); managers and api.py never call this
        directly.

        Unlike the best-effort registration inside the login flow
        (_register_device(strict=False) swallows every failure), this RAISES
        typed errors (AuthError / ServerError / ConfigurationError) -- see
        _register_device(strict=True).

        The device id is NOT rotated: RegisterDevice (re-)creates the
        server-side record for the DeviceSerial supplied, so the SAME id is
        sent; generating a fresh one would churn the device identity and any
        server-side per-device state. ``force`` is therefore accepted for the
        session contract but has no shortcut to skip today -- registration
        in the login flow is unconditional anyway (the web client
        re-registers on every login too).

        Persists the device id after success (write-through, see
        _persist_device_id): the original bug was a stored id whose
        server-side registration had expired; the reactive recovery fixes
        the session, the write-through keeps memory and storage consistent.
        """
        logger.debug(f"HRTi: targeted device re-registration (force={force})")
        if self._register_device(strict=True):
            self._persist_device_id()

    def _persist_device_id(self) -> None:
        """
        Write the CURRENT device id back to the storage it is loaded from on
        startup (settings_manager.get_device_id(provider_name, country)).

        Defensive about the save API (its name is not pinned anywhere in
        this file): tries the natural setter names, each with the signature
        MIRRORING the getter -- (provider_name, country, device_id), country
        being None for the flat HRTi keys. No other signature is guessed: a
        2-arg call against a setter with an optional country parameter would
        silently bind the device id to the country slot.

        Never raises. If no setter exists, logs ONE warning naming the
        expected API -- then the id lives only in memory for this process
        and the reactive ErrorCode-4 recovery in api.api_post self-heals
        after every restart instead of never. If get_device_id turns out to
        be get-or-create, this whole method is a harmless no-op except in
        the freshly-generated branches of _initialize_device.
        """
        device_id = self._device_id
        if not device_id:
            return
        settings_manager = getattr(self, "settings_manager", None)
        if settings_manager is None:
            return
        for name in ("set_device_id", "save_device_id", "store_device_id"):
            setter = getattr(settings_manager, name, None)
            if not callable(setter):
                continue
            try:
                setter(self.provider_name, self.country, device_id)
                logger.debug(f"HRTi: device id persisted via {name}")
                return
            except TypeError:
                continue  # wrong name/signature -- try the next candidate
            except Exception as exc:
                logger.warning(f"HRTi: persisting the device id failed ({name}): {exc!r}")
                return
        logger.warning(
            "HRTi: settings manager exposes no device-id setter "
            "(tried set_device_id/save_device_id/store_device_id with the "
            "get_device_id-mirroring signature (provider, country, device_id)) "
            "-- the current device id is not persisted; ErrorCode-4 recovery "
            "stays reactive. Add the setter to make it stick across restarts."
        )