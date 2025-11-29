# [file name]: auth.py
# [file content begin]
# streaming_providers/providers/hrti/auth.py
import json
import base64
import time
import uuid
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

from ...base.auth.base_auth import BaseAuthenticator, BaseAuthToken, TokenAuthLevel
from ...base.utils.logger import logger
from .models import HRTiCredentials, HRTiAuthToken
from .constants import HRTiConfig
from ...base.models.proxy_models import ProxyConfig


class HRTiAuthenticator(BaseAuthenticator):
    def __init__(self, credentials=None, config_dir=None,
                 proxy_config: Optional[ProxyConfig] = None, http_manager=None):

        # Initialize configuration FIRST
        self._config = HRTiConfig()

        # Get proxy_config if not provided
        if proxy_config is None:
            from ...base.network import ProxyConfigManager
            proxy_mgr = ProxyConfigManager(config_dir)
            proxy_config = proxy_mgr.get_proxy_config('hrti')

        # Store HTTP manager and proxy config locally (like MagentaEU)
        self._http_manager = http_manager
        self._proxy_config = proxy_config

        # Require http_manager like MagentaEU does
        if http_manager is None:
            raise ValueError("http_manager is required for HRTiAuthenticator")

        # Initialize HRTi-specific properties BEFORE calling parent init
        self._ip_address = None
        self._device_id = None
        self._user_id = None  # Initialize _user_id here

        # Call parent init WITHOUT proxy_config and http_manager (like MagentaEU)
        super().__init__(
            provider_name='hrti',
            credentials=credentials,
            country=None,  # Changed from 'HR' to None for flat credential structure
            config_dir=config_dir
            # NO proxy_config or http_manager passed to parent
        )

        # Load or initialize device ID
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
            raise ValueError("HTTP manager not available - this should have been set during initialization")
        return self._http_manager

    @http_manager.setter
    def http_manager(self, value):
        """Allow setting http_manager"""
        self._http_manager = value

    @property
    def auth_endpoint(self) -> str:
        """HRTi authentication endpoint"""
        return self.config.api_endpoints['grant_access']

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers specifically for authentication endpoint"""
        # Get IP address and device ID first
        if not self._ip_address:
            self._get_ip_address()

        device_id = self.get_device_id()

        # Special headers for authentication endpoint with /signin referer
        headers = {
            'User-Agent': self.config.user_agent,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'deviceid': device_id,
            'devicetypeid': self.config.device_reference_id,
            'host': 'hrti.hrt.hr',
            'ipaddress': self._ip_address,
            'operatorreferenceid': self.config.operator_reference_id,
            'origin': self.config.base_website,
            'referer': f'{self.config.base_website}/signin'  # Critical: Use /signin for auth
        }

        return headers

    def _get_api_headers(self, bearer_token: str = None) -> Dict[str, str]:
        """Get headers for regular API endpoints"""
        if not self._ip_address:
            self._get_ip_address()

        device_id = self.get_device_id()

        headers = {
            'User-Agent': self.config.user_agent,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'deviceid': device_id,
            'devicetypeid': self.config.device_reference_id,
            'host': 'hrti.hrt.hr',
            'ipaddress': self._ip_address,
            'operatorreferenceid': self.config.operator_reference_id,
            'origin': self.config.base_website,
            'referer': f'{self.config.base_website}/login'  # Use /login for API calls
        }

        # CRITICAL: Add authorization header if token is provided
        if bearer_token:
            headers['authorization'] = f'Client {bearer_token}'
            logger.debug(f"Added authorization header with token: {bearer_token[:20]}...")

        return headers

    def _build_auth_payload(self) -> Dict[str, Any]:
        """Build HRTi-specific authentication payload"""
        # HRTi uses specific format: {"Username":"...","Password":"...","OperatorReferenceId":"hrt"}
        if hasattr(self.credentials, 'username') and hasattr(self.credentials, 'password'):
            return {
                "Username": self.credentials.username,
                "Password": self.credentials.password,
                "OperatorReferenceId": self.config.operator_reference_id
            }
        else:
            # Fallback for any other credential type
            return {
                "Username": getattr(self.credentials, 'username', ''),
                "Password": getattr(self.credentials, 'password', ''),
                "OperatorReferenceId": self.config.operator_reference_id
            }

    def _create_token_from_response(self, response_data: Dict[str, Any]) -> HRTiAuthToken:
        """Create HRTi-specific token from API response"""
        result = response_data.get('Result', {})

        # Debug the response structure
        logger.debug(f"GrantAccess response Result keys: {list(result.keys())}")

        # Extract token
        access_token = result.get('Token', '')
        logger.debug(f"Extracted access_token: {'present' if access_token else 'MISSING'}")
        if access_token:
            logger.debug(f"Token length: {len(access_token)}, starts with: {access_token[:20]}...")

        # Store user ID if available
        if 'Customer' in result:
            self._user_id = result['Customer'].get('CustomerId', '')
            logger.debug(f"Extracted user_id: {self._user_id}")
        else:
            logger.warning("No Customer data in response")

        token = HRTiAuthToken(
            access_token=access_token,
            token_type='Client',
            expires_in=86400,  # 24 hours default
            issued_at=time.time(),
            user_id=self._user_id or '',  # Ensure user_id is never None
            valid_from=result.get('ValidFrom', ''),
            valid_to=result.get('ValidTo', '')
        )

        # Classify the token immediately after creation
        token.auth_level = self._classify_token(token)

        logger.debug(f"Created HRTiAuthToken - access_token: {bool(token.access_token)}, user_id: {token.user_id}")

        return token

    def get_fallback_credentials(self):
        """Get fallback credentials (anonymous access)"""
        return HRTiCredentials(
            username='anonymoushrt',
            password='an0nPasshrt'
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
        if token.access_token:
            logger.debug(f"Token value: {token.access_token[:20]}...")
        else:
            logger.warning("Token created but access_token is empty!")

        # Step 5: Register device (now with token available in self._current_token)
        self._register_device()

        # Step 6: Get content rating and profiles
        self._get_initial_data()

        logger.info(f"HRTi authentication successful - user_id: {token.user_id}, auth_level: {token.auth_level.value}")

        # Save the session after successful authentication
        self._save_session()

        return token

    def _get_ip_address(self) -> str:
        """Get public IP address"""
        if self._ip_address:
            return self._ip_address

        try:
            # Use the http_manager that's guaranteed to be available
            response = self.http_manager.get(
                self.config.api_endpoints['get_ip'],
                operation='api'
            )
            response.raise_for_status()
            self._ip_address = response.text.strip().strip('"')  # Remove quotes if present
            logger.debug(f"Retrieved IP address: {self._ip_address}")
            return self._ip_address
        except Exception as e:
            logger.error(f"Error getting IP address: {e}")
            self._ip_address = "0.0.0.0"  # Fallback
            return self._ip_address

    def _get_environment_config(self):
        """Get HRTi environment configuration"""
        try:
            # Get env config
            env_response = self.http_manager.get(
                self.config.env_endpoint,
                operation='api'
            )
            env_response.raise_for_status()
            env_data = env_response.json()

            # Get main config
            config_response = self.http_manager.get(
                self.config.config_endpoint,
                operation='api'
            )
            config_response.raise_for_status()
            config_data = config_response.json()

            # Update config with retrieved values
            self.config.update_from_api(env_data, config_data)
            logger.debug("HRTi environment configuration loaded")

        except Exception as e:
            logger.warning(f"Error loading HRTi environment config: {e}")

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
            if 'deviceid' in safe_headers:
                safe_headers['deviceid'] = f"{safe_headers['deviceid'][:8]}..."
            logger.debug(f"HRTi Auth Headers: {safe_headers}")

            safe_payload = payload.copy()
            if 'Password' in safe_payload:
                safe_payload['Password'] = '***' if safe_payload['Password'] else '<empty>'
            logger.debug(f"HRTi Auth Payload: {safe_payload}")

            response = self.http_manager.post(
                self.auth_endpoint,
                operation='auth',
                headers=headers,
                data=json.dumps(payload)
            )

            logger.debug(f"HRTi Auth Response - Status: {response.status_code}")
            response.raise_for_status()

            result = response.json()
            if 'Result' not in result:
                raise Exception("No result in grant access response")

            customer_id = result.get('Result', {}).get('Customer', {}).get('CustomerId', 'unknown')
            logger.debug(f"Grant access successful - user: {customer_id}")
            return result

        except Exception as e:
            logger.error(f"HRTi grant access failed: {e}")
            # Only fallback to anonymous if we're not already using it
            if not isinstance(self.credentials, HRTiCredentials) or self.credentials.username != 'anonymoushrt':
                logger.info("Falling back to anonymous credentials")
                self.credentials = self.get_fallback_credentials()
                return self._perform_grant_access()
            else:
                raise e

    def _register_device(self):
        """Register device with HRTi using API headers with proper authorization"""
        try:
            # Get the bearer token from current token - THIS IS CRITICAL
            bearer_token = self._current_token.access_token if self._current_token else ''
            if not bearer_token:
                logger.warning("No bearer token available for device registration")
                return

            # Use API headers with proper authorization and referer
            headers = self._get_api_headers(bearer_token)  # This should include authorization

            # Update the referer to root path for device registration
            headers['referer'] = f'{self.config.base_website}/'

            payload = {
                "DeviceSerial": self._device_id,
                "DeviceReferenceId": self.config.device_reference_id,
                "IpAddress": self._ip_address,
                "ConnectionType": self.config.connection_type,
                "ApplicationVersion": self.config.application_version,
                "DrmId": self._device_id,
                "OsVersion": self.config.os_version,
                "ClientType": self.config.client_type
            }

            # Log the request for debugging - include authorization this time
            safe_headers = headers.copy()
            if 'authorization' in safe_headers:
                auth_value = safe_headers['authorization']
                safe_headers['authorization'] = f"{auth_value[:20]}..." if auth_value else "MISSING"
            else:
                safe_headers['authorization'] = "MISSING"  # This will show if it's missing

            logger.debug(f"HRTi Device Registration Headers: {safe_headers}")
            logger.debug(f"HRTi Device Registration Payload: {payload}")

            response = self.http_manager.post(
                self.config.api_endpoints['register_device'],
                operation='api',
                headers=headers,
                data=json.dumps(payload)
            )

            logger.debug(f"Device registration response status: {response.status_code}")
            logger.debug(f"Device registration response headers: {dict(response.headers)}")
            logger.debug(f"Device registration response content: {response.text}")

            response.raise_for_status()

            # Log successful response
            result = response.json()
            logger.debug(f"HRTi device registration successful: {result}")

        except Exception as e:
            logger.warning(f"HRTi device registration failed: {e}")

    def _get_initial_data(self):
        """Get initial content rating and profiles using API headers with proper authorization"""
        try:
            bearer_token = self._current_token.access_token if self._current_token else ''
            headers = self._get_api_headers(bearer_token)

            # Update the referer to root path for these API calls
            headers['referer'] = f'{self.config.base_website}/'

            # Get content ratings
            content_response = self.http_manager.post(
                self.config.api_endpoints['content_ratings'],
                operation='api',
                headers=headers,
                data=json.dumps({})
            )
            content_response.raise_for_status()

            # Get profiles
            profiles_response = self.http_manager.post(
                self.config.api_endpoints['profiles'],
                operation='api',
                headers=headers,
                data=json.dumps({})
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
                logger.debug(f"Generated new device ID: {self._device_id}")

            # Ensure it's a valid UUID format
            if not self._validate_uuid(self._device_id):
                logger.warning(f"Invalid device ID format, generating new one: {self._device_id}")
                self._device_id = str(uuid.uuid4())

        except Exception as e:
            logger.error(f"Error initializing device ID: {e}")
            self._device_id = str(uuid.uuid4())

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
        """Get IP address"""
        if not self._ip_address:
            self._get_ip_address()
        return self._ip_address

    def _load_session(self) -> None:
        """Override to ensure _user_id is set when loading session"""
        try:
            # Call parent method first
            super()._load_session()

            # If we have a current token and it's an HRTiAuthToken, set _user_id
            if self._current_token and isinstance(self._current_token, HRTiAuthToken):
                self._user_id = self._current_token.user_id
                logger.debug(f"Set _user_id from loaded session: {self._user_id}")

        except Exception as e:
            logger.error(f"Error in HRTi session loading: {e}")
            # Ensure _user_id is at least an empty string
            self._user_id = self._user_id or ''

    def authorize_session(self, content_type: str, content_ref_id: str,
                          channel_id: str = None, **kwargs) -> Optional[Dict[str, Any]]:
        """Authorize a playback session"""
        try:
            bearer_token = self._current_token.access_token if self._current_token else ''
            headers = self._get_api_headers(bearer_token)

            payload = {
                "ContentType": content_type,
                "ContentReferenceId": content_ref_id,
                "ContentDrmId": f"{content_ref_id}_drm",
                "VideostoreReferenceIds": kwargs.get('video_store_ids', []),
                "ChannelReferenceId": channel_id,
                "StartTime": kwargs.get('start_time'),
                "EndTime": kwargs.get('end_time')
            }

            response = self.http_manager.post(
                self.config.api_endpoints['authorize_session'],
                operation='api',
                headers=headers,
                data=json.dumps(payload)
            )
            response.raise_for_status()

            result = response.json()
            if 'Result' in result:
                logger.debug("HRTi session authorization successful")
                return result['Result']
            else:
                logger.warning("No result in session authorization response")
                return None

        except Exception as e:
            logger.error(f"HRTi session authorization failed: {e}")
            return None

    def get_license_data(self, session_id: str) -> str:
        """Generate license data for DRM"""
        try:
            drm_license = {
                'userId': self._user_id or '',
                'sessionId': session_id,
                'merchant': self.config.merchant
            }

            license_bytes = json.dumps(drm_license).encode('utf-8')
            license_b64 = base64.b64encode(license_bytes).decode('utf-8')
            return license_b64

        except Exception as e:
            logger.error(f"Error generating license data: {e}")
            return ""

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
            if token.user_id == 'anonymoushrt':
                return TokenAuthLevel.ANONYMOUS

            # Check if we have user credentials available
            from ...base.auth.credentials import UserPasswordCredentials

            # Check stored credentials first
            try:
                stored_creds = self.settings_manager.get_provider_credentials(self.provider_name, self.country)
            except TypeError:
                stored_creds = self.settings_manager.get_provider_credentials(self.provider_name)

            has_user_creds = isinstance(stored_creds, UserPasswordCredentials) and stored_creds.validate()

            # Check current credentials
            if not has_user_creds:
                has_user_creds = isinstance(self.credentials, UserPasswordCredentials) and self.credentials.validate()

            # If we have user credentials and token has a real user_id, it's user authenticated
            if has_user_creds and token.user_id and token.user_id != 'anonymoushrt':
                return TokenAuthLevel.USER_AUTHENTICATED

        # Check if using anonymous credentials
        if (hasattr(self.credentials, 'username') and
                self.credentials.username == 'anonymoushrt'):
            return TokenAuthLevel.ANONYMOUS

        # If we have user credentials, consider it user authenticated
        if (hasattr(self.credentials, 'username') and
                self.credentials.username and
                self.credentials.username != 'anonymoushrt'):
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
                stored_creds = self.settings_manager.get_provider_credentials(self.provider_name, self.country)
            except TypeError:
                stored_creds = self.settings_manager.get_provider_credentials(self.provider_name)

            has_stored_user_creds = isinstance(stored_creds, UserPasswordCredentials) and stored_creds.validate()

            # Check current credentials
            has_current_user_creds = isinstance(self.credentials,
                                                UserPasswordCredentials) and self.credentials.validate()

            # Upgrade if we have any user credentials
            return has_stored_user_creds or has_current_user_creds

        return False

    def get_bearer_token(self, force_refresh: bool = False, force_upgrade: bool = False) -> str:
        """
        Get bearer token with automatic upgrade from anonymous to user credentials
        """
        logger.debug(f"HRTi get_bearer_token: force_refresh={force_refresh}, force_upgrade={force_upgrade}")

        # Get current token (authenticate if needed)
        current_token = self.authenticate(force_refresh=force_refresh)

        # Check if upgrade is needed/requested
        should_upgrade = force_upgrade or self.should_upgrade_token(current_token)

        if should_upgrade:
            logger.info(
                f"HRTi token upgrade triggered (force={force_upgrade}, should_upgrade={self.should_upgrade_token(current_token)})")

            # Store original credentials at the beginning
            original_credentials = self.credentials

            try:
                # Get user credentials from settings manager
                try:
                    user_creds = self.settings_manager.get_provider_credentials(self.provider_name, self.country)
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
                        logger.warning("Authentication succeeded but token is still anonymous level")
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
# [file content end]