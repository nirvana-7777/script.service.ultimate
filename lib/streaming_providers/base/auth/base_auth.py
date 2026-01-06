# streaming_providers/base/auth/base_auth.py (Country-Aware)
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

from ..utils.logger import logger


class TokenAuthLevel(Enum):
    """Classification of token authentication levels"""

    ANONYMOUS = "anonymous"  # No user authentication
    CLIENT_CREDENTIALS = "client_credentials"  # Client credentials flow
    USER_AUTHENTICATED = "user_authenticated"  # User login flow
    UNKNOWN = "unknown"  # Cannot determine


@dataclass
class BaseAuthToken(ABC):
    """Base class for authentication tokens with enhanced metadata"""

    access_token: str
    token_type: str
    expires_in: int
    issued_at: float
    refresh_token: Optional[str] = None
    refresh_expires_in: int = 0

    # Token metadata for upgrade logic
    auth_level: TokenAuthLevel = TokenAuthLevel.UNKNOWN
    credential_type: Optional[str] = None  # Type of credentials used

    @property
    def is_expired(self) -> bool:
        """Check if token is expired (with 5 minute buffer)"""
        return time.time() >= (self.issued_at + self.expires_in - 300)

    def needs_refresh(self) -> bool:
        """Check if token should be refreshed"""
        if not self.refresh_token:
            return False

        current_time = time.time()
        access_token_expiry = self.issued_at + self.expires_in
        needs_access_refresh = current_time > (access_token_expiry - 300)

        refresh_token_valid = True
        if self.refresh_expires_in > 0:
            refresh_token_expiry = self.issued_at + self.refresh_expires_in
            refresh_token_valid = current_time < (refresh_token_expiry - 300)

        return needs_access_refresh and refresh_token_valid

    def is_anonymous(self) -> bool:
        """Check if this is an anonymous token"""
        return self.auth_level == TokenAuthLevel.ANONYMOUS

    def is_client_credentials(self) -> bool:
        """Check if this is a client credentials token"""
        return self.auth_level == TokenAuthLevel.CLIENT_CREDENTIALS

    def is_user_authenticated(self) -> bool:
        """Check if this is a user-authenticated token"""
        return self.auth_level == TokenAuthLevel.USER_AUTHENTICATED

    def can_be_upgraded(self) -> bool:
        """Check if this token can be upgraded to a higher auth level"""
        return self.auth_level in [
            TokenAuthLevel.ANONYMOUS,
            TokenAuthLevel.CLIENT_CREDENTIALS,
            TokenAuthLevel.UNKNOWN,
        ]

    @property
    def bearer_token(self) -> str:
        """Get the bearer token string"""
        return self.access_token

    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary representation"""
        pass


class BaseAuthenticator(ABC):
    """
    Abstract base class for provider authenticators
    Now supports country-specific authentication
    """

    def __init__(
        self,
        provider_name: str,
        settings_manager=None,
        credentials=None,
        country: Optional[str] = None,
        config_dir: Optional[str] = None,
        enable_kodi_integration: bool = True,
    ):
        """
        Initialize authenticator

        Args:
            provider_name: Name of the streaming provider
            settings_manager: Injected settings manager (SettingsManager or compatible)
            credentials: Optional credentials to use (overrides all other sources)
            country: Optional country code (e.g., 'de', 'at', 'ch') for country-specific sessions
            config_dir: Optional config directory override (for backward compatibility)
            enable_kodi_integration: Whether to enable Kodi settings integration (for backward compatibility)
        """
        self.provider_name = provider_name
        self.country = country
        self._current_token: Optional[BaseAuthToken] = None

        # Log country configuration
        if self.country:
            logger.info(
                f"Initializing {provider_name} authenticator for country: {country}"
            )
        else:
            logger.info(
                f"Initializing {provider_name} authenticator (no country specified)"
            )

        # Use injected settings manager or create one for backward compatibility
        if settings_manager is not None:
            self.settings_manager = settings_manager
            logger.info(f"Using injected settings manager for {provider_name}")
        else:
            # Create settings manager for backward compatibility
            self.settings_manager = self._create_settings_manager(
                config_dir, enable_kodi_integration
            )
            logger.info(
                f"Created settings manager for backward compatibility for {provider_name}"
            )

        # Register provider with settings manager
        if hasattr(self.settings_manager, "register_provider"):
            self.settings_manager.register_provider(provider_name)

        # Load credentials with priority:
        # 1. Provided credentials (highest priority)
        # 2. Settings manager
        if credentials:
            self.credentials = credentials
            logger.info(f"Using provided credentials for {provider_name}")
        else:
            self.credentials = self._load_credentials_from_manager()

        # Load existing session/token
        self._load_session()

    def _create_settings_manager(
        self, config_dir: Optional[str] = None, enable_kodi_integration: bool = True
    ):
        """Create settings manager for backward compatibility"""
        try:
            # Try to use the new SettingsManager
            from ..settings.settings_manager import SettingsManager

            settings_manager = SettingsManager(
                config_dir=config_dir, enable_kodi_integration=enable_kodi_integration
            )
            logger.debug(f"Created SettingsManager for {self.provider_name}")
            return settings_manager

        except ImportError as e:
            logger.warning(f"Could not import SettingsManager: {e}")
            # Fall back to adapter approach
            return self._create_adapter_fallback(config_dir, enable_kodi_integration)

    def _create_adapter_fallback(
        self, config_dir: Optional[str] = None, enable_kodi_integration: bool = True
    ):
        """Create fallback using adapter pattern"""
        try:
            from ..settings.settings_manager_adapter import \
                SettingsManagerFactory

            adapter = SettingsManagerFactory.create_default_adapter(
                prefer_unified=True,
                config_dir=config_dir,
                enable_kodi_integration=enable_kodi_integration,
            )
            logger.debug(f"Created adapter fallback for {self.provider_name}")
            return adapter

        except ImportError as e:
            logger.warning(f"Could not create adapter fallback: {e}")
            # Create minimal fallback
            return self._create_minimal_fallback(config_dir)

    def _create_minimal_fallback(self, config_dir: Optional[str] = None):
        """Create minimal fallback manager"""
        try:
            # Try to create basic managers directly
            from .credential_manager import CredentialManager
            from .session_manager import SessionManager

            class MinimalSettingsManager:
                def __init__(self, config_dir):
                    self.session_manager = SessionManager(config_dir)
                    self.credential_manager = (
                        CredentialManager(config_dir)
                        if hasattr(self, "CredentialManager")
                        else None
                    )

                def get_provider_credentials(self, provider_name, country=None):
                    if self.credential_manager:
                        return self.credential_manager.load_credentials(
                            provider_name, country
                        )
                    return None

                def save_provider_credentials(
                    self, provider_name, credentials, country=None
                ):
                    if self.credential_manager:
                        return self.credential_manager.save_credentials(
                            provider_name, credentials, country
                        )
                    return False

                def load_token_data(self, provider_name, country=None):
                    return self.session_manager.load_token_data(provider_name, country)

                def save_token_data(self, provider_name, token_data, country=None):
                    return self.session_manager.save_session(
                        provider_name, token_data, country
                    )

                def get_device_id(self, provider_name, country=None):
                    return self.session_manager.get_device_id(provider_name, country)

                def clear_token(self, provider_name, country=None):
                    return self.session_manager.clear_token(provider_name, country)

                def get_credential_info(self, provider_name, country=None):
                    return {
                        "provider_name": provider_name,
                        "country": country,
                        "source": "minimal_fallback",
                        "config_dir": config_dir,
                    }

                def register_provider(self, provider_name):
                    # No-op for minimal fallback
                    return True

            return MinimalSettingsManager(config_dir)

        except ImportError:
            # Absolute minimal fallback
            return self._create_absolute_minimal_fallback()

    def _create_absolute_minimal_fallback(self):
        """Create absolute minimal fallback when nothing else works"""

        class AbsoluteMinimalManager:
            def get_provider_credentials(self, provider_name, country=None):
                return None

            def save_provider_credentials(
                self, provider_name, credentials, country=None
            ):
                return False

            def load_token_data(self, provider_name, country=None):
                return None

            def save_token_data(self, provider_name, token_data, country=None):
                return False

            def get_device_id(self, provider_name, country=None):
                import uuid

                return str(uuid.uuid4())

            def clear_token(self, provider_name, country=None):
                return False

            def get_credential_info(self, provider_name, country=None):
                return {
                    "provider_name": provider_name,
                    "country": country,
                    "source": "absolute_minimal",
                }

            def register_provider(self, provider_name):
                return True

        logger.warning(f"Using absolute minimal fallback for {self.provider_name}")
        return AbsoluteMinimalManager()

    def _load_credentials_from_manager(self):
        """Load credentials from the settings manager"""
        try:
            # Check if it's a SettingsManager instance (or compatible)
            if hasattr(self.settings_manager, "get_provider_credentials"):
                # Try country-aware call first
                try:
                    return self.settings_manager.get_provider_credentials(
                        self.provider_name, self.country
                    )
                except TypeError:
                    # Fallback for managers that don't support country parameter
                    logger.debug(
                        f"Settings manager doesn't support country parameter, using without"
                    )
                    return self.settings_manager.get_provider_credentials(
                        self.provider_name
                    )
            else:
                logger.warning(
                    f"Settings manager has no credential loading method for {self.provider_name}"
                )
                return None

        except Exception as e:
            logger.error(
                f"Error loading credentials from manager for {self.provider_name}: {e}"
            )
            return None

    # Abstract methods remain unchanged
    @property
    @abstractmethod
    def auth_endpoint(self) -> str:
        """Authentication endpoint URL"""
        pass

    @abstractmethod
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers for authentication request"""
        pass

    @abstractmethod
    def _build_auth_payload(self) -> Dict[str, Any]:
        """Build authentication payload"""
        pass

    @abstractmethod
    def _create_token_from_response(
        self, response_data: Dict[str, Any]
    ) -> BaseAuthToken:
        """Create token object from API response"""
        pass

    @abstractmethod
    def get_fallback_credentials(self):
        """Get fallback credentials when no user credentials are available"""
        pass

    @abstractmethod
    def _perform_authentication(self) -> BaseAuthToken:
        """Perform the actual authentication request"""
        pass

    # Session management methods
    def _load_session(self) -> None:
        """Load token from persistent storage"""
        try:
            country_str = f" (country: {self.country})" if self.country else ""
            logger.debug(f"Loading session for {self.provider_name}{country_str}")

            # Try country-aware call first
            try:
                token_data = self.settings_manager.load_token_data(
                    self.provider_name, self.country
                )
            except TypeError:
                # Fallback for managers that don't support country parameter
                logger.debug(
                    f"Settings manager doesn't support country parameter, using without"
                )
                token_data = self.settings_manager.load_token_data(self.provider_name)

            if token_data:
                self._current_token = self._create_token_from_response(token_data)
                logger.info(
                    f"Successfully loaded existing session for {self.provider_name}{country_str}"
                )
            else:
                logger.info(
                    f"No existing session found for {self.provider_name}{country_str}"
                )
                self._current_token = None

        except Exception as e:
            logger.error(f"Error loading session for {self.provider_name}: {e}")
            self._current_token = None

    def _save_session(self) -> None:
        """Save current token to persistent storage"""
        if self._current_token:
            try:
                country_str = f" (country: {self.country})" if self.country else ""

                # Try country-aware call first
                try:
                    success = self.settings_manager.save_token_data(
                        self.provider_name, self._current_token.to_dict(), self.country
                    )
                except TypeError:
                    # Fallback for managers that don't support country parameter
                    logger.debug(
                        f"Settings manager doesn't support country parameter, using without"
                    )
                    success = self.settings_manager.save_token_data(
                        self.provider_name, self._current_token.to_dict()
                    )

                if success:
                    logger.debug(f"Saved session for {self.provider_name}{country_str}")
                else:
                    logger.warning(
                        f"Failed to save session for {self.provider_name}{country_str}"
                    )
            except Exception as e:
                logger.error(f"Error saving session for {self.provider_name}: {e}")

    def _ensure_credentials(self) -> bool:
        """Ensure we have valid credentials"""
        # Try to refresh credentials from settings manager
        if not self.credentials or not self.credentials.validate():
            fresh_credentials = self._load_credentials_from_manager()
            if fresh_credentials and fresh_credentials.validate():
                self.credentials = fresh_credentials
                logger.debug(f"Refreshed credentials for {self.provider_name}")

        # If we still don't have valid credentials, try fallback
        if not self.credentials or not self.credentials.validate():
            logger.info(
                f"No valid user credentials found for {self.provider_name}, using fallback"
            )
            self.credentials = self.get_fallback_credentials()

        return self.credentials is not None and self.credentials.validate()

    def authenticate(self, force_refresh: bool = False) -> BaseAuthToken:
        """Authenticate and get access token with persistent storage"""
        country_str = f" (country: {self.country})" if self.country else ""
        logger.debug(
            f"[{self.provider_name}{country_str}] Starting authentication, force_refresh={force_refresh}"
        )

        # DEBUG: Log current token state
        if self._current_token:
            logger.debug(
                f"[{self.provider_name}{country_str}] Current token state - "
                f"is_expired: {self._current_token.is_expired}, "
                f"has_refresh: {bool(self._current_token.refresh_token)}, "
                f"needs_refresh: {self._current_token.needs_refresh()}"
            )
        else:
            logger.debug(f"[{self.provider_name}{country_str}] No current token")

        # 1. Return existing token if valid
        if (
            not force_refresh
            and self._current_token
            and not self._current_token.is_expired
        ):
            logger.info(
                f"[{self.provider_name}{country_str}] Using existing valid token"
            )
            return self._current_token

        # 2. ENHANCED REFRESH LOGIC: Attempt refresh if we have a token with refresh capability
        # This covers both: tokens that need refresh AND expired tokens that can be refreshed
        should_attempt_refresh = (
            not force_refresh
            and self._current_token
            and self._current_token.refresh_token
            and (self._current_token.needs_refresh() or self._current_token.is_expired)
        )

        logger.debug(
            f"[{self.provider_name}{country_str}] Refresh decision - "
            f"should_attempt_refresh: {should_attempt_refresh}, "
            f"force_refresh: {force_refresh}, "
            f"has_token: {bool(self._current_token)}, "
            f"has_refresh_token: {bool(self._current_token.refresh_token if self._current_token else False)}, "
            f"needs_refresh: {self._current_token.needs_refresh() if self._current_token else False}, "
            f"is_expired: {self._current_token.is_expired if self._current_token else False}"
        )

        if should_attempt_refresh:
            logger.info(f"[{self.provider_name}{country_str}] Attempting token refresh")
            try:
                refreshed_token = (
                    self._refresh_token()
                )  # Provider-specific implementation
                logger.debug(
                    f"[{self.provider_name}{country_str}] Refresh result: {refreshed_token is not None}"
                )

                if refreshed_token:
                    self._current_token = refreshed_token
                    self._save_session()
                    logger.info(
                        f"[{self.provider_name}{country_str}] Token refresh successful"
                    )
                    return self._current_token
                else:
                    logger.debug(
                        f"[{self.provider_name}{country_str}] Refresh failed, falling back to full auth"
                    )
            except Exception as e:
                logger.warning(
                    f"[{self.provider_name}{country_str}] Token refresh failed: {e}"
                )

        # 3. Ensure we have credentials before attempting full authentication
        if not self._ensure_credentials():
            raise Exception(f"No valid credentials available for {self.provider_name}")

        # 4. Perform full authentication
        logger.info(
            f"[{self.provider_name}{country_str}] Performing new authentication"
        )
        token = self._perform_authentication()
        self._current_token = token
        self._save_session()
        logger.info(f"[{self.provider_name}{country_str}] Authentication successful")
        return token

    # Credential management methods
    def save_credentials(self, credentials, sync_to_kodi: bool = False) -> bool:
        """Save credentials to persistent storage"""
        try:
            # Try country-aware call first
            try:
                success = self.settings_manager.save_provider_credentials(
                    self.provider_name, credentials, self.country
                )
            except TypeError:
                # Fallback for managers that don't support country parameter
                logger.debug(
                    f"Settings manager doesn't support country parameter, using without"
                )
                success = self.settings_manager.save_provider_credentials(
                    self.provider_name, credentials
                )

            if success:
                self.credentials = credentials
                country_str = f" (country: {self.country})" if self.country else ""
                logger.info(f"Saved credentials for {self.provider_name}{country_str}")
            return success
        except Exception as e:
            logger.error(f"Error saving credentials for {self.provider_name}: {e}")
            return False

    def sync_credentials_from_kodi(self) -> bool:
        """
        Manually sync credentials from Kodi settings (for backward compatibility)
        """
        try:
            if hasattr(self.settings_manager, "sync_all_from_kodi"):
                results = self.settings_manager.sync_all_from_kodi()
                success = results.get(self.provider_name, True)

                if success:
                    # Reload credentials after successful sync
                    self.credentials = self._load_credentials_from_manager()
                    logger.info(
                        f"Successfully synced and reloaded credentials from Kodi for {self.provider_name}"
                    )

                return success
            else:
                logger.debug(
                    f"No Kodi sync capability available for {self.provider_name}"
                )
                return True
        except Exception as e:
            logger.error(
                f"Error syncing credentials from Kodi for {self.provider_name}: {e}"
            )
            return False

    def get_credential_info(self) -> Dict[str, Any]:
        """Get information about credential sources"""
        base_info = {
            "provider": self.provider_name,
            "country": self.country,
            "has_current_credentials": self.credentials is not None,
            "current_credentials_valid": (
                self.credentials.validate() if self.credentials else False
            ),
            "current_credential_type": (
                self.credentials.credential_type if self.credentials else None
            ),
        }

        # Add settings manager info if available
        try:
            # Try country-aware call first
            try:
                manager_info = self.settings_manager.get_credential_info(
                    self.provider_name, self.country
                )
            except TypeError:
                manager_info = self.settings_manager.get_credential_info(
                    self.provider_name
                )
            base_info.update(manager_info)
        except Exception as e:
            logger.debug(
                f"Could not get extended credential info for {self.provider_name}: {e}"
            )

        return base_info

    # Backward compatibility aliases
    def get_credential_source_info(self) -> Dict[str, Any]:
        """Alias for get_credential_info for backward compatibility"""
        return self.get_credential_info()

    def clear_stored_credentials(self) -> bool:
        """Clear stored credentials and revert to fallback credentials"""
        try:
            self.credentials = self.get_fallback_credentials()

            # Try to clear through settings manager
            success = True
            if hasattr(self.settings_manager, "credential_manager"):
                # Try country-aware call first
                try:
                    success = (
                        self.settings_manager.credential_manager.delete_credentials(
                            self.provider_name, self.country
                        )
                    )
                except TypeError:
                    success = (
                        self.settings_manager.credential_manager.delete_credentials(
                            self.provider_name
                        )
                    )
            else:
                logger.debug(
                    f"No credential deletion capability in settings manager for {self.provider_name}"
                )

            if success:
                logger.info(
                    f"{self.provider_name}: Stored credentials cleared successfully"
                )
                self.invalidate_token()
            else:
                logger.warning(
                    f"{self.provider_name}: Failed to clear stored credentials"
                )
            return success
        except Exception as e:
            logger.error(
                f"Error clearing stored credentials for {self.provider_name}: {e}"
            )
            return False

    def has_stored_credentials(self) -> bool:
        """Check if stored credentials exist"""
        try:
            # Try country-aware call first
            try:
                credentials = self.settings_manager.get_provider_credentials(
                    self.provider_name, self.country
                )
            except TypeError:
                credentials = self.settings_manager.get_provider_credentials(
                    self.provider_name
                )
            return credentials is not None and credentials.validate()
        except Exception as e:
            logger.debug(
                f"Error checking stored credentials for {self.provider_name}: {e}"
            )
            return False

    def test_current_credentials(self) -> bool:
        """Test current credentials by attempting authentication"""
        try:
            country_str = f" (country: {self.country})" if self.country else ""
            logger.debug(f"Testing credentials for {self.provider_name}{country_str}")
            self.authenticate(force_refresh=True)
            logger.info(f"Credential test passed for {self.provider_name}{country_str}")
            return True
        except Exception as e:
            logger.warning(f"Credential test failed for {self.provider_name}: {e}")
            return False

    # Token management methods
    def _refresh_token(self) -> Optional[BaseAuthToken]:
        """Refresh the current token using refresh token"""
        return None

    def get_bearer_token(self, force_refresh: bool = False) -> str:
        """Get current bearer token, authenticating if necessary"""
        token = self.authenticate(force_refresh)
        return token.bearer_token

    def is_authenticated(self) -> bool:
        """Check if currently authenticated with valid token"""
        return self._current_token is not None and not self._current_token.is_expired

    def invalidate_token(self) -> None:
        """Invalidate current token"""
        country_str = f" (country: {self.country})" if self.country else ""
        logger.debug(f"Invalidating token for {self.provider_name}{country_str}")
        self._current_token = None

        try:
            # Try country-aware call first
            try:
                self.settings_manager.clear_token(self.provider_name, self.country)
            except TypeError:
                self.settings_manager.clear_token(self.provider_name)
        except Exception as e:
            logger.debug(
                f"Could not clear token from settings manager for {self.provider_name}: {e}"
            )

    def get_device_id(self) -> str:
        """Get persistent device ID for this provider"""
        try:
            # Try country-aware call first
            try:
                return self.settings_manager.get_device_id(
                    self.provider_name, self.country
                )
            except TypeError:
                return self.settings_manager.get_device_id(self.provider_name)
        except Exception as e:
            logger.error(f"Error getting device ID for {self.provider_name}: {e}")
            import uuid

            return str(uuid.uuid4())

    def get_token_info(self) -> Optional[Dict[str, Any]]:
        """Get information about the current token"""
        if not self._current_token:
            return None

        base_info = {
            "expires_in": self._current_token.expires_in,
            "issued_at": self._current_token.issued_at,
            "is_expired": self._current_token.is_expired,
            "token_type": self._current_token.token_type,
            "has_refresh_token": self._current_token.refresh_token is not None,
            "country": self.country,
        }

        base_info.update(self._current_token.to_dict())
        return base_info

    def get_authentication_status(self) -> Dict[str, Any]:
        """Get detailed authentication status information"""
        return {
            "provider": self.provider_name,
            "country": self.country,
            "is_authenticated": self.is_authenticated(),
            "token_info": self.get_token_info(),
            "credential_info": self.get_credential_info(),
        }

    @abstractmethod
    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        """
        Classify the authentication level of a token

        Must be implemented by subclasses to provide provider-specific logic
        for determining if a token is anonymous, client credentials, or user-authenticated.

        Args:
            token: Token to classify

        Returns:
            TokenAuthLevel indicating the authentication level
        """
        pass

    def should_upgrade_token(self, token: BaseAuthToken) -> bool:
        """
        Determine if a token should be upgraded based on:
        1. Token's current authentication level
        2. Availability of user credentials
        3. Provider-specific upgrade policy

        Args:
            token: Current token to evaluate

        Returns:
            True if token should be upgraded, False otherwise
        """
        if not token:
            return False

        # Classify token if not already classified
        if token.auth_level == TokenAuthLevel.UNKNOWN:
            token.auth_level = self._classify_token(token)

        # Check if token can be upgraded
        if not token.can_be_upgraded():
            return False

        # Check if we have user credentials available
        from ...base.auth.credentials import UserPasswordCredentials

        # Check stored credentials first
        try:
            stored_creds = self.settings_manager.get_provider_credentials(
                self.provider_name, self.country
            )
        except TypeError:
            stored_creds = self.settings_manager.get_provider_credentials(
                self.provider_name
            )

        has_user_creds = (
            isinstance(stored_creds, UserPasswordCredentials)
            and stored_creds.validate()
        )

        # Check current credentials
        if not has_user_creds:
            has_user_creds = (
                isinstance(self.credentials, UserPasswordCredentials)
                and self.credentials.validate()
            )

        # Only upgrade if we have user credentials
        return has_user_creds
