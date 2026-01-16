# streaming_providers/base/auth/session_manager.py
import time
import uuid
from typing import Any, Dict, Optional

# Import centralized logger and VFS
from ..utils.logger import logger
from ..utils.vfs import VFS
from .base_auth import BaseAuthToken


class SessionManager:
    """
    Manages persistent session data including tokens and device IDs
    Compatible with both Kodi and standalone environments via VFS abstraction
    Now supports country-specific sessions and scope-based token storage
    """

    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize SessionManager

        Args:
            config_dir: Optional config directory override (mainly for testing)
        """
        # Initialize VFS with optional config directory override
        if config_dir:
            self.vfs = VFS()
            self.vfs._base_path = config_dir
        else:
            self.vfs = VFS()

        # Session file is always in the root of the VFS base path
        self.session_file = "session.json"

        # Ensure base directory exists
        self.vfs.mkdirs("")

        logger.debug(f"SessionManager initialized with VFS base: {self.vfs.base_path}")
        logger.debug(f"Session file: {self.vfs.join_path(self.session_file)}")

    @staticmethod
    def _get_session_path(provider: str, country: Optional[str] = None) -> tuple:
        """
        Determine the path to session data based on country

        Args:
            provider: Provider name
            country: Optional country code (e.g., 'de', 'at', 'ch')

        Returns:
            Tuple of (keys_path, is_nested) where keys_path is list of keys to navigate
        """
        if country:
            return [provider, country], True
        else:
            return [provider], False

    def load_session(
        self, provider: str, country: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Load session data for a specific provider and optional country

        Args:
            provider: Provider name
            country: Optional country code (e.g., 'de', 'at', 'ch')

        Returns:
            Session data dictionary or None
        """
        country_str = f" (country: {country})" if country else ""

        try:
            logger.debug(f"Attempting to load session data for {provider}{country_str}")

            data = self.vfs.read_json(self.session_file)
            if not data:
                logger.info(f"Session file does not exist or is empty")
                return None

            # Navigate to the correct session data
            keys_path, is_nested = self._get_session_path(provider, country)
            session_data = data

            for key in keys_path:
                if not isinstance(session_data, dict) or key not in session_data:
                    logger.info(f"No session data found at path: {' -> '.join(keys_path)}")
                    return None
                session_data = session_data[key]

            if session_data:
                # Log what we found (without sensitive data)
                safe_data = self._get_safe_representation(session_data)
                logger.info(f"Loaded session data for {provider}{country_str}: {safe_data}")
            else:
                logger.info(f"No session data found for {provider}{country_str} in session file")

            return session_data

        except Exception as e:
            logger.error(f"Error loading session for {provider}{country_str}: {e}")
            return None

    def save_session(
        self, provider: str, session_data: Dict[str, Any], country: Optional[str] = None
    ) -> bool:
        """
        Save session data for a specific provider and optional country

        Args:
            provider: Provider name
            session_data: Session data to save
            country: Optional country code (e.g., 'de', 'at', 'ch')

        Returns:
            True if successful, False otherwise
        """
        country_str = f" (country: {country})" if country else ""

        try:
            logger.debug(f"Attempting to save session data for {provider}{country_str}")

            # Load existing data
            data = self.vfs.read_json(self.session_file) or {}
            logger.debug(f"Loaded existing data for providers: {list(data.keys())}")

            # Extract and preserve token classification data if it's a token object
            if hasattr(session_data, "auth_level"):
                if hasattr(session_data, "to_dict"):
                    session_data = session_data.to_dict()
                else:
                    token_dict = {}
                    for key in [
                        "access_token",
                        "refresh_token",
                        "token_type",
                        "expires_in",
                        "issued_at",
                        "refresh_expires_in",
                    ]:
                        if hasattr(session_data, key):
                            token_dict[key] = getattr(session_data, key)
                    session_data = token_dict

            # Log what we're about to save (without sensitive data)
            safe_data = self._get_safe_representation(session_data)
            logger.info(f"Saving session data for {provider}{country_str}: {safe_data}")

            # Navigate and create nested structure if needed
            keys_path, is_nested = self._get_session_path(provider, country)

            # Build nested structure
            current = data
            for i, key in enumerate(keys_path[:-1]):
                if key not in current:
                    current[key] = {}
                elif not isinstance(current[key], dict):
                    logger.warning(f"Overwriting non-dict value at {key}")
                    current[key] = {}
                current = current[key]

            # Set the final value
            current[keys_path[-1]] = session_data

            # Save to file using VFS
            success = self.vfs.write_json(self.session_file, data)

            if success:
                logger.info(f"Successfully saved session data for {provider}{country_str}")

                # Verify by reading it back
                verify_data = self.vfs.read_json(self.session_file)
                if verify_data:
                    verify_current = verify_data
                    found = True
                    for key in keys_path:
                        if not isinstance(verify_current, dict) or key not in verify_current:
                            found = False
                            break
                        verify_current = verify_current[key]

                    if found:
                        logger.debug(
                            f"Verification successful: {provider}{country_str} data found in saved file"
                        )
                    else:
                        logger.error(
                            f"Verification failed: {provider}{country_str} data NOT found in saved file"
                        )
                        return False
                else:
                    logger.error(f"Verification failed: Could not read back session file")
                    return False
            else:
                logger.error(f"Failed to write session file")
                return False

            return True

        except Exception as e:
            import traceback

            logger.error(f"Error saving session for {provider}{country_str}: {e}")
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return False

    def save_scoped_token(
        self,
        provider: str,
        scope: str,
        token_data: Dict[str, Any],
        country: Optional[str] = None,
    ) -> bool:
        """
        Save authentication token for a specific scope

        Args:
            provider: Provider name
            scope: Token scope (e.g., 'line_auth', 'taa', 'yo_digital')
            token_data: Token data to save
            country: Optional country code

        Returns:
            True if successful, False otherwise
        """
        country_str = f" (country: {country})" if country else ""

        try:
            logger.debug(f"Saving scoped token for {provider}{country_str}, scope: {scope}")

            # Load existing session data
            session_data = self.load_session(provider, country) or {}

            # Update token data for this scope
            session_data[scope] = token_data

            # Log what we're saving
            safe_token_data = self._get_safe_representation(token_data)
            logger.info(f"Scoped token data for {provider}{country_str}/{scope}: {safe_token_data}")

            success = self.save_session(provider, session_data, country)
            if success:
                logger.info(f"Successfully saved scoped token for {provider}{country_str}/{scope}")
            else:
                logger.error(f"Failed to save scoped token for {provider}{country_str}/{scope}")
            return success

        except Exception as e:
            logger.error(f"Error saving scoped token for {provider}{country_str}/{scope}: {e}")
            return False

    def load_scoped_token(
        self, provider: str, scope: str, country: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Load token data for a specific scope (ENHANCED VERSION)
        """
        country_str = f" (country: {country})" if country else ""

        logger.debug(f"Loading scoped token for {provider}{country_str}, scope: {scope}")

        session_data = self.load_session(provider, country)
        if not session_data:
            logger.info(f"No session data available for {provider}{country_str}")
            return None

        # Check if scope exists
        if scope not in session_data:
            logger.info(f"No token found for scope '{scope}' in {provider}{country_str}")
            logger.debug(f"Available scopes: {list(session_data.keys())}")
            return None

        token_data = session_data[scope]

        # 🚨 FIX: Special handling for persona scope
        if scope == "persona":
            if not isinstance(token_data, dict) or "persona_token" not in token_data:
                logger.warning(f"Persona scope exists but doesn't contain valid persona token data")
                return None

            # Persona tokens don't expire in the same way - they use expires_at field
            logger.info(f"Loaded persona token for {provider}{country_str}")
            return token_data

        # Validate it's actually token data (for other scopes)
        if not isinstance(token_data, dict) or "access_token" not in token_data:
            logger.warning(f"Scope '{scope}' exists but doesn't contain valid token data")
            return None

        # Check access token expiration
        access_token_expired = self._is_token_expired(token_data)

        # For yo_digital, also check refresh token
        if scope == "yo_digital" and "refresh_token" in token_data:
            refresh_token_expired = self._is_refresh_token_expired(token_data)

            if access_token_expired and not refresh_token_expired:
                logger.info(
                    f"Access token expired for scope '{scope}' but refresh token still valid"
                )
                return token_data  # Return so caller can attempt refresh
            elif access_token_expired and refresh_token_expired:
                logger.warning(f"Both access and refresh tokens expired for scope '{scope}'")
                return None  # Both expired, no point returning
            else:
                logger.info(f"Loaded valid token for {provider}{country_str}/{scope}")
                return token_data

        # Standard token handling (tvhubs, taa, etc.)
        if access_token_expired:
            logger.info(f"Token for scope '{scope}' is expired")
            # Still return it - caller might want to attempt refresh or re-auth
            return token_data

        logger.info(f"Loaded valid token for {provider}{country_str}/{scope}")
        return token_data

    @staticmethod
    def _is_token_expired(token_data: Dict[str, Any], buffer_seconds: int = 300) -> bool:
        """
        Check if token is expired with buffer

        Enhanced to support multiple expiration formats:
        1. Standard format: expires_in + issued_at (for access_token)
        2. yo_digital format: separate expiry for access_token and refresh_token

        Args:
            token_data: Token data dictionary
            buffer_seconds: Seconds buffer before expiry (default 5 minutes)

        Returns:
            True if expired, False otherwise

        Note:
            For yo_digital tokens with both access_token and refresh_token,
            this checks the access_token expiration only (not refresh_token).
        """
        current_time = time.time()

        # Format 1: Standard single token expiration
        # Used by: tvhubs tokens, taa tokens, SAM3 tokens
        if "expires_in" in token_data and "issued_at" in token_data:
            expires_in = token_data.get("expires_in", 0)
            issued_at = token_data.get("issued_at", 0)
            expires_at = issued_at + expires_in

            is_expired = current_time >= (expires_at - buffer_seconds)

            if is_expired:
                logger.debug(
                    f"Token expired (standard format): "
                    f"issued_at={issued_at}, expires_in={expires_in}, "
                    f"expires_at={expires_at}, current={current_time}"
                )

            return is_expired

        # Format 2: yo_digital separate expiration for access_token
        # yo_digital tokens have separate expiry for access and refresh tokens
        if "access_token_expires_in" in token_data and "access_token_issued_at" in token_data:
            expires_in = token_data.get("access_token_expires_in", 0)
            issued_at = token_data.get("access_token_issued_at", 0)
            expires_at = issued_at + expires_in

            is_expired = current_time >= (expires_at - buffer_seconds)

            if is_expired:
                logger.debug(
                    f"Access token expired (yo_digital format): "
                    f"issued_at={issued_at}, expires_in={expires_in}, "
                    f"expires_at={expires_at}, current={current_time}"
                )

            return is_expired

        # Format 3: Direct expiration timestamp (if some API returns 'exp' or 'expires_at')
        if "expires_at" in token_data:
            expires_at = token_data.get("expires_at", 0)
            is_expired = current_time >= (expires_at - buffer_seconds)

            if is_expired:
                logger.debug(
                    f"Token expired (direct timestamp): "
                    f"expires_at={expires_at}, current={current_time}"
                )

            return is_expired

        # No expiration info available - assume valid
        logger.debug("No expiration info in token data - assuming valid")
        return False

    @staticmethod
    def _is_refresh_token_expired(token_data: Dict[str, Any], buffer_seconds: int = 300) -> bool:
        """
        Check if refresh token is expired (for yo_digital tokens)

        This is a separate check specifically for yo_digital refresh tokens
        which have their own expiration separate from access tokens.

        Args:
            token_data: Token data dictionary
            buffer_seconds: Seconds buffer before expiry (default 5 minutes)

        Returns:
            True if refresh token expired, False otherwise or if no refresh token
        """
        # yo_digital format with separate refresh token expiry
        if "refresh_token_expires_in" in token_data and "refresh_token_issued_at" in token_data:
            current_time = time.time()
            expires_in = token_data.get("refresh_token_expires_in", 0)
            issued_at = token_data.get("refresh_token_issued_at", 0)
            expires_at = issued_at + expires_in

            is_expired = current_time >= (expires_at - buffer_seconds)

            if is_expired:
                logger.debug(
                    f"Refresh token expired (yo_digital format): "
                    f"issued_at={issued_at}, expires_in={expires_in}, "
                    f"expires_at={expires_at}, current={current_time}"
                )

            return is_expired

        # No refresh token or no expiration info
        return False

    def save_token(
        self, provider: str, token: BaseAuthToken, country: Optional[str] = None
    ) -> bool:
        """
        Save authentication token for a provider (legacy compatibility)

        Args:
            provider: Provider name
            token: Authentication token to save
            country: Optional country code

        Returns:
            True if successful, False otherwise
        """
        country_str = f" (country: {country})" if country else ""

        try:
            logger.debug(f"Saving authentication token for {provider}{country_str}")

            # Load existing session data
            session_data = self.load_session(provider, country) or {}

            # Update token data
            token_data = token.to_dict()

            # Log token info (without sensitive data)
            safe_token_data = self._get_safe_representation(token_data)
            logger.info(f"Token data to save for {provider}{country_str}: {safe_token_data}")

            session_data.update(token_data)

            success = self.save_session(provider, session_data, country)
            if success:
                logger.info(f"Successfully saved authentication token for {provider}{country_str}")
            else:
                logger.error(f"Failed to save authentication token for {provider}{country_str}")
            return success

        except Exception as e:
            logger.error(f"Error saving token for {provider}{country_str}: {e}")
            return False

    def load_token_data(
        self, provider: str, country: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Load token data for a provider (legacy compatibility)"""
        country_str = f" (country: {country})" if country else ""

        logger.debug(f"Loading token data for {provider}{country_str}")

        session_data = self.load_session(provider, country)
        if not session_data:
            logger.info(f"No session data available for token loading for {provider}{country_str}")
            return None

        # Check if we have token data
        if "access_token" not in session_data:
            logger.info(f"No access token found in session data for {provider}{country_str}")
            logger.debug(f"Available session keys: {list(session_data.keys())}")
            return None

        # Check if token is expired
        if self._is_token_expired(session_data):
            has_refresh_token = bool(session_data.get("refresh_token"))
            if has_refresh_token:
                logger.info(
                    f"Token expired for {provider}{country_str} but refresh token available"
                )
                return session_data
            else:
                logger.info(
                    f"Token expired for {provider}{country_str} and no refresh token available"
                )
                return None

        logger.info(f"Loaded valid token data for {provider}{country_str}")
        return session_data

    def get_device_id(self, provider: str, country: Optional[str] = None) -> str:
        """Get or generate device ID for a provider"""
        country_str = f" (country: {country})" if country else ""

        session_data = self.load_session(provider, country) or {}

        device_id = session_data.get("device_id")
        if not device_id:
            device_id = str(uuid.uuid4())
            session_data["device_id"] = device_id
            self.save_session(provider, session_data, country)
            logger.info(f"Generated new device ID for {provider}{country_str}: {device_id}")
        else:
            logger.debug(f"Using existing device ID for {provider}{country_str}: {device_id}")

        return device_id

    def clear_session(self, provider: str, country: Optional[str] = None) -> bool:
        """Clear session data for a provider and optional country"""
        country_str = f" (country: {country})" if country else ""

        try:
            data = self.vfs.read_json(self.session_file)
            if not data:
                logger.debug(
                    f"No session file exists, nothing to clear for {provider}{country_str}"
                )
                return True

            if country:
                if (
                    provider in data
                    and isinstance(data[provider], dict)
                    and country in data[provider]
                ):
                    del data[provider][country]
                    logger.info(f"Cleared session data for {provider}{country_str}")

                    if not data[provider]:
                        del data[provider]
                        logger.debug(f"Provider {provider} had no more countries, removed entirely")

                    return self.vfs.write_json(self.session_file, data)
                else:
                    logger.debug(f"No session data found to clear for {provider}{country_str}")
            else:
                if provider in data:
                    del data[provider]
                    logger.info(f"Cleared all session data for {provider}")
                    return self.vfs.write_json(self.session_file, data)
                else:
                    logger.debug(f"No session data found to clear for {provider}")

            return True

        except Exception as e:
            logger.error(f"Error clearing session for {provider}{country_str}: {e}")
            return False

    def clear_scoped_token(self, provider: str, scope: str, country: Optional[str] = None) -> bool:
        """
        Clear token for a specific scope

        Args:
            provider: Provider name
            scope: Token scope to clear
            country: Optional country code

        Returns:
            True if successful, False otherwise
        """
        country_str = f" (country: {country})" if country else ""

        try:
            session_data = self.load_session(provider, country)
            if not session_data:
                logger.debug(f"No session data found for {provider}{country_str}")
                return True

            if scope in session_data:
                del session_data[scope]
                logger.info(f"Cleared scoped token for {provider}{country_str}/{scope}")
                return self.save_session(provider, session_data, country)
            else:
                logger.debug(f"No token found for scope '{scope}' in {provider}{country_str}")
                return True

        except Exception as e:
            logger.error(f"Error clearing scoped token for {provider}{country_str}/{scope}: {e}")
            return False

    def clear_token(self, provider: str, country: Optional[str] = None) -> bool:
        """Clear only token data but keep other session data (legacy compatibility)"""
        country_str = f" (country: {country})" if country else ""

        try:
            session_data = self.load_session(provider, country)
            if not session_data:
                logger.debug(f"No session data found, nothing to clear for {provider}{country_str}")
                return True

            # Remove token-related fields
            token_fields = [
                "access_token",
                "refresh_token",
                "token_type",
                "expires_in",
                "issued_at",
                "auth_level",
                "credential_type",
            ]
            fields_removed = []
            for field in token_fields:
                if session_data.pop(field, None) is not None:
                    fields_removed.append(field)

            if fields_removed:
                logger.debug(f"Cleared token fields {fields_removed} for {provider}{country_str}")

            return self.save_session(provider, session_data, country)

        except Exception as e:
            logger.error(f"Error clearing token for {provider}{country_str}: {e}")
            return False

    def get_all_countries(self, provider: str) -> list:
        """Get all countries that have session data for a provider"""
        try:
            data = self.vfs.read_json(self.session_file)
            if not data or provider not in data:
                return []

            provider_data = data[provider]

            if isinstance(provider_data, dict):
                countries = []
                for key, value in provider_data.items():
                    if isinstance(value, dict) and len(key) <= 3:
                        countries.append(key)
                return countries

            return []

        except Exception as e:
            logger.error(f"Error getting countries for {provider}: {e}")
            return []

    @staticmethod
    def _get_safe_representation(data: Any) -> Dict[str, Any]:
        """Get safe representation of data hiding sensitive fields"""
        if not isinstance(data, dict):
            return {}

        safe_data = {}
        for key, value in data.items():
            if key in [
                "access_token",
                "refresh_token",
                "client_secret",
                "password",
                "persona_token",
                "persona_jwt",
            ]:  # ← ADD THESE TWO FIELDS
                safe_data[key] = f"<present>" if value else f"<missing>"
            elif isinstance(value, dict):
                # Recursively handle nested dicts (for scoped tokens)
                safe_data[key] = SessionManager._get_safe_representation(value)
            else:
                safe_data[key] = value

        return safe_data

    def debug_session_file(self) -> None:
        """Debug method to log the current state of the session file"""
        try:
            logger.info(f"=== SESSION FILE DEBUG INFO ===")

            vfs_info = self.vfs.debug_info()
            for key, value in vfs_info.items():
                logger.info(f"VFS {key}: {value}")

            session_file_path = self.vfs.join_path(self.session_file)
            logger.info(f"Session file path: {session_file_path}")
            logger.info(f"Session file exists: {self.vfs.exists(self.session_file)}")

            if self.vfs.exists(self.session_file):
                file_size = self.vfs.get_size(self.session_file)
                logger.info(f"Session file size: {file_size} bytes")

                if file_size and file_size > 0:
                    data = self.vfs.read_json(self.session_file)
                    if data:
                        logger.info(
                            f"Session file contains {len(data)} providers: {list(data.keys())}"
                        )

                        for provider, provider_data in data.items():
                            if isinstance(provider_data, dict):
                                has_countries = any(
                                    isinstance(v, dict) and len(k) <= 3
                                    for k, v in provider_data.items()
                                )

                                if has_countries:
                                    logger.info(f"  {provider} (country-aware):")
                                    for country, session_data in provider_data.items():
                                        if isinstance(session_data, dict):
                                            safe_repr = self._get_safe_representation(session_data)
                                            logger.info(f"    {country}: {safe_repr}")
                                else:
                                    safe_repr = self._get_safe_representation(provider_data)
                                    logger.info(f"  {provider} (no country): {safe_repr}")
                    else:
                        logger.error("Session file contains invalid JSON or is empty")
                else:
                    logger.info("Session file is empty")
            else:
                logger.info("Session file does not exist yet")

            logger.info(f"=== END SESSION FILE DEBUG ===")

        except Exception as e:
            logger.error(f"Error during session file debug: {e}")
