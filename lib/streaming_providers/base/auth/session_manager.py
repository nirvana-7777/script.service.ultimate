# streaming_providers/base/auth/session_manager.py
import uuid
import time
from typing import Optional, Dict, Any
from .base_auth import BaseAuthToken

# Import centralized logger and VFS
from ..utils.logger import logger
from ..utils.vfs import VFS


class SessionManager:
    """
    Manages persistent session data including tokens and device IDs
    Compatible with both Kodi and standalone environments via VFS abstraction
    Now supports country-specific sessions
    """

    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize SessionManager

        Args:
            config_dir: Optional config directory override (mainly for testing)
        """
        # Initialize VFS with optional config directory override
        if config_dir:
            # For custom config directories, we'll use a VFS instance that treats
            # the config_dir as the base path directly
            self.vfs = VFS()
            self.vfs._base_path = config_dir
        else:
            # Use default VFS (handles Kodi vs standard filesystem automatically)
            self.vfs = VFS()

        # Session file is always in the root of the VFS base path
        self.session_file = 'session.json'

        # Ensure base directory exists
        self.vfs.mkdirs('')

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

    def load_session(self, provider: str, country: Optional[str] = None) -> Optional[Dict[str, Any]]:
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
                safe_data = {}
                for key, value in session_data.items():
                    if key in ['access_token', 'refresh_token', 'client_secret', 'password']:
                        safe_data[key] = f"<{key}_present>" if value else f"<{key}_missing>"
                    else:
                        safe_data[key] = value
                logger.info(f"Loaded session data for {provider}{country_str}: {safe_data}")
            else:
                logger.info(f"No session data found for {provider}{country_str} in session file")

            return session_data

        except Exception as e:
            logger.error(f"Error loading session for {provider}{country_str}: {e}")
            return None

    def save_session(self, provider: str, session_data: Dict[str, Any],
                     country: Optional[str] = None) -> bool:
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
            if hasattr(session_data, 'auth_level'):
                # If session_data is a token-like object, convert to dict first
                if hasattr(session_data, 'to_dict'):
                    session_data = session_data.to_dict()
                else:
                    # Extract classification fields from object
                    token_dict = {}
                    for key in ['access_token', 'refresh_token', 'token_type', 'expires_in', 'issued_at',
                                'refresh_expires_in']:
                        if hasattr(session_data, key):
                            token_dict[key] = getattr(session_data, key)
                    session_data = token_dict

            # Log what we're about to save (without sensitive data)
            safe_data = {}
            for key, value in session_data.items():
                if key in ['access_token', 'refresh_token', 'client_secret', 'password']:
                    safe_data[key] = f"<{key}_present>" if value else f"<{key}_missing>"
                else:
                    safe_data[key] = value
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
                    # Navigate to verify
                    verify_current = verify_data
                    found = True
                    for key in keys_path:
                        if not isinstance(verify_current, dict) or key not in verify_current:
                            found = False
                            break
                        verify_current = verify_current[key]

                    if found:
                        logger.debug(f"Verification successful: {provider}{country_str} data found in saved file")
                    else:
                        logger.error(f"Verification failed: {provider}{country_str} data NOT found in saved file")
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

    def save_token(self, provider: str, token: BaseAuthToken,
                   country: Optional[str] = None) -> bool:
        """
        Save authentication token for a provider

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
            logger.debug(f"Current session data keys before token save: {list(session_data.keys())}")

            # Update token data - include classification fields
            token_data = token.to_dict()

            # Log token info (without sensitive data)
            safe_token_data = {}
            for key, value in token_data.items():
                if key in ['access_token', 'refresh_token']:
                    safe_token_data[key] = f"<{key}_present>" if value else f"<{key}_missing>"
                elif key in ['auth_level', 'credential_type']:
                    safe_token_data[key] = value  # Include classification info
                else:
                    safe_token_data[key] = value
            logger.info(f"Token data to save for {provider}{country_str}: {safe_token_data}")

            session_data.update(token_data)
            logger.debug(f"Updated session data keys after token merge: {list(session_data.keys())}")

            success = self.save_session(provider, session_data, country)
            if success:
                logger.info(f"Successfully saved authentication token for {provider}{country_str}")
            else:
                logger.error(f"Failed to save authentication token for {provider}{country_str}")
            return success

        except Exception as e:
            logger.error(f"Error saving token for {provider}{country_str}: {e}")
            return False

    def load_token_data(self, provider: str, country: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Load token data for a provider

        Args:
            provider: Provider name
            country: Optional country code

        Returns:
            Dictionary with token data or None if not found/expired
        """
        country_str = f" (country: {country})" if country else ""

        logger.debug(f"Loading token data for {provider}{country_str}")

        session_data = self.load_session(provider, country)
        if not session_data:
            logger.info(f"No session data available for token loading for {provider}{country_str}")
            return None

        # Check if we have token data
        if 'access_token' not in session_data:
            logger.info(f"No access token found in session data for {provider}{country_str}")
            logger.debug(f"Available session keys: {list(session_data.keys())}")
            return None

        # Check if token is expired (with 5 minute buffer)
        expires_in = session_data.get('expires_in', 0)
        issued_at = session_data.get('issued_at', 0)
        current_time = time.time()
        expires_at = issued_at + expires_in
        time_until_expiry = expires_at - current_time

        logger.debug(f"Token expiry check for {provider}{country_str}: issued_at={issued_at}, "
                     f"expires_in={expires_in}, current_time={current_time}, "
                     f"time_until_expiry={time_until_expiry:.0f}")

        if current_time >= (expires_at - 300):  # 5 minute buffer
            logger.info(f"Token expired for {provider}{country_str} "
                        f"(expired {abs(time_until_expiry):.0f}s ago)")
            return None

        logger.info(f"Loaded valid token data for {provider}{country_str} "
                    f"(expires in {time_until_expiry:.0f}s, "
                    f"auth_level={session_data.get('auth_level')})")
        return session_data

    def get_device_id(self, provider: str, country: Optional[str] = None) -> str:
        """
        Get or generate device ID for a provider

        Args:
            provider: Provider name
            country: Optional country code

        Returns:
            Device ID (UUID string)
        """
        country_str = f" (country: {country})" if country else ""

        session_data = self.load_session(provider, country) or {}

        device_id = session_data.get('device_id')
        if not device_id:
            # Generate new device ID
            device_id = str(uuid.uuid4())
            session_data['device_id'] = device_id
            self.save_session(provider, session_data, country)
            logger.info(f"Generated new device ID for {provider}{country_str}: {device_id}")
        else:
            logger.debug(f"Using existing device ID for {provider}{country_str}: {device_id}")

        return device_id

    def clear_session(self, provider: str, country: Optional[str] = None) -> bool:
        """
        Clear session data for a provider and optional country

        Args:
            provider: Provider name
            country: Optional country code (if None, clears entire provider)

        Returns:
            True if successful, False otherwise
        """
        country_str = f" (country: {country})" if country else ""

        try:
            data = self.vfs.read_json(self.session_file)
            if not data:
                logger.debug(f"No session file exists, nothing to clear for {provider}{country_str}")
                return True

            if country:
                # Clear specific country data
                if provider in data and isinstance(data[provider], dict) and country in data[provider]:
                    del data[provider][country]
                    logger.info(f"Cleared session data for {provider}{country_str}")

                    # If provider dict is now empty, remove it entirely
                    if not data[provider]:
                        del data[provider]
                        logger.debug(f"Provider {provider} had no more countries, removed entirely")

                    return self.vfs.write_json(self.session_file, data)
                else:
                    logger.debug(f"No session data found to clear for {provider}{country_str}")
            else:
                # Clear entire provider data (all countries)
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

    def clear_token(self, provider: str, country: Optional[str] = None) -> bool:
        """
        Clear only token data but keep other session data (like device_id)

        Args:
            provider: Provider name
            country: Optional country code

        Returns:
            True if successful, False otherwise
        """
        country_str = f" (country: {country})" if country else ""

        try:
            session_data = self.load_session(provider, country)
            if not session_data:
                logger.debug(f"No session data found, nothing to clear for {provider}{country_str}")
                return True

            # Remove token-related fields
            token_fields = ['access_token', 'refresh_token', 'token_type', 'expires_in',
                            'issued_at', 'auth_level', 'credential_type']
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
        """
        Get all countries that have session data for a provider

        Args:
            provider: Provider name

        Returns:
            List of country codes
        """
        try:
            data = self.vfs.read_json(self.session_file)
            if not data or provider not in data:
                return []

            provider_data = data[provider]

            # Check if this is a nested (country-aware) structure
            if isinstance(provider_data, dict):
                # Check if any keys look like country codes (2-3 char strings)
                # and their values are dicts (session data)
                countries = []
                for key, value in provider_data.items():
                    if isinstance(value, dict) and len(key) <= 3:
                        countries.append(key)
                return countries

            return []

        except Exception as e:
            logger.error(f"Error getting countries for {provider}: {e}")
            return []

    def debug_session_file(self) -> None:
        """
        Debug method to log the current state of the session file
        """
        try:
            logger.info(f"=== SESSION FILE DEBUG INFO ===")

            # Get VFS debug info
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
                        logger.info(f"Session file contains {len(data)} providers: {list(data.keys())}")

                        for provider, provider_data in data.items():
                            if isinstance(provider_data, dict):
                                # Check if nested (has countries)
                                has_countries = any(
                                    isinstance(v, dict) and len(k) <= 3
                                    for k, v in provider_data.items()
                                )

                                if has_countries:
                                    logger.info(f"  {provider} (country-aware):")
                                    for country, session_data in provider_data.items():
                                        if isinstance(session_data, dict):
                                            safe_keys = self._get_safe_keys(session_data)
                                            logger.info(f"    {country}: {safe_keys}")
                                else:
                                    # Flat structure (no country)
                                    safe_keys = self._get_safe_keys(provider_data)
                                    logger.info(f"  {provider} (no country): {safe_keys}")
                    else:
                        logger.error("Session file contains invalid JSON or is empty")
                else:
                    logger.info("Session file is empty")
            else:
                logger.info("Session file does not exist yet")

            logger.info(f"=== END SESSION FILE DEBUG ===")

        except Exception as e:
            logger.error(f"Error during session file debug: {e}")

    @staticmethod
    def _get_safe_keys(session_data: Dict[str, Any]) -> list:
        """Helper to get safe representation of session keys"""
        safe_keys = []
        for key in session_data.keys():
            if key in ['access_token', 'refresh_token']:
                safe_keys.append(f"{key}:present" if session_data[key] else f"{key}:missing")
            else:
                safe_keys.append(f"{key}:{session_data[key]}")
        return safe_keys