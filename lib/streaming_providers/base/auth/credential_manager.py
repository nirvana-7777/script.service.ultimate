# streaming_providers/base/auth/credential_manager.py
import time
from typing import Any, Dict, List, Optional

# Import centralized logger and VFS
from ..utils.logger import logger
from .credentials import (BaseCredentials, ClientCredentials,
                          UserPasswordCredentials)


class CredentialManager:
    """
    Manages loading and saving credentials from/to persistent storage
    Now supports country-specific credentials
    """

    def __init__(self, config_dir: Optional[str] = None):
        # Initialize VFS with config directory support
        from ..utils.vfs import VFS

        self.vfs = VFS(config_dir=config_dir)

        # Credentials file is always in the root of the VFS base path
        self.credentials_file = "credentials.json"

        # Ensure base directory exists
        self.vfs.mkdirs("")
        logger.debug(
            f"CredentialManager initialized with VFS base: {self.vfs.base_path}"
        )

    @staticmethod
    def _get_credential_path(provider: str, country: Optional[str] = None) -> tuple:
        """
        Determine the path to credential data based on country

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

    def load_credentials(
        self, provider: str, country: Optional[str] = None
    ) -> Optional[BaseCredentials]:
        """
        Load credentials for a specific provider and optional country.

        Now with fallback: tries with country first, then without country
        for backward compatibility with credentials stored without country nesting.

        Args:
            provider: Provider name (e.g., 'rtlplus', 'joyn')
            country: Optional country code (e.g., 'de', 'at', 'ch')

        Returns:
            BaseCredentials instance or None if not found
        """
        country_str = f" (country: {country})" if country else ""

        try:
            logger.debug(
                f"CredentialManager: Loading credentials for '{provider}{country_str}'"
            )

            # Check if credentials file exists
            if not self.vfs.exists(self.credentials_file):
                logger.debug(
                    f"CredentialManager: Credentials file does not exist: {self.credentials_file}"
                )
                return None

            logger.debug(
                f"CredentialManager: Reading credentials file: {self.credentials_file}"
            )
            data = self.vfs.read_json(self.credentials_file)

            if not data:
                logger.debug(
                    f"CredentialManager: Credentials file is empty or invalid JSON"
                )
                return None

            logger.debug(
                f"CredentialManager: Available providers in file: {list(data.keys())}"
            )

            # Try with country first (new format: {"provider": {"country": {...}}})
            if country:
                keys_path, _ = self._get_credential_path(provider, country)
                provider_data = data
                found = True

                for key in keys_path:
                    if not isinstance(provider_data, dict) or key not in provider_data:
                        found = False
                        break
                    provider_data = provider_data[key]

                if found and provider_data:
                    logger.debug(
                        f"CredentialManager: Found credentials with country nesting for '{provider}{country_str}'"
                    )
                    return self._create_credential_from_data(
                        provider, country, provider_data
                    )

                # Fallback: try without country (legacy format: {"provider": {...}})
                logger.debug(
                    f"CredentialManager: No country-nested credentials found, trying legacy format"
                )
                keys_path, _ = self._get_credential_path(provider, None)
                provider_data = data

                for key in keys_path:
                    if not isinstance(provider_data, dict) or key not in provider_data:
                        logger.debug(
                            f"CredentialManager: No credentials found at path: {' -> '.join(keys_path)}"
                        )
                        return None
                    provider_data = provider_data[key]

                if provider_data:
                    logger.debug(
                        f"CredentialManager: Found credentials in legacy format for '{provider}{country_str}'"
                    )
                    return self._create_credential_from_data(
                        provider, country, provider_data
                    )

                return None

            # No country specified - direct lookup
            keys_path, _ = self._get_credential_path(provider, None)
            provider_data = data

            for key in keys_path:
                if not isinstance(provider_data, dict) or key not in provider_data:
                    logger.debug(
                        f"CredentialManager: No data found at path: {' -> '.join(keys_path)}"
                    )
                    return None
                provider_data = provider_data[key]

            if not provider_data:
                logger.debug(
                    f"CredentialManager: No data found for provider '{provider}'"
                )
                return None

            return self._create_credential_from_data(provider, None, provider_data)

        except Exception as e:
            logger.error(
                f"CredentialManager: Error loading credentials for '{provider}{country_str}': {e}"
            )
            return None

    def _create_credential_from_data(
        self, provider: str, country: Optional[str], provider_data: dict
    ) -> Optional[BaseCredentials]:
        """
        Helper method to create credential object from loaded data.

        Args:
            provider: Provider name
            country: Optional country code (for logging)
            provider_data: Dictionary containing credential data

        Returns:
            BaseCredentials instance or None
        """
        country_str = f" (country: {country})" if country else ""

        logger.debug(
            f"CredentialManager: Found data for '{provider}{country_str}': {list(provider_data.keys())}"
        )

        credential_type = provider_data.get("type")
        logger.debug(
            f"CredentialManager: Credential type for '{provider}{country_str}': {credential_type}"
        )

        if credential_type == "user_password":
            username = provider_data.get("username", "")
            password_present = "password" in provider_data
            client_id = provider_data.get("client_id")

            logger.debug(
                f"CredentialManager: Creating UserPasswordCredentials for '{provider}{country_str}'"
            )
            logger.debug(
                f"CredentialManager: Username: '{username}', Password present: {password_present}, Client ID: {client_id}"
            )

            creds = UserPasswordCredentials(
                username=username,
                password=self._decode_password(provider_data.get("password", "")),
                client_id=client_id,
                grant_type=provider_data.get("grant_type", "password"),
            )

            logger.debug(
                f"CredentialManager: Successfully created UserPasswordCredentials for '{provider}{country_str}'"
            )
            return creds

        elif credential_type == "client_credentials":
            client_id = provider_data.get("client_id", "")
            client_secret_present = "client_secret" in provider_data

            logger.debug(
                f"CredentialManager: Creating ClientCredentials for '{provider}{country_str}'"
            )
            logger.debug(
                f"CredentialManager: Client ID: '{client_id}', Client secret present: {client_secret_present}"
            )

            creds = ClientCredentials(
                client_id=client_id,
                client_secret=self._decode_password(
                    provider_data.get("client_secret", "")
                ),
                grant_type=provider_data.get("grant_type", "client_credentials"),
            )

            logger.debug(
                f"CredentialManager: Successfully created ClientCredentials for '{provider}{country_str}'"
            )
            return creds

        else:
            logger.error(
                f"CredentialManager: Unknown credential type for '{provider}{country_str}': {credential_type}"
            )
            return None

    def save_credentials(
        self, provider: str, credentials: BaseCredentials, country: Optional[str] = None
    ) -> bool:
        """
        Save credentials for a specific provider and optional country

        Args:
            provider: Provider name
            credentials: Credentials to save
            country: Optional country code

        Returns:
            True if successful, False otherwise
        """
        country_str = f" (country: {country})" if country else ""
        try:
            logger.debug(
                f"Saving {credentials.credential_type} credentials for {provider}{country_str}"
            )

            # Load existing data
            data = {}
            if self.vfs.exists(self.credentials_file):
                data = self.vfs.read_json(self.credentials_file) or {}

            # Prepare provider data based on credential type
            if isinstance(credentials, UserPasswordCredentials):
                provider_data = {
                    "type": "user_password",
                    "username": credentials.username,
                    "password": self._encode_password(credentials.password),
                    "grant_type": credentials.grant_type,
                }
                if credentials.client_id:
                    provider_data["client_id"] = credentials.client_id

            elif isinstance(credentials, ClientCredentials):
                provider_data = {
                    "type": "client_credentials",
                    "client_id": credentials.client_id,
                    "client_secret": self._encode_password(credentials.client_secret),
                    "grant_type": credentials.grant_type,
                }
            else:
                logger.error(f"Unsupported credential type: {type(credentials)}")
                return False

            # Navigate and create nested structure if needed
            keys_path, is_nested = self._get_credential_path(provider, country)

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
            current[keys_path[-1]] = provider_data

            # Save to file using VFS
            success = self.vfs.write_json(self.credentials_file, data)

            if success:
                logger.info(
                    f"Successfully saved credentials for {provider}{country_str}"
                )

                # Verify by reading back
                verify_data = self.vfs.read_json(self.credentials_file)
                if verify_data:
                    verify_current = verify_data
                    found = True
                    for key in keys_path:
                        if (
                            not isinstance(verify_current, dict)
                            or key not in verify_current
                        ):
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

                return True
            else:
                logger.error(f"Failed to save credentials for {provider}{country_str}")
                return False

        except Exception as e:
            country_str = f" (country: {country})" if country else ""
            logger.error(f"Error saving credentials for {provider}{country_str}: {e}")
            return False

    def delete_credentials(self, provider: str, country: Optional[str] = None) -> bool:
        """
        Delete credentials for a specific provider and optional country

        Args:
            provider: Provider name
            country: Optional country code (if None, deletes entire provider or all countries)

        Returns:
            True if successful, False otherwise
        """
        country_str = f" (country: {country})" if country else ""
        try:

            if not self.vfs.exists(self.credentials_file):
                logger.debug(
                    f"No credentials file exists, nothing to delete for {provider}{country_str}"
                )
                return True

            data = self.vfs.read_json(self.credentials_file)
            if not data:
                logger.debug(
                    f"Credentials file is empty, nothing to delete for {provider}{country_str}"
                )
                return True

            if country:
                # Delete specific country data
                if (
                    provider in data
                    and isinstance(data[provider], dict)
                    and country in data[provider]
                ):
                    del data[provider][country]
                    logger.info(
                        f"Deleted stored credentials for {provider}{country_str}"
                    )

                    # If provider dict is now empty, remove it entirely
                    if not data[provider]:
                        del data[provider]
                        logger.debug(
                            f"Provider {provider} had no more countries, removed entirely"
                        )

                    return self.vfs.write_json(self.credentials_file, data)
                else:
                    logger.debug(
                        f"No stored credentials found to delete for {provider}{country_str}"
                    )
            else:
                # Delete entire provider data (all countries)
                if provider in data:
                    del data[provider]
                    logger.info(f"Deleted all stored credentials for {provider}")
                    return self.vfs.write_json(self.credentials_file, data)
                else:
                    logger.debug(
                        f"No stored credentials found to delete for {provider}"
                    )

            return True

        except Exception as e:
            country_str = f" (country: {country})" if country else ""
            logger.error(f"Error deleting credentials for {provider}{country_str}: {e}")
            return False

    def list_providers(self) -> List[str]:
        """
        List all providers with stored credentials

        Returns:
            List of provider names
        """
        try:
            if not self.vfs.exists(self.credentials_file):
                logger.debug(
                    "No credentials file exists, returning empty provider list"
                )
                return []

            data = self.vfs.read_json(self.credentials_file)
            if not data:
                logger.debug("Credentials file is empty, returning empty provider list")
                return []

            providers = list(data.keys())
            logger.debug(f"Found stored credentials for providers: {providers}")
            return providers

        except Exception as e:
            logger.error(f"Error listing providers: {e}")
            return []

    def get_all_countries(self, provider: str) -> List[str]:
        """
        Get all countries that have credentials for a provider

        Args:
            provider: Provider name

        Returns:
            List of country codes
        """
        try:
            if not self.vfs.exists(self.credentials_file):
                return []

            data = self.vfs.read_json(self.credentials_file)
            if not data or provider not in data:
                return []

            provider_data = data[provider]

            # Check if this is a nested (country-aware) structure
            if isinstance(provider_data, dict):
                # Check if any keys look like country codes (2-3 char strings)
                # and their values are dicts (credential data)
                countries = []
                for key, value in provider_data.items():
                    if isinstance(value, dict) and len(key) <= 3 and "type" in value:
                        countries.append(key)
                return countries

            return []

        except Exception as e:
            logger.error(f"Error getting countries for {provider}: {e}")
            return []

    def has_credentials(self, provider: str, country: Optional[str] = None) -> bool:
        """
        Check if credentials exist for a provider and optional country

        Args:
            provider: Provider name
            country: Optional country code

        Returns:
            True if credentials exist, False otherwise
        """
        credentials = self.load_credentials(provider, country)
        return credentials is not None and credentials.validate()

    @staticmethod
    def _encode_password(password: str) -> str:
        """No encoding - store as plaintext (TEMPORARY INSECURE SOLUTION)."""
        logger.warning(
            "Storing password in plaintext - this is insecure and should be replaced with proper encryption"
        )
        return password

    @staticmethod
    def _decode_password(encoded_password: str) -> str:
        """No decoding needed - passwords are stored in plaintext."""
        return encoded_password

    def export_config(
        self, provider: Optional[str] = None, country: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Export credentials to a portable format

        Args:
            provider: Optional provider name to export (if None, exports all)
            country: Optional country code (only used if provider is specified)

        Returns:
            Dictionary with credentials data
        """
        export_data = {
            "version": "1.1",  # Bumped for country support
            "exported_at": time.time(),
            "credentials": {},
        }

        if provider:
            # Export specific provider
            if country:
                # Export specific country
                credentials = self.load_credentials(provider, country)
                if credentials:
                    export_data["credentials"][provider] = {
                        country: self._credential_to_dict(credentials)
                    }
            else:
                # Export all countries for provider or non-country data
                countries = self.get_all_countries(provider)
                if countries:
                    # Provider has country-specific credentials
                    provider_data = {}
                    for ctry in countries:
                        credentials = self.load_credentials(provider, ctry)
                        if credentials:
                            provider_data[ctry] = self._credential_to_dict(credentials)
                    if provider_data:
                        export_data["credentials"][provider] = provider_data
                else:
                    # Non-country provider
                    credentials = self.load_credentials(provider)
                    if credentials:
                        export_data["credentials"][provider] = self._credential_to_dict(
                            credentials
                        )
        else:
            # Export all providers
            for prov in self.list_providers():
                countries = self.get_all_countries(prov)
                if countries:
                    # Provider has country-specific credentials
                    provider_data = {}
                    for ctry in countries:
                        credentials = self.load_credentials(prov, ctry)
                        if credentials:
                            provider_data[ctry] = self._credential_to_dict(credentials)
                    if provider_data:
                        export_data["credentials"][prov] = provider_data
                else:
                    # Non-country provider
                    credentials = self.load_credentials(prov)
                    if credentials:
                        export_data["credentials"][prov] = self._credential_to_dict(
                            credentials
                        )

        return export_data

    @staticmethod
    def _credential_to_dict(credentials: BaseCredentials) -> Dict[str, Any]:
        """Convert credentials object to dictionary for export"""
        if isinstance(credentials, UserPasswordCredentials):
            return {
                "type": "user_password",
                "username": credentials.username,
                "password": credentials.password,
                "client_id": credentials.client_id,
            }
        elif isinstance(credentials, ClientCredentials):
            return {
                "type": "client_credentials",
                "client_id": credentials.client_id,
                "client_secret": credentials.client_secret,
            }
        else:
            return {}

    def import_config(self, config_data: Dict[str, Any]) -> Dict[str, bool]:
        """
        Import credentials from exported configuration

        Args:
            config_data: Configuration data from export_config()

        Returns:
            Dictionary mapping provider names (or provider_country) to import success status
        """
        results = {}

        # Validate config data
        if not isinstance(config_data, dict) or "credentials" not in config_data:
            logger.error("Invalid credential config data format")
            return results

        credentials_data = config_data.get("credentials", {})

        for provider, provider_data in credentials_data.items():
            try:
                # Check if this is country-aware structure
                if isinstance(provider_data, dict) and not provider_data.get("type"):
                    # Nested structure with countries
                    for country, cred_data in provider_data.items():
                        if not isinstance(cred_data, dict):
                            continue

                        credentials = self._dict_to_credential(cred_data)
                        if credentials:
                            success = self.save_credentials(
                                provider, credentials, country
                            )
                            results[f"{provider}_{country}"] = success

                            if success:
                                logger.info(
                                    f"Successfully imported credentials for {provider} ({country})"
                                )
                            else:
                                logger.error(
                                    f"Failed to import credentials for {provider} ({country})"
                                )
                else:
                    # Flat structure (no country)
                    credentials = self._dict_to_credential(provider_data)
                    if credentials:
                        success = self.save_credentials(provider, credentials)
                        results[provider] = success

                        if success:
                            logger.info(
                                f"Successfully imported credentials for {provider}"
                            )
                        else:
                            logger.error(f"Failed to import credentials for {provider}")

            except Exception as e:
                logger.error(f"Error importing credentials for {provider}: {e}")
                results[provider] = False

        return results

    @staticmethod
    def _dict_to_credential(cred_data: Dict[str, Any]) -> Optional[BaseCredentials]:
        """Convert dictionary to credentials object"""
        try:
            if cred_data.get("type") == "user_password":
                return UserPasswordCredentials(
                    username=cred_data.get("username", ""),
                    password=cred_data.get("password", ""),
                    client_id=cred_data.get("client_id"),
                )
            elif cred_data.get("type") == "client_credentials":
                return ClientCredentials(
                    client_id=cred_data.get("client_id", ""),
                    client_secret=cred_data.get("client_secret", ""),
                )
            else:
                logger.error(f"Unknown credential type: {cred_data.get('type')}")
                return None
        except Exception as e:
            logger.error(f"Error creating credential from dict: {e}")
            return None

    def debug_credentials_file(self) -> None:
        """Debug method to log the current state of the credentials file"""
        try:
            logger.info(f"=== CREDENTIALS FILE DEBUG INFO ===")

            credentials_file_path = self.vfs.join_path(self.credentials_file)
            logger.info(f"Credentials file path: {credentials_file_path}")
            logger.info(
                f"Credentials file exists: {self.vfs.exists(self.credentials_file)}"
            )

            if self.vfs.exists(self.credentials_file):
                file_size = self.vfs.get_size(self.credentials_file)
                logger.info(f"Credentials file size: {file_size} bytes")

                if file_size and file_size > 0:
                    data = self.vfs.read_json(self.credentials_file)
                    if data:
                        logger.info(
                            f"Credentials file contains {len(data)} providers: {list(data.keys())}"
                        )

                        for provider, provider_data in data.items():
                            if isinstance(provider_data, dict):
                                # Check if nested (has countries)
                                has_countries = any(
                                    isinstance(v, dict) and len(k) <= 3 and "type" in v
                                    for k, v in provider_data.items()
                                )

                                if has_countries:
                                    logger.info(f"  {provider} (country-aware):")
                                    for country, cred_data in provider_data.items():
                                        if (
                                            isinstance(cred_data, dict)
                                            and "type" in cred_data
                                        ):
                                            cred_type = cred_data.get("type")
                                            username = cred_data.get("username", "N/A")
                                            logger.info(
                                                f"    {country}: type={cred_type}, username={username}"
                                            )
                                else:
                                    # Flat structure (no country)
                                    cred_type = provider_data.get("type", "unknown")
                                    username = provider_data.get("username", "N/A")
                                    logger.info(
                                        f"  {provider} (no country): type={cred_type}, username={username}"
                                    )
                    else:
                        logger.error(
                            "Credentials file contains invalid JSON or is empty"
                        )
                else:
                    logger.info("Credentials file is empty")
            else:
                logger.info("Credentials file does not exist yet")

            logger.info(f"=== END CREDENTIALS FILE DEBUG ===")

        except Exception as e:
            logger.error(f"Error during credentials file debug: {e}")
