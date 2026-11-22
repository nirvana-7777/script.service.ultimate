# streaming_providers/base/settings/kodi_settings_bridge.py
import json
import xml.etree.ElementTree as ElementTree
from typing import Any, Dict, List, Optional, Set, Tuple

from ..auth.credentials import BaseCredentials, ClientCredentials, UserPasswordCredentials
from ..models.proxy_models import ProxyConfig
from ..utils.environment import get_environment_manager, get_vfs_instance, is_kodi_environment
from ..utils.logger import logger


class KodiSettingsBridge:
    """Bridge between Kodi addon settings and internal configuration system"""

    # Markers that identify credential settings
    CREDENTIAL_MARKERS = {"_username", "_password", "_client_id", "_client_secret"}

    def __init__(self, addon_id: Optional[str] = None, config_dir: Optional[str] = None):
        """Initialize Kodi settings bridge"""
        self.addon = None
        self.addon_id = addon_id
        self._env_manager = get_environment_manager()

        # Initialize VFS with config directory support
        self.vfs = get_vfs_instance(config_dir=config_dir)

        # Settings storage for standalone mode
        self._standalone_settings: Dict[str, str] = {}
        self._settings_file = "standalone_settings.json"
        self._load_standalone_settings()

        if is_kodi_environment():
            try:
                import xbmcaddon

                if addon_id:
                    self.addon = xbmcaddon.Addon(addon_id)
                else:
                    self.addon = xbmcaddon.Addon()
                self.addon_id = self.addon.getAddonInfo("id")
                logger.info(f"Kodi settings bridge initialized for addon: {self.addon_id}")
            except Exception as e:
                logger.error(f"Failed to initialize Kodi addon: {e}")
                self.addon = None

    def is_kodi_environment(self) -> bool:
        """Check if currently running in Kodi environment"""
        return is_kodi_environment() and self.addon is not None

    def _load_standalone_settings(self) -> None:
        """Load settings from file in standalone mode"""
        if not is_kodi_environment() and self.vfs.exists(self._settings_file):
            try:
                content = self.vfs.read_text(self._settings_file)
                if content:
                    self._standalone_settings = json.loads(content)
                    logger.debug(f"Loaded {len(self._standalone_settings)} standalone settings")
            except Exception as e:
                logger.error(f"Error loading standalone settings: {e}")

    def _save_standalone_settings(self) -> None:
        """Save settings to file in standalone mode"""
        if not is_kodi_environment():
            try:
                self.vfs.write_json(self._settings_file, self._standalone_settings)
                logger.debug(f"Saved {len(self._standalone_settings)} standalone settings")
            except Exception as e:
                logger.error(f"Error saving standalone settings: {e}")

    def get_setting(self, setting_id: str, default: str = "") -> str:
        """Get setting value, works in both Kodi and standalone mode"""
        if self.is_kodi_environment():
            try:
                return self.addon.getSetting(setting_id) or default
            except Exception as e:
                logger.error(f"Error getting setting {setting_id}: {e}")
                return default
        else:
            # Standalone mode: use local storage
            return self._standalone_settings.get(setting_id, default)

    def set_setting(self, setting_id: str, value: str) -> bool:
        """Set setting value, works in both Kodi and standalone mode"""
        if self.is_kodi_environment():
            try:
                self.addon.setSetting(setting_id, value)
                logger.debug(f"Set Kodi setting {setting_id}")
                return True
            except Exception as e:
                logger.error(f"Error setting {setting_id}: {e}")
                return False
        else:
            # Standalone mode: update local storage
            self._standalone_settings[setting_id] = value
            self._save_standalone_settings()
            logger.debug(f"Set standalone setting {setting_id}")
            return True

    def get_addon_info(self) -> Dict[str, str]:
        """Get information about current Kodi addon or environment"""
        if not self.is_kodi_environment():
            # Return environment info in standalone mode
            return {
                "environment": "standalone",
                "id": self._env_manager.get_config("addon_id", "standalone"),
                "name": self._env_manager.get_config("addon_name", "Ultimate Backend"),
                "version": self._env_manager.get_config("addon_version", "1.0.0"),
                "config_dir": self.vfs.base_path,
                "profile_path": self._env_manager.get_config("profile_path", ""),
            }

        return {
            "environment": "kodi",
            "id": self.addon.getAddonInfo("id"),
            "name": self.addon.getAddonInfo("name"),
            "version": self.addon.getAddonInfo("version"),
            "author": self.addon.getAddonInfo("author"),
            "path": self.addon.getAddonInfo("path"),
        }

    # ============= Dynamic Discovery =============

    def _get_all_setting_ids(self) -> List[str]:
        """
        Get all setting IDs from settings.xml by parsing the file.

        Returns:
            List of all setting IDs found in settings.xml
        """
        if not self.is_kodi_environment():
            # In standalone mode, return keys from standalone settings
            return list(self._standalone_settings.keys())

        try:
            # Read settings.xml from VFS base path (addon profile directory)
            xml_content = self.vfs.read_text("settings.xml")
            if not xml_content:
                logger.warning("settings.xml not found or empty")
                return []

            root = ElementTree.fromstring(xml_content)

            # Extract all setting IDs
            setting_ids = []
            for setting in root.findall(".//setting"):
                setting_id = setting.get("id")
                if setting_id:
                    setting_ids.append(setting_id)

            logger.info(f"Found {len(setting_ids)} settings in settings.xml")
            logger.debug(f"Setting IDs: {setting_ids}")

            return setting_ids

        except Exception as e:
            logger.error(f"Error reading settings.xml: {e}")
            return []

    def _parse_provider_country(self, setting_id: str) -> Optional[Tuple[str, Optional[str]]]:
        """
        Parse a setting ID to extract provider and optional country.

        Pattern:
        - provider_marker → (provider, None)
        - provider_country_marker → (provider, country)
        - anything else → None

        Args:
            setting_id: Setting ID like "joyn_username" or "joyn_de_username"

        Returns:
            Tuple of (provider, country) or None if pattern doesn't match
        """
        # Check if ends with a credential marker
        marker = None
        for m in self.CREDENTIAL_MARKERS:
            if setting_id.endswith(m):
                marker = m
                break

        if not marker:
            return None

        # Remove the marker
        prefix = setting_id[: -len(marker)]

        # Split by underscore
        parts = prefix.split("_")

        if len(parts) == 1:
            # provider only
            return parts[0], None
        elif len(parts) == 2:
            # provider_country
            return parts[0], parts[1]
        else:
            # Too many parts, doesn't match our pattern
            return None

    def discover_all_providers(self) -> Dict[str, List[str]]:
        """
        Scan all settings and discover providers with their countries dynamically.

        Works in both Kodi and standalone mode.

        Returns:
            Dict mapping provider names to list of countries.
            Empty list means provider without country.
            Example: {'joyn': ['de', 'at'], 'rtlplus': ['de'], 'zattoo': []}
        """
        discovered: Dict[str, Set[Optional[str]]] = {}

        # Get all setting IDs
        setting_ids = self._get_all_setting_ids()

        for setting_id in setting_ids:
            result = self._parse_provider_country(setting_id)
            if result:
                provider, country = result
                if provider not in discovered:
                    discovered[provider] = set()
                discovered[provider].add(country)

        # Convert sets to lists, with None values converted to empty list
        result = {}
        for provider, countries in discovered.items():
            country_list = []
            for country in countries:
                if country is None:
                    # Provider without country - represent as empty list for that provider
                    if not country_list:  # Only add if we haven't already
                        result[provider] = []
                else:
                    country_list.append(country)

            if country_list:
                result[provider] = sorted(country_list)
            elif provider not in result:
                result[provider] = []

        logger.info(f"Discovered providers: {result}")
        return result

    def detect_all_providers_from_kodi(self) -> Dict[str, List[str]]:
        """
        Alias for discover_all_providers() for backward compatibility.
        """
        return self.discover_all_providers()

    def detect_countries_for_provider(self, provider: str) -> List[str]:
        """
        Discover which countries are configured for a specific provider.

        Args:
            provider: Provider name (e.g., 'joyn')

        Returns:
            List of detected country codes (e.g., ['de', 'at'])
        """
        all_providers = self.discover_all_providers()
        countries = all_providers.get(provider, [])

        # Filter out empty list (which means provider without country)
        if not countries:
            return []

        return countries

    def get_all_countries_for_provider(
        self, provider: str, available_countries: List[str]
    ) -> List[str]:
        """
        Check which countries from a given list have credentials configured for a provider.

        Args:
            provider: Provider name
            available_countries: List of country codes to check

        Returns:
            List of country codes that have credentials
        """
        discovered_countries = self.detect_countries_for_provider(provider)
        return [c for c in available_countries if c in discovered_countries]

    # ============= Credential Operations =============

    def read_credentials_from_kodi(
        self, provider: str, country: Optional[str] = None
    ) -> Optional[BaseCredentials]:
        """
        Read authentication credentials from settings for a provider.
        Uses convention: {provider}_{country}_username, {provider}_{country}_password, etc.
        If country is None, tries without country suffix for backward compatibility.
        Works in both Kodi and standalone mode.
        """
        country_suffix = f"_{country}" if country else ""

        try:
            # Use unified get_setting method
            username = self.get_setting(f"{provider}{country_suffix}_username")
            password = self.get_setting(f"{provider}{country_suffix}_password")
            client_id = self.get_setting(f"{provider}{country_suffix}_client_id")
            client_secret = self.get_setting(f"{provider}{country_suffix}_client_secret")

            logger.debug(f"Settings for {provider}{country_suffix}:")
            logger.debug(f"  username: '{username}' (empty={not username})")
            logger.debug(f"  password: {'***' if password else '(empty)'}")
            logger.debug(f"  client_id: '{client_id}' (empty={not client_id})")
            logger.debug(f"  client_secret: {'***' if client_secret else '(empty)'}")

            # Determine credential type based on available values
            if username and password:
                logger.info(f"Found username/password credentials for {provider}{country_suffix}")
                return UserPasswordCredentials(
                    username=username.strip(),
                    password=password.strip(),
                    client_id=client_id.strip() if client_id else None,
                )
            elif client_id and client_secret:
                logger.info(f"Found client credentials for {provider}{country_suffix}")
                return ClientCredentials(
                    client_id=client_id.strip(), client_secret=client_secret.strip()
                )

            logger.debug(f"No valid credentials found for {provider}{country_suffix}")
            return None

        except Exception as e:
            logger.error(f"Error reading credentials for {provider}: {e}")
            return None

    def write_credentials_to_kodi(
        self, provider: str, credentials: BaseCredentials, country: Optional[str] = None
    ) -> bool:
        """Write authentication credentials to settings"""
        country_suffix = f"_{country}" if country else ""

        try:
            if isinstance(credentials, UserPasswordCredentials):
                self.set_setting(f"{provider}{country_suffix}_username", credentials.username)
                self.set_setting(f"{provider}{country_suffix}_password", credentials.password)
                if credentials.client_id:
                    self.set_setting(f"{provider}{country_suffix}_client_id", credentials.client_id)
                logger.info(f"Wrote username/password credentials for {provider}{country_suffix}")
                return True

            elif isinstance(credentials, ClientCredentials):
                self.set_setting(f"{provider}{country_suffix}_client_id", credentials.client_id)
                self.set_setting(
                    f"{provider}{country_suffix}_client_secret",
                    credentials.client_secret,
                )
                logger.info(f"Wrote client credentials for {provider}{country_suffix}")
                return True

            return False

        except Exception as e:
            logger.error(f"Error writing credentials for {provider}: {e}")
            return False

    def sync_credentials_to_file(
        self, provider: str, credential_manager, country: Optional[str] = None
    ) -> bool:
        """Sync provider credentials from settings to credential file"""
        credentials = self.read_credentials_from_kodi(provider, country)
        if not credentials:
            logger.debug(f"No credentials to sync for {provider}")
            return False

        # Check if credentials are different from file
        file_credentials = credential_manager.load_credentials(provider, country)
        if self._credentials_equal(credentials, file_credentials):
            logger.debug(f"Credentials already in sync for {provider}")
            return True  # Already in sync

        success = credential_manager.save_credentials(provider, credentials, country)
        if success:
            logger.info(f"Synced credentials from settings to file for {provider}")
        return success

    # ============= Proxy Operations =============

    def read_proxy_config_from_kodi(
        self, provider: str, country: Optional[str] = None
    ) -> Optional[ProxyConfig]:
        """
        Read proxy configuration from settings for a provider.
        Uses convention: {provider}_{country}_proxy_enabled, {provider}_{country}_proxy_host, etc.
        """
        country_suffix = f"_{country}" if country else ""

        try:
            # Check if proxy is enabled
            proxy_enabled = self.get_setting(f"{provider}{country_suffix}_proxy_enabled")
            logger.debug(f"Proxy enabled setting for {provider}{country_suffix}: '{proxy_enabled}'")

            if not proxy_enabled or proxy_enabled.lower() not in ["true", "1", "yes"]:
                logger.debug(f"Proxy not enabled for {provider}{country_suffix}")
                return None

            proxy_host = self.get_setting(f"{provider}{country_suffix}_proxy_host")
            proxy_port_str = self.get_setting(f"{provider}{country_suffix}_proxy_port")

            logger.debug(f"Proxy settings for {provider}{country_suffix}:")
            logger.debug(f"  host: '{proxy_host}'")
            logger.debug(f"  port: '{proxy_port_str}'")

            if not proxy_host or not proxy_port_str:
                logger.debug(f"Proxy host or port missing for {provider}{country_suffix}")
                return None

            try:
                proxy_port = int(proxy_port_str)
            except ValueError:
                logger.error(
                    f"Invalid proxy port '{proxy_port_str}' for {provider}{country_suffix}"
                )
                return None

            # Create proxy config
            proxy_config = ProxyConfig(host=proxy_host.strip(), port=proxy_port)

            logger.info(
                f"Found proxy config for {provider}{country_suffix}: {proxy_host}:{proxy_port}"
            )
            return proxy_config

        except Exception as e:
            logger.error(f"Error reading proxy config for {provider}: {e}")
            return None

    def write_proxy_config_to_kodi(
        self, provider: str, proxy_config: ProxyConfig, country: Optional[str] = None
    ) -> bool:
        """Write proxy configuration to settings"""
        country_suffix = f"_{country}" if country else ""

        try:
            self.set_setting(f"{provider}{country_suffix}_proxy_enabled", "true")
            self.set_setting(f"{provider}{country_suffix}_proxy_host", proxy_config.host)
            self.set_setting(f"{provider}{country_suffix}_proxy_port", str(proxy_config.port))

            logger.info(f"Wrote proxy config for {provider}{country_suffix}")
            return True

        except Exception as e:
            logger.error(f"Error writing proxy config for {provider}: {e}")
            return False

    def sync_proxy_config_to_file(
        self, provider: str, proxy_manager, country: Optional[str] = None
    ) -> bool:
        """Sync provider proxy config from settings to proxy config file"""
        proxy_config = self.read_proxy_config_from_kodi(provider, country)
        if not proxy_config:
            logger.debug(f"No proxy config to sync for {provider}")
            return False

        # Check if proxy config is different from file
        file_proxy = proxy_manager.get_proxy_config(provider, country)
        if self._proxy_configs_equal(proxy_config, file_proxy):
            logger.debug(f"Proxy config already in sync for {provider}")
            return True  # Already in sync

        success = proxy_manager.set_proxy_config(provider, proxy_config, country)
        if success:
            logger.info(f"Synced proxy config from settings to file for {provider}")
        return success

    def read_ip_address_from_kodi(
        self, provider: str, country: Optional[str] = None
    ) -> Optional[str]:
        """
        Read IP address from settings for a provider.
        Uses convention: {provider}_{country}_ipaddress or {provider}_ipaddress

        Args:
            provider: Provider name (e.g., 'hrti')
            country: Optional country code

        Returns:
            Configured IP address or None if not set
        """
        country_suffix = f"_{country}" if country else ""

        try:
            ip_address = self.get_setting(f"{provider}{country_suffix}_ipaddress")

            logger.debug(f"IP address setting for {provider}{country_suffix}: '{ip_address}'")

            if ip_address and ip_address.strip():
                logger.info(
                    f"Found configured IP address for {provider}{country_suffix}: {ip_address}"
                )
                return ip_address.strip()

            logger.debug(f"No IP address configured for {provider}{country_suffix}")
            return None

        except Exception as e:
            logger.error(f"Error reading IP address for {provider}: {e}")
            return None

    # ============= Comparison Helpers =============

    @staticmethod
    def _credentials_equal(
        cred1: Optional[BaseCredentials], cred2: Optional[BaseCredentials]
    ) -> bool:
        """Compare two credentials for equality"""
        if cred1 is None and cred2 is None:
            return True
        if cred1 is None or cred2 is None:
            return False
        if type(cred1) != type(cred2):
            return False

        if isinstance(cred1, UserPasswordCredentials) and isinstance(
            cred2, UserPasswordCredentials
        ):
            return (
                cred1.username == cred2.username
                and cred1.password == cred2.password
                and cred1.client_id == cred2.client_id
            )
        elif isinstance(cred1, ClientCredentials) and isinstance(cred2, ClientCredentials):
            return cred1.client_id == cred2.client_id and cred1.client_secret == cred2.client_secret

        return False

    @staticmethod
    def _proxy_configs_equal(proxy1: Optional[ProxyConfig], proxy2: Optional[ProxyConfig]) -> bool:
        """Compare two proxy configurations for equality"""
        if proxy1 is None and proxy2 is None:
            return True
        if proxy1 is None or proxy2 is None:
            return False

        # Compare basic properties
        if (
            proxy1.host != proxy2.host
            or proxy1.port != proxy2.port
            or proxy1.proxy_type != proxy2.proxy_type
        ):
            return False

        # Compare authentication
        if (proxy1.auth is None) != (proxy2.auth is None):
            return False
        if proxy1.auth and proxy2.auth:
            if (
                proxy1.auth.username != proxy2.auth.username
                or proxy1.auth.password != proxy2.auth.password
            ):
                return False

        # Compare scope
        if (
            proxy1.scope.api_calls != proxy2.scope.api_calls
            or proxy1.scope.authentication != proxy2.scope.authentication
            or proxy1.scope.manifests != proxy2.scope.manifests
            or proxy1.scope.license != proxy2.scope.license
        ):
            return False

        return True

    def debug_info(self) -> Dict[str, Any]:
        """Get debug information about the settings bridge"""
        info = {
            "environment": "kodi" if self.is_kodi_environment() else "standalone",
            "addon_info": self.get_addon_info(),
            "has_addon": self.addon is not None,
            "standalone_settings_count": len(self._standalone_settings),
            "vfs_base_path": self.vfs.base_path,
        }

        if self.is_kodi_environment():
            info["addon_id"] = self.addon_id
            info["kodi_available"] = True
        else:
            info["kodi_available"] = False

        return info
