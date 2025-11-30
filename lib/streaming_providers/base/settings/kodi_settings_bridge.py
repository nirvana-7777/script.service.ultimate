# streaming_providers/base/settings/kodi_settings_bridge.py
from typing import Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ElementTree

from ..auth.credentials import BaseCredentials, UserPasswordCredentials, ClientCredentials
from ..models.proxy_models import ProxyConfig
from ..utils.logger import logger

try:
    import xbmcaddon

    KODI_AVAILABLE = True
except ImportError:
    KODI_AVAILABLE = False


class KodiSettingsBridge:
    """Bridge between Kodi addon settings and internal configuration system"""

    # Markers that identify credential settings
    CREDENTIAL_MARKERS = {'_username', '_password', '_client_id', '_client_secret'}

    def __init__(self, addon_id: Optional[str] = None, config_dir: Optional[str] = None):
        """Initialize Kodi settings bridge"""
        self.addon = None
        self.addon_id = addon_id

        # Initialize VFS with config directory support
        from ..utils.vfs import VFS
        self.vfs = VFS(config_dir=config_dir)

        if KODI_AVAILABLE:
            try:
                if addon_id:
                    self.addon = xbmcaddon.Addon(addon_id)
                else:
                    self.addon = xbmcaddon.Addon()
                self.addon_id = self.addon.getAddonInfo('id')
                logger.info(f"Kodi settings bridge initialized for addon: {self.addon_id}")
            except Exception as e:
                logger.error(f"Failed to initialize Kodi addon: {e}")
                self.addon = None

    def is_kodi_environment(self) -> bool:
        """Check if currently running in Kodi environment"""
        return KODI_AVAILABLE and self.addon is not None

    def get_addon_info(self) -> Dict[str, str]:
        """Get information about current Kodi addon (ID, version, etc.)"""
        if not self.is_kodi_environment():
            return {"error": "Not in Kodi environment"}

        return {
            'id': self.addon.getAddonInfo('id'),
            'name': self.addon.getAddonInfo('name'),
            'version': self.addon.getAddonInfo('version'),
            'author': self.addon.getAddonInfo('author'),
            'path': self.addon.getAddonInfo('path')
        }

    # ============= Dynamic Discovery =============

    def _get_all_setting_ids(self) -> List[str]:
        """
        Get all setting IDs from settings.xml by parsing the file.

        Returns:
            List of all setting IDs found in settings.xml
        """
        if not self.is_kodi_environment():
            return []

        try:
            # Read settings.xml from VFS base path (addon profile directory)
            xml_content = self.vfs.read_text('settings.xml')
            if not xml_content:
                logger.warning("settings.xml not found or empty")
                return []
            if not xml_content:
                logger.warning("settings.xml is empty")
                return []

            root = ElementTree.fromstring(xml_content)

            # Extract all setting IDs
            setting_ids = []
            for setting in root.findall('.//setting'):
                setting_id = setting.get('id')
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
        prefix = setting_id[:-len(marker)]

        # Split by underscore
        parts = prefix.split('_')

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
        Scan all Kodi settings and discover providers with their countries dynamically.

        Returns:
            Dict mapping provider names to list of countries.
            Empty list means provider without country.
            Example: {'joyn': ['de', 'at'], 'rtlplus': ['de'], 'zattoo': []}
        """
        if not self.is_kodi_environment():
            return {}

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

    def get_all_countries_for_provider(self, provider: str, available_countries: List[str]) -> List[str]:
        """
        Check which countries from a given list have credentials configured for a provider.

        Args:
            provider: Provider name
            available_countries: List of country codes to check

        Returns:
            List of country codes that have credentials in Kodi
        """
        discovered_countries = self.detect_countries_for_provider(provider)
        return [c for c in available_countries if c in discovered_countries]

    # ============= Credential Operations =============

    def read_credentials_from_kodi(self, provider: str, country: Optional[str] = None) -> Optional[BaseCredentials]:
        """
        Read authentication credentials from Kodi settings for a provider.
        Uses convention: {provider}_{country}_username, {provider}_{country}_password, etc.
        If country is None, tries without country suffix for backward compatibility.
        """
        if not self.is_kodi_environment():
            return None

        country_suffix = f"_{country}" if country else ""

        try:
            # Try convention-based setting names
            username = self.addon.getSetting(f'{provider}{country_suffix}_username')
            password = self.addon.getSetting(f'{provider}{country_suffix}_password')
            client_id = self.addon.getSetting(f'{provider}{country_suffix}_client_id')
            client_secret = self.addon.getSetting(f'{provider}{country_suffix}_client_secret')

            logger.debug(f"Kodi settings for {provider}{country_suffix}:")
            logger.debug(f"  username: '{username}' (empty={not username})")
            logger.debug(f"  password: {'***' if password else '(empty)'}")
            logger.debug(f"  client_id: '{client_id}' (empty={not client_id})")
            logger.debug(f"  client_secret: {'***' if client_secret else '(empty)'}")

            # Determine credential type based on available values
            if username and password:
                logger.info(f"Found username/password credentials for {provider}{country_suffix} in Kodi")
                return UserPasswordCredentials(
                    username=username.strip(),
                    password=password.strip(),
                    client_id=client_id.strip() if client_id else None
                )
            elif client_id and client_secret:
                logger.info(f"Found client credentials for {provider}{country_suffix} in Kodi")
                return ClientCredentials(
                    client_id=client_id.strip(),
                    client_secret=client_secret.strip()
                )

            logger.debug(f"No valid credentials found in Kodi for {provider}{country_suffix}")
            return None

        except Exception as e:
            logger.error(f"Error reading credentials from Kodi for {provider}: {e}")
            return None

    def write_credentials_to_kodi(self, provider: str, credentials: BaseCredentials,
                                  country: Optional[str] = None) -> bool:
        """Write authentication credentials to Kodi settings"""
        if not self.is_kodi_environment():
            return False

        country_suffix = f"_{country}" if country else ""

        try:
            if isinstance(credentials, UserPasswordCredentials):
                self.addon.setSetting(f'{provider}{country_suffix}_username', credentials.username)
                self.addon.setSetting(f'{provider}{country_suffix}_password', credentials.password)
                if credentials.client_id:
                    self.addon.setSetting(f'{provider}{country_suffix}_client_id', credentials.client_id)
                logger.info(f"Wrote username/password credentials to Kodi for {provider}{country_suffix}")
                return True

            elif isinstance(credentials, ClientCredentials):
                self.addon.setSetting(f'{provider}{country_suffix}_client_id', credentials.client_id)
                self.addon.setSetting(f'{provider}{country_suffix}_client_secret', credentials.client_secret)
                logger.info(f"Wrote client credentials to Kodi for {provider}{country_suffix}")
                return True

            return False

        except Exception as e:
            logger.error(f"Error writing credentials to Kodi for {provider}: {e}")
            return False

    def sync_credentials_to_file(self, provider: str, credential_manager,
                                 country: Optional[str] = None) -> bool:
        """Sync provider credentials from Kodi settings to credential file"""
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
            logger.info(f"Synced credentials from Kodi to file for {provider}")
        return success

    # ============= Proxy Operations =============

    def read_proxy_config_from_kodi(self, provider: str, country: Optional[str] = None) -> Optional[ProxyConfig]:
        """
        Read proxy configuration from Kodi settings for a provider.
        Uses convention: {provider}_{country}_proxy_enabled, {provider}_{country}_proxy_host, etc.
        """
        if not self.is_kodi_environment():
            return None

        country_suffix = f"_{country}" if country else ""

        try:
            # Check if proxy is enabled
            proxy_enabled = self.addon.getSetting(f'{provider}{country_suffix}_proxy_enabled')
            logger.debug(f"Proxy enabled setting for {provider}{country_suffix}: '{proxy_enabled}'")

            if not proxy_enabled or proxy_enabled.lower() not in ['true', '1', 'yes']:
                logger.debug(f"Proxy not enabled for {provider}{country_suffix}")
                return None

            proxy_host = self.addon.getSetting(f'{provider}{country_suffix}_proxy_host')
            proxy_port_str = self.addon.getSetting(f'{provider}{country_suffix}_proxy_port')

            logger.debug(f"Proxy settings for {provider}{country_suffix}:")
            logger.debug(f"  host: '{proxy_host}'")
            logger.debug(f"  port: '{proxy_port_str}'")

            if not proxy_host or not proxy_port_str:
                logger.debug(f"Proxy host or port missing for {provider}{country_suffix}")
                return None

            try:
                proxy_port = int(proxy_port_str)
            except ValueError:
                logger.error(f"Invalid proxy port '{proxy_port_str}' for {provider}{country_suffix}")
                return None

            # Create proxy config
            proxy_config = ProxyConfig(host=proxy_host.strip(), port=proxy_port)

            logger.info(f"Found proxy config for {provider}{country_suffix} in Kodi: {proxy_host}:{proxy_port}")
            return proxy_config

        except Exception as e:
            logger.error(f"Error reading proxy config from Kodi for {provider}: {e}")
            return None

    def write_proxy_config_to_kodi(self, provider: str, proxy_config: ProxyConfig,
                                   country: Optional[str] = None) -> bool:
        """Write proxy configuration to Kodi settings"""
        if not self.is_kodi_environment():
            return False

        country_suffix = f"_{country}" if country else ""

        try:
            self.addon.setSetting(f'{provider}{country_suffix}_proxy_enabled', 'true')
            self.addon.setSetting(f'{provider}{country_suffix}_proxy_host', proxy_config.host)
            self.addon.setSetting(f'{provider}{country_suffix}_proxy_port', str(proxy_config.port))

            logger.info(f"Wrote proxy config to Kodi for {provider}{country_suffix}")
            return True

        except Exception as e:
            logger.error(f"Error writing proxy config to Kodi for {provider}: {e}")
            return False

    def sync_proxy_config_to_file(self, provider: str, proxy_manager,
                                  country: Optional[str] = None) -> bool:
        """Sync provider proxy config from Kodi settings to proxy config file"""
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
            logger.info(f"Synced proxy config from Kodi to file for {provider}")
        return success

    def read_ip_address_from_kodi(self, provider: str, country: Optional[str] = None) -> Optional[str]:
        """
        Read IP address from Kodi settings for a provider.
        Uses convention: {provider}_{country}_ipaddress or {provider}_ipaddress

        Args:
            provider: Provider name (e.g., 'hrti')
            country: Optional country code

        Returns:
            Configured IP address or None if not set
        """
        if not self.is_kodi_environment():
            return None

        country_suffix = f"_{country}" if country else ""

        try:
            ip_address = self.addon.getSetting(f'{provider}{country_suffix}_ipaddress')

            logger.debug(f"IP address setting for {provider}{country_suffix}: '{ip_address}'")

            if ip_address and ip_address.strip():
                logger.info(f"Found configured IP address for {provider}{country_suffix}: {ip_address}")
                return ip_address.strip()

            logger.debug(f"No IP address configured for {provider}{country_suffix}")
            return None

        except Exception as e:
            logger.error(f"Error reading IP address from Kodi for {provider}: {e}")
            return None

    # ============= Comparison Helpers =============

    @staticmethod
    def _credentials_equal(cred1: Optional[BaseCredentials], cred2: Optional[BaseCredentials]) -> bool:
        """Compare two credentials for equality"""
        if cred1 is None and cred2 is None:
            return True
        if cred1 is None or cred2 is None:
            return False
        if type(cred1) != type(cred2):
            return False

        if isinstance(cred1, UserPasswordCredentials) and isinstance(cred2, UserPasswordCredentials):
            return (cred1.username == cred2.username and
                    cred1.password == cred2.password and
                    cred1.client_id == cred2.client_id)
        elif isinstance(cred1, ClientCredentials) and isinstance(cred2, ClientCredentials):
            return (cred1.client_id == cred2.client_id and
                    cred1.client_secret == cred2.client_secret)

        return False

    @staticmethod
    def _proxy_configs_equal(proxy1: Optional[ProxyConfig], proxy2: Optional[ProxyConfig]) -> bool:
        """Compare two proxy configurations for equality"""
        if proxy1 is None and proxy2 is None:
            return True
        if proxy1 is None or proxy2 is None:
            return False

        # Compare basic properties
        if (proxy1.host != proxy2.host or
                proxy1.port != proxy2.port or
                proxy1.proxy_type != proxy2.proxy_type):
            return False

        # Compare authentication
        if (proxy1.auth is None) != (proxy2.auth is None):
            return False
        if proxy1.auth and proxy2.auth:
            if (proxy1.auth.username != proxy2.auth.username or
                    proxy1.auth.password != proxy2.auth.password):
                return False

        # Compare scope
        if (proxy1.scope.api_calls != proxy2.scope.api_calls or
                proxy1.scope.authentication != proxy2.scope.authentication or
                proxy1.scope.manifests != proxy2.scope.manifests or
                proxy1.scope.license != proxy2.scope.license):
            return False

        return True