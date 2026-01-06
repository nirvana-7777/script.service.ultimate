# streaming_providers/base/network/proxy_manager.py
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models.proxy_models import ProxyConfig, ProxyScope
from ..utils.logger import logger


class ProxyConfigManager:
    """
    Manages proxy configurations with file-based persistence
    Supports per-provider proxy settings with global fallbacks
    Now supports country-specific proxy configurations
    """

    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize proxy configuration manager with VFS support
        """
        # Initialize VFS with config directory support
        from ..utils.vfs import VFS

        self.vfs = VFS(config_dir=config_dir)

        # Keep legacy attributes for backward compatibility but use VFS primarily
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            self.config_dir = Path.home() / ".streaming_providers" / "config"

        self.proxy_config_file = "proxy_config.json"  # Use relative path for VFS

        # Cache for loaded configurations
        self._config_cache: Dict[str, ProxyConfig] = {}
        self._global_config: Optional[ProxyConfig] = None

        # Load existing configurations
        self._load_configurations()

    @staticmethod
    def _get_proxy_path(provider_name: str, country: Optional[str] = None) -> tuple:
        """
        Determine the path to proxy data based on country

        Args:
            provider_name: Provider name
            country: Optional country code (e.g., 'de', 'at', 'ch')

        Returns:
            Tuple of (cache_key, is_nested)
        """
        if country:
            return f"{provider_name}_{country}", True
        else:
            return provider_name, False

    def _load_configurations(self) -> None:
        """Load proxy configurations from file using VFS"""
        try:
            vfs_data = self.vfs.read_json(self.proxy_config_file)

            if vfs_data is None:
                logger.debug(
                    "No proxy configuration file found, starting with empty config"
                )
                return

            # Load global configuration
            if "global" in vfs_data:
                self._global_config = ProxyConfig.from_dict(vfs_data["global"])
                logger.debug("Loaded global proxy configuration")

            # Load provider-specific configurations
            providers = vfs_data.get("providers", {})
            for provider_name, provider_data in providers.items():
                try:
                    # Check if this is a nested (country-aware) structure
                    if isinstance(provider_data, dict) and any(
                        isinstance(v, dict) and len(k) <= 3
                        for k, v in provider_data.items()
                    ):
                        # Country-aware structure
                        for country, config_data in provider_data.items():
                            if isinstance(config_data, dict) and len(country) <= 3:
                                cache_key = f"{provider_name}_{country}"
                                self._config_cache[cache_key] = ProxyConfig.from_dict(
                                    config_data
                                )
                                logger.debug(
                                    f"Loaded proxy config for {provider_name} ({country})"
                                )
                    else:
                        # Flat structure (no country)
                        self._config_cache[provider_name] = ProxyConfig.from_dict(
                            provider_data
                        )
                        logger.debug(
                            f"Loaded proxy configuration for provider: {provider_name}"
                        )
                except Exception as e:
                    logger.error(f"Error loading proxy config for {provider_name}: {e}")

        except Exception as e:
            logger.error(f"Error loading proxy configurations: {e}")

    def _save_configurations(self) -> bool:
        """Save proxy configurations to file using VFS"""
        try:
            data: Dict[str, Any] = {
                "providers": {},
                "metadata": {
                    "version": "1.1",  # Bumped for country support
                    "description": "Streaming provider proxy configurations",
                },
            }

            # Save global configuration
            if self._global_config:
                data["global"] = self._global_config.to_dict()

            # Save provider-specific configurations
            # Group by provider to maintain nested structure
            provider_configs: Dict[str, Dict] = {}

            for cache_key, config in self._config_cache.items():
                if "_" in cache_key and len(cache_key.split("_")[-1]) <= 3:
                    # Country-aware key (e.g., "joyn_de")
                    parts = cache_key.rsplit("_", 1)
                    provider_name = parts[0]
                    country = parts[1]

                    if provider_name not in provider_configs:
                        provider_configs[provider_name] = {}
                    provider_configs[provider_name][country] = config.to_dict()
                else:
                    # Non-country key
                    provider_configs[cache_key] = config.to_dict()

            data["providers"] = provider_configs

            # Save using VFS
            success = self.vfs.write_json(self.proxy_config_file, data)

            if success:
                logger.debug("Saved proxy configurations")
            else:
                logger.error("Failed to save proxy configurations")

            return success

        except Exception as e:
            logger.error(f"Error saving proxy configurations: {e}")
            return False

    def get_proxy_config(
        self, provider_name: str, country: Optional[str] = None
    ) -> Optional[ProxyConfig]:
        """
        Get proxy configuration for a provider and optional country

        Args:
            provider_name: Provider name
            country: Optional country code

        Returns:
            ProxyConfig or None
        """
        cache_key, _ = self._get_proxy_path(provider_name, country)

        # Check provider-specific config first
        if cache_key in self._config_cache:
            config = self._config_cache[cache_key]
            country_str = f" ({country})" if country else ""
            logger.debug(
                f"Using provider-specific proxy for {provider_name}{country_str}: "
                f"{config.proxy_type.value}://{config.host}:{config.port}"
            )
            return config

        # If country specified but not found, try without country
        if country and provider_name in self._config_cache:
            config = self._config_cache[provider_name]
            logger.debug(
                f"Using non-country proxy for {provider_name} ({country}): "
                f"{config.proxy_type.value}://{config.host}:{config.port}"
            )
            return config

        # Fall back to global config
        if self._global_config:
            country_str = f" ({country})" if country else ""
            logger.debug(
                f"Using global proxy for {provider_name}{country_str}: "
                f"{self._global_config.proxy_type.value}://{self._global_config.host}:{self._global_config.port}"
            )
            return self._global_config

        country_str = f" ({country})" if country else ""
        logger.debug(f"No proxy configuration found for {provider_name}{country_str}")
        return None

    def set_proxy_config(
        self,
        provider_name: str,
        proxy_config: ProxyConfig,
        country: Optional[str] = None,
    ) -> bool:
        """
        Set proxy configuration for a provider

        Args:
            provider_name: Name of the provider (use 'global' for global config)
            proxy_config: Proxy configuration to set
            country: Optional country code

        Returns:
            True if successful, False otherwise
        """
        if not proxy_config.validate():
            logger.error(f"Invalid proxy configuration for {provider_name}")
            return False

        try:
            if provider_name == "global":
                self._global_config = proxy_config
                logger.info("Set global proxy configuration")
            else:
                cache_key, _ = self._get_proxy_path(provider_name, country)
                self._config_cache[cache_key] = proxy_config
                country_str = f" ({country})" if country else ""
                logger.info(
                    f"Set proxy configuration for provider: {provider_name}{country_str}"
                )

            return self._save_configurations()

        except Exception as e:
            country_str = f" ({country})" if country else ""
            logger.error(
                f"Error setting proxy configuration for {provider_name}{country_str}: {e}"
            )
            return False

    def remove_proxy_config(
        self, provider_name: str, country: Optional[str] = None
    ) -> bool:
        """
        Remove proxy configuration for a provider

        Args:
            provider_name: Name of the provider (use 'global' for global config)
            country: Optional country code (if None, removes all countries for provider)

        Returns:
            True if successful, False otherwise
        """
        try:
            if provider_name == "global":
                self._global_config = None
                logger.info("Removed global proxy configuration")
            else:
                if country:
                    # Remove specific country
                    cache_key, _ = self._get_proxy_path(provider_name, country)
                    if cache_key in self._config_cache:
                        del self._config_cache[cache_key]
                        logger.info(
                            f"Removed proxy configuration for {provider_name} ({country})"
                        )
                    else:
                        logger.warning(
                            f"No proxy configuration found for {provider_name} ({country})"
                        )
                        return True
                else:
                    # Remove all countries for provider
                    keys_to_remove = [
                        key
                        for key in self._config_cache.keys()
                        if key == provider_name or key.startswith(f"{provider_name}_")
                    ]

                    if keys_to_remove:
                        for key in keys_to_remove:
                            del self._config_cache[key]
                        logger.info(
                            f"Removed all proxy configurations for {provider_name}"
                        )
                    else:
                        logger.warning(
                            f"No proxy configuration found for {provider_name}"
                        )
                        return True

            return self._save_configurations()

        except Exception as e:
            country_str = f" ({country})" if country else ""
            logger.error(
                f"Error removing proxy configuration for {provider_name}{country_str}: {e}"
            )
            return False

    def get_all_countries(self, provider_name: str) -> List[str]:
        """
        Get all countries that have proxy configs for a provider

        Args:
            provider_name: Provider name

        Returns:
            List of country codes
        """
        countries = []
        prefix = f"{provider_name}_"

        for cache_key in self._config_cache.keys():
            if cache_key.startswith(prefix):
                country = cache_key[len(prefix) :]
                if len(country) <= 3:  # Validate it looks like a country code
                    countries.append(country)

        return countries

    def list_proxy_configs(self) -> List[str]:
        """
        Get list of providers with proxy configurations

        Returns:
            List of provider names (including country-specific ones)
        """
        providers = list(self._config_cache.keys())
        if self._global_config:
            providers.append("global")
        return providers

    def test_proxy_config(
        self, provider_name: str, country: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Test proxy configuration for a provider

        Args:
            provider_name: Name of the provider
            country: Optional country code

        Returns:
            Dictionary with test results
        """
        proxy_config = self.get_proxy_config(provider_name, country)
        if not proxy_config:
            return {
                "success": False,
                "error": "No proxy configuration found",
                "provider": provider_name,
                "country": country,
            }

        # Test basic connectivity through proxy
        from .http_manager import HTTPManager, RequestConfig

        config = RequestConfig(proxy_config=proxy_config, provider=provider_name)

        manager = HTTPManager(config)
        result = manager.test_connection()
        result["provider"] = provider_name
        result["country"] = country
        result["proxy_config"] = proxy_config.to_dict()

        manager.close()
        return result

    def get_proxy_info(
        self, provider_name: str, country: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get detailed information about proxy configuration

        Args:
            provider_name: Name of the provider
            country: Optional country code

        Returns:
            Dictionary with proxy information
        """
        proxy_config = self.get_proxy_config(provider_name, country)
        cache_key, _ = self._get_proxy_path(provider_name, country)

        info = {
            "provider": provider_name,
            "country": country,
            "has_proxy": proxy_config is not None,
            "config_source": None,
            "proxy_details": None,
        }

        if proxy_config:
            # Determine config source
            if cache_key in self._config_cache:
                info["config_source"] = (
                    "provider_country_specific" if country else "provider_specific"
                )
            elif country and provider_name in self._config_cache:
                info["config_source"] = "provider_fallback"
            elif self._global_config:
                info["config_source"] = "global"

            # Add proxy details (without sensitive auth info)
            info["proxy_details"] = {
                "host": proxy_config.host,
                "port": proxy_config.port,
                "proxy_type": proxy_config.proxy_type.value,
                "has_auth": proxy_config.auth is not None,
                "scope": proxy_config.scope.__dict__,
                "timeout": proxy_config.timeout,
                "verify_ssl": proxy_config.verify_ssl,
            }

        return info

    def export_config(self, export_path: Optional[str] = None) -> str:
        """
        Export proxy configurations to a file

        Args:
            export_path: Optional path to export to, defaults to backup file

        Returns:
            Path to exported file
        """
        if not export_path:
            export_path = str(
                self.config_dir / f"proxy_config_backup_{int(time.time())}.json"
            )

        try:
            # Create export data with country-aware structure
            providers_export = {}

            for cache_key, config in self._config_cache.items():
                if "_" in cache_key and len(cache_key.split("_")[-1]) <= 3:
                    # Country-aware key
                    parts = cache_key.rsplit("_", 1)
                    provider_name = parts[0]
                    country = parts[1]

                    if provider_name not in providers_export:
                        providers_export[provider_name] = {}
                    providers_export[provider_name][country] = config.to_dict()
                else:
                    # Non-country key
                    providers_export[cache_key] = config.to_dict()

            export_data = {
                "metadata": {
                    "exported_at": time.time(),
                    "version": "1.1",
                    "source": "streaming_providers_proxy_manager",
                },
                "global": (
                    self._global_config.to_dict() if self._global_config else None
                ),
                "providers": providers_export,
            }

            with open(export_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Exported proxy configurations to {export_path}")
            return export_path

        except Exception as e:
            logger.error(f"Error exporting proxy configurations: {e}")
            raise

    def import_config(self, import_path: str, merge: bool = True) -> bool:
        """
        Import proxy configurations from a file

        Args:
            import_path: Path to import file
            merge: If True, merge with existing configs; if False, replace all

        Returns:
            True if successful, False otherwise
        """
        try:
            with open(import_path, "r", encoding="utf-8") as f:
                import_data = json.load(f)

            if not merge:
                # Clear existing configurations
                self._config_cache.clear()
                self._global_config = None

            # Import global configuration
            if "global" in import_data and import_data["global"]:
                self._global_config = ProxyConfig.from_dict(import_data["global"])

            # Import provider configurations
            providers = import_data.get("providers", {})
            for provider_name, provider_data in providers.items():
                try:
                    # Check if nested (country-aware)
                    if isinstance(provider_data, dict) and any(
                        isinstance(v, dict) and len(k) <= 3
                        for k, v in provider_data.items()
                    ):
                        # Country-aware structure
                        for country, config_data in provider_data.items():
                            if isinstance(config_data, dict) and len(country) <= 3:
                                cache_key = f"{provider_name}_{country}"
                                self._config_cache[cache_key] = ProxyConfig.from_dict(
                                    config_data
                                )
                    else:
                        # Flat structure
                        self._config_cache[provider_name] = ProxyConfig.from_dict(
                            provider_data
                        )
                except Exception as e:
                    logger.error(f"Error importing config for {provider_name}: {e}")

            # Save the imported configurations
            success = self._save_configurations()
            if success:
                logger.info(
                    f"Successfully imported proxy configurations from {import_path}"
                )
            return success

        except Exception as e:
            logger.error(f"Error importing proxy configurations: {e}")
            return False

    def create_proxy_from_url(
        self,
        provider_name: str,
        proxy_url: str,
        scope: Optional[ProxyScope] = None,
        country: Optional[str] = None,
    ) -> bool:
        """
        Create and set proxy configuration from URL

        Args:
            provider_name: Name of the provider
            proxy_url: Proxy URL (e.g., "http://user:pass@proxy.example.com:8080")
            scope: Optional scope configuration
            country: Optional country code

        Returns:
            True if successful, False otherwise
        """
        try:
            proxy_config = ProxyConfig.from_url(proxy_url, scope)
            return self.set_proxy_config(provider_name, proxy_config, country)
        except Exception as e:
            country_str = f" ({country})" if country else ""
            logger.error(
                f"Error creating proxy config from URL for {provider_name}{country_str}: {e}"
            )
            return False

    def bulk_set_proxy(
        self,
        proxy_config: ProxyConfig,
        provider_names: List[str],
        country: Optional[str] = None,
    ) -> Dict[str, bool]:
        """
        Set the same proxy configuration for multiple providers

        Args:
            proxy_config: Proxy configuration to set
            provider_names: List of provider names
            country: Optional country code to apply to all providers

        Returns:
            Dictionary mapping provider names to success status
        """
        results = {}
        for provider_name in provider_names:
            results[provider_name] = self.set_proxy_config(
                provider_name, proxy_config, country
            )
        return results

    def get_all_proxy_info(self) -> Dict[str, Dict[str, Any]]:
        """
        Get proxy information for all configured providers

        Returns:
            Dictionary mapping provider names to their proxy info
        """
        info = {}

        # Add global config info
        if self._global_config:
            info["global"] = self.get_proxy_info("global")

        # Add provider-specific configs
        for cache_key in self._config_cache.keys():
            if "_" in cache_key and len(cache_key.split("_")[-1]) <= 3:
                # Country-aware key
                parts = cache_key.rsplit("_", 1)
                provider_name = parts[0]
                country = parts[1]
                info[cache_key] = self.get_proxy_info(provider_name, country)
            else:
                # Non-country key
                info[cache_key] = self.get_proxy_info(cache_key)

        return info
