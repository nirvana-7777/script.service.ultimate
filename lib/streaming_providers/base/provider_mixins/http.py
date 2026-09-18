"""Provider HTTP-manager setup mixin: proxy resolution and HTTPManager creation."""

from typing import TYPE_CHECKING, Dict, Optional

from ..models.proxy_models import ProxyConfig
from ..network import HTTPManager, HTTPManagerFactory
from ..utils.logger import logger


class ProviderHttpMixin:
    if TYPE_CHECKING:
        # Provided by StreamingProvider.__init__ once this is composed
        # into the full class — declared here only for type checkers.
        provider_name: str
        country: str
        _http_manager: Optional[HTTPManager]

    @property
    def http_manager(self) -> Optional[HTTPManager]:
        """Return the provider's HTTP manager instance"""
        return self._http_manager

    @http_manager.setter
    def http_manager(self, value: HTTPManager):
        """Set the provider's HTTP manager instance"""
        self._http_manager = value

    def _setup_http_manager(
        self,
        provider_name: str,
        proxy_config: Optional[ProxyConfig] = None,
        proxy_url: Optional[str] = None,
        config_dir: Optional[str] = None,
        country: Optional[str] = None,
        user_agent: Optional[str] = None,
        timeout: Optional[int] = None,
        max_retries: Optional[int] = None,
        **kwargs,
    ) -> HTTPManager:
        """Standard HTTP manager setup for providers with intelligent proxy resolution"""
        if country is None:
            country = self.country

        resolved_proxy = self._resolve_proxy_config(
            proxy_config=proxy_config,
            proxy_url=proxy_url,
            config_dir=config_dir,
            provider_name=provider_name,
            country=country,
        )

        manager_kwargs = {}
        if user_agent:
            manager_kwargs["user_agent"] = user_agent
        if timeout:
            manager_kwargs["timeout"] = timeout
        if max_retries:
            manager_kwargs["max_retries"] = max_retries
        manager_kwargs.update(kwargs)

        http_manager = HTTPManagerFactory.create_for_provider(
            provider_name=provider_name, proxy_config=resolved_proxy, **manager_kwargs
        )

        self._log_http_manager_setup(provider_name, resolved_proxy, manager_kwargs)
        return http_manager

    @staticmethod
    def _resolve_proxy_config(
        proxy_config: Optional[ProxyConfig],
        proxy_url: Optional[str],
        config_dir: Optional[str],
        provider_name: str,
        country: str,
    ) -> Optional[ProxyConfig]:
        """Resolve proxy configuration from multiple sources with priority"""
        if proxy_config is not None:
            logger.debug(f"{provider_name}: Using directly provided proxy configuration")
            return proxy_config

        if proxy_url:
            try:
                logger.debug(f"{provider_name}: Creating proxy config from URL")
                return ProxyConfig.from_url(proxy_url)
            except Exception as e:
                logger.warning(f"{provider_name}: Failed to parse proxy URL '{proxy_url}': {e}")

        try:
            from ..network import ProxyConfigManager

            proxy_mgr = ProxyConfigManager(config_dir)
            managed_proxy = proxy_mgr.get_proxy_config(provider_name, country)

            if managed_proxy:
                logger.debug(f"{provider_name}: Using proxy from ProxyConfigManager")
                return managed_proxy
            else:
                logger.debug(f"{provider_name}: No proxy configuration found in ProxyConfigManager")

        except Exception as e:
            logger.warning(f"{provider_name}: Could not load proxy from ProxyConfigManager: {e}")

        logger.debug(f"{provider_name}: No proxy configuration available")
        return None

    @staticmethod
    def _log_http_manager_setup(
        provider_name: str, proxy_config: Optional[ProxyConfig], manager_kwargs: Dict
    ) -> None:
        """Log HTTP manager setup information"""
        info_parts = [f"HTTP manager initialized for '{provider_name}'"]

        if proxy_config:
            proxy_type = proxy_config.proxy_type.value if proxy_config.proxy_type else "http"
            proxy_host = f"{proxy_config.host}:{proxy_config.port}"
            has_auth = "authenticated" if proxy_config.auth else "no-auth"
            info_parts.append(f"proxy: {proxy_type}://{proxy_host} ({has_auth})")
        else:
            info_parts.append("proxy: none")

        if "user_agent" in manager_kwargs:
            ua_preview = (
                manager_kwargs["user_agent"][:50] + "..."
                if len(manager_kwargs["user_agent"]) > 50
                else manager_kwargs["user_agent"]
            )
            info_parts.append(f"user-agent: {ua_preview}")

        if "timeout" in manager_kwargs:
            info_parts.append(f"timeout: {manager_kwargs['timeout']}s")

        if "max_retries" in manager_kwargs:
            info_parts.append(f"retries: {manager_kwargs['max_retries']}")

        logger.info(f"{provider_name}: {', '.join(info_parts)}")

    def _share_http_manager_with_authenticator(
        self, authenticator, http_manager: Optional[HTTPManager] = None
    ) -> HTTPManager:
        """Share HTTP manager with authenticator for consistency"""
        if http_manager is None:
            http_manager = self.http_manager

        if http_manager and hasattr(authenticator, "http_manager"):
            if authenticator.http_manager is None:
                logger.debug(f"{self.provider_name}: Sharing HTTP manager with authenticator")
                authenticator.http_manager = http_manager
            else:
                logger.debug(f"{self.provider_name}: Using authenticator's existing HTTP manager")
                http_manager = authenticator.http_manager

        return http_manager