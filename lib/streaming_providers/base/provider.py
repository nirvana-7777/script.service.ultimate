# streaming_providers/base/provider.py - Enhanced with Header Abstractions

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Callable
from enum import Enum
import json
from datetime import datetime

from .models.streaming_channel import StreamingChannel
from .models.drm_models import DRMConfig
from .models.proxy_models import ProxyConfig
from .network import HTTPManagerFactory, HTTPManager
from .utils.logger import logger


class AuthType(Enum):
    """Authentication token types"""
    BEARER = "bearer"
    BASIC = "basic"
    CLIENT = "client"
    CUSTOM = "custom"
    NONE = "none"


class StreamingProvider(ABC):
    """
    Abstract base class for streaming providers with centralized HTTP and auth management
    """

    def __init__(self, country: str = 'DE'):
        self.country = country
        self.channels: List[StreamingChannel] = []
        self._http_manager = None
        self._default_user_agent = 'StreamingProvider/1.0'
        self.authenticator = None  # Optional: set by concrete providers

    # ============================================================================
    # HTTP MANAGER SETUP (Already Implemented)
    # ============================================================================

    @property
    def http_manager(self) -> Optional[HTTPManager]:
        """Return the provider's HTTP manager instance"""
        return self._http_manager

    @http_manager.setter
    def http_manager(self, value: HTTPManager):
        """Set the provider's HTTP manager instance"""
        self._http_manager = value

    def _setup_http_manager(self,
                            provider_name: str,
                            proxy_config: Optional[ProxyConfig] = None,
                            proxy_url: Optional[str] = None,
                            config_dir: Optional[str] = None,
                            country: Optional[str] = None,
                            user_agent: Optional[str] = None,
                            timeout: Optional[int] = None,
                            max_retries: Optional[int] = None,
                            **kwargs) -> HTTPManager:
        """Standard HTTP manager setup for providers with intelligent proxy resolution"""
        if country is None:
            country = self.country

        resolved_proxy = self._resolve_proxy_config(
            proxy_config=proxy_config,
            proxy_url=proxy_url,
            config_dir=config_dir,
            provider_name=provider_name,
            country=country
        )

        manager_kwargs = {}
        if user_agent:
            manager_kwargs['user_agent'] = user_agent
        if timeout:
            manager_kwargs['timeout'] = timeout
        if max_retries:
            manager_kwargs['max_retries'] = max_retries
        manager_kwargs.update(kwargs)

        http_manager = HTTPManagerFactory.create_for_provider(
            provider_name=provider_name,
            proxy_config=resolved_proxy,
            **manager_kwargs
        )

        self._log_http_manager_setup(provider_name, resolved_proxy, manager_kwargs)
        return http_manager

    @staticmethod
    def _resolve_proxy_config(proxy_config: Optional[ProxyConfig],
                              proxy_url: Optional[str],
                              config_dir: Optional[str],
                              provider_name: str,
                              country: str) -> Optional[ProxyConfig]:
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
            from .network import ProxyConfigManager
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
    def _log_http_manager_setup(provider_name: str,
                                proxy_config: Optional[ProxyConfig],
                                manager_kwargs: Dict) -> None:
        """Log HTTP manager setup information"""
        info_parts = [f"HTTP manager initialized for '{provider_name}'"]

        if proxy_config:
            proxy_type = proxy_config.proxy_type.value if proxy_config.proxy_type else 'http'
            proxy_host = f"{proxy_config.host}:{proxy_config.port}"
            has_auth = "authenticated" if proxy_config.auth else "no-auth"
            info_parts.append(f"proxy: {proxy_type}://{proxy_host} ({has_auth})")
        else:
            info_parts.append("proxy: none")

        if 'user_agent' in manager_kwargs:
            ua_preview = manager_kwargs['user_agent'][:50] + '...' if len(manager_kwargs['user_agent']) > 50 else \
            manager_kwargs['user_agent']
            info_parts.append(f"user-agent: {ua_preview}")

        if 'timeout' in manager_kwargs:
            info_parts.append(f"timeout: {manager_kwargs['timeout']}s")

        if 'max_retries' in manager_kwargs:
            info_parts.append(f"retries: {manager_kwargs['max_retries']}")

        logger.info(f"{provider_name}: {', '.join(info_parts)}")

    def _share_http_manager_with_authenticator(self,
                                               authenticator,
                                               http_manager: Optional[HTTPManager] = None) -> HTTPManager:
        """Share HTTP manager with authenticator for consistency"""
        if http_manager is None:
            http_manager = self.http_manager

        if http_manager and hasattr(authenticator, 'http_manager'):
            if authenticator.http_manager is None:
                logger.debug(f"{self.provider_name}: Sharing HTTP manager with authenticator")
                authenticator.http_manager = http_manager
            else:
                logger.debug(f"{self.provider_name}: Using authenticator's existing HTTP manager")
                http_manager = authenticator.http_manager

        return http_manager

    # ============================================================================
    # AUTHENTICATION HEADER ABSTRACTIONS (NEW)
    # ============================================================================

    def _get_base_headers(self,
                          user_agent: Optional[str] = None,
                          accept: str = 'application/json',
                          content_type: str = 'application/json',
                          additional_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Get base headers for API requests

        Args:
            user_agent: Custom user agent (uses default if None)
            accept: Accept header value
            content_type: Content-Type header value
            additional_headers: Additional headers to merge

        Returns:
            Dictionary of HTTP headers
        """
        headers = {
            'User-Agent': user_agent or self._default_user_agent,
            'Accept': accept,
            'Content-Type': content_type
        }

        if additional_headers:
            headers.update(additional_headers)

        return headers

    def _get_authenticated_headers(self,
                                   auth_type: AuthType = AuthType.BEARER,
                                   token_getter: Optional[Callable[[], str]] = None,
                                   token_key: str = 'Authorization',
                                   base_headers: Optional[Dict[str, str]] = None,
                                   additional_headers: Optional[Dict[str, str]] = None,
                                   **kwargs) -> Dict[str, str]:
        """
        Get headers with authentication token

        This is a flexible method that handles different authentication schemes
        commonly used by streaming providers.

        Args:
            auth_type: Type of auth (BEARER, BASIC, CLIENT, CUSTOM, NONE)
            token_getter: Function to get token (uses self.authenticator.get_bearer_token if None)
            token_key: Header key for token (default: 'Authorization')
            base_headers: Base headers to start with (creates new if None)
            additional_headers: Additional headers to add after auth
            **kwargs: Arguments passed to token_getter

        Returns:
            Dictionary of authenticated HTTP headers
        """
        # Start with base headers or create new
        headers = base_headers.copy() if base_headers else self._get_base_headers()

        # Add authentication if needed
        if auth_type != AuthType.NONE:
            # Get token using provided getter or default to authenticator
            if token_getter:
                token = token_getter()
            elif self.authenticator is not None:
                token = self.authenticator.get_bearer_token(**kwargs)
            else:
                logger.warning(f"{self.provider_name}: No token getter or authenticator available")
                token = None

            # Add auth header based on type
            if token:
                if auth_type == AuthType.BEARER:
                    headers[token_key] = f'Bearer {token}'
                elif auth_type == AuthType.BASIC:
                    headers[token_key] = f'Basic {token}'
                elif auth_type == AuthType.CLIENT:
                    headers[token_key] = f'Client {token}'
                elif auth_type == AuthType.CUSTOM:
                    # Custom type - just use token as-is
                    headers[token_key] = token

        # Add any additional headers
        if additional_headers:
            headers.update(additional_headers)

        return headers

    def _build_provider_headers(self,
                                base_headers: Optional[Dict[str, str]] = None,
                                auth_type: AuthType = AuthType.NONE,
                                provider_headers: Optional[Dict[str, str]] = None,
                                **auth_kwargs) -> Dict[str, str]:
        """
        Build complete headers with provider-specific fields

        This is a convenience method that combines base headers, authentication,
        and provider-specific headers in one call.

        Args:
            base_headers: Base headers (created if None)
            auth_type: Authentication type (NONE = no auth)
            provider_headers: Provider-specific headers to add
            **auth_kwargs: Arguments for authentication

        Returns:
            Complete headers dictionary
        """
        # Start with base or provided headers
        headers = base_headers.copy() if base_headers else self._get_base_headers()

        # Add authentication if needed
        if auth_type != AuthType.NONE:
            headers = self._get_authenticated_headers(
                auth_type=auth_type,
                base_headers=headers,
                **auth_kwargs
            )

        # Add provider-specific headers
        if provider_headers:
            headers.update(provider_headers)

        return headers

    def _add_auth_to_headers(self,
                             headers: Dict[str, str],
                             auth_type: AuthType = AuthType.BEARER,
                             token_getter: Optional[Callable[[], str]] = None,
                             token_key: str = 'Authorization',
                             **kwargs) -> Dict[str, str]:
        """
        Add authentication to existing headers (in-place modification)

        Useful when you've already built headers and just need to add auth.

        Args:
            headers: Headers dictionary to modify
            auth_type: Type of authentication
            token_getter: Function to get token
            token_key: Header key for token
            **kwargs: Arguments for token_getter

        Returns:
            The modified headers dictionary (same object)
        """
        if auth_type == AuthType.NONE:
            return headers

        # Get token
        if token_getter:
            token = token_getter()
        elif self.authenticator is not None:
            token = self.authenticator.get_bearer_token(**kwargs)
        else:
            logger.warning(f"{self.provider_name}: No token available for auth")
            return headers

        # Add auth header
        if token:
            if auth_type == AuthType.BEARER:
                headers[token_key] = f'Bearer {token}'
            elif auth_type == AuthType.BASIC:
                headers[token_key] = f'Basic {token}'
            elif auth_type == AuthType.CLIENT:
                headers[token_key] = f'Client {token}'
            elif auth_type == AuthType.CUSTOM:
                headers[token_key] = token

        return headers

    def _get_auth_token(self,
                        token_type: str = 'bearer',
                        force_refresh: bool = False,
                        **kwargs) -> Optional[str]:
        """
        Get authentication token from authenticator

        Convenience method for getting tokens with common options.

        Args:
            token_type: Type of token to get ('bearer', 'device', 'persona', etc.)
            force_refresh: Force token refresh
            **kwargs: Additional arguments for authenticator

        Returns:
            Token string or None
        """
        if self.authenticator is None:
            logger.warning(f"{self.provider_name}: No authenticator available")
            return None

        try:
            # Try to get token based on type
            if token_type == 'bearer':
                return self.authenticator.get_bearer_token(force_refresh=force_refresh, **kwargs)
            elif hasattr(self.authenticator, f'get_{token_type}_token'):
                getter = getattr(self.authenticator, f'get_{token_type}_token')
                return getter(force_refresh=force_refresh, **kwargs)
            else:
                # Default to bearer token
                return self.authenticator.get_bearer_token(force_refresh=force_refresh, **kwargs)
        except Exception as e:
            logger.error(f"{self.provider_name}: Error getting {token_type} token: {e}")
            return None

    # ============================================================================
    # ABSTRACT METHODS (Required by all providers)
    # ============================================================================

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name (e.g., 'joyn', 'zdf', 'ard')"""
        pass

    @property
    @abstractmethod
    def provider_label(self) -> str:
        """Return the provider label (e.g., 'JOYN', 'ZDF', 'RTL+')"""
        pass

    @property
    @abstractmethod
    def provider_logo(self) -> str:
        """Return the provider logo URL"""
        pass

    @property
    @abstractmethod
    def uses_dynamic_manifests(self) -> bool:
        """Return True if provider uses truly dynamic manifests"""
        pass

    @abstractmethod
    def get_channels(self, **kwargs) -> List[StreamingChannel]:
        """Fetch channels from the provider"""
        pass

    @abstractmethod
    def get_drm(self, channel_id: str, **kwargs) -> List[DRMConfig]:
        """Get all DRM configurations for a channel by ID"""
        return []

    def get_epg(self, channel_id: str,
                start_time: Optional[datetime] = None,
                end_time: Optional[datetime] = None,
                **kwargs) -> List[Dict]:
        """Get EPG data for a channel"""
        return []

    @staticmethod
    def get_epg_xmltv(**kwargs) -> Optional[str]:
        """Get complete EPG data for this provider in XMLTV format"""
        return None

    @abstractmethod
    def enrich_channel_data(self, channel: StreamingChannel, **kwargs) -> Optional[StreamingChannel]:
        """Enrich channel with additional data including manifest URL"""
        return None

    @abstractmethod
    def get_manifest(self, channel_id: str, **kwargs) -> Optional[str]:
        """Get manifest URL for a specific channel by ID"""
        return None

    def get_dynamic_manifest_params(self, channel: StreamingChannel, **kwargs) -> Optional[str]:
        """Optional: Get dynamic manifest parameters for a channel"""
        return None

    def to_output_format(self, channels: List[StreamingChannel] = None) -> Dict:
        """Convert channels to output format"""
        if channels is None:
            channels = self.channels

        return {
            'Provider': self.provider_name,
            'Country': self.country,
            'Channels': [channel.to_dict() for channel in channels]
        }

    def to_json(self, channels: List[StreamingChannel] = None, indent: int = 2) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_output_format(channels), indent=indent, ensure_ascii=False)