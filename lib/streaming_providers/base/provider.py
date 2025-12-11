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

    @property
    @abstractmethod
    def implements_epg(self) -> bool:
        """
        Indicates whether this provider has its own EPG implementation.
        If False, the generic EPG manager will be used.

        Override in subclass and return True if provider has native EPG.

        Returns:
            True if provider implements its own EPG, False to use generic EPG
        """
        pass

    @abstractmethod
    def get_channels(self, **kwargs) -> List[StreamingChannel]:
        """Fetch channels from the provider"""
        pass

    @abstractmethod
    def get_drm(self, channel_id: str, **kwargs) -> List[DRMConfig]:
        """Get all DRM configurations for a channel by ID"""
        return []

    @property
    def catchup_window(self) -> int:
        """
        Return the catchup window in HOURS for this provider.

        Returns:
            int: Number of hours of catchup available (0 = no catchup support)
        """
        return 0

    @property
    def supports_catchup(self) -> bool:
        """
        Check if provider supports catchup/timeshift functionality.

        Returns:
            bool: True if catchup is supported
        """
        return self.catchup_window > 0

    @property
    def requires_user_credentials(self) -> bool:
        """
        Some providers do not need to authenticate

        Returns:
            bool: True if user credentials are required
        """
        return True

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


    # ============================================================================
    # CATCHUP ABSTRACT METHODS
    # ============================================================================

    def get_catchup_manifest(self,
                             channel_id: str,
                             start_time: int,
                             end_time: int,
                             epg_id: Optional[str] = None,
                             **kwargs) -> Optional[str]:
        """
        Get manifest URL for catchup/timeshift content.

        Args:
            channel_id: Channel identifier
            start_time: Start time as Unix timestamp
            end_time: End time as Unix timestamp
            epg_id: Optional EPG event ID (might be needed by some providers)
            **kwargs: Additional provider-specific parameters

        Returns:
            Manifest URL for catchup content, or None if not supported

        Default implementation falls back to live manifest.
        Override in subclass to implement provider-specific catchup logic.
        """
        if not self.supports_catchup:
            logger.debug(f"{self.provider_name}: Catchup not supported, falling back to live manifest")
            return self.get_manifest(channel_id, **kwargs)

        logger.warning(f"{self.provider_name}: get_catchup_manifest not implemented, "
                       f"falling back to live manifest")
        return self.get_manifest(channel_id, **kwargs)

    def get_catchup_drm(self,
                        channel_id: str,
                        start_time: int,
                        end_time: int,
                        epg_id: Optional[str] = None,
                        **kwargs) -> List[DRMConfig]:
        """
        Get DRM configurations for catchup content.

        Args:
            channel_id: Channel identifier
            start_time: Start time as Unix timestamp
            end_time: End time as Unix timestamp
            epg_id: Optional EPG event ID (might be needed for DRM licensing)
            **kwargs: Additional provider-specific parameters

        Returns:
            List of DRM configurations for catchup content

        Default implementation falls back to live DRM.
        Override in subclass if catchup requires different DRM configuration.
        """
        if not self.supports_catchup:
            logger.debug(f"{self.provider_name}: Catchup not supported, falling back to live DRM")
            return self.get_drm(channel_id, **kwargs)

        logger.debug(f"{self.provider_name}: get_catchup_drm not implemented, "
                     f"using live DRM configuration")
        return self.get_drm(channel_id, **kwargs)

    # ============================================================================
    # CATCHUP HELPER METHODS
    # ============================================================================

    def get_catchup_window_for_channel(self, channel_id: str) -> int:
        """
        Get catchup window for a specific channel in HOURS.

        Args:
            channel_id: Channel identifier

        Returns:
            int: Catchup window in hours for this channel
        """
        return self.catchup_window

    def validate_catchup_request(self, start_time: int, end_time: int) -> tuple[bool, Optional[str]]:
        """
        Validate a catchup request against provider's capabilities.

        Args:
            start_time: Start time as Unix timestamp
            end_time: End time as Unix timestamp

        Returns:
            Tuple of (is_valid, error_message)
        """
        import time

        if not self.supports_catchup:
            return False, f"Provider '{self.provider_name}' does not support catchup"

        if start_time >= end_time:
            return False, "Invalid time range: start_time must be before end_time"

        now = int(time.time())
        if start_time > now:
            return False, "Cannot request future content"

        # CHANGE FROM DAYS TO HOURS HERE
        max_age_seconds = self.catchup_window * 3600  # hours to seconds
        content_age = now - start_time

        if content_age > max_age_seconds:
            hours_ago = content_age // 3600
            return False, (f"Content is outside catchup window "
                           f"(requested: {hours_ago} hours ago, "
                           f"max: {self.catchup_window} hours)")

        return True, None

    def format_catchup_time_params(self,
                                   start_time: int,
                                   end_time: int,
                                   format_type: str = 'iso') -> Dict[str, str]:
        """
        Format time parameters for provider-specific API calls.

        Different providers expect different time formats in their APIs.
        This helper converts Unix timestamps to various formats.

        Args:
            start_time: Start time as Unix timestamp
            end_time: End time as Unix timestamp
            format_type: Format type ('iso', 'unix', 'millis', 'custom')

        Returns:
            Dictionary with formatted time parameters

        Override in subclass for provider-specific formatting.
        """
        from datetime import datetime

        if format_type == 'iso':
            # ISO 8601 format
            start_dt = datetime.fromtimestamp(start_time)
            end_dt = datetime.fromtimestamp(end_time)
            return {
                'start': start_dt.isoformat(),
                'end': end_dt.isoformat()
            }
        elif format_type == 'unix':
            # Unix timestamps (seconds)
            return {
                'start': str(start_time),
                'end': str(end_time)
            }
        elif format_type == 'millis':
            # Milliseconds since epoch
            return {
                'start': str(start_time * 1000),
                'end': str(end_time * 1000)
            }
        else:
            # Default to unix
            return {
                'start': str(start_time),
                'end': str(end_time)
            }

    def build_catchup_manifest_url(self,
                                   base_url: str,
                                   start_time: int,
                                   end_time: int,
                                   url_format: str = 'query') -> str:
        """
        Build catchup manifest URL with time parameters.

        Helper method to construct manifest URLs with time parameters
        in various formats that different providers use.

        Args:
            base_url: Base manifest URL
            start_time: Start time as Unix timestamp
            end_time: End time as Unix timestamp
            url_format: Format ('query', 'path', 'fragment')

        Returns:
            Complete manifest URL with time parameters

        Override in subclass for provider-specific URL construction.
        """
        if url_format == 'query':
            # Add as query parameters
            separator = '&' if '?' in base_url else '?'
            return f"{base_url}{separator}start={start_time}&end={end_time}"
        elif url_format == 'path':
            # Add to path (e.g., /manifest/start/end.mpd)
            return f"{base_url}/{start_time}/{end_time}"
        elif url_format == 'fragment':
            # Add as URL fragment (e.g., manifest.mpd#t=start,end)
            return f"{base_url}#t={start_time},{end_time}"
        else:
            # Default to query parameters
            separator = '&' if '?' in base_url else '?'
            return f"{base_url}{separator}start={start_time}&end={end_time}"