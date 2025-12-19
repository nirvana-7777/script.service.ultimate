# streaming_providers/base/provider.py - Enhanced with Header Abstractions
"""
Streaming Provider Base Class

Authentication System:
---------------------
Providers implement authentication through three core components:

1. CAPABILITIES (Declarative):
   - supported_auth_types: List[str] - What auth methods the provider CAN use
   - preferred_auth_type: str - Which method SHOULD be used by default

2. STATE (Dynamic):
   - get_current_auth_type(context) -> str - Which method IS currently active
   - get_auth_status(context) -> AuthStatus - Complete authentication status

3. LOGIC (Optional Overrides):
   - _calculate_auth_state(context) -> Optional[AuthState] - Custom auth state logic
   - _calculate_readiness(context) -> Optional[Tuple[bool, str]] - Custom readiness
   - get_auth_details(context) -> Dict[str, Any] - Provider-specific details

Auth Type Definitions:
   - 'user_credentials': Username/password (Joyn, RTL+)
   - 'client_credentials': Client ID/secret (Joyn fallback, some APIs)
   - 'network_based': Fixed-line/network auth (Magenta2, cable providers)
   - 'anonymous': No auth needed (ZDF, ARD)
   - 'device_registration': Device-based auth (Smart TV apps)
   - 'embedded_client': Built-in credentials

Implementation Examples:
----------------------
# Simple provider (ZDF)
class ZDFProvider(StreamingProvider):
    @property
    def supported_auth_types(self) -> List[str]:
        return ['anonymous']  # Just one type

# Multi-auth provider (Joyn)
class JoynProvider(StreamingProvider):
    @property
    def supported_auth_types(self) -> List[str]:
        return ['client_credentials', 'user_credentials']

    @property
    def preferred_auth_type(self) -> str:
        return 'user_credentials'  # Prefer full access

    def get_current_auth_type(self, context: AuthContext) -> str:
        # Custom logic to detect current auth mode
        token = context.get_token(self.provider_name, None, self.country)
        return 'user_credentials' if token and token.get('auth_level') == 'user_authenticated' else 'client_credentials'

# Network-based provider (Magenta2)
class Magenta2Provider(StreamingProvider):
    @property
    def supported_auth_types(self) -> List[str]:
        return ['network_based']

    @property
    def primary_token_scope(self) -> Optional[str]:
        return 'yo_digital'  # Uses scoped tokens

    def _calculate_readiness(self, context: AuthContext):
        # Check multiple token scopes
        yo_token = context.get_token(self.provider_name, 'yo_digital', self.country)
        if yo_token and not context.session._is_token_expired(yo_token):
            return True, "Has valid streaming token"
        return False, "No valid tokens found"
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
import json
from datetime import datetime

from .models.streaming_channel import StreamingChannel
from .models.drm_models import DRMConfig
from .models.proxy_models import ProxyConfig
from .network import HTTPManagerFactory, HTTPManager
from .utils.logger import logger
from ..providers.auth import AuthContext, AuthStatus


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

    SUPPORTED_COUNTRIES: List[str] = []

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

    @classmethod
    def get_supported_countries(cls) -> List[str]:
        """
        Get list of countries supported by this provider.

        Returns:
            List of ISO country codes (e.g., ['de', 'at', 'ch'])
            Empty list means single-country provider using default country
        """
        return cls.SUPPORTED_COUNTRIES.copy()

    @classmethod
    def supports_multiple_countries(cls) -> bool:
        """
        Check if this provider supports multiple countries.

        Returns:
            True if provider supports country-specific instances
        """
        return len(cls.SUPPORTED_COUNTRIES) > 0

    @classmethod
    def validate_country(cls, country: str) -> bool:
        """
        Validate if a country is supported by this provider.

        Args:
            country: ISO country code to validate

        Returns:
            True if country is supported or provider is single-country
        """
        if not cls.supports_multiple_countries():
            # Single-country providers accept any country (or ignore it)
            return True

        return country.lower() in [c.lower() for c in cls.SUPPORTED_COUNTRIES]

    def validate_auth_type(self, auth_type: str) -> bool:
        """
        Check if an auth type is supported by this provider.

        Useful for:
        - Validating user input in configuration UI
        - Safely switching auth modes
        - Error messages when unsupported auth is requested

        Args:
            auth_type: Auth type to check (e.g., 'user_credentials')

        Returns:
            True if supported, False otherwise

        Example:
            if provider.validate_auth_type('user_credentials'):
                # Safe to request user credentials
        """
        return auth_type in self.supported_auth_types

    def get_auth_type_description(self, auth_type: str) -> str:
        """
        Get human-readable description of an auth type.

        Args:
            auth_type: Auth type to describe

        Returns:
            Description string or empty string if not supported
        """
        descriptions = {
            'user_credentials': 'Username and password authentication',
            'client_credentials': 'Client ID and secret authentication',
            'network_based': 'Network/fixed-line authentication',
            'anonymous': 'No authentication required',
            'device_registration': 'Device registration authentication',
            'embedded_client': 'Built-in credentials authentication'
        }

        if auth_type in descriptions:
            return descriptions[auth_type]

        # For custom auth types
        return f"Custom authentication: {auth_type}"

    def get_auth_requirements(self, auth_type: str) -> Dict[str, Any]:
        """
        Get requirements for a specific auth type.

        Args:
            auth_type: Auth type to get requirements for

        Returns:
            Dictionary with requirement information

        Raises:
            ValueError: If auth_type is not supported
        """
        if not self.validate_auth_type(auth_type):
            raise ValueError(f"Auth type '{auth_type}' not supported by {self.provider_name}")

        requirements = {
            'auth_type': auth_type,
            'needs_storage': auth_type in ['user_credentials', 'client_credentials'],
            'provides_token': auth_type != 'anonymous',
            'user_interaction_required': auth_type in ['user_credentials', 'device_registration']
        }

        # Type-specific details
        if auth_type == 'user_credentials':
            requirements.update({
                'fields': ['username', 'password'],
                'optional_fields': ['client_id'],
                'storage_key': 'user_password'
            })
        elif auth_type == 'client_credentials':
            requirements.update({
                'fields': ['client_id', 'client_secret'],
                'storage_key': 'client_credentials'
            })
        elif auth_type == 'network_based':
            requirements.update({
                'description': 'Authenticates via your network provider',
                'automatic': True
            })

        return requirements

    # ===== AUTHENTICATION PROPERTIES AND METHODS =====

    @property
    @abstractmethod
    def supported_auth_types(self) -> List[str]:
        """List of authentication types this provider supports."""
        pass

    @property
    def preferred_auth_type(self) -> str:
        """Preferred authentication type (first in supported list)."""
        types = self.supported_auth_types
        return types[0] if types else 'unknown'

    @property
    def requires_stored_credentials(self) -> bool:
        """True if provider needs credentials stored in settings."""
        credential_types = ['user_credentials', 'client_credentials']
        return any(auth_type in credential_types
                   for auth_type in self.supported_auth_types)

    # ===== AUTHENTICATION PROPERTIES =====

    def get_current_auth_type(self, context: AuthContext) -> str:
        """
        Determine which auth type is currently active.

        Default implementation checks tokens/credentials.
        Override for providers with complex auth logic.

        Args:
            context: AuthContext for accessing tokens/credentials

        Returns:
            Current active auth type
        """
        return self._determine_current_auth_type_default(context)

    def _determine_current_auth_type_default(self, context: AuthContext) -> str:
        """
        Default logic for determining current auth type.
        Providers can override get_current_auth_type() directly instead.
        """
        # 1. Check if provider requires stored credentials
        if self.requires_stored_credentials:
            credentials = context.get_credentials(self.provider_name, self.country)
            if credentials:
                # Map credential type to auth type
                if hasattr(credentials, 'credential_type'):
                    if credentials.credential_type == 'user_password':
                        return 'user_credentials'
                    elif credentials.credential_type == 'client_credentials':
                        return 'client_credentials'

        # 2. Check token auth level
        primary_token = context.get_token(
            self.provider_name,
            self.primary_token_scope,
            self.country
        )
        if primary_token:
            auth_level = primary_token.get('auth_level')
            if auth_level == 'user_authenticated':
                return 'user_credentials'
            elif auth_level == 'client_credentials':
                return 'client_credentials'
            elif auth_level == 'anonymous':
                return 'anonymous'
            elif auth_level == 'network_based':
                return 'network_based'

        # 3. Return first supported type as default
        return self.preferred_auth_type

    # Token management properties (keep these)
    @property
    def primary_token_scope(self) -> Optional[str]:
        """
        Primary token scope for this provider.
        None = uses root-level token or no token needed.

        Returns:
            Token scope string or None
        """
        return None

    @property
    def token_scopes(self) -> List[str]:
        """
        All token scopes this provider uses.

        Returns:
            List of token scope strings
        """
        scope = self.primary_token_scope
        return [scope] if scope else []

    def get_auth_status(self, context: AuthContext) -> 'AuthStatus':
        """
        Get authentication status for this provider.
        Uses AuthStatusBuilder by default.

        Override only for providers with special requirements.

        Args:
            context: AuthContext with access to settings

        Returns:
            AuthStatus object
        """
        from ..providers.auth_builder import AuthStatusBuilder  # Import here to avoid circular imports
        return AuthStatusBuilder.for_provider(self, context)

    # Optional override methods for providers with special logic
    def _calculate_auth_state(self, context: AuthContext):
        """
        Override to provide custom auth state calculation.
        Return None to use standard calculation.

        Returns:
            AuthState or None
        """
        return None

    def _calculate_readiness(self, context: AuthContext):
        """
        Override to provide custom readiness calculation.
        Return None to use standard calculation.

        Returns:
            Tuple of (is_ready: bool, reason: str) or None
        """
        return None

    def get_auth_details(self, context: AuthContext) -> Dict[str, Any]:
        """
        Override to provide provider-specific auth details.

        Returns:
            Dictionary with provider-specific information
        """
        return {}
