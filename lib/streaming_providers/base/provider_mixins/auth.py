"""Provider authentication mixin: header building, token retrieval, auth-type
introspection and AuthStatus reporting.

Behavior-preserving split out of provider.py, with one fix: the BEARER/BASIC/
CLIENT/CUSTOM header-formatting switch used to be duplicated verbatim in both
`_get_authenticated_headers` and `_add_auth_to_headers`. It's now a single
`_format_auth_header_value` helper that both call — same output for the same
input, one place to extend when a new AuthType is added.
"""

from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

from ...providers.auth import AuthContext, AuthStatus
from ..auth_type import AuthType
from ..utils.logger import logger


class ProviderAuthMixin:
    if TYPE_CHECKING:
        # Provided by StreamingProvider / sibling mixins once this is
        # actually composed into the full class. Declared here only so
        # IDEs and type checkers stop flagging them as unresolved on
        # ProviderAuthMixin in isolation — no runtime effect.
        provider_name: str
        country: str
        authenticator: Any
        _default_user_agent: str
        supported_auth_types: List[str]

    def _get_base_headers(
        self,
        user_agent: Optional[str] = None,
        accept: str = "application/json",
        content_type: str = "application/json",
        additional_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
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
            "User-Agent": user_agent or self._default_user_agent,
            "Accept": accept,
            "Content-Type": content_type,
        }

        if additional_headers:
            headers.update(additional_headers)

        return headers

    @staticmethod
    def _format_auth_header_value(auth_type: AuthType, token: str) -> Optional[str]:
        """
        Render a token into the header value for the given auth type.

        Shared by `_get_authenticated_headers` and `_add_auth_to_headers` so
        the BEARER/BASIC/CLIENT/CUSTOM mapping only lives in one place.

        Returns None for an auth type that isn't one of the known schemes
        (callers leave the header untouched in that case, matching the
        previous behavior of simply not entering any elif branch).
        """
        if auth_type == AuthType.BEARER:
            return f"Bearer {token}"
        elif auth_type == AuthType.BASIC:
            return f"Basic {token}"
        elif auth_type == AuthType.CLIENT:
            return f"Client {token}"
        elif auth_type == AuthType.CUSTOM:
            return token
        return None

    def _get_authenticated_headers(
        self,
        auth_type: AuthType = AuthType.BEARER,
        token_getter: Optional[Callable[[], str]] = None,
        token_key: str = "Authorization",
        base_headers: Optional[Dict[str, str]] = None,
        additional_headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> Dict[str, str]:
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
                value = self._format_auth_header_value(auth_type, token)
                if value is not None:
                    headers[token_key] = value

        # Add any additional headers
        if additional_headers:
            headers.update(additional_headers)

        return headers

    def _build_provider_headers(
        self,
        base_headers: Optional[Dict[str, str]] = None,
        auth_type: AuthType = AuthType.NONE,
        provider_headers: Optional[Dict[str, str]] = None,
        **auth_kwargs,
    ) -> Dict[str, str]:
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
                auth_type=auth_type, base_headers=headers, **auth_kwargs
            )

        # Add provider-specific headers
        if provider_headers:
            headers.update(provider_headers)

        return headers

    def _add_auth_to_headers(
        self,
        headers: Dict[str, str],
        auth_type: AuthType = AuthType.BEARER,
        token_getter: Optional[Callable[[], str]] = None,
        token_key: str = "Authorization",
        **kwargs,
    ) -> Dict[str, str]:
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
            value = self._format_auth_header_value(auth_type, token)
            if value is not None:
                headers[token_key] = value

        return headers

    def _get_auth_token(
        self, token_type: str = "bearer", force_refresh: bool = False, **kwargs
    ) -> Optional[str]:
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
            if token_type == "bearer":
                return self.authenticator.get_bearer_token(force_refresh=force_refresh, **kwargs)
            elif hasattr(self.authenticator, f"get_{token_type}_token"):
                getter = getattr(self.authenticator, f"get_{token_type}_token")
                return getter(force_refresh=force_refresh, **kwargs)
            else:
                # Default to bearer token
                return self.authenticator.get_bearer_token(force_refresh=force_refresh, **kwargs)
        except Exception as e:
            logger.error(f"{self.provider_name}: Error getting {token_type} token: {e}")
            return None

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
            "user_credentials": "Username and password authentication",
            "client_credentials": "Client ID and secret authentication",
            "network_based": "Network/fixed-line authentication",
            "anonymous": "No authentication required",
            "device_registration": "Device registration authentication",
            "embedded_client": "Built-in credentials authentication",
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

        requirements: Dict[str, Any] = {
            "auth_type": auth_type,
            "needs_storage": auth_type in ["user_credentials", "client_credentials"],
            "provides_token": auth_type != "anonymous",
            "user_interaction_required": auth_type in ["user_credentials", "device_registration"],
        }

        # Type-specific details
        if auth_type == "user_credentials":
            requirements.update(
                {
                    "fields": ["username", "password"],
                    "optional_fields": ["client_id"],
                    "storage_key": "user_password",
                }
            )
        elif auth_type == "client_credentials":
            requirements.update(
                {
                    "fields": ["client_id", "client_secret"],
                    "storage_key": "client_credentials",
                }
            )
        elif auth_type == "network_based":
            requirements.update(
                {
                    "description": "Authenticates via your network provider",
                    "automatic": True,
                }
            )

        return requirements

    # ===== AUTHENTICATION PROPERTIES AND METHODS =====

    @property
    def preferred_auth_type(self) -> str:
        """Preferred authentication type (first in supported list)."""
        types = self.supported_auth_types
        return types[0] if types else "unknown"

    @property
    def requires_stored_credentials(self) -> bool:
        """True if provider needs credentials stored in settings."""
        credential_types = ["user_credentials", "client_credentials"]
        return any(auth_type in credential_types for auth_type in self.supported_auth_types)

    @property
    def requires_manifest_context(self) -> bool:
        """True if provider needs to use same http manager to get manifest."""
        return False

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
                if hasattr(credentials, "credential_type"):
                    if credentials.credential_type == "user_password":
                        return "user_credentials"
                    elif credentials.credential_type == "client_credentials":
                        return "client_credentials"

        # 2. Check token auth level
        primary_token = context.get_token(
            self.provider_name, self.primary_token_scope, self.country
        )
        if primary_token:
            auth_level = primary_token.get("auth_level")
            if auth_level == "user_authenticated":
                return "user_credentials"
            elif auth_level == "client_credentials":
                return "client_credentials"
            elif auth_level == "anonymous":
                return "anonymous"
            elif auth_level == "network_based":
                return "network_based"

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

    def get_auth_status(self, context: AuthContext) -> "AuthStatus":
        """
        Get authentication status for this provider.
        Uses AuthStatusBuilder by default.

        Override only for providers with special requirements.

        Args:
            context: AuthContext with access to settings

        Returns:
            AuthStatus object
        """
        from ...providers.auth_builder import (
            AuthStatusBuilder,
        )  # Import here to avoid circular imports

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