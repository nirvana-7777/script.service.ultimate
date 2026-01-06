# streaming_providers/providers/auth_builder.py

from typing import Any, Dict, Optional, Tuple

from ..base.models.auth import AuthState, AuthStatus, TokenInfo
from .auth_context import AuthContext


class AuthStatusBuilder:
    """
    Simplified builder for authentication status.
    All logic in one class, no intermediate data dict.
    """

    @staticmethod
    def for_provider(provider, context: AuthContext) -> AuthStatus:
        """Build auth status directly from provider and context"""

        # Get current auth type
        current_auth_type = provider.get_current_auth_type(context)

        # Calculate auth state (with provider override support)
        auth_state = AuthStatusBuilder._calculate_auth_state_with_override(
            provider, context
        )

        # Calculate readiness (with provider override support)
        is_ready, reason = AuthStatusBuilder._calculate_readiness_with_override(
            provider, context
        )

        # Build token info
        token_scopes = AuthStatusBuilder._build_token_scopes(provider, context)

        # Get credentials info
        has_credentials, credentials_type = AuthStatusBuilder._get_credentials_info(
            provider, context
        )

        # Get provider-specific details
        provider_specific = AuthStatusBuilder._get_provider_specific_details(
            provider, context, current_auth_type
        )

        # Get token expiration info
        (
            token_expires_at,
            token_expires_in_seconds,
            refresh_token_expires_at,
            refresh_token_expires_in_seconds,
        ) = AuthStatusBuilder._get_token_expiration_info(provider, context)

        # Build and return
        return AuthStatus(
            provider_name=provider.provider_name,
            provider_label=provider.provider_label,
            country=provider.country,
            auth_type=current_auth_type,
            auth_state=auth_state,
            is_ready=is_ready,
            readiness_reason=reason,
            requires_stored_credentials=provider.requires_stored_credentials,
            has_credentials=has_credentials,
            credentials_type=credentials_type,
            has_valid_token=AuthStatusBuilder._has_valid_token(provider, context),
            primary_token_scope=provider.primary_token_scope,
            token_scopes=token_scopes,
            last_authentication=AuthStatusBuilder._get_last_auth_time(
                provider, context
            ),
            provider_specific=provider_specific,
            token_expires_at=token_expires_at,
            token_expires_in_seconds=token_expires_in_seconds,
            refresh_token_expires_at=refresh_token_expires_at,
            refresh_token_expires_in_seconds=refresh_token_expires_in_seconds,
        )

    # ===== Calculation Methods (with provider override support) =====

    @staticmethod
    def _calculate_auth_state_with_override(
        provider, context: AuthContext
    ) -> AuthState:
        """Calculate auth state, allowing provider override"""
        # Check if provider has custom logic
        if hasattr(provider, "_calculate_auth_state"):
            custom_state = provider._calculate_auth_state(context)
            if custom_state:
                return custom_state

        # Standard calculation
        return AuthStatusBuilder._calculate_auth_state(provider, context)

    @staticmethod
    def _calculate_readiness_with_override(
        provider, context: AuthContext
    ) -> Tuple[bool, str]:
        """Calculate readiness, allowing provider override"""
        # Check if provider has custom logic
        if hasattr(provider, "_calculate_readiness"):
            custom_result = provider._calculate_readiness(context)
            if custom_result:
                return custom_result

        # Standard calculation
        return AuthStatusBuilder._calculate_readiness(provider, context)

    # ===== Standard Calculation Methods =====

    @staticmethod
    def _calculate_auth_state(provider, context: AuthContext) -> AuthState:
        """Standard auth state calculation"""

        # Anonymous providers don't need auth
        if "anonymous" in provider.supported_auth_types:
            return AuthState.NOT_APPLICABLE

        # Check if we have any valid token
        if AuthStatusBuilder._has_valid_token(provider, context):
            return AuthState.AUTHENTICATED

        # Check if we have an expired token that can be refreshed
        expired_token = AuthStatusBuilder._get_expired_token_with_refresh(
            provider, context
        )
        if expired_token:
            return AuthState.EXPIRED

        # Not authenticated
        return AuthState.NOT_AUTHENTICATED

    @staticmethod
    def _calculate_readiness(provider, context: AuthContext) -> Tuple[bool, str]:
        """
        Standard readiness calculation.

        Priority order:
        1. Anonymous providers are always ready
        2. Valid token = ready (credentials not needed if already authenticated)
        3. Expired refreshable token = ready (can refresh)
        4. Check for stored credentials
        5. Network-based providers (special case)
        """

        # 1. Anonymous providers are always ready
        if "anonymous" in provider.supported_auth_types:
            return True, "Anonymous provider always ready"

        # 2. Check if we have a valid token (MOST IMPORTANT)
        if AuthStatusBuilder._has_valid_token(provider, context):
            return True, "Has valid authentication token"

        # 3. Check if we have an expired token that can be refreshed
        expired_token = AuthStatusBuilder._get_expired_token_with_refresh(
            provider, context
        )
        if expired_token:
            return True, "Has expired token with refresh capability"

        # 4. Check credentials if required (only matters if no valid token)
        if provider.requires_stored_credentials:
            credentials = context.get_credentials(
                provider.provider_name, provider.country
            )
            if not credentials:
                return False, "Missing required credentials"

            # Has credentials but no token yet
            return False, "Has credentials but needs authentication"

        # 5. Network-based providers might be authenticating
        if "network_based" in provider.supported_auth_types:
            return False, "Network authentication in progress"

        # 6. Not ready
        return False, "Not authenticated"

    # ===== Helper Methods =====

    @staticmethod
    def _has_valid_token(provider, context: AuthContext) -> bool:
        """Check if provider has any valid token"""
        # Check primary scope first
        if provider.primary_token_scope:
            token = context.get_token(
                provider.provider_name, provider.primary_token_scope, provider.country
            )
            if token and not context.is_token_expired(token):
                return True

        # Check all scopes
        for scope in provider.token_scopes:
            token = context.get_token(provider.provider_name, scope, provider.country)
            if token and not context.is_token_expired(token):
                return True

        # Check root-level token
        token = context.get_token(provider.provider_name, None, provider.country)
        if token and not context.is_token_expired(token):
            return True

        return False

    @staticmethod
    def _get_expired_token_with_refresh(
        provider, context: AuthContext
    ) -> Optional[Dict[str, Any]]:
        """Get an expired token that has refresh capability"""
        # Check primary scope
        if provider.primary_token_scope:
            token = context.get_token(
                provider.provider_name, provider.primary_token_scope, provider.country
            )
            if token and context.is_token_expired(token) and token.get("refresh_token"):
                return token

        # Check all scopes
        for scope in provider.token_scopes:
            token = context.get_token(provider.provider_name, scope, provider.country)
            if token and context.is_token_expired(token) and token.get("refresh_token"):
                return token

        # Check root-level token
        token = context.get_token(provider.provider_name, None, provider.country)
        if token and context.is_token_expired(token) and token.get("refresh_token"):
            return token

        return None

    @staticmethod
    def _build_token_scopes(provider, context: AuthContext) -> Dict[str, TokenInfo]:
        """Build token scope information"""
        token_scopes = {}

        for scope in provider.token_scopes:
            token_data = context.get_token(
                provider.provider_name, scope, provider.country
            )
            if token_data:
                expires_at = None
                if "issued_at" in token_data and "expires_in" in token_data:
                    expires_at = token_data["issued_at"] + token_data["expires_in"]

                token_info = TokenInfo(
                    scope=scope,
                    has_token=True,
                    is_valid=not context.is_token_expired(token_data),
                    expires_at=expires_at,
                    has_refresh_token=bool(token_data.get("refresh_token")),
                    auth_level=token_data.get("auth_level"),
                )
            else:
                token_info = TokenInfo(scope=scope, has_token=False, is_valid=False)
            token_scopes[scope] = token_info

        return token_scopes

    @staticmethod
    def _get_credentials_info(
        provider, context: AuthContext
    ) -> Tuple[bool, Optional[str]]:
        """Get credentials information"""
        if not provider.requires_stored_credentials:
            return False, None

        credentials = context.get_credentials(provider.provider_name, provider.country)
        if credentials:
            return True, credentials.credential_type

        return False, None

    @staticmethod
    def _get_last_auth_time(provider, context: AuthContext) -> Optional[float]:
        """Get last authentication time from token"""
        if provider.primary_token_scope:
            token = context.get_token(
                provider.provider_name, provider.primary_token_scope, provider.country
            )
            if token and "issued_at" in token:
                return token["issued_at"]

        # Check root-level token
        token = context.get_token(provider.provider_name, None, provider.country)
        if token and "issued_at" in token:
            return token["issued_at"]

        return None

    @staticmethod
    def _get_provider_specific_details(
        provider, context: AuthContext, current_auth_type: str
    ) -> Dict[str, Any]:
        """Get provider-specific auth details"""
        details = {
            "supported_auth_types": provider.supported_auth_types,
            "preferred_auth_type": provider.preferred_auth_type,
            "current_auth_type": current_auth_type,
        }

        # Add provider's own details if available
        if hasattr(provider, "get_auth_details"):
            custom_details = provider.get_auth_details(context)
            details.update(custom_details)

        return details

    @staticmethod
    def _get_token_expiration_info(
        provider, context: AuthContext
    ) -> Tuple[Optional[float], Optional[int], Optional[float], Optional[int]]:
        """
        Get token expiration information.

        Returns:
            Tuple of (token_expires_at, token_expires_in_seconds,
                     refresh_token_expires_at, refresh_token_expires_in_seconds)
        """
        import time

        current_time = time.time()

        token_expires_at: Optional[float] = None
        token_expires_in_seconds: Optional[int] = None
        refresh_token_expires_at: Optional[float] = None
        refresh_token_expires_in_seconds: Optional[int] = None

        # Try to get the primary token
        token_data: Optional[Dict[str, Any]] = None

        # Check primary scope first
        if provider.primary_token_scope:
            token_data = context.get_token(
                provider.provider_name, provider.primary_token_scope, provider.country
            )

        # If no primary scope or no token, check root-level token
        if not token_data:
            token_data = context.get_token(
                provider.provider_name, None, provider.country
            )

        # If still no token, try first available scope
        if not token_data and provider.token_scopes:
            for scope in provider.token_scopes:
                token_data = context.get_token(
                    provider.provider_name, scope, provider.country
                )
                if token_data:
                    break

        if not token_data:
            return None, None, None, None

        # Calculate access token expiration
        # Standard format: expires_in + issued_at
        if "expires_in" in token_data and "issued_at" in token_data:
            expires_in = token_data["expires_in"]
            issued_at = token_data["issued_at"]
            if isinstance(expires_in, (int, float)) and isinstance(
                issued_at, (int, float)
            ):
                token_expires_at = float(issued_at) + float(expires_in)
                token_expires_in_seconds = int(token_expires_at - current_time)

        # yo_digital format: separate access token expiration
        elif (
            "access_token_expires_in" in token_data
            and "access_token_issued_at" in token_data
        ):
            expires_in = token_data["access_token_expires_in"]
            issued_at = token_data["access_token_issued_at"]
            if isinstance(expires_in, (int, float)) and isinstance(
                issued_at, (int, float)
            ):
                token_expires_at = float(issued_at) + float(expires_in)
                token_expires_in_seconds = int(token_expires_at - current_time)

        # Direct expiration timestamp
        elif "expires_at" in token_data:
            expires_at = token_data["expires_at"]
            if isinstance(expires_at, (int, float)):
                token_expires_at = float(expires_at)
                token_expires_in_seconds = int(token_expires_at - current_time)

        # Calculate refresh token expiration (yo_digital format)
        if (
            "refresh_token_expires_in" in token_data
            and "refresh_token_issued_at" in token_data
        ):
            refresh_expires_in = token_data["refresh_token_expires_in"]
            refresh_issued_at = token_data["refresh_token_issued_at"]
            if isinstance(refresh_expires_in, (int, float)) and isinstance(
                refresh_issued_at, (int, float)
            ):
                refresh_token_expires_at = float(refresh_issued_at) + float(
                    refresh_expires_in
                )
                refresh_token_expires_in_seconds = int(
                    refresh_token_expires_at - current_time
                )

        return (
            token_expires_at,
            token_expires_in_seconds,
            refresh_token_expires_at,
            refresh_token_expires_in_seconds,
        )
