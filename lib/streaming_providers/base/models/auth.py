# streaming_providers/base/models/auth.py
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class AuthState(Enum):
    """Authentication state"""

    NOT_APPLICABLE = "not_applicable"
    NOT_AUTHENTICATED = "not_authenticated"
    AUTHENTICATED = "authenticated"
    EXPIRED = "expired"


@dataclass
class TokenInfo:
    """Information about a specific token scope"""

    scope: str
    has_token: bool
    is_valid: bool
    expires_at: Optional[float] = None
    has_refresh_token: bool = False
    auth_level: Optional[str] = None


@dataclass
class AuthStatus:
    """Complete authentication status for a provider"""

    provider_name: str
    provider_label: str
    country: Optional[str]
    auth_type: str
    auth_state: AuthState
    is_ready: bool
    readiness_reason: str
    requires_stored_credentials: bool
    has_credentials: bool
    credentials_type: Optional[str]
    has_valid_token: bool
    primary_token_scope: Optional[str]
    token_scopes: Dict[str, TokenInfo]
    last_authentication: Optional[float]
    provider_specific: Dict[str, Any]

    # NEW: Token expiration fields
    token_expires_at: Optional[float] = None
    token_expires_in_seconds: Optional[int] = None
    refresh_token_expires_at: Optional[float] = None
    refresh_token_expires_in_seconds: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        import time

        result = {
            "provider": (
                f"{self.provider_name}_{self.country}"
                if self.country
                else self.provider_name
            ),
            "provider_name": self.provider_name,
            "provider_label": self.provider_label,
            "country": self.country,
            "auth_type": self.auth_type,
            "auth_state": self.auth_state.value,
            "is_ready": self.is_ready,
            "readiness_reason": self.readiness_reason,
            "primary_token_scope": self.primary_token_scope,
            "has_valid_token": self.has_valid_token,
            "token_scopes": {
                scope: {
                    "scope": info.scope,
                    "has_token": info.has_token,
                    "is_valid": info.is_valid,
                    "expires_at": info.expires_at,
                    "has_refresh_token": info.has_refresh_token,
                    "auth_level": info.auth_level,
                }
                for scope, info in self.token_scopes.items()
            },
            "requires_stored_credentials": self.requires_stored_credentials,
            "has_credentials": self.has_credentials,
            "credentials_type": self.credentials_type,
            "timestamp": time.time(),
            "last_authentication": self.last_authentication,
            "provider_specific": self.provider_specific,
            "auth_state_description": self._get_auth_state_description(),
        }

        # Add token expiration info if available
        if self.token_expires_at is not None:
            result["token_expires_at"] = self.token_expires_at

        if self.token_expires_in_seconds is not None:
            result["token_expires_in_seconds"] = self.token_expires_in_seconds

        if self.refresh_token_expires_at is not None:
            result["refresh_token_expires_at"] = self.refresh_token_expires_at

        if self.refresh_token_expires_in_seconds is not None:
            result["refresh_token_expires_in_seconds"] = (
                self.refresh_token_expires_in_seconds
            )

        return result

    def _get_auth_state_description(self) -> str:
        """Get human-readable description of auth state"""
        if self.auth_state == AuthState.NOT_APPLICABLE:
            return "Authentication not required"
        elif self.auth_state == AuthState.AUTHENTICATED:
            return "Successfully authenticated"
        elif self.auth_state == AuthState.EXPIRED:
            return "Authentication expired, refresh available"
        else:
            return "Not authenticated"
