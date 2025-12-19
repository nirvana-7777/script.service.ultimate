# streaming_providers/base/models/auth.py
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from enum import Enum
import time


class AuthState(Enum):
    """Standardized authentication states"""
    NOT_AUTHENTICATED = "not_authenticated"
    AUTHENTICATED = "authenticated"
    EXPIRED = "expired"
    PENDING = "pending"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class TokenInfo:
    """Standardized token information"""
    scope: str
    has_token: bool
    is_valid: bool
    expires_at: Optional[float] = None
    has_refresh_token: bool = False
    auth_level: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'scope': self.scope,
            'has_token': self.has_token,
            'is_valid': self.is_valid,
            'expires_at': self.expires_at,
            'has_refresh_token': self.has_refresh_token,
            'auth_level': self.auth_level
        }


@dataclass
class AuthStatus:
    """Complete authentication status for a provider"""
    # Core identification
    provider_name: str
    provider_label: str
    country: str

    # Authentication
    auth_type: str
    auth_state: AuthState

    # Readiness
    is_ready: bool
    readiness_reason: Optional[str] = None

    # Tokens
    primary_token_scope: Optional[str] = None
    token_scopes: Dict[str, TokenInfo] = field(default_factory=dict)
    has_valid_token: bool = False

    # Credentials
    requires_stored_credentials: bool = True
    has_credentials: bool = False
    credentials_type: Optional[str] = None

    # Metadata
    timestamp: float = field(default_factory=time.time)
    last_authentication: Optional[float] = None
    provider_specific: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to API response format"""
        result = {
            # Identification
            'provider': f"{self.provider_name}_{self.country}",
            'provider_name': self.provider_name,
            'provider_label': self.provider_label,
            'country': self.country,

            # Authentication
            'auth_type': self.auth_type,
            'auth_state': self.auth_state.value,

            # Readiness
            'is_ready': self.is_ready,
            'readiness_reason': self.readiness_reason,

            # Tokens
            'primary_token_scope': self.primary_token_scope,
            'has_valid_token': self.has_valid_token,
            'token_scopes': {
                scope: token.to_dict()
                for scope, token in self.token_scopes.items()
            },

            # Credentials
            'requires_stored_credentials': self.requires_stored_credentials,
            'has_credentials': self.has_credentials,
            'credentials_type': self.credentials_type,

            # Metadata
            'timestamp': self.timestamp,
            'last_authentication': self.last_authentication,
            'provider_specific': self.provider_specific
        }

        # Add state description
        descriptions = {
            AuthState.NOT_AUTHENTICATED: "Not authenticated",
            AuthState.AUTHENTICATED: "Successfully authenticated",
            AuthState.EXPIRED: "Authentication expired",
            AuthState.PENDING: "Authentication in progress",
            AuthState.ERROR: "Authentication error",
            AuthState.NOT_APPLICABLE: "Authentication not required"
        }
        result['auth_state_description'] = descriptions.get(self.auth_state, "Unknown state")

        return result