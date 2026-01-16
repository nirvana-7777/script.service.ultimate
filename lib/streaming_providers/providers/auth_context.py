# streaming_providers/providers/auth_context.py
from typing import Any, Dict, List, Optional


class AuthContext:
    """
    Context passed to providers for accessing shared services.
    Simple wrapper around SettingsManager.
    """

    def __init__(self, settings_manager):
        self.settings = settings_manager
        self.session = settings_manager.session_manager if settings_manager else None
        self.credentials = settings_manager.credential_manager if settings_manager else None

    def get_credentials(self, provider_name: str, country: str = None) -> Optional[Any]:
        """Get credentials for provider"""
        if self.settings:
            return self.settings.get_provider_credentials(provider_name, country)
        return None

    def get_token(
        self, provider_name: str, scope: str = None, country: str = None
    ) -> Optional[Dict[str, Any]]:
        """
        Get token for provider (scoped or root-level).

        Now with fallback: tries with country first, then without country
        for backward compatibility with tokens stored without country nesting.

        Args:
            provider_name: Provider name
            scope: Optional token scope
            country: Optional country code

        Returns:
            Token data dictionary or None
        """
        if not self.session:
            return None

        # Try with country first (new format)
        if country:
            if scope:
                token = self.session.load_scoped_token(provider_name, scope, country)
            else:
                token = self.session.load_token_data(provider_name, country)

            if token:
                return token

            # Fallback: try without country (legacy format)
            # This handles tokens stored as {"provider": {...}} instead of {"provider": {"country": {...}}}
            if scope:
                token = self.session.load_scoped_token(provider_name, scope, None)
            else:
                token = self.session.load_token_data(provider_name, None)

            return token

        # No country specified - direct lookup
        if scope:
            return self.session.load_scoped_token(provider_name, scope, None)
        else:
            return self.session.load_token_data(provider_name, None)

    def get_all_scopes(self, provider_name: str, country: str = None) -> List[str]:
        """Get all token scopes for provider"""
        if not self.session:
            return []

        if hasattr(self.session, "list_scoped_tokens"):
            return self.session.list_scoped_tokens(provider_name, country)

        return []

    def is_token_expired(self, token_data):
        """Check if token is expired"""
        if self.session and hasattr(self.session, "_is_token_expired"):
            return self.session._is_token_expired(token_data)
        return True  # Conservative default
