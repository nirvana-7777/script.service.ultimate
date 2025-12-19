# streaming_providers/providers/auth_context.py
from typing import Optional, List, Dict, Any


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

    def get_token(self, provider_name: str, scope: str = None,
                  country: str = None) -> Optional[Dict[str, Any]]:
        """Get token for provider (scoped or root-level)"""
        if not self.session:
            return None

        if scope:
            return self.session.load_scoped_token(provider_name, scope, country)
        else:
            return self.session.load_token_data(provider_name, country)

    def get_all_scopes(self, provider_name: str, country: str = None) -> List[str]:
        """Get all token scopes for provider"""
        if not self.session:
            return []

        if hasattr(self.session, 'list_scoped_tokens'):
            return self.session.list_scoped_tokens(provider_name, country)

        return []

    def is_token_expired(self, token_data):
        """Check if token is expired"""
        if self.session and hasattr(self.session, '_is_token_expired'):
            return self.session._is_token_expired(token_data)
        return True  # Conservative default