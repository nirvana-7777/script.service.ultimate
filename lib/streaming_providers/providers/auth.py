from abc import ABC, abstractmethod
from typing import Any, Dict, List

from ..base.models.auth import AuthStatus


class ProviderAuthInterface(ABC):
    """
    Interface for providers to report their authentication status.
    Providers implement only their unique logic.
    """

    def __init__(self, provider_instance):
        self.provider = provider_instance

    @abstractmethod
    def collect_auth_data(self, context) -> Dict[str, Any]:
        """
        Collect all authentication data needed for status calculation.
        This is provider-specific.

        Args:
            context: AuthContext with access to settings, sessions, etc.

        Returns:
            Dictionary with provider-specific auth data
        """
        pass

    @abstractmethod
    def build_auth_status(self, auth_data: Dict[str, Any]) -> AuthStatus:
        """
        Build AuthStatus from collected data.
        This is provider-specific.

        Args:
            auth_data: Data collected by collect_auth_data()

        Returns:
            Complete AuthStatus object
        """
        pass

    def get_status(self, context) -> AuthStatus:
        """
        Template method: collects data and builds status.
        Providers shouldn't override this unless special handling needed.
        """
        auth_data = self.collect_auth_data(context)
        return self.build_auth_status(auth_data)


class AuthContext:
    """
    Context passed to providers for accessing shared services.
    Encapsulates all external dependencies.
    """

    def __init__(self, settings_manager, session_manager, credential_manager):
        self.settings = settings_manager
        self.session = session_manager
        self.credentials = credential_manager

    def get_credentials(self, provider_name: str, country: str = None):
        return self.settings.get_provider_credentials(provider_name, country)

    def get_token(self, provider_name: str, scope: str = None, country: str = None):
        if scope:
            return self.session.load_scoped_token(provider_name, scope, country)
        else:
            return self.session.load_token_data(provider_name, country)

    def get_all_scopes(self, provider_name: str, country: str = None) -> List[str]:
        return self.session.list_scoped_tokens(provider_name, country)
