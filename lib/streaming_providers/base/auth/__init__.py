# streaming_providers/base/auth/__init__.py
from .base_auth import BaseAuthenticator, BaseAuthToken
from .credential_manager import CredentialManager
from .credentials import BaseCredentials, ClientCredentials, UserPasswordCredentials
from .session_manager import SessionManager

# Only export what consumers should use
__all__ = [
    "BaseAuthenticator",
    "BaseAuthToken",
    "BaseCredentials",
    "UserPasswordCredentials",
    "ClientCredentials",
    "SessionManager",
    "CredentialManager",
]
