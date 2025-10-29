# streaming_providers/base/auth/__init__.py
from .base_auth import BaseAuthenticator, BaseAuthToken
from .credentials import BaseCredentials, UserPasswordCredentials, ClientCredentials
from .session_manager import SessionManager
from .credential_manager import CredentialManager

# Only export what consumers should use
__all__ = [
    'BaseAuthenticator',
    'BaseAuthToken',
    'BaseCredentials',
    'UserPasswordCredentials',
    'ClientCredentials',
    'SessionManager',
    'CredentialManager'
]