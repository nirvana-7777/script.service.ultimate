# streaming_providers/base/auth/__init__.py
from .base_auth import BaseAuthenticator, BaseAuthToken
from .base_oauth2_auth import (
    BaseOAuth2Authenticator,
    OAuth2Error,
    OIDCConfiguration,
    SessionAwareHTTPManager,
)
from .credential_manager import CredentialManager
from .credentials import BaseCredentials, ClientCredentials, UserPasswordCredentials
from .session_manager import SessionManager
from .remote_login_extension import OAuth2RemoteLoginMixin
from .remote_login_manager import RemoteLoginManager, RemoteLoginSession

# Only export what consumers should use
__all__ = [
    "BaseAuthenticator",
    "BaseAuthToken",
    "BaseCredentials",
    "UserPasswordCredentials",
    "ClientCredentials",
    "SessionManager",
    "CredentialManager",
    # OAuth2 base
    "BaseOAuth2Authenticator",
    "OAuth2Error",
    "OIDCConfiguration",
    "SessionAwareHTTPManager",
    # Remote login
    "RemoteLoginManager",
    "RemoteLoginSession",
    "OAuth2RemoteLoginMixin",
]
