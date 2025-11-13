# streaming_providers/base/auth/credentials.py
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, Optional


@dataclass
class BaseCredentials(ABC):
    """
    Base class for authentication credentials
    """

    @abstractmethod
    def validate(self) -> bool:
        """Validate credentials"""
        pass

    @abstractmethod
    def to_auth_payload(self) -> Dict[str, Any]:
        """Convert credentials to authentication payload"""
        pass

    @property
    @abstractmethod
    def credential_type(self) -> str:
        """Return the type of credentials for storage identification"""
        pass


@dataclass
class UserPasswordCredentials(BaseCredentials):
    """
    Username/password based credentials
    """
    username: str
    password: str
    client_id: Optional[str] = None
    grant_type: str = 'password'

    def validate(self) -> bool:
        """Validate username/password credentials"""
        return bool(self.username and self.password)

    def to_auth_payload(self) -> Dict[str, Any]:
        """Convert to authentication payload"""
        payload = {
            'grant_type': self.grant_type,
            'username': self.username,
            'password': self.password
        }
        if self.client_id:
            payload['client_id'] = self.client_id
        return payload

    @property
    def credential_type(self) -> str:
        return "user_password"


@dataclass
class ClientCredentials(BaseCredentials):
    """
    Client credentials (client_id/client_secret) based authentication
    """
    client_id: str
    client_secret: Optional[str] = ""
    grant_type: str = 'client_credentials'

    def validate(self) -> bool:
        """Validate client credentials"""
        return bool(self.client_id and self.client_secret)

    def to_auth_payload(self) -> Dict[str, Any]:
        """Convert to authentication payload"""
        return {
            'grant_type': self.grant_type,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }

    @property
    def credential_type(self) -> str:
        return "client_credentials"
