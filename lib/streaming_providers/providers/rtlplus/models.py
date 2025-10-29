# streaming_providers/providers/rtlplus/models.py
from dataclasses import dataclass
from typing import Dict, Any, Optional
from ...base.auth.base_auth import BaseAuthToken
from ...base.auth.credentials import UserPasswordCredentials, ClientCredentials
from .constants import RTLPlusDefaults


@dataclass
class RTLPlusUserCredentials(UserPasswordCredentials):
    """
    RTL+ specific username/password credentials
    """

    def __init__(self, username: str, password: str, client_id: Optional[str] = None):
        super().__init__(
            username=username,
            password=password,
            client_id=client_id or RTLPlusDefaults.CLIENT_ID,
            grant_type='password'
        )

    def to_auth_payload(self) -> Dict[str, Any]:
        """Convert to authentication payload for RTL+"""
        payload = {
            'grant_type': self.grant_type,
            'username': self.username,
            'password': self.password
        }
        # RTL+ might need client_id for user auth - adjust based on API requirements
        if self.client_id:
            payload['client_id'] = self.client_id
        return payload


@dataclass
class RTLPlusClientCredentials(ClientCredentials):
    """
    RTL+ specific client credentials (anonymous access)
    """

    def __init__(self, client_id: Optional[str] = None, client_secret: Optional[str] = None):
        super().__init__(
            client_id=client_id or RTLPlusDefaults.ANONYMOUS_CLIENT_ID,
            client_secret=client_secret or RTLPlusDefaults.ANONYMOUS_CLIENT_SECRET,
            grant_type='client_credentials'
        )


class RTLPlusAuthToken(BaseAuthToken):
    """
    RTL+ specific authentication token
    """

    def __init__(self, access_token: str, token_type: str, expires_in: int,
                 issued_at: float, refresh_token: Optional[str] = None,
                 refresh_expires_in: int = 0, not_before_policy: Optional[int] = None,
                 scope: str = ""):
        # Initialize parent class with refresh_expires_in
        super().__init__(
            access_token=access_token,
            token_type=token_type,
            expires_in=expires_in,
            issued_at=issued_at,
            refresh_token=refresh_token,
            refresh_expires_in=refresh_expires_in
        )
        # RTL+ specific fields
        self.refresh_expires_in = refresh_expires_in
        self.not_before_policy = not_before_policy
        self.scope = scope

    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary"""
        return {
            'access_token': self.access_token,
            'token_type': self.token_type,
            'expires_in': self.expires_in,
            'issued_at': self.issued_at,
            'refresh_token': self.refresh_token,
            'refresh_expires_in': self.refresh_expires_in,
            'not_before_policy': self.not_before_policy,
            'scope': self.scope
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], issued_at: float) -> 'RTLPlusAuthToken':
        """Create token from dictionary response"""
        return cls(
            access_token=data['access_token'],
            token_type=data.get('token_type', 'Bearer'),
            expires_in=data.get('expires_in', 0),
            issued_at=issued_at,
            refresh_token=data.get('refresh_token'),
            refresh_expires_in=data.get('refresh_expires_in', 0),
            not_before_policy=data.get('not-before-policy'),
            scope=data.get('scope', '')
        )

    def is_valid(self) -> bool:
        """Check if token is still valid"""
        import time
        if not self.access_token:
            return False

        current_time = time.time()
        # Add small buffer (30 seconds) to account for network delays
        buffer_time = 30

        return current_time < (self.issued_at + self.expires_in - buffer_time)

    # Add this method to the RTLPlusAuthToken class in models.py
    def is_anonymous_token(self) -> bool:
        """Check if this token was obtained via anonymous authentication"""
        if not self.access_token:
            return True

        try:
            # Simple check without full JWT decoding - look for anonymous client ID pattern
            return 'anonymous-user' in self.access_token
        except:
            return False

@dataclass
class RTLPlusChannel:
    """
    RTL+ channel information
    """
    id: str
    name: str
    slug: str
    logo_url: Optional[str] = None
    description: Optional[str] = None
    is_live: bool = True
    channel_type: str = "BROADCAST"
    sort_order: int = 0

    def __post_init__(self):
        """Validate channel data after initialization"""
        if not self.id or not self.name:
            raise ValueError("Channel must have both id and name")

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> 'RTLPlusChannel':
        """Create channel from API response data"""
        return cls(
            id=data['id'],
            name=data['name'],
            slug=data.get('slug', ''),
            logo_url=data.get('logoUrl'),
            description=data.get('description'),
            is_live=data.get('isLive', True),
            channel_type=data.get('channelType', 'BROADCAST'),
            sort_order=data.get('sortOrder', 0)
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert channel to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'slug': self.slug,
            'logo_url': self.logo_url,
            'description': self.description,
            'is_live': self.is_live,
            'channel_type': self.channel_type,
            'sort_order': self.sort_order
        }


@dataclass
class RTLPlusStreamInfo:
    """
    RTL+ stream information
    """
    manifest_url: str
    channel_id: str
    drm_license_url: Optional[str] = None
    drm_key_id: Optional[str] = None
    stream_type: str = "HLS"
    quality: str = "auto"

    def __post_init__(self):
        """Validate stream info after initialization"""
        if not self.manifest_url or not self.channel_id:
            raise ValueError("Stream must have both manifest_url and channel_id")

    @classmethod
    def from_manifest_response(cls, data: Dict[str, Any], channel_id: str) -> 'RTLPlusStreamInfo':
        """Create stream info from manifest API response"""
        return cls(
            manifest_url=data['url'],
            channel_id=channel_id,
            drm_license_url=data.get('drmLicenseUrl'),
            drm_key_id=data.get('drmKeyId'),
            stream_type=data.get('type', 'HLS'),
            quality=data.get('quality', 'auto')
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert stream info to dictionary"""
        return {
            'manifest_url': self.manifest_url,
            'channel_id': self.channel_id,
            'drm_license_url': self.drm_license_url,
            'drm_key_id': self.drm_key_id,
            'stream_type': self.stream_type,
            'quality': self.quality
        }

    def has_drm(self) -> bool:
        """Check if stream has DRM protection"""
        return bool(self.drm_license_url and self.drm_key_id)