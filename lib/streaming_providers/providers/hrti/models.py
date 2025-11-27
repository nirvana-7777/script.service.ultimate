# [file name]: models.py
# [file content begin]
# streaming_providers/providers/hrti/models.py
from dataclasses import dataclass
from typing import Dict, Any, Optional

from ...base.auth.base_auth import BaseAuthToken
from ...base.auth.credentials import UserPasswordCredentials
from .constants import HRTiDefaults


@dataclass
class HRTiCredentials(UserPasswordCredentials):
    """
    HRTi specific username/password credentials
    """

    def __init__(self, username: str, password: str):
        super().__init__(username=username, password=password)
        # credential_type is not a property in base class, so we don't set it

    def to_auth_payload(self) -> Dict[str, Any]:
        """Convert to authentication payload for HRTi"""
        return {
            "Username": self.username,
            "Password": self.password,
            "OperatorReferenceId": HRTiDefaults.OPERATOR_REFERENCE_ID
        }

    def validate(self) -> bool:
        """Validate HRTi credentials"""
        return bool(self.username and self.password)


class HRTiAuthToken(BaseAuthToken):
    """
    HRTi specific authentication token
    """

    def __init__(self, access_token: str, token_type: str, expires_in: int,
                 issued_at: float, user_id: str = '', valid_from: str = '',
                 valid_to: str = '', refresh_token: Optional[str] = None):

        super().__init__(
            access_token=access_token,
            token_type=token_type,
            expires_in=expires_in,
            issued_at=issued_at,
            refresh_token=refresh_token
        )

        # HRTi specific fields
        self.user_id = user_id
        self.valid_from = valid_from
        self.valid_to = valid_to
        # Don't set credential_type - it's not in base class

    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary"""
        base_dict = {
            'access_token': self.access_token,
            'token_type': self.token_type,
            'expires_in': self.expires_in,
            'issued_at': self.issued_at,
            'refresh_token': self.refresh_token or ""
        }

        # Add HRTi specific fields
        base_dict.update({
            'user_id': self.user_id,
            'valid_from': self.valid_from,
            'valid_to': self.valid_to
        })

        # Add auth_level if available
        if hasattr(self, 'auth_level') and self.auth_level:
            base_dict['auth_level'] = self.auth_level.value

        return base_dict

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HRTiAuthToken':
        """Create token from dictionary"""
        return cls(
            access_token=data['access_token'],
            token_type=data.get('token_type', 'Client'),
            expires_in=data.get('expires_in', 86400),
            issued_at=data.get('issued_at', 0),
            user_id=data.get('user_id', ''),
            valid_from=data.get('valid_from', ''),
            valid_to=data.get('valid_to', ''),
            refresh_token=data.get('refresh_token')
        )

    def is_valid(self) -> bool:
        """Check if token is still valid"""
        import time
        if not self.access_token:
            return False

        # Basic expiration check
        current_time = time.time()
        buffer_time = 300  # 5 minutes buffer

        return current_time < (self.issued_at + self.expires_in - buffer_time)


@dataclass
class HRTiChannel:
    """
    HRTi channel information
    """
    id: str
    name: str
    reference_id: str
    streaming_url: str
    icon_url: str
    is_radio: bool = False
    description: Optional[str] = None
    sort_order: int = 0

    def __post_init__(self):
        """Validate channel data after initialization"""
        if not self.id or not self.name or not self.reference_id:
            raise ValueError("Channel must have id, name, and reference_id")

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> 'HRTiChannel':
        """Create channel from API response data"""
        return cls(
            id=data.get('ReferenceId', ''),
            name=data.get('Name', ''),
            reference_id=data.get('ReferenceId', ''),
            streaming_url=data.get('StreamingURL', ''),
            icon_url=data.get('Icon', ''),
            is_radio=data.get('Radio', False),
            description=data.get('Description'),
            sort_order=data.get('SortOrder', 0)
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert channel to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'reference_id': self.reference_id,
            'streaming_url': self.streaming_url,
            'icon_url': self.icon_url,
            'is_radio': self.is_radio,
            'description': self.description,
            'sort_order': self.sort_order
        }


@dataclass
class HRTiEpgEntry:
    """
    HRTi EPG (Electronic Program Guide) entry
    """
    reference_id: str
    title: str
    description_short: str
    description_long: str
    start_time: str
    end_time: str
    image_url: str
    channel_reference_id: str
    content_rating: Optional[str] = None
    episode_number: Optional[str] = None
    season_number: Optional[str] = None

    @classmethod
    def from_api_response(cls, data: Dict[str, Any], channel_id: str) -> 'HRTiEpgEntry':
        """Create EPG entry from API response"""
        return cls(
            reference_id=data.get('ReferenceId', ''),
            title=data.get('Title', ''),
            description_short=data.get('DescriptionShort', ''),
            description_long=data.get('DescriptionLong', ''),
            start_time=data.get('TimeStart', ''),
            end_time=data.get('TimeEnd', ''),
            image_url=data.get('ImagePath', ''),
            channel_reference_id=channel_id,
            content_rating=data.get('ContentRating'),
            episode_number=data.get('EpisodeNr'),
            season_number=data.get('SeasonNr')
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert EPG entry to dictionary"""
        return {
            'reference_id': self.reference_id,
            'title': self.title,
            'description_short': self.description_short,
            'description_long': self.description_long,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'image_url': self.image_url,
            'channel_reference_id': self.channel_reference_id,
            'content_rating': self.content_rating,
            'episode_number': self.episode_number,
            'season_number': self.season_number
        }


@dataclass
class HRTiSession:
    """
    HRTi playback session information
    """
    session_id: str
    authorized: bool
    drm_id: str
    channel_reference_id: str
    content_reference_id: str

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> 'HRTiSession':
        """Create session from API response"""
        return cls(
            session_id=data.get('SessionId', ''),
            authorized=data.get('Authorized', False),
            drm_id=data.get('DrmId', ''),
            channel_reference_id=data.get('ChannelReferenceId', ''),
            content_reference_id=data.get('ContentReferenceId', '')
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary"""
        return {
            'session_id': self.session_id,
            'authorized': self.authorized,
            'drm_id': self.drm_id,
            'channel_reference_id': self.channel_reference_id,
            'content_reference_id': self.content_reference_id
        }
# [file content end]