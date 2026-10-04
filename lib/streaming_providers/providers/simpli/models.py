# streaming_providers/providers/simpli/models.py
"""
simpliTV models.

A custom Channel subclass carries extra provider metadata (codename,
logo, recording id/status). Base fields are preserved; extras are
appended.

A custom AuthToken subclass exists because BaseAuthToken is an ABC with
an abstract to_dict() -- it cannot be instantiated directly, so the
provider needs a concrete subclass. The simpliTV token is a plain opaque
UUID with no refresh flow, so to_dict() is only the storage contract
required by BaseAuthenticator._save_session(); the provider does not
persist sessions.
"""

from dataclasses import dataclass
from typing import Any, Dict

from ...base.auth.base_auth import BaseAuthToken
from ...base.models import Channel


@dataclass
class SimpliTVAuthToken(BaseAuthToken):
    """
    Concrete BaseAuthToken for simpliTV.

    simpliTV issues a plain opaque token (a UUID string) with no refresh
    token and no scopes. BaseAuthToken is an ABC with an abstract
    to_dict(); this subclass provides it so the provider can construct
    an instance in auth._perform_authentication().

    to_dict() is only exercised if the host persists sessions through a
    settings_manager (BaseAuthenticator._save_session). It is provided
    for completeness and compatibility; this provider does not itself
    persist tokens.
    """

    def to_dict(self) -> Dict[str, Any]:
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "issued_at": self.issued_at,
            "refresh_token": self.refresh_token,
            "refresh_expires_in": self.refresh_expires_in,
            "auth_level": self.auth_level.value,
            "credential_type": self.credential_type,
        }


@dataclass
class SimpliTVChannel(Channel):
    """
    A live channel or a recording.

    Live channels: channel_id is "live:<codename>", `codename` is the
    channel codename, `recording_id` is empty. Names and logos are
    derived from the codename (see logos.py).

    Recordings: channel_id is "rec:<programme codename>" (the content_id
    used to play the recording), `codename` is that programme codename,
    and `recording_id` is the provider's recording id (what
    delete_recording takes). The two are different namespaces and must
    not be conflated. `recording_status` is "Recorded", "Scheduled" or
    "Failed"; only "Recorded" is playable.
    """

    codename: str = ""
    logo_url: str = ""
    current_programme: str = ""
    current_start: str = ""
    current_stop: str = ""
    is_npvr_enabled: bool = False
    is_series_recording_enabled: bool = False
    is_catchup_enabled: bool = False
    recording_id: str = ""
    recording_status: str = ""

    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        result["Codename"] = self.codename
        result["LogoUrl"] = self.logo_url
        result["CurrentProgramme"] = self.current_programme
        result["CurrentStart"] = self.current_start
        result["CurrentStop"] = self.current_stop
        result["IsNpvrEnabled"] = self.is_npvr_enabled
        result["IsSeriesRecordingEnabled"] = self.is_series_recording_enabled
        result["IsCatchupEnabled"] = self.is_catchup_enabled
        result["RecordingId"] = self.recording_id
        result["RecordingStatus"] = self.recording_status
        return result