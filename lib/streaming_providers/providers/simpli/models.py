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

Field-name notes
----------------
Content declares `content_id` (not `channel_id`) and `provider` as
required fields. Channel adds a `channel_id` *property* that proxies to
`content_id`, but dataclass __init__ assigns to declared fields
directly and does not invoke properties -- constructors must therefore
use `content_id=` and `provider=`.

Content already declares `logo_url`. It is deliberately NOT re-declared
here: re-declaring a parent dataclass field in a subclass shadows it and
can reorder the generated __init__ parameters. Inheriting it is the
correct behaviour.
"""

from dataclasses import dataclass
from typing import Any, Dict

from ...base.auth.base_auth import BaseAuthToken
from ...base.models import Channel
from ...base.models.recording import Recording


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

    Live channels: content_id is "live:<codename>", `codename` is the
    channel codename, `recording_id` is empty. Names and logos are
    derived from the codename (see logos.py).

    Recordings: content_id is "rec:<programme codename>" (the id used
    to play the recording), `codename` is that programme codename, and
    `recording_id` is the provider's recording id (what
    delete_recording takes). The two are different namespaces and must
    not be conflated. `recording_status` is "Recorded", "Scheduled" or
    "Failed"; only "Recorded" is playable.
    """

    codename: str = ""
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
        result["CurrentProgramme"] = self.current_programme
        result["CurrentStart"] = self.current_start
        result["CurrentStop"] = self.current_stop
        result["IsNpvrEnabled"] = self.is_npvr_enabled
        result["IsSeriesRecordingEnabled"] = self.is_series_recording_enabled
        result["IsCatchupEnabled"] = self.is_catchup_enabled
        result["RecordingId"] = self.recording_id
        result["RecordingStatus"] = self.recording_status
        return result

@dataclass
class SimpliTVRecording(Recording):
    """
    One NPvR recording.

    Inherits Recording (not Channel): RecordingOperations filters on
    `is_deleted`, and the legacy mixin is typed List[Recording].

    Ids (two namespaces):
        content_id  "rec:<programme codename>" -- plays the recording
                    (get_manifest / get_drm) AND is what clients hold, since
                    Recording.recording_id is an alias of content_id.
        remote_id   the provider's recordingId -- what DeleteRecording takes.
                    SimpliTVRecordingsManager.delete_recording accepts either.

    remote_status is the raw API status ("Recorded", "Scheduled",
    "Failed"); `status` is the mapped RecordingStatus. Only "Recorded" is
    playable. to_dict() keeps the keys the former SimpliTVChannel-based
    recordings emitted (Codename, RecordingId, RecordingStatus,
    CurrentStart, CurrentStop).
    """

    codename: str = ""
    remote_id: str = ""
    remote_status: str = ""
    current_start: str = ""
    current_stop: str = ""

    @property
    def is_playable(self) -> bool:
        return self.remote_status == "Recorded"

    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        result["Codename"] = self.codename
        result["CurrentProgramme"] = self.name
        result["CurrentStart"] = self.current_start
        result["CurrentStop"] = self.current_stop
        result["RecordingId"] = self.remote_id
        result["RecordingStatus"] = self.remote_status
        return result
