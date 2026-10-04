# streaming_providers/providers/simplitv/models.py
"""
simpliTV models.

A custom Channel subclass carries extra provider metadata (codename,
logo, recording id/status). Base fields are preserved; extras are
appended.

No custom AuthToken subclass: the token is a plain opaque string, and
the device key is discovered via GetDevices (registered only if the
account has none) -- see auth.py for the two-step flow.
"""

from dataclasses import dataclass
from typing import Any, Dict

from ...base.models import Channel


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