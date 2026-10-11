# streaming_providers/providers/example/recordings_manager.py
"""
Recordings (cloud PVR) manager skeleton.

--- WIRING ---
from .recordings_manager import ExampleRecordingsManager
def _build_recordings(self):
    return ExampleRecordingsManager(http_manager=self.http_manager, auth=self.auth,
                                    country=self.country, config=self.provider_config)
--- END WIRING ---

Contract (RecordingsManager ABC) -- the part that bites:
  * get_recordings(**kw) -> List[Recording]   (models.recording.Recording or a
    subclass). NOT Channel: RecordingOperations filters on
    `Recording.is_deleted`. `include_deleted` arrives in **kw; honour it if
    the backend can list deleted items, else ignore it.
  * Two id namespaces: content_id ("rec:<x>", what get_manifest / get_drm
    receive -- played through your CHANNEL manager, there is no manifest
    method here) and your backend's own recording id. Recording.recording_id
    is an ALIAS of content_id, so clients only hold content_id:
    delete_recording MUST accept the content_id (resolve it through your
    listing) and may also accept the backend id.
  * delete_recording raises ItemNotFoundError (also a KeyError) when the
    recording does not exist; never return silently on a failed delete.
  * schedule_recording is optional. If you implement it you MUST also
    override supports_scheduling -> True. NOTE: the legacy surface has no
    entry point for it (timers use add_timer/Timer); wire it explicitly.
  * Map your backend status onto RecordingStatus; unknown -> PENDING.
  * Recording.to_dict()["ContentType"] stays "LIVE" (known quirk, TODO D-18).
"""

from typing import Any, List

from ....base.errors import ItemNotFoundError
from ....base.managers import RecordingsManager
from ....base.models.recording import Recording


class ExampleRecordingsManager(RecordingsManager):
    def get_recordings(self, **kw: Any) -> List[Recording]:
        # TODO: return Recording objects (content_id="rec:<x>", provider=<PROVIDER_NAME>)
        return []

    def delete_recording(self, recording_id: str, **kw: Any) -> None:
        # TODO: accept "rec:<x>" (resolve via the listing) and the backend id.
        raise ItemNotFoundError(f"no recording {recording_id!r}")
