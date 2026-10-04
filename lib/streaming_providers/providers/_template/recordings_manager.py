# streaming_providers/providers/_template/recordings_manager.py
"""
{TODO: Provider name} recordings manager (optional).

Include this file only if the provider has cloud / network PVR
recordings. Providers without recordings don't create a recordings
manager -- the provider's implements_recordings is False and calls to
get_recordings return [].

See ../_template/README.md for the contract.

Reference implementation
------------------------
simpliTV's SimpliTVRecordingsManager
(providers/simplitv/recordings_manager.py) is the first example: it
returns recordings as SimpliTVChannel objects, carries recording_id
on the subclass, and paginates through /v2/Pvr/GetRecordings.

Recording identity
------------------
A recording has its own id (recording_id) distinct from the content_id
of the underlying programme. The two namespaces are usually different:
recording_id is what you pass to delete_recording, content_id is what
you pass to get_manifest to play the recording. Keep them separate.

Recordings do not participate in the content_id router (they have their
own id namespace); the manager may override handles_recording_id() when
several recordings managers exist (cloud PVR + local PVR, say).
"""

from typing import List

from ...base.managers import RecordingsManager
from ...base.models import Channel
from ...base.utils.logger import logger


class YourRecordingsManager(RecordingsManager):
    """
    Recordings for {TODO: provider name}.

    What this manager owns
    ----------------------
        get_recordings     -- the recording list
        delete_recording   -- remove one recording by recording_id
        schedule_recording -- (optional) create a new recording

    What this manager does NOT own
    ------------------------------
        Manifest fetching. A recording is played via a content_id that
        the provider's router resolves. Depending on the provider, that
        fetch might route through the ChannelManager (simpliTV shares
        the codename namespace between a channel and its recordings),
        through the VodManager, or through a dedicated playback path.

        Do not add a get_manifest method here. Route it in the
        provider's get_manifest instead. See
        providers/simplitv/provider.py for the pattern. (Two managers
        may accept the same prefix, e.g. "rec:", when their concerns
        are disjoint -- but only ONE router branch per prefix.)

    Recording identity
    ------------------
        recording_id -- what delete_recording receives. Not a content_id.
        content_id   -- what get_manifest receives to play the
                        recording. Usually a prefixed form of the
                        underlying programme's identifier.

    See ../_template/README.md for the full contract.
    """

    def __init__(
        self,
        *,
        http_manager,
        auth,
        country,
        config,
        recordings_cache=None,
    ):
        super().__init__(
            http_manager=http_manager,
            auth=auth,
            country=country,
            config=config,
        )
        self._recordings_cache = (
            recordings_cache if recordings_cache is not None else {}
        )

    # ----- Abstract methods -----

    def get_recordings(self, **kw) -> List[Channel]:
        """
        Return the user's recordings.

        Return [] when there are none. Do NOT raise for "empty".
        """
        raise NotImplementedError("YourRecordingsManager.get_recordings")

    def delete_recording(self, recording_id: str, **kw) -> None:
        """
        Delete a recording.

        Raises:
            KeyError:      if the recording doesn't exist.
            ProviderError: (a subclass from base.errors) on backend
                           failure. Never return silently on failure.
        """
        raise NotImplementedError("YourRecordingsManager.delete_recording")

    # ----- Concrete methods (optional overrides) -----

    # def schedule_recording(self, content_id: str, **kw):
    #     """
    #     Schedule a recording of content_id.
    #
    #     Override only if the provider supports scheduling.
    #     Return value is provider-specific: some providers return the
    #     created recording (a Channel), others return a bool.
    #     """
    #     ...