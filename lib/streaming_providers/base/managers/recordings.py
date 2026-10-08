# streaming_providers/base/managers/recordings.py
"""
RecordingsManager ABC.

Public interface
----------------
    handles_recording_id(recording_id)                  -> bool            [concrete]
    get_recordings(**kw)                                -> List[Recording] [abstract]
    delete_recording(recording_id, **kw)                -> None            [abstract]
    schedule_recording(content_id, **kw)                -> Recording|bool  [concrete, optional]

Constructor contract
--------------------
Four required keyword-only collaborators. No **kwargs. Subclasses accept
extra keyword-only args explicitly and call super().__init__ with only
the four required.

Return-value conventions
------------------------
get_recordings returns [] when the provider has no recordings. Callers
should treat an empty list as "no recordings", not as an error.

delete_recording raises ItemNotFoundError (also a KeyError) when the
recording does not exist, and ProviderError subclasses (usually ServerError
/ EntitlementError / OperationFailedError) on transport or permission
failures. Returning silently on a failed delete would hide real errors.

schedule_recording is optional -- the ABC provides a default that raises
UnsupportedOperationError, and supports_scheduling is False. Providers that
support scheduling override both.

Recording identity
------------------
A recording is identified by its provider-side recording_id, which is a
distinct namespace from content_id. Some providers use the same value
for both; some do not. The ABC treats them as separate parameters so
that distinction is preserved.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, List

from ..errors import UnsupportedOperationError
from ..models.recording import Recording
from ._base import ManagerBase


class RecordingsManager(ManagerBase):
    """
    Abstract base for provider recordings managers.

    Recording identity
    ------------------
    A recording is identified by its provider-side recording_id, which
    is a distinct namespace from content_id. Some providers use the same
    value for both; some do not. The ABC treats them as separate
    parameters so that distinction is preserved.

    No manifest method
    ------------------
    This ABC deliberately has no get_manifest method. Recordings are
    played via the same content_id that a channel or VOD manager
    resolves -- the provider's router decides which manager owns the
    manifest fetch. Some providers resolve a recording's manifest
    through their ChannelManager (the API shares the codename
    namespace between a channel and its recordings, as simpliTV does);
    others may route through VodManager or a dedicated playback path.
    The recordings manager's job is the *list* and the *delete*, not
    the playback URL.

    Providers that need a recording's manifest should implement the
    routing in their provider's get_manifest, not by adding a
    get_manifest method here. See the simpliTV provider's provider.py
    for the pattern.
    """

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def handles_recording_id(self, recording_id: str) -> bool:
        """
        True if this manager can handle the given recording_id.

        Default: True. Override in providers whose recording IDs have a
        distinguishable prefix or format, so a router can dispatch
        without a wasted request. Not used by the base provider; a
        provider that surfaces recordings through multiple managers can
        consult this to route delete/update calls.
        """
        return True

    # ------------------------------------------------------------------
    # Abstract
    # ------------------------------------------------------------------

    @abstractmethod
    def get_recordings(self, **kw: Any) -> List[Recording]:
        """
        Return recordings for the authenticated user.

        Return [] when the provider has no recordings. Do NOT raise
        NotFoundError for "no recordings" -- that is a valid empty
        result, not a missing resource.

        Items MUST be models.recording.Recording (or a subclass).
        RecordingOperations filters on ``Recording.is_deleted`` and the
        legacy mixin is typed List[Recording]; a bare Channel has no
        ``is_deleted`` and breaks that filter.

        ``include_deleted`` arrives in **kw (RecordingOperations always
        passes it). Honour it when the backend can list deleted items;
        otherwise ignore it -- the caller filters again.

        Providers whose recordings carry extra fields subclass Recording and
        document them in the subclass's docstring.
        """
        raise NotImplementedError

    @abstractmethod
    def delete_recording(self, recording_id: str, **kw: Any) -> None:
        """
        Delete a recording.

        Raises:
            ItemNotFoundError: if the recording does not exist (also a
                               KeyError).
            ProviderError:     on transport / permission / server failure.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Concrete -- optional
    # ------------------------------------------------------------------

    @property
    def supports_scheduling(self) -> bool:
        """
        True when schedule_recording() is implemented. Default False.

        Providers that override schedule_recording MUST also override this
        to return True, so callers can gate the UI instead of catching
        UnsupportedOperationError.
        """
        return False

    def schedule_recording(self, content_id: str, **kw: Any) -> Any:
        """
        Schedule a recording of content_id.

        Optional. Return value is provider-specific: some providers
        return the created recording (a Recording), others return a bool
        indicating success. The ABC does not constrain the shape
        because there is no shared one across providers.

        Default raises UnsupportedOperationError (a NotImplementedYetError
        subclass, so old handlers still match). "Not supported by this
        provider" is not the same as "planned, not done yet". Providers
        that support scheduling override this AND supports_scheduling.
        """
        raise UnsupportedOperationError(
            f"{self.__class__.__name__} does not support schedule_recording"
        )