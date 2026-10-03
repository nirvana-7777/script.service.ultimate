# streaming_providers/base/managers/recordings.py
"""
RecordingsManager ABC.

Public interface
----------------
    handles_recording_id(recording_id)                  -> bool            [concrete]
    get_recordings(**kw)                                -> List[Channel]   [abstract]
    delete_recording(recording_id, **kw)                -> None            [abstract]
    schedule_recording(content_id, **kw)                -> Channel|bool    [concrete, optional]

Constructor contract
--------------------
Four required keyword-only collaborators. No **kwargs. Subclasses accept
extra keyword-only args explicitly and call super().__init__ with only
the four required.

Return-value conventions
------------------------
get_recordings returns [] when the provider has no recordings. Callers
should treat an empty list as "no recordings", not as an error.

delete_recording raises KeyError when the recording does not exist, and
ProviderError subclasses (usually ServerError / EntitlementError) on
transport or permission failures. Returning silently on a failed delete
would hide real errors.

schedule_recording is optional -- the ABC provides a default that raises
NotImplementedYetError. Providers that support scheduling override it.

Recording identity
------------------
A recording is identified by its provider-side recording_id, which is a
distinct namespace from content_id. Some providers use the same value
for both; some do not. The ABC treats them as separate parameters so
that distinction is preserved.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, List

from ..errors import NotImplementedYetError
from ..models import Channel
from ..protocols import AuthProtocol
from ..utils.logger import logger


class RecordingsManager(ABC):
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
    get_manifest method here. See providers/simplitv/provider.py for
    the pattern.
    """

    def __init__(
        self,
        *,
        http_manager: Any,
        auth: AuthProtocol,
        country: str,
        config: Any,
    ) -> None:
        if not isinstance(auth, AuthProtocol):
            logger.warning(
                f"{self.__class__.__name__}: auth does not match AuthProtocol "
                f"(missing one of get_access_token / build_headers / "
                f"invalidate). Got {type(auth).__name__}."
            )
        self.http_manager = http_manager
        self.auth = auth
        self.country = country
        self.config = config

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
    def get_recordings(self, **kw: Any) -> List[Channel]:
        """
        Return recordings for the authenticated user.

        Return [] when the provider has no recordings. Do NOT raise
        NotFoundError for "no recordings" -- that is a valid empty
        result, not a missing resource.

        Recording objects are returned as Channel instances (or a
        Channel subclass carrying extra fields such as recording_id,
        start/stop times, and the underlying content_id). The base
        Channel shape is preserved because downstream callers expect a
        content_id and a name.

        Providers whose recordings are conceptually distinct from their
        channels (e.g. cloud-PVR recordings that store their own
        programme metadata) should subclass Channel with the extra
        fields they need, and document them in the subclass's docstring.
        """
        raise NotImplementedError

    @abstractmethod
    def delete_recording(self, recording_id: str, **kw: Any) -> None:
        """
        Delete a recording.

        Raises:
            KeyError:      if the recording does not exist.
            ProviderError: on transport / permission / server failure.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Concrete -- optional
    # ------------------------------------------------------------------

    def schedule_recording(self, content_id: str, **kw: Any) -> Any:
        """
        Schedule a recording of content_id.

        Optional. Return value is provider-specific: some providers
        return the created recording (a Channel), others return a bool
        indicating success. The ABC does not constrain the shape
        because there is no shared one across providers.

        Default raises NotImplementedYetError. Providers that support
        scheduling override this.
        """
        raise NotImplementedYetError(
            f"{self.__class__.__name__}.schedule_recording is not "
            f"implemented"
        )