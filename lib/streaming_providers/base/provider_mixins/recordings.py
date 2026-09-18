"""Provider recording (cloud/network PVR) mixin."""

from typing import List

from ..models.recording import Recording


class ProviderRecordingsMixin:
    @property
    def implements_recordings(self) -> bool:
        """
        True if this provider can return recorded content.

        Return False (default) for providers that only offer live or VOD content.
        RecordingOperations skips providers where this returns False when
        aggregating across all providers.
        """
        return False

    def get_recordings(
            self,
            include_deleted: bool = False,
            **kwargs,
    ) -> List[Recording]:
        """
        Return recordings available for the authenticated user.

        Args:
            include_deleted: If True, also return recordings marked as deleted
                             (useful for a trash/recycle-bin view).
            **kwargs: Provider-specific filtering options.

        Returns:
            List of Recording objects, or [] if recordings are not supported.
        """
        return []

    def delete_recording(self, recording_id: str, **kwargs) -> None:
        """
        Permanently delete a recording on the provider's backend.

        Args:
            recording_id: The recording to delete (== content_id on the model).
            **kwargs:     Provider-specific arguments.

        Returns:
            None on success.

        Raises:
            KeyError:     If no recording with this ID exists.
            RuntimeError: If the provider refuses the deletion (e.g. the
                          recording is currently being captured, or the user
                          lacks permission).

        Default implementation raises NotImplementedError so misconfigured
        providers fail loudly rather than silently doing nothing.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not implement delete_recording(). "
            "Override this method to support recording deletion."
        )