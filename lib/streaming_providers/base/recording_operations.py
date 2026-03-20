# streaming_providers/base/recording_operations.py
"""
Recording-related operations separated from core registry.
Mirrors the structure of EventOperations.
"""

from typing import Dict, List, Optional

from .models.recording import Recording
from .utils.logger import logger


class RecordingOperations:
    """Handles all recording-related operations."""

    def __init__(self, registry):
        self.registry = registry
        logger.debug("RecordingOperations: Initialized")

    def get_recordings(
        self,
        provider_name: str,
        include_deleted: bool = False,
    ) -> List[Recording]:
        """
        Get recordings from a specific provider.

        Args:
            provider_name: Name of the provider to query.
            include_deleted: If True, include recordings marked as deleted.

        Returns:
            List of Recording objects.

        Raises:
            ValueError: If the provider is not found or disabled.
        """
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        recordings = provider.get_recordings(include_deleted=include_deleted)

        if not include_deleted:
            recordings = [r for r in recordings if not r.is_deleted]

        logger.info(
            f"Retrieved {len(recordings)} recordings from '{provider_name}'"
        )
        return recordings

    def get_all_recordings(
        self,
        include_deleted: bool = False,
    ) -> Dict[str, List[Recording]]:
        """
        Get recordings from all enabled providers.

        Args:
            include_deleted: If True, include recordings marked as deleted.

        Returns:
            Dict mapping provider name → list of Recording objects.
        """
        enabled = self.registry.get_enabled_providers()
        logger.info(f"Fetching recordings from {len(enabled)} providers")

        result = {}
        total = 0

        for name in enabled:
            try:
                recordings = self.get_recordings(
                    name, include_deleted=include_deleted
                )
                result[name] = recordings
                total += len(recordings)
            except Exception as e:
                logger.error(f"Failed to get recordings from '{name}': {e}")
                result[name] = []

        logger.info(f"Retrieved {total} total recordings")
        return result

    def get_recording_manifest(
        self, provider_name: str, recording_id: str, **kwargs
    ) -> Optional[str]:
        """
        Get manifest URL for a specific recording.

        Delegates to provider.get_manifest() — the same method used for
        channels and events — because manifest resolution is content-type-agnostic.

        Args:
            provider_name: Name of the provider.
            recording_id: Recording identifier (== content_id on the model).
            **kwargs: Additional provider-specific arguments.

        Returns:
            Manifest URL string, or None if unavailable.

        Raises:
            ValueError: If the provider is not found or disabled.
        """
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        manifest_url = provider.get_manifest(content_id=recording_id, **kwargs)
        if manifest_url:
            logger.debug(
                f"Retrieved manifest for recording '{recording_id}' "
                f"from '{provider_name}'"
            )
        return manifest_url

    def delete_recording(
        self, provider_name: str, recording_id: str, **kwargs
    ) -> None:
        """
        Permanently delete a recording on the provider.

        Delegates to provider.delete_recording(recording_id).  The provider is
        responsible for the actual API call; this layer only resolves the
        provider instance and handles registry-level errors.

        Args:
            provider_name: Name of the provider.
            recording_id:  Recording identifier (== content_id on the model).
            **kwargs:      Additional provider-specific arguments.

        Returns:
            None on success.

        Raises:
            ValueError:   If the provider is not found or disabled.
            KeyError:     If the recording does not exist on the provider.
            RuntimeError: If the provider rejects the deletion (e.g. permission
                          denied, recording currently in progress).
        """
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")

        provider.delete_recording(recording_id, **kwargs)
        logger.info(
            f"Deleted recording '{recording_id}' from '{provider_name}'"
        )