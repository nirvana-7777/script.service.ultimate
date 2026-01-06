# streaming_providers/base/drm/drm_plugin.py
from abc import ABC, abstractmethod
from typing import Optional

from ..models.drm_models import DRMConfig, DRMSystem, PSSHData


class DRMPlugin(ABC):
    """
    Abstract base class for DRM configuration plugins.

    Plugins can register to process DRM configs for specific DRM systems
    and transform them before they are returned to the caller.
    """

    @property
    @abstractmethod
    def plugin_name(self) -> str:
        """Return the unique plugin name"""
        pass

    @property
    @abstractmethod
    def supported_drm_system(self) -> DRMSystem:
        """Return the DRM system this plugin processes"""
        pass

    @abstractmethod
    def process_drm_config(
        self, drm_config: DRMConfig, pssh_data: Optional[PSSHData], **kwargs
    ) -> Optional[DRMConfig]:
        """
        Process and transform a DRM configuration.

        Args:
            drm_config: The DRM config to process (guaranteed to match supported_drm_system)
            pssh_data: The PSSH data for this DRM system from the manifest, or None if not available
            **kwargs: Additional context from the original method call

        Returns:
            Transformed DRMConfig, or None if the config should be filtered out

        Raises:
            Exception: Any exception will be caught and logged, plugin will be skipped
        """
        pass
