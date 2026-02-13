"""
DRM Configuration Model

Main configuration class that combines DRM system, PSSH data, and license config.
"""

from dataclasses import dataclass
from typing import Optional

from .drm_systems import DRMSystem
from .license_config import LicenseConfig
from .exceptions import LicenseConfigError


@dataclass
class DRMConfig:
    """
    Complete DRM Configuration.

    Combines DRM system identification with license configuration
    for a single DRM system.

    Attributes:
        system: DRM system type
        priority: Priority for multi-DRM scenarios (higher = preferred)
        license: License server configuration (optional for unencrypted)
    """

    system: DRMSystem
    priority: int = 0
    license: Optional[LicenseConfig] = None

    def validate(self) -> None:
        """
        Validate the DRM configuration.

        Raises:
            LicenseConfigError: If configuration is invalid
        """
        if not isinstance(self.system, DRMSystem):
            raise LicenseConfigError(
                f"system must be a DRMSystem enum, got {type(self.system)}"
            )

        if self.license:
            self.license.validate()

    def to_dict(self) -> dict:
        """
        Convert to dictionary format expected by players.

        Returns:
            Dictionary with DRM configuration in player-compatible format:
            {
                "com.widevine.alpha": {
                    "priority": 1,
                    "license": {...}
                }
            }
        """
        result = {
            self.system.value: {
                "priority": self.priority
            }
        }

        if self.license:
            license_dict = self.license.to_dict()
            if license_dict:
                result[self.system.value]["license"] = license_dict

        return result

    @classmethod
    def create_widevine(
            cls,
            server_url: str,
            priority: int = 1,
            **license_kwargs
    ) -> "DRMConfig":
        """
        Helper to create Widevine DRM configuration.

        Args:
            server_url: Widevine license server URL
            priority: Priority (default: 1)
            **license_kwargs: Additional LicenseConfig parameters

        Returns:
            DRMConfig instance for Widevine
        """
        license_config = LicenseConfig(server_url=server_url, **license_kwargs)
        return cls(system=DRMSystem.WIDEVINE, priority=priority, license=license_config)

    @classmethod
    def create_playready(
            cls,
            server_url: str,
            priority: int = 1,
            **license_kwargs
    ) -> "DRMConfig":
        """
        Helper to create PlayReady DRM configuration.

        Args:
            server_url: PlayReady license server URL
            priority: Priority (default: 1)
            **license_kwargs: Additional LicenseConfig parameters

        Returns:
            DRMConfig instance for PlayReady
        """
        license_config = LicenseConfig(server_url=server_url, **license_kwargs)
        return cls(system=DRMSystem.PLAYREADY, priority=priority, license=license_config)

    @classmethod
    def create_clearkey(
            cls,
            keyids: dict[str, str],
            priority: int = 0,
            **license_kwargs
    ) -> "DRMConfig":
        """
        Helper to create ClearKey DRM configuration.

        Args:
            keyids: Mapping of Key IDs to Keys (hex strings)
            priority: Priority (default: 0)
            **license_kwargs: Additional LicenseConfig parameters

        Returns:
            DRMConfig instance for ClearKey
        """
        license_config = LicenseConfig(keyids=keyids, **license_kwargs)
        return cls(system=DRMSystem.CLEARKEY, priority=priority, license=license_config)

    @classmethod
    def create_fairplay(
            cls,
            server_url: str,
            server_certificate: str,
            priority: int = 1,
            **license_kwargs
    ) -> "DRMConfig":
        """
        Helper to create FairPlay DRM configuration.

        Args:
            server_url: FairPlay license server URL (skd://)
            server_certificate: Base64-encoded FairPlay certificate
            priority: Priority (default: 1)
            **license_kwargs: Additional LicenseConfig parameters

        Returns:
            DRMConfig instance for FairPlay
        """
        license_config = LicenseConfig(
            server_url=server_url,
            server_certificate=server_certificate,
            **license_kwargs
        )
        return cls(system=DRMSystem.FAIRPLAY, priority=priority, license=license_config)

    def __repr__(self) -> str:
        """Return detailed representation."""
        has_license = "with license" if self.license else "no license"
        return (
            f"<DRMConfig({self.system.name}, priority={self.priority}, {has_license})>"
        )