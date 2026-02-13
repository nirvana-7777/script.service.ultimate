"""
DRM System Definitions

Enum for supported DRM systems with efficient UUID and alias lookups.
"""

from enum import Enum
from functools import cached_property
from typing import Optional

from .constants import DRM_SYSTEM_NAMES, DRM_SYSTEM_UUIDS, DRM_ALIAS_MAPPING
from .utils import normalize_uuid, normalize_alias
from .exceptions import InvalidUUIDError


class DRMSystem(str, Enum):
    """
    Supported DRM Systems

    Each DRM system has:
    - A unique identifier (Android/EME format)
    - A standard UUID (ISO/IEC 23001-7)
    - Multiple aliases for flexible lookups
    """

    WIDEVINE = "com.widevine.alpha"
    PLAYREADY = "com.microsoft.playready"
    WISEPLAY = "com.huawei.wiseplay"
    CLEARKEY = "org.w3.clearkey"
    FAIRPLAY = "com.apple.fps"
    GENERIC = "generic"
    NONE = "none"

    @cached_property
    def system_uuid(self) -> str:
        """
        Get the standard UUID for this DRM system (normalized, no hyphens).

        Returns:
            32-character hex string (lowercase, no hyphens), or empty string for GENERIC/NONE
        """
        # Get enum name (e.g., 'WIDEVINE')
        enum_name = self.name
        return DRM_SYSTEM_NAMES.get(enum_name, "")

    @cached_property
    def system_uuid_formatted(self) -> str:
        """
        Get the formatted UUID with hyphens for this DRM system.

        Returns:
            UUID string with hyphens (8-4-4-4-12), or empty string for GENERIC/NONE
        """
        uuid = self.system_uuid
        if not uuid:
            return ""

        return (
            f"{uuid[0:8]}-{uuid[8:12]}-{uuid[12:16]}-"
            f"{uuid[16:20]}-{uuid[20:32]}"
        )

    @classmethod
    def from_uuid(cls, uuid: str) -> Optional["DRMSystem"]:
        """
        Get DRM system from UUID.

        Accepts any format (with or without hyphens).

        Args:
            uuid: UUID string (e.g., "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")

        Returns:
            DRMSystem enum value or None if not recognized

        Examples:
            >>> DRMSystem.from_uuid("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")
            <DRMSystem.WIDEVINE: 'com.widevine.alpha'>

            >>> DRMSystem.from_uuid("edef8ba979d64acea3c827dcd51d21ed")
            <DRMSystem.WIDEVINE: 'com.widevine.alpha'>
        """
        if not uuid:
            return None

        try:
            # Normalize UUID (removes hyphens, validates format)
            normalized = normalize_uuid(uuid)
        except InvalidUUIDError:
            return None

        # Lookup in mapping
        enum_name = DRM_SYSTEM_UUIDS.get(normalized)
        if not enum_name:
            return None

        return getattr(cls, enum_name, None)

    @classmethod
    def from_alias(cls, alias: str) -> Optional["DRMSystem"]:
        """
        Resolve DRM system from human-friendly alias or UUID.

        Handles:
        - Short aliases: "clearkey", "widevine", "playready", "fairplay", "wiseplay"
        - Full Android identifiers: "com.widevine.alpha", "org.w3.clearkey", etc.
        - UUIDs (with or without hyphens): "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"

        Args:
            alias: DRM system alias, identifier, or UUID

        Returns:
            DRMSystem enum value or None if unrecognized

        Examples:
            >>> DRMSystem.from_alias("widevine")
            <DRMSystem.WIDEVINE: 'com.widevine.alpha'>

            >>> DRMSystem.from_alias("com.widevine.alpha")
            <DRMSystem.WIDEVINE: 'com.widevine.alpha'>

            >>> DRMSystem.from_alias("clearkey")
            <DRMSystem.CLEARKEY: 'org.w3.clearkey'>
        """
        if not alias:
            return None

        # Normalize alias (remove dots, hyphens, lowercase)
        normalized = normalize_alias(alias)

        # Lookup in alias mapping
        enum_name = DRM_ALIAS_MAPPING.get(normalized)
        if not enum_name:
            return None

        return getattr(cls, enum_name, None)

    def __str__(self) -> str:
        """Return the DRM system identifier"""
        return self.value

    def __repr__(self) -> str:
        """Return detailed representation"""
        return f"<{self.__class__.__name__}.{self.name}: '{self.value}'>"