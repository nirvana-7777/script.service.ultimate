"""
PSSH Data Model

Data class for storing PSSH (Protection System Specific Header) information.
"""

from dataclasses import dataclass, field
from functools import cached_property
from typing import Optional

from .drm_systems import DRMSystem
from .pssh_parser import PSSHParser
from .utils import normalize_uuid, normalize_key_id, format_uuid, deduplicate_key_ids
from .exceptions import InvalidPSSHError, InvalidKeyIDError


@dataclass
class PSSHData:
    """
    Container for PSSH (Protection System Specific Header) data.

    Attributes:
        system_id: DRM system UUID (normalized, 32 hex chars, no hyphens)
        pssh_box: Base64-encoded PSSH box (optional if extracting from segments)
        key_ids: List of Key IDs (normalized, 32 hex chars, no hyphens)
        source: Source of PSSH data (e.g., "manifest", "segment", "init")
    """

    system_id: str
    pssh_box: str = ""
    key_ids: list[str] = field(default_factory=list)
    source: str = "manifest"

    def __post_init__(self):
        """Normalize and validate all data at creation time."""
        # Normalize system_id
        if self.system_id:
            try:
                self.system_id = normalize_uuid(self.system_id)
            except Exception as e:
                raise InvalidPSSHError(f"Invalid system_id: {e}") from e
        else:
            raise InvalidPSSHError("system_id is required")

        # Normalize key_ids
        if self.key_ids:
            normalized_kids = []
            for kid in self.key_ids:
                try:
                    normalized_kids.append(normalize_key_id(kid))
                except InvalidKeyIDError:
                    # Skip invalid KIDs but don't fail
                    pass

            # Remove duplicates while preserving order
            self.key_ids = deduplicate_key_ids(normalized_kids)

        # Auto-extract key_ids from pssh_box if provided but no key_ids
        if self.pssh_box and not self.key_ids:
            try:
                metadata = PSSHParser.parse_pssh_box(self.pssh_box)
                self.key_ids = metadata["key_ids"]
            except Exception:
                # If extraction fails, leave key_ids empty
                # They might be available in tenc boxes or segments
                pass

    @cached_property
    def drm_system(self) -> Optional[DRMSystem]:
        """
        Get DRM system enum from system_id.

        Returns:
            DRMSystem enum value or None if not recognized
        """
        return DRMSystem.from_uuid(self.system_id)

    @cached_property
    def system_id_formatted(self) -> str:
        """
        Get system_id with hyphens for display.

        Returns:
            UUID string with hyphens (8-4-4-4-12)
        """
        return format_uuid(self.system_id)

    @cached_property
    def pssh_version(self) -> int:
        """
        Get PSSH version from the box.

        Returns:
            PSSH version number, or -1 if no PSSH box
        """
        if not self.pssh_box:
            return -1

        try:
            return PSSHParser.get_pssh_version(self.pssh_box)
        except Exception:
            return -1

    def needs_tenc_fallback(self) -> bool:
        """
        Check if this PSSH needs tenc box fallback for Key IDs.

        Returns:
            True if tenc fallback is needed (version 0 PSSH without KIDs)
        """
        return PSSHParser.needs_tenc_fallback(self.pssh_box, self.drm_system)

    @property
    def needs_extraction(self) -> bool:
        """
        Check if PSSH/key_ids need to be extracted from segments.

        Returns:
            True if PSSH box or Key IDs are missing
        """
        return not self.pssh_box or not self.key_ids

    def add_key_ids(self, new_kids: list[str]) -> None:
        """
        Add Key IDs to the existing list (normalized and deduplicated).

        Args:
            new_kids: List of Key IDs to add
        """
        normalized_kids = []
        for kid in new_kids:
            try:
                normalized_kids.append(normalize_key_id(kid))
            except InvalidKeyIDError:
                # Skip invalid KIDs
                pass

        # Merge with existing and deduplicate
        all_kids = self.key_ids + normalized_kids
        self.key_ids = deduplicate_key_ids(all_kids)

    def validate(self) -> None:
        """
        Validate the PSSH data.

        Raises:
            InvalidPSSHError: If data is invalid
        """
        if not self.system_id:
            raise InvalidPSSHError("system_id is required")

        # Validate system_id format
        try:
            normalize_uuid(self.system_id)
        except Exception as e:
            raise InvalidPSSHError(f"Invalid system_id format: {e}") from e

        # Validate pssh_box if present
        if self.pssh_box:
            try:
                PSSHParser.parse_pssh_box(self.pssh_box)
            except Exception as e:
                raise InvalidPSSHError(f"Invalid pssh_box: {e}") from e

        # Validate key_ids format
        for kid in self.key_ids:
            try:
                normalize_key_id(kid)
            except Exception as e:
                raise InvalidPSSHError(f"Invalid key_id format: {e}") from e

    def to_dict(self) -> dict:
        """
        Convert to dictionary representation.

        Returns:
            Dictionary with all PSSH data
        """
        return {
            "system_id": self.system_id,
            "system_id_formatted": self.system_id_formatted,
            "pssh_box": self.pssh_box,
            "key_ids": self.key_ids,
            "source": self.source,
            "drm_system": self.drm_system.value if self.drm_system else None,
            "version": self.pssh_version,
        }

    def __repr__(self) -> str:
        """Return detailed representation."""
        drm_name = self.drm_system.name if self.drm_system else "UNKNOWN"
        kid_count = len(self.key_ids)
        return (
            f"<PSSHData({drm_name}, v{self.pssh_version}, "
            f"{kid_count} KIDs, source='{self.source}')>"
        )