"""
PSSH Box Parser

Handles parsing of Protection System Specific Header (PSSH) boxes
according to ISO/IEC 23001-7 specification.

PSSH Box Structure:
┌────────────────────────────────────┐
│ Box Size (4 bytes)                 │
├────────────────────────────────────┤
│ Box Type 'pssh' (4 bytes)          │
├────────────────────────────────────┤
│ Version (1 byte) | Flags (3 bytes) │
├────────────────────────────────────┤
│ System ID (16 bytes UUID)          │
├────────────────────────────────────┤
│ [Version 1+]                       │
│ KID Count (4 bytes)                │
│ KIDs (16 bytes each)               │
├────────────────────────────────────┤
│ Data Size (4 bytes)                │
├────────────────────────────────────┤
│ Data (variable length)             │
└────────────────────────────────────┘
"""

import struct
from typing import Optional

from .constants import (
    PSSHOffsets,
    KID_SIZE_BYTES,
    MAX_PSSH_SIZE,
    MAX_KEY_ID_COUNT,
)
from .drm_systems import DRMSystem
from .exceptions import InvalidPSSHError, PSSHSizeError
from .utils import bytes_to_uuid_hex, safe_base64_decode


class PSSHParser:
    """
    Parser for PSSH (Protection System Specific Header) boxes.

    Handles both version 0 and version 1+ PSSH boxes, extracting:
    - System ID (DRM system UUID)
    - Key IDs (for version 1+)
    - PSSH version
    """

    @staticmethod
    def parse_pssh_box(pssh_base64: str) -> dict:
        """
        Parse a PSSH box and extract metadata.

        Args:
            pssh_base64: Base64-encoded PSSH box

        Returns:
            Dictionary containing:
                - system_id: Normalized UUID (32 hex chars, no hyphens)
                - version: PSSH version (0 or 1+)
                - key_ids: List of Key IDs (normalized, no hyphens)
                - drm_system: DRMSystem enum value (if recognized)

        Raises:
            InvalidPSSHError: If PSSH box is malformed
            PSSHSizeError: If PSSH box exceeds size limits
        """
        if not pssh_base64:
            raise InvalidPSSHError("PSSH box cannot be empty")

        # Decode base64
        try:
            pssh_bytes = safe_base64_decode(pssh_base64)
        except Exception as e:
            raise InvalidPSSHError(f"Failed to decode PSSH base64: {e}") from e

        # Check size limits
        if len(pssh_bytes) > MAX_PSSH_SIZE:
            raise PSSHSizeError(
                f"PSSH box too large: {len(pssh_bytes)} bytes (max: {MAX_PSSH_SIZE})"
            )

        # Validate minimum size
        if len(pssh_bytes) < PSSHOffsets.MIN_PSSH_SIZE:
            raise InvalidPSSHError(
                f"PSSH box too small: {len(pssh_bytes)} bytes "
                f"(minimum: {PSSHOffsets.MIN_PSSH_SIZE})"
            )

        # Parse box header
        box_size = struct.unpack(">I", pssh_bytes[PSSHOffsets.BOX_SIZE:4])[0]
        box_type = pssh_bytes[PSSHOffsets.BOX_TYPE:PSSHOffsets.BOX_TYPE_END]

        if box_type != b"pssh":
            raise InvalidPSSHError(
                f"Not a PSSH box: type is '{box_type.decode('ascii', errors='ignore')}'"
            )

        # Parse version and system ID
        version = pssh_bytes[PSSHOffsets.VERSION]
        system_id_bytes = pssh_bytes[PSSHOffsets.SYSTEM_ID_START:PSSHOffsets.SYSTEM_ID_END]
        system_id = bytes_to_uuid_hex(system_id_bytes)

        # Try to identify DRM system
        drm_system = DRMSystem.from_uuid(system_id)

        # Extract Key IDs based on version
        key_ids = []
        if version > 0:
            key_ids = PSSHParser._extract_kids_from_v1_pssh(pssh_bytes, drm_system)

        return {
            "system_id": system_id,
            "version": version,
            "key_ids": key_ids,
            "drm_system": drm_system,
        }

    @staticmethod
    def _extract_kids_from_v1_pssh(
            pssh_bytes: bytes,
            drm_system: Optional[DRMSystem]
    ) -> list[str]:
        """
        Extract Key IDs from version 1+ PSSH box.

        Args:
            pssh_bytes: Raw PSSH box bytes
            drm_system: Identified DRM system (if any)

        Returns:
            List of normalized Key IDs (32 hex chars, no hyphens)

        Raises:
            InvalidPSSHError: If PSSH structure is invalid
        """
        if len(pssh_bytes) < PSSHOffsets.MIN_V1_PSSH_SIZE:
            raise InvalidPSSHError(
                f"Version 1+ PSSH too small: {len(pssh_bytes)} bytes "
                f"(minimum: {PSSHOffsets.MIN_V1_PSSH_SIZE})"
            )

        # Read KID count
        kid_count = struct.unpack(
            ">I",
            pssh_bytes[PSSHOffsets.V1_KID_COUNT:PSSHOffsets.V1_KID_COUNT_END]
        )[0]

        # Validate KID count
        if kid_count > MAX_KEY_ID_COUNT:
            raise InvalidPSSHError(
                f"Too many Key IDs in PSSH: {kid_count} (max: {MAX_KEY_ID_COUNT})"
            )

        # Calculate required size
        required_size = PSSHOffsets.V1_KIDS_START + (kid_count * KID_SIZE_BYTES)
        if len(pssh_bytes) < required_size:
            raise InvalidPSSHError(
                f"PSSH truncated: claims {kid_count} KIDs but only "
                f"{len(pssh_bytes)} bytes available"
            )

        # Extract KIDs
        key_ids = []
        for i in range(kid_count):
            start_offset = PSSHOffsets.V1_KIDS_START + (i * KID_SIZE_BYTES)
            end_offset = start_offset + KID_SIZE_BYTES
            kid_bytes = pssh_bytes[start_offset:end_offset]

            # Convert to hex based on DRM system
            # Widevine uses raw bytes, others may use UUID byte order
            if drm_system == DRMSystem.WIDEVINE:
                # Widevine: KIDs are raw bytes (big-endian)
                kid_hex = bytes_to_uuid_hex(kid_bytes)
            elif drm_system == DRMSystem.PLAYREADY:
                # PlayReady: KIDs are in UUID byte order (mixed-endian)
                kid_hex = PSSHParser._parse_uuid_bytes(kid_bytes)
            else:
                # Unknown system: try UUID format first, fallback to raw
                try:
                    kid_hex = PSSHParser._parse_uuid_bytes(kid_bytes)
                except Exception:
                    kid_hex = bytes_to_uuid_hex(kid_bytes)

            key_ids.append(kid_hex)

        return key_ids

    @staticmethod
    def _parse_uuid_bytes(data: bytes) -> str:
        """
        Parse UUID bytes with mixed-endian format (Microsoft GUID format).

        UUID byte order (RFC 4122):
        - time_low (4 bytes): big-endian → little-endian
        - time_mid (2 bytes): big-endian → little-endian
        - time_hi_version (2 bytes): big-endian → little-endian
        - clock_seq (2 bytes): big-endian (no change)
        - node (6 bytes): big-endian (no change)

        Args:
            data: 16 bytes of UUID data

        Returns:
            32-character hex string (normalized, no hyphens)
        """
        if len(data) != 16:
            raise ValueError(f"UUID bytes must be 16 bytes (got {len(data)})")

        # Parse with mixed-endian format
        time_low = struct.unpack("<I", data[0:4])[0]  # Little-endian
        time_mid = struct.unpack("<H", data[4:6])[0]  # Little-endian
        time_hi = struct.unpack("<H", data[6:8])[0]  # Little-endian
        clock_seq = data[8:10].hex()  # Big-endian (raw)
        node = data[10:16].hex()  # Big-endian (raw)

        # Format as hex string
        uuid_hex = (
            f"{time_low:08x}{time_mid:04x}{time_hi:04x}{clock_seq}{node}"
        )

        return uuid_hex.lower()

    @staticmethod
    def get_pssh_version(pssh_base64: str) -> int:
        """
        Get PSSH version without full parsing.

        Args:
            pssh_base64: Base64-encoded PSSH box

        Returns:
            PSSH version number (0, 1, etc.)

        Raises:
            InvalidPSSHError: If PSSH box is malformed
        """
        if not pssh_base64:
            raise InvalidPSSHError("PSSH box cannot be empty")

        try:
            pssh_bytes = safe_base64_decode(pssh_base64)
        except Exception as e:
            raise InvalidPSSHError(f"Failed to decode PSSH base64: {e}") from e

        if len(pssh_bytes) < PSSHOffsets.VERSION + 1:
            raise InvalidPSSHError(f"PSSH box too small to read version")

        return pssh_bytes[PSSHOffsets.VERSION]

    @staticmethod
    def needs_tenc_fallback(pssh_base64: str, drm_system: Optional[DRMSystem]) -> bool:
        """
        Check if PSSH needs tenc box fallback for Key IDs.

        Version 0 PSSH boxes don't contain Key IDs, so we need to extract
        them from tenc boxes in the MP4 structure.

        Args:
            pssh_base64: Base64-encoded PSSH box
            drm_system: DRM system (if known)

        Returns:
            True if tenc fallback is needed
        """
        if not pssh_base64:
            return True

        try:
            metadata = PSSHParser.parse_pssh_box(pssh_base64)

            # Need fallback if:
            # 1. No Key IDs extracted
            # 2. Version 0 PSSH (doesn't contain KIDs)
            # 3. Widevine system (commonly uses tenc)
            return (
                    not metadata["key_ids"] and
                    metadata["version"] == 0 and
                    metadata["drm_system"] == DRMSystem.WIDEVINE
            )
        except Exception:
            return True