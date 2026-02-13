"""
tenc Box Parser

Handles parsing of Track Encryption (tenc) boxes for extracting Key IDs
when PSSH boxes don't contain them (version 0 PSSH).
"""

import struct

from .constants import TencOffsets, MAX_TENC_SIZE, KID_SIZE_BYTES
from .exceptions import InvalidTencError
from .utils import bytes_to_uuid_hex


class TencParser:
    """
    Parser for tenc (Track Encryption) boxes.

    Used as fallback when PSSH version 0 doesn't contain Key IDs.
    According to ISO/IEC 23001-7, tenc boxes contain default encryption
    information including the default Key ID.
    """

    @staticmethod
    def extract_kids_from_tenc(tenc_data: bytes) -> list[str]:
        """
        Extract Key IDs from tenc box data.

        This is typically used as a fallback when PSSH version 0 boxes
        don't contain Key IDs directly.

        Args:
            tenc_data: Raw tenc box bytes

        Returns:
            List of normalized Key IDs (32 hex chars, no hyphens)

        Raises:
            InvalidTencError: If tenc box is malformed
        """
        if not tenc_data:
            raise InvalidTencError("tenc box data cannot be empty")

        # Check size limits
        if len(tenc_data) > MAX_TENC_SIZE:
            raise InvalidTencError(
                f"tenc box too large: {len(tenc_data)} bytes (max: {MAX_TENC_SIZE})"
            )

        # Validate minimum size for version 0
        if len(tenc_data) < TencOffsets.MIN_TENC_V0_SIZE:
            raise InvalidTencError(
                f"tenc box too small: {len(tenc_data)} bytes "
                f"(minimum: {TencOffsets.MIN_TENC_V0_SIZE})"
            )

        # Validate box type
        box_type = tenc_data[TencOffsets.BOX_TYPE:TencOffsets.BOX_TYPE_END]
        if box_type != b"tenc":
            raise InvalidTencError(
                f"Not a tenc box: type is '{box_type.decode('ascii', errors='ignore')}'"
            )

        # Parse version
        version = tenc_data[TencOffsets.VERSION]

        # Extract KID based on version
        if version == 0:
            return TencParser._extract_kid_from_v0_tenc(tenc_data)
        elif version == 1:
            return TencParser._extract_kid_from_v1_tenc(tenc_data)
        else:
            raise InvalidTencError(f"Unsupported tenc version: {version}")

    @staticmethod
    def _extract_kid_from_v0_tenc(tenc_data: bytes) -> list[str]:
        """
        Extract Key ID from version 0 tenc box.

        Version 0 structure:
        [16]    Reserved (uint8)
        [17]    default_is_protected (uint8)
        [18]    default_per_sample_IV_size (uint8)
        [19-34] default_KID (16 bytes)

        Args:
            tenc_data: Raw tenc box bytes

        Returns:
            List containing single normalized Key ID

        Raises:
            InvalidTencError: If tenc structure is invalid
        """
        if len(tenc_data) < TencOffsets.V0_KID_END:
            raise InvalidTencError(
                f"tenc v0 box truncated: {len(tenc_data)} bytes "
                f"(need at least {TencOffsets.V0_KID_END})"
            )

        # Check if track is protected
        is_protected = tenc_data[TencOffsets.V0_IS_PROTECTED]
        if is_protected == 0:
            # Unencrypted track, no KID
            return []

        # Extract KID bytes
        kid_bytes = tenc_data[TencOffsets.V0_KID_START:TencOffsets.V0_KID_END]

        # tenc KIDs are typically in UUID/GUID format (mixed-endian)
        try:
            kid_hex = TencParser._parse_guid_bytes(kid_bytes)
        except Exception:
            # Fallback to raw hex if GUID parsing fails
            kid_hex = bytes_to_uuid_hex(kid_bytes)

        return [kid_hex]

    @staticmethod
    def _extract_kid_from_v1_tenc(tenc_data: bytes) -> list[str]:
        """
        Extract Key ID from version 1 tenc box.

        Version 1 structure:
        [16]    default_constant_IV_size (uint8)
        [17+]   default_constant_IV (if IV_size > 0)
        [...]   default_KID (16 bytes, after IV)

        Args:
            tenc_data: Raw tenc box bytes

        Returns:
            List containing single normalized Key ID

        Raises:
            InvalidTencError: If tenc structure is invalid
        """
        # Read IV size
        if len(tenc_data) < 17:
            raise InvalidTencError("tenc v1 box too small to read IV size")

        iv_size = tenc_data[16]

        # KID starts after IV
        kid_start = 17 + iv_size
        kid_end = kid_start + KID_SIZE_BYTES

        if len(tenc_data) < kid_end:
            raise InvalidTencError(
                f"tenc v1 box truncated: {len(tenc_data)} bytes "
                f"(need at least {kid_end} for KID)"
            )

        # Extract KID bytes
        kid_bytes = tenc_data[kid_start:kid_end]

        # tenc KIDs are typically in UUID/GUID format
        try:
            kid_hex = TencParser._parse_guid_bytes(kid_bytes)
        except Exception:
            kid_hex = bytes_to_uuid_hex(kid_bytes)

        return [kid_hex]

    @staticmethod
    def _parse_guid_bytes(data: bytes) -> str:
        """
        Parse GUID/UUID bytes with mixed-endian format (Microsoft GUID).

        GUID byte order:
        - Data1 (4 bytes): little-endian
        - Data2 (2 bytes): little-endian
        - Data3 (2 bytes): little-endian
        - Data4 (8 bytes): big-endian

        Args:
            data: 16 bytes of GUID data

        Returns:
            32-character hex string (normalized, no hyphens)
        """
        if len(data) != 16:
            raise ValueError(f"GUID bytes must be 16 bytes (got {len(data)})")

        # Parse with mixed-endian format (Microsoft GUID)
        data1 = struct.unpack("<I", data[0:4])[0]  # Little-endian uint32
        data2 = struct.unpack("<H", data[4:6])[0]  # Little-endian uint16
        data3 = struct.unpack("<H", data[6:8])[0]  # Little-endian uint16
        data4 = data[8:16].hex()  # Big-endian (raw bytes)

        # Format as hex string
        guid_hex = f"{data1:08x}{data2:04x}{data3:04x}{data4}"

        return guid_hex.lower()

    @staticmethod
    def is_track_encrypted(tenc_data: bytes) -> bool:
        """
        Check if track is encrypted based on tenc box.

        Args:
            tenc_data: Raw tenc box bytes

        Returns:
            True if track is encrypted, False otherwise
        """
        if not tenc_data or len(tenc_data) < TencOffsets.V0_IS_PROTECTED + 1:
            return False

        version = tenc_data[TencOffsets.VERSION]

        if version == 0:
            is_protected = tenc_data[TencOffsets.V0_IS_PROTECTED]
            return is_protected != 0

        # Version 1+ tracks are assumed encrypted if tenc box exists
        return True