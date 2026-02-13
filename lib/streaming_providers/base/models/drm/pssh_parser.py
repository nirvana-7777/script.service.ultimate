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

import base64
import binascii
import re
import struct
from typing import Optional, List, Tuple

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
    - Key IDs (from box header for v1+, or from payload for v0 Widevine)
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

        # Validate box size matches actual data
        if box_size > len(pssh_bytes):
            raise InvalidPSSHError(
                f"PSSH box size mismatch: header claims {box_size} bytes, "
                f"but only {len(pssh_bytes)} bytes available"
            )

        # Parse version and system ID
        version = pssh_bytes[PSSHOffsets.VERSION]
        system_id_bytes = pssh_bytes[PSSHOffsets.SYSTEM_ID_START:PSSHOffsets.SYSTEM_ID_END]
        system_id = bytes_to_uuid_hex(system_id_bytes)

        # Try to identify DRM system
        drm_system = DRMSystem.from_uuid(system_id)

        # Extract Key IDs using multiple strategies:
        key_ids = []

        # Strategy 1: From PSSH header (version 1+)
        if version > 0:
            try:
                key_ids = PSSHParser._extract_kids_from_v1_header(pssh_bytes, drm_system)
            except InvalidPSSHError:
                # If v1 header extraction fails, try payload parsing as fallback
                key_ids = []

        # Strategy 2: From Widevine payload (works for v0 and v1)
        if not key_ids and drm_system == DRMSystem.WIDEVINE:
            key_ids = PSSHParser._extract_kids_from_widevine_payload(pssh_bytes)

        # Strategy 3: From PlayReady payload (if needed)
        if not key_ids and drm_system == DRMSystem.PLAYREADY:
            key_ids = PSSHParser._extract_kids_from_playready_payload(pssh_bytes)

        return {
            "system_id": system_id,
            "version": version,
            "key_ids": key_ids,
            "drm_system": drm_system,
        }

    @staticmethod
    def _extract_kids_from_v1_header(
            pssh_bytes: bytes,
            drm_system: Optional[DRMSystem]
    ) -> List[str]:
        """
        Extract Key IDs from version 1+ PSSH box header.

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

            # Handle byte order based on DRM system
            kid_hex = PSSHParser._format_kid_bytes(kid_bytes, drm_system)

            # Filter out null/empty KIDs
            if kid_hex and kid_hex != '0' * 32:
                key_ids.append(kid_hex)

        return key_ids

    @staticmethod
    def _extract_kids_from_widevine_payload(pssh_bytes: bytes) -> List[str]:
        """
        Extract Key IDs from Widevine PSSH payload (protobuf format).

        This parses the internal Widevine structure to find KIDs (field type 0x12)
        even in version 0 PSSH boxes.

        Args:
            pssh_bytes: Raw PSSH box bytes

        Returns:
            List of normalized Key IDs found in protobuf payload
        """
        key_ids = []

        try:
            # Find where the data payload starts
            version = pssh_bytes[PSSHOffsets.VERSION]
            data_start = PSSHParser._calculate_payload_start(pssh_bytes, version)

            if data_start is None or data_start >= len(pssh_bytes):
                return []

            # Parse Widevine protobuf
            # Field types in Widevine PSSH:
            # 0x12 = KID (repeated bytes)
            # 0x1a = Provider
            # 0x22 = Content ID
            # 0x2a = Track Type
            # 0x32 = Policy
            # 0x38 = Crypto Period Index
            # 0x48 = Protection Scheme
            # 0x50 = Crypto Period Seconds

            data = pssh_bytes[data_start:]
            pos = 0

            while pos < len(data):
                if pos + 1 > len(data):
                    break

                field_type = data[pos]
                pos += 1

                # Parse length (varint in protobuf)
                if pos >= len(data):
                    break

                length, bytes_read = PSSHParser._read_protobuf_varint(data[pos:])
                pos += bytes_read

                if pos + length > len(data):
                    break

                # Field type 0x12 = KID (bytes)
                if field_type == 0x12:
                    kid_bytes = data[pos:pos+length]
                    # KIDs are 16 bytes
                    if len(kid_bytes) == KID_SIZE_BYTES:
                        kid_hex = kid_bytes.hex().lower()
                        # Filter out null KIDs
                        if kid_hex != '0' * 32:
                            key_ids.append(kid_hex)

                pos += length

        except (struct.error, IndexError, ValueError):
            # Silently handle protobuf parsing errors
            return []

        return key_ids

    @staticmethod
    def _extract_kids_from_playready_payload(pssh_bytes: bytes) -> List[str]:
        """
        Extract Key IDs from PlayReady PSSH payload.

        PlayReady PSSH contains a WRMHEADER XML with KIDs.

        Args:
            pssh_bytes: Raw PSSH box bytes

        Returns:
            List of normalized Key IDs found in XML payload
        """
        try:
            # Find where data starts
            version = pssh_bytes[PSSHOffsets.VERSION]
            data_start = PSSHParser._calculate_payload_start(pssh_bytes, version)

            if data_start is None or data_start >= len(pssh_bytes):
                return []

            # PlayReady data is UTF-16LE XML
            playready_data = pssh_bytes[data_start:].decode('utf-16le', errors='ignore')

            # Look for KID in WRMHEADER
            # KID appears as: <KID>base64-encoded KID</KID> or attribute
            kid_pattern = r'<KID[^>]*>([^<]+)</KID>'
            kid_matches = re.findall(kid_pattern, playready_data, re.IGNORECASE)

            key_ids = []
            for kid_b64 in kid_matches:
                try:
                    # KID in PlayReady is often base64-encoded UUID
                    kid_bytes = base64.b64decode(kid_b64)
                    if len(kid_bytes) == KID_SIZE_BYTES:
                        # PlayReady KIDs are in mixed-endian format
                        kid_hex = PSSHParser._parse_uuid_bytes(kid_bytes)
                        # Filter out null KIDs
                        if kid_hex != '0' * 32:
                            key_ids.append(kid_hex)
                except (ValueError, binascii.Error):
                    # Skip invalid base64
                    continue

            return key_ids

        except (UnicodeDecodeError, struct.error, IndexError):
            return []

    @staticmethod
    def _calculate_payload_start(pssh_bytes: bytes, version: int) -> Optional[int]:
        """
        Calculate where the payload data starts in a PSSH box.

        Args:
            pssh_bytes: Raw PSSH box bytes
            version: PSSH version (0 or 1+)

        Returns:
            Byte offset where payload starts, or None if invalid
        """
        try:
            if version > 0:
                # v1+: Data starts after KIDs
                if len(pssh_bytes) < PSSHOffsets.V1_KID_COUNT_END:
                    return None

                # Get KID count
                kid_count = struct.unpack(
                    ">I",
                    pssh_bytes[PSSHOffsets.V1_KID_COUNT:PSSHOffsets.V1_KID_COUNT_END]
                )[0]
                data_start = PSSHOffsets.V1_KIDS_START + (kid_count * KID_SIZE_BYTES)

                # Skip data size field (4 bytes)
                if len(pssh_bytes) < data_start + 4:
                    return None
                data_start += 4
            else:
                # v0: Data starts right after system ID
                data_start = PSSHOffsets.SYSTEM_ID_END

                # Skip data size field (4 bytes)
                if len(pssh_bytes) < data_start + 4:
                    return None
                data_size = struct.unpack(">I", pssh_bytes[data_start:data_start+4])[0]
                data_start += 4

                # Validate data size
                if data_start + data_size > len(pssh_bytes):
                    return None

            return data_start

        except (struct.error, IndexError):
            return None

    @staticmethod
    def _read_protobuf_varint(data: bytes) -> Tuple[int, int]:
        """
        Read a protobuf varint from bytes.

        Args:
            data: Byte array to read from

        Returns:
            Tuple of (value, bytes_read)
        """
        value = 0
        shift = 0
        bytes_read = 0

        for byte in data:
            bytes_read += 1
            value |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7

            # Prevent infinite loops on malformed data
            if bytes_read > 10:  # Varint max is 10 bytes
                break

        return value, bytes_read

    @staticmethod
    def _format_kid_bytes(kid_bytes: bytes, drm_system: Optional[DRMSystem]) -> str:
        """
        Format KID bytes based on DRM system.

        Args:
            kid_bytes: 16 bytes of KID data
            drm_system: DRM system identifier

        Returns:
            Normalized 32-character hex string (no hyphens)
        """
        if len(kid_bytes) != KID_SIZE_BYTES:
            return ""

        try:
            if drm_system == DRMSystem.WIDEVINE:
                # Widevine: raw bytes
                return kid_bytes.hex().lower()
            elif drm_system == DRMSystem.PLAYREADY:
                # PlayReady: mixed-endian UUID format
                return PSSHParser._parse_uuid_bytes(kid_bytes)
            else:
                # Unknown: try UUID format first
                try:
                    return PSSHParser._parse_uuid_bytes(kid_bytes)
                except (ValueError, struct.error):
                    return kid_bytes.hex().lower()
        except Exception:
            return ""

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

        Raises:
            ValueError: If data is not exactly 16 bytes
        """
        if len(data) != KID_SIZE_BYTES:
            raise ValueError(f"UUID bytes must be {KID_SIZE_BYTES} bytes (got {len(data)})")

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

        We now try multiple strategies to extract KIDs:
        1. From PSSH header (v1+)
        2. From Widevine payload (v0/v1)
        3. From PlayReady payload
        4. Fallback to tenc if all fail

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

            # If we have key_ids from any method, no fallback needed
            if metadata["key_ids"]:
                return False

            # No KIDs found - need tenc fallback
            return True

        except Exception:
            # Parse failed - need tenc fallback
            return True