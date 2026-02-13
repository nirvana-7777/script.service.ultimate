"""
tenc Box Parser

Simplified parser based on working implementation that successfully
handles real-world streams without strict ISO spec compliance.
"""

from ...utils import logger


class TencParser:
    """Parser for tenc (Track Encryption) boxes."""

    @staticmethod
    def extract_kids_from_tenc(tenc_data: bytes) -> list[str]:
        """
        Extract Key IDs from tenc box data.

        Based on working code that extracts KID from bytes 9-25
        after validating is_protected at byte 7.

        Args:
            tenc_data: Raw tenc box data (starting after 8-byte header)

        Returns:
            List containing single Key ID if found, empty list otherwise
        """
        if not tenc_data:
            return []

        # Size check based on working code
        if len(tenc_data) < 24:
            logger.debug(f"tenc data too small: {len(tenc_data)} bytes (need 24)")
            return []

        try:
            # Version and flags are at start but we don't really need them
            # version_flags = struct.unpack(">I", tenc_data[0:4])[0]
            # version = (version_flags >> 24) & 0xFF

            # Check if track is protected (byte 7)
            if len(tenc_data) > 7:
                is_protected = tenc_data[7]
                if is_protected == 0:
                    logger.debug("Track not encrypted (is_protected=0)")
                    return []

            # Extract KID from bytes 9-24
            if len(tenc_data) >= 25:
                kid_bytes = tenc_data[9:25]

                # Working code uses simple hexlify
                kid_hex = kid_bytes.hex().lower()

                logger.debug(f"Extracted KID: {kid_hex[:8]}...")
                return [kid_hex]
            else:
                logger.debug(f"tenc data too short for KID: {len(tenc_data)} bytes")
                return []

        except Exception as e:
            logger.debug(f"Failed to extract KID from tenc: {e}")
            return []

    @staticmethod
    def is_track_encrypted(tenc_data: bytes) -> bool:
        """Check if track is encrypted based on is_protected flag."""
        if not tenc_data or len(tenc_data) < 8:
            return False

        try:
            is_protected = tenc_data[7] if len(tenc_data) > 7 else 0
            return is_protected != 0
        except Exception:
            return False