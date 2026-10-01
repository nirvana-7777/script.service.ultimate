# In tenc_parser.py - SIMPLIFIED VERSION (NO LOGGING)

from typing import Optional


class TencParser:
    """Parser for tenc (Track Encryption) boxes - simplified version."""

    @staticmethod
    def extract_kid_from_tenc(tenc_data: bytes) -> Optional[bytes]:
        """
        Extract Key ID from tenc box data.
        Returns raw bytes of KID or None if not found.
        """
        if not tenc_data or len(tenc_data) < 24:
            return None

        try:
            # Check if track is protected (byte 7)
            if len(tenc_data) > 7:
                is_protected = tenc_data[7]
                if is_protected == 0:
                    return None

            # Extract KID from bytes 9-24
            if len(tenc_data) >= 25:
                kid_bytes = tenc_data[9:25]
                return kid_bytes

        except Exception:
            pass

        return None

    @staticmethod
    def extract_kids_from_tenc(tenc_data: bytes) -> list[str]:
        """
        Extract Key IDs from tenc box data.

        Args:
            tenc_data: Raw tenc box data (FULL box, including header)

        Returns:
            List containing the extracted Key ID (normalized)
        """
        if not tenc_data or len(tenc_data) < 32:
            return []

        try:
            # Verify this is a tenc box
            if len(tenc_data) >= 8:
                box_type = tenc_data[4:8]
                if box_type != b'tenc':
                    return []

            # Full box layout: header(8) + version/flags(4) + reserved(1)
            # + crypt/skip(1) + default_isProtected(1) + ivSize(1) + KID(16)
            if tenc_data[14] == 0:
                return []  # unprotected track: the KID field is meaningless

            kid_bytes = tenc_data[16:32]
            if any(kid_bytes):
                return [kid_bytes.hex().lower()]

        except Exception:
            pass

        return []