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

            # The KID appears to be at offset 16-31 in your data
            # Let's check if that looks like a valid KID
            if len(tenc_data) >= 32:
                # Try offset 16 first (based on your data)
                kid_bytes = tenc_data[16:32]
                kid_hex = kid_bytes.hex().lower()

                # Validate it's not all zeros
                if not all(c == '0' for c in kid_hex):
                    return [kid_hex]

            # If that didn't work, try scanning for valid-looking KID
            for offset in range(0, len(tenc_data) - 16):
                chunk = tenc_data[offset:offset + 16]
                # Check if it looks like a valid KID (not all zeros, not repetitive)
                if all(b == 0 for b in chunk):
                    continue
                if all(b == chunk[0] for b in chunk):
                    continue

                # This could be a KID
                kid_hex = chunk.hex().lower()
                return [kid_hex]

        except Exception:
            pass

        return []