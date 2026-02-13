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
        Extract Key IDs as hex strings.
        This matches the interface expected by other code.
        """
        kid_bytes = TencParser.extract_kid_from_tenc(tenc_data)
        if kid_bytes:
            return [kid_bytes.hex().lower()]
        return []