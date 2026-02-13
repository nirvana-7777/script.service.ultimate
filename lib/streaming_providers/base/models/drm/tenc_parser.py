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
        """Extract Key IDs as hex strings."""
        if not tenc_data:
            return []

        # DEBUG: Dump the entire tenc data
        print(f"TENC DATA ({len(tenc_data)} bytes): {tenc_data.hex()}")
        print(f"Bytes 0-3 (version/flags): {tenc_data[0:4].hex()}")
        if len(tenc_data) > 7:
            print(f"Byte 7 (is_protected): {tenc_data[7]} (0x{tenc_data[7]:02x})")
        if len(tenc_data) > 8:
            print(f"Byte 8 (iv_size): {tenc_data[8]} (0x{tenc_data[8]:02x})")
        if len(tenc_data) >= 25:
            kid_bytes = tenc_data[9:25]
            print(f"Bytes 9-24 (KID): {kid_bytes.hex()}")

        # Original logic...
        kid_bytes = TencParser.extract_kid_from_tenc(tenc_data)
        if kid_bytes:
            kid_hex = kid_bytes.hex().lower()
            print(f"Extracted KID: {kid_hex}")
            if all(c == '0' for c in kid_hex):
                print("⚠️ WARNING: KID is all zeros!")
            return [kid_hex]
        return []