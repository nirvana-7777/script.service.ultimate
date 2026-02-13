"""
DRM Constants and Configuration

Contains all magic numbers, offsets, and constants used in DRM processing.
"""

from typing import FrozenSet

# Character sets for validation
HEX_CHARS: FrozenSet[str] = frozenset('0123456789abcdef')
BASE64_CHARS: FrozenSet[str] = frozenset(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
)

# Size limits for security
MAX_PSSH_SIZE: int = 64 * 1024  # 64KB
MAX_TENC_SIZE: int = 1024  # 1KB
MAX_KEY_ID_COUNT: int = 100  # Maximum KIDs in a single PSSH

# KID and UUID sizes
KID_SIZE_BYTES: int = 16  # 128 bits
UUID_HEX_LENGTH: int = 32  # 32 hex characters without hyphens
UUID_FORMATTED_LENGTH: int = 36  # 36 characters with hyphens


class PSSHOffsets:
    """
    PSSH Box Binary Structure Offsets

    PSSH Box Format (ISO/IEC 23001-7):
    [0-3]   Box size (uint32)
    [4-7]   Box type ('pssh')
    [8]     Version (uint8)
    [9-11]  Flags (uint24)
    [12-27] System ID (16 bytes)

    Version 0:
    [28-31] Data size (uint32)
    [32+]   Data

    Version 1+:
    [28-31] KID count (uint32)
    [32+]   KIDs (16 bytes each)
    [...]   Data size (uint32)
    [...]   Data
    """
    BOX_SIZE = 0
    BOX_TYPE = 4
    BOX_TYPE_END = 8
    VERSION = 8
    FLAGS = 9
    FLAGS_END = 12
    SYSTEM_ID_START = 12
    SYSTEM_ID_END = 28

    # Version 1+ specific
    V1_KID_COUNT = 28
    V1_KID_COUNT_END = 32
    V1_KIDS_START = 32

    # Version 0 specific
    V0_DATA_SIZE = 28
    V0_DATA_SIZE_END = 32
    V0_DATA_START = 32

    # Minimum sizes
    MIN_PSSH_SIZE = 32  # Minimum valid PSSH box
    MIN_V1_PSSH_SIZE = 36  # Minimum V1 PSSH with 0 KIDs


class TencOffsets:
    """
    Track Encryption Box (tenc) Binary Structure Offsets

    tenc Box Format (ISO/IEC 23001-7):
    [0-3]   Box size (uint32)
    [4-7]   Box type ('tenc')
    [8]     Version (uint8)
    [9-11]  Flags (uint24)
    [12-15] Reserved (uint24) + default_crypt_byte_block (uint8)

    Version 0:
    [16]    Reserved (uint8)
    [17]    default_is_protected (uint8)
    [18]    default_per_sample_IV_size (uint8)
    [19-34] default_KID (16 bytes)

    Version 1:
    [16]    default_constant_IV_size (uint8)
    [17+]   default_constant_IV (if size > 0)
    [...]   default_KID (16 bytes, after IV)
    """
    BOX_SIZE = 0
    BOX_TYPE = 4
    BOX_TYPE_END = 8
    VERSION = 8

    # Version 0 specific
    V0_IS_PROTECTED = 17
    V0_IV_SIZE = 18
    V0_KID_START = 19
    V0_KID_END = 35

    MIN_TENC_V0_SIZE = 35  # Minimum valid V0 tenc box


# DRM System UUID Mappings (normalized, no hyphens)
DRM_SYSTEM_UUIDS: dict[str, str] = {
    "edef8ba979d64acea3c827dcd51d21ed": "WIDEVINE",
    "9a04f07998404286ab92e65be0885f95": "PLAYREADY",
    "e2719d58a985b3c9781ab030af78d30e": "CLEARKEY",
    "3d5e6d359b9a41e8b843dd3c6e72c42c": "WISEPLAY",
    "94ce86fb07ff4f43adb893d2fa968ca2": "FAIRPLAY",
}

# Reverse mapping for quick lookups
DRM_SYSTEM_NAMES: dict[str, str] = {
    "WIDEVINE": "edef8ba979d64acea3c827dcd51d21ed",
    "PLAYREADY": "9a04f07998404286ab92e65be0885f95",
    "CLEARKEY": "e2719d58a985b3c9781ab030af78d30e",
    "WISEPLAY": "3d5e6d359b9a41e8b843dd3c6e72c42c",
    "FAIRPLAY": "94ce86fb07ff4f43adb893d2fa968ca2",
    "GENERIC": "",
    "NONE": "",
}

# DRM System Alias Mappings (all normalized - no dots, hyphens, lowercase)
DRM_ALIAS_MAPPING: dict[str, str] = {
    # Widevine
    "widevine": "WIDEVINE",
    "comwidevinealpha": "WIDEVINE",
    "edef8ba979d64acea3c827dcd51d21ed": "WIDEVINE",

    # PlayReady
    "playready": "PLAYREADY",
    "commicrosoftplayready": "PLAYREADY",
    "9a04f07998404286ab92e65be0885f95": "PLAYREADY",

    # ClearKey
    "clearkey": "CLEARKEY",
    "orgw3clearkey": "CLEARKEY",
    "e2719d58a985b3c9781ab030af78d30e": "CLEARKEY",

    # FairPlay
    "fairplay": "FAIRPLAY",
    "comapplefps": "FAIRPLAY",
    "skd": "FAIRPLAY",
    "94ce86fb07ff4f43adb893d2fa968ca2": "FAIRPLAY",

    # WisePlay
    "wiseplay": "WISEPLAY",
    "comhuaweiwiseplay": "WISEPLAY",
    "3d5e6d359b9a41e8b843dd3c6e72c42c": "WISEPLAY",

    # Generic/None
    "generic": "GENERIC",
    "none": "NONE",
    "unencrypted": "NONE",
}