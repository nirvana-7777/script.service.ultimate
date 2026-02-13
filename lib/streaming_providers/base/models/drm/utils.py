"""
DRM Utility Functions

Common utility functions for UUID formatting, validation, and normalization.
"""

import base64
import binascii
from typing import Optional

from .constants import HEX_CHARS, UUID_HEX_LENGTH, UUID_FORMATTED_LENGTH
from .exceptions import InvalidUUIDError, InvalidKeyIDError, Base64DecodingError


def is_hex_string(s: str, length: Optional[int] = None) -> bool:
    """
    Check if string contains only hexadecimal characters.

    Args:
        s: String to validate
        length: Optional expected length

    Returns:
        True if string is valid hex (and matches length if provided)
    """
    if not s:
        return False

    if length is not None and len(s) != length:
        return False

    return all(c in HEX_CHARS for c in s.lower())


def normalize_uuid(uuid: str) -> str:
    """
    Normalize UUID to 32 lowercase hex characters without hyphens.

    Args:
        uuid: UUID string (with or without hyphens)

    Returns:
        Normalized UUID string (32 hex chars, no hyphens, lowercase)

    Raises:
        InvalidUUIDError: If UUID format is invalid
    """
    if not uuid:
        raise InvalidUUIDError("UUID cannot be empty")

    # Remove hyphens and convert to lowercase
    normalized = uuid.lower().replace("-", "")

    # Validate format
    if len(normalized) != UUID_HEX_LENGTH:
        raise InvalidUUIDError(
            f"UUID must be {UUID_HEX_LENGTH} hex characters (got {len(normalized)}): {uuid}"
        )

    if not is_hex_string(normalized):
        raise InvalidUUIDError(f"UUID contains non-hex characters: {uuid}")

    return normalized


def format_uuid(uuid: str) -> str:
    """
    Format UUID with standard hyphens (8-4-4-4-12).

    Args:
        uuid: UUID string (32 hex chars, no hyphens)

    Returns:
        Formatted UUID string with hyphens

    Raises:
        InvalidUUIDError: If UUID format is invalid
    """
    normalized = normalize_uuid(uuid)

    return (
        f"{normalized[0:8]}-{normalized[8:12]}-{normalized[12:16]}-"
        f"{normalized[16:20]}-{normalized[20:32]}"
    )


def normalize_key_id(kid: str) -> str:
    """
    Normalize Key ID to 32 lowercase hex characters without hyphens.

    Args:
        kid: Key ID string (with or without hyphens)

    Returns:
        Normalized Key ID string (32 hex chars, no hyphens, lowercase)

    Raises:
        InvalidKeyIDError: If Key ID format is invalid
    """
    if not kid:
        raise InvalidKeyIDError("Key ID cannot be empty")

    # Remove hyphens and convert to lowercase
    normalized = kid.lower().replace("-", "")

    # Validate format
    if len(normalized) != UUID_HEX_LENGTH:
        raise InvalidKeyIDError(
            f"Key ID must be {UUID_HEX_LENGTH} hex characters (got {len(normalized)}): {kid}"
        )

    if not is_hex_string(normalized):
        raise InvalidKeyIDError(f"Key ID contains non-hex characters: {kid}")

    return normalized


def bytes_to_uuid_hex(data: bytes) -> str:
    """
    Convert 16 bytes to UUID hex string (no hyphens).

    This is more efficient than using the uuid module.

    Args:
        data: 16 bytes of UUID data

    Returns:
        32-character hex string (lowercase, no hyphens)

    Raises:
        InvalidUUIDError: If data is not 16 bytes
    """
    if len(data) != 16:
        raise InvalidUUIDError(f"UUID bytes must be 16 bytes long (got {len(data)})")

    return data.hex().lower()


def bytes_to_uuid_formatted(data: bytes) -> str:
    """
    Convert 16 bytes to formatted UUID string with hyphens.

    Args:
        data: 16 bytes of UUID data

    Returns:
        36-character UUID string with hyphens (8-4-4-4-12)

    Raises:
        InvalidUUIDError: If data is not 16 bytes
    """
    hex_string = bytes_to_uuid_hex(data)
    return format_uuid(hex_string)


def uuid_to_bytes(uuid: str) -> bytes:
    """
    Convert UUID string to 16 bytes.

    Args:
        uuid: UUID string (with or without hyphens)

    Returns:
        16 bytes of UUID data

    Raises:
        InvalidUUIDError: If UUID format is invalid
    """
    normalized = normalize_uuid(uuid)
    return bytes.fromhex(normalized)


def safe_base64_decode(data: str) -> bytes:
    """
    Safely decode base64 string with better error handling.

    Args:
        data: Base64-encoded string

    Returns:
        Decoded bytes

    Raises:
        Base64DecodingError: If decoding fails
    """
    if not data:
        raise Base64DecodingError("Cannot decode empty base64 string")

    try:
        return base64.b64decode(data)
    except (binascii.Error, ValueError) as e:
        raise Base64DecodingError(f"Failed to decode base64 data: {e}") from e


def safe_base64_encode(data: bytes) -> str:
    """
    Safely encode bytes to base64 string.

    Args:
        data: Bytes to encode

    Returns:
        Base64-encoded string
    """
    if not data:
        return ""

    return base64.b64encode(data).decode('utf-8')


def normalize_alias(alias: str) -> str:
    """
    Normalize alias for consistent lookups.

    Removes hyphens, dots, and converts to lowercase.

    Args:
        alias: Alias string

    Returns:
        Normalized alias
    """
    return alias.lower().strip().replace("-", "").replace(".", "")


def deduplicate_key_ids(key_ids: list[str]) -> list[str]:
    """
    Remove duplicate Key IDs while preserving order.

    Args:
        key_ids: List of Key IDs (normalized)

    Returns:
        List of unique Key IDs in original order
    """
    seen = set()
    result = []

    for kid in key_ids:
        if kid not in seen:
            seen.add(kid)
            result.append(kid)

    return result