"""
DRM Models Package

Comprehensive DRM (Digital Rights Management) support for streaming providers.

This package provides:
- DRM system identification and configuration
- PSSH (Protection System Specific Header) parsing
- tenc (Track Encryption) box parsing
- License server configuration
- Multi-DRM support with priority handling

Usage:
    from streaming_providers.base.models.drm import (
        DRMSystem,
        DRMConfig,
        PSSHData,
        LicenseConfig,
    )

    # Create Widevine configuration
    drm_config = DRMConfig.create_widevine(
        server_url="https://license.example.com/widevine",
        priority=1
    )

    # Parse PSSH from manifest
    pssh_data = PSSHData(
        system_id="edef8ba9-79d6-4ace-a3c8-27dcd51d21ed",
        pssh_box="base64_encoded_pssh_box"
    )
"""

# Version
__version__ = "2.0.0"

# Core enums
from .drm_systems import DRMSystem

# Data models
from .pssh_data import PSSHData
from .license_config import (
    LicenseConfig,
    LicenseUnwrapperParams,
    WrapperType,
    UnwrapperType,
)
from .drm_config import DRMConfig

# Parsers (for advanced usage)
from .pssh_parser import PSSHParser
from .tenc_parser import TencParser

# Exceptions
from .exceptions import (
    DRMError,
    InvalidPSSHError,
    InvalidTencError,
    InvalidUUIDError,
    InvalidKeyIDError,
    PSSHSizeError,
    UnsupportedDRMSystemError,
    LicenseConfigError,
    Base64DecodingError,
)

# Utilities (for advanced usage)
from .utils import (
    normalize_uuid,
    format_uuid,
    normalize_key_id,
    bytes_to_uuid_hex,
    bytes_to_uuid_formatted,
    uuid_to_bytes,
    safe_base64_decode,
    safe_base64_encode,
    deduplicate_key_ids,
)

# Constants (for advanced usage)
from .constants import (
    PSSHOffsets,
    TencOffsets,
    MAX_PSSH_SIZE,
    MAX_TENC_SIZE,
    KID_SIZE_BYTES,
)

# Public API
__all__ = [
    # Version
    "__version__",

    # Core classes
    "DRMSystem",
    "DRMConfig",
    "PSSHData",
    "LicenseConfig",
    "LicenseUnwrapperParams",

    # Enums
    "WrapperType",
    "UnwrapperType",

    # Parsers
    "PSSHParser",
    "TencParser",

    # Exceptions
    "DRMError",
    "InvalidPSSHError",
    "InvalidTencError",
    "InvalidUUIDError",
    "InvalidKeyIDError",
    "PSSHSizeError",
    "UnsupportedDRMSystemError",
    "LicenseConfigError",
    "Base64DecodingError",

    # Utilities
    "normalize_uuid",
    "format_uuid",
    "normalize_key_id",
    "bytes_to_uuid_hex",
    "bytes_to_uuid_formatted",
    "uuid_to_bytes",
    "safe_base64_decode",
    "safe_base64_encode",
    "deduplicate_key_ids",

    # Constants
    "PSSHOffsets",
    "TencOffsets",
    "MAX_PSSH_SIZE",
    "MAX_TENC_SIZE",
    "KID_SIZE_BYTES",
]