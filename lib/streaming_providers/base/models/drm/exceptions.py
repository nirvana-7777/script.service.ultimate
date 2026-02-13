"""
DRM-specific Exception Classes

Custom exceptions for better error handling and debugging in DRM operations.
"""


class DRMError(Exception):
    """Base exception for all DRM-related errors"""
    pass


class InvalidPSSHError(DRMError):
    """Raised when PSSH box data is invalid or malformed"""
    pass


class InvalidTencError(DRMError):
    """Raised when tenc box data is invalid or malformed"""
    pass


class InvalidUUIDError(DRMError):
    """Raised when UUID format is invalid"""
    pass


class InvalidKeyIDError(DRMError):
    """Raised when Key ID format is invalid"""
    pass


class PSSHSizeError(DRMError):
    """Raised when PSSH box exceeds size limits"""
    pass


class UnsupportedDRMSystemError(DRMError):
    """Raised when DRM system is not supported"""
    pass


class LicenseConfigError(DRMError):
    """Raised when license configuration is invalid"""
    pass


class Base64DecodingError(DRMError):
    """Raised when base64 decoding fails"""
    pass