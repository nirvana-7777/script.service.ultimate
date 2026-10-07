"""
DRM-specific Exception Classes

Custom exceptions for better error handling and debugging in DRM operations.

All of them descend from DRMError, which is a ConfigurationError and
therefore a ProviderError (base/errors.py). A caller that handles
``ProviderError`` now also catches DRM configuration problems; before this
change DRMError derived from plain Exception and slipped past every
``except ProviderError`` handler.
"""

from ...errors import ConfigurationError


class DRMError(ConfigurationError):
    """Base exception for all DRM-related errors.

    ``message`` is optional so call sites that raise a bare
    ``InvalidPSSHError()`` keep working (ProviderError itself requires one).
    """

    def __init__(self, message: str = "", **kw) -> None:
        super().__init__(message, **kw)


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