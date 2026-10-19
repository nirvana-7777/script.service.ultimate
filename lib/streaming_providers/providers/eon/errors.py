# streaming_providers/providers/eon/errors.py
"""Eon-specific typed errors (subclasses of base.errors)."""

from ...base.errors import AuthError


class EonLoginRejected(AuthError):
    """The password grant was refused (wrong credentials / unknown device).
    PERMANENT: no retry until the credentials change (see EonAuth gate)."""


class EonOtpRequiredError(AuthError):
    """
    Android TV login needs a one-time code the user enters in the operator's
    web portal. NOT retryable by the backend: the settings UI shows `otp`,
    the user confirms it, and the next auth attempt exchanges it.
    """

    def __init__(self, message: str, *, otp: str = "", expires_minutes: int = 0):
        super().__init__(message)
        self.otp = otp
        self.expires_minutes = expires_minutes