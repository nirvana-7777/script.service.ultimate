# streaming_providers/providers/discovery/exceptions.py
"""
Discovery+ Provider Exceptions

Specific exception types for Discovery+ provider operations.
"""


class DiscoveryError(Exception):
    """Base exception for Discovery provider errors"""
    pass


class PlaybackRestrictedException(DiscoveryError):
    """Exception raised when content playback is restricted"""

    def __init__(self, reason: str = "", error_code: str = ""):
        """
        Initialize playback restriction exception.

        Args:
            reason: Human-readable reason for restriction
            error_code: Machine-readable error code
        """
        self.reason = reason
        self.error_code = error_code

        message = "Playback restricted"
        if reason:
            message = f"{message}: {reason}"
        if error_code:
            message = f"{message} ({error_code})"

        super().__init__(message)


class AuthenticationError(DiscoveryError):
    """Base exception for authentication failures"""
    pass


class InvalidCredentialsError(AuthenticationError):
    """Invalid or missing credentials provided"""

    def __init__(self, message: str = "Invalid or missing credentials"):
        super().__init__(message)


class UnsupportedCredentialTypeError(AuthenticationError):
    """Unsupported credential type provided"""

    def __init__(self, credential_type: str):
        self.credential_type = credential_type
        super().__init__(f"Unsupported credential type: {credential_type}")


class TokenExpiredError(AuthenticationError):
    """Authentication token has expired"""

    def __init__(self, message: str = "Authentication token has expired"):
        super().__init__(message)


class EndpointDiscoveryError(DiscoveryError):
    """Failed to discover API endpoints"""

    def __init__(self, message: str = "Failed to discover API endpoints"):
        super().__init__(message)


class ChannelNotFoundError(DiscoveryError):
    """Requested channel not found"""

    def __init__(self, channel_id: str):
        self.channel_id = channel_id
        super().__init__(f"Channel not found: {channel_id}")


class ManifestFetchError(DiscoveryError):
    """Failed to fetch streaming manifest"""

    def __init__(self, message: str = "Failed to fetch streaming manifest"):
        super().__init__(message)


class DRMConfigurationError(DiscoveryError):
    """DRM configuration error"""

    def __init__(self, message: str = "DRM configuration error"):
        super().__init__(message)