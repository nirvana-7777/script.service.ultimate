# streaming_providers/base/utils/logger.py
import xbmc


class XBMCLogger:
    """Centralized logging using XBMC's logging system."""

    def __init__(self, addon_name: str, addon_version: str):
        self.addon_name = addon_name
        self.addon_version = addon_version
        self.prefix = f"[{addon_name} v{addon_version}]"

    def log(self, message: str, level: int = xbmc.LOGINFO) -> None:
        """Main logging method.

        Args:
            message: The message to log
            level: One of xbmc.LOGDEBUG, LOGINFO, LOGWARNING, LOGERROR, LOGFATAL
        """
        xbmc.log(f"{self.prefix} {message}", level)

    def debug(self, message: str) -> None:
        self.log(message, xbmc.LOGDEBUG)

    def info(self, message: str) -> None:
        self.log(message, xbmc.LOGINFO)

    def warning(self, message: str) -> None:
        self.log(message, xbmc.LOGWARNING)

    def error(self, message: str, exc_info=False) -> None:
        self.log(message, xbmc.LOGERROR)

    def critical(self, message: str) -> None:
        self.log(message, xbmc.LOGFATAL)

    def log_auth_event(self, provider: str, event: str, details: str = "") -> None:
        """Specialized logging method for authentication events."""
        message = f"AUTH [{provider}] {event}"
        if details:
            message += f" - {details}"
        self.info(message)

    def log_credential_event(self, provider: str, event: str, details: str = "") -> None:
        """Specialized logging method for credential management events."""
        message = f"CRED [{provider}] {event}"
        if details:
            message += f" - {details}"
        self.info(message)

    def log_session_event(self, provider: str, event: str, details: str = "") -> None:
        """Specialized logging method for session management events."""
        message = f"SESSION [{provider}] {event}"
        if details:
            message += f" - {details}"
        self.debug(message)


# Initialize with your addon info
logger = XBMCLogger(
    addon_name="Ultimate Backend",
    addon_version="1.0.0"  # You could get this from your addon.xml
)