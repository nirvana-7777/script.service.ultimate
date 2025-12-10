# streaming_providers/base/utils/logger.py
"""
Centralized logging module for Ultimate Backend.
Provides environment-aware logging for both Kodi and standalone modes.
"""

import sys
import logging

# Import environment manager
from .environment import get_environment_manager

# Get environment manager
_env_manager_instance = get_environment_manager()


class BaseLogger:
    """Base logger interface that all logger implementations must follow"""

    def __init__(self, logger_name: str, logger_version: str):
        self.logger_name = logger_name
        self.logger_version = logger_version
        self.prefix = f"[{logger_name} v{logger_version}]"

    def debug(self, message: str) -> None:
        """Log debug message"""
        raise NotImplementedError

    def info(self, message: str) -> None:
        """Log info message"""
        raise NotImplementedError

    def warning(self, message: str) -> None:
        """Log warning message"""
        raise NotImplementedError

    def error(self, message: str, exc_info: bool = False) -> None:
        """Log error message"""
        raise NotImplementedError

    def critical(self, message: str) -> None:
        """Log critical message"""
        raise NotImplementedError

    # Specialized methods
    def log_auth_event(self, provider: str, event: str, details: str = "") -> None:
        """Log authentication event"""
        log_message = f"AUTH [{provider}] {event}"
        if details:
            log_message += f" - {details}"
        self.info(log_message)

    def log_credential_event(self, provider: str, event: str, details: str = "") -> None:
        """Log credential event"""
        log_message = f"CRED [{provider}] {event}"
        if details:
            log_message += f" - {details}"
        self.info(log_message)

    def log_session_event(self, provider: str, event: str, details: str = "") -> None:
        """Log session event"""
        log_message = f"SESSION [{provider}] {event}"
        if details:
            log_message += f" - {details}"
        self.debug(log_message)


def create_logger() -> BaseLogger:
    """Create appropriate logger instance based on environment"""

    # Get configuration
    app_name = _env_manager_instance.get_config('addon_name', 'Ultimate Backend')
    app_version = _env_manager_instance.get_config('addon_version', '1.0.0')

    if _env_manager_instance.is_kodi():
        # Try to create Kodi logger
        try:
            import xbmc

            class XBMCLogger(BaseLogger):
                """Centralized logging using XBMC's logging system."""

                def debug(self, message: str) -> None:
                    xbmc.log(f"{self.prefix} {message}", xbmc.LOGDEBUG)

                def info(self, message: str) -> None:
                    xbmc.log(f"{self.prefix} {message}", xbmc.LOGINFO)

                def warning(self, message: str) -> None:
                    xbmc.log(f"{self.prefix} {message}", xbmc.LOGWARNING)

                def error(self, message: str, exc_info: bool = False) -> None:
                    xbmc.log(f"{self.prefix} {message}", xbmc.LOGERROR)

                def critical(self, message: str) -> None:
                    xbmc.log(f"{self.prefix} {message}", xbmc.LOGFATAL)

            return XBMCLogger(str(app_name), str(app_version))

        except ImportError as xbmc_import_error:
            print(f"Failed to import xbmc: {xbmc_import_error}", file=sys.stderr)
            # Fall through to standard logger

    # Create standard logger (fallback for non-Kodi or failed Kodi)
    class StandardLogger(BaseLogger):
        """Standard Python logging for non-Kodi environments."""

        def __init__(self, logger_name: str, logger_version: str):
            super().__init__(logger_name, logger_version)

            # Configure logging
            self._logger = logging.getLogger(logger_name)

            # Only add handlers if none exist
            if not self._logger.handlers:
                # Console handler
                console_handler = logging.StreamHandler(sys.stdout)
                formatter = logging.Formatter(
                    f'%(asctime)s {self.prefix} %(levelname)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
                console_handler.setFormatter(formatter)
                self._logger.addHandler(console_handler)

                # File handler (optional)
                log_dir = _env_manager_instance.get_config('profile_path')
                if log_dir:
                    import os
                    log_file = os.path.join(str(log_dir), 'ultimate-backend.log')
                    try:
                        file_handler = logging.FileHandler(log_file, encoding='utf-8')
                        file_handler.setFormatter(formatter)
                        self._logger.addHandler(file_handler)
                    except (OSError, PermissionError) as file_handler_error:
                        # Log to console only if file logging fails
                        print(f"Failed to create file handler: {file_handler_error}", file=sys.stderr)

                self._logger.setLevel(logging.DEBUG)

        def debug(self, message: str) -> None:
            self._logger.debug(message)

        def info(self, message: str) -> None:
            self._logger.info(message)

        def warning(self, message: str) -> None:
            self._logger.warning(message)

        def error(self, message: str, exc_info: bool = False) -> None:
            if exc_info:
                self._logger.error(message, exc_info=True)
            else:
                self._logger.error(message)

        def critical(self, message: str) -> None:
            self._logger.critical(message)

    return StandardLogger(str(app_name), str(app_version))


# Create global logger instance - this is the actual logger object users will import
logger: BaseLogger = create_logger()

# Export the BaseLogger type for type hints
__all__ = ['BaseLogger', 'logger']