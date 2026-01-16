# streaming_providers/base/utils/vfs.py
"""
Virtual File System abstraction layer
Provides transparent file operations for both Kodi and regular Python environments
"""

import json
import os
from typing import Any, Dict, List, Optional, Tuple

# Import centralized environment manager
from .environment import get_environment_manager, is_kodi_environment

# Import centralized logger
from .logger import logger


class VFS:
    """
    Virtual File System abstraction layer

    Provides a unified interface for file operations that works in both
    Kodi addon environments and standard Python environments.
    """

    def __init__(self, config_dir: Optional[str] = None, addon_subdir: str = ""):
        """
        Initialize VFS handler with explicit config directory support

        Args:
            config_dir: Optional explicit config directory (overrides automatic detection)
            addon_subdir: Optional subdirectory within addon data (for organization)
        """
        self.addon_subdir = addon_subdir
        self._base_path = None
        self._explicit_config_dir = config_dir
        self._env_manager = get_environment_manager()

        logger.debug(f"VFS initialized with config_dir={config_dir}, addon_subdir={addon_subdir}")

    @property
    def base_path(self) -> str:
        """Get the base path for file operations"""
        if self._base_path is None:
            if self._explicit_config_dir:
                # Use explicitly provided config directory
                self._base_path = self._explicit_config_dir
                logger.info(f"Using explicit config directory: {self._base_path}")
            else:
                # Use profile path from environment manager
                profile_path = self._env_manager.get_config("profile_path", "")
                if self.addon_subdir:
                    if is_kodi_environment():
                        # Kodi uses forward slashes
                        self._base_path = os.path.join(profile_path, self.addon_subdir).replace(
                            "\\", "/"
                        )
                    else:
                        # Standard filesystem
                        self._base_path = os.path.join(profile_path, self.addon_subdir)
                else:
                    self._base_path = profile_path

                logger.info(f"Base path from environment: {self._base_path}")

            # Ensure base directory exists
            self.mkdirs("")

        return self._base_path

    def join_path(self, *parts) -> str:
        """
        Join path components using appropriate separator for environment

        Args:
            *parts: Path components to join

        Returns:
            Joined path string
        """
        if is_kodi_environment():
            # Kodi VFS uses forward slashes
            path = self.base_path
            for part in parts:
                if part:
                    path = path.rstrip("/") + "/" + str(part).lstrip("/")
            return path
        else:
            # Use os.path.join for standard filesystem
            return os.path.join(self.base_path, *[str(p) for p in parts if p])

    def exists(self, filepath: str) -> bool:
        """
        Check if file or directory exists

        Args:
            filepath: Path to check (relative to base_path or absolute)

        Returns:
            True if exists, False otherwise
        """
        try:
            if not os.path.isabs(filepath):
                filepath = self.join_path(filepath)

            if is_kodi_environment():
                import xbmcvfs

                return xbmcvfs.exists(filepath)
            else:
                import pathlib

                return pathlib.Path(filepath).exists()
        except Exception as e:
            logger.error(f"Error checking if {filepath} exists: {e}")
            return False

    def mkdirs(self, dirpath: str) -> bool:
        """
        Create directory and all parent directories

        Args:
            dirpath: Directory path to create

        Returns:
            True if successful, False otherwise
        """
        try:
            if not os.path.isabs(dirpath):
                dirpath = self.join_path(dirpath)

            if is_kodi_environment():
                import xbmcvfs

                if not xbmcvfs.exists(dirpath):
                    result = xbmcvfs.mkdirs(dirpath)
                    logger.debug(f"Kodi mkdirs {dirpath}: {result}")
                    return result
                return True
            else:
                import pathlib

                pathlib.Path(dirpath).mkdir(parents=True, exist_ok=True)
                return True
        except Exception as e:
            logger.error(f"Error creating directory {dirpath}: {e}")
            return False

    def read_text(self, filepath: str, encoding: str = "utf-8") -> Optional[str]:
        """
        Read text content from file

        Args:
            filepath: File path to read
            encoding: Text encoding (ignored in Kodi VFS)

        Returns:
            File content as string or None if error/not found
        """
        try:
            if not os.path.isabs(filepath):
                filepath = self.join_path(filepath)

            if is_kodi_environment():
                import xbmcvfs

                if not xbmcvfs.exists(filepath):
                    return None
                with xbmcvfs.File(filepath, "r") as f:
                    content = f.read()
                    return content if content else None
            else:
                import pathlib

                path = pathlib.Path(filepath)
                if not path.exists():
                    return None
                with open(path, "r", encoding=encoding) as f:
                    return f.read()
        except Exception as e:
            logger.error(f"Error reading file {filepath}: {e}")
            return None

    def write_text(self, filepath: str, content: str, encoding: str = "utf-8") -> bool:
        """
        Write text content to file

        Args:
            filepath: File path to write
            content: Text content to write
            encoding: Text encoding (ignored in Kodi VFS)

        Returns:
            True if successful, False otherwise
        """
        try:
            if not os.path.isabs(filepath):
                filepath = self.join_path(filepath)

            if is_kodi_environment():
                import xbmcvfs

                # Ensure directory exists
                dir_path = "/".join(filepath.split("/")[:-1])
                if dir_path and not xbmcvfs.exists(dir_path):
                    xbmcvfs.mkdirs(dir_path)

                with xbmcvfs.File(filepath, "w") as f:
                    bytes_written = f.write(content)
                    logger.debug(f"Kodi file write: {bytes_written} bytes to {filepath}")
                    return bytes_written > 0
            else:
                import pathlib

                path = pathlib.Path(filepath)
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, "w", encoding=encoding) as f:
                    f.write(content)
                return True
        except Exception as e:
            logger.error(f"Error writing file {filepath}: {e}")
            return False

    def delete(self, filepath: str) -> bool:
        """
        Delete file

        Args:
            filepath: File path to delete

        Returns:
            True if successful, False otherwise
        """
        try:
            if not os.path.isabs(filepath):
                filepath = self.join_path(filepath)

            if is_kodi_environment():
                import xbmcvfs

                if xbmcvfs.exists(filepath):
                    return xbmcvfs.delete(filepath)
                return True
            else:
                import pathlib

                path = pathlib.Path(filepath)
                if path.exists():
                    path.unlink()
                return True
        except Exception as e:
            logger.error(f"Error deleting file {filepath}: {e}")
            return False

    def read_json(self, filepath: str) -> Optional[dict]:
        """
        Read and parse JSON file

        Args:
            filepath: JSON file path to read

        Returns:
            Parsed JSON data or None if error/not found
        """
        try:
            content = self.read_text(filepath)
            if content:
                return json.loads(content)
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {filepath}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error reading JSON file {filepath}: {e}")
            return None

    def write_json(self, filepath: str, data: Any, indent: int = 2) -> bool:
        """
        Write data to JSON file

        Args:
            filepath: JSON file path to write
            data: Data to serialize as JSON
            indent: JSON indentation level

        Returns:
            True if successful, False otherwise
        """
        try:
            content = json.dumps(data, indent=indent, ensure_ascii=False, default=str)
            return self.write_text(filepath, content)
        except Exception as e:
            logger.error(f"Error writing JSON file {filepath}: {e}")
            return False

    def list_files(self, dirpath: str = "", pattern: str = "*") -> List[str]:
        """
        List files in directory

        Args:
            dirpath: Directory path to list (relative to base_path)
            pattern: File pattern filter (basic glob patterns)

        Returns:
            List of filenames
        """
        try:
            if not dirpath:
                dirpath = self.base_path
            elif not os.path.isabs(dirpath):
                dirpath = self.join_path(dirpath)

            if is_kodi_environment():
                import fnmatch

                import xbmcvfs

                if not xbmcvfs.exists(dirpath):
                    return []

                dirs, files = xbmcvfs.listdir(dirpath)
                # Basic pattern matching (only supports * wildcard)
                if pattern == "*":
                    return files
                else:
                    # Simple pattern matching
                    return [f for f in files if fnmatch.fnmatch(f, pattern)]
            else:
                import pathlib

                path = pathlib.Path(dirpath)
                if not path.exists() or not path.is_dir():
                    return []

                if pattern == "*":
                    return [f.name for f in path.iterdir() if f.is_file()]
                else:
                    return [f.name for f in path.glob(pattern) if f.is_file()]
        except Exception as e:
            logger.error(f"Error listing files in {dirpath}: {e}")
            return []

    def get_size(self, filepath: str) -> Optional[int]:
        """
        Get file size in bytes

        Args:
            filepath: File path

        Returns:
            File size in bytes or None if error/not found
        """
        try:
            if not os.path.isabs(filepath):
                filepath = self.join_path(filepath)

            if is_kodi_environment():
                import xbmcvfs

                if not xbmcvfs.exists(filepath):
                    return None
                stat = xbmcvfs.Stat(filepath)
                return stat.st_size()
            else:
                import pathlib

                path = pathlib.Path(filepath)
                if not path.exists():
                    return None
                return path.stat().st_size
        except Exception as e:
            logger.error(f"Error getting size of {filepath}: {e}")
            return None

    def ensure_directory(self, filepath: str) -> bool:
        """
        Ensure directory for filepath exists

        Args:
            filepath: File path to ensure directory for

        Returns:
            True if successful, False otherwise
        """
        try:
            if not os.path.isabs(filepath):
                filepath = self.join_path(filepath)

            dir_path = os.path.dirname(filepath)
            return self.mkdirs(dir_path)
        except Exception as e:
            logger.error(f"Error ensuring directory for {filepath}: {e}")
            return False

    def debug_info(self) -> dict:
        """
        Get debug information about the VFS environment

        Returns:
            Dictionary with debug information
        """
        info = {
            "kodi_available": is_kodi_environment(),
            "base_path": self.base_path,
            "base_path_exists": self.exists(""),
            "explicit_config_dir": self._explicit_config_dir,
            "addon_subdir": self.addon_subdir,
            "environment": self._env_manager.get_environment(),
        }

        if is_kodi_environment():
            try:
                import xbmc
                import xbmcaddon

                addon = xbmcaddon.Addon()
                info.update(
                    {
                        "addon_id": addon.getAddonInfo("id"),
                        "addon_version": addon.getAddonInfo("version"),
                        "kodi_version": xbmc.getInfoLabel("System.BuildVersion"),
                    }
                )
            except Exception as e:
                info["kodi_error"] = str(e)

        return info


# Cache for VFS instances with different configurations
_vfs_cache: Dict[Tuple[Optional[str], str], "VFS"] = {}


def get_vfs(config_dir: Optional[str] = None, addon_subdir: str = "") -> "VFS":
    """
    Get VFS instance for specific configuration

    Uses a cache to avoid creating multiple instances with same configuration

    Args:
        config_dir: Optional explicit config directory
        addon_subdir: Optional subdirectory within addon data

    Returns:
        VFS instance
    """
    global _vfs_cache

    cache_key = (config_dir, addon_subdir)

    if cache_key not in _vfs_cache:
        _vfs_cache[cache_key] = VFS(config_dir, addon_subdir)

    return _vfs_cache[cache_key]


# For backward compatibility with existing code
_global_vfs = None


def get_global_vfs(config_dir: Optional[str] = None, addon_subdir: str = "") -> "VFS":
    """
    Get global VFS instance (for backward compatibility)

    Note: Consider using get_vfs() for new code
    """
    global _global_vfs
    vfs = get_vfs(config_dir, addon_subdir)
    _global_vfs = vfs  # Keep reference for backward compatibility
    return vfs


# Convenience functions that use VFS cache
def exists(filepath: str, config_dir: Optional[str] = None, addon_subdir: str = "") -> bool:
    """Check if file exists"""
    return get_vfs(config_dir, addon_subdir).exists(filepath)


def mkdirs(dirpath: str, config_dir: Optional[str] = None, addon_subdir: str = "") -> bool:
    """Create directories"""
    return get_vfs(config_dir, addon_subdir).mkdirs(dirpath)


def read_text(
    filepath: str,
    encoding: str = "utf-8",
    config_dir: Optional[str] = None,
    addon_subdir: str = "",
) -> Optional[str]:
    """Read text file"""
    return get_vfs(config_dir, addon_subdir).read_text(filepath, encoding)


def write_text(
    filepath: str,
    content: str,
    encoding: str = "utf-8",
    config_dir: Optional[str] = None,
    addon_subdir: str = "",
) -> bool:
    """Write text file"""
    return get_vfs(config_dir, addon_subdir).write_text(filepath, content, encoding)


def read_json(
    filepath: str, config_dir: Optional[str] = None, addon_subdir: str = ""
) -> Optional[dict]:
    """Read JSON file"""
    return get_vfs(config_dir, addon_subdir).read_json(filepath)


def write_json(
    filepath: str,
    data: Any,
    indent: int = 2,
    config_dir: Optional[str] = None,
    addon_subdir: str = "",
) -> bool:
    """Write JSON file"""
    return get_vfs(config_dir, addon_subdir).write_json(filepath, data, indent)


def delete(filepath: str, config_dir: Optional[str] = None, addon_subdir: str = "") -> bool:
    """Delete file"""
    return get_vfs(config_dir, addon_subdir).delete(filepath)


def join_path(*parts, config_dir: Optional[str] = None, addon_subdir: str = "") -> str:
    """Join path components"""
    vfs = get_vfs(config_dir, addon_subdir)
    return vfs.join_path(*parts)
