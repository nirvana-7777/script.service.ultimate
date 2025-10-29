# streaming_providers/base/utils/vfs.py
"""
Virtual File System abstraction layer
Provides transparent file operations for both Kodi and regular Python environments
"""

import json
import os
from typing import Optional, Any, List
from pathlib import Path

# Import centralized logger
from .logger import logger

# Kodi imports - with fallback for non-Kodi environments
try:
    import xbmc
    import xbmcvfs
    import xbmcaddon

    KODI_AVAILABLE = True
    logger.info("Kodi VFS environment detected")
except ImportError:
    KODI_AVAILABLE = False
    logger.info("Standard filesystem environment detected")


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
        logger.debug(f"VFS initialized with config_dir={config_dir}, addon_subdir={addon_subdir}")

    @property
    def base_path(self) -> str:
        """Get the base path for file operations"""
        if self._base_path is None:
            if self._explicit_config_dir:
                # Use explicitly provided config directory
                self._base_path = self._explicit_config_dir
                logger.info(f"Using explicit config directory: {self._base_path}")
            elif KODI_AVAILABLE:
                # Use Kodi's addon data directory
                try:
                    addon = xbmcaddon.Addon()
                    # Use xbmcvfs.translatePath instead of xbmc.translatePath for Kodi 19+
                    addon_profile = xbmcvfs.translatePath(addon.getAddonInfo('profile'))
                    if self.addon_subdir:
                        self._base_path = os.path.join(addon_profile, self.addon_subdir).replace('\\', '/')
                    else:
                        self._base_path = addon_profile.replace('\\', '/')
                    logger.info(f"Kodi base path: {self._base_path}")
                except Exception as e:
                    logger.error(f"Error getting Kodi addon path: {e}")
                    # Fallback to temp directory
                    try:
                        self._base_path = xbmcvfs.translatePath("special://temp/streaming_providers")
                    except:
                        self._base_path = "/tmp/streaming_providers"
            else:
                # Use standard filesystem
                if self.addon_subdir:
                    self._base_path = str(Path.home() / '.streaming_providers' / self.addon_subdir)
                else:
                    self._base_path = str(Path.home() / '.streaming_providers')
                logger.info(f"Standard filesystem base path: {self._base_path}")

            # Ensure base directory exists
            self.mkdirs('')

        return self._base_path

    def join_path(self, *parts) -> str:
        """
        Join path components using appropriate separator for environment

        Args:
            *parts: Path components to join

        Returns:
            Joined path string
        """
        if KODI_AVAILABLE:
            # Kodi VFS uses forward slashes
            path = self.base_path
            for part in parts:
                if part:
                    path = path.rstrip('/') + '/' + str(part).lstrip('/')
            return path
        else:
            # Use pathlib for standard filesystem
            path = Path(self.base_path)
            for part in parts:
                if part:
                    path = path / str(part)
            return str(path)

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

            if KODI_AVAILABLE:
                return xbmcvfs.exists(filepath)
            else:
                return Path(filepath).exists()
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

            if KODI_AVAILABLE:
                if not xbmcvfs.exists(dirpath):
                    result = xbmcvfs.mkdirs(dirpath)
                    logger.debug(f"Kodi mkdirs {dirpath}: {result}")
                    return result
                return True
            else:
                Path(dirpath).mkdir(parents=True, exist_ok=True)
                return True
        except Exception as e:
            logger.error(f"Error creating directory {dirpath}: {e}")
            return False

    def read_text(self, filepath: str, encoding: str = 'utf-8') -> Optional[str]:
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

            if KODI_AVAILABLE:
                if not xbmcvfs.exists(filepath):
                    return None
                with xbmcvfs.File(filepath, 'r') as f:
                    content = f.read()
                    return content if content else None
            else:
                path = Path(filepath)
                if not path.exists():
                    return None
                with open(path, 'r', encoding=encoding) as f:
                    return f.read()
        except Exception as e:
            logger.error(f"Error reading file {filepath}: {e}")
            return None

    def write_text(self, filepath: str, content: str, encoding: str = 'utf-8') -> bool:
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

            if KODI_AVAILABLE:
                # Ensure directory exists
                dir_path = '/'.join(filepath.split('/')[:-1])
                if dir_path and not xbmcvfs.exists(dir_path):
                    xbmcvfs.mkdirs(dir_path)

                with xbmcvfs.File(filepath, 'w') as f:
                    bytes_written = f.write(content)
                    logger.debug(f"Kodi file write: {bytes_written} bytes to {filepath}")
                    return bytes_written > 0
            else:
                path = Path(filepath)
                path.parent.mkdir(parents=True, exist_ok=True)
                with open(path, 'w', encoding=encoding) as f:
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

            if KODI_AVAILABLE:
                if xbmcvfs.exists(filepath):
                    return xbmcvfs.delete(filepath)
                return True
            else:
                path = Path(filepath)
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

            if KODI_AVAILABLE:
                if not xbmcvfs.exists(dirpath):
                    return []

                dirs, files = xbmcvfs.listdir(dirpath)
                # Basic pattern matching (only supports * wildcard)
                if pattern == "*":
                    return files
                else:
                    # Simple pattern matching
                    import fnmatch
                    return [f for f in files if fnmatch.fnmatch(f, pattern)]
            else:
                path = Path(dirpath)
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

            if KODI_AVAILABLE:
                if not xbmcvfs.exists(filepath):
                    return None
                stat = xbmcvfs.Stat(filepath)
                return stat.st_size()
            else:
                path = Path(filepath)
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
            'kodi_available': KODI_AVAILABLE,
            'base_path': self.base_path,
            'base_path_exists': self.exists(''),
            'explicit_config_dir': self._explicit_config_dir,
            'addon_subdir': self.addon_subdir
        }

        if KODI_AVAILABLE:
            try:
                addon = xbmcaddon.Addon()
                info.update({
                    'addon_id': addon.getAddonInfo('id'),
                    'addon_version': addon.getAddonInfo('version'),
                    'kodi_version': xbmc.getInfoLabel('System.BuildVersion'),
                })
            except Exception as e:
                info['kodi_error'] = str(e)

        return info


# Convenience functions for global VFS instance
_global_vfs = None


def get_vfs(config_dir: Optional[str] = None, addon_subdir: str = "") -> VFS:
    """
    Get global VFS instance

    Args:
        config_dir: Optional explicit config directory
        addon_subdir: Optional subdirectory within addon data

    Returns:
        VFS instance
    """
    global _global_vfs
    if _global_vfs is None or _global_vfs._explicit_config_dir != config_dir or _global_vfs.addon_subdir != addon_subdir:
        _global_vfs = VFS(config_dir, addon_subdir)
    return _global_vfs


# Convenience functions that use global VFS
def exists(filepath: str, config_dir: Optional[str] = None) -> bool:
    """Check if file exists"""
    return get_vfs(config_dir).exists(filepath)


def mkdirs(dirpath: str, config_dir: Optional[str] = None) -> bool:
    """Create directories"""
    return get_vfs(config_dir).mkdirs(dirpath)


def read_text(filepath: str, encoding: str = 'utf-8', config_dir: Optional[str] = None) -> Optional[str]:
    """Read text file"""
    return get_vfs(config_dir).read_text(filepath, encoding)


def write_text(filepath: str, content: str, encoding: str = 'utf-8', config_dir: Optional[str] = None) -> bool:
    """Write text file"""
    return get_vfs(config_dir).write_text(filepath, content, encoding)


def read_json(filepath: str, config_dir: Optional[str] = None) -> Optional[dict]:
    """Read JSON file"""
    return get_vfs(config_dir).read_json(filepath)


def write_json(filepath: str, data: Any, indent: int = 2, config_dir: Optional[str] = None) -> bool:
    """Write JSON file"""
    return get_vfs(config_dir).write_json(filepath, data, indent)


def delete(filepath: str, config_dir: Optional[str] = None) -> bool:
    """Delete file"""
    return get_vfs(config_dir).delete(filepath)


def join_path(*parts, config_dir: Optional[str] = None) -> str:
    """Join path components"""
    vfs = get_vfs(config_dir)
    return vfs.join_path(*parts)