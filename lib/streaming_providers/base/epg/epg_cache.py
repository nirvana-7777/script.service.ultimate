#!/usr/bin/env python3
# streaming_providers/base/epg/epg_cache.py
"""
EPG Cache Manager using VFS
Handles downloading, caching, and TTL management for EPG XML files
"""

import time
from typing import Dict, Optional

from ..utils.logger import logger
from ..utils.vfs import VFS


class EPGCache:
    """
    Manages EPG XML file caching with VFS backend.
    Handles both plain and gzipped XML files.
    """

    # Cache TTL: 24 hours
    CACHE_TTL_SECONDS = 24 * 60 * 60

    # File names
    EPG_FILE = "epg.xml"
    EPG_GZ_FILE = "epg.xml.gz"
    METADATA_FILE = "epg_metadata.json"

    def __init__(self, vfs_subdir: str = "epg_cache"):
        """
        Initialize EPG cache manager.

        Args:
            vfs_subdir: Subdirectory under addon data for EPG cache
        """
        self.vfs = VFS(addon_subdir=vfs_subdir)
        logger.info(f"EPGCache: Initialized with VFS path: {self.vfs.base_path}")

    def _get_metadata(self) -> Optional[Dict]:
        """
        Load cache metadata from VFS.

        Returns:
            Metadata dictionary or None if not found/invalid
        """
        metadata = self.vfs.read_json(self.METADATA_FILE)
        if metadata:
            logger.debug(f"EPGCache: Loaded metadata: {metadata}")
        return metadata

    def _save_metadata(self, url: str, file_size: int, is_gzipped: bool) -> bool:
        """
        Save cache metadata to VFS.

        Args:
            url: EPG source URL
            file_size: Size of cached file in bytes
            is_gzipped: Whether file is gzipped

        Returns:
            True if saved successfully
        """
        metadata = {
            "downloaded_at": int(time.time()),
            "url": url,
            "file_size": file_size,
            "is_gzipped": is_gzipped,
        }

        success = self.vfs.write_json(self.METADATA_FILE, metadata)
        if success:
            logger.info(f"EPGCache: Saved metadata for {url}")
        else:
            logger.error(f"EPGCache: Failed to save metadata")
        return success

    def is_cache_valid(self) -> bool:
        """
        Check if cached EPG is still valid (within TTL).

        Returns:
            True if cache exists and is valid
        """
        metadata = self._get_metadata()
        if not metadata:
            logger.debug("EPGCache: No metadata found, cache invalid")
            return False

        # Check if EPG file exists
        filename = self.EPG_GZ_FILE if metadata.get("is_gzipped") else self.EPG_FILE
        if not self.vfs.exists(filename):
            logger.debug(f"EPGCache: EPG file '{filename}' not found, cache invalid")
            return False

        # Check TTL
        downloaded_at = metadata.get("downloaded_at", 0)
        age = int(time.time()) - downloaded_at

        if age > self.CACHE_TTL_SECONDS:
            logger.info(f"EPGCache: Cache expired (age: {age}s, TTL: {self.CACHE_TTL_SECONDS}s)")
            return False

        logger.debug(f"EPGCache: Cache valid (age: {age}s)")
        return True

    def get_cached_file_path(self) -> Optional[str]:
        """
        Get path to cached EPG file if valid.

        Returns:
            Full path to EPG file, or None if cache invalid
        """
        if not self.is_cache_valid():
            return None

        metadata = self._get_metadata()
        if not metadata:
            return None

        filename = self.EPG_GZ_FILE if metadata.get("is_gzipped") else self.EPG_FILE
        file_path = self.vfs.join_path(filename)

        logger.debug(f"EPGCache: Returning cached file path: {file_path}")
        return file_path

    def download_and_cache(self, url: str) -> Optional[str]:
        """
        Download EPG file from URL and cache it.
        Handles both plain and gzipped files automatically.

        Args:
            url: URL to download EPG from

        Returns:
            Path to cached file, or None on failure
        """
        logger.info(f"EPGCache: Downloading EPG from {url}")

        try:
            import requests

            # Download with streaming to handle large files
            response = requests.get(url, stream=True, timeout=60)
            response.raise_for_status()

            # Determine if content is gzipped
            content_type = response.headers.get("Content-Type", "").lower()
            content_encoding = response.headers.get("Content-Encoding", "").lower()
            is_gzipped = "gzip" in content_encoding or url.endswith(".gz") or "gzip" in content_type

            filename = self.EPG_GZ_FILE if is_gzipped else self.EPG_FILE

            # Get full file path
            file_path = self.vfs.join_path(filename)

            # Ensure directory exists
            self.vfs.ensure_directory(file_path)

            # Download in chunks
            chunk_size = 8192
            total_size = 0

            with open(file_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        total_size += len(chunk)

            logger.info(f"EPGCache: Downloaded {total_size} bytes to {filename}")

            # Save metadata
            self._save_metadata(url, total_size, is_gzipped)

            return file_path

        except Exception as e:
            logger.error(f"EPGCache: Download failed: {e}", exc_info=True)
            return None

    def get_or_download(self, url: str) -> Optional[str]:
        """
        Get cached EPG file path, or download if cache is invalid.

        Args:
            url: URL to download from if cache invalid

        Returns:
            Path to EPG file (cached or freshly downloaded), or None on failure
        """
        # Try cache first
        cached_path = self.get_cached_file_path()
        if cached_path:
            logger.info("EPGCache: Using cached EPG file")
            return cached_path

        # Cache miss or expired - download new
        logger.info("EPGCache: Cache miss or expired, downloading")
        return self.download_and_cache(url)

    def clear_cache(self) -> bool:
        """
        Clear all cached EPG files and metadata.

        Returns:
            True if cleared successfully
        """
        logger.info("EPGCache: Clearing cache")

        success = True

        # Delete EPG files
        for filename in [self.EPG_FILE, self.EPG_GZ_FILE, self.METADATA_FILE]:
            if self.vfs.exists(filename):
                if not self.vfs.delete(filename):
                    logger.warning(f"EPGCache: Failed to delete {filename}")
                    success = False

        if success:
            logger.info("EPGCache: Cache cleared successfully")

        return success

    def get_cache_info(self) -> Optional[Dict]:
        """
        Get information about cached EPG.

        Returns:
            Dictionary with cache info, or None if no cache
        """
        metadata = self._get_metadata()
        if not metadata:
            return None

        filename = self.EPG_GZ_FILE if metadata.get("is_gzipped") else self.EPG_FILE
        file_exists = self.vfs.exists(filename)

        age = int(time.time()) - metadata.get("downloaded_at", 0)
        is_valid = self.is_cache_valid()

        return {
            "url": metadata.get("url"),
            "downloaded_at": metadata.get("downloaded_at"),
            "age_seconds": age,
            "file_size": metadata.get("file_size"),
            "is_gzipped": metadata.get("is_gzipped"),
            "file_exists": file_exists,
            "is_valid": is_valid,
            "ttl_seconds": self.CACHE_TTL_SECONDS,
        }
