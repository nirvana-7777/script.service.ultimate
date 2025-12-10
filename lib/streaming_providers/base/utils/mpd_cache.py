# streaming_providers/base/utils/mpd_cache.py
import time
from typing import Optional
from .vfs import VFS
from .logger import logger


class MPDCacheManager:
    """
    Manages caching of rewritten MPD manifests with TTL support
    """

    def __init__(self):
        """Initialize MPD cache manager with VFS"""
        self.vfs = VFS(addon_subdir="mpd_cache")
        logger.debug(f"MPD cache initialized at: {self.vfs.base_path}")

    @staticmethod
    def _get_cache_key(provider: str, channel_id: str) -> str:
        """Generate cache key for provider/channel"""
        return f"{provider}_{channel_id}"

    @staticmethod
    def _get_manifest_filename(cache_key: str) -> str:
        """Get filename for cached manifest"""
        return f"{cache_key}.xml"

    @staticmethod
    def _get_meta_filename(cache_key: str) -> str:
        """Get filename for cache metadata"""
        return f"{cache_key}.meta"

    def get(self, provider: str, channel_id: str) -> Optional[str]:
        """
        Get cached MPD manifest if valid

        Args:
            provider: Provider name
            channel_id: Channel ID

        Returns:
            Cached MPD content if valid and not expired, None otherwise
        """
        cache_key = self._get_cache_key(provider, channel_id)
        meta_file = self._get_meta_filename(cache_key)
        manifest_file = self._get_manifest_filename(cache_key)

        try:
            # Read metadata first (small file)
            meta = self.vfs.read_json(meta_file)
            if not meta:
                logger.debug(f"No cache metadata found for {cache_key}")
                return None

            # Check expiry
            expiry = meta.get('expiry', 0)
            now = int(time.time())

            if now >= expiry:
                logger.debug(f"Cache expired for {cache_key} (expired {now - expiry}s ago)")
                # Clean up expired cache
                self.vfs.delete(manifest_file)
                self.vfs.delete(meta_file)
                return None

            # Cache is valid, read manifest
            manifest_content = self.vfs.read_text(manifest_file)
            if manifest_content:
                logger.info(f"Cache hit for {cache_key} (expires in {expiry - now}s)")
                return manifest_content
            else:
                logger.warning(f"Cache metadata exists but manifest file missing for {cache_key}")
                self.vfs.delete(meta_file)
                return None

        except Exception as e:
            logger.error(f"Error reading cache for {cache_key}: {e}")
            return None

    def set(self, provider: str, channel_id: str, mpd_content: str,
            ttl: int, original_url: Optional[str] = None) -> bool:
        """
        Store MPD manifest in cache with TTL

        Args:
            provider: Provider name
            channel_id: Channel ID
            mpd_content: Rewritten MPD content
            ttl: Time to live in seconds
            original_url: Original manifest URL (for debugging)

        Returns:
            True if successfully cached, False otherwise
        """
        cache_key = self._get_cache_key(provider, channel_id)
        meta_file = self._get_meta_filename(cache_key)
        manifest_file = self._get_manifest_filename(cache_key)

        try:
            # Calculate expiry timestamp
            expiry = int(time.time()) + ttl

            # Create metadata
            meta = {
                'expiry': expiry,
                'ttl': ttl,
                'cached_at': int(time.time()),
                'provider': provider,
                'channel_id': channel_id
            }

            if original_url:
                meta['original_url'] = original_url

            # Write manifest
            if not self.vfs.write_text(manifest_file, mpd_content):
                logger.error(f"Failed to write manifest cache for {cache_key}")
                return False

            # Write metadata
            if not self.vfs.write_json(meta_file, meta):
                logger.error(f"Failed to write metadata cache for {cache_key}")
                # Clean up manifest if metadata write failed
                self.vfs.delete(manifest_file)
                return False

            logger.info(f"Cached MPD for {cache_key} with TTL={ttl}s (expires at {expiry})")
            return True

        except Exception as e:
            logger.error(f"Error caching MPD for {cache_key}: {e}")
            return False

    def delete(self, provider: str, channel_id: str) -> bool:
        """
        Delete cached MPD for a channel

        Args:
            provider: Provider name
            channel_id: Channel ID

        Returns:
            True if deleted or didn't exist, False on error
        """
        cache_key = self._get_cache_key(provider, channel_id)
        meta_file = self._get_meta_filename(cache_key)
        manifest_file = self._get_manifest_filename(cache_key)

        try:
            self.vfs.delete(manifest_file)
            self.vfs.delete(meta_file)
            logger.debug(f"Deleted cache for {cache_key}")
            return True
        except Exception as e:
            logger.error(f"Error deleting cache for {cache_key}: {e}")
            return False

    def clear_all(self) -> bool:
        """
        Clear all cached MPD files

        Returns:
            True if successful, False otherwise
        """
        try:
            files = self.vfs.listdir()
            deleted = 0

            for file in files:
                if file.endswith('.xml') or file.endswith('.meta'):
                    if self.vfs.delete(file):
                        deleted += 1

            logger.info(f"Cleared {deleted} cached MPD files")
            return True

        except Exception as e:
            logger.error(f"Error clearing MPD cache: {e}")
            return False

    def clear_expired(self) -> int:
        """
        Clear all expired cached MPD files

        Returns:
            Number of expired entries cleared
        """
        try:
            files = self.vfs.listdir()
            now = int(time.time())
            cleared = 0

            # Find all meta files
            meta_files = [f for f in files if f.endswith('.meta')]

            for meta_file in meta_files:
                try:
                    meta = self.vfs.read_json(meta_file)
                    if meta and meta.get('expiry', 0) < now:
                        # Expired, delete both meta and manifest
                        cache_key = meta_file.replace('.meta', '')
                        self.vfs.delete(f"{cache_key}.xml")
                        self.vfs.delete(meta_file)
                        cleared += 1
                        logger.debug(f"Cleared expired cache: {cache_key}")
                except Exception as e:
                    logger.warning(f"Error checking {meta_file}: {e}")

            if cleared > 0:
                logger.info(f"Cleared {cleared} expired MPD cache entries")

            return cleared

        except Exception as e:
            logger.error(f"Error clearing expired caches: {e}")
            return 0

    def get_cache_info(self, provider: str, channel_id: str) -> Optional[dict]:
        """
        Get cache information without reading the full manifest

        Args:
            provider: Provider name
            channel_id: Channel ID

        Returns:
            Cache metadata dict or None if not cached
        """
        cache_key = self._get_cache_key(provider, channel_id)
        meta_file = self._get_meta_filename(cache_key)

        try:
            meta = self.vfs.read_json(meta_file)
            if meta:
                now = int(time.time())
                meta['expired'] = now >= meta.get('expiry', 0)
                meta['remaining_ttl'] = max(0, meta.get('expiry', 0) - now)
            return meta
        except Exception as e:
            logger.debug(f"Error getting cache info for {cache_key}: {e}")
            return None
