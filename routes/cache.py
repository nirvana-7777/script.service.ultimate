#!/usr/bin/env python3
"""
Cache management route handlers
"""

from bottle import response
from streaming_providers.base.utils import logger


def setup_cache_routes(app, manager, service):
    """Setup cache management routes"""

    @app.route("/api/cache/pssh", method="DELETE")
    def clear_pssh_cache():
        """
        Clear all PSSH cache entries.

        This is useful for:
        - Debugging
        - Freeing memory
        - Forcing re-extraction of all channels
        """
        try:
            cache_size = len(manager.drm_ops.pssh_cache.cache)
            manager.drm_ops.pssh_cache.clear()

            response.status = 200
            return {"message": "PSSH cache cleared", "entries_cleared": cache_size}

        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            response.status = 500
            return {"error": "Failed to clear cache", "message": str(e)}

    @app.route("/api/cache/pssh", method="GET")
    def get_pssh_cache_stats():
        """
        Get PSSH cache statistics.

        Returns information about:
        - Number of cached entries
        - TTL configuration
        - Memory usage estimate
        """
        try:
            cache = manager.drm_ops.pssh_cache

            with cache.lock:
                entries = []
                total_size = 0

                for key, (pssh_list, timestamp) in cache.cache.items():
                    import time

                    age = time.time() - timestamp
                    expires_in = cache.ttl - age

                    # Estimate size
                    size = sum(
                        len(p.pssh_box) + len(str(p.key_ids)) + len(p.system_id)
                        for p in pssh_list
                    )
                    total_size += size

                    entries.append(
                        {
                            "key": key,
                            "pssh_count": len(pssh_list),
                            "age_seconds": int(age),
                            "expires_in_seconds": int(expires_in),
                            "size_bytes": size,
                        }
                    )

            response.status = 200
            return {
                "total_entries": len(entries),
                "ttl_seconds": cache.ttl,
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / 1024 / 1024, 2),
                "entries": sorted(
                    entries, key=lambda x: x["age_seconds"], reverse=True
                ),
            }

        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            response.status = 500
            return {"error": "Failed to get cache stats", "message": str(e)}

    @app.route("/api/cache/mpd/clear")
    def clear_mpd_cache():
        """Clear all cached MPD manifests"""
        try:
            service.mpd_cache.clear_all()
            return {"success": True, "message": "MPD cache cleared"}
        except Exception as e:
            logger.error(f"Error clearing MPD cache: {e}")
            response.status = 500
            return {"error": str(e)}

    @app.route("/api/cache/mpd/clear-expired")
    def clear_expired_mpd_cache():
        """Clear expired MPD cache entries"""
        try:
            cleared = service.mpd_cache.clear_expired()
            return {"success": True, "cleared": cleared}
        except Exception as e:
            logger.error(f"Error clearing expired MPD cache: {e}")
            response.status = 500
            return {"error": str(e)}

    @app.route("/api/cache/mpd/<provider>/<channel_id>")
    def get_mpd_cache_info(provider, channel_id):
        """Get cache information for a specific channel"""
        try:
            info = service.mpd_cache.get_cache_info(provider, channel_id)
            if info:
                return {"success": True, "cache_info": info}
            else:
                response.status = 404
                return {"success": False, "message": "No cache found"}
        except Exception as e:
            logger.error(f"Error getting cache info: {e}")
            response.status = 500
            return {"error": str(e)}

    @app.route("/api/cache/mpd/<provider>/<channel_id>/delete")
    def delete_mpd_cache(provider, channel_id):
        """Delete cached MPD for a specific channel"""
        try:
            service.mpd_cache.delete(provider, channel_id)
            return {
                "success": True,
                "message": f"Cache deleted for {provider}/{channel_id}",
            }
        except Exception as e:
            logger.error(f"Error deleting cache: {e}")
            response.status = 500
            return {"error": str(e)}
