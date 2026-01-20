#!/usr/bin/env python3
"""
DRM and PSSH route handlers
"""

import traceback

from bottle import request, response
from streaming_providers.base.utils import logger


def setup_drm_routes(app, manager, service):
    """Setup DRM and PSSH-related routes"""

    @app.route("/api/providers/<provider>/channels/<channel_id>/pssh")
    def get_channel_pssh(provider, channel_id):
        """
        Extract PSSH data for a channel.

        Query parameters:
        - country: Optional country code for geo-specific manifests
        - force_refresh: If 'true', bypass cache and re-extract PSSH

        Returns:
        {
            "provider": "provider_name",
            "channel_id": "channel_id",
            "manifest_url": "https://...",
            "pssh_data": [
                {
                    "system_id": "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed",
                    "drm_system": "com.widevine.alpha",
                    "pssh_box": "AAAANHBzc2g...",
                    "key_ids": ["64656d6f..."],
                    "source": "mp4_segment"
                }
            ],
            "count": 1,
            "cached": true
        }
        """
        try:
            # Parse query parameters
            country = request.params.get("country")
            force_refresh = request.params.get("force_refresh", "").lower() == "true"

            # Check cache status BEFORE clearing (to know if it was cached)
            cache_key = f"{provider}:{channel_id}"
            was_cached_before = manager.drm_ops.pssh_cache.get(cache_key) is not None

            # Clear cache if force refresh requested
            if force_refresh:
                with manager.drm_ops.pssh_cache.lock:
                    if cache_key in manager.drm_ops.pssh_cache.cache:
                        del manager.drm_ops.pssh_cache.cache[cache_key]
                logger.info(f"Cache cleared for force_refresh request: {cache_key}")
                was_cached_before = False  # Since we just cleared it

            # Get DRM configs - this will check cache and extract if needed
            try:
                # This method handles caching internally
                drm_configs = manager.drm_ops.get_channel_drm_configs(
                    provider_name=provider, channel_id=channel_id, country=country
                )
            except ValueError as e:
                response.status = 404
                return {
                    "error": "Provider not found",
                    "message": str(e),
                    "provider": provider,
                }
            except Exception as e:
                response.status = 500
                return {
                    "error": "Failed to get DRM configs",
                    "message": str(e),
                    "provider": provider,
                    "channel_id": channel_id,
                }

            # Get manifest URL for reference
            try:
                manifest_url = manager.get_channel_manifest(
                    provider_name=provider, channel_id=channel_id, country=country
                )
            except Exception as e:
                manifest_url = None
                logger.debug(f"Could not get manifest URL: {e}")

            # Now get the PSSH data from cache (after get_channel_drm_configs has populated it)
            pssh_data_list = manager.drm_ops.pssh_cache.get(cache_key)
            was_cached_after = pssh_data_list is not None

            if not pssh_data_list:
                # If no PSSH data in cache, try to extract from manifest
                if manifest_url:
                    try:
                        pssh_data_list = manager.drm_ops._extract_pssh_from_manifest(
                            manifest_url
                        )
                        # Cache the result
                        if pssh_data_list:
                            manager.drm_ops.pssh_cache.set(cache_key, pssh_data_list)
                    except Exception as extract_err:
                        logger.warning(
                            f"Failed to extract PSSH from manifest: {extract_err}"
                        )
                        pssh_data_list = []
                else:
                    pssh_data_list = []

            # Convert PSSH data to dictionary format
            pssh_list = []
            for pssh_data in pssh_data_list:
                pssh_dict = {
                    "system_id": pssh_data.system_id,
                    "drm_system": (
                        pssh_data.drm_system.value if pssh_data.drm_system else None
                    ),
                    "pssh_box": pssh_data.pssh_box if pssh_data.pssh_box else None,
                    "key_ids": pssh_data.key_ids if pssh_data.key_ids else [],
                    "source": pssh_data.source,
                }

                # Add human-readable system name
                if pssh_data.drm_system:
                    pssh_dict["drm_system_name"] = {
                        "com.widevine.alpha": "Widevine",
                        "com.microsoft.playready": "PlayReady",
                        "com.apple.fps": "FairPlay",
                        "org.w3.clearkey": "ClearKey",
                        "com.huawei.wiseplay": "Wiseplay",
                    }.get(pssh_data.drm_system.value, pssh_data.drm_system.value)

                # Remove None values for cleaner response
                pssh_dict = {k: v for k, v in pssh_dict.items() if v is not None}
                pssh_list.append(pssh_dict)

            response.status = 200
            return {
                "provider": provider,
                "channel_id": channel_id,
                "manifest_url": manifest_url,
                "pssh_data": pssh_list,
                "count": len(pssh_list),
                "cached": was_cached_after,  # Whether data came from cache AFTER the operation
                "was_cached_before": was_cached_before,  # Whether data was in cache BEFORE the operation
                "cache_ttl_seconds": manager.drm_ops.pssh_cache.ttl,
            }

        except Exception as e:
            # Catch-all for unexpected errors
            logger.error(f"Unexpected error in get_channel_pssh: {e}")
            logger.error(traceback.format_exc())
            response.status = 500
            return {
                "error": "Internal server error",
                "message": str(e),
                "provider": provider,
                "channel_id": channel_id,
                "traceback": (
                    traceback.format_exc() if app.config.get("debug") else None
                ),
            }

    @app.route(
        "/api/providers/<provider>/channels/<channel_id>/pssh/refresh",
        method="POST",
    )
    def refresh_channel_pssh(provider, channel_id):
        """
        Force refresh PSSH data for a channel (clears cache and re-extracts).

        This is useful when:
        - Keys have been rotated
        - Manifest structure has changed
        - Previous extraction failed
        """
        try:
            # Parse query parameters
            country = request.params.get("country")

            # Generate cache key
            cache_key = f"{provider}:{channel_id}"

            # Check if entry exists in cache before clearing
            was_cached = manager.drm_ops.pssh_cache.get(cache_key) is not None

            # Clear the specific cache entry
            with manager.drm_ops.pssh_cache.lock:
                if cache_key in manager.drm_ops.pssh_cache.cache:
                    del manager.drm_ops.pssh_cache.cache[cache_key]

            if was_cached:
                logger.info(f"Cleared cache for {cache_key}")
            else:
                logger.info(f"No cache entry found for {cache_key}")

            # Now extract fresh data by calling get_channel_drm_configs
            # This will force a fresh extraction since cache was cleared
            try:
                drm_configs = manager.drm_ops.get_channel_drm_configs(
                    provider_name=provider, channel_id=channel_id, country=country
                )
            except ValueError as e:
                response.status = 404
                return {
                    "error": "Provider not found",
                    "message": str(e),
                    "provider": provider,
                }
            except Exception as e:
                response.status = 500
                return {
                    "error": "Failed to refresh DRM configs",
                    "message": str(e),
                    "provider": provider,
                    "channel_id": channel_id,
                }

            # Get the newly cached PSSH data
            pssh_data_list = manager.drm_ops.pssh_cache.get(cache_key)
            now_cached = pssh_data_list is not None

            # Get manifest URL for reference
            try:
                manifest_url = manager.get_channel_manifest(
                    provider_name=provider, channel_id=channel_id, country=country
                )
            except Exception as e:
                manifest_url = None

            response.status = 200
            return {
                "message": "PSSH data refreshed successfully",
                "provider": provider,
                "channel_id": channel_id,
                "manifest_url": manifest_url,
                "pssh_count": len(pssh_data_list) if pssh_data_list else 0,
                "was_cached": was_cached,
                "now_cached": now_cached,
                "extraction_successful": (
                    len(pssh_data_list) > 0 if pssh_data_list else False
                ),
            }

        except Exception as e:
            logger.error(f"Error refreshing PSSH: {e}")
            response.status = 500
            return {"error": "Failed to refresh PSSH data", "message": str(e)}
