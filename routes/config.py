#!/usr/bin/env python3
"""
Configuration route handlers
"""

import json
import os

from bottle import request, response
from streaming_providers.base.utils import logger


def setup_config_routes(app, manager, service):
    """Setup configuration-related routes"""

    @app.route("/api/config/export")
    def export_config():
        """Export all configurations as JSON"""
        try:
            settings_manager = service._get_settings_manager()

            # Use SettingsManager's export method
            export_path = settings_manager.export_all_settings()

            # Read the exported file
            with open(export_path, "r", encoding="utf-8") as f:
                config_data = json.load(f)

            response.content_type = "application/json"
            response.headers["Content-Disposition"] = (
                f'attachment; filename="{os.path.basename(export_path)}"'
            )
            return json.dumps(config_data, indent=2)

        except Exception as e:
            logger.error(f"Error exporting config: {e}")
            response.status = 500
            return {"error": str(e)}

    @app.route("/api/config/import", method="POST")
    def import_config():
        """Import configurations from JSON"""
        try:
            import_data = request.json
        except ValueError:
            response.status = 400
            return {"error": "Invalid JSON format"}

        if not import_data:
            response.status = 400
            return {"error": "No data provided"}

        # Validate it's a dict
        if not isinstance(import_data, dict):
            response.status = 400
            return {"error": "Import data must be a JSON object"}

        # Create temp file
        try:
            import json
            import tempfile
            import uuid

            temp_dir = tempfile.gettempdir()
            temp_file = os.path.join(temp_dir, f"import_{uuid.uuid4()}.json")

            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(import_data, f)
        except (IOError, OSError, PermissionError) as file_err:
            logger.error(f"Failed to create temp file: {file_err}")
            response.status = 500
            return {"error": "Failed to process import file"}

        imported_count = 0
        try:
            # Use SettingsManager to import
            settings_manager = service._get_settings_manager()

            # Import credentials
            credentials = import_data.get("providers", {})

            for provider_name, provider_data in credentials.items():
                # Validate provider data
                if not isinstance(provider_data, dict):
                    logger.warning(
                        f"Skipping invalid provider data for {provider_name}"
                    )
                    continue

                # Extract credential data if available
                if "credentials" in provider_data:
                    cred_data = provider_data["credentials"]
                    if isinstance(cred_data, dict):
                        success, message = (
                            settings_manager.save_provider_credentials_from_api(
                                provider_name, cred_data
                            )
                        )
                        if success:
                            imported_count += 1
                            logger.info(f"Imported credentials for {provider_name}")
                        else:
                            logger.warning(
                                f"Failed to import credentials for {provider_name}: {message}"
                            )

                # Import proxy data if available
                if "proxy" in provider_data:
                    proxy_data = provider_data["proxy"]
                    if isinstance(proxy_data, dict):
                        success, message = (
                            settings_manager.save_provider_proxy_from_api(
                                provider_name, proxy_data
                            )
                        )
                        if success:
                            imported_count += 1
                            logger.info(f"Imported proxy for {provider_name}")
                        else:
                            logger.warning(
                                f"Failed to import proxy for {provider_name}: {message}"
                            )

        except Exception as process_err:
            logger.error(
                f"Error during import processing: {process_err}", exc_info=True
            )
            response.status = 500
            return {"error": f"Import failed: {str(process_err)}"}

        finally:
            # Always try to clean up temp file
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except (FileNotFoundError, PermissionError, OSError) as cleanup_err:
                logger.debug(f"Could not remove temp file {temp_file}: {cleanup_err}")

        return {
            "success": True,
            "imported": imported_count,
            "message": f"Imported {imported_count} configurations",
        }

    @app.route("/api/config/epg", method="GET")
    def get_epg_config():
        """Get current EPG configuration"""
        try:
            from streaming_providers.base.utils.environment import (
                get_environment_manager,
            )

            env_mgr = get_environment_manager()

            config = {
                "epg_url": env_mgr.get_config("epg_url", ""),
                "epg_cache_ttl": env_mgr.get_config("epg_cache_ttl", 86400),
                "source": (
                    "config.json" if env_mgr.get_config("epg_url") else "default"
                ),
            }

            # Also check environment variable for reference
            import os

            env_epg_url = os.environ.get("ULTIMATE_EPG_URL")
            if env_epg_url:
                config["environment_variable"] = env_epg_url

            return {
                "success": True,
                "config": config,
                "epg_manager_status": (
                    "initialized"
                    if hasattr(service, "epg_manager")
                    else "not_initialized"
                ),
            }
        except Exception as e:
            logger.error(f"API Error in /api/config/epg: {str(e)}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    @app.route("/api/config/epg", method="POST")
    def set_epg_config():
        """Set EPG configuration"""
        try:
            # Parse JSON body
            try:
                epg_data = request.json
            except Exception as json_err:
                logger.error(f"Invalid JSON in request body: {json_err}")
                response.status = 400
                return {"error": "Invalid JSON in request body"}

            if not epg_data:
                response.status = 400
                return {"error": "Request body must contain EPG configuration"}

            # Validate it's a dictionary
            if not isinstance(epg_data, dict):
                response.status = 400
                return {"error": "EPG data must be a JSON object"}

            # Validate URL format
            epg_url = epg_data.get("epg_url", "").strip()
            if epg_url:
                # Basic URL validation
                if not (
                    epg_url.startswith("http://") or epg_url.startswith("https://")
                ):
                    response.status = 400
                    return {"error": "EPG URL must start with http:// or https://"}

                # Validate it's an XML/GZ file
                if not (
                    epg_url.endswith(".xml")
                    or epg_url.endswith(".xml.gz")
                    or epg_url.endswith(".gz")
                ):
                    logger.warning(f"EPG URL doesn't end with .xml or .gz: {epg_url}")

            # Use environment manager
            from streaming_providers.base.utils.environment import (
                get_environment_manager,
            )

            env_mgr = get_environment_manager()

            # Get current config
            import json
            import os

            profile_path = env_mgr.get_config("profile_path", "")
            config_file = os.path.join(profile_path, "config.json")
            config_data = {}

            if os.path.exists(config_file):
                try:
                    with open(config_file, "r", encoding="utf-8") as f:
                        config_data = json.load(f)
                except Exception as e:
                    logger.error(f"Error reading config.json: {e}")
                    config_data = {}

            # Update with new values
            config_data["epg_url"] = epg_url

            # Optional: EPG cache TTL
            if "epg_cache_ttl" in epg_data:
                try:
                    ttl = int(epg_data["epg_cache_ttl"])
                    if ttl > 0:
                        config_data["epg_cache_ttl"] = ttl
                except ValueError:
                    pass

            # Save back to config.json
            try:
                with open(config_file, "w", encoding="utf-8") as f:
                    json.dump(config_data, f, indent=2, ensure_ascii=False)

                # Update environment manager cache
                env_mgr.set_config("epg_url", epg_url)
                if "epg_cache_ttl" in config_data:
                    env_mgr.set_config("epg_cache_ttl", config_data["epg_cache_ttl"])

                logger.info(f"Updated EPG configuration: URL={epg_url}")

                return {
                    "success": True,
                    "message": "EPG configuration updated successfully",
                    "config": {
                        "epg_url": epg_url,
                        "epg_cache_ttl": config_data.get("epg_cache_ttl", 86400),
                    },
                }

            except Exception as e:
                logger.error(f"Error writing config.json: {e}")
                response.status = 500
                return {"error": f"Failed to save configuration: {str(e)}"}

        except Exception as e:
            logger.error(f"API Error in POST /api/config/epg: {str(e)}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    @app.route("/api/config/epg/clear-cache", method="POST")
    def clear_epg_cache():
        """Clear EPG cache"""
        try:
            if hasattr(service, "epg_manager") and service.epg_manager:
                success = service.epg_manager.clear_cache()
                if success:
                    return {"success": True, "message": "EPG cache cleared"}
                else:
                    response.status = 500
                    return {"error": "Failed to clear EPG cache"}
            else:
                response.status = 404
                return {"error": "EPG manager not initialized"}
        except Exception as e:
            logger.error(f"API Error clearing EPG cache: {str(e)}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}

    @app.route("/api/config/epg/cache-info", method="GET")
    def get_epg_cache_info():
        """Get EPG cache information"""
        try:
            if hasattr(service, "epg_manager") and service.epg_manager:
                cache_info = service.epg_manager.get_cache_info()
                mapping_stats = service.epg_manager.get_mapping_stats()

                return {
                    "success": True,
                    "cache_info": cache_info,
                    "mapping_stats": mapping_stats,
                }
            else:
                response.status = 404
                return {"error": "EPG manager not initialized"}
        except Exception as e:
            logger.error(f"API Error getting EPG cache info: {str(e)}")
            response.status = 500
            return {"error": f"Internal server error: {str(e)}"}
