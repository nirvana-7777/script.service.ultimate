#!/usr/bin/env python3
"""
EPG-related route handlers
"""

from bottle import request, response
from streaming_providers.base.utils import logger


def setup_epg_routes(app, manager, service):
    """Setup EPG-related routes"""

    @app.route("/api/epg/status", method="GET")
    def get_epg_status():
        """Get EPG configuration and cache status"""
        try:
            result = {
                "configured": bool(service.epg_url)
                and service.epg_url != "https://example.com/epg.xml.gz",
                "epg_url": service.epg_url if service.epg_url else "Not configured",
                "cache_valid": False,
                "cache_path": None,
                "channel_count": 0,
                "environment_used": False,
            }

            # Check if we used the environment variable
            import os

            env_url = os.environ.get("ULTIMATE_EPG_URL")
            if env_url and env_url == service.epg_url:
                result["environment_used"] = True

            if (
                result["configured"]
                and hasattr(service, "epg_manager")
                and service.epg_manager
            ):
                try:
                    cache = service.epg_manager.cache
                    xml_path = cache.get_cached_file_path()

                    if xml_path:
                        result["cache_valid"] = True
                        result["cache_path"] = xml_path

                        # Try to count channels
                        import gzip
                        import xml.etree.ElementTree as ET

                        def open_xml_file(file_path):
                            if file_path.endswith(".gz"):
                                return gzip.open(file_path, "rt", encoding="utf-8")
                            else:
                                return open(file_path, "r", encoding="utf-8")

                        channel_ids = set()
                        try:
                            with open_xml_file(xml_path) as xml_file:
                                context = ET.iterparse(xml_file, events=("start",))
                                for event, elem in context:
                                    if elem.tag == "channel":
                                        channel_id = elem.get("id")
                                        if channel_id:
                                            channel_ids.add(channel_id)
                                    elem.clear()
                            result["channel_count"] = len(channel_ids)
                        except Exception as parse_err:
                            result["parse_error"] = str(parse_err)
                except Exception as cache_err:
                    result["cache_error"] = str(cache_err)
            else:
                result["hint"] = "Please configure EPG URL in Advanced settings"

            return result

        except Exception as e:
            logger.error(f"Error getting EPG status: {e}")
            response.status = 500
            return {"error": str(e)}

    @app.route("/api/epg/xmltv-channels", method="GET")
    def get_epg_xmltv_channels():
        """Get all unique channel IDs from EPG XML file with display names"""
        try:
            # Check if EPG manager is available
            if not hasattr(service, "epg_manager") or not service.epg_manager:
                response.status = 404
                return {"error": "EPG module not available"}

            # Check if we have a valid EPG URL configured
            if (
                not service.epg_url
                or service.epg_url == "https://example.com/epg.xml.gz"
            ):
                response.status = 400
                return {
                    "error": "EPG URL not configured",
                    "hint": "Please configure a valid EPG URL in Advanced settings",
                    "current_url": service.epg_url,
                }

            # Get the cache manager from EPG manager
            cache = service.epg_manager.cache

            logger.info(f"EPG Channels: Using URL: {service.epg_url}")

            # This will download if not cached, or return cached path
            xml_path = cache.get_or_download(service.epg_url)

            if not xml_path:
                response.status = 404
                return {
                    "error": f"EPG file not available from {service.epg_url}",
                    "details": "Failed to download or cache EPG file.",
                    "hint": "Check if the URL is accessible and contains valid XMLTV data.",
                }

            # Parse XML to get channel IDs and display names
            import gzip
            import os
            import xml.etree.ElementTree as ET

            if not os.path.exists(xml_path):
                response.status = 404
                return {"error": f"EPG file does not exist at path: {xml_path}"}

            channel_ids = []
            channel_map = {}  # Map of id -> display name

            def open_xml_file(file_path):
                if file_path.endswith(".gz"):
                    return gzip.open(file_path, "rt", encoding="utf-8")
                else:
                    return open(file_path, "r", encoding="utf-8")

            logger.info(f"Parsing EPG file: {xml_path}")
            file_size = os.path.getsize(xml_path)
            logger.info(f"EPG file size: {file_size} bytes")

            with open_xml_file(xml_path) as xml_file:
                # Use iterparse for memory efficiency
                context = ET.iterparse(xml_file, events=("start", "end"))

                current_channel_id = None
                current_display_names = []

                for event, elem in context:
                    if event == "start" and elem.tag == "channel":
                        current_channel_id = elem.get("id")
                        current_display_names = []

                    elif event == "end" and elem.tag == "display-name":
                        if current_channel_id and elem.text:
                            current_display_names.append(elem.text.strip())

                    elif event == "end" and elem.tag == "channel":
                        if current_channel_id:
                            channel_ids.append(current_channel_id)
                            # Use the first display name as the primary name
                            if current_display_names:
                                channel_map[current_channel_id] = current_display_names[
                                    0
                                ]
                            else:
                                channel_map[current_channel_id] = current_channel_id
                            current_channel_id = None

                    # Clear element to save memory
                    if event == "end":
                        elem.clear()

            logger.info(f"Found {len(channel_ids)} channels in EPG")

            # Sort channels for consistent output
            sorted_channels = sorted(channel_ids)

            return {
                "channels": sorted_channels,
                "channel_map": channel_map,  # NEW: Map of id -> display name
                "count": len(sorted_channels),
                "source_url": service.epg_url,
                "cache_path": xml_path,
                "cache_size_bytes": file_size,
            }

        except ET.ParseError as parse_err:
            logger.error(f"XML parse error in EPG file: {parse_err}")
            response.status = 500
            return {
                "error": f"Failed to parse EPG XML file: {str(parse_err)}",
                "hint": "The EPG file may be malformed or not valid XMLTV format.",
            }
        except Exception as e:
            logger.error(f"Error getting EPG channels: {e}", exc_info=True)
            response.status = 500
            return {"error": f"Failed to process EPG file: {str(e)}"}

    @app.route("/api/providers/<provider>/epg-mapping", method="GET")
    def get_epg_mapping(provider):
        """Get current EPG mapping for a provider"""
        try:
            from streaming_providers.base.utils.vfs import VFS
        except ImportError:
            # If VFS is not available, return empty mapping
            return {"provider": provider, "mapping": {}, "exists": False}

        try:
            mapping_file = f"{provider}_epg_mapping.json"
            vfs = VFS(addon_subdir="")

            if vfs.exists(mapping_file):
                mapping_data = vfs.read_json(mapping_file)
                if mapping_data:
                    # The file structure is:
                    # {
                    #   "_provider_name": "...",
                    #   "channel_id": {"epg_id": "...", "name": "..."}
                    # }

                    # Extract mapping (skip internal fields starting with _)
                    internal_fields = [
                        "_provider_name",
                        "_created_at",
                        "_updated_at",
                        "_version",
                    ]
                    actual_mapping = {
                        k: v
                        for k, v in mapping_data.items()
                        if k not in internal_fields
                    }

                    logger.info(
                        f"Loaded EPG mapping for {provider}: {len(actual_mapping)} channels"
                    )
                    logger.debug(f"Sample mappings: {list(actual_mapping.items())[:3]}")

                    return {
                        "provider": provider,
                        "mapping": actual_mapping,
                        "exists": True,
                    }

            # Return empty mapping if file doesn't exist
            logger.info(f"No EPG mapping file found for {provider}")
            return {"provider": provider, "mapping": {}, "exists": False}

        except Exception as e:
            logger.error(
                f"Error getting EPG mapping for {provider}: {e}", exc_info=True
            )
            response.status = 500
            return {"error": f"Failed to load mapping: {str(e)}"}

    @app.route("/api/providers/<provider>/epg-mapping", method="POST")
    def save_epg_mapping(provider):
        """Save EPG mapping for a provider"""
        try:
            from streaming_providers.base.utils.vfs import VFS
        except ImportError:
            response.status = 500
            return {"error": "VFS module not available"}

        try:
            # Get JSON data from request body using Bottle's request object
            try:
                mapping_data = request.json.get("mapping", {}) if request.json else {}
            except Exception as json_err:
                logger.error(f"Invalid JSON in request body: {json_err}")
                response.status = 400
                return {"error": "Invalid JSON in request body"}

            # Get provider label if available
            provider_label = provider
            try:
                provider_instance = manager.get_provider(provider)
                if provider_instance:
                    provider_label = getattr(
                        provider_instance, "provider_label", provider
                    )
            except:
                pass

            # Build the file structure:
            # {
            #   "_provider_name": "Provider Label",
            #   "channel_id": {"epg_id": "...", "name": "..."}
            # }
            full_mapping = {"_provider_name": provider_label}

            # Add each mapping entry
            for channel_id, mapping_value in mapping_data.items():
                if isinstance(mapping_value, dict):
                    # Already has structure {"epg_id": "...", "name": "..."}
                    full_mapping[channel_id] = mapping_value
                elif isinstance(mapping_value, str):
                    # Simple string, convert to object
                    full_mapping[channel_id] = {
                        "epg_id": mapping_value,
                        "name": "",  # Name not provided
                    }

            # Save to file
            vfs = VFS(addon_subdir="")
            mapping_file = f"{provider}_epg_mapping.json"

            success = vfs.write_json(mapping_file, full_mapping)

            if success:
                logger.info(
                    f"Saved EPG mapping for {provider}: {len(mapping_data)} channels"
                )

                # Clear mapping cache if it exists
                try:
                    from streaming_providers.base.epg.epg_mapping import EPGMapping

                    mapping_manager = EPGMapping()
                    mapping_manager.reload_mapping(provider)
                    logger.info(f"Reloaded EPG mapping cache for {provider}")
                except ImportError:
                    logger.debug("EPGMapping not available for cache reload")
                    pass
                except Exception as reload_err:
                    logger.warning(f"Could not reload mapping cache: {reload_err}")

                return {
                    "success": True,
                    "message": f"Mapping saved for {provider}",
                    "channels_mapped": len(mapping_data),
                }
            else:
                response.status = 500
                return {"error": "Failed to save mapping file"}

        except Exception as e:
            logger.error(f"Error saving EPG mapping for {provider}: {e}", exc_info=True)
            response.status = 500
            return {"error": f"Failed to save mapping: {str(e)}"}
