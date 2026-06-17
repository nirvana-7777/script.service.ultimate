#!/usr/bin/env python3
"""
EPG (Electronic Program Guide) routes.

These routes provide program schedule information for channels.

Endpoints:
  GET /api/epg/status                                         – Cache/config health check
  GET /api/epg/xmltv-channels                                 – All channel IDs + display names from XMLTV source
  GET /api/providers/<provider>/epg                           – Bulk XMLTV export (download)
  GET /api/providers/<provider>/epg/grid                      – Multi-channel grid view (JSON)
  GET /api/providers/<provider>/channels/<channel_id>/epg     – Single-channel program list
  GET /api/providers/<provider>/programs/<program_id>         – Deep program detail
  GET /api/providers/<provider>/epg-mapping                   – Load channel→EPG ID mapping
  POST /api/providers/<provider>/epg-mapping                  – Persist channel→EPG ID mapping
"""

import gzip
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from bottle import request, response
from streaming_providers.base.epg_operations import EPGOperations
from streaming_providers.base.utils import logger


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_time_param(value: str | None) -> datetime | None:
    """
    Parse a query-string time value into a timezone-aware datetime.

    Accepts:
      - Unix timestamp (integer string): "1710000000"
      - ISO 8601 string:                "2024-03-10T00:00:00Z"

    Returns None and logs a warning if the value cannot be parsed.
    """
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (ValueError, TypeError):
        pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        logger.warning(f"Invalid time format, ignoring: {value!r}")
        return None


def _open_xml(file_path: str):
    """Open a plain or gzip-compressed XMLTV file for text reading."""
    if file_path.endswith(".gz"):
        return gzip.open(file_path, "rt", encoding="utf-8")
    return open(file_path, "r", encoding="utf-8")


# ---------------------------------------------------------------------------
# Route setup
# ---------------------------------------------------------------------------

def setup_epg_routes(app, manager, service):
    """Register all EPG-related routes on *app*."""

    # EPGOperations is instantiated once here so that EPGManager, EPGCache,
    # EPGMapping and their VFS helpers are constructed only a single time,
    # not on every incoming HTTP request.
    epg_ops = EPGOperations(manager.registry)

    # ------------------------------------------------------------------
    # 1. EPG system status
    # ------------------------------------------------------------------

    @app.route("/api/epg/status", method="GET")
    def get_epg_status():
        """Return EPG configuration and cache status."""
        try:
            configured = bool(service.epg_url) and service.epg_url != "https://example.com/epg.xml.gz"
            result = {
                "configured": configured,
                "epg_url": service.epg_url or "Not configured",
                "cache_valid": False,
                "cache_path": None,
                "channel_count": 0,
                "environment_used": False,
            }

            env_url = os.environ.get("ULTIMATE_EPG_URL")
            if env_url and env_url == service.epg_url:
                result["environment_used"] = True

            if configured and hasattr(service, "epg_manager") and service.epg_manager:
                try:
                    xml_path = service.epg_manager.cache.get_cached_file_path()
                    if xml_path:
                        result["cache_valid"] = True
                        result["cache_path"] = xml_path
                        channel_ids: set[str] = set()
                        try:
                            with _open_xml(xml_path) as f:
                                for event, elem in ET.iterparse(f, events=("start",)):
                                    if elem.tag == "channel":
                                        cid = elem.get("id")
                                        if cid:
                                            channel_ids.add(cid)
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

    # ------------------------------------------------------------------
    # 2. XMLTV channel list
    # ------------------------------------------------------------------

    @app.route("/api/epg/xmltv-channels", method="GET")
    def get_epg_xmltv_channels():
        """Return all channel IDs and display names from the XMLTV source file."""
        try:
            if not hasattr(service, "epg_manager") or not service.epg_manager:
                response.status = 404
                return {"error": "EPG module not available"}

            if not service.epg_url or service.epg_url == "https://example.com/epg.xml.gz":
                response.status = 400
                return {
                    "error": "EPG URL not configured",
                    "hint": "Please configure a valid EPG URL in Advanced settings",
                    "current_url": service.epg_url,
                }

            cache = service.epg_manager.cache
            logger.info(f"EPG xmltv-channels: using URL {service.epg_url}")
            xml_path = cache.get_or_download(service.epg_url)

            if not xml_path or not os.path.exists(xml_path):
                response.status = 404
                return {
                    "error": f"EPG file not available from {service.epg_url}",
                    "hint": "Check if the URL is accessible and contains valid XMLTV data.",
                }

            file_size = os.path.getsize(xml_path)
            logger.info(f"Parsing EPG file: {xml_path} ({file_size} bytes)")

            channel_ids: list[str] = []
            channel_map: dict[str, str] = {}
            current_id: str | None = None
            current_names: list[str] = []

            with _open_xml(xml_path) as f:
                for event, elem in ET.iterparse(f, events=("start", "end")):
                    if event == "start" and elem.tag == "channel":
                        current_id = elem.get("id")
                        current_names = []
                    elif event == "end" and elem.tag == "display-name":
                        if current_id and elem.text:
                            current_names.append(elem.text.strip())
                    elif event == "end" and elem.tag == "channel":
                        if current_id:
                            channel_ids.append(current_id)
                            channel_map[current_id] = current_names[0] if current_names else current_id
                            current_id = None
                    if event == "end":
                        elem.clear()

            sorted_channels = sorted(channel_ids)
            logger.info(f"Found {len(sorted_channels)} channels in EPG")

            return {
                "channels": sorted_channels,
                "channel_map": channel_map,
                "count": len(sorted_channels),
                "source_url": service.epg_url,
                "cache_path": xml_path,
                "cache_size_bytes": file_size,
            }

        except ET.ParseError as e:
            logger.error(f"XML parse error in EPG file: {e}")
            response.status = 500
            return {
                "error": f"Failed to parse EPG XML file: {e}",
                "hint": "The EPG file may be malformed or not valid XMLTV format.",
            }
        except Exception as e:
            logger.error(f"Error getting EPG channels: {e}", exc_info=True)
            response.status = 500
            return {"error": f"Failed to process EPG file: {e}"}

    # ------------------------------------------------------------------
    # 3. Bulk XMLTV export  (provider-scoped)
    # ------------------------------------------------------------------

    @app.route("/api/providers/<provider>/epg", method="GET")
    def get_provider_epg_xmltv(provider):
        """Download the full XMLTV feed for a provider."""
        try:
            response.content_type = "application/xml; charset=utf-8"
            response.headers["Content-Disposition"] = (
                f'attachment; filename="{provider}_epg.xml"'
            )

            xmltv_data = manager.get_provider_epg_xmltv(
                provider_name=provider,
                country=request.query.get("country"),
            )

            if not xmltv_data:
                response.status = 404
                return {"error": f'EPG data not available for provider "{provider}"'}

            return xmltv_data

        except ValueError as e:
            logger.error(f"XMLTV EPG error for {provider}: {e}")
            response.status = 404
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"XMLTV EPG error for {provider}: {e}")
            response.status = 500
            return {"error": f"Internal server error: {e}"}

    # ------------------------------------------------------------------
    # 4. Multi-channel grid view  (NEW)
    # ------------------------------------------------------------------

    @app.route("/api/providers/<provider>/epg/grid", method="GET")
    def get_provider_epg_grid(provider):
        """
        Return a time-windowed grid of programs across multiple channels.

        Query params:
          start_time  – window start (Unix timestamp or ISO 8601); defaults to now
          end_time    – window end   (Unix timestamp or ISO 8601); defaults to now+3h
          channels    – comma-separated channel IDs to include (omit = all)
          country     – optional country filter forwarded to the provider
        """
        try:
            start_time = _parse_time_param(request.query.get("start_time"))
            end_time   = _parse_time_param(request.query.get("end_time"))
            country    = request.query.get("country")

            raw_channels = request.query.get("channels")
            channel_ids  = [c.strip() for c in raw_channels.split(",") if c.strip()] if raw_channels else None

            grid_data = epg_ops.get_provider_epg_grid(
                provider_name=provider,
                start_time=start_time,
                end_time=end_time,
                channel_ids=channel_ids,
                country=country,
            )

            # Serialize EPGEntry objects to dicts here, at the response
            # boundary — epg_ops returns EPGEntry objects (not JSON-safe).
            grid_data = {
                cid: [entry.to_dict() for entry in entries]
                for cid, entries in grid_data.items()
            }

            response.content_type = "application/json; charset=utf-8"
            return {
                "provider": provider,
                "start_time": request.query.get("start_time"),
                "end_time": request.query.get("end_time"),
                "channels_count": len(grid_data),
                "grid": grid_data,
            }

        except ValueError as e:
            logger.error(f"Grid EPG error for {provider}: {e}")
            response.status = 404
            response.content_type = "application/json; charset=utf-8"
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Grid EPG error for {provider}: {e}")
            response.status = 500
            response.content_type = "application/json; charset=utf-8"
            return {"error": f"Internal server error: {e}"}

    # ------------------------------------------------------------------
    # 5. Single-channel program list
    # ------------------------------------------------------------------

    @app.route("/api/providers/<provider>/channels/<channel_id>/epg", method="GET")
    def get_channel_epg(provider, channel_id):
        """
        Return programs for a single channel within a time window.

        Query params:
          start_time / start  – window start (Unix timestamp or ISO 8601)
          end_time   / end    – window end   (Unix timestamp or ISO 8601)
          limit               – max number of programs to return (default 100)
          country             – optional country filter
        """
        try:
            # Accept both old (start_time/end_time) and new (start/end) param names.
            start_time = _parse_time_param(
                request.query.get("start_time") or request.query.get("start")
            )
            end_time = _parse_time_param(
                request.query.get("end_time") or request.query.get("end")
            )
            limit   = request.query.get("limit", default=100, type=int)
            country = request.query.get("country")

            programs = epg_ops.get_channel_epg(
                provider_name=provider,
                channel_id=channel_id,
                start_time=start_time,
                end_time=end_time,
                limit=limit,
                country=country,
            )

            # Serialize EPGEntry objects to dicts here, at the response
            # boundary — epg_ops returns EPGEntry objects (not JSON-safe).
            programs = [entry.to_dict() for entry in programs]

            response.content_type = "application/json; charset=utf-8"
            return {
                "provider": provider,
                "channel_id": channel_id,
                "start_time": request.query.get("start_time") or request.query.get("start"),
                "end_time":   request.query.get("end_time")   or request.query.get("end"),
                "count": len(programs),
                "programs": programs,
            }

        except ValueError as e:
            logger.error(f"EPG error for {provider}/{channel_id}: {e}")
            response.status = 404
            response.content_type = "application/json; charset=utf-8"
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"EPG error for {provider}/{channel_id}: {e}")
            response.status = 500
            response.content_type = "application/json; charset=utf-8"
            return {"error": f"Internal server error: {e}"}

    # ------------------------------------------------------------------
    # 6. Deep program detail  (NEW)
    # ------------------------------------------------------------------

    @app.route("/api/providers/<provider>/programs/<program_id>", method="GET")
    def get_program_details(provider, program_id):
        """
        Return full metadata for a single program.

        Useful for detail views, catchup deep-links, and series grouping.
        """
        try:
            program_data = epg_ops.get_program_details(
                provider_name=provider,
                program_id=program_id,
            )

            if not program_data:
                response.status = 404
                response.content_type = "application/json; charset=utf-8"
                return {"error": f"Program '{program_id}' not found for provider '{provider}'"}

            # Serialize EPGEntry objects to dicts here, at the response
            # boundary — epg_ops returns EPGEntry objects (not JSON-safe)
            # on the native path. The generic fallback path can return a
            # plain dict, so only convert if it's actually an EPGEntry.
            if hasattr(program_data, "to_dict"):
                program_data = program_data.to_dict()

            response.content_type = "application/json; charset=utf-8"
            return {
                "provider": provider,
                "program_id": program_id,
                "details": program_data,
            }

        except ValueError as e:
            logger.error(f"Program detail error for {provider}/{program_id}: {e}")
            response.status = 404
            response.content_type = "application/json; charset=utf-8"
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"Program detail error for {provider}/{program_id}: {e}")
            response.status = 500
            response.content_type = "application/json; charset=utf-8"
            return {"error": f"Internal server error: {e}"}

    # ------------------------------------------------------------------
    # 7. EPG channel mapping  (GET + POST)
    # ------------------------------------------------------------------

    @app.route("/api/providers/<provider>/epg-mapping", method="GET")
    def get_epg_mapping(provider):
        """Return the persisted channel→EPG ID mapping for a provider."""
        try:
            from streaming_providers.base.utils.vfs import VFS
        except ImportError:
            return {"provider": provider, "mapping": {}, "exists": False}

        try:
            vfs = VFS(addon_subdir="")
            mapping_file = f"{provider}_epg_mapping.json"

            if not vfs.exists(mapping_file):
                logger.info(f"No EPG mapping file found for {provider}")
                return {"provider": provider, "mapping": {}, "exists": False}

            mapping_data = vfs.read_json(mapping_file) or {}

            _internal = {"_provider_name", "_created_at", "_updated_at", "_version"}
            actual_mapping = {k: v for k, v in mapping_data.items() if k not in _internal}

            logger.info(f"Loaded EPG mapping for {provider}: {len(actual_mapping)} channels")
            logger.debug(f"Sample mappings: {list(actual_mapping.items())[:3]}")

            return {"provider": provider, "mapping": actual_mapping, "exists": True}

        except Exception as e:
            logger.error(f"Error getting EPG mapping for {provider}: {e}", exc_info=True)
            response.status = 500
            return {"error": f"Failed to load mapping: {e}"}

    @app.route("/api/providers/<provider>/epg-mapping", method="POST")
    def save_epg_mapping(provider):
        """Persist a channel→EPG ID mapping for a provider."""
        try:
            from streaming_providers.base.utils.vfs import VFS
        except ImportError:
            response.status = 500
            return {"error": "VFS module not available"}

        try:
            try:
                mapping_data = request.json.get("mapping", {}) if request.json else {}
            except Exception as json_err:
                logger.error(f"Invalid JSON in request body: {json_err}")
                response.status = 400
                return {"error": "Invalid JSON in request body"}

            # Resolve provider display label if possible.
            provider_label = provider
            try:
                inst = manager.get_provider(provider)
                if inst:
                    provider_label = getattr(inst, "provider_label", provider)
            except Exception:
                pass

            full_mapping: dict = {"_provider_name": provider_label}
            for channel_id, value in mapping_data.items():
                if isinstance(value, dict):
                    full_mapping[channel_id] = value
                elif isinstance(value, str):
                    full_mapping[channel_id] = {"epg_id": value, "name": ""}

            vfs = VFS(addon_subdir="")
            mapping_file = f"{provider}_epg_mapping.json"
            success = vfs.write_json(mapping_file, full_mapping)

            if not success:
                response.status = 500
                return {"error": "Failed to save mapping file"}

            logger.info(f"Saved EPG mapping for {provider}: {len(mapping_data)} channels")

            # Best-effort cache invalidation.
            try:
                from streaming_providers.base.epg.epg_mapping import EPGMapping
                EPGMapping().reload_mapping(provider)
                logger.info(f"Reloaded EPG mapping cache for {provider}")
            except ImportError:
                logger.debug("EPGMapping not available for cache reload")
            except Exception as reload_err:
                logger.warning(f"Could not reload mapping cache: {reload_err}")

            return {
                "success": True,
                "message": f"Mapping saved for {provider}",
                "channels_mapped": len(mapping_data),
            }

        except Exception as e:
            logger.error(f"Error saving EPG mapping for {provider}: {e}", exc_info=True)
            response.status = 500
            return {"error": f"Failed to save mapping: {e}"}