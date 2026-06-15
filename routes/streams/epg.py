#!/usr/bin/env python3
"""
EPG (Electronic Program Guide) routes.

These routes provide program schedule information for channels.
"""

from datetime import datetime, timezone
from bottle import request, response
from streaming_providers.base.utils import logger


def setup_epg_routes(app, manager, service):
    """Setup all EPG-related routes."""

    # Note: EPG routes don't need the full helpers factory since they don't
    # use the stream resolution helpers. They only need manager.

    @app.route("/api/providers/<provider>/channels/<channel_id>/epg")
    def get_channel_epg(provider, channel_id):
        try:
            kwargs = {"country": request.query.get("country")}

            if request.query.get("start_time"):
                start_time_str = request.query.get("start_time")
                try:
                    kwargs["start_time"] = datetime.fromtimestamp(
                        int(start_time_str), tz=timezone.utc
                    )
                except (ValueError, TypeError):
                    try:
                        kwargs["start_time"] = datetime.fromisoformat(
                            start_time_str.replace("Z", "+00:00")
                        )
                    except ValueError:
                        logger.warning(f"Invalid start_time format: {start_time_str}")

            if request.query.get("end_time"):
                end_time_str = request.query.get("end_time")
                try:
                    kwargs["end_time"] = datetime.fromtimestamp(
                        int(end_time_str), tz=timezone.utc
                    )
                except (ValueError, TypeError):
                    try:
                        kwargs["end_time"] = datetime.fromisoformat(
                            end_time_str.replace("Z", "+00:00")
                        )
                    except ValueError:
                        logger.warning(f"Invalid end_time format: {end_time_str}")

            epg_data = manager.get_channel_epg(
                provider_name=provider, channel_id=channel_id, **kwargs
            )

            response.content_type = "application/json; charset=utf-8"
            return {"provider": provider, "channel_id": channel_id, "epg": epg_data}

        except ValueError as e:
            logger.error(f"EPG error for {provider}/{channel_id}: {e}")
            response.status = 404
            response.content_type = "application/json; charset=utf-8"
            return {"error": str(e)}
        except Exception as e:
            logger.error(f"EPG error for {provider}/{channel_id}: {e}")
            response.status = 500
            response.content_type = "application/json; charset=utf-8"
            return {"error": f"Internal server error: {str(e)}"}

    @app.route("/api/providers/<provider>/epg")
    def get_provider_epg_xmltv(provider):
        try:
            response.content_type = "application/xml; charset=utf-8"
            response.headers["Content-Disposition"] = (
                f'attachment; filename="{provider}_epg.xml"'
            )

            xmltv_data = manager.get_provider_epg_xmltv(
                provider_name=provider, country=request.query.get("country")
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
            return {"error": f"Internal server error: {str(e)}"}