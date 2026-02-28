#!/usr/bin/env python3
"""
Event-related route handlers
"""

from datetime import datetime

from bottle import request, response
from streaming_providers.base.utils import logger


def setup_events_routes(app, manager, service):
    """Setup event-related routes"""

    @app.route("/api/providers/<provider>/events", method="GET")
    def get_provider_events(provider):
        """
        Get events from a specific provider.

        Query parameters:
        - start_time: Optional ISO 8601 timestamp — only return events ending after this time
        - end_time: Optional ISO 8601 timestamp — only return events starting before this time

        Returns:
        {
            "provider": "provider_name",
            "events": [
                {
                    ...Event fields...
                }
            ],
            "count": 1
        }
        """
        try:
            # Parse optional time range query parameters
            start_time = None
            end_time = None

            start_time_str = request.params.get("start_time")
            end_time_str = request.params.get("end_time")

            if start_time_str:
                try:
                    start_time = datetime.fromisoformat(start_time_str)
                except ValueError:
                    response.status = 400
                    return {
                        "error": "Invalid start_time format",
                        "message": "Use ISO 8601 format, e.g. 2026-03-01T00:00:00",
                    }

            if end_time_str:
                try:
                    end_time = datetime.fromisoformat(end_time_str)
                except ValueError:
                    response.status = 400
                    return {
                        "error": "Invalid end_time format",
                        "message": "Use ISO 8601 format, e.g. 2026-03-01T23:59:59",
                    }

            try:
                events = manager.event_ops.get_events(
                    provider_name=provider,
                    start_time=start_time,
                    end_time=end_time,
                )
            except ValueError as e:
                response.status = 404
                return {
                    "error": "Provider not found",
                    "message": str(e),
                    "provider": provider,
                }
            except Exception as e:
                logger.error(f"Failed to get events from '{provider}': {e}")
                response.status = 500
                return {
                    "error": "Failed to get events",
                    "message": str(e),
                    "provider": provider,
                }

            # Serialize Event objects to dicts
            serialized = [event.to_dict() for event in events]

            response.status = 200
            return {
                "provider": provider,
                "events": serialized,
                "count": len(serialized),
            }

        except Exception as e:
            logger.error(f"Unexpected error in get_provider_events: {e}")
            response.status = 500
            return {
                "error": "Internal server error",
                "message": str(e),
                "provider": provider,
            }