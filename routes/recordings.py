#!/usr/bin/env python3
"""
Recording-related route handlers.
Mirrors the structure of events.py.
"""

from bottle import request, response
from streaming_providers.base.utils import logger


def setup_recordings_routes(app, manager, service):
    """Setup recording-related routes."""

    @app.route("/api/providers/<provider>/recordings", method="GET")
    def get_provider_recordings(provider):
        """
        Get recordings from a specific provider.

        Query parameters:
        - include_deleted: Optional bool (true/false) — include deleted recordings.
          Defaults to false.

        Returns:
        {
            "provider": "provider_name",
            "recordings": [
                { ...Recording fields... }
            ],
            "count": 1
        }
        """
        try:
            # Parse optional query parameters
            include_deleted_str = request.params.get("include_deleted", "false").lower()
            include_deleted = include_deleted_str in ("1", "true", "yes")

            try:
                recordings = manager.recording_ops.get_recordings(
                    provider_name=provider,
                    include_deleted=include_deleted,
                )
            except ValueError as e:
                response.status = 404
                return {
                    "error": "Provider not found",
                    "message": str(e),
                    "provider": provider,
                }
            except Exception as e:
                logger.error(f"Failed to get recordings from '{provider}': {e}")
                response.status = 500
                return {
                    "error": "Failed to get recordings",
                    "message": str(e),
                    "provider": provider,
                }

            serialized = [recording.to_dict() for recording in recordings]

            response.status = 200
            return {
                "provider": provider,
                "recordings": serialized,
                "count": len(serialized),
            }

        except Exception as e:
            logger.error(f"Unexpected error in get_provider_recordings: {e}")
            response.status = 500
            return {
                "error": "Internal server error",
                "message": str(e),
                "provider": provider,
            }

    @app.route("/api/providers/<provider>/recordings/<recording_id>", method="GET")
    def get_provider_recording(provider, recording_id):
        """
        Get a single recording by ID from a specific provider.

        Returns:
        { ...Recording fields... }
        """
        try:
            try:
                recordings = manager.recording_ops.get_recordings(
                    provider_name=provider,
                    include_deleted=True,  # include deleted so a 404 is explicit
                )
            except ValueError as e:
                response.status = 404
                return {
                    "error": "Provider not found",
                    "message": str(e),
                    "provider": provider,
                }
            except Exception as e:
                logger.error(
                    f"Failed to get recordings from '{provider}': {e}"
                )
                response.status = 500
                return {
                    "error": "Failed to get recordings",
                    "message": str(e),
                    "provider": provider,
                }

            match = next(
                (r for r in recordings if r.recording_id == recording_id), None
            )
            if not match:
                response.status = 404
                return {
                    "error": "Recording not found",
                    "message": f"No recording with id '{recording_id}' from '{provider}'",
                    "provider": provider,
                    "recording_id": recording_id,
                }

            response.status = 200
            return match.to_dict()

        except Exception as e:
            logger.error(f"Unexpected error in get_provider_recording: {e}")
            response.status = 500
            return {
                "error": "Internal server error",
                "message": str(e),
                "provider": provider,
            }

    @app.route("/api/providers/<provider>/recordings/<recording_id>", method="DELETE")
    def delete_provider_recording(provider, recording_id):
        """
        Permanently delete a single recording from a specific provider.

        Returns:
            204 No Content on success.
            404 if the provider or recording is not found.
            409 if the provider refuses the deletion (e.g. recording in progress).
            500 on unexpected errors.
        """
        try:
            try:
                manager.recording_ops.delete_recording(
                    provider_name=provider,
                    recording_id=recording_id,
                )
            except ValueError as e:
                # Raised by RecordingOperations when provider is not found
                response.status = 404
                return {
                    "error": "Provider not found",
                    "message": str(e),
                    "provider": provider,
                }
            except KeyError as e:
                # Raised by the provider when the recording ID does not exist
                response.status = 404
                return {
                    "error": "Recording not found",
                    "message": str(e),
                    "provider": provider,
                    "recording_id": recording_id,
                }
            except RuntimeError as e:
                # Raised by the provider when deletion is refused
                # (e.g. recording currently in progress, insufficient permissions)
                response.status = 409
                return {
                    "error": "Deletion refused by provider",
                    "message": str(e),
                    "provider": provider,
                    "recording_id": recording_id,
                }
            except Exception as e:
                logger.error(
                    f"Failed to delete recording '{recording_id}' "
                    f"from '{provider}': {e}"
                )
                response.status = 500
                return {
                    "error": "Failed to delete recording",
                    "message": str(e),
                    "provider": provider,
                    "recording_id": recording_id,
                }

            # 204 No Content — no body
            response.status = 204
            return ""

        except Exception as e:
            logger.error(f"Unexpected error in delete_provider_recording: {e}")
            response.status = 500
            return {
                "error": "Internal server error",
                "message": str(e),
                "provider": provider,
            }