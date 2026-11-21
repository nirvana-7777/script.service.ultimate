#!/usr/bin/env python3
"""
Timer-related route handlers.
Mirrors the structure of recordings.py.

Endpoints
---------
GET  /api/providers/<provider>/timer-types
GET  /api/providers/<provider>/timers
GET  /api/providers/<provider>/timers/<client_index>
POST /api/providers/<provider>/timers
PUT  /api/providers/<provider>/timers/<client_index>
DELETE /api/providers/<provider>/timers/<client_index>
"""

import json
from bottle import request, response

from streaming_providers.base.models.timer import (
    DuplicateHandling,
    Timer,
    TimerState,
    TimerWeekday,
)
from streaming_providers.base.timer_operations import (
    ProviderNotFoundError,
    TimersNotSupportedError,
)
from streaming_providers.base.utils import logger

from datetime import datetime


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_datetime(value: str, field_name: str) -> datetime:
    """
    Parse an ISO 8601 datetime string, raising ValueError with a clear
    message if parsing fails.
    """
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        raise ValueError(
            f"'{field_name}' must be an ISO 8601 datetime string "
            f"(e.g. '2025-06-01T20:15:00'), got: {value!r}"
        )


def _timer_from_body(body: dict, client_index: int = 0) -> Timer:
    """
    Deserialise a request body dictionary into a Timer object.

    Required keys:  title, timer_type_id, provider
    All other keys are optional and map directly to Timer fields.

    Raises:
        ValueError: If required keys are missing or a field cannot be parsed.
    """
    for required in ("title", "timer_type_id"):
        if required not in body:
            raise ValueError(f"Missing required field: '{required}'")

    kwargs = {}

    # Timing
    if "start_time" in body and body["start_time"] is not None:
        kwargs["start_time"] = _parse_datetime(body["start_time"], "start_time")
    if "end_time" in body and body["end_time"] is not None:
        kwargs["end_time"] = _parse_datetime(body["end_time"], "end_time")
    if "first_day" in body and body["first_day"] is not None:
        kwargs["first_day"] = _parse_datetime(body["first_day"], "first_day")

    # Enumerations
    if "state" in body:
        try:
            kwargs["state"] = TimerState(body["state"])
        except ValueError:
            raise ValueError(
                f"Invalid state '{body['state']}'. "
                f"Valid values: {[s.value for s in TimerState]}"
            )

    if "weekdays" in body:
        try:
            kwargs["weekdays"] = TimerWeekday(int(body["weekdays"]))
        except (ValueError, TypeError):
            raise ValueError(
                f"'weekdays' must be an integer bitmask "
                f"(e.g. {TimerWeekday.MONDAY.value} for Monday). "
                f"Got: {body['weekdays']!r}"
            )

    if "prevent_duplicate_episodes" in body:
        try:
            kwargs["prevent_duplicate_episodes"] = DuplicateHandling(
                int(body["prevent_duplicate_episodes"])
            )
        except (ValueError, TypeError):
            raise ValueError(
                f"Invalid prevent_duplicate_episodes value: "
                f"{body['prevent_duplicate_episodes']!r}. "
                f"Valid values: {[d.value for d in DuplicateHandling]}"
            )

    # Scalar fields — passed through directly if present
    scalar_fields = (
        "timer_type_id",
        "title",
        "parent_client_index",
        "client_channel_uid",
        "channel_name",
        "start_any_time",
        "end_any_time",
        "margin_start",
        "margin_end",
        "epg_search_string",
        "full_text_epg_search",
        "epg_uid",
        "epg_event_id",
        "series_link",
        "directory",
        "priority",
        "lifetime",
        "max_recordings",
        "recording_group",
        "genre_type",
        "genre_sub_type",
        "description",
    )
    for f in scalar_fields:
        if f in body:
            kwargs[f] = body[f]

    return Timer(client_index=client_index, **kwargs)


# Timer payloads are a few hundred bytes; anything bigger is not a timer.
_MAX_BODY_BYTES = 64 * 1024


def _exc_message(e: Exception) -> str:
    """str(KeyError('x')) is "'x'" — unwrap it."""
    if isinstance(e, KeyError) and e.args:
        return str(e.args[0])
    return str(e)


def _read_json_object(provider: str, **extra):
    """
    Read the request body as a JSON object.

    Returns ``(body, None)`` on success, or ``(None, error_payload)`` after
    setting ``response.status``.

    Bottle's ``request.json`` raises HTTPError(400) on malformed JSON, which the
    routes' blanket ``except Exception`` would turn into a 500 — and it hides
    the raw bytes.  Reading the body ourselves avoids both.
    """
    request_id = request.get_header("X-Request-Id", "")
    raw = request.body.read(_MAX_BODY_BYTES + 1)
    if len(raw) > _MAX_BODY_BYTES:
        response.status = 413
        return None, {
            "error": "Payload too large",
            "message": f"Request body exceeds {_MAX_BODY_BYTES} bytes",
            "provider": provider,
            **extra,
        }

    logger.debug(
        f"timers[{provider}] reqid={request_id!r}: "
        f"Content-Type={request.get_header('Content-Type', '')!r} "
        f"bytes={len(raw)} body={raw[:2000]!r}"
    )

    try:
        body = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as e:
        logger.warning(
            f"timers[{provider}] reqid={request_id!r}: body is not valid UTF-8: "
            f"{e} (first 100 bytes hex: {raw[:100].hex()})"
        )
        response.status = 400
        return None, {
            "error": "Bad request",
            "message": f"Request body is not valid UTF-8: {e}",
            "provider": provider,
            **extra,
        }
    except json.JSONDecodeError as e:
        logger.warning(
            f"timers[{provider}] reqid={request_id!r}: JSON decode failed at "
            f"line {e.lineno} col {e.colno} (char {e.pos}): {e.msg} - "
            f"context: {raw[max(0, e.pos - 30):e.pos + 30]!r}"
        )
        response.status = 400
        return None, {
            "error": "Bad request",
            "message": f"Request body must be valid JSON: {e.msg} at position {e.pos}",
            "provider": provider,
            **extra,
        }

    if not isinstance(body, dict) or not body:
        response.status = 400
        return None, {
            "error": "Bad request",
            "message": "Request body must be a non-empty JSON object",
            "provider": provider,
            **extra,
        }
    return body, None


def _provider_unavailable(e: Exception, provider: str, **extra) -> dict:
    """404 for an unknown/disabled provider, 501 when it has no timer support."""
    if isinstance(e, TimersNotSupportedError):
        response.status = 501
        error = "Timers not supported"
    else:
        response.status = 404
        error = "Provider not found"
    return {"error": error, "message": str(e), "provider": provider, **extra}


def _provider_error(
    e: Exception, title: str, provider: str, default_status: int = 409, **extra
) -> dict:
    """
    Response for an error raised by the provider while talking to its backend.

    If the exception carries structured upstream info (``e.upstream``, see
    NpvrApiError) it is passed on to the client: ``message`` becomes the
    upstream's own explanation (e.g. "Recording is not allowed on this event")
    and the full details go into ``upstream``.  An upstream 5xx maps to 502;
    anything else keeps ``default_status``.
    """
    upstream = getattr(e, "upstream", None) or None
    status = upstream.get("status") if upstream else None
    response.status = 502 if isinstance(status, int) and status >= 500 else default_status

    logger.error(f"{title} on '{provider}': {_exc_message(e)}")

    body = {
        "error": title,
        "message": (upstream or {}).get("details") or _exc_message(e),
        "provider": provider,
        **extra,
    }
    if upstream:
        body["upstream"] = upstream
    return body


# ---------------------------------------------------------------------------
# Route setup
# ---------------------------------------------------------------------------

def setup_timers_routes(app, manager, service):
    """Register timer-related routes on the Bottle app."""

    # ------------------------------------------------------------------ #
    # GET /api/providers/<provider>/timer-types                           #
    # ------------------------------------------------------------------ #

    @app.route("/api/providers/<provider>/timer-types", method="GET")
    def get_provider_timer_types(provider):
        """
        Get the timer types supported by a specific provider.

        Returns:
        {
            "provider": "provider_name",
            "timer_types": [ { ...TimerType fields... } ],
            "count": 2
        }
        """
        try:
            try:
                timer_types = manager.timer_ops.get_timer_types(provider_name=provider)
            except (ProviderNotFoundError, TimersNotSupportedError) as e:
                return _provider_unavailable(e, provider)

            serialized = [tt.to_dict() for tt in timer_types]
            response.status = 200
            return {
                "provider": provider,
                "timer_types": serialized,
                "count": len(serialized),
            }

        except Exception as e:
            logger.error(f"Unexpected error in get_provider_timer_types: {e}")
            response.status = 500
            return {"error": "Internal server error", "message": str(e), "provider": provider}

    # ------------------------------------------------------------------ #
    # GET /api/providers/<provider>/timers                                #
    # ------------------------------------------------------------------ #

    @app.route("/api/providers/<provider>/timers", method="GET")
    def get_provider_timers(provider):
        """
        List timers for a specific provider.

        Query parameters:
            include_inactive: bool (default false) — include completed /
                              cancelled / error timers.

        Returns:
        {
            "provider": "provider_name",
            "timers": [ { ...Timer fields... } ],
            "count": 3
        }
        """
        try:
            include_inactive = (
                request.params.get("include_inactive", "false").lower()
                in ("1", "true", "yes")
            )

            try:
                timers = manager.timer_ops.get_timers(
                    provider_name=provider,
                    include_inactive=include_inactive,
                )
            except (ProviderNotFoundError, TimersNotSupportedError) as e:
                return _provider_unavailable(e, provider)
            except RuntimeError as e:
                return _provider_error(
                    e, "Failed to get timers", provider, default_status=502
                )
            except Exception as e:
                logger.error(f"Failed to get timers from '{provider}': {e}")
                response.status = 500
                return {
                    "error": "Failed to get timers",
                    "message": str(e),
                    "provider": provider,
                }

            serialized = [t.to_dict() for t in timers]
            response.status = 200
            return {
                "provider": provider,
                "timers": serialized,
                "count": len(serialized),
            }

        except Exception as e:
            logger.error(f"Unexpected error in get_provider_timers: {e}")
            response.status = 500
            return {"error": "Internal server error", "message": str(e), "provider": provider}

    # ------------------------------------------------------------------ #
    # GET /api/providers/<provider>/timers/<client_index>                 #
    # ------------------------------------------------------------------ #

    @app.route("/api/providers/<provider>/timers/<client_index:int>", method="GET")
    def get_provider_timer(provider, client_index):
        """
        Get a single timer by its client index.

        Returns:
            { ...Timer fields... }
        """
        try:
            try:
                timer = manager.timer_ops.get_timer(
                    provider_name=provider,
                    client_index=client_index,
                )
            except (ProviderNotFoundError, TimersNotSupportedError) as e:
                return _provider_unavailable(e, provider)
            except RuntimeError as e:
                return _provider_error(
                    e, "Failed to get timer", provider,
                    default_status=502, client_index=client_index,
                )
            except Exception as e:
                logger.error(
                    f"Failed to get timer {client_index} from '{provider}': {e}"
                )
                response.status = 500
                return {
                    "error": "Failed to get timer",
                    "message": str(e),
                    "provider": provider,
                    "client_index": client_index,
                }

            if timer is None:
                response.status = 404
                return {
                    "error": "Timer not found",
                    "message": (
                        f"No timer with client_index {client_index} "
                        f"from '{provider}'"
                    ),
                    "provider": provider,
                    "client_index": client_index,
                }

            response.status = 200
            return timer.to_dict()

        except Exception as e:
            logger.error(f"Unexpected error in get_provider_timer: {e}")
            response.status = 500
            return {
                "error": "Internal server error",
                "message": str(e),
                "provider": provider,
            }

    # ------------------------------------------------------------------ #
    # POST /api/providers/<provider>/timers                               #
    # ------------------------------------------------------------------ #

    @app.route("/api/providers/<provider>/timers", method="POST")
    def add_provider_timer(provider):
        """
        Schedule a new timer on a specific provider.

        Request body (JSON):
        {
            "title": "Tatort",              // required
            "timer_type_id": 1,             // required
            "client_channel_uid": 42,
            "start_time": "2025-06-01T20:15:00",
            "end_time":   "2025-06-01T21:45:00",
            "margin_start": 5,
            "margin_end": 10,
            "priority": 50,
            "lifetime": 30,
            ...
        }

        Returns:
            201 Created with the saved Timer in the body.
            400 if the request body is invalid.
            404 if the provider is not found.
            409 if the provider refuses the timer (e.g. conflict); the
                provider's own explanation is in "message" and, when the
                backend sent one, the structured error in "upstream".
            501 if the provider has no timer support.
            502 if the provider's backend failed (upstream 5xx).
            500 on unexpected errors.
        """
        try:
            body, error = _read_json_object(provider)
            if error:
                return error

            # Inject provider so the Timer knows where it belongs
            body.setdefault("provider", provider)

            try:
                timer = _timer_from_body(body)
            except ValueError as e:
                response.status = 400
                return {
                    "error": "Invalid timer data",
                    "message": str(e),
                    "provider": provider,
                }

            try:
                saved = manager.timer_ops.add_timer(
                    provider_name=provider, timer=timer
                )
            except (ProviderNotFoundError, TimersNotSupportedError) as e:
                return _provider_unavailable(e, provider)
            except ValueError as e:
                # Provider-side validation (e.g. missing/invalid epg_event_id).
                response.status = 400
                return {
                    "error": "Invalid timer data",
                    "message": str(e),
                    "provider": provider,
                }
            except RuntimeError as e:
                return _provider_error(e, "Timer rejected by provider", provider)
            except Exception as e:
                logger.error(f"Failed to add timer on '{provider}': {e}")
                response.status = 500
                return {
                    "error": "Failed to add timer",
                    "message": str(e),
                    "provider": provider,
                }

            response.status = 201
            return saved.to_dict()

        except Exception as e:
            logger.error(f"Unexpected error in add_provider_timer: {e}")
            response.status = 500
            return {"error": "Internal server error", "message": str(e), "provider": provider}

    # ------------------------------------------------------------------ #
    # PUT /api/providers/<provider>/timers/<client_index>                 #
    # ------------------------------------------------------------------ #

    @app.route("/api/providers/<provider>/timers/<client_index:int>", method="PUT")
    def update_provider_timer(provider, client_index):
        """
        Update an existing timer.

        The client_index from the URL takes precedence over any value in the
        body — this prevents accidental cross-timer updates.

        Request body (JSON): same shape as POST, all fields optional except
        those the provider requires to be present on an update.

        Returns:
            200 OK with the updated Timer in the body.
            400 if the request body is invalid.
            404 if the provider or timer is not found.
            409 if the provider refuses the update.
            500 on unexpected errors.
        """
        try:
            body, error = _read_json_object(provider, client_index=client_index)
            if error:
                return error

            body.setdefault("provider", provider)

            try:
                timer = _timer_from_body(body, client_index=client_index)
            except ValueError as e:
                response.status = 400
                return {
                    "error": "Invalid timer data",
                    "message": str(e),
                    "provider": provider,
                    "client_index": client_index,
                }

            try:
                updated = manager.timer_ops.update_timer(
                    provider_name=provider, timer=timer
                )
            except (ProviderNotFoundError, TimersNotSupportedError) as e:
                return _provider_unavailable(e, provider)
            except ValueError as e:
                response.status = 400
                return {
                    "error": "Invalid timer data",
                    "message": str(e),
                    "provider": provider,
                    "client_index": client_index,
                }
            except KeyError as e:
                response.status = 404
                return {
                    "error": "Timer not found",
                    "message": _exc_message(e),
                    "provider": provider,
                    "client_index": client_index,
                }
            except RuntimeError as e:
                return _provider_error(
                    e, "Update refused by provider", provider,
                    client_index=client_index,
                )
            except Exception as e:
                logger.error(
                    f"Failed to update timer {client_index} on '{provider}': {e}"
                )
                response.status = 500
                return {
                    "error": "Failed to update timer",
                    "message": str(e),
                    "provider": provider,
                    "client_index": client_index,
                }

            response.status = 200
            return updated.to_dict()

        except Exception as e:
            logger.error(f"Unexpected error in update_provider_timer: {e}")
            response.status = 500
            return {
                "error": "Internal server error",
                "message": str(e),
                "provider": provider,
            }

    # ------------------------------------------------------------------ #
    # DELETE /api/providers/<provider>/timers/<client_index>              #
    # ------------------------------------------------------------------ #

    @app.route("/api/providers/<provider>/timers/<client_index:int>", method="DELETE")
    def delete_provider_timer(provider, client_index):
        """
        Delete a timer.

        Query parameters:
            force: bool (default false) — if the timer is currently recording,
                   abort the ongoing capture and delete.

        Returns:
            204 No Content on success.
            404 if the provider or timer is not found.
            409 if the provider refuses deletion and force was not set.
            500 on unexpected errors.
        """
        try:
            force = (
                request.params.get("force", "false").lower()
                in ("1", "true", "yes")
            )

            try:
                manager.timer_ops.delete_timer(
                    provider_name=provider,
                    client_index=client_index,
                    force_delete=force,
                )
            except (ProviderNotFoundError, TimersNotSupportedError) as e:
                return _provider_unavailable(e, provider)
            except KeyError as e:
                response.status = 404
                return {
                    "error": "Timer not found",
                    "message": _exc_message(e),
                    "provider": provider,
                    "client_index": client_index,
                }
            except RuntimeError as e:
                return _provider_error(
                    e, "Deletion refused by provider", provider,
                    client_index=client_index,
                )
            except Exception as e:
                logger.error(
                    f"Failed to delete timer {client_index} from '{provider}': {e}"
                )
                response.status = 500
                return {
                    "error": "Failed to delete timer",
                    "message": str(e),
                    "provider": provider,
                    "client_index": client_index,
                }

            # 204 No Content — no body
            response.status = 204
            return ""

        except Exception as e:
            logger.error(f"Unexpected error in delete_provider_timer: {e}")
            response.status = 500
            return {
                "error": "Internal server error",
                "message": str(e),
                "provider": provider,
            }