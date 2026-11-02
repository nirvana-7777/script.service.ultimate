"""
The only module route code touches.

    @tracked("channel")          wrap a stream handler: one event per call,
    def _handle_channel_stream(provider, channel_id): ...

    annotate(is_catchup=..., proxy=...)   optional extra fields for the current request

Cost on the request thread when analytics is enabled: a handful of attribute
reads, one dict literal and one deque.append. When disabled: a single
`get_emitter() is None` check. Everything is wrapped so that no analytics
failure can change a response.
"""
from __future__ import annotations

import functools
import time
from typing import Any, Callable

from bottle import HTTPResponse, request, response

from .emitter import get_emitter
from .events import (
    DELIVERY_ERROR,
    DELIVERY_PROXIED,
    DELIVERY_REDIRECT,
    EVENT_MANIFEST_REQUEST,
)

_ENV_KEY = "analytics.extra"
_UA_MAX = 256


def annotate(**fields: Any) -> None:
    """Attach extra fields to the event of the current request. Never raises."""
    try:
        request.environ.setdefault(_ENV_KEY, {}).update(fields)
    except Exception:  # noqa: BLE001
        pass


def _classify(status: int, redirected: bool) -> str:
    if status >= 400:
        return DELIVERY_ERROR
    return DELIVERY_REDIRECT if redirected else DELIVERY_PROXIED


def _emit(emitter, content_type: str, provider: str, content_id: str,
          status: int, delivery: str) -> None:
    try:
        ua = request.headers.get("User-Agent")
        raw = {
            "event_type": EVENT_MANIFEST_REQUEST,
            "ts": time.time(),
            "client_ip": request.remote_addr,
            "provider": provider,
            "channel_id": content_id,
            "content_type": content_type,
            "http_status": status,
            "delivery": delivery,
            "user_agent": ua[:_UA_MAX] if ua else None,
            "country": request.query.get("country") or None,
        }
        extra = request.environ.get(_ENV_KEY)
        if extra:
            raw.update(extra)
        emitter.emit(raw)
    except Exception:  # noqa: BLE001
        pass


def tracked(content_type: str) -> Callable:
    """
    Decorator for `handler(provider, content_id, ...)`. Emits exactly one event
    per call, including for redirects (which Bottle raises as HTTPResponse),
    handler-set error statuses and unexpected exceptions. Never alters the
    handler's return value, raised exception, or response.
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(provider, content_id, *args, **kwargs):
            emitter = get_emitter()
            if emitter is None:
                return fn(provider, content_id, *args, **kwargs)

            status, delivery = 500, DELIVERY_ERROR
            try:
                result = fn(provider, content_id, *args, **kwargs)
                status = response.status_code
                delivery = _classify(status, redirected=False)
                return result
            except HTTPResponse as exc:
                status = exc.status_code
                delivery = _classify(status, redirected=300 <= status < 400)
                raise
            finally:
                _emit(emitter, content_type, provider, content_id, status, delivery)
        return wrapper
    return decorator