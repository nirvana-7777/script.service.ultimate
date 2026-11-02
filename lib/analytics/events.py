"""
Analytics event schema. Pure data, no I/O.

The request thread builds a plain dict of raw values (cheapest possible).
Everything else (anonymisation, None-stripping, schema_version) happens on the
consumer thread via finalize(), so none of it costs the request path anything.
"""
from __future__ import annotations

from typing import Any, Dict

try:  # TypedDict is documentation only; keep import safe on old interpreters
    from typing import TypedDict
except ImportError:  # pragma: no cover
    TypedDict = dict  # type: ignore

SCHEMA_VERSION = 1

# Event vocabulary: the backend only names what happened.
EVENT_MANIFEST_REQUEST = "manifest_request"

# How the request was served.
DELIVERY_REDIRECT = "redirect"   # 302 to the upstream manifest; the client talks to upstream directly afterwards
DELIVERY_PROXIED = "proxied"     # manifest body returned (rewritten/decrypted); the media proxy sees the segments
DELIVERY_ERROR = "error"         # status >= 400 or an unhandled exception


class AnalyticsEvent(TypedDict, total=False):
    """Wire format (after finalize). Keys with None values are omitted."""
    event_type: str
    ts: float                    # Unix epoch seconds, taken on the request thread
    client_ip: str               # raw, truncated or hashed depending on ANALYTICS_ANONYMIZE
    provider: str
    channel_id: str              # id of the content item (channel/event/vod/recording)
    content_type: str            # "channel" | "event" | "vod" | "recording"
    http_status: int
    delivery: str                # DELIVERY_*
    user_agent: str
    country: str
    is_catchup: bool
    drm_variant: str
    client_drm: bool
    no_proxy: bool
    highest_quality_only: bool
    proxy: str                   # only if a route calls annotate(proxy=...); userinfo is always stripped
    manifest_refresh_hint: int   # only if a route calls annotate(manifest_refresh_hint=...)
    schema_version: int


def finalize(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Drop None values (so consumers can key-presence-check) and stamp the schema version."""
    out = {k: v for k, v in raw.items() if v is not None}
    out["schema_version"] = SCHEMA_VERSION
    return out