# streaming_providers/providers/movetv/ids.py
"""
Id grammar of the move.tv provider -- the SINGLE owner (pure functions, no I/O).

live   : the numeric catalogue id of a channel, e.g. "1234"   (str.isdigit())
VOD    : browse nodes only (no VOD playback exists, README §7):
             ""                         root  -> content types
             "content_type_<ct>"        content type -> categories
             "category_<ct>_<cat>"      category -> items (paged)
         VOD item ids are numeric too, but are never routed: the VOD manager
         claims no ids (handles_content_id is False), so a numeric id is always
         a live id for the router.
"""

import re
from typing import Tuple, Union

from ...base.errors import BadRequestError

CONTENT_TYPE_PREFIX = "content_type_"
CATEGORY_PREFIX = "category_"

_CONTENT_TYPE_RE = re.compile(r"^content_type_(\d+)$")
_CATEGORY_RE = re.compile(r"^category_(\d+)_(\d+)$")


def is_live_id(content_id: object) -> bool:
    return isinstance(content_id, str) and content_id.isascii() and content_id.isdigit()


def parse_live_id(content_id: str) -> int:
    if not is_live_id(content_id):
        raise BadRequestError(f"move.tv: not a live channel id: {content_id!r}")
    return int(content_id)


def content_type_node(content_type_id: int) -> str:
    return f"{CONTENT_TYPE_PREFIX}{int(content_type_id)}"


def category_node(content_type_id: int, category_id: Union[int, str]) -> str:
    return f"{CATEGORY_PREFIX}{int(content_type_id)}_{int(category_id)}"


def parse_vod_node(content_id: str) -> Tuple:
    """-> ("root",) | ("content_type", ct) | ("category", ct, cat); BadRequestError otherwise."""
    if not content_id or content_id == "root":
        return ("root",)
    m = _CONTENT_TYPE_RE.match(content_id)
    if m:
        return "content_type", int(m.group(1))
    m = _CATEGORY_RE.match(content_id)
    if m:
        return "category", int(m.group(1)), int(m.group(2))
    raise BadRequestError(f"move.tv: unknown VOD node id: {content_id!r}")