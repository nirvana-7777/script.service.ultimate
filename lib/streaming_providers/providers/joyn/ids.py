# streaming_providers/providers/joyn/ids.py
# -*- coding: utf-8 -*-
"""
Content-id grammar — the ONE place that decides "live or VOD".

Both managers' `handles_content_id()` call into this module, so the router
(README §7) and the managers can never disagree. Pure functions: no I/O, no
state, safe to call on every routing attempt.

Grammar (documented in constants.py next to VOD_ID_PREFIXES):
    live  — bare channel slugs ("sat1-de", "sat1-de-hd")
    VOD   — a_/b_/c_/d_ asset ids, block-<n>, any browse path containing "/",
            any v1-style block id containing ":"
"""

from .constants import VOD_ID_PREFIXES


def is_vod_id(content_id: str) -> bool:
    if not content_id:
        return False
    return (
        content_id.startswith(VOD_ID_PREFIXES)
        or "/" in content_id
        or ":" in content_id
    )


def is_live_id(content_id: str) -> bool:
    return bool(content_id) and not is_vod_id(content_id)