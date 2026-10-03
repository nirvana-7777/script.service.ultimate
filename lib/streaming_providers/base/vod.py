# streaming_providers/base/vod.py
"""
Shared VOD return type.

Prior to this module, providers returned VOD category children in three
different shapes (dict-with-entries, bare list, ...). This module defines
one canonical shape.

Pagination rule: `next_cursor is None` is the authoritative end-of-list
signal (exposed as `has_more`). `total` may be missing; do not use it to
decide whether to keep paging.

Truthiness: bool(page) is driven by __len__, so an empty page is falsy and
a page with entries is truthy -- matching list semantics. An empty page
with a next_cursor is falsy; check `page.has_more` when the caller means
"are there more pages?".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Union

from .models.vod import VodCategory, VodItem


VodEntry = Union[VodCategory, VodItem]


@dataclass
class VodPage:
    """
    One page of VOD results.

    Attributes:
        entries:     Mixed list of VodCategory and VodItem.
        next_cursor: Opaque continuation token; None = no next page.
        total:       Optional total count; None = unknown.

    Truthiness follows list semantics via __len__: an empty page is falsy.
    For pagination, use `has_more` -- NOT bool(page) -- because a page can
    legitimately have zero entries and a non-None cursor.
    """

    entries: List[VodEntry] = field(default_factory=list)
    next_cursor: Optional[str] = None
    total: Optional[int] = None

    @property
    def has_more(self) -> bool:
        """True when the provider indicated a next page exists.

        This is the correct pagination check. `bool(page)` answers
        "are there entries to display?" -- a different question.
        """
        return self.next_cursor is not None

    def __len__(self) -> int:
        # Drives both len(page) and bool(page) via Python's default
        # truthiness rule for objects with __len__. Matches list semantics.
        return len(self.entries)

    def __iter__(self) -> Iterator[VodEntry]:
        return iter(self.entries)

    def to_dict(self) -> dict:
        return {
            "entries": [
                e.to_dict() if hasattr(e, "to_dict") else e
                for e in self.entries
            ],
            "next_cursor": self.next_cursor,
            "total": self.total,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def empty_page() -> VodPage:
    """Return a fresh empty VodPage with no pagination."""
    return VodPage()


def normalize_vod_result(result) -> VodPage:
    """
    Coerce a legacy return value into a VodPage.

    Migration bridge. Once every provider returns VodPage directly, this
    becomes redundant.
    """
    if isinstance(result, VodPage):
        return result
    if result is None:
        return VodPage()
    if isinstance(result, dict):
        return VodPage(
            entries=result.get("entries") or [],
            next_cursor=result.get("next_cursor"),
            total=result.get("total"),
        )
    if isinstance(result, list):
        return VodPage(entries=result)
    import logging
    logging.getLogger(__name__).warning(
        f"normalize_vod_result: unexpected type {type(result).__name__}; "
        f"returning empty page"
    )
    return VodPage()