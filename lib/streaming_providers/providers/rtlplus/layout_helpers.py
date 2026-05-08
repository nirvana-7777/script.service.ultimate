# streaming_providers/providers/rtlplus/layout_helpers.py
"""
RTL+ Layout Helpers

Pure, stateless utilities shared across event_manager, vod_manager, and
channel_manager.  No I/O, no provider references — safe to import anywhere.

Centralises:
  - Lock-target unwrapping         (_unwrap_target)
  - German date parsing            (parse_german_datetime)
  - Signed image URL construction  (build_image_url, extract_thumbnail)
"""

import hashlib
import re
from datetime import datetime
from typing import Dict, Optional

from .constants import RTLPlusDefaults

# ---------------------------------------------------------------------------
# Lock-target unwrapping
# ---------------------------------------------------------------------------

def unwrap_target(target: Dict) -> Dict:
    """
    Unwrap a lock-wrapped action target to its original target dict.

    The Bedrock API wraps pay-walled or auth-gated targets like this::

        {
            "type": "lock",
            "value_lock": {
                "originalTarget": { "type": "...", "value_layout": {...} }
            }
        }

    Calling this function on any target — locked or not — always returns the
    "real" target so callers never need the ``if target.get("type") == "lock"``
    boilerplate.

    Args:
        target: The raw ``action.target`` dict from a layout item.

    Returns:
        The unwrapped target dict, or the original dict if it wasn't locked.
    """
    if not isinstance(target, dict):
        return {}
    if target.get("type") == "lock":
        lock_value = target.get("value_lock", {})
        if isinstance(lock_value, dict):
            inner = lock_value.get("originalTarget", {})
            if isinstance(inner, dict):
                return inner
    return target


# ---------------------------------------------------------------------------
# German date parsing
# ---------------------------------------------------------------------------

# Ordered from most-specific to least-specific so the first match wins.
_DATE_PATTERNS = [
    # "Do., 07.05.26, 20:30 Uhr"  (weekday, 2-digit year, with "Uhr")
    r"[A-Za-z]+\.?,\s*(\d{2})\.(\d{2})\.(\d{2}),\s*(\d{2}):(\d{2})\s*Uhr",
    # "Do., 07.05.26, 20:30"       (weekday, 2-digit year, without "Uhr")
    r"[A-Za-z]+\.?,\s*(\d{2})\.(\d{2})\.(\d{2}),\s*(\d{2}):(\d{2})",
    # "07.05.26, 20:30 Uhr"        (no weekday, 2-digit year, with "Uhr")
    r"(\d{2})\.(\d{2})\.(\d{2}),\s*(\d{2}):(\d{2})\s*Uhr",
    # "07.05.2026, 20:30"          (no weekday, 4-digit year)
    r"(\d{2})\.(\d{2})\.(\d{4}),\s*(\d{2}):(\d{2})",
    # "07.05.26 20:30"             (no comma)
    r"(\d{2})\.(\d{2})\.(\d{2})\s+(\d{2}):(\d{2})",
    # "07.05.26"                   (date only, no time)
    r"(\d{2})\.(\d{2})\.(\d{2,4})",
]


def parse_german_datetime(text: str) -> Optional[datetime]:
    """
    Parse a German-formatted date/time string embedded in arbitrary text.

    Handles all variants seen in RTL+ Bedrock highlight strings, e.g.::

        "Fußball • Do., 07.05.26, 20:30 Uhr"
        "Motorsport • Fr., 15.05.26, 13:10 Uhr"
        "Motorsport \u2022 Sa., 16.05.26, 14:15 Uhr"
        "07.05.2026, 20:30"

    Two-digit years are expanded to the 21st century (``26`` → ``2026``).

    Args:
        text: Any string that may contain a German date.

    Returns:
        A ``datetime`` object, or ``None`` if no recognisable date was found.
    """
    for pattern in _DATE_PATTERNS:
        match = re.search(pattern, text)
        if not match:
            continue

        groups = match.groups()
        if len(groups) < 3:
            continue

        try:
            day = int(groups[0])
            month = int(groups[1])
            year = int(groups[2])

            # Expand 2-digit year
            if year < 100:
                year = 2000 + year

            hour = int(groups[3]) if len(groups) > 3 else 0
            minute = int(groups[4]) if len(groups) > 4 else 0

            return datetime(year, month, day, hour, minute)
        except ValueError:
            continue  # Try the next pattern

    return None


# ---------------------------------------------------------------------------
# Signed image URL construction
# ---------------------------------------------------------------------------

def build_image_url(image_id: str) -> str:
    """
    Build a signed Bedrock CDN image URL for the given image ID.

    Hash formula: ``SHA1("/v2/images/{id}/raw?{params}" + IMAGE_SIGNING_KEY)``

    The signing key is appended as a suffix (secret-suffix construction),
    verified against multiple known-good URLs captured from network traces.

    Args:
        image_id: The raw image ID returned by the Bedrock API.

    Returns:
        A fully-qualified, signed image URL.
    """
    suffix = f"/{image_id}/raw?{RTLPlusDefaults.IMAGE_PARAMS}"
    signed_path = f"/v2/images{suffix}"
    image_hash = hashlib.sha1(
        (signed_path + RTLPlusDefaults.IMAGE_SIGNING_KEY).encode()
    ).hexdigest()
    return f"{RTLPlusDefaults.IMAGE_BASE_URL}{suffix}&hash={image_hash}"


def extract_thumbnail(item_content: Dict) -> Optional[str]:
    """
    Extract the best available thumbnail URL from a Bedrock item's content dict.

    Tries aspect ratios in preference order: 16:9, 3:1, 1:1, 2:3.
    Falls back to the top-level ``image.id`` if no ratio-keyed ID is found.

    Args:
        item_content: The ``itemContent`` dict from a Bedrock block item.

    Returns:
        A signed CDN URL, or ``None`` if no image data is present.
    """
    image = item_content.get("image", {})
    if not image:
        return None

    for ratio in ("16:9", "3:1", "1:1", "2:3"):
        image_id = image.get("idsByRatio", {}).get(ratio)
        if image_id:
            return build_image_url(image_id)

    image_id = image.get("id")
    if image_id:
        return build_image_url(image_id)

    return None


def extract_thumbnail_from_layout(layout: Dict) -> Optional[str]:
    """
    Extract a thumbnail URL from a top-level program/video layout dict.

    Reads from ``layout.seo.image.id``, which is populated on program and
    video layout responses but not on individual block items.

    Args:
        layout: A full Bedrock layout response dict.

    Returns:
        A signed CDN URL, or ``None`` if no SEO image is present.
    """
    image_id = layout.get("seo", {}).get("image", {}).get("id")
    if image_id:
        return build_image_url(image_id)
    return None