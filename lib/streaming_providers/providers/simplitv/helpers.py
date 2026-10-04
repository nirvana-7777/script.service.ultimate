# streaming_providers/providers/simplitv/helpers.py
"""
Helpers shared by more than one simpliTV module.

Public names on purpose: the template README requires that a helper
used by several modules is public (no leading underscore).
"""

import re
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

from ...base.errors import ProviderError, ServerError


def prefer_dash(url: str) -> str:
    """
    Rewrite an HLS manifest URL to its DASH equivalent.

    Fallback only, and only for DRM-protected content. The
    AcquireContent response normally carries both DASH (Type 9) and HLS
    (Type 2) entries, and the channel manager picks the DASH one
    directly when the content is protected; this function is called
    only when the protected asset is HLS-only.

    Never applied to unprotected content: the CDN has been serving the
    HLS URL to the addon for those since day one, and swapping it out
    has not been validated. Restart relies on a DVR seek offset from
    the window start, and DASH time-shift semantics can differ from
    HLS.

    The replacement list is exactly the addon's forward direction; the
    "nodrm" pair exists only in the addon's reverse (DASH -> HLS)
    direction and must not be applied here.
    """
    for old, new in (
        (".m3u8", ".mpd"),
        ("/hls/", "/dash/"),
        ("hls_live", "dash_live"),
        ("/hls4h/", "/dash4h/"),
    ):
        if old in url:
            url = url.replace(old, new)
    return url


@contextmanager
def transport_errors(what: str):
    """
    Wrap *unexpected* failures (network, bad JSON) in ServerError while
    letting typed provider errors through untouched.

    Callers rely on AuthError / RateLimitError / GeoBlockError etc. to
    refresh tokens or back off, so these must never be flattened into a
    generic error.
    """
    try:
        yield
    except ProviderError:
        raise
    except Exception as e:
        raise ServerError(f"simpliTV: {what} failed: {e}") from e


# Fractional seconds followed by end-of-string, Z, or a UTC offset.
_FRACTION = re.compile(r"\.(\d+)(?=$|[Zz]|[+-]\d{2}(?::?\d{2})?$)")
_OFFSET_NO_COLON = re.compile(r"([+-]\d{2})(\d{2})$")


def parse_iso(value: Optional[str]) -> Optional[datetime]:
    """
    Parse an ISO-8601 timestamp to a timezone-aware datetime, or None
    if missing / malformed.

    datetime.fromisoformat on Python < 3.11 accepts only 3 or 6
    fractional digits and rejects "Z" and "+HHMM". .NET-style APIs
    emit 7 digits, so the string is normalised first: fraction cut or
    padded to 6 digits, "Z" -> "+00:00", "+HHMM" -> "+HH:MM". A
    timestamp without an offset is read as UTC, never as local time.
    """
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    s = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), s)
    if s[-1] in "Zz":
        s = s[:-1] + "+00:00"
    s = _OFFSET_NO_COLON.sub(r"\1:\2", s)
    try:
        dt = datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt