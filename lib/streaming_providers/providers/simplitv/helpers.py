# streaming_providers/providers/simplitv/helpers.py
"""
Helpers shared by more than one simpliTV module.

Public names on purpose: the template README requires that a helper
used by several modules is public (no leading underscore).
"""

from contextlib import contextmanager

from ...base.errors import ProviderError, ServerError


def prefer_dash(url: str) -> str:
    """
    Rewrite an HLS manifest URL to its DASH equivalent.

    Use ONLY for DRM-protected content: inputstream.adaptive needs DASH
    there. Unprotected streams stay on the HLS URL the API returned (the
    existing addon plays those through ffmpegdirect). The replacement
    list is exactly the addon's forward direction; the "nodrm" pair
    exists only in the addon's reverse (DASH -> HLS) direction and must
    not be applied here.
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
