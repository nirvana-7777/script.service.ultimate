# streaming_providers/base/utils/proxy_url.py
"""
Media-proxy URL construction shared by the HLS path.

Produces exactly the URL form MPDRewriter.build_proxy_url emits for the plain
(non-decrypt) case:

    {media_proxy_url}/api/proxy/<token>

    token = base64url(urlencode({"url": ..., "proxy": ..., "headers": ...}))

`proxy` is the provider HTTP proxy (omitted when None), `headers` is
base64url(JSON) of the provider's segment headers (omitted when empty). The
parameter ORDER (url, proxy, headers) matters for byte-identical output and is
pinned by test_proxy_url.py against MPDRewriter itself.

Stdlib only. MPDRewriter keeps its own copy for now; the test guards against
drift until it is switched over to these helpers.
"""

import base64
import json
from typing import Callable, Mapping, Optional
from urllib.parse import urlencode


def encode_url(value: str) -> str:
    """base64url without padding (same as MPDRewriter.encode_url)."""
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("utf-8").rstrip("=")


def decode_url(token: str) -> str:
    """Inverse of encode_url. Raises ValueError (binascii.Error and
    UnicodeDecodeError are subclasses) for malformed input."""
    # validate=True: urlsafe_b64decode would silently drop invalid characters.
    raw = base64.b64decode(token + "=" * (-len(token) % 4), altchars=b"-_", validate=True)
    return raw.decode("utf-8")


def encode_segment_headers(headers: Mapping[str, str]) -> str:
    """base64url(JSON) of a header mapping, as carried in the `headers` param."""
    return base64.urlsafe_b64encode(json.dumps(headers).encode()).decode().rstrip("=")


def make_media_proxy_url_builder(
    media_proxy_url: str,
    *,
    provider_proxy_url: Optional[str] = None,
    segment_headers: Optional[Mapping[str, str]] = None,
    endpoint: str = "proxy",
) -> Callable[[str], str]:
    """Return build(url) -> media-proxy URL. The static params (provider proxy,
    encoded headers) are computed once, so rewriting a playlist with thousands
    of segments does not re-encode the headers per segment."""
    base = f"{media_proxy_url.rstrip('/')}/api/{endpoint}"
    static = {}
    if provider_proxy_url:
        static["proxy"] = provider_proxy_url
    if segment_headers:
        static["headers"] = encode_segment_headers(segment_headers)

    def build(url: str) -> str:
        return f"{base}/{encode_url(urlencode({'url': url, **static}))}"

    return build
