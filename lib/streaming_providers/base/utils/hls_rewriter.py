# streaming_providers/base/utils/hls_rewriter.py
"""
HLS playlist rewriter (phase 2, Option A).

Pure text transformation, no I/O and no knowledge of the proxy URL scheme or
token signing: every reference in the playlist is resolved to an absolute
upstream URL and handed to a caller-supplied `build_url(url, kind)`, which
returns the URL to put into the playlist. Under Option A the caller maps
  PLAYLIST            -> the backend's playlist endpoint
  SEGMENT / INIT / KEY -> the media proxy (/api/proxy/<token>)
Kind is decided from the TAG a reference sits in, never from the file
extension (tokenised CDN URLs usually have none).

Guarantees
- Line order, comments, #EXT-X-MEDIA-SEQUENCE, discontinuity tags, BYTERANGE
  and every attribute other than URI="..." are passed through untouched.
- data: URIs and non-http(s) schemes (skd://, ...) are never rewritten.
- Relative references resolve against `base_url` (the post-redirect playlist
  URL), inheriting its query like the DASH path when `inherit_query` is true.

Not supported (raises UnsupportedHLSFeature): low-latency HLS tags. Whether to
support or reject LL-HLS is still an open decision (handoff question 5);
rejecting is the safe default because blocking reloads and part requests
cannot be served through a rewritten playlist.

AES-128 key URIs are only routed through `build_url` when `proxy_keys=True`
(and METHOD=AES-128 with an identity KEYFORMAT). Default is False, matching
the current "AES-128 = unknown, pass through" policy (absolutised only).
"""

import re
from enum import Enum
from typing import Callable, Optional
from urllib.parse import urlsplit

from ..stream_format import join_hls_uri


class HLSResource(str, Enum):
    PLAYLIST = "playlist"  # variant / audio / subtitle / I-frame playlist
    SEGMENT = "segment"    # media segment
    INIT = "init"          # EXT-X-MAP initialisation segment
    KEY = "key"            # AES-128 key file


class HLSRewriteError(ValueError):
    """The input is not a rewritable HLS playlist."""


class UnsupportedHLSFeature(HLSRewriteError):
    """The playlist uses a feature the proxied path does not support."""


UrlBuilder = Callable[[str, HLSResource], str]

# Same lookbehind as stream_format._HLS_URI_ATTR_RE: vendor attributes such as
# X-ASSET-URI stay untouched.
_URI_ATTR_RE = re.compile(r'(?<![A-Za-z0-9-])URI="([^"]*)"')
_METHOD_RE = re.compile(r'(?<![A-Za-z0-9-])METHOD=([A-Z0-9-]+)')
_KEYFORMAT_RE = re.compile(r'(?<![A-Za-z0-9-])KEYFORMAT="([^"]*)"')

_LOW_LATENCY_TAGS = frozenset({
    "EXT-X-PART",
    "EXT-X-PART-INF",
    "EXT-X-PRELOAD-HINT",
    "EXT-X-RENDITION-REPORT",
})

_PLAYLIST_TAGS = frozenset({"EXT-X-MEDIA", "EXT-X-I-FRAME-STREAM-INF"})
_KEY_TAGS = frozenset({"EXT-X-KEY", "EXT-X-SESSION-KEY"})


def _is_rewritable_reference(uri: str) -> bool:
    """Relative references and http(s) URLs only. data:, skd:, etc. are left."""
    return urlsplit(uri).scheme.lower() in ("", "http", "https")


def _kind_for_tag(name: str, line: str, proxy_keys: bool) -> Optional[HLSResource]:
    """Resource kind of the URI="..." attribute of a tag, None = absolutise only."""
    if name in _PLAYLIST_TAGS:
        return HLSResource.PLAYLIST
    if name == "EXT-X-MAP":
        return HLSResource.INIT
    if name in _KEY_TAGS and proxy_keys:
        method = _METHOD_RE.search(line)
        keyformat = _KEYFORMAT_RE.search(line)
        if (
            method and method.group(1) == "AES-128"
            and (keyformat is None or keyformat.group(1).lower() == "identity")
        ):
            return HLSResource.KEY
    return None


_TARGET_DURATION_RE = re.compile(r"^#EXT-X-TARGETDURATION:(\d+)", re.MULTILINE)


def hls_cache_ttl(
    content: str,
    *,
    master_ttl: float = 30.0,
    vod_ttl: float = 120.0,
    live_min: float = 1.0,
    live_max: float = 5.0,
    live_default: float = 2.0,
) -> float:
    """How long a REWRITTEN playlist may be reused, in seconds.

    master (multivariant)      -> master_ttl: stable within a session
    media + #EXT-X-ENDLIST     -> vod_ttl: complete, does not change
    live media playlist        -> half the target duration, clamped to
                                  [live_min, live_max]: viewers share one
                                  rewrite per refresh interval, but nobody is
                                  served a playlist older than half a segment
    The upstream Cache-Control header is deliberately not consulted: CDNs
    often send none or a value unrelated to the refresh interval.
    """
    if "#EXT-X-STREAM-INF" in content:
        return master_ttl
    if "#EXT-X-ENDLIST" in content:
        return vod_ttl
    match = _TARGET_DURATION_RE.search(content)
    if not match:
        return live_default
    return max(live_min, min(live_max, int(match.group(1)) / 2.0))


def rewrite_hls_playlist(
    content: str,
    base_url: str,
    build_url: UrlBuilder,
    *,
    inherit_query: bool = True,
    proxy_keys: bool = False,
) -> str:
    """Rewrite every reference in an HLS playlist.

    Args:
        content: playlist text (master or media).
        base_url: URL the playlist was actually fetched from (post-redirect).
        build_url: maps (absolute upstream URL, kind) -> URL for the output.
        inherit_query: relative references inherit base_url's query (see
            stream_format.join_hls_uri); providers opt out through
            `inherit_manifest_query_on_segments = False`.
        proxy_keys: route AES-128 key URIs through build_url (default: only
            absolutise them).

    Raises:
        HLSRewriteError: content is not an HLS playlist.
        UnsupportedHLSFeature: low-latency HLS tags present.
    """
    content = content.lstrip("\ufeff")  # a BOM must not turn #EXTM3U into a "segment"
    if not content.lstrip(" \t\r\n").startswith("#EXTM3U"):
        raise HLSRewriteError("not an HLS playlist (missing #EXTM3U)")

    def resolve(uri: str, kind: Optional[HLSResource]) -> str:
        if not uri or not _is_rewritable_reference(uri):
            return uri
        # An absolute URL is taken exactly as the upstream wrote it (no query
        # inheritance, as in MPDRewriter._urljoin_preserve_query); only relative
        # references resolve against base_url.
        absolute = uri if urlsplit(uri).scheme else join_hls_uri(base_url, uri, inherit_query)
        return absolute if kind is None else build_url(absolute, kind)

    out = []
    expect_variant_uri = False  # the line after #EXT-X-STREAM-INF is a playlist

    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            out.append(raw)
            continue

        if line.startswith("#"):
            name = line[1:].split(":", 1)[0]
            if name in _LOW_LATENCY_TAGS:
                raise UnsupportedHLSFeature(
                    f"low-latency HLS tag {name} is not supported on the proxied path"
                )
            if name == "EXT-X-STREAM-INF":
                expect_variant_uri = True
                out.append(line)
                continue
            kind = _kind_for_tag(name, line, proxy_keys)
            out.append(_URI_ATTR_RE.sub(
                lambda m, k=kind: f'URI="{resolve(m.group(1), k)}"', line
            ))
            continue

        kind = HLSResource.PLAYLIST if expect_variant_uri else HLSResource.SEGMENT
        expect_variant_uri = False
        out.append(resolve(line, kind))

    result = "\n".join(out)
    return result + "\n" if content.endswith("\n") else result
