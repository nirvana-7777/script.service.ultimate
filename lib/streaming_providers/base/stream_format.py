# streaming_providers/base/stream_format.py
"""
Stream (manifest) format identification: DASH vs HLS.

Deliberately a LEAF module: standard library only, no imports from the rest
of the package. Both `models/` (Content.streaming_format) and
`drm_operations` need it, and `utils/__init__` may pull in modules that
import `models`, so anything heavier here risks an import cycle.

Contract: `None` means "format unknown" everywhere (there is no UNKNOWN member).

Precedence used by callers (strongest first):
    sniffed manifest content > per-content hint (Content.streaming_format)
    > provider default > URL extension
`detect_format` implements the content / content-type / URL part; the hint
and provider default are applied by the caller.
"""

import re
from enum import Enum
from typing import Dict, Iterator, Optional
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit


class StreamFormat(str, Enum):
    """Adaptive-streaming manifest format.

    Subclasses str so existing string comparisons and JSON serialisation keep
    working; always serialise via `.value` (str() is overridden to match).
    """

    DASH = "dash"
    HLS = "hls"

    def __str__(self) -> str:
        return self.value

    @classmethod
    def parse(cls, value) -> Optional["StreamFormat"]:
        """Tolerant parser for legacy / provider-supplied values.

        Accepts members, format names, file-extension style names and MIME
        types (case-insensitive, parameters like '; charset=utf-8' ignored).
        Returns None for None, empty or unrecognised input.
        """
        if value is None:
            return None
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            return None
        key = value.split(";", 1)[0].strip().lower()
        return _ALIASES.get(key)


_ALIASES: Dict[str, StreamFormat] = {
    # DASH
    "dash": StreamFormat.DASH,
    "mpd": StreamFormat.DASH,
    "mpeg-dash": StreamFormat.DASH,
    "mpeg_dash": StreamFormat.DASH,
    "mpegdash": StreamFormat.DASH,
    "dash+xml": StreamFormat.DASH,
    "application/dash+xml": StreamFormat.DASH,
    # HLS
    "hls": StreamFormat.HLS,
    "m3u8": StreamFormat.HLS,
    "applehls": StreamFormat.HLS,
    "apple_hls": StreamFormat.HLS,
    "apple-hls": StreamFormat.HLS,
    "x-mpegurl": StreamFormat.HLS,
    "vnd.apple.mpegurl": StreamFormat.HLS,
    "application/x-mpegurl": StreamFormat.HLS,
    "application/vnd.apple.mpegurl": StreamFormat.HLS,
}

# An MPD root element can follow an XML prolog, comments and a BOM; 8 KB is
# far more than any real prolog but still trivially cheap.
_SNIFF_CHARS = 8192
_MPD_ROOT_RE = re.compile(r"<\s*(?:[\w.-]+:)?MPD[\s>/]")


def detect_format(
    content: Optional[str] = None,
    url: Optional[str] = None,
    content_type: Optional[str] = None,
) -> Optional[StreamFormat]:
    """Identify the format of a manifest.

    Content is the source of truth: when `content` is given (non-empty) it is
    the ONLY thing consulted, so a fetched error page behind an '.mpd' URL is
    not mistaken for DASH. Without content, falls back to the Content-Type
    header, then to the URL path. Tokenised / redirected URLs frequently have
    no extension, which is why content wins.
    """
    if content:
        head = content[:_SNIFF_CHARS].lstrip("\ufeff \t\r\n")
        if head.startswith("#EXTM3U"):
            return StreamFormat.HLS
        if _MPD_ROOT_RE.search(head):
            return StreamFormat.DASH
        return None

    if content_type:
        fmt = StreamFormat.parse(content_type)
        if fmt is not None:
            return fmt

    if url:
        try:
            path = urlparse(url).path.lower()
        except ValueError:
            return None
        segments = path.split("/")
        if any(seg.endswith(".mpd") for seg in segments):
            return StreamFormat.DASH
        if any(seg.endswith(".m3u8") for seg in segments):
            return StreamFormat.HLS
    return None


# ---------------------------------------------------------------------------
# HLS playlist helpers (RFC 8216). Pure text functions, no I/O.
# ---------------------------------------------------------------------------

# attribute-list entry: NAME=value, value either "quoted" (may contain commas
# and '=', e.g. data: URIs) or bare.
_HLS_ATTR_RE = re.compile(r'([A-Z0-9-]+)=("[^"]*"|[^,]*)')
_HLS_KEY_PREFIXES = ("#EXT-X-KEY:", "#EXT-X-SESSION-KEY:")


def is_hls_master(content: str) -> bool:
    """True for a master (multivariant) playlist. A media playlist never
    contains #EXT-X-STREAM-INF."""
    return "#EXT-X-STREAM-INF" in content


def hls_has_media_segments(content: str) -> bool:
    """True if the playlist lists at least one media segment (#EXTINF)."""
    return "#EXTINF" in content


def first_hls_variant_uri(content: str) -> Optional[str]:
    """URI of the first variant in a master playlist (the line following the
    first #EXT-X-STREAM-INF), or None. I-frame playlists are skipped."""
    expect_uri = False
    for raw in content.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#EXT-X-STREAM-INF"):
            expect_uri = True
            continue
        if expect_uri:
            if line.startswith("#"):
                continue  # other tags may sit between the tag and the URI
            return line
    return None


def hls_key_attributes(content: str) -> Iterator[Dict[str, str]]:
    """Yield the attribute dict (values unquoted) of every #EXT-X-KEY and
    #EXT-X-SESSION-KEY tag, in document order."""
    for raw in content.splitlines():
        line = raw.strip()
        if not line.startswith(_HLS_KEY_PREFIXES):
            continue
        attrs: Dict[str, str] = {}
        for match in _HLS_ATTR_RE.finditer(line.split(":", 1)[1]):
            attrs[match.group(1)] = match.group(2).strip('"')
        yield attrs


# ---------------------------------------------------------------------------
# Serving helpers
# ---------------------------------------------------------------------------

DASH_CONTENT_TYPE = "application/dash+xml; charset=utf-8"
HLS_CONTENT_TYPE = "application/vnd.apple.mpegurl"


def content_type_for(stream_format: Optional[StreamFormat]) -> str:
    """HTTP Content-Type for a manifest of the given format. Unknown falls back
    to DASH, which is what every manifest route served before HLS existed."""
    return HLS_CONTENT_TYPE if stream_format is StreamFormat.HLS else DASH_CONTENT_TYPE


def join_hls_uri(base_url: str, uri: str, inherit_query: bool = True) -> str:
    """Resolve a playlist/segment URI against its parent (RFC 3986).

    Like segment URLs for DASH, a query-less reference inherits the parent's
    query (auth token) when inherit_query is true. Providers opt out via
    `inherit_manifest_query_on_segments = False`.
    """
    joined = urljoin(base_url, uri)
    if inherit_query:
        base_query = urlsplit(base_url).query
        parts = urlsplit(joined)
        if base_query and not parts.query:
            joined = urlunsplit(parts._replace(query=base_query))
    return joined


# URI="..." attribute inside a tag; the lookbehind keeps vendor attributes such
# as X-ASSET-URI untouched.
_HLS_URI_ATTR_RE = re.compile(r'(?<![A-Za-z0-9-])URI="([^"]*)"')


def absolutize_hls_playlist(content: str, base_url: str, inherit_query: bool = True) -> str:
    """Rewrite every relative reference in an HLS playlist to an absolute URL.

    HLS has no <BaseURL> (the DASH trick used by `_inject_base_url`), so a
    playlist that is re-served from another host must carry absolute URLs or
    the player resolves them against OUR server. Handles URI lines (variants,
    segments) and URI="..." attributes (EXT-X-MAP, -KEY, -SESSION-KEY, -MEDIA,
    -I-FRAME-STREAM-INF, -PART, -PRELOAD-HINT, ...). data: URIs and already
    absolute URLs are left alone. The playlist is otherwise returned verbatim.
    """

    def _abs(uri: str) -> str:
        if not uri or uri.lower().startswith("data:"):
            return uri
        return join_hls_uri(base_url, uri, inherit_query)

    out = []
    for raw in content.splitlines():
        stripped = raw.strip()
        if not stripped:
            out.append(raw)
        elif stripped.startswith("#"):
            out.append(_HLS_URI_ATTR_RE.sub(lambda m: f'URI="{_abs(m.group(1))}"', raw))
        else:
            out.append(_abs(stripped))
    result = "\n".join(out)
    return result + "\n" if content.endswith("\n") else result