# streaming_providers/providers/eon/stream_url.py
"""
Builds the signed Eon CDN URL. Pure functions: no network, no state.

The CDN takes the whole request as an AES-CBC encrypted `;`-separated
payload (query parameter `a`, IV in `i`), both urlsafe-base64 without
padding. The key is the account's `stream_key` (urlsafe base64). The payload
carries a `ctime` (server time in ms) that the CDN accepts for ~20 s only,
and a `session` id; reusing a session id while the CDN still considers it
active gets the request rejected -- always pass a fresh one.

Layout differences (ported from PVREon.cpp / StreamRedirectProxy.cpp):
    web        : channel;stream;sp;u;ss;minvbr;sig;session;m;device;ctime;
                 conn;[adaptive];player;[t=<start>000];aa
                 (no maxvbr, `sig` also in the query string)
    androidtv  : channel;stream;sp;u;m;device;ctime;lang;player;aa;conn;
                 minvbr;ss;session;maxvbr[;t=<start>000;]
                 (no `sig`, `lang` also in the query string)
`ss` is the stream key (the same urlsafe string that is the AES key), `m` the
server IP; the URL host is the server HOSTNAME.
Live has no `t`; catchup passes the programme start (Unix seconds).

The decoded key length decides the AES variant here (16/24/32 bytes). The
C++ addon used tiny-AES whose default build is AES-128 (first 16 bytes of
the key). Verify on a device that the stream key is exactly 16 bytes; if it
is longer the two implementations disagree.
"""

import base64
import os
from dataclasses import dataclass
from typing import Callable, Optional

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .constants import EonDefaults, EonPlatform


@dataclass(frozen=True)
class StreamUrlParams:
    platform: EonPlatform
    publishing_point: str
    stream_profile: str          # coreStreamId of the chosen rendering profile
    service_provider: str
    stream_user: str
    stream_key: str
    server_host: str             # hostname: the URL host
    server_ip: str               # payload `m=`
    device_number: str
    sig: str
    aa_enabled: bool
    video_bitrate: int           # 0 for audio-only profiles
    ctime_ms: str                # /v1/time -> "time", passed through verbatim
    session_id: str
    adaptive: bool = True
    start_time: Optional[int] = None   # Unix seconds; None = live


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64u_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _encrypt(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError(f"unsupported stream key length: {len(key)} bytes")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def build_payload(p: StreamUrlParams) -> str:
    """The plaintext that gets encrypted (exposed for tests)."""
    minvbr = min(EonDefaults.MIN_VIDEO_BITRATE, p.video_bitrate)
    aa = "true" if p.aa_enabled else "false"
    t = f"t={p.start_time}000" if p.start_time else None

    if p.platform.is_android_tv:
        parts = [
            f"channel={p.publishing_point}",
            f"stream={p.stream_profile}",
            f"sp={p.service_provider}",
            f"u={p.stream_user}",
            f"m={p.server_ip}",
            f"device={p.device_number}",
            f"ctime={p.ctime_ms}",
            "lang=eng",
            f"player={EonDefaults.PLAYER}",
            f"aa={aa}",
            f"conn={p.platform.conn_type}",
            f"minvbr={minvbr}",
            f"ss={p.stream_key}",
            f"session={p.session_id}",
            f"maxvbr={p.video_bitrate}",
        ]
        payload = ";".join(parts)
        if t:
            payload += f";{t};"
        return payload

    parts = [
        f"channel={p.publishing_point}",
        f"stream={p.stream_profile}",
        f"sp={p.service_provider}",
        f"u={p.stream_user}",
        f"ss={p.stream_key}",
        f"minvbr={minvbr}",
        f"sig={p.sig}",
        f"session={p.session_id}",
        f"m={p.server_ip}",
        f"device={p.device_number}",
        f"ctime={p.ctime_ms}",
        f"conn={p.platform.conn_type}",
    ]
    if p.adaptive:
        parts.append("adaptive=true")
    parts.append(f"player={EonDefaults.PLAYER}")
    if t:
        parts.append(t)
    parts.append(f"aa={aa}")
    return ";".join(parts)


def build_stream_url(
    p: StreamUrlParams, *, iv: Optional[bytes] = None
) -> str:
    """Encrypt the payload and assemble the CDN URL. `iv` is for tests."""
    iv = iv if iv is not None else os.urandom(16)
    key = _b64u_decode(p.stream_key)
    cipher = _encrypt(key, build_payload(p).encode("utf-8"), iv)

    query = f"i={_b64u_encode(iv)}&a={_b64u_encode(cipher)}"
    if p.platform.is_android_tv:
        query += "&lang=eng"
    query += f"&sp={p.service_provider}&u={p.stream_user}&player={EonDefaults.PLAYER}"
    query += f"&session={p.session_id}"
    if not p.platform.is_android_tv:
        query += f"&sig={p.sig}"
    return f"https://{p.server_host}/stream?{query}"


def decrypt_for_test(url_query_a: str, url_query_i: str, stream_key: str) -> str:
    """Inverse of the encryption (tests only)."""
    key = _b64u_decode(stream_key)
    dec = Cipher(algorithms.AES(key), modes.CBC(_b64u_decode(url_query_i))).decryptor()
    padded = dec.update(_b64u_decode(url_query_a)) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")