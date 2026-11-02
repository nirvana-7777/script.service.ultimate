"""
Optional anonymisation. Runs on the consumer thread only, never on the request path.

ANALYTICS_ANONYMIZE:
  off       client_ip is sent as-is (default)
  truncate  IPv4 -> /24, IPv6 -> /48 (203.0.113.7 -> 203.0.113.0)
  hash      salted SHA-256 (first 16 hex chars). Keeps "same client" clustering
            without sending the address. Requires ANALYTICS_HASH_SALT; rotate the
            salt on a schedule. Note: a salted hash of an IP is pseudonymous, not
            anonymous, under GDPR.

Proxy URLs always lose their userinfo (user:pass@). Unless mode is "off" the
host is also replaced by a short hash, so events still group by proxy.
"""
from __future__ import annotations

import hashlib
import ipaddress
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlsplit

from streaming_providers.base.utils import logger

Anonymizer = Callable[[Dict[str, Any]], Dict[str, Any]]

_MODES = ("off", "truncate", "hash")


def _hash(value: str, salt: str, length: int = 16) -> str:
    return hashlib.sha256(f"{salt}|{value}".encode("utf-8")).hexdigest()[:length]


def truncate_ip(ip: str) -> Optional[str]:
    """IPv4 -> /24 network address, IPv6 -> /48. Returns None if unparsable."""
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    prefix = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False).network_address)


def sanitize_proxy(proxy: str, *, hide_host: bool, salt: str = "") -> Optional[str]:
    """Strip credentials; optionally replace the host with a short hash."""
    parts = urlsplit(proxy)
    host = parts.netloc.rpartition("@")[2]
    if not parts.scheme or not host:
        return None
    if hide_host:
        return f"{parts.scheme}://{_hash(host, salt, 8)}"
    return f"{parts.scheme}://{host}"


def make_anonymizer(mode: str = "off", salt: str = "") -> Anonymizer:
    mode = (mode or "off").strip().lower()
    if mode not in _MODES:
        logger.warning(f"Unknown ANALYTICS_ANONYMIZE={mode!r}; falling back to 'truncate'")
        mode = "truncate"
    if mode == "hash" and not salt:
        logger.warning("ANALYTICS_ANONYMIZE=hash needs ANALYTICS_HASH_SALT; falling back to 'truncate'")
        mode = "truncate"

    def apply(raw: Dict[str, Any]) -> Dict[str, Any]:
        out = dict(raw)
        ip = out.get("client_ip")
        if ip and mode != "off":
            out["client_ip"] = _hash(ip, salt) if mode == "hash" else truncate_ip(ip)
        proxy = out.get("proxy")
        if proxy:
            out["proxy"] = sanitize_proxy(proxy, hide_host=(mode != "off"), salt=salt)
        return out

    return apply