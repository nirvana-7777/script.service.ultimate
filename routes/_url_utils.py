#!/usr/bin/env python3
"""
Shared helpers for deriving the base URL to hand out to clients.

Kept separate from the individual route modules because the M3U route needs
to absolutize URLs that were baked into a host-independent cache, and other
routes (manifest endpoints) build absolute URLs the same way.
"""

from bottle import request


def build_base_url() -> str:
    """
    Build the scheme://host[:port] prefix the current client used to reach us.

    This is deliberately just the address the client itself put in its
    request: whatever name/IP/port it used is, by definition, reachable from
    where it is. Bottle's request.urlparts already resolves it in the right
    order: X-Forwarded-Host / X-Forwarded-Proto (reverse proxy), then the
    Host header, then SERVER_NAME:SERVER_PORT (HTTP/1.0 without Host).

    Do NOT derive this from the local socket address: behind Docker bridge
    networking or a reverse proxy that is the container/proxy-internal IP,
    and dual-stack sockets report IPv4-mapped (::ffff:a.b.c.d) or scoped
    (fe80::1%eth0) addresses that are not valid in URLs. (An earlier version
    looked for a "waitress.client_socket" environ key; waitress never sets
    one, and the server is bottle's default wsgiref anyway.)
    """
    parts = request.urlparts
    return f"{parts.scheme}://{parts.netloc}"