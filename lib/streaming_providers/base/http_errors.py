# streaming_providers/base/http_errors.py
"""
Transport-agnostic mapping from the shared provider error hierarchy
(base/errors.py) to an HTTP status and a JSON-serialisable body.

Kept free of any web-framework import so it can be unit-tested and reused;
the route layer applies the result to its own response object.

Rules:
  * Errors that tell the CLIENT something actionable (auth, entitlement,
    not found, bad request, geo-block, rate limit, pending login) echo the
    provider's message.
  * Upstream/server-side failures and unknown exceptions return a generic
    message. Their detail (which can contain URLs with tokens) is for the
    log only - see `log_detail`.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from .errors import (
    AccountRestrictedError,
    AuthError,
    AuthPendingError,
    BadRequestError,
    CatchupRequiredError,
    ConfigurationError,
    EntitlementError,
    GeoBlockError,
    NotFoundError,
    NotImplementedYetError,
    OperationFailedError,
    PlaybackRestrictedError,
    ProviderError,
    RateLimitError,
    ServerError,
)

# Most specific first: the first isinstance() match wins.
_STATUS_BY_TYPE: Tuple[Tuple[type, int, bool], ...] = (
    # (exception type, HTTP status, echo provider message to client?)
    (AuthPendingError, 202, True),
    (AuthError, 401, True),
    (GeoBlockError, 451, True),
    (AccountRestrictedError, 403, True),
    (EntitlementError, 403, True),
    (PlaybackRestrictedError, 403, True),
    (NotFoundError, 404, True),
    (BadRequestError, 400, True),
    (RateLimitError, 429, True),
    (CatchupRequiredError, 409, True),
    (NotImplementedYetError, 501, True),  # also UnsupportedOperationError
    (ConfigurationError, 503, True),
    (ServerError, 502, False),  # also TransportError
    (OperationFailedError, 502, False),
    (ProviderError, 502, False),
)

GENERIC_UPSTREAM_MESSAGE = "Upstream provider error"
GENERIC_INTERNAL_MESSAGE = "Internal server error"


def error_to_http(exc: BaseException) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
    """
    Returns (status, body, headers) for an exception.

    A pending login is a normal outcome, so it maps to 202 with everything a
    client needs to display the code, plus a Retry-After header.
    """
    headers: Dict[str, str] = {}

    if isinstance(exc, AuthPendingError):
        body: Dict[str, Any] = {
            "status": "login_pending",
            "login_code": exc.login_code,
            "qr_target_url": exc.qr_target_url,
            "remaining_seconds": exc.remaining_seconds,
        }
        if exc.retry_after:
            headers["Retry-After"] = str(int(exc.retry_after))
        return 202, body, headers

    for exc_type, status, echo in _STATUS_BY_TYPE:
        if isinstance(exc, exc_type):
            message = str(exc) if echo else GENERIC_UPSTREAM_MESSAGE
            body = {"error": message, "error_type": type(exc).__name__}
            code = getattr(exc, "code", None)
            if code is not None:
                body["code"] = code
            if isinstance(exc, RateLimitError) and exc.retry_after:
                headers["Retry-After"] = str(int(exc.retry_after))
            return status, body, headers

    return 500, {"error": GENERIC_INTERNAL_MESSAGE}, headers


def log_detail(exc: BaseException, context: str) -> Optional[str]:
    """Message for the server log, or None if nothing should be logged
    (a pending login is not an error)."""
    if isinstance(exc, AuthPendingError):
        return None
    return f"{context}: {type(exc).__name__}: {exc}"