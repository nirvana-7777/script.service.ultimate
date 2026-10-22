# streaming_providers/base/errors.py
"""
Shared provider error hierarchy.

Rationale
---------
Every provider raises its own exception types for the same handful of
conditions: expired auth, geo-block, entitlement denial, content removed,
rate limits, server faults, playback restrictions, catchup-required items.
Downstream code (operations layer, Kodi plugin, UI) then has to special-case
per provider.

This module provides one hierarchy that all providers can subclass. Providers
MAY keep their own exception class names (existing callers can still catch
those); the only requirement is that the provider's classes inherit from the
appropriate base here.

This is a *convention*, not a mechanical enforcement. Nothing prevents a
provider from raising a bare Exception. But if a provider raises from this
hierarchy, callers get uniform handling for free.

Usage in a provider:

    from ...base.errors import AuthError, GeoBlockError

    class MyVodAuthError(AuthError): ...
    class MyVodGeoBlockError(GeoBlockError): ...

Usage in a caller:

    from ...base.errors import AuthError, GeoBlockError, ProviderError

    try:
        manifest = provider.get_manifest(content_id)
    except AuthError:
        ...    # refresh credentials / prompt for re-login
    except GeoBlockError:
        ...    # not available in your region
    except ProviderError as e:
        ...    # generic fallback; e.code may carry a provider-specific code

Error codes
-----------
Some providers (Discovery+) emit machine-readable codes alongside the
exception type. This base supports an optional `code` attribute. Providers
that don't use codes leave it None.
"""

from __future__ import annotations

import email.utils
import math
from datetime import datetime, timezone
from typing import Any, Optional, Tuple


class ProviderError(Exception):
    """
    Base class for all provider errors.

    Every subclass accepts (message, *, status=None, url=None, code=None) and
    stores them as attributes so callers can inspect without re-parsing the
    message string.

    Note on pickling / copy.deepcopy:
        Subclasses are allowed to have different __init__ signatures
        (e.g. ChannelNotFoundError(channel_id)) and to carry extra payload
        attributes. __reduce__ below reconstructs via __new__ and restores
        __dict__ as state, so it works regardless of the subclass's
        constructor shape and preserves every attribute.
    """

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        url: Optional[str] = None,
        code: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.url = url
        self.code = code

    def __repr__(self) -> str:
        msg = self.args[0] if self.args else ""
        parts = [self.__class__.__name__, f"({msg!r}"]
        if self.status is not None:
            parts.append(f", status={self.status}")
        if self.code is not None:
            parts.append(f", code={self.code!r}")
        parts.append(")")
        return "".join(parts)

    def __reduce__(self) -> Tuple[Any, ...]:
        """
        Preserve ALL attributes across pickle / copy.deepcopy.

        Returns a 3-tuple (callable, args, state). The annotation is
        Tuple[Any, ...] because __reduce__ can return a 2-tuple or a
        3-tuple depending on whether state is provided; the base
        object.__reduce__ signature reflects this.

        Exception.__reduce__ uses args only, which drops keyword-only fields
        (status, url, code) and any subclass payload. Reconstruction goes
        through __new__ so the subclass's __init__ is not called -- this
        means subclass constructors with different signatures (e.g.
        PlaybackRestrictedException(reason, error_code)) work fine, and
        __dict__ is restored as-is.
        """
        return (
            _rebuild_provider_error,
            (self.__class__, self.args),
            self.__dict__.copy(),
        )


def _rebuild_provider_error(
    cls: type, args: Tuple
) -> "ProviderError":
    """
    Reconstruction helper for ProviderError.__reduce__.

    Deliberately does not call cls(...). Creates a bare instance and sets
    args; pickle then restores __dict__ as state, so every attribute the
    original had comes back regardless of the subclass constructor.
    """
    exc = cls.__new__(cls)
    exc.args = tuple(args)
    return exc


# ---------------------------------------------------------------------------
# Auth / session
# ---------------------------------------------------------------------------

class AuthError(ProviderError):
    """401-style failure: token expired, invalid, or missing."""


class CredentialsError(AuthError):
    """Invalid username/password (as opposed to a stale token)."""


class SessionExpiredError(AuthError):
    """Server-side session is gone; a full re-login is required."""


class AuthPendingError(AuthError):
    """
    An interactive login (QR / device code) has been started and is waiting
    for the user. Not a failure: the caller should show the code and retry.

    Subclasses AuthError so generic "needs login" handling still applies;
    HTTP layers should check for it first and answer 202 with the payload.

    Attributes:
        login_code:        short code for manual entry
        qr_target_url:     URL to encode in a QR code (may be None)
        remaining_seconds: time left before the code expires
        retry_after:       suggested seconds before the caller retries
    """

    def __init__(
        self,
        message: str = "Interactive login pending",
        *,
        login_code: Optional[str] = None,
        qr_target_url: Optional[str] = None,
        remaining_seconds: Optional[int] = None,
        retry_after: Optional[int] = None,
        status: Optional[int] = None,
        url: Optional[str] = None,
        code: Optional[str] = None,
    ) -> None:
        super().__init__(message, status=status, url=url, code=code)
        self.login_code = login_code
        self.qr_target_url = qr_target_url
        self.remaining_seconds = remaining_seconds
        self.retry_after = retry_after


# ---------------------------------------------------------------------------
# Access control
# ---------------------------------------------------------------------------

class GeoBlockError(ProviderError):
    """Content is not available in the caller's region."""


class EntitlementError(ProviderError):
    """Authenticated, but not entitled to this content."""


class AccountRestrictedError(EntitlementError):
    """Account-level gate (e.g. VOD disabled for the whole account)."""


class PlaybackRestrictedError(ProviderError):
    """Playback is refused for a reason not covered above."""


# ---------------------------------------------------------------------------
# Content lookup
# ---------------------------------------------------------------------------

class NotFoundError(ProviderError):
    """Content is known to the provider but has been removed.

    At the manager top level, "this manager doesn't handle that content_id"
    is signalled by returning None/[] -- not by raising NotFoundError. See
    the "None vs exception" section in providers/_template/README.md.

    NotFoundError is for the case where the provider *knows* the content
    belongs in its domain but has been removed (e.g. a VOD detail fetch
    returns 404 for an id that was recently listed). The orchestrator's
    router will try other managers, then re-raise this if nobody resolves.
    """


class ItemNotFoundError(NotFoundError, KeyError):
    """A user-scoped item (recording, favorite, bookmark) does not exist.

    Raised by delete_recording / remove_favorite / delete_bookmark when the
    id is not currently stored. It is deliberately BOTH a NotFoundError
    (uniform ProviderError handling) and a KeyError (the pre-existing
    convention documented on the Provider*Mixin classes), so callers can
    migrate from ``except KeyError`` to ``except ItemNotFoundError`` at
    their own pace. Do not confuse with "this manager doesn't handle that
    content_id", which is a None / [] return value.
    """

    def __str__(self) -> str:
        # KeyError.__str__ would repr() the message (extra quotes).
        if len(self.args) == 1:
            return str(self.args[0])
        return Exception.__str__(self)


class BadRequestError(ProviderError):
    """400 -- the request was malformed for the endpoint called.

    Used as a routing signal by providers that guess endpoint shape from an
    opaque content_id (e.g. Magenta's page-vs-component dispatch). The
    orchestrator's router does NOT swallow this -- providers that need that
    behavior override handles_content_id() instead.
    """


# ---------------------------------------------------------------------------
# Transport / server
# ---------------------------------------------------------------------------

class RateLimitError(ProviderError):
    """429 -- caller should back off and retry.

    ``retry_after`` is the server's Retry-After hint in seconds (already
    capped by parse_retry_after), or None when the server sent none. It is a
    class attribute default so provider subclasses with their own __init__
    (e.g. a WAF-block exception) still have the attribute.
    """

    retry_after: Optional[float] = None

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        url: Optional[str] = None,
        code: Optional[str] = None,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message, status=status, url=url, code=code)
        self.retry_after = retry_after


class ServerError(ProviderError):
    """5xx -- retryable."""


class TransportError(ServerError):
    """Connection-level failure (DNS, TLS, timeout) -- no HTTP status.

    Deliberately a ServerError: the error contract (README section 8) maps
    "network down" to ServerError and says retry loops retry only
    ServerError/untyped errors. As a sibling instead of a subclass, a
    TransportError would have escaped every such retry loop.
    """


# ---------------------------------------------------------------------------
# Flow control
# ---------------------------------------------------------------------------

class CatchupRequiredError(ProviderError):
    """This 'VOD' item is actually a catch-up entry from a linear channel."""


class NotImplementedYetError(ProviderError):
    """Feature captured but not yet wired up."""


class UnsupportedOperationError(NotImplementedYetError):
    """The provider does not support this operation (and will not).

    Distinct in meaning from NotImplementedYetError ("planned, not done").
    Subclasses it so existing handlers keep working. Prefer checking the
    capability flag (e.g. RecordingsManager.supports_scheduling) before
    calling, and treat this as the safety net.
    """


class ConfigurationError(ProviderError):
    """Provider is misconfigured."""


class OperationFailedError(ProviderError, RuntimeError):
    """A write operation was rejected or failed on the provider backend.

    Raised by add_favorite / remove_favorite / update_bookmark /
    delete_bookmark / delete_recording on backend refusal or failure. Also a
    RuntimeError so existing ``except RuntimeError`` handlers keep working.
    Prefer a more specific subclass of ProviderError (ServerError,
    EntitlementError, ...) when the cause is known.
    """


# ---------------------------------------------------------------------------
# HTTP status -> error class mapping
# ---------------------------------------------------------------------------

def parse_retry_after(
    value: Any, *, max_seconds: float = 300.0
) -> Optional[float]:
    """
    Parse a Retry-After header (delta-seconds or HTTP-date) into seconds.

    Returns None when the value is missing or unparseable. Negative values
    (a date in the past) become 0.0; results are capped at ``max_seconds`` so
    a hostile or buggy header cannot park a worker thread for hours.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        seconds = float(text)
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(text)
        except (TypeError, ValueError):
            return None
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        seconds = (when - datetime.now(timezone.utc)).total_seconds()
    if math.isnan(seconds):
        return None
    return min(max(seconds, 0.0), max_seconds)


_GEO_MARKERS = ("geo", "region")
_WAF_MARKERS = (
    "captcha",
    "cf-chl",
    "just a moment",
    "attention required",
    "cloudflare",
)


def default_error_for_status_heuristic(
    status: int,
    message: str,
    *,
    url: Optional[str] = None,
    body_snippet: str = "",
    retry_after: Optional[float] = None,
) -> ProviderError:
    """
    Heuristic mapping from HTTP status to ProviderError subclass.

    This is a heuristic, not a contract. Providers with their own error
    classification should construct the specific error directly rather than
    relying on this. The 403 branch in particular uses substring matches on
    body_snippet and is intentionally shallow so providers do not depend on
    it accidentally.

    403 order: geo markers first (a Cloudflare "country or region" block is
    permanent), then WAF/CAPTCHA markers (transient -> RateLimitError, as the
    README error contract requires), else EntitlementError.
    """
    if status == 400:
        return BadRequestError(message, status=status, url=url)
    if status == 401:
        return AuthError(message, status=status, url=url)
    if status == 402:
        return EntitlementError(message, status=status, url=url)
    if status == 403:
        lower = body_snippet.lower()
        if any(marker in lower for marker in _GEO_MARKERS):
            return GeoBlockError(message, status=status, url=url)
        if any(marker in lower for marker in _WAF_MARKERS):
            return RateLimitError(
                message, status=status, url=url, retry_after=retry_after
            )
        return EntitlementError(message, status=status, url=url)
    if status in (404, 410):
        return NotFoundError(message, status=status, url=url)
    if status == 429:
        return RateLimitError(
            message, status=status, url=url, retry_after=retry_after
        )
    if status == 451:
        return GeoBlockError(message, status=status, url=url)
    if 500 <= status < 600:
        return ServerError(message, status=status, url=url)
    return ProviderError(message, status=status, url=url)


def error_from_response(
    response: Any, message: Optional[str] = None, *, body_limit: int = 500
) -> ProviderError:
    """
    Build a ProviderError from any response-like object (requests or
    curl_cffi): needs ``status_code``; uses ``url``, ``reason``, ``headers``
    and ``text`` when present. Applies default_error_for_status_heuristic and
    fills ``retry_after`` from the Retry-After header.
    """
    try:
        status = int(getattr(response, "status_code", 0) or 0)
    except (TypeError, ValueError):
        status = 0
    raw_url = getattr(response, "url", None)
    url = str(raw_url) if raw_url else None

    try:
        snippet = (response.text or "")[:body_limit]
    except Exception:
        snippet = ""

    headers = getattr(response, "headers", None)
    raw_retry = headers.get("Retry-After") if hasattr(headers, "get") else None
    retry_after = parse_retry_after(raw_retry)

    if message is None:
        reason = getattr(response, "reason", None) or ""
        message = f"HTTP {status} {reason}".strip()
        if url:
            message += f" for {url}"

    return default_error_for_status_heuristic(
        status, message, url=url, body_snippet=snippet, retry_after=retry_after
    )


def error_from_exception(exc: BaseException, *, body_limit: int = 500) -> ProviderError:
    """
    Convert an HTTP-layer exception into a ProviderError.

    * already a ProviderError            -> returned unchanged
    * has a non-None ``.response``       -> error_from_response()
    * no response (timeout, DNS, proxy)  -> TransportError

    Only pass exceptions raised by the HTTP layer (HTTPManager raises
    requests exceptions on both of its backends). Usage::

        try:
            resp = http.get(url, operation="api")
        except Exception as exc:
            raise error_from_exception(exc) from exc
    """
    if isinstance(exc, ProviderError):
        return exc
    response = getattr(exc, "response", None)
    if response is not None:  # NOT `if response`: a 4xx/5xx Response is falsy
        return error_from_response(response, body_limit=body_limit)
    return TransportError(str(exc) or exc.__class__.__name__)