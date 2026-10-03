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
    """429 -- caller should back off and retry."""


class ServerError(ProviderError):
    """5xx -- retryable."""


class TransportError(ProviderError):
    """Connection-level failure (DNS, TLS, timeout) -- no HTTP status."""


# ---------------------------------------------------------------------------
# Flow control
# ---------------------------------------------------------------------------

class CatchupRequiredError(ProviderError):
    """This 'VOD' item is actually a catch-up entry from a linear channel."""


class NotImplementedYetError(ProviderError):
    """Feature captured but not yet wired up."""


class ConfigurationError(ProviderError):
    """Provider is misconfigured."""


# ---------------------------------------------------------------------------
# HTTP status -> error class heuristic
# ---------------------------------------------------------------------------

def default_error_for_status_heuristic(
    status: int,
    message: str,
    *,
    url: Optional[str] = None,
    body_snippet: str = "",
) -> ProviderError:
    """
    Heuristic mapping from HTTP status to ProviderError subclass.

    This is a heuristic, not a contract. Providers with their own error
    classification should construct the specific error directly rather than
    relying on this. The 403 branch in particular uses a substring match on
    body_snippet and is intentionally shallow so providers do not depend on
    it accidentally.
    """
    if status == 400:
        return BadRequestError(message, status=status, url=url)
    if status == 401:
        return AuthError(message, status=status, url=url)
    if status == 403:
        lower = body_snippet.lower()
        if "geo" in lower or "region" in lower:
            return GeoBlockError(message, status=status, url=url)
        return EntitlementError(message, status=status, url=url)
    if status == 404:
        return NotFoundError(message, status=status, url=url)
    if status == 429:
        return RateLimitError(message, status=status, url=url)
    if 500 <= status < 600:
        return ServerError(message, status=status, url=url)
    return ProviderError(message, status=status, url=url)