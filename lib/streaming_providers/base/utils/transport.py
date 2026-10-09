# streaming_providers/base/utils/transport.py
"""
transport_errors -- shared wrapper for provider network calls.

Wraps *unexpected* failures (network, bad JSON, malformed payloads) in
ServerError and lets typed provider errors (AuthError, RateLimitError,
GeoBlockError, ...) through untouched: callers rely on those to refresh
tokens or back off, so they must never be flattened into a generic error.

simpli keeps its own identical copy in providers/simpli/helpers.py until it
is switched over to this one.
"""

from contextlib import contextmanager

from ..errors import ProviderError, ServerError


@contextmanager
def transport_errors(what: str, provider: str = ""):
    try:
        yield
    except ProviderError:
        raise
    except Exception as e:
        prefix = f"{provider}: " if provider else ""
        raise ServerError(f"{prefix}{what} failed: {e}") from e
