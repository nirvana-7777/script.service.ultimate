# streaming_providers/providers/joyn/entitlement.py
# -*- coding: utf-8 -*-
"""
Joyn entitlement helper — a dedicated collaborator, provider-owned, injected
into both the channel manager and the VOD manager (README §5.1: two consumers).

Error contract
--------------
PlaybackRestrictedException / SubscriptionRequiredException (both
JoynEntitlementError -> EntitlementError) are terminal and propagate. Any other
entitlement failure (no token, unparsable 400 body) raises JoynEntitlementError.
Transport failures propagate and are wrapped by transport_errors at the call
site in the manager.

How a 400 is detected
---------------------
README §8 states that the HTTP manager raises for 4xx/5xx itself; v1 code
assumed it *returns* a 400 response. Neither is verified for every transport, so
BOTH are handled: a returned 400 response, and an exception that carries a
`.response` with status 400. Either way the Joyn error body is parsed, so the
`-hd` variant probe in get_channel_entitlement_token keeps working.

Cache lifecycle
---------------
`_resolved_channel_variants` maps a caller-facing channel id to the id the
entitlement service accepts ("sat1-de" -> "sat1-de-hd"). It is a property of the
channel, not of the session, so it is not time-based — but it IS cleared on
credential change: JoynProvider._clear_caches() is registered as the session's
`on_invalidate` callback and calls clear() below.
"""

from typing import Any, Dict, List, Optional, Tuple

from ...base.errors import ServerError
from ...base.utils.logger import logger
from .constants import (
    CONTENT_TYPE_LIVE,
    DEFAULT_REQUEST_TIMEOUT,
    ERROR_CODES,
    JOYN_STREAMING_ENDPOINTS,
)
from .models import (
    JoynEntitlementError,
    PlaybackRestrictedException,
    SubscriptionRequiredException,
)


class JoynEntitlement:
    def __init__(self, *, http_manager, auth, config, cache: Optional[Dict] = None):
        self.http_manager = http_manager
        self.auth = auth
        self.config = config
        self._cache = cache if cache is not None else {}
        self._resolved_channel_variants: Dict[str, str] = self._cache.setdefault(
            "resolved_channel_variants", {}
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def clear(self) -> None:
        """Forget resolved channel variants (credentials changed).

        Clears the inner dict in place: clearing the provider-owned outer dict
        would orphan the reference held here.
        """
        self._resolved_channel_variants.clear()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_entitlement_token(
        self, content_id: str, content_type: str = CONTENT_TYPE_LIVE
    ) -> str:
        """
        Fetch an entitlement token for a single content id.

        Raises:
            PlaybackRestrictedException / SubscriptionRequiredException — rights
            JoynEntitlementError — missing token, unparsable error body
            ProviderError subclasses (AuthError, ...) propagate untouched
        """
        token = self.auth.get_access_token()
        headers = self.config.entitlement_headers(token)
        payload = {"content_id": content_id, "content_type": content_type}
        url = JOYN_STREAMING_ENDPOINTS["ENTITLEMENT"]

        try:
            response = self.http_manager.post(
                url,
                operation="auth",   # the "auth" proxy scope matches the entitlement service
                headers=headers,
                json_data=payload,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
        except Exception as exc:
            failed = getattr(exc, "response", None)
            if failed is not None and getattr(failed, "status_code", None) == 400:
                self._raise_from_400_body(content_id, failed)   # always raises
            raise

        status = response.status_code
        if status == 400:
            self._raise_from_400_body(content_id, response)     # always raises
        if status >= 400:
            logger.warning(
                f"Entitlement failed for {content_id} (type={content_type}): HTTP {status}"
            )
            raise ServerError(f"Entitlement HTTP {status} for {content_id}")

        data = response.json()
        # The reference client accepts either key; keep both.
        token = data.get("entitlement_token") or data.get("token")
        if not token:
            logger.warning(
                f"Entitlement response for {content_id} had no token "
                f"(keys={list(data.keys())})"
            )
            raise JoynEntitlementError(
                f"No entitlement_token in response for {content_id}"
            )
        return token

    def get_channel_entitlement_token(self, channel_id: str) -> Tuple[str, str]:
        """
        Resolve entitlement for a live channel, trying the `-hd` variant.

        Returns (resolved_channel_id, entitlement_token). The resolved id is what
        the playlist endpoint must be called with.

        Rights errors are terminal and propagate immediately — the same account
        would get the same answer on the other variant.
        """
        cached_resolved = self._resolved_channel_variants.get(channel_id)
        if cached_resolved:
            try:
                token = self.get_entitlement_token(cached_resolved, CONTENT_TYPE_LIVE)
                if token:
                    return cached_resolved, token
            except (PlaybackRestrictedException, SubscriptionRequiredException):
                raise
            except JoynEntitlementError:
                logger.debug(
                    f"Cached variant {cached_resolved} no longer resolves; re-probing"
                )
                self._resolved_channel_variants.pop(channel_id, None)

        candidates: List[str] = []
        if channel_id.endswith("-sd"):
            candidates.append(channel_id[:-3] + "-hd")
        elif not channel_id.endswith("-hd"):
            candidates.append(channel_id + "-hd")
        candidates.append(channel_id)

        last_error: Optional[Exception] = None
        for cid in candidates:
            try:
                token = self.get_entitlement_token(cid, CONTENT_TYPE_LIVE)
                if token:
                    self._resolved_channel_variants[channel_id] = cid
                    return cid, token
            except (PlaybackRestrictedException, SubscriptionRequiredException):
                raise
            except JoynEntitlementError as exc:
                last_error = exc
                continue

        raise last_error or JoynEntitlementError(
            f"No entitlement token for {channel_id} (tried {candidates})"
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _raise_from_400_body(content_id: str, response: Any) -> None:
        """Always raises. Joyn answers 400 with a JSON *list*; element 0 has code/msg."""
        try:
            body = response.json()
        except ValueError as exc:
            logger.warning(
                f"Entitlement 400 for {content_id}: failed to parse error body: {exc}"
            )
            raise JoynEntitlementError(
                f"Bad entitlement response for {content_id} (400), "
                f"failed to parse error: {exc}"
            ) from exc

        error = body[0] if isinstance(body, list) and body else None
        if not isinstance(error, dict):
            raise JoynEntitlementError(
                f"Bad entitlement response for {content_id} (400)"
            )

        code = error.get("code", "UNKNOWN")
        msg = error.get("msg", "No error message provided")
        if code == ERROR_CODES["PLAYBACK_RESTRICTED"]:
            raise PlaybackRestrictedException(
                f"Playback restricted for {content_id}: {msg}"
            )
        if code == ERROR_CODES["BUSINESS_MODEL_NOT_SUITABLE"]:
            raise SubscriptionRequiredException(
                f"Subscription required for {content_id} ({code}): {msg}"
            )
        raise JoynEntitlementError(f"Entitlement error for {content_id} ({code}): {msg}")