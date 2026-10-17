# streaming_providers/providers/zdf/auth.py
"""
ZDF auth -- Variant A (README §9): lazy, no network in __init__.

ZDF live TV needs no user account. The API wants two expiring, public client
tokens of the web player, which the start page embeds in its Next.js flight
data (`videoToken` for GraphQL POST + PTMD, `appToken` for the channel list).

Behaviour:
  * tokens are fetched on first use and cached with their expiry; they are
    renewed TOKEN_REFRESH_BUFFER_SECONDS before they run out. One lock makes
    concurrent callers share a single fetch.
  * if the page fetch or parse fails, the static fallback tokens of the config
    are used and no new fetch is tried for TOKEN_FETCH_BACKOFF_SECONDS (no
    request storm while zdf.de is down or its page layout changed).
  * `refresh_after_rejection()` is the one-shot recovery for a request the API
    refused: drop the cache, fetch again, and say whether the tokens changed.
    The manager retries exactly once, and only if they did.

Satisfies AuthProtocol: get_access_token() / build_headers() / invalidate().
Tokens are never logged.
"""

import threading
import time
from typing import Any, Dict, Tuple

from ...base.utils.logger import logger
from .constants import ZdfDefaults
from .models import parse_flight_tokens


class ZdfAuth:
    def __init__(self, *, http_manager: Any, config: Any):
        self._http = http_manager
        self._config = config
        self._lock = threading.RLock()
        self._tokens: Dict[str, Tuple[str, float]] = {}   # kind -> (token, expires_at)
        self._retry_after = 0.0

    # ------------------------------------------------------------------
    # Token handling
    # ------------------------------------------------------------------
    def _is_fresh(self, kind: str) -> bool:
        entry = self._tokens.get(kind)
        return bool(entry) and entry[1] - time.time() > ZdfDefaults.TOKEN_REFRESH_BUFFER_SECONDS

    def _fetch_tokens(self) -> None:
        resp = self._http.get(
            ZdfDefaults.WEB_URL,
            headers=self._config.page_headers(),
            operation="api",
        )
        tokens = parse_flight_tokens(resp.text)
        if not tokens:
            raise ValueError("no videoToken / appToken found in the zdf.de page")
        self._tokens.update(tokens)

    def _token(self, kind: str) -> str:
        with self._lock:
            if self._is_fresh(kind):
                return self._tokens[kind][0]
            now = time.time()
            if now >= self._retry_after:
                try:
                    self._fetch_tokens()
                except Exception as exc:       # network, parse, anything: fall back
                    self._retry_after = now + ZdfDefaults.TOKEN_FETCH_BACKOFF_SECONDS
                    logger.warning(
                        f"{ZdfDefaults.PROVIDER_LABEL}: token fetch failed, "
                        f"using fallback tokens: {exc!r}"
                    )
            if self._is_fresh(kind):
                return self._tokens[kind][0]
            if kind == ZdfDefaults.TOKEN_KIND_LIST:
                return self._config.list_token
            return self._config.api_token

    def get_access_token(self) -> str:
        """The videoToken (GraphQL POST and PTMD)."""
        return self._token(ZdfDefaults.TOKEN_KIND_API)

    def invalidate(self) -> None:
        """Drop cached tokens (and the fetch back-off); the next use refetches."""
        with self._lock:
            self._tokens.clear()
            self._retry_after = 0.0

    def refresh_after_rejection(self) -> bool:
        """
        Called after the API refused a request. Refetch and report whether
        either token actually changed (False = retrying would be pointless).
        """
        with self._lock:
            before = (self.get_access_token(), self._token(ZdfDefaults.TOKEN_KIND_LIST))
            self.invalidate()
            after = (self.get_access_token(), self._token(ZdfDefaults.TOKEN_KIND_LIST))
            return before != after

    # ------------------------------------------------------------------
    # Headers
    # ------------------------------------------------------------------
    def build_headers(self) -> Dict[str, str]:
        """Default API headers (GraphQL POST)."""
        return self._config.graphql_headers(self.get_access_token())

    def build_list_headers(self) -> Dict[str, str]:
        """Persisted-query GET: appToken + app id."""
        return self._config.list_headers(self._token(ZdfDefaults.TOKEN_KIND_LIST))

    def build_ptmd_headers(self) -> Dict[str, str]:
        return self._config.ptmd_headers(self.get_access_token())
