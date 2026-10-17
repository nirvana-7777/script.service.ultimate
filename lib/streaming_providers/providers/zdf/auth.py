# streaming_providers/providers/zdf/auth.py
"""
ZDF auth -- Variant A (README §9), degenerate on purpose.

ZDF live TV needs no user account: the API only wants the public web-client
bearer tokens (constants.py / config override). There is nothing to log in to,
nothing to refresh and nothing persisted, so no lock, no expiry and no
retry/backoff exist here. If ZDF ever rotates the tokens, the symptom is an
HTTP 401/403 from the HTTP manager; the fix is a config override.

Satisfies AuthProtocol: get_access_token() / build_headers() / invalidate().
"""

from typing import Any, Dict


class ZdfAuth:
    def __init__(self, *, config: Any):
        self._config = config

    def get_access_token(self) -> str:
        return self._config.api_token

    def build_headers(self) -> Dict[str, str]:
        """Default API headers (GraphQL POST)."""
        return self._config.graphql_headers()

    def build_list_headers(self) -> Dict[str, str]:
        """Persisted-query GET: it uses its own client token and app id."""
        return self._config.list_headers()

    def build_ptmd_headers(self) -> Dict[str, str]:
        return self._config.ptmd_headers()

    def invalidate(self) -> None:
        """Static public tokens: nothing in memory or in storage to clear."""
        return None
