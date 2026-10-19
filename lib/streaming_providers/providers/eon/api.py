# streaming_providers/providers/eon/api.py
"""
Authenticated JSON access to the Eon API with the 401 recovery ladder.

One place owns "call, on 401 recover the session once, retry once": managers
never write their own retry. Everything else is mapped to typed errors via
base.errors.error_from_exception.
"""

from typing import Any, Dict, Optional

from requests.exceptions import HTTPError

from ...base.errors import ProviderError, ServerError, error_from_exception
from .constants import EonConfig, EonDefaults
from .bootstrap import EonEndpoints

_PROVIDER = EonDefaults.PROVIDER_LABEL


class EonApi:
    def __init__(self, *, http_manager: Any, auth: Any, endpoints: EonEndpoints, config: EonConfig):
        self._http = http_manager
        self._auth = auth
        self._endpoints = endpoints
        self._config = config

    def get_json(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
        operation: str = "api",
    ) -> Any:
        url = self._endpoints.url(path)
        for attempt in (1, 2):
            token = self._auth.get_access_token()
            headers = {**self._config.bearer_headers(token), **(extra_headers or {})}
            try:
                resp = self._http.get(url, params=params, headers=headers, operation=operation)
                return resp.json()
            except ProviderError:
                raise
            except HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status == 401 and attempt == 1:
                    self._auth.recover(token)
                    continue
                raise error_from_exception(exc) from exc
            except ValueError as exc:   # body is not JSON
                raise ServerError(f"{_PROVIDER}: non-JSON response from {path}") from exc
            except Exception as exc:
                raise error_from_exception(exc) from exc
        raise ServerError(f"{_PROVIDER}: unreachable")  # pragma: no cover

    def server_time(self) -> str:
        """Server clock in ms, as the string the CDN payload expects."""
        data = self.get_json(EonDefaults.PATH_TIME)
        value = data.get("time") if isinstance(data, dict) else None
        if not value:
            raise ServerError(f"{_PROVIDER}: time response has no `time`")
        return str(value)