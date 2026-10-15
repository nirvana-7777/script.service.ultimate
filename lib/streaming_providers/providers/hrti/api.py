# streaming_providers/providers/hrti/api.py
"""
Shared API-call helper for the HRTi managers (one place for the error
contract instead of a try/except in every method).

  * endpoint URL from the lazily loaded dynamic config
  * authorization/device headers from the session (a fresh token per request)
  * transport / HTTP-status errors become typed errors (base.errors);
    works whether the HTTP manager raises or returns the response
  * HTTP 401 / AuthError  -> ONE session refresh + exactly one retry
  * API body ``ErrorCode != 0``: raises ServerError for required endpoints,
    returns None for optional ones (``required=False``)
"""

import json
from typing import Any, Dict, Optional

from ...base.errors import (
    AuthError,
    ProviderError,
    ServerError,
    TransportError,
    default_error_for_status_heuristic,
)
from ...base.utils.logger import logger
from .constants import HRTiConfig


def _snippet(response: Any) -> str:
    try:
        return (response.text or "")[:200]
    except Exception:  # response object without text
        return ""


def typed_error_for(exc: BaseException, url: Optional[str] = None) -> ProviderError:
    """Typed error for an exception raised by the HTTP layer: an exception that
    carries a response is mapped by its status, anything else is a transport
    fault."""
    failed = getattr(exc, "response", None)
    status = getattr(failed, "status_code", None)
    if isinstance(status, int):
        return default_error_for_status_heuristic(
            status, f"HRTi HTTP {status}: {exc}", url=url, body_snippet=_snippet(failed)
        )
    return TransportError(f"HRTi request failed: {exc}", url=url)


def _post_json(http_manager: Any, url: str, headers: Dict[str, str], payload: Dict) -> Dict:
    try:
        response = http_manager.post(
            url, operation="api", headers=headers, data=json.dumps(payload)
        )
    except ProviderError:
        raise
    except Exception as exc:  # HTTP manager raising for 4xx/5xx or transport faults
        raise typed_error_for(exc, url) from exc

    status = getattr(response, "status_code", None)
    if isinstance(status, int) and status >= 400:
        raise default_error_for_status_heuristic(
            status, f"HRTi HTTP {status}", url=url, body_snippet=_snippet(response)
        )
    try:
        data = response.json()
    except ValueError as exc:
        raise ServerError("HRTi: response is not valid JSON", url=url) from exc
    if not isinstance(data, dict):
        raise ServerError("HRTi: unexpected response shape", url=url)
    return data


def api_post(
    *,
    http_manager: Any,
    session: Any,
    config: HRTiConfig,
    endpoint_key: str,
    payload: Dict,
    referer_path: str = "/",
    required: bool = True,
) -> Optional[Any]:
    """POST to a named endpoint and return the ``Result`` field."""
    url = config.endpoint(endpoint_key)
    data: Dict = {}
    for attempt in (1, 2):
        # Token and device state are read OUTSIDE the try: a login failure is
        # already a typed error and must not trigger the 401 recovery.
        headers = config.api_headers(
            token=session.get_access_token(),
            device_id=session.device_id,
            ip_address=session.ip_address,
            referer_path=referer_path,
        )
        try:
            data = _post_json(http_manager, url, headers, payload)
            break
        except AuthError:
            if attempt == 1:
                logger.info(f"HRTi: {endpoint_key} answered 401, refreshing the session once")
                session.refresh()
                continue
            raise

    code = data.get("ErrorCode", 0)
    if code not in (0, None):
        description = data.get("ErrorDescription")
        if required:
            raise ServerError(
                f"HRTi API error for {endpoint_key}: [{code}] {description}",
                url=url,
                code=str(code),
            )
        logger.debug(f"HRTi optional endpoint {endpoint_key}: [{code}] {description}")
        return None
    return data.get("Result")
