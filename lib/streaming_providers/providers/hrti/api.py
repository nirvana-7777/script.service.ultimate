# streaming_providers/providers/hrti/api.py
"""
Shared API-call helper for the HRTi managers (one place for the error
contract instead of a try/except in every method).

  * endpoint URL from the lazily loaded dynamic config
  * authorization/device headers from the session (a fresh token per request)
  * transport / HTTP-status errors become typed errors (base.errors);
    works whether the HTTP manager raises or returns the response
  * HTTP 401 / AuthError  -> ONE session refresh + exactly one retry
  * body ErrorCode == 4 (the server no longer knows this device session --
    typically a device id loaded from persisted storage that the server has
    since expired) -> ONE device re-registration through the session + ONE
    retry; a request that STILL answers ErrorCode 4 raises AuthError, also
    for optional endpoints (a broken session is not "nothing there")
  * other API body ``ErrorCode != 0``: raises ServerError for required
    endpoints, returns None for optional ones (``required=False``)

Worst case per call: 4 requests, 2 session refreshes, 1 device
re-registration. The state change lives in the session
(reregister_device), which locks and re-checks -- concurrent callers that
all fail with the same stale device id must not stampede RegisterDevice.
"""

import json
from typing import Any, Dict, Optional, Tuple

from ...base.errors import (
    AuthError,
    ProviderError,
    ServerError,
    TransportError,
    default_error_for_status_heuristic,
)
from ...base.utils.logger import logger
from .constants import HRTiConfig

#: Body-level error code: the server no longer knows this device session.
#: Observed with a device id loaded from persisted storage after the
#: server-side registration had expired. Recoverable exactly once per call
#: (see api_post); a surviving ErrorCode 4 is an AuthError.
DEVICE_SESSION_INVALID_CODE = 4


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


def _post_with_auth_recovery(
    *,
    http_manager: Any,
    session: Any,
    config: HRTiConfig,
    url: str,
    endpoint_key: str,
    payload: Dict,
    referer_path: str,
) -> Tuple[Dict, Optional[str]]:
    """POST + parse with ONE session refresh on HTTP 401 / AuthError.

    Returns ``(parsed body, device id used for the request that produced
    it)``. The device id is captured at header-build time (token first, then
    device id -- v1 evaluation order) so the ErrorCode-4 recovery can hand
    the session the id that actually failed (concurrency re-check in
    HRTiSession.reregister_device).
    """
    data: Dict = {}
    device_id: Optional[str] = None
    for attempt in (1, 2):
        # Token and device state are read OUTSIDE the try: a login failure is
        # already a typed error and must not trigger the 401 recovery.
        token = session.get_access_token()
        device_id = session.device_id
        headers = config.api_headers(
            token=token,
            device_id=device_id,
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
    return data, device_id


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
    """POST to a named endpoint and return the ``Result`` field.

    Recovery ladder, each step at most ONCE per call:
      1. HTTP 401 / AuthError -> session.refresh() + one retry
      2. body ErrorCode == 4  -> session.reregister_device() + one retry
         (the retry runs through step 1 again, so a token that died together
         with the old device registration is refreshed there)

    A failure DURING recovery (re-registration or the retry request) raises
    its typed error and propagates. ErrorCode 4 that survives the
    re-registration raises AuthError -- for optional endpoints too: with the
    old code a stale device id silently emptied EPG and every other optional
    endpoint. All other ErrorCode != 0 follow the required/optional rule.
    """
    url = config.endpoint(endpoint_key)

    data, device_id_used = _post_with_auth_recovery(
        http_manager=http_manager,
        session=session,
        config=config,
        url=url,
        endpoint_key=endpoint_key,
        payload=payload,
        referer_path=referer_path,
    )

    if data.get("ErrorCode") == DEVICE_SESSION_INVALID_CODE:
        logger.warning(
            f"HRTi: {endpoint_key} answered ErrorCode {DEVICE_SESSION_INVALID_CODE} "
            f"(invalid device/session) for device id {device_id_used!r}; "
            f"re-registering the device once"
        )
        session.reregister_device(failed_device_id=device_id_used)
        data, _ = _post_with_auth_recovery(
            http_manager=http_manager,
            session=session,
            config=config,
            url=url,
            endpoint_key=endpoint_key,
            payload=payload,
            referer_path=referer_path,
        )
        if data.get("ErrorCode") == DEVICE_SESSION_INVALID_CODE:
            # NOTE: constructor kwargs of base.errors are not fully verified
            # (README §8); add url= here too if AuthError supports it
            # (ServerError / TransportError do).
            raise AuthError(
                "HRTi: device session still invalid (ErrorCode "
                f"{DEVICE_SESSION_INVALID_CODE}) after re-registration"
            )

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