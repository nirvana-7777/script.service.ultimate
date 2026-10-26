# streaming_providers/providers/movetv/api.py
"""
Shared request helpers of the move.tv provider (module functions, no state
except SourceCache): one authenticated POST with ONE 401 recovery, and the
live/catchup "source" fetch with its Play-Auth cache.

Error handling (README §8):
  * typed ProviderErrors propagate unchanged and are never retried;
  * the HTTP manager's 4xx/5xx behaviour is not verified, so BOTH a returned
    error response and an exception carrying `.response` are handled;
  * everything unexpected becomes ServerError.
"""

import re
import threading
import time
from collections import OrderedDict
from typing import Any, Callable, Dict, Optional, Tuple

from ...base.errors import ProviderError, ServerError, default_error_for_status_heuristic
from ...base.utils.logger import logger
from .constants import MoveTVConfig

# (content_url, play_auth_header_value, expires_at_epoch_seconds)
SourceInfo = Tuple[str, str, float]

_PLAY_AUTH_EXPIRY_RE = re.compile(MoveTVConfig.PLAY_AUTH_EXPIRY_PATTERN)


class SourceCache:
    """Thread-safe LRU cache for source URLs + Play-Auth values.

    Keyed by content_id (live), "<content_id>:<epg_id>" (catchup) and by the
    content_url itself (so segment/manifest header lookups can find the entry
    from the URL alone).
    """

    def __init__(self, max_size: int = MoveTVConfig.SOURCE_CACHE_SIZE):
        self._cache: "OrderedDict[str, SourceInfo]" = OrderedDict()
        self._lock = threading.Lock()
        self._max_size = max_size

    def get(self, key: str) -> Optional[SourceInfo]:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
            return None

    def set(self, key: str, value: SourceInfo) -> None:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = value
            if len(self._cache) > self._max_size:
                self._cache.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


def is_fresh(entry: Optional[SourceInfo]) -> bool:
    """A cached source is usable while its Play-Auth expiry is > buffer away.
    An entry without a parsed expiry (0.0) is never reused (as in v1)."""
    if not entry:
        return False
    expires_at = entry[2]
    return bool(expires_at) and time.time() < (expires_at - MoveTVConfig.PLAY_AUTH_EARLY_EXPIRY_SECONDS)


def parse_play_auth_expiry(header_value: str) -> float:
    if not header_value:
        return 0.0
    match = _PLAY_AUTH_EXPIRY_RE.search(header_value)
    if match:
        return float(match.group(1))
    logger.warning("move.tv: could not parse expiry from X-Play-Auth")
    return 0.0


def _status_of_response(response: Any) -> Optional[int]:
    status = getattr(response, "status_code", None)
    return status if isinstance(status, int) else None


def _status_of_exception(exc: BaseException) -> Optional[int]:
    return _status_of_response(getattr(exc, "response", None))


def api_post(
    http_manager: Any,
    session: Any,
    url: str,
    build_payload: Callable[[Dict[str, Any]], Dict[str, Any]],
    *,
    what: str,
    operation: str = "api",
    need_profile: bool = True,
) -> Dict[str, Any]:
    """
    POST an authenticated JSON request and return the parsed body (a dict).

    `build_payload(session_info)` is called for every attempt, so ids that
    change after a token refresh are picked up. A 401 triggers exactly ONE
    `session.recover()` (refresh token, else full login) and one retry; a second
    401 raises AuthError. Nothing else is retried.
    """
    response: Any = None
    for attempt in (1, 2):
        info = session.info(need_profile=need_profile)   # raises typed AuthError & co.
        headers = MoveTVConfig.get_api_headers(info["auth_token"], dev_id=info.get("uid"))
        try:
            response = http_manager.post(
                url, operation=operation, json=build_payload(info), headers=headers
            )
            status = _status_of_response(response)
        except ProviderError:
            raise
        except Exception as exc:                     # HTTP manager may raise on 4xx/5xx
            status = _status_of_exception(exc)
            if status is None:
                raise ServerError(f"move.tv: {what} failed: {exc}", url=url) from exc
            response = exc.response                  # type: ignore[attr-defined]
        if status == 401 and attempt == 1:
            logger.info(f"move.tv: 401 on {what} -- recovering the session")
            session.recover()
            continue
        if status is not None and status >= 400:
            raise default_error_for_status_heuristic(
                status, f"move.tv: {what} failed (HTTP {status})", url=url
            )
        break
    try:
        data = response.json()
    except Exception as exc:
        raise ServerError(f"move.tv: {what}: invalid JSON response: {exc}", url=url) from exc
    if not isinstance(data, dict):
        raise ServerError(f"move.tv: {what}: unexpected response body", url=url)
    return data


def fetch_source(
    *,
    http_manager: Any,
    session: Any,
    cache: SourceCache,
    url: str,
    build_payload: Callable[[], Dict[str, Any]],
    cache_key: str,
    operation: str,
    what: str,
) -> Optional[SourceInfo]:
    """
    Fetch a live or catchup source (manifest URL + Play-Auth header value).

    Returns None when the API answers success=false or without a URL ("no
    such source"); typed errors propagate. The result is cached under
    `cache_key` and under the URL itself.
    """
    cached = cache.get(cache_key)
    if is_fresh(cached):
        logger.debug(f"move.tv: cache hit for {what} (key={cache_key})")
        return cached

    def payload(info: Dict[str, Any]) -> Dict[str, Any]:
        body = dict(build_payload())
        body["customerId"] = info["customer_id"]
        body["customerProfileId"] = info["customer_profile_id"]
        body["appVersion"] = MoveTVConfig.APP_VERSION
        body["dtype"] = MoveTVConfig.DTYPE_DASH
        return body

    data = api_post(http_manager, session, url, payload, what=what, operation=operation)
    if not data.get("success"):
        logger.warning(f"move.tv: {what}: source endpoint returned success=false")
        return None
    content_url = data.get("content_url")
    if not content_url:
        logger.warning(f"move.tv: {what}: response without content_url")
        return None
    header_value = (data.get("protection") or {}).get("headerValue", "") or ""
    entry: SourceInfo = (content_url, header_value, parse_play_auth_expiry(header_value))
    cache.set(cache_key, entry)
    cache.set(content_url, entry)
    logger.info(f"move.tv: fetched {what}: {content_url}")
    return entry