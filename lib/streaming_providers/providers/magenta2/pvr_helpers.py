# streaming_providers/providers/magenta2/pvr_helpers.py
"""
Shared nPVR utility helpers for Magenta2.

Both RecordingsManager and TimersManager need the same low-level parsing and
mapping logic.  Keeping it here avoids duplication while keeping each manager
class focused on its own domain.

Public surface
--------------
    PvrHelpers          — static-method namespace (no state)
    PvrHttpMixin        — HTTP + auth plumbing shared by both managers
"""

import json
import re
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlencode  # NEW: for _log_request()

from .constants import PVR_ACCEPT_HEADER
from ...base.utils.logger import logger
from ...base.network import HTTPManager
from .config_models import ProviderConfig


# ---------------------------------------------------------------------------
# Upstream error handling
# ---------------------------------------------------------------------------

# Cap for an upstream error body written to the log.  Real nPVR error bodies are
# a few hundred bytes; the cap only guards against an upstream that answers
# with a full HTML error page.
_MAX_LOGGED_BODY_CHARS = 8192
# Cap for the fallback text used in the exception message / API response when
# the body is not a ThePlatform JSON error.
_MAX_SUMMARY_CHARS = 300


class NpvrApiError(RuntimeError):
    """
    A nPVR / ThePlatform request failed.

    Subclasses RuntimeError, so existing ``except RuntimeError`` handlers keep
    working.  The upstream error is kept in structured form so the route layer
    can hand it to the client instead of a generic message.

    ThePlatform error bodies look like::

        {"code": 403, "name": "Forbidden Error",
         "details": "Recording is not allowed on this event",
         "correlationId": "<session>::<call>"}
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        error_name: Optional[str] = None,
        details: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.error_name = error_name
        self.details = details
        self.correlation_id = correlation_id

    @property
    def upstream(self) -> Dict[str, object]:
        """Structured upstream error for API responses (empty for transport errors)."""
        data = {
            "status": self.status_code,
            "name": self.error_name,
            "details": self.details,
            "correlation_id": self.correlation_id,
        }
        return {k: v for k, v in data.items() if v is not None}


def _parse_error_body(text: str) -> Dict[str, Optional[str]]:
    """Best-effort extraction of name / details / correlationId from a JSON error body."""
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}

    def pick(*keys: str) -> Optional[str]:
        for key in keys:
            value = data.get(key)
            if value:
                return str(value)
        return None

    return {
        "name": pick("name", "title"),
        "details": pick("details", "description", "message"),
        "correlation_id": pick("correlationId"),
    }


# ---------------------------------------------------------------------------
# Pure parsing / mapping helpers
# ---------------------------------------------------------------------------

class PvrHelpers:
    """Static helpers for parsing nPVR API responses."""

    # ------------------------------------------------------------------
    # Duration
    # ------------------------------------------------------------------

    @staticmethod
    def parse_iso8601_duration(duration_str: str) -> Optional[int]:
        """
        Parse an ISO 8601 duration string and return total seconds.

        Supported:  PT2H44M5S, PT26M19S, PT45S, P1DT2H

        Returns:
            Total duration in whole seconds, or None on parse failure.
        """
        pattern = re.compile(
            r"P(?:(?P<days>\d+)D)?"
            r"(?:T"
            r"(?:(?P<hours>\d+)H)?"
            r"(?:(?P<minutes>\d+)M)?"
            r"(?:(?P<seconds>\d+(?:\.\d+)?)S)?"
            r")?",
            re.IGNORECASE,
        )
        match = pattern.fullmatch(duration_str.strip())
        if not match:
            return None
        days    = int(match.group("days")    or 0)
        hours   = int(match.group("hours")   or 0)
        minutes = int(match.group("minutes") or 0)
        seconds = float(match.group("seconds") or 0)
        total   = days * 86400 + hours * 3600 + minutes * 60 + int(seconds)
        return total if total > 0 else None

    # ------------------------------------------------------------------
    # Datetime
    # ------------------------------------------------------------------

    @staticmethod
    def parse_datetime(dt_str: Optional[str]) -> Optional[datetime]:
        """Parse an ISO 8601 datetime string to a timezone-aware datetime."""
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None

    # ------------------------------------------------------------------
    # Lifetime
    # ------------------------------------------------------------------

    @staticmethod
    def compute_lifetime_days(expiration_str: Optional[str]) -> Optional[int]:
        """
        Compute whole days remaining until expiry.

        Returns:
            Days remaining (minimum 0), or None when not available.
        """
        if not expiration_str:
            return None
        try:
            expiry = datetime.fromisoformat(expiration_str.replace("Z", "+00:00"))
            now    = datetime.now(tz=timezone.utc)
            delta  = expiry - now
            return max(0, delta.days)
        except (ValueError, AttributeError):
            return None

    # ------------------------------------------------------------------
    # Genre
    # ------------------------------------------------------------------

    @staticmethod
    def extract_primary_genre(tags: List[Dict]) -> Optional[str]:
        """
        Extract the primary genre title from a program tags list.

        Prefers ``genre-primary``; falls back to first ``genre-secondary``.
        """
        primary: Optional[str]   = None
        secondary: Optional[str] = None
        for tag in tags:
            scheme = tag.get("scheme", "")
            title  = tag.get("title", "").strip()
            if not title:
                continue
            if scheme == "genre-primary" and primary is None:
                primary = title
            elif scheme == "genre-secondary" and secondary is None:
                secondary = title
        return primary or secondary

    # ------------------------------------------------------------------
    # Thumbnails
    # ------------------------------------------------------------------

    @staticmethod
    def pick_thumbnail(
        thumbnails: Dict,
        preferred_key: str,
        fallback_key: Optional[str] = None,
    ) -> Optional[str]:
        """
        Pick a thumbnail URL from a program thumbnails dict.

        Matches keys by prefix (e.g. ``"mainWide"`` matches ``"mainWide-0x0"``).
        Falls back to ``fallback_key`` then to the first available URL.
        """
        for key, value in thumbnails.items():
            if key.startswith(preferred_key):
                return (value or {}).get("url")
        if fallback_key:
            for key, value in thumbnails.items():
                if key.startswith(fallback_key):
                    return (value or {}).get("url")
        for value in thumbnails.values():
            url = (value or {}).get("url")
            if url:
                return url
        return None

    # ------------------------------------------------------------------
    # URI helpers
    # ------------------------------------------------------------------

    @staticmethod
    def extract_numeric_tail(uri: Optional[str]) -> Optional[int]:
        """
        Extract the numeric ID from the tail of a theplatform URI.

        e.g. ``".../Station/265809448374"`` → ``265809448374``
        """
        if not uri:
            return None
        tail = uri.rstrip("/").rsplit("/", 1)[-1]
        try:
            return int(tail)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def extract_mpx_guid(playback_url: Optional[str]) -> Optional[str]:
        """
        Extract the MPX media GUID from a theplatform selector URL.

        e.g. ``"http://link.theplatform.eu/s/mdeprod/media/W3tyz38x4RtWzxcuggbnBw"``
             → ``"W3tyz38x4RtWzxcuggbnBw"``

        Returns None when the URL is absent or does not contain ``/media/``.
        """
        if not playback_url:
            return None
        tail = playback_url.rstrip("/").rsplit("/media/", 1)
        if len(tail) == 2:
            return tail[1].split("?")[0] or None
        return None


# ---------------------------------------------------------------------------
# HTTP + auth plumbing shared by both managers
# ---------------------------------------------------------------------------

class PvrHttpMixin:
    """
    Mixin providing HTTP and auth plumbing for nPVR manager classes.

    Concrete subclasses must assign these attributes in their ``__init__``:
        _http                   — HTTPManager
        _provider               — str (provider name for log messages)
        _provider_config        — ProviderConfig or None
        _auth_headers_callback  — Callable[[], Dict[str, str]] or None
    """

    # Typed stubs — assigned by the concrete subclass __init__.
    # Declared here so that static analysers (PyCharm, mypy) resolve
    # attribute references inside the mixin methods without warnings.
    _http: HTTPManager
    _provider: str
    _provider_config: Optional[ProviderConfig]
    _auth_headers_callback: Optional[Callable[[], Dict[str, str]]]

    # NEW: opt-in request logging flags.  Concrete subclasses may override
    # these in __init__ (e.g. from an env var).  When _log_request_headers is
    # False, _log_request() returns immediately — zero overhead.
    _log_request_headers: bool = False
    _log_auth_token: bool = False

    # ------------------------------------------------------------------
    # Request logging (NEW)
    # ------------------------------------------------------------------

    def _log_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        params: Optional[Dict] = None,
        payload: Optional[Dict] = None,
    ) -> None:
        """
        Dump the complete request URL, headers and payload for debugging.

        Opt-in via ``_log_request_headers``.  The ``Authorization`` value is
        redacted unless ``_log_auth_token`` is also True — a Basic persona
        token is a bearer credential and must not leak into logs.

        Emitted at DEBUG level, so it is dropped at INFO (production default).
        Enable with ``ULTIMATE_DEBUG=1`` or ``debug_mode: true`` in config.
        """
        if not self._log_request_headers:
            return

        redacted: Dict[str, str] = {}
        for key, value in headers.items():
            if key.lower() == "authorization" and not self._log_auth_token:
                scheme = value.split(" ", 1)[0] if " " in value else value
                redacted[key] = f"{scheme} <redacted len={len(value)}>"
            else:
                redacted[key] = value

        full_url = url
        if params:
            sep = "&" if "?" in url else "?"
            full_url = f"{url}{sep}{urlencode(params, doseq=True)}"

        logger.debug(
            f"{self._provider}: >>> {method} {full_url} | "
            f"headers={redacted} | payload={payload}"
        )

    # ------------------------------------------------------------------
    # Base-URL resolution
    # ------------------------------------------------------------------

    def _get_pvr_base_url(self) -> str:
        """
        Resolve the nPVR base URL from the discovered manifest config.

        Resolution order:
          1. ``provider_config.manifest.mpx.pvr_base_url``  (dynamic, preferred)
          2. Raises RuntimeError — no hardcoded fallback.
        """
        if self._provider_config is not None:
            try:
                pvr_url = self._provider_config.manifest.mpx.pvr_base_url
                if pvr_url:
                    return pvr_url.rstrip("/")
            except AttributeError:
                pass

        raise RuntimeError(
            f"{self._provider}: PVR base URL not available — "
            "provider configuration must be fully discovered before "
            "using this manager."
        )

    # ------------------------------------------------------------------
    # Auth headers
    # ------------------------------------------------------------------

    def _build_auth_headers(self) -> Dict[str, str]:
        """
        Build authentication headers for nPVR requests.

        The nPVR API uses ``Authorization: Basic {persona_token}``.

        Raises:
            RuntimeError: When ``auth_headers_callback`` is not configured.
        """
        if self._auth_headers_callback is None:
            raise RuntimeError(
                f"{self._provider}: auth_headers_callback not configured — "
                "cannot make authenticated nPVR requests."
            )
        try:
            return self._auth_headers_callback()
        except Exception as exc:
            raise RuntimeError(
                f"{self._provider}: auth_headers_callback raised an exception: {exc}"
            ) from exc

    # ------------------------------------------------------------------
    # Error construction + logging
    # ------------------------------------------------------------------

    def _api_error(
        self,
        method: str,
        url: str,
        *,
        response=None,
        exc: Optional[BaseException] = None,
    ) -> NpvrApiError:
        """
        Build the :class:`NpvrApiError` for a failed request and log it at
        ERROR together with the COMPLETE upstream response body.

        Works for both failure shapes: a response with a non-success status, and
        an exception raised by the HTTP layer (``requests.HTTPError`` carries the
        response on ``exc.response``).  Never raises.

        NOTE: do not test a ``requests.Response`` for truthiness — its
        ``__bool__`` is ``.ok`` and therefore False for every 4xx/5xx.
        """
        if response is None and exc is not None:
            response = getattr(exc, "response", None)

        status: Optional[int] = None
        body_text = ""
        if response is not None:
            status = getattr(response, "status_code", None)
            try:
                body_text = response.text or ""
            except Exception:  # undecodable / already-consumed body
                body_text = ""

        if status is None:
            reason = (
                f"{type(exc).__name__}: {exc}" if exc is not None
                else "no response received"
            )
            logger.error(
                f"{self._provider}: nPVR {method} {url} failed: {reason}",
                exc_info=exc,
            )
            return NpvrApiError(f"{self._provider}: {method} request failed: {reason}")

        if len(body_text) > _MAX_LOGGED_BODY_CHARS:
            shown = (
                f"{body_text[:_MAX_LOGGED_BODY_CHARS]}"
                f"... [truncated, {len(body_text)} chars total]"
            )
        else:
            shown = body_text or "<empty>"
        logger.error(
            f"{self._provider}: nPVR {method} {url} failed [HTTP {status}] "
            f"- response body: {shown}"
        )

        info = _parse_error_body(body_text)
        fallback = body_text.strip()[:_MAX_SUMMARY_CHARS]
        details = info.get("details") or (None if info else (fallback or None))
        summary = details or info.get("name") or "<empty response body>"
        return NpvrApiError(
            f"{self._provider}: {method} failed [HTTP {status}]: {summary}",
            status_code=status,
            error_name=info.get("name"),
            details=details,
            correlation_id=info.get("correlation_id"),
        )

    # ------------------------------------------------------------------
    # HTTP verbs
    # ------------------------------------------------------------------

    def _get(
        self, url: str, params: Dict, raise_on_error: bool = False
    ) -> Optional[Dict]:
        """
        Authenticated GET against the nPVR API.

        Sets the required ``Accept`` header via ``PVR_ACCEPT_HEADER``.

        Args:
            raise_on_error: When True, a failed request raises
                :class:`NpvrApiError` instead of returning None, so callers can
                tell "request failed" apart from "nothing there".

        Returns:
            Parsed JSON body, or None on error (unless ``raise_on_error``).
        """
        headers = self._build_auth_headers()
        headers["Accept"] = PVR_ACCEPT_HEADER

        self._log_request("GET", url, headers, params=params)  # NEW

        try:
            response = self._http.get(url, params=params, headers=headers)
            if response is not None and response.status_code == 200:
                return response.json()
            error = self._api_error("GET", url, response=response)
        except Exception as exc:
            error = self._api_error("GET", url, exc=exc)
            if raise_on_error:
                raise error from exc
            return None
        if raise_on_error:
            raise error
        return None

    def _post(self, url: str, payload: Dict) -> Optional[Dict]:
        """
        Authenticated POST against the nPVR API.

        Returns:
            Parsed JSON body on 200/201, or None on error.
        """
        headers = self._build_auth_headers()
        headers["Content-Type"] = PVR_ACCEPT_HEADER
        headers["Accept"]       = PVR_ACCEPT_HEADER

        self._log_request("POST", url, headers, payload=payload)  # NEW

        try:
            response = self._http.post(url, json=payload, headers=headers)
            if response is not None and response.status_code in (200, 201):
                return response.json()
            self._api_error("POST", url, response=response)
        except Exception as exc:
            self._api_error("POST", url, exc=exc)
        return None

    def _post_async(
        self,
        url: str,
        payload: Dict,
        content_type: str = PVR_ACCEPT_HEADER,
    ) -> Tuple[int, Optional[Dict]]:
        """
        Authenticated POST for endpoints that answer asynchronously
        (``202 Accepted``, usually with an empty body).

        Unlike :meth:`_post`, failures are RAISED instead of returned as None,
        so an empty body can be told apart from an error.

        Args:
            url:          Full request URL (query string included).
            payload:      JSON body.
            content_type: Content-Type header (e.g. ``"application/json;v=3"``).

        Returns:
            ``(status_code, body)`` where ``body`` is the parsed JSON object, or
            None when the response has no (JSON) body.

        Raises:
            NpvrApiError (a RuntimeError): On transport errors, no response, or
                a non-2xx status.  Status, error name, details and correlation
                id of the upstream error are available as attributes.
        """
        headers = self._build_auth_headers()
        headers["Content-Type"] = content_type
        headers["Accept"]       = PVR_ACCEPT_HEADER

        self._log_request("POST", url, headers, payload=payload)  # NEW

        try:
            response = self._http.post(url, json=payload, headers=headers)
        except Exception as exc:
            # HTTP layers that raise on 4xx/5xx (requests.HTTPError) carry the
            # response on the exception; _api_error() extracts and logs its body.
            raise self._api_error("POST", url, exc=exc) from exc

        if response is None or response.status_code not in (200, 201, 202, 204):
            raise self._api_error("POST", url, response=response)

        body: Optional[Dict] = None
        if response.text and response.text.strip():
            try:
                parsed = response.json()
                body = parsed if isinstance(parsed, dict) else None
            except ValueError:
                body = None

        return response.status_code, body

    def _put(self, url: str, payload: Dict) -> Optional[Dict]:
        """
        Authenticated PUT against the nPVR API.

        Returns:
            Parsed JSON body on 200, or None on error.
        """
        headers = self._build_auth_headers()
        headers["Content-Type"] = PVR_ACCEPT_HEADER
        headers["Accept"]       = PVR_ACCEPT_HEADER

        self._log_request("PUT", url, headers, payload=payload)  # NEW

        try:
            response = self._http.put(url, json=payload, headers=headers)
            if response is not None and response.status_code == 200:
                return response.json()
            self._api_error("PUT", url, response=response)
        except Exception as exc:
            self._api_error("PUT", url, exc=exc)
        return None

    def _delete(
        self,
        url: str,
        ok_statuses: Tuple[int, ...] = (200, 202, 204),
    ) -> int:
        """
        Authenticated DELETE against the nPVR API.

        Args:
            url:         Full request URL (query string included).
            ok_statuses: Status codes treated as success.  ``202 Accepted`` is
                         included because ``delete-recording-for-listing``
                         answers asynchronously.

        Returns:
            HTTP status code on success.

        Raises:
            KeyError:     On 404.
            NpvrApiError (a RuntimeError): On any other non-success status or
                transport error.
        """
        headers = self._build_auth_headers()

        self._log_request("DELETE", url, headers)  # NEW

        try:
            response = self._http.delete(url, headers=headers)
        except Exception as exc:
            error = self._api_error("DELETE", url, exc=exc)
            if error.status_code == 404:
                raise KeyError(
                    f"{self._provider}: Resource not found: {url}"
                ) from exc
            raise error from exc

        if response is None or response.status_code not in ok_statuses:
            error = self._api_error("DELETE", url, response=response)
            if error.status_code == 404:
                raise KeyError(f"{self._provider}: Resource not found: {url}")
            raise error

        return response.status_code