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

import re
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from .constants import PVR_ACCEPT_HEADER
from ...base.utils.logger import logger
from ...base.network import HTTPManager
from .config_models import ProviderConfig


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
    # HTTP verbs
    # ------------------------------------------------------------------

    def _get(self, url: str, params: Dict) -> Optional[Dict]:
        """
        Authenticated GET against the nPVR API.

        Sets the required ``Accept`` header via ``PVR_ACCEPT_HEADER``.

        Returns:
            Parsed JSON body, or None on error.
        """
        headers = self._build_auth_headers()
        headers["Accept"] = PVR_ACCEPT_HEADER

        try:
            response = self._http.get(url, params=params, headers=headers)
            if response and response.status_code == 200:
                return response.json()
            logger.warning(
                f"{self._provider}: nPVR GET failed "
                f"[{response.status_code if response else 'no response'}] {url}"
            )
        except Exception as exc:
            logger.error(f"{self._provider}: nPVR GET exception for {url}: {exc}")
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

        try:
            response = self._http.post(url, json=payload, headers=headers)
            if response and response.status_code in (200, 201):
                return response.json()
            logger.warning(
                f"{self._provider}: nPVR POST failed "
                f"[{response.status_code if response else 'no response'}] {url}"
            )
        except Exception as exc:
            logger.error(f"{self._provider}: nPVR POST exception for {url}: {exc}")
        return None

    def _put(self, url: str, payload: Dict) -> Optional[Dict]:
        """
        Authenticated PUT against the nPVR API.

        Returns:
            Parsed JSON body on 200, or None on error.
        """
        headers = self._build_auth_headers()
        headers["Content-Type"] = PVR_ACCEPT_HEADER
        headers["Accept"]       = PVR_ACCEPT_HEADER

        try:
            response = self._http.put(url, json=payload, headers=headers)
            if response and response.status_code == 200:
                return response.json()
            logger.warning(
                f"{self._provider}: nPVR PUT failed "
                f"[{response.status_code if response else 'no response'}] {url}"
            )
        except Exception as exc:
            logger.error(f"{self._provider}: nPVR PUT exception for {url}: {exc}")
        return None

    def _delete(self, url: str) -> int:
        """
        Authenticated DELETE against the nPVR API.

        Returns:
            HTTP status code on success.

        Raises:
            KeyError:     On 404.
            RuntimeError: On any other non-success status or transport error.
        """
        headers = self._build_auth_headers()

        try:
            response = self._http.delete(url, headers=headers)
        except Exception as exc:
            raise RuntimeError(
                f"{self._provider}: DELETE request failed for {url}: {exc}"
            ) from exc

        if response is None:
            raise RuntimeError(
                f"{self._provider}: No response received for DELETE {url}"
            )

        if response.status_code == 404:
            raise KeyError(f"{self._provider}: Resource not found: {url}")

        if response.status_code not in (200, 204):
            raise RuntimeError(
                f"{self._provider}: DELETE failed [{response.status_code}] {url}: "
                f"{response.text[:200]}"
            )

        return response.status_code