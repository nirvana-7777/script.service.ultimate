# streaming_providers/providers/livgolf/auth.py
# -*- coding: utf-8 -*-
"""
Anonymous authentication for the LIV Golf / ViewLift API.

The flow is intentionally simple:
  1. Generate a stable ``browser-<uuid4>`` device ID (persisted in the token).
  2. POST to the anonymous-token endpoint — no credentials required.
  3. The response contains a JWT ``authorizationToken`` valid for ~1 year.
  4. On every subsequent request supply it as the ``Authorization`` header.

Token persistence reuses the BaseAuthenticator / BaseAuthToken machinery so
that the token survives process restarts (stored via settings_manager).
"""

import json
import time
import uuid
import base64
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ...base.auth.base_auth import BaseAuthenticator, BaseAuthToken, TokenAuthLevel
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger
from .constants import (
    API_ENDPOINTS,
    DEFAULT_REQUEST_TIMEOUT,
    PLATFORM,
    PROVIDER_NAME,
    SITE,
    get_base_headers,
)


# ---------------------------------------------------------------------------
# JWT helpers (no external dependency — same pattern as magentaeu)
# ---------------------------------------------------------------------------

def _base64url_decode(s: str) -> bytes:
    padding = "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _decode_jwt_payload(token: str) -> Dict[str, Any]:
    """Decode JWT payload without signature verification."""
    try:
        _, payload_b64, _ = token.split(".")
        return json.loads(_base64url_decode(payload_b64).decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Cannot decode JWT: {exc}") from exc


def _token_expires_at(token: str) -> float:
    """Return the ``exp`` claim as a Unix timestamp, or 0 on failure."""
    try:
        return float(_decode_jwt_payload(token).get("exp", 0))
    except Exception:
        return 0.0


# ---------------------------------------------------------------------------
# Token dataclass
# ---------------------------------------------------------------------------

@dataclass
class LivGolfAuthToken(BaseAuthToken):
    """
    Thin wrapper around BaseAuthToken that adds the ``device_id`` used when
    requesting the anonymous token (needed to stay consistent across refreshes).
    """

    device_id: str = field(default="")

    # ------------------------------------------------------------------
    # Serialisation — must round-trip through BaseAuthenticator's
    # settings_manager.save_session / load_session machinery.
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "issued_at": self.issued_at,
            "auth_level": (
                self.auth_level.value if self.auth_level else TokenAuthLevel.ANONYMOUS.value
            ),
            "credential_type": self.credential_type or "",
            "device_id": self.device_id,
        }


# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------

class LivGolfAuthenticator(BaseAuthenticator):
    """
    Anonymous-only authenticator for the LIV Golf ViewLift API.

    No username / password are required or supported.  The token is a long-lived
    JWT (~1 year) tied to a generated ``browser-<uuid>`` device ID.
    """

    def __init__(
        self,
        config_dir: Optional[str] = None,
        http_manager=None,
        proxy_config: Optional[ProxyConfig] = None,
    ) -> None:
        if http_manager is None:
            raise ValueError("http_manager is required for LivGolfAuthenticator")

        self._http_manager = http_manager
        self._proxy_config = proxy_config

        # BaseAuthenticator.__init__ loads any persisted session automatically.
        super().__init__(
            provider_name=PROVIDER_NAME,
            config_dir=config_dir,
            # No credentials needed for anonymous auth
            credentials=None,
            # No Kodi integration required
            enable_kodi_integration=False,
        )

        # Ensure we always have a device_id — either restored from disk or freshly generated.
        if not self._current_token or not isinstance(self._current_token, LivGolfAuthToken):
            device_id = f"browser-{uuid.uuid4()}"
            self._current_token = LivGolfAuthToken(
                access_token="",
                token_type="Bearer",
                expires_in=0,
                issued_at=time.time(),
                device_id=device_id,
            )
            logger.debug(f"[LivGolfAuthenticator] Generated new device_id: {device_id}")
        else:
            logger.debug(
                f"[LivGolfAuthenticator] Restored device_id: {self._current_token.device_id}"
            )

    # ------------------------------------------------------------------
    # BaseAuthenticator abstract-method implementations
    # ------------------------------------------------------------------

    @property
    def auth_endpoint(self) -> str:
        """Anonymous token endpoint — device_id filled in at call time."""
        return API_ENDPOINTS["ANONYMOUS_TOKEN"]

    def _get_auth_headers(self) -> Dict[str, str]:
        return get_base_headers()

    def _build_auth_payload(self) -> Dict[str, Any]:
        # Anonymous token is obtained via GET — no POST body needed.
        return {}

    def get_fallback_credentials(self):
        return None

    def _perform_authentication(self) -> BaseAuthToken:
        """Fetch a fresh anonymous token from the ViewLift identity endpoint."""
        device_id = self._device_id

        url = API_ENDPOINTS["ANONYMOUS_TOKEN"].format(
            site=SITE,
            platform=PLATFORM,
            device_id=device_id,
        )

        logger.info(f"[LivGolfAuthenticator] Requesting anonymous token (device_id={device_id})")

        response = self._http_manager.get(
            url,
            operation="auth_anonymous",
            headers=get_base_headers(),
            timeout=DEFAULT_REQUEST_TIMEOUT,
        )
        response.raise_for_status()

        data = response.json()
        raw_token = data.get("authorizationToken")
        if not raw_token:
            raise ValueError(
                f"Anonymous token response missing 'authorizationToken'. "
                f"Keys received: {list(data.keys())}"
            )

        exp = _token_expires_at(raw_token)
        issued = time.time()
        expires_in = max(0, int(exp - issued)) if exp else 86400 * 365

        token = LivGolfAuthToken(
            access_token=raw_token,
            token_type="Bearer",
            expires_in=expires_in,
            issued_at=issued,
            device_id=device_id,
            auth_level=TokenAuthLevel.ANONYMOUS,
        )

        logger.info(
            f"[LivGolfAuthenticator] Anonymous token obtained "
            f"(expires_in={expires_in}s, device_id={device_id})"
        )
        return token

    def _refresh_token(self) -> Optional[BaseAuthToken]:
        """
        ViewLift anonymous tokens are very long-lived (~1 year), but when they
        do expire we simply request a new one — same device_id, new JWT.
        """
        logger.info("[LivGolfAuthenticator] Refreshing anonymous token")
        try:
            return self._perform_authentication()
        except Exception as exc:
            logger.warning(f"[LivGolfAuthenticator] Token refresh failed: {exc}")
            return None

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        return TokenAuthLevel.ANONYMOUS

    def _create_token_from_response(self, response_data: Dict[str, Any]) -> BaseAuthToken:
        """Restore a token from the persisted session dict."""
        raw_token = response_data.get("access_token", "")
        device_id = response_data.get("device_id") or f"browser-{uuid.uuid4()}"

        exp = _token_expires_at(raw_token) if raw_token else 0.0
        issued = response_data.get("issued_at", time.time())
        expires_in = response_data.get("expires_in", 0)

        token = LivGolfAuthToken(
            access_token=raw_token,
            token_type=response_data.get("token_type", "Bearer"),
            expires_in=expires_in,
            issued_at=issued,
            device_id=device_id,
            auth_level=TokenAuthLevel.ANONYMOUS,
        )
        return token

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @property
    def _device_id(self) -> str:
        """Return the stable device ID, regardless of token state."""
        if self._current_token and isinstance(self._current_token, LivGolfAuthToken):
            return self._current_token.device_id or f"browser-{uuid.uuid4()}"
        return f"browser-{uuid.uuid4()}"

    def get_authorization_header(self, force_refresh: bool = False) -> str:
        """
        Return a ready-to-use ``Authorization`` header value (the raw JWT,
        *without* a ``Bearer `` prefix — the LIV Golf API uses the raw token).
        """
        token = self.get_bearer_token(force_refresh=force_refresh)
        # get_bearer_token may prepend "Bearer " — strip it for this API
        if token and token.startswith("Bearer "):
            return token[len("Bearer "):]
        return token or ""

    def is_token_expired(self) -> bool:
        """True if the current token is missing or within the expiry margin."""
        if not self._current_token or not self._current_token.access_token:
            return True
        exp = _token_expires_at(self._current_token.access_token)
        if exp == 0:
            return False  # Cannot determine expiry — assume valid
        from .constants import TOKEN_EXPIRY_MARGIN_SECONDS
        return time.time() >= (exp - TOKEN_EXPIRY_MARGIN_SECONDS)