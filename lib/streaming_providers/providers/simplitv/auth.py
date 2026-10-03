# streaming_providers/providers/simplitv/auth.py
"""
simpliTV authentication.

Two deliberate deviations from the AuthProtocol's *implied* shape (the
protocol only requires the three method names, not their semantics):

  1. The simpliTV token is passed as a *query parameter* (GET) or *body
     field* (POST), never as an Authorization header. build_headers()
     therefore returns base headers only; callers attach the token via
     with_token() / auth_body(). One endpoint (GetRecordings) names the
     query parameter `tokenValue` instead of `token`.

  2. A second credential, the *device key*, is required by
     AcquireContent. It lives on the server: GetDevices returns the
     account's registered device, and a device is only registered when
     the list is empty. Nothing about it is persisted locally, so a
     restart or invalidate() can never leak devices.

Sessions are not persisted: the token is cheap to re-acquire, and the
device key is re-read from the server.
"""

import secrets
import string
import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ...base.auth.base_auth import BaseAuthToken
from ...base.errors import AuthError, CredentialsError
from ...base.utils.logger import logger

from .constants import SimpliTVConfig, SimpliTVDefaults


def _generate_device_key() -> str:
    """32 lowercase-alnum chars (the addon's format), from a CSPRNG."""
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(32))


class SimpliTVAuth:
    """
    Authenticator for simpliTV.

    Not a subclass of any base class -- matches AuthProtocol by shape for
    the three shared methods, plus simpliTV-specific helpers
    (with_token, auth_body) and the device-key accessor.

    Thread-safe: the backend serves requests from several threads, and
    login / device registration must happen once, not once per thread.
    """

    def __init__(
        self,
        *,
        http_manager,
        country: str,
        settings_manager=None,
        credentials=None,
        config: Optional[SimpliTVConfig] = None,
        **provider_opts,
    ):
        self.http_manager = http_manager
        self.country = country
        self.settings_manager = settings_manager
        self._credentials = credentials
        self.config = config or SimpliTVConfig()
        self._cached_token: Optional[BaseAuthToken] = None
        self._device_key: Optional[str] = None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # The three shared methods
    # ------------------------------------------------------------------

    def get_access_token(self, force_refresh: bool = False) -> str:
        with self._lock:
            if (
                not force_refresh
                and self._cached_token
                and not self._cached_token.is_expired
            ):
                return self._cached_token.access_token
            self._cached_token = self._perform_authentication()
            return self._cached_token.access_token

    def build_headers(
        self, token: Optional[str] = None, **opts
    ) -> Dict[str, str]:
        """
        Return *base* headers for the simpliTV API.

        The token is deliberately NOT placed here -- see with_token() and
        auth_body(). The `token` argument is accepted for protocol
        compatibility and ignored.
        """
        return self.config.get_api_headers()

    def invalidate(self) -> None:
        """
        Drop the cached token; the next call logs in again.

        The device key is kept: it identifies the install, not the
        session.
        """
        with self._lock:
            self._cached_token = None

    # ------------------------------------------------------------------
    # simpliTV-specific helpers
    # ------------------------------------------------------------------

    def with_token(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        param: str = SimpliTVDefaults.TOKEN_PARAM,
    ) -> str:
        """Append the token (as `param`) and any extra params to `url`."""
        token = self.get_access_token()
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query))
        query[param] = token
        if params:
            query.update(params)
        return urlunparse(parsed._replace(query=urlencode(query)))

    def auth_body(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Return `payload` with the token merged in as a body field."""
        merged = dict(payload)
        merged["token"] = self.get_access_token()
        return merged

    def get_device_key(self) -> str:
        """
        Return the account's device key.

        Reads GetDevices first and uses the registered device; registers
        a new one only if the account has none.
        """
        with self._lock:
            if self._device_key:
                return self._device_key

            devices = self._list_devices()
            if not devices:
                self._register_device()
                devices = self._list_devices()
            if not devices:
                raise AuthError(
                    "simpliTV: device registration returned no devices"
                )
            self._device_key = devices[0]["key"]
            logger.debug(f"simpliTV[{self.country}]: device key resolved")
            return self._device_key

    # ------------------------------------------------------------------
    # Provider-specific implementation
    # ------------------------------------------------------------------

    def _perform_authentication(self) -> BaseAuthToken:
        creds = self._resolve_credentials()
        logger.debug(f"simpliTV[{self.country}]: logging in")

        payload = {
            "Login": creds["username"],
            "Password": creds["password"],
            "LongExpiration": "true",
            "platformCodename": self.config.platform_codename,
        }
        resp = self.http_manager.post(
            self.config.authenticate_url(),
            json=payload,
            headers=self.build_headers(),
        )
        token_value = resp.json().get("token")
        if not token_value:
            raise AuthError("simpliTV: no token in authenticate response")

        return BaseAuthToken(
            access_token=token_value,
            token_type="token",
            expires_in=SimpliTVDefaults.TOKEN_LIFETIME_SECONDS,
            issued_at=time.time(),
        )

    def _resolve_credentials(self) -> Dict[str, str]:
        raw = self._credentials or self._load_stored_credentials()
        if not raw:
            raise CredentialsError("simpliTV: no credentials available")

        if isinstance(raw, dict):
            username, password = raw.get("username"), raw.get("password")
        else:
            username = getattr(raw, "username", None)
            password = getattr(raw, "password", None)
        if not username or not password:
            raise CredentialsError("simpliTV: username or password empty")
        return {"username": username, "password": password}

    def _load_stored_credentials(self):
        """
        Seam for credentials held by the host's settings_manager.

        TODO(host): the template expects a fallback to stored
        credentials, but the settings_manager accessor name is not
        known here and is deliberately not guessed. Implement against
        the real base API; return None when nothing is stored.
        """
        return None

    def _list_devices(self) -> list:
        url = self.with_token(
            self.config.get_devices_url(),
            {"platformCodename": self.config.platform_codename},
        )
        resp = self.http_manager.get(url, headers=self.build_headers())
        return resp.json().get("devices") or []

    def _register_device(self) -> None:
        logger.info(
            f"simpliTV[{self.country}]: no registered device on the "
            f"account, registering one"
        )
        payload = {
            "deviceKey": _generate_device_key(),
            "deviceName": SimpliTVDefaults.DEVICE_NAME,
            "generalDeviceType": SimpliTVDefaults.DEVICE_GENERAL_TYPE,
            "operatingSystem": SimpliTVDefaults.DEVICE_OS,
            "platformCodename": self.config.platform_codename,
            "pushToken": "",
            "userAgent": self.config.user_agent,
            "userToken": self.get_access_token(),
            "versionOs": SimpliTVDefaults.DEVICE_OS_VERSION,
        }
        self.http_manager.post(
            self.config.register_device_url(),
            json=payload,
            headers=self.build_headers(),
        )
