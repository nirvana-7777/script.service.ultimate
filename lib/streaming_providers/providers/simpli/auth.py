# streaming_providers/providers/simpli/auth.py
"""
simpliTV authentication.

Two deliberate deviations from the AuthProtocol's *implied* shape:

  1. The simpliTV token is passed as a *query parameter* (GET) or *body
     field* (POST), never as an Authorization header. build_headers()
     therefore returns base headers only; callers attach the token via
     with_token() / auth_body(). One endpoint (GetRecordings) names the
     query parameter `tokenValue` instead of `token`.

  2. A second credential, the *device key*, is required by
     AcquireContent. It is discovered from the server (GetDevices) and
     registered once if the account has none. Sessions are not
     persisted: the token is cheap to re-acquire.

Device key lifecycle
--------------------
On first use:
  1. GetDevices. If the account already has devices, reuse the first
     one's key. This is the common case on a re-install.
  2. If GetDevices is empty, generate a fresh key and RegisterDevice.
  3. GetDevices again and use the first entry. If the server does not
     hand a device back, raise -- do not proceed with an unverified
     key. The read-back, not the RegisterDevice response, is the
     authoritative check (the RegisterDevice response shape is not
     verified).

The key is cached in-process only. The settings_manager accessor names
are host-specific and are not guessed. A process restart therefore hits
GetDevices again, which returns the already-registered device.

Error handling: network / JSON failures in the device calls are wrapped
in ServerError by transport_errors(); typed provider errors (AuthError
etc.) pass through unchanged.
"""

import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ...base.auth.base_auth import BaseAuthToken
from ...base.errors import AuthError, CredentialsError
from ...base.utils.logger import logger

from .constants import SimpliTVConfig, SimpliTVDefaults
from .helpers import parse_iso, transport_errors


def _generate_device_key() -> str:
    """
    Return a 10-digit numeric device key.

    The browser log shows the format the server accepts:
    "1421859737". Earlier versions of this provider used a 32-char
    lowercase-alnum string (ported from the addon); that shape is not
    what the API advertises.
    """
    return f"{secrets.randbelow(10**10):010d}"


def _mask(key: Optional[str]) -> str:
    """Short tag for logs; never the full key."""
    if not key or len(key) < 6:
        return "***"
    return f"{key[:2]}...{key[-2:]}"


def _parse_expiry(iso: Optional[str]) -> Optional[int]:
    """
    Parse `tokenExpirationTime` to seconds from now. Returns None on
    missing / malformed input or a time already in the past.
    """
    dt = parse_iso(iso)
    if dt is None:
        return None
    delta = (dt - datetime.now(timezone.utc)).total_seconds()
    if delta <= 0:
        return None
    return int(delta)


def _extract_device_key(entry: Any) -> str:
    """
    Return the device key from one GetDevices entry.

    The response shape is unverified (the browser capture never calls
    GetDevices). "key" is the addon's field name; "deviceKey" is the
    field the RegisterDevice payload uses. Either is accepted; if
    neither is present (or the entry is not an object), raise rather
    than silently return empty.
    """
    if not isinstance(entry, dict):
        raise AuthError(
            f"simpliTV: GetDevices entry is not an object: "
            f"{type(entry).__name__}"
        )
    for field in ("key", "deviceKey"):
        value = entry.get(field)
        if value:
            return str(value)
    raise AuthError(
        f"simpliTV: GetDevices entry has no device key field "
        f"(keys: {sorted(entry.keys())!r})"
    )


class SimpliTVAuth:
    """
    Authenticator for simpliTV.

    Not a subclass of any base class -- matches AuthProtocol by shape
    for the three shared methods, plus simpliTV-specific helpers
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

        The token is deliberately NOT placed here -- see with_token()
        and auth_body(). The `token` argument is accepted for protocol
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
        """
        Append the token (as `param`) and any extra params to `url`.

        NOTE: this parses and re-encodes the existing query string, so
        the pre-encoded `$headers` blob is re-encoded. The key/value
        pairs are identical, but the bytes differ from the browser
        capture. If the server ever proves sensitive to that, build the
        query string by hand instead.
        """
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

        Order of preference:
          1. In-process cache.
          2. GetDevices -- reuse the first registered device.
          3. RegisterDevice with a fresh key, then GetDevices again.
        """
        with self._lock:
            if self._device_key:
                return self._device_key

            devices = self._list_devices()
            if devices:
                self._device_key = _extract_device_key(devices[0])
                logger.debug(
                    f"simpliTV[{self.country}]: reusing device "
                    f"{_mask(self._device_key)}"
                )
                return self._device_key

            self._register_device(_generate_device_key())

            devices = self._list_devices()
            if not devices:
                raise AuthError(
                    "simpliTV: device registration did not result in a "
                    "registered device (GetDevices is still empty)"
                )
            self._device_key = _extract_device_key(devices[0])
            logger.debug(
                f"simpliTV[{self.country}]: registered device "
                f"{_mask(self._device_key)}"
            )
            return self._device_key

    # ------------------------------------------------------------------
    # Provider-specific implementation
    # ------------------------------------------------------------------

    def _perform_authentication(self) -> BaseAuthToken:
        creds = self._resolve_credentials()
        logger.debug(f"simpliTV[{self.country}]: logging in")

        # The browser sends lowercase `login`/`password` and does NOT
        # send LongExpiration.
        payload = {
            "platformCodename": self.config.platform_codename,
            "login": creds["username"],
            "password": creds["password"],
        }
        resp = self.http_manager.post(
            self.config.authenticate_url(),
            json=payload,
            headers=self.build_headers(),
        )
        data = resp.json()
        token_value = data.get("token")
        if not token_value:
            raise AuthError("simpliTV: no token in authenticate response")

        expires_in = (
            _parse_expiry(data.get("tokenExpirationTime"))
            or SimpliTVDefaults.TOKEN_LIFETIME_SECONDS
        )

        return BaseAuthToken(
            access_token=token_value,
            token_type="token",
            expires_in=expires_in,
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

        TODO(host): implement against the real base API; return None
        when nothing is stored.
        """
        return None

    # ------------------------------------------------------------------
    # Device list / registration
    # ------------------------------------------------------------------

    def _list_devices(self) -> list:
        """
        GET /v1/Devices/GetDevices. Returns the raw device list (may be
        empty; that is not an error).

        with_token() runs outside transport_errors so a login failure
        keeps its own type.
        """
        url = self.with_token(
            self.config.get_devices_url(),
            {"platformCodename": self.config.platform_codename},
        )
        with transport_errors("GetDevices"):
            resp = self.http_manager.get(
                url, headers=self.config.get_api_headers()
            )
            devices = resp.json().get("devices")
        return devices if isinstance(devices, list) else []

    def _register_device(self, device_key: str) -> None:
        """
        Register a device key with the server.

        Payload matches the browser capture for RegisterDevice. The
        response shape is not verified, so only an explicit
        `result.success == false` is treated as a refusal; anything
        else is accepted and the caller's GetDevices read-back decides
        whether registration actually happened.
        """
        logger.debug(
            f"simpliTV[{self.country}]: registering device "
            f"{_mask(device_key)}"
        )
        payload = {
            "platformCodename": self.config.platform_codename,
            "deviceKey": device_key,
            "userToken": self.get_access_token(),
            "pushToken": "",
            "generalDeviceType": SimpliTVDefaults.DEVICE_GENERAL_TYPE,
            "deviceName": SimpliTVDefaults.DEVICE_NAME,
            "browserVersion": SimpliTVDefaults.DEVICE_BROWSER_VERSION,
            "userAgent": self.config.user_agent,
            "operatingSystem": SimpliTVDefaults.DEVICE_OS,
            "versionOs": SimpliTVDefaults.DEVICE_OS_VERSION,
        }
        with transport_errors("RegisterDevice"):
            resp = self.http_manager.post(
                self.config.register_device_url(),
                json=payload,
                headers=self.build_headers(),
            )
        try:
            data = resp.json()
        except ValueError:
            return  # empty / non-JSON body: rely on the read-back
        result = data.get("result") if isinstance(data, dict) else None
        if isinstance(result, dict) and result.get("success") is False:
            raise AuthError(
                f"simpliTV: RegisterDevice refused (response: {data!r})"
            )