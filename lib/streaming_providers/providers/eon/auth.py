# streaming_providers/providers/eon/auth.py
"""
Eon authentication -- the auth class itself satisfies AuthProtocol
(get_access_token / build_headers / invalidate); managers get it directly.

Three identities are involved (see PVREon / HttpClient):
  * client token   -- OAuth client_credentials at the broker; shared with
                      EonEndpoints (brand / CDN discovery) and used for device
                      registration. Owned by EonClientToken, re-fetched on 401.
  * device         -- serial (client-generated), deviceId / deviceNumber
                      (server-minted). CLIENT IDENTITY: persisted, never
                      cleared with the session.
  * user session   -- access / refresh token + stream key + stream user. The
                      stream key is also the AES key of the CDN URL.

Login flows (platform- and brand-dependent):
  web        refresh_token grant, else the brand's flow (config.login_flow):
               password  password grant (username SHA-256 in upper-case hex +
                         password + deviceNumber, multipart form)
               oidc      authorization code + PKCE through the brand's own
                         identity provider (Vivacom BG, see oidc_login.py);
                         the token endpoint mints the device itself, so there
                         is NO separate device registration in this flow
  androidtv  refresh_token grant, else OTP: the server hands out a code the
             user confirms in the operator's portal (EonOtpRequiredError),
             the next attempt exchanges it.

Recovery ladder on a rejected token (recover()), each rung once:
  1. refresh_token grant   2. password / OTP login   3. re-register the
  device (new deviceNumber) and log in again -> else AuthError.

Failure policy (same as the Variant B session adapter, README §9): a failed
login is recorded ONCE, after the whole ladder has run --
  * EonLoginRejected (wrong credentials)  -> PERMANENT: no network until
    set_credentials() / reset();
  * EonOtpRequiredError                   -> a pending human step, never
    gated (the next call exchanges the confirmed code);
  * anything else (network, 5xx, WAF 403) -> TRANSIENT: exponential backoff
    BACKOFF_BASE * 2^(n-1) s, capped. A rejected grant INSIDE the ladder is a
    signal (stale device), not a verdict, and is not recorded.
`last_error` keeps the original exception for the auth-status UI.

Persistence: only what cannot be re-derived is stored -- device serial / id /
number (client identity) and the refresh token. The STREAM KEY and stream user
come back with every token response (also the refresh grant) and live in
memory only: they are the AES key of the CDN URL, and SessionManager logs the
values of unknown keys in clear at INFO.

Rules: lazy (no network in __init__), one login for concurrent callers,
typed errors only, nothing secret in logs (lengths at most).
"""

import hashlib
import json
import secrets
import string
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Protocol, Type
from urllib.parse import urlencode

from requests.exceptions import HTTPError

from ...base.errors import AuthError, ProviderError, ServerError, error_from_exception
from ...base.utils.logger import logger
from ...base.utils.transport import transport_errors
from .constants import EonConfig, EonDefaults
from .bootstrap import EonClientToken, EonEndpoints
from .errors import EonLoginRejected, EonOtpRequiredError
from .models import EonDeviceRegistration, EonTokenResponse
from .oidc_login import EonOidcLogin

_PROVIDER = EonDefaults.PROVIDER_LABEL

K_DEVICE_SERIAL = "device_serial"
K_DEVICE_ID = "device_id"
K_DEVICE_NUMBER = "device_number"
K_REFRESH_TOKEN = "refresh_token"

_SERIAL_ALPHABET = string.digits + string.ascii_letters + "-"
_OIDC_SERIAL_ALPHABET = string.digits + string.ascii_letters
_TOKEN_REFRESH_BUFFER_SECONDS = 60
BACKOFF_BASE_SECONDS = 30
BACKOFF_MAX_SECONDS = 900


class EonStore(Protocol):
    """Durable key/value state owned by the backend's session layer."""

    def get(self, key: str) -> Optional[str]: ...
    def set(self, key: str, value: str) -> None: ...
    def set_many(self, values: Dict[str, str]) -> None: ...
    def delete(self, key: str) -> None: ...


class MemoryStore:
    """Non-durable default. With it every restart registers a NEW device."""

    def __init__(self) -> None:
        self._data: Dict[str, str] = {}

    def get(self, key: str) -> Optional[str]:
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        self._data[key] = value

    def set_many(self, values: Dict[str, str]) -> None:
        self._data.update(values)

    def delete(self, key: str) -> None:
        self._data.pop(key, None)


@dataclass(frozen=True)
class StreamCredentials:
    stream_key: str
    stream_user: str
    device_number: str


class EonAuth:
    def __init__(
        self,
        *,
        http_manager: Any,
        config: EonConfig,
        endpoints: EonEndpoints,
        client_token: EonClientToken,
        store: Optional[EonStore] = None,
        credentials: Any = None,
        credentials_loader: Optional[Callable[[], Any]] = None,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._http = http_manager
        self._config = config
        self._endpoints = endpoints
        self._client_token = client_token
        self._store: EonStore = store if store is not None else MemoryStore()
        self._credentials = credentials      # object with .username / .password
        self._credentials_loader = credentials_loader   # lazy: no disk/network in __init__
        self._stream_key: Optional[str] = None           # memory only (see docstring)
        self._stream_user: Optional[str] = None
        self._access_token: Optional[str] = None
        self._expires_at: Optional[float] = None
        self._pending_otp: Optional[str] = None
        self._lock = threading.RLock()
        self._clock = clock
        self.last_error: Optional[Exception] = None
        self._permanent: Optional[Exception] = None
        self._failures = 0
        self._retry_at = 0.0
        self._oidc: Optional[EonOidcLogin] = (
            EonOidcLogin(http_manager=http_manager, config=config, endpoints=endpoints)
            if config.login_flow == EonDefaults.LOGIN_FLOW_OIDC else None
        )

    # ------------------------------------------------------------------
    # Credentials
    # ------------------------------------------------------------------
    def _current_credentials(self) -> Any:
        if self._credentials is None and self._credentials_loader is not None:
            try:
                self._credentials = self._credentials_loader()
            except Exception as exc:     # a broken settings backend is "no credentials"
                logger.warning(f"{_PROVIDER}: could not load stored credentials: {exc!r}")
        return self._credentials

    @property
    def has_credentials(self) -> bool:
        c = self._current_credentials()
        return bool(c and getattr(c, "username", None) and getattr(c, "password", None))

    def set_credentials(self, credentials: Any) -> None:
        """Replace the credentials, drop the session and forget any failure."""
        self._credentials = credentials
        self.invalidate()
        self.reset()

    def reset(self) -> None:
        """Forget recorded failures (permanent verdict and backoff)."""
        with self._lock:
            self.last_error = None
            self._permanent = None
            self._failures = 0
            self._retry_at = 0.0

    def details(self) -> Dict[str, Any]:
        """Free-form details for the auth-status UI."""
        details: Dict[str, Any] = {}
        if self.last_error is not None:
            details["last_error"] = str(self.last_error)
            details["last_error_type"] = type(self.last_error).__name__
        if isinstance(self.last_error, EonOtpRequiredError):
            details["otp"] = self.last_error.otp
            details["otp_expires_minutes"] = self.last_error.expires_minutes
        return details

    # ------------------------------------------------------------------
    # AuthProtocol
    # ------------------------------------------------------------------
    def get_access_token(self, force_refresh: bool = False) -> str:
        if not force_refresh and self._token_valid():
            return self._access_token  # type: ignore[return-value]
        with self._lock:
            if not force_refresh and self._token_valid():   # another thread logged in
                return self._access_token  # type: ignore[return-value]
            self._gated(self._login)
            return self._access_token  # type: ignore[return-value]

    def build_headers(self) -> Dict[str, str]:
        """API headers incl. the bearer token (not for CDN requests)."""
        return self._config.bearer_headers(self.get_access_token())

    def invalidate(self) -> None:
        """Drop the SESSION (tokens, stream credentials). The device stays."""
        with self._lock:
            self._access_token = None
            self._expires_at = None
            self._pending_otp = None
            self._stream_key = None
            self._stream_user = None
            self._store.delete(K_REFRESH_TOKEN)

    # ------------------------------------------------------------------
    # Eon-specific
    # ------------------------------------------------------------------
    def stream_credentials(self) -> StreamCredentials:
        """Stream key / user / device number, logging in first if needed."""
        self.get_access_token()
        number = self._store.get(K_DEVICE_NUMBER)
        if not (self._stream_key and self._stream_user and number):
            raise ServerError(f"{_PROVIDER}: the session carries no stream credentials")
        return StreamCredentials(
            stream_key=self._stream_key, stream_user=self._stream_user, device_number=number
        )

    def recover(self, failed_token: Optional[str]) -> None:
        """Repair the session after a 401 with `failed_token`."""
        with self._lock:
            if self._access_token and self._access_token != failed_token:
                return      # another thread already repaired it
            self._access_token = None
            self._expires_at = None
            self._gated(self._ladder)

    def _ladder(self) -> None:
        try:
            self._login()                   # rungs 1 + 2
            return
        except EonOtpRequiredError:
            raise
        except AuthError as exc:
            if self._oidc is not None and isinstance(exc, EonLoginRejected):
                # The IdP's verdict on the password: a new device cannot change
                # it, and a second attempt risks locking the account.
                raise
            logger.warning(f"{_PROVIDER}: login failed; re-registering the device")
        self._reset_device()                # rung 3
        self._login()                       # AuthError propagates

    def _gated(self, action: Callable[[], None]) -> None:
        """Run a login action behind the failure gate and record its outcome."""
        if self._permanent is not None:
            raise self._permanent
        if self._clock() < self._retry_at and self.last_error is not None:
            raise self.last_error
        try:
            action()
        except EonOtpRequiredError as exc:
            self.last_error = exc           # a pending human step: not a failure
            raise
        except Exception as exc:
            self._record_failure(exc)
            raise
        self.last_error = None
        self._failures = 0
        self._retry_at = 0.0

    def _record_failure(self, exc: Exception) -> None:
        self.last_error = exc
        if isinstance(exc, EonLoginRejected):
            self._permanent = exc
            return
        self._failures += 1
        delay = min(BACKOFF_BASE_SECONDS * 2 ** (self._failures - 1), BACKOFF_MAX_SECONDS)
        self._retry_at = self._clock() + delay

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------
    def _token_valid(self) -> bool:
        if not self._access_token:
            return False
        if self._expires_at is None:      # the server never told us: 401 decides
            return True
        return time.time() < self._expires_at - _TOKEN_REFRESH_BUFFER_SECONDS

    def _login(self) -> None:
        refresh = self._store.get(K_REFRESH_TOKEN)
        if refresh:
            try:
                self._apply(self._grant_refresh(refresh))
                return
            except AuthError:
                logger.info(f"{_PROVIDER}: refresh token rejected")
                self._store.delete(K_REFRESH_TOKEN)

        if self._config.platform.is_android_tv:
            self._login_otp()
            return

        if not self.has_credentials:
            raise AuthError(
                f"{_PROVIDER}: no credentials configured. "
                f"Set username and password in the addon settings."
            )
        if self._oidc is not None:
            self._apply(self._login_oidc())
        else:
            self._ensure_device()
            self._apply(self._grant_password())
        logger.info(f"{_PROVIDER}: authenticated")

    def _apply(self, tok: EonTokenResponse) -> None:
        self._access_token = tok.access_token
        self._expires_at = time.time() + tok.expires_in if tok.expires_in else None
        if tok.stream_key:
            self._stream_key = tok.stream_key
        if tok.stream_user:
            self._stream_user = tok.stream_user
        durable = {}
        if tok.refresh_token:
            durable[K_REFRESH_TOKEN] = tok.refresh_token
        if tok.device_number:
            durable[K_DEVICE_NUMBER] = tok.device_number
        if durable:
            self._store.set_many(durable)

    def _grant(self, params: Dict[str, str], *, data: Optional[bytes] = None,
               headers: Optional[Dict[str, str]] = None,
               rejected: Type[AuthError] = AuthError,
               rejected_statuses: tuple = (400, 401, 403),
               path: str = EonDefaults.PATH_OAUTH_TOKEN,
               label: Optional[str] = None) -> EonTokenResponse:
        """POST to a token endpoint. `params` go into the query string (the
        broker-style endpoints); the OIDC endpoint takes everything in `data`
        and passes an empty `params`."""
        label = label or params["grant_type"]
        url = self._endpoints.url(path)
        hdrs = headers if headers is not None else self._config.basic_headers()
        with transport_errors(f"token ({label})", _PROVIDER):
            try:
                kwargs: Dict[str, Any] = {"headers": hdrs, "operation": "auth"}
                if params:
                    kwargs["params"] = params
                if data is not None:
                    kwargs["data"] = data
                else:
                    kwargs["json"] = {}
                resp = self._http.post(url, **kwargs)
                return EonTokenResponse.from_api_response(resp.json())
            except HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                if status in (400, 401, 403):
                    kind = rejected if status in rejected_statuses else AuthError
                    raise kind(f"{_PROVIDER}: {label} grant rejected (HTTP {status})") from exc
                raise error_from_exception(exc) from exc
            except ValueError as exc:       # 200 but not a token response
                raise ServerError(f"{_PROVIDER}: {label} response is not a token: {exc}") from exc

    def _grant_refresh(self, refresh: str) -> EonTokenResponse:
        if self._oidc is None:
            return self._grant({"grant_type": "refresh_token", "refresh_token": refresh})
        client = self._config.oidc_client
        # UNVERIFIED against a browser capture: the standard refresh (same Basic auth as the code exchange)
        # request. A rejection just falls through to a full login (see _login).
        body = urlencode({
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client.client_id,
        }).encode("ascii")
        return self._grant({}, data=body, headers=self._oidc_headers(), label="refresh_token",
                           path=EonDefaults.PATH_OAUTH2_TOKEN)

    # ------------------------------------------------------------------
    # OIDC flow (brands with an external identity provider)
    # ------------------------------------------------------------------
    def _oidc_headers(self) -> Dict[str, str]:
        client = self._config.oidc_client
        return {
            "User-Agent": self._config.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": client.origin,
            "Referer": client.origin + "/",
            "Accept-Language": "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
            **({"Authorization": client.basic_auth_value()} if client.client_secret else {}),
        }

    def _login_oidc(self) -> EonTokenResponse:
        creds = self._current_credentials()
        authz = self._oidc.authorize(creds.username, creds.password)   # type: ignore[union-attr]
        client = self._config.oidc_client
        body = urlencode({
            "grant_type": "authorization_code",
            "client_id": client.client_id,
            "code": authz.code,
            "redirect_uri": client.redirect_uri,
            "code_verifier": authz.code_verifier,
            "serial_number": self._oidc_serial(authz.identity_key),
            "device_type": client.device_type,
            "platform_identifier": client.platform_identifier,
        }).encode("ascii")
        # A rejected code is NOT a wrong-password verdict (that was the IdP's call
        # in authorize()): plain AuthError, so the ladder may retry with a new device.
        return self._grant({}, data=body, headers=self._oidc_headers(),
                           label="authorization_code", path=EonDefaults.PATH_OAUTH2_TOKEN)

    def _oidc_serial(self, identity_key: str) -> str:
        """Stable random seed (persisted, masked key) + the server's identity_key,
        as the web app builds it. A seed of another length (left by the password
        flow) is replaced: that device is useless for this flow anyway."""
        seed = self._store.get(K_DEVICE_SERIAL)
        if not seed or len(seed) != EonDefaults.OIDC_SERIAL_SEED_LENGTH:
            seed = "".join(secrets.choice(_OIDC_SERIAL_ALPHABET)
                           for _ in range(EonDefaults.OIDC_SERIAL_SEED_LENGTH))
            self._store.set(K_DEVICE_SERIAL, seed)
        return seed + identity_key

    def _grant_password(self) -> EonTokenResponse:
        device_number = self._store.get(K_DEVICE_NUMBER)
        if not device_number:
            raise AuthError(f"{_PROVIDER}: no device number; device registration failed")
        boundary = "----EonBoundary" + secrets.token_hex(8)
        creds = self._current_credentials()
        username_hash = hashlib.sha256(creds.username.encode("utf-8")).hexdigest().upper()
        fields = (("username", username_hash),
                  ("password", creds.password),
                  ("device_number", device_number))
        body = "".join(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'
            for name, value in fields
        ) + f"--{boundary}--"
        headers = {
            "User-Agent": self._config.user_agent,
            "Accept": "application/json",
            "Authorization": self._config.basic_auth_value(),
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        }
        # 400/401 = wrong credentials (permanent); a 403 may be a WAF -> transient.
        return self._grant({"grant_type": "password"}, data=body.encode("utf-8"), headers=headers,
                           rejected=EonLoginRejected, rejected_statuses=(400, 401))

    def _login_otp(self) -> None:
        self._ensure_device()
        device_number = self._store.get(K_DEVICE_NUMBER) or ""
        if self._pending_otp is None:
            data = self._generic_get(EonDefaults.PATH_OTP, {"deviceNumber": device_number})
            otp = data.get("otp") if isinstance(data, dict) else None
            if not otp:
                raise ServerError(f"{_PROVIDER}: OTP response has no code")
            minutes = int(data.get("expiresInSeconds") or 0) // 60
            self._pending_otp = str(otp)
            raise EonOtpRequiredError(
                f"{_PROVIDER}: confirm the one-time code {otp} in the operator's portal",
                otp=str(otp), expires_minutes=minutes,
            )
        otp, self._pending_otp = self._pending_otp, None
        try:
            self._apply(self._grant({"grant_type": "otp", "otp": otp, "device_number": device_number}))
        except AuthError as exc:
            raise AuthError(f"{_PROVIDER}: the one-time code was not confirmed or has expired") from exc

    # ------------------------------------------------------------------
    # Generic client-token calls + device registration
    # ------------------------------------------------------------------
    def _generic_call(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None,
                      body: Optional[Dict[str, Any]] = None) -> Any:
        """Call with the client token; one retry after refreshing it on 401.
        Returns the response; callers inspect `status_code` themselves."""
        func = getattr(self._http, method, None)
        if func is None:
            raise NotImplementedError(f"http_manager has no {method}()")
        url = self._endpoints.url(path)
        for attempt in (1, 2):
            headers = self._config.bearer_headers(self._client_token.get(force=attempt == 2))
            kwargs: Dict[str, Any] = {"headers": headers, "operation": "api", "raise_for_status": False}
            if params:
                kwargs["params"] = params
            if body is not None:
                kwargs["json"] = body
            resp = func(url, **kwargs)
            if resp.status_code != 401 or attempt == 2:
                return resp
        raise ServerError(f"{_PROVIDER}: unreachable")  # pragma: no cover

    def _generic_get(self, path: str, params: Dict[str, Any]) -> Any:
        with transport_errors(path, _PROVIDER):
            resp = self._generic_call("get", path, params=params)
            if resp.status_code != 200:
                if resp.status_code in (400, 401, 403):
                    raise AuthError(f"{_PROVIDER}: {path} rejected (HTTP {resp.status_code})")
                try:
                    resp.raise_for_status()
                except HTTPError as exc:
                    raise error_from_exception(exc) from exc
                raise ServerError(f"{_PROVIDER}: {path} answered HTTP {resp.status_code}")
            return resp.json()

    def _ensure_serial(self) -> str:
        serial = self._store.get(K_DEVICE_SERIAL)
        if not serial:
            serial = "".join(secrets.choice(_SERIAL_ALPHABET) for _ in range(21))
            self._store.set(K_DEVICE_SERIAL, serial)
        return serial

    def _ensure_device(self) -> None:
        if self._store.get(K_DEVICE_ID) and self._store.get(K_DEVICE_NUMBER):
            return
        self._register_device()

    def _reset_device(self) -> None:
        self.invalidate()
        self._store.delete(K_DEVICE_ID)
        self._store.delete(K_DEVICE_NUMBER)
        if self._oidc is not None:
            # No registration call in this flow: a new serial makes the token
            # endpoint mint a new device on the next login.
            self._store.delete(K_DEVICE_SERIAL)
            return
        self._register_device()

    def _register_device(self) -> None:
        """v2 (PATCH) when a deviceNumber is already known and the HTTP layer
        can PATCH; v1 (POST) mints one otherwise. A v2 answer other than
        404/405/501 is final: falling back would hide the rejection."""
        serial = self._ensure_serial()
        platform = self._config.platform
        number = self._store.get(K_DEVICE_NUMBER)

        with transport_errors("device registration", _PROVIDER):
            if number and hasattr(self._http, "patch"):
                resp = self._generic_call("patch", EonDefaults.PATH_DEVICES_V2, body={
                    "deviceNumber": number,
                    "deviceName": platform.device_name,
                    "modelName": platform.device_model,
                    "clientSwVersion": platform.client_sw_version,
                    **({"clientSwBuild": platform.client_sw_build} if platform.is_android_tv else {}),
                    "systemSwVersion": {"systemName": platform.system_sw, "version": platform.system_version},
                })
                if resp.status_code in (200, 206):
                    self._store_device(resp)
                    return
                if resp.status_code not in (404, 405, 501):
                    raise AuthError(
                        f"{_PROVIDER}: device registration rejected (HTTP {resp.status_code})"
                    )
            elif number:
                logger.warning(f"{_PROVIDER}: http_manager cannot PATCH; registering via v1")

            body: Dict[str, Any] = {
                "deviceName": platform.device_name,
                "deviceType": platform.device_type,
                "modelName": platform.device_model,
                "platform": platform.device_platform,
                "serial": serial,
                "clientSwVersion": platform.client_sw_version,
            }
            if platform.is_android_tv:
                body["clientSwBuild"] = platform.client_sw_build
            body["systemSwVersion"] = {"name": platform.system_sw, "version": platform.system_version}
            if platform.is_android_tv:
                body["fcmToken"] = ""
            resp = self._generic_call("post", EonDefaults.PATH_DEVICES_V1, body=body)
            if resp.status_code not in (200, 206):
                if resp.status_code in (400, 401, 403):
                    raise AuthError(f"{_PROVIDER}: device registration rejected (HTTP {resp.status_code})")
                raise ServerError(f"{_PROVIDER}: device registration failed (HTTP {resp.status_code})")
            self._store_device(resp)

    def _store_device(self, resp: Any) -> None:
        try:
            reg = EonDeviceRegistration.from_api_response(resp.json())
        except ValueError as exc:
            raise ServerError(f"{_PROVIDER}: {exc}") from exc
        self._store.set_many({K_DEVICE_ID: reg.device_id, K_DEVICE_NUMBER: reg.device_number})
        logger.info(f"{_PROVIDER}: device registered")