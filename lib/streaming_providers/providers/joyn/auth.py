# streaming_providers/providers/joyn/auth.py
# -*- coding: utf-8 -*-
import base64
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from ...base.auth.base_auth import BaseAuthToken, TokenAuthLevel
from ...base.auth.base_oauth2_auth import BaseOAuth2Authenticator, WafBlockedException
from ...base.auth.credentials import ClientCredentials, UserPasswordCredentials
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger
from .constants import (
    COUNTRY_TENANT_MAPPING,
    DEFAULT_COUNTRY,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_MAX_RETRIES,
    DEFAULT_PLATFORM,
    DEVICE_IDS,
    JOYN_AUTH_HEADERS_BASE,
    JOYN_CLIENT_VERSION,
    JOYN_DOMAINS,
    JOYN_OAUTH_SCOPE,
    JOYN_USER_AGENT,
    SUPPORTED_COUNTRIES,
)


@dataclass
class JoynCredentials(ClientCredentials):
    """Joyn-specific credentials for client credentials flow (anonymous auth)"""
    client_name: str = DEFAULT_PLATFORM
    country: str = DEFAULT_COUNTRY
    distribution_tenant: Optional[str] = field(default=None)

    def __post_init__(self):
        if not self.client_id:
            self.client_id = DEVICE_IDS.get(self.client_name, DEVICE_IDS[DEFAULT_PLATFORM])
        if not self.distribution_tenant and self.country in COUNTRY_TENANT_MAPPING:
            self.distribution_tenant = COUNTRY_TENANT_MAPPING[self.country]

    def validate(self) -> bool:
        return bool(self.client_id and self.client_name and self.country in SUPPORTED_COUNTRIES)

    def to_auth_payload(self) -> Dict[str, Any]:
        return {
            "client_id": self.client_id,
            "client_name": self.client_name,
            "anon_device_id": str(uuid.uuid4()),
        }

    @property
    def credential_type(self) -> str:
        return "joyn_client_credentials"


@dataclass
class JoynAuthToken(BaseAuthToken):
    """Joyn-specific authentication token"""
    refresh_token: Optional[str] = field(default="")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token or "",
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "issued_at": self.issued_at,
        }

    def get_jwt_claims(self) -> Optional[Dict[str, Any]]:
        """Extract JWT claims from access token for classification"""
        try:
            if not self.access_token:
                return None
            parts = self.access_token.split(".")
            if len(parts) != 3:
                return None
            payload_b64 = parts[1]
            padding = len(payload_b64) % 4
            if padding:
                payload_b64 += "=" * (4 - padding)
            payload_json = base64.b64decode(payload_b64).decode("utf-8")
            return json.loads(payload_json)
        except Exception as e:
            logger.debug(f"Failed to extract JWT claims: {e}")
            return None


class JoynAuthenticator(BaseOAuth2Authenticator):
    """
    Joyn authenticator based on actual network traffic logs.
    """

    def __init__(
            self,
            country: str = DEFAULT_COUNTRY,
            platform: str = DEFAULT_PLATFORM,
            settings_manager=None,
            credentials=None,
            config_dir: Optional[str] = None,
            http_manager=None,
            proxy_config: Optional[ProxyConfig] = None,
    ):
        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(f"Unsupported country: {country}")
        if http_manager is None:
            raise ValueError("http_manager is required for JoynAuthenticator")

        self.country = country
        self.platform = platform
        self.distribution_tenant = COUNTRY_TENANT_MAPPING.get(country, "JOYN")

        # Cache for flow parameters
        self._sso_endpoints_cache = None
        self._sso_endpoints_timestamp = None
        self._sso_cache_ttl = 3600
        self._cmp_uc_id = None
        self._cmp_uc_instance = None
        self._auth_base_path = None
        self._web_login_url = None
        self._extracted_client_id = None

        # Initialize base class
        super().__init__(
            provider_name="joyn",
            settings_manager=settings_manager,
            credentials=credentials,
            country=country,
            config_dir=config_dir,
            enable_kodi_integration=True,
            http_manager=http_manager,
            proxy_config=proxy_config,
        )

        # Load or generate persistent device ID
        self._device_id = self._load_or_generate_device_id()
        self._use_pkce = True

        # Create config object
        class JoynConfig:
            def __init__(self, country, platform):
                self.country = country
                self.platform = platform
                self.timeout = DEFAULT_REQUEST_TIMEOUT
                self.max_retries = DEFAULT_MAX_RETRIES
                self.user_agent = JOYN_USER_AGENT
                self.base_website = JOYN_DOMAINS.get(country, JOYN_DOMAINS["de"])

            def get_base_headers(self):
                return {
                    "User-Agent": self.user_agent,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Origin": self.base_website,
                    "joyn-client-version": JOYN_CLIENT_VERSION,
                    "joyn-country": self.country.upper(),
                    "joyn-distribution-tenant": COUNTRY_TENANT_MAPPING.get(self.country, "JOYN"),
                    "joyn-platform": self.platform,
                }

        self._config = JoynConfig(country, platform)
        self._enable_oidc_discovery = False

        if settings_manager is not None:
            settings_manager.register_provider(
                "joyn",
                supports_countries=True,
                available_countries=SUPPORTED_COUNTRIES,
            )

        # CRITICAL: Use the CORRECT web client ID
        self._client_id = DEVICE_IDS.get(self.platform, DEVICE_IDS[DEFAULT_PLATFORM])
        logger.info(f"Using Joyn client_id: {self._client_id}")

        if self.credentials is None:
            logger.info(f"No credentials for joyn/{self.country}, using anonymous fallback")
            self.credentials = self.get_fallback_credentials()

    def _load_or_generate_device_id(self) -> str:
        """Load existing device ID from settings or generate new one"""
        if self.settings_manager and hasattr(self.settings_manager, 'get_setting'):
            try:
                device_id = self.settings_manager.get_setting("joyn_device_id")
                if device_id:
                    logger.debug(f"Loaded existing device_id: {device_id}")
                    return device_id
            except Exception as e:
                logger.debug(f"Could not load device_id: {e}")

        new_device_id = str(uuid.uuid4())
        if self.settings_manager and hasattr(self.settings_manager, 'set_setting'):
            try:
                self.settings_manager.set_setting("joyn_device_id", new_device_id)
            except Exception as e:
                logger.debug(f"Could not save device_id: {e}")

        logger.debug(f"Generated new device_id: {new_device_id}")
        return new_device_id

    @property
    def oauth_client_id(self) -> str:
        return self._client_id

    @property
    def oauth_scope(self) -> str:
        return JOYN_OAUTH_SCOPE

    @property
    def oauth_redirect_uri(self) -> str:
        from .constants import get_oauth_redirect_uri
        return get_oauth_redirect_uri(self.country)

    def _discover_sso_endpoints(self) -> Dict[str, str]:
        """Discover Joyn's SSO endpoints and keep the server-issued web-login URL and client_id as-is."""
        if self._sso_endpoints_cache and self._sso_endpoints_timestamp:
            if (time.time() - self._sso_endpoints_timestamp) < self._sso_cache_ttl:
                return self._sso_endpoints_cache

        try:
            # Use the locally-generated per-install device id for discovery, matching the
            # reference client's `client_ids['client_id']` (NOT the fixed DEVICE_IDS constant).
            url = f"https://auth.joyn.de/sso/endpoints?client_id={self._device_id}&client_name={self.platform}"
            headers = self._get_joyn_auth_headers()

            response = self.http_manager.get(
                url,
                operation="sso_discovery",
                headers=headers,
                timeout=getattr(self.config, "timeout", 30)
            )
            response.raise_for_status()

            endpoints = response.json()

            # Keep the full, unmodified web-login URL. The server embeds its own client_id
            # and tracking params (cmpUcId, cmpUcInstance) in this URL; the reference client
            # GETs this URL verbatim rather than reconstructing an authorize URL by hand.
            auth_endpoint_full = endpoints.get("web-login", "")
            self._web_login_url = auth_endpoint_full

            parsed_auth = urlparse(auth_endpoint_full)
            self._auth_base_path = urlunparse((
                parsed_auth.scheme,
                parsed_auth.netloc,
                parsed_auth.path,
                "", "", ""
            ))

            # Extract the server-issued client_id and tracking params for reuse in
            # consent-accept and redeem-token calls later in the flow.
            params = parse_qs(parsed_auth.query)
            self._extracted_client_id = params.get("client_id", [None])[0]
            self._cmp_uc_id = params.get("cmpUcId", [None])[0]
            self._cmp_uc_instance = params.get("cmpUcInstance", [None])[0]

            self._sso_endpoints_cache = {
                "authorization_base_path": self._auth_base_path,
                "web_login_url": self._web_login_url,
                "client_id": self._extracted_client_id,
                "token_endpoint": endpoints.get("redeem-token", "https://auth.joyn.de/auth/7pass/token"),
            }

            self._sso_endpoints_timestamp = time.time()
            logger.debug(f"Discovered web-login URL: {self._web_login_url}")
            logger.debug(f"Extracted client_id: {self._extracted_client_id}")

            return self._sso_endpoints_cache

        except Exception as e:
            logger.warning(f"Failed to discover SSO endpoints: {e}")
            self._auth_base_path = "https://auth.7pass.de/authz-srv/authz"
            return {
                "authorization_base_path": self._auth_base_path,
                "token_endpoint": "https://auth.joyn.de/auth/7pass/token",
            }

    @property
    def oauth_authorize_endpoint(self) -> str:
        """Get clean authorization base path"""
        self._discover_sso_endpoints()
        return self._auth_base_path or "https://auth.7pass.de/authz-srv/authz"

    @property
    def oauth_token_endpoint(self) -> str:
        endpoints = self._discover_sso_endpoints()
        return endpoints.get("token_endpoint", "https://auth.joyn.de/auth/7pass/token")

    def _get_joyn_auth_headers(self) -> Dict[str, str]:
        headers = JOYN_AUTH_HEADERS_BASE.copy()
        headers.update({
            "Origin": JOYN_DOMAINS.get(self.country, JOYN_DOMAINS["de"]),
            "joyn-country": self.country.upper(),
            "joyn-distribution-tenant": f"JOYN_{self.country.upper()}",
            "joyn-platform": self.platform,
            "joyn-request-id": str(uuid.uuid4()),
            "Content-Type": "application/json",
        })
        return headers

    def _get_auth_headers(self) -> Dict[str, str]:
        return self._get_joyn_auth_headers()

    def _should_use_json_for_token_exchange(self, **kwargs) -> bool:
        return True

    def _build_token_exchange_payload(
            self, authorization_code: str, code_verifier: str, state: str = None, **kwargs
    ) -> Dict[str, Any]:
        payload = super()._build_token_exchange_payload(
            authorization_code=authorization_code,
            code_verifier=code_verifier,
            state=state,
            **kwargs
        )

        cd1 = kwargs.get('cd1')
        if cd1 is None:
            cd1 = self._device_id

        if cd1:
            payload["tracking_id"] = cd1
            payload["tracking_name"] = self.platform

        return payload

    def _get_token_exchange_endpoint(self, **kwargs) -> str:
        return self.oauth_token_endpoint

    def _get_token_exchange_headers(self, **kwargs) -> Dict[str, str]:
        headers = super()._get_token_exchange_headers(**kwargs)
        joyn_headers = self._get_joyn_auth_headers()
        for key, value in joyn_headers.items():
            if key not in headers:
                headers[key] = value
        return headers

    def _refresh_oauth_token(self) -> Optional[BaseAuthToken]:
        if not self._current_token or not self._current_token.refresh_token:
            return None

        try:
            if hasattr(self._current_token, 'get_jwt_claims'):
                claims = self._current_token.get_jwt_claims()
                if claims and claims.get("jIdC", "").startswith("JNAA-"):
                    logger.debug("Anonymous token cannot be refreshed")
                    return None

            return super()._refresh_oauth_token()
        except Exception as e:
            logger.warning(f"Token refresh failed: {e}")
            return None

    def _perform_oauth_authorization_code_flow(self, username: str, password: str) -> Dict[str, Any]:
        """Complete Joyn login flow matching the exact sequence observed from working traffic.

        Joyn does not implement real PKCE (code_verifier is always sent empty in the
        redeem-token call) and does not use a verification-srv/initiate + device-fingerprint
        mechanism. The client_id used for consent-accept and redeem-token is the one the
        server itself embeds in the web-login redirect URL, not a fixed platform constant.
        """
        try:
            logger.debug("Starting Joyn login flow")

            # Discover endpoints - gives us the literal web-login URL and its embedded client_id
            self._discover_sso_endpoints()

            if not self._web_login_url:
                raise Exception("Failed to get web-login URL from SSO discovery")

            client_id = self._extracted_client_id or self.oauth_client_id
            cd1 = self._device_id

            session = self._create_oauth_session()
            # SessionAwareHTTPManager pre-loads Origin/Referer/User-Agent for the Joyn
            # website and applies them AFTER our per-call headers, silently overriding
            # them. We set explicit, per-step headers below (different Origin for
            # auth.7pass.de vs auth.joyn.de), so clear the defaults here.
            session.headers.clear()

            def _request(method, url, **kwargs):
                headers = kwargs.pop("headers", {}).copy()
                # joyn-* headers don't belong on calls to the 7pass.de auth domain;
                # they're only sent on calls to Joyn's own auth.joyn.de endpoints
                # (SSO discovery, redeem-token), matching the reference client.
                if "auth.7pass.de" in url:
                    clean_headers = {
                        k: v for k, v in headers.items()
                        if not k.lower().startswith('joyn-')
                    }
                else:
                    clean_headers = dict(headers)
                clean_headers.setdefault("User-Agent", JOYN_USER_AGENT)
                clean_headers.setdefault("Accept", "*/*")
                # Browser-realistic headers to prevent Cloudflare managed challenges.
                # CF uses sec-fetch-* and ch-ua hints to distinguish real browsers from bots.
                clean_headers.setdefault("Accept-Language", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7")
                clean_headers.setdefault("Accept-Encoding", "gzip, deflate, br")
                clean_headers.setdefault("Cache-Control", "no-cache")
                clean_headers.setdefault("Pragma", "no-cache")
                clean_headers.setdefault("sec-ch-ua", '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"')
                clean_headers.setdefault("sec-ch-ua-mobile", "?0")
                clean_headers.setdefault("sec-ch-ua-platform", '"Windows"')
                if method.upper() == "POST":
                    clean_headers.setdefault("Sec-Fetch-Site", "same-site")
                    clean_headers.setdefault("Sec-Fetch-Mode", "cors")
                    clean_headers.setdefault("Sec-Fetch-Dest", "empty")
                else:
                    clean_headers.setdefault("Sec-Fetch-Site", "none")
                    clean_headers.setdefault("Sec-Fetch-Mode", "navigate")
                    clean_headers.setdefault("Sec-Fetch-Dest", "document")
                    clean_headers.setdefault("Sec-Fetch-User", "?1")

                content_type = kwargs.pop("content_type", None)
                if content_type:
                    clean_headers["Content-Type"] = content_type

                allow_redirects = kwargs.pop("allow_redirects", True)
                timeout = getattr(self.config, "timeout", 30)

                if method.upper() == "GET":
                    return session.get(url, headers=clean_headers, timeout=timeout,
                                       allow_redirects=allow_redirects, **kwargs)
                else:
                    return session.post(url, headers=clean_headers, timeout=timeout,
                                        allow_redirects=allow_redirects, **kwargs)

            def _check_cf(response):
                """Raise WafBlockedException if response is a Cloudflare challenge page."""
                if "Just a moment" in response.text or "challenge-platform" in response.text:
                    raise WafBlockedException("Cloudflare managed challenge detected")

            def _raise_if_cf_error(e):
                """http_manager raises HTTPError before we see the response, so 403/429
                Cloudflare challenges must be detected from the exception's response body."""
                resp = getattr(e, "response", None)
                raw = getattr(resp, "text", str(e))
                if "Just a moment" in raw or "challenge-platform" in raw or "captcha" in raw.lower():
                    raise WafBlockedException(f"Cloudflare/CAPTCHA block: {e}")
                if resp is not None and resp.status_code in (403, 429):
                    raise WafBlockedException(f"Joyn login blocked by WAF ({resp.status_code}): {e}")

            # 1. GET the literal web-login URL as issued by the server (do not rebuild it)
            try:
                response = _request("GET", self._web_login_url, allow_redirects=True)
            except WafBlockedException:
                raise
            except Exception as e:
                _raise_if_cf_error(e)
                raise
            _check_cf(response)

            final_url = response.url

            if "error.html" in final_url or "error_code" in final_url:
                error_match = re.search(r'error_code=(\d+)', final_url)
                error_code = error_match.group(1) if error_match else "unknown"
                raise Exception(f"Authorization failed: error_code={error_code}")

            parsed_url = urlparse(final_url)
            query_params = parse_qs(parsed_url.query)
            request_id = query_params.get("requestId", [None])[0]

            if not request_id:
                match = re.search(r'requestId["\']?\s*[=:]\s*["\']([^"\']+)', response.text)
                if match:
                    request_id = match.group(1)

            if not request_id:
                raise Exception("Could not extract request_id from response")

            logger.debug(f"Extracted request_id: {request_id}")

            # 2. Language/registration-setup check — non-fatal
            try:
                _request(
                    "GET",
                    f"https://auth.7pass.de/registration-setup-srv/public/list?acceptlanguage=undefined&requestId={request_id}",
                )
            except Exception as e:
                logger.debug(f"registration-setup failed (non-fatal): {e}")

            # 3. Check whether the email exists — non-fatal
            try:
                _request(
                    "POST",
                    f"https://auth.7pass.de/users-srv/user/checkexists/{request_id}",
                    json={"email": username, "requestId": request_id},
                    content_type="application/json",
                )
            except Exception as e:
                logger.debug(f"checkexists failed (non-fatal): {e}")

            # 4. Configured verification methods list — non-fatal
            try:
                _request(
                    "POST",
                    "https://auth.7pass.de/verification-srv/v2/setup/public/configured/list",
                    json={"email": username, "request_id": request_id},
                    content_type="application/json",
                )
            except Exception as e:
                logger.debug(f"verification-srv failed (non-fatal): {e}")

            # 5. Submit username/password directly (form-encoded)
            try:
                login_response = _request(
                    "POST",
                    "https://auth.7pass.de/login-srv/login",
                    data=urlencode({
                        "username": username,
                        "password": password,
                        "requestId": request_id,
                    }).encode(),
                    content_type="application/x-www-form-urlencoded",
                    allow_redirects=True,
                )
            except WafBlockedException:
                raise
            except Exception as e:
                _raise_if_cf_error(e)
                raise

            _check_cf(login_response)
            final_url = login_response.url
            parsed = urlparse(final_url)
            params = parse_qs(parsed.query)

            # 6. Handle consent if the server didn't return a code directly
            if params.get("code") is None:
                sub = params.get("sub", [None])[0]
                track_id = params.get("track_id", [None])[0]

                if sub and track_id:
                    logger.debug(f"Accepting consent for sub={sub}")
                    try:
                        _request(
                            "POST",
                            "https://auth.7pass.de/consent-management-srv/consent/scope/accept",
                            json={
                                "sub": sub,
                                "client_id": client_id,
                                "scopes": [{"offline_access": "denied"}],
                            },
                            content_type="application/json",
                        )
                    except WafBlockedException:
                        raise
                    except Exception as e:
                        _raise_if_cf_error(e)
                        raise

                    try:
                        continue_response = _request(
                            "POST",
                            f"https://auth.7pass.de/login-srv/precheck/continue/{track_id}",
                            data=b"",
                            content_type="application/x-www-form-urlencoded",
                            allow_redirects=True,
                        )
                    except WafBlockedException:
                        raise
                    except Exception as e:
                        _raise_if_cf_error(e)
                        raise
                    final_url = continue_response.url
                    parsed = urlparse(final_url)
                    params = parse_qs(parsed.query)

            auth_code = params.get("code", [None])[0]
            if not auth_code:
                raise Exception("No authorization code in response")

            logger.debug("Authorization code obtained")

            # 7. Redeem the code directly. Joyn does not implement real PKCE — the working
            # client always sends code_verifier as an empty string here.
            cd1_value = params.get("cd1", [None])[0] or cd1
            redeem_data = {
                "client_id": client_id,
                "code": auth_code,
                "code_verifier": "",
                "redirect_uri": self.oauth_redirect_uri,
                "tracking_id": cd1_value,
                "tracking_name": self.platform,
            }

            try:
                redeem_response = _request(
                    "POST",
                    self.oauth_token_endpoint,
                    json=redeem_data,
                    content_type="application/json",
                    headers=self._get_joyn_auth_headers(),
                    allow_redirects=False,
                )
            except WafBlockedException:
                raise
            except Exception as e:
                _raise_if_cf_error(e)
                raise

            _check_cf(redeem_response)
            token_data = redeem_response.json()

            logger.info("Joyn login flow successful")
            return token_data

        except WafBlockedException:
            raise
        except Exception as e:
            logger.error(f"Joyn login flow failed: {e}")
            raise

    def authenticate_with_fallback(self, username: str, password: str) -> Dict[str, Any]:
        try:
            return self._perform_oauth_authorization_code_flow(username, password)
        except WafBlockedException as e:
            logger.warning(f"{self.provider_name}: WAF block detected ({e}), trying remote login")
            try:
                return self._perform_remote_login_flow()
            except Exception as remote_err:
                logger.warning(
                    f"{self.provider_name}: Remote login failed ({remote_err}), falling back to client credentials")
                return self._perform_oauth_client_credentials_flow()
        except Exception as e:
            logger.warning(f"{self.provider_name}: Login failed ({e}), falling back to client credentials")
            return self._perform_oauth_client_credentials_flow()

    def _perform_oauth_client_credentials_flow(self) -> Dict[str, Any]:
        try:
            logger.info(f"Starting client credentials flow")

            payload = {
                "client_id": self.oauth_client_id,
                "client_name": self.platform,
                "anon_device_id": self._device_id
            }

            anonymous_token_url = "https://auth.joyn.de/auth/anonymous"

            headers = {
                "Content-Type": "application/json",
                "User-Agent": JOYN_USER_AGENT,
                "Accept": "application/json",
                "Origin": JOYN_DOMAINS.get(self.country, JOYN_DOMAINS["de"]),
            }

            logger.debug(f"Anonymous token request to {anonymous_token_url} with client_id: {payload['client_id']}")

            response = self.http_manager.post(
                anonymous_token_url,
                operation="auth",
                headers=headers,
                json_data=payload,
                timeout=getattr(self.config, "timeout", 30)
            )

            self._check_oauth_error_response(response)
            response.raise_for_status()
            token_data = response.json()

            logger.info(f"Client credentials flow successful")
            return token_data

        except Exception as e:
            logger.error(f"Client credentials flow failed: {e}")
            raise

    def get_fallback_credentials(self) -> JoynCredentials:
        return JoynCredentials(
            client_id=self._client_id,
            client_secret="",
            country=self.country,
        )

    def _build_auth_payload(self) -> Dict[str, Any]:
        if not self.credentials:
            raise Exception("No credentials available")
        return self.credentials.to_auth_payload()

    def _create_token_from_response(self, response_data: Dict[str, Any]) -> BaseAuthToken:
        token = JoynAuthToken(
            access_token=response_data["access_token"],
            refresh_token=response_data.get("refresh_token", ""),
            token_type=response_data.get("token_type", "Bearer"),
            expires_in=response_data.get("expires_in", 86400),
            issued_at=response_data.get("issued_at", time.time()),
        )
        token.auth_level = self._classify_token(token)
        return token

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        try:
            if not token or not token.access_token:
                return TokenAuthLevel.UNKNOWN

            claims = token.get_jwt_claims() if hasattr(token, "get_jwt_claims") else None
            if not claims:
                return TokenAuthLevel.UNKNOWN

            jidc = claims.get("jIdC", "")
            if jidc.startswith("JNAA-"):
                return TokenAuthLevel.CLIENT_CREDENTIALS
            elif jidc.startswith("JNDE-"):
                return TokenAuthLevel.USER_AUTHENTICATED

            if "social_id" in claims:
                return TokenAuthLevel.USER_AUTHENTICATED

            return TokenAuthLevel.UNKNOWN
        except Exception as e:
            logger.error(f"Error classifying token: {e}")
            return TokenAuthLevel.UNKNOWN

    def _perform_authentication(self) -> BaseAuthToken:
        if isinstance(self.credentials, UserPasswordCredentials):
            token_data = self.authenticate_with_fallback(
                self.credentials.username, self.credentials.password
            )
        else:
            token_data = self._perform_oauth_client_credentials_flow()

        return self._create_token_from_response(token_data)

    def get_bearer_token(self, force_refresh: bool = False, force_upgrade: bool = False) -> str:
        return super().get_bearer_token(force_refresh=force_refresh, force_upgrade=force_upgrade)

    def is_authenticated(self) -> bool:
        return self._current_token is not None and not self._current_token.is_expired

    def invalidate_token(self) -> None:
        self._current_token = None
        try:
            self.settings_manager.clear_token(self.provider_name)
        except (AttributeError, KeyError, IOError, OSError):
            pass

    def debug_token_classification(self) -> Dict[str, Any]:
        if not self._current_token:
            return {"error": "No current token"}

        claims = self._current_token.get_jwt_claims() if hasattr(self._current_token, "get_jwt_claims") else {}

        return {
            "token_type": type(self._current_token).__name__,
            "auth_level": self._current_token.auth_level.value,
            "is_expired": self._current_token.is_expired,
            "has_refresh": bool(self._current_token.refresh_token),
            "jwt_claims_available": bool(claims),
            "key_claims": {
                "jIdC": claims.get("jIdC", "MISSING"),
                "cId": claims.get("cId", "MISSING"),
                "social_id": "PRESENT" if "social_id" in claims else "MISSING",
            } if claims else {},
        }