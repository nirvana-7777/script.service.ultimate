# streaming_providers/providers/discovery/auth.py
"""
Discovery+ Authentication

Handles authentication for Discovery+ including anonymous and user credentials.
Supports two-step token negotiation with session headers.
"""
import time
import uuid

import requests
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ...base.auth.base_auth import BaseAuthenticator, BaseAuthToken, TokenAuthLevel
from ...base.auth.credentials import BaseCredentials, UserPasswordCredentials
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger

from .constants import (
    DEFAULT_DEVICE_ID,
    DEFAULT_ENV,
    DEFAULT_REALM,
    DEFAULT_TENANT,
    DISCOVERY_ARKOSE_DATA_PAYLOAD,
    DISCOVERY_ARKOSE_DATA_URL,
    DISCOVERY_ARKOSE_FC_URL,
    DISCOVERY_ARKOSE_SITEKEY,
    DISCOVERY_AUTH_ORIGIN,
    DISCOVERY_AUTH_REFERER,
    DISCOVERY_BOOTSTRAP_URL,
    DISCOVERY_CLIENT_ID_PREFIX,
    DISCOVERY_DEVICE_CONSENT,
    DISCOVERY_DEFAULT_TIMEZONE,
    DISCOVERY_DEVICE_INFO_TEMPLATE,
    DISCOVERY_DISCO_CLIENT,
    DISCOVERY_DISCO_PARAMS,
    DISCOVERY_GISDK_CLIENT_ID,
    DISCOVERY_USER_AGENT,
    HOME_MARKET_MAPPING,
    AuthProvider,
)
from .exceptions import (
    InvalidCredentialsError,
    UnsupportedCredentialTypeError,
    EndpointDiscoveryError,
)


@dataclass
class DiscoveryAnonymousCredentials(BaseCredentials):
    """Discovery+ anonymous credentials - no client_id/secret needed"""

    realm: str = DEFAULT_REALM

    def validate(self) -> bool:
        """Validate anonymous credentials"""
        return bool(self.realm)

    @property
    def credential_type(self) -> str:
        return "discovery_anonymous"

    def to_auth_payload(self) -> Dict[str, Any]:
        """
        Convert to authentication payload.

        For anonymous auth, Discovery+ uses query parameters, not a payload.
        Return empty dict as this method is required by BaseCredentials.
        """
        return {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage"""
        return {
            "type": self.credential_type,
            "realm": self.realm,
        }


@dataclass
class DiscoveryUserCredentials(UserPasswordCredentials):
    """Discovery+ user credentials"""

    provider: str = AuthProvider.USERNAME_PASSWORD.value

    def to_login_payload(self) -> Dict[str, Any]:
        """
        Convert to login payload for API request.

        Returns:
            Dictionary formatted for Discovery+ login API
        """
        return {
            "credentials": {
                "password": self.password,
                "username": self.username,
                "provider": self.provider,
            }
        }

    @property
    def credential_type(self) -> str:
        return "discovery_user"


@dataclass
class DiscoveryAuthToken(BaseAuthToken):
    """Discovery+ authentication token"""

    refresh_token: Optional[str] = field(default=None)
    realm: Optional[str] = field(default=None)
    anonymous: bool = field(default=True)
    token_id: Optional[str] = field(default=None)
    st_cookie: Optional[str] = field(default=None)  # long-lived session cookie

    @classmethod
    def from_token_response(
            cls,
            response_data: Dict[str, Any],
            response=None,
    ) -> "DiscoveryAuthToken":
        """
        Create token from API response.

        Args:
            response_data: Parsed JSON body from /token or /login response
            response: Optional raw requests.Response — used to extract the
                      st= session cookie which is the true session credential.

        Returns:
            Initialized DiscoveryAuthToken
        """
        data = response_data.get("data", {})
        attributes = data.get("attributes", {})

        # Extract st= cookie from the response if available.
        # This is the long-lived session cookie that allows re-deriving
        # the access token on subsequent /token calls without re-login.
        st_cookie = None
        if response is not None:
            st_cookie = response.cookies.get("st")

        token = cls(
            access_token=attributes.get("token", ""),
            token_type="Bearer",
            expires_in=31536000,  # Default 1 year
            issued_at=time.time(),
            realm=attributes.get("realm"),
            anonymous=attributes.get("anonymous", True),
            token_id=data.get("id"),
            st_cookie=st_cookie,
        )

        # Parse JWT for more accurate expiration
        token._parse_jwt_expiration()
        return token

    def _parse_jwt_expiration(self) -> None:
        """
        Extract expiration from JWT token.

        Updates expires_in based on JWT exp claim if present.
        """
        try:
            parts = self.access_token.split(".")
            if len(parts) == 3:
                import base64
                import json

                payload_b64 = parts[1]
                # Add padding if needed
                padding = len(payload_b64) % 4
                if padding:
                    payload_b64 += "=" * (4 - padding)

                payload = json.loads(base64.b64decode(payload_b64))
                if "exp" in payload:
                    self.expires_in = payload["exp"] - self.issued_at
        except Exception:
            # If JWT parsing fails, keep default expiration
            pass

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert token to dictionary.

        Returns:
            Dictionary representation of the token
        """
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "issued_at": self.issued_at,
            "realm": self.realm,
            "anonymous": self.anonymous,
            "token_id": self.token_id,
            "st_cookie": self.st_cookie,
        }


class DiscoveryAuthenticator(BaseAuthenticator):
    """
    Discovery+ authenticator with dynamic endpoint discovery.

    Supports:
    - Anonymous authentication (two-step token negotiation)
    - User credentials (username/password upgrade from anonymous token)
    - Dynamic endpoint discovery from bootstrap
    - Session header persistence (x-disco-id, x-wbd-session-state, x-wbd-ace)

    Auth flows:
      Anonymous : GET /token (no headers) → 400 + session headers
                  → GET /token (with session headers) → 200 + anon token
                  → GET /bootstrap (with session headers + Bearer anon token)
                    → 200 + full endpoint/routing map

      User      : [same two-step /token negotiation]
                  → POST /login (Authorization: Bearer <anon_token>) → 200 + user token
                  → GET /bootstrap (with session headers + Bearer user token)
                    → 200 + full endpoint/routing map

    Bootstrap is always called AFTER a token is obtained so it receives proper
    session headers and an Authorization header, allowing it to return the
    correct country-specific endpoint routing rather than a generic/empty 400.

    Note: Discovery+ uses simple token-based auth, not OAuth2.
    """

    @staticmethod
    def _promote_credentials(credentials):
        """
        Ensure credentials are Discovery-specific types rather than bare base classes.

        The credential manager deserialises stored credentials as plain
        UserPasswordCredentials. Promoting them here means every downstream
        isinstance(..., DiscoveryUserCredentials) check works correctly without
        requiring changes to shared infrastructure.
        """
        from ...base.auth.credentials import UserPasswordCredentials as BaseUPC

        if isinstance(credentials, BaseUPC) and not isinstance(credentials, DiscoveryUserCredentials):
            return DiscoveryUserCredentials(
                username=credentials.username,
                password=credentials.password,
            )
        return credentials

    def __init__(
            self,
            country: str = "de",
            settings_manager=None,
            credentials=None,
            config_dir: Optional[str] = None,
            http_manager=None,
            proxy_config: Optional[ProxyConfig] = None,
    ):
        self.country = country
        self.home_market = HOME_MARKET_MAPPING.get(country, "emea")
        self.tenant = DEFAULT_TENANT
        self.env = DEFAULT_ENV
        self.device_id = DEFAULT_DEVICE_ID

        # Session headers storage (from /token 400 response)
        self._session_state: Optional[str] = None
        self._disco_id: Optional[str] = None
        self._wbd_ace: Optional[str] = None

        # Store http_manager and proxy_config BEFORE calling super().__init__
        self._http_manager = http_manager
        self._proxy_config = proxy_config
        self._endpoints: Dict[str, str] = {}
        self._api_groups: Dict[str, Any] = {}
        self._routing: Dict[str, Any] = {}

        # Promote credentials to Discovery-specific type before passing to super,
        # so that isinstance checks throughout the auth flow work correctly.
        # The credential manager returns bare UserPasswordCredentials; wrapping
        # here ensures DiscoveryUserCredentials is used consistently.
        promoted_credentials = self._promote_credentials(credentials) if credentials else None
        logger.debug(
            f"Discovery __init__: original={type(credentials).__name__}, "
            f"promoted={type(promoted_credentials).__name__}"
        )

        # Call parent __init__ (BaseAuthenticator signature)
        super().__init__(
            provider_name="discovery",
            settings_manager=settings_manager,
            credentials=promoted_credentials,
            country=country,
            config_dir=config_dir,
            enable_kodi_integration=True,
        )

        logger.debug(f"Discovery __init__ post-super: self.credentials={type(self.credentials).__name__}")

        # If no credentials were provided at construction time, attempt to load
        # from storage. Promote here too — the credential manager always returns
        # bare base-class instances.
        if not self.credentials:
            raw = self._load_credentials_from_manager()
            if raw:
                self.credentials = self._promote_credentials(raw)
                logger.info(f"Loaded stored credentials for discovery ({country})")

    @property
    def http_manager(self):
        """
        Get or create HTTP manager.

        Returns:
            HTTP manager instance

        Raises:
            RuntimeError: If HTTP manager cannot be created
        """
        if self._http_manager is not None:
            return self._http_manager

        logger.warning(
            f"No HTTP manager available for {self.provider_name}, creating one"
        )

        try:
            from ...base.network import HTTPManagerFactory

            self._http_manager = HTTPManagerFactory.create_for_provider(
                self.provider_name,
                proxy_config=self._proxy_config,
                user_agent=DISCOVERY_USER_AGENT,
                timeout=30,
            )
        except Exception as e:
            logger.error(f"Error creating HTTP manager: {e}")
            raise RuntimeError(
                f"Cannot create HTTP manager for {self.provider_name}: {e}"
            )

        return self._http_manager

    def _discover_endpoints(self, auth_headers: Dict[str, str]) -> None:
        """
        Discover API endpoints from bootstrap using an authenticated session.

        Bootstrap is a POST with an empty JSON body {}. It requires:
          - Authorization: Bearer <token>
          - Full session headers (x-disco-id, x-wbd-session-state, x-wbd-ace)
            populated from the /token negotiation.

        Must be called AFTER a token has been obtained so all of the above
        are available.

        Args:
            auth_headers: Headers including Authorization and all session headers,
                          as built by _build_authenticated_headers().
        """
        try:
            logger.debug(f"Discovering endpoints for Discovery+ ({self.country})")

            # Bootstrap is a POST with empty body — not a GET.
            # http_manager.post() calls raise_for_status() internally, so we
            # catch HTTPError and inspect the response ourselves to avoid
            # treating a non-200 as a hard failure.
            try:
                response = self.http_manager.post(
                    DISCOVERY_BOOTSTRAP_URL,
                    operation="bootstrap",
                    headers=auth_headers,
                    json_data={},
                    timeout=30,
                )
            except requests.exceptions.HTTPError as e:
                status = e.response.status_code if e.response is not None else "unknown"
                body = ""
                if e.response is not None:
                    try:
                        body = f" — body: {e.response.json()}"
                    except Exception:
                        body = f" — body: {e.response.text[:200]}"
                logger.warning(
                    f"Bootstrap returned {status}{body} — falling back to hardcoded endpoints"
                )
                return

            try:
                data = response.json()
            except Exception as parse_err:
                logger.warning(
                    f"Could not parse bootstrap response: {parse_err}. "
                    "Falling back to hardcoded endpoints."
                )
                return

            # Store routing info
            self._routing = data.get("routing", {})
            self._api_groups = data.get("apiGroups", {})

            # Build endpoint map
            self._endpoints = {}
            for endpoint in data.get("endpoints", []):
                path = endpoint.get("path")
                api_group = endpoint.get("apiGroup")
                if path and api_group and api_group in self._api_groups:
                    base_url = self._build_api_url(api_group)
                    if base_url:
                        self._endpoints[path] = f"{base_url}{path}"

            logger.debug(
                f"Discovered {len(self._endpoints)} endpoints from bootstrap"
            )

        except Exception as e:
            logger.warning(f"Failed to discover endpoints: {e}")

    def _build_api_url(self, api_group: str) -> Optional[str]:
        """
        Build API URL from apiGroup template.

        Args:
            api_group: API group identifier

        Returns:
            Constructed API URL or None if template not found
        """
        if not self._api_groups or api_group not in self._api_groups:
            return None

        template = self._api_groups[api_group].get("baseUrl", "")
        if not template:
            return None

        # Replace placeholders
        replacements = {
            "{tenant}": self.tenant,
            "{homeMarket}": self.home_market,
            "{env}": self.env,
            "{domain}": "api.discoveryplus.com",
        }

        url = template
        for key, value in replacements.items():
            url = url.replace(key, value)

        return url

    def get_endpoint(self, path: str) -> Optional[str]:
        """
        Get full URL for an endpoint path discovered from bootstrap.

        Args:
            path: Endpoint path (e.g., '/token')

        Returns:
            Full endpoint URL or None if not yet discovered (fallbacks apply)
        """
        return self._endpoints.get(path)

    @property
    def auth_endpoint(self) -> str:
        """
        Get authentication endpoint URL (required by BaseAuthenticator).

        For Discovery+, this returns the login endpoint for user auth
        or token endpoint for anonymous auth.

        Returns:
            Authentication endpoint URL
        """
        return self.login_endpoint

    @property
    def token_endpoint(self) -> str:
        """Get token endpoint URL"""
        endpoint = self.get_endpoint("/token")
        if endpoint:
            return endpoint
        return f"https://default.any-any.{self.env}.api.discoveryplus.com/token"

    @property
    def login_endpoint(self) -> str:
        """Get login endpoint URL"""
        endpoint = self.get_endpoint("/login")
        if endpoint:
            return endpoint
        bolt_any = self._build_api_url("bolt-any-homemarket")
        return (
            f"{bolt_any}/login" if bolt_any
            else "https://default.any-emea.prd.api.discoveryplus.com/login"
        )

    @property
    def playback_endpoint(self) -> str:
        """Get playback endpoint URL"""
        endpoint = self.get_endpoint("/any/playback/v1/playbackInfo")
        if endpoint:
            return endpoint
        bolt_any = self._build_api_url("bolt-any-homemarket")
        return (
            f"{bolt_any}/any/playback/v1/playbackInfo" if bolt_any
            else "https://default.any-any.prd.api.discoveryplus.com/any/playback/v1/playbackInfo"
        )

    @property
    def cms_home_endpoint(self) -> str:
        """Get CMS home endpoint URL"""
        endpoint = self.get_endpoint("/cms/routes/home")
        if endpoint:
            return endpoint
        bolt_any = self._build_api_url("bolt-any-homemarket")
        return (
            f"{bolt_any}/cms/routes/home" if bolt_any
            else "https://default.any-any.prd.api.discoveryplus.com/cms/routes/home"
        )

    @property
    def cms_collections_endpoint(self) -> str:
        """Get CMS collections endpoint URL"""
        endpoint = self.get_endpoint("/cms/collections")
        if endpoint:
            return endpoint
        bolt_any = self._build_api_url("bolt-any-homemarket")
        return (
            f"{bolt_any}/cms/collections" if bolt_any
            else "https://default.any-any.prd.api.discoveryplus.com/cms/collections"
        )

    def _build_client_id(self) -> str:
        """
        Build x-disco-client-id header value.

        Format: web1_{env}:{timestamp}:{hmac_sha256}
        The HMAC-SHA256 is computed over "{prefix}:{timestamp}" using the
        GI SDK client ID as the key.

        Returns:
            Client ID string
        """
        import hashlib
        import hmac as hmac_lib

        timestamp = str(int(time.time()))
        message = f"{DISCOVERY_CLIENT_ID_PREFIX}:{timestamp}"
        signature = hmac_lib.new(
            DISCOVERY_GISDK_CLIENT_ID.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"{message}:{signature}"

    def _build_device_info(self) -> str:
        """
        Build x-device-info header.

        Format: dplus/<version> (desktop/desktop; Linux/x86_64; device-id/session-id)
        """
        device_id = self.device_id or DEFAULT_DEVICE_ID
        session_id = str(uuid.uuid4())
        return DISCOVERY_DEVICE_INFO_TEMPLATE.format(
            device_id=device_id, session_id=session_id
        )

    def _build_base_headers(self) -> Dict[str, str]:
        """
        Build base headers for all requests, including session headers if available.

        Returns:
            Dictionary of HTTP headers
        """
        headers = {
            "User-Agent": DISCOVERY_USER_AGENT,
            "x-device-info": self._build_device_info(),
            "x-disco-client": DISCOVERY_DISCO_CLIENT,
            "x-disco-client-id": self._build_client_id(),
            "x-disco-params": DISCOVERY_DISCO_PARAMS,
            "x-gisdk": f"clientId={DISCOVERY_GISDK_CLIENT_ID}",
            "x-wbd-device-consent": DISCOVERY_DEVICE_CONSENT,
            "x-wbd-preferred-language": f"{self.country.lower()}-DE",
            "x-wbd-time-zone": DISCOVERY_DEFAULT_TIMEZONE,
        }

        # Add session headers if we have them (from /token 400 response)
        if self._disco_id:
            headers["x-disco-id"] = self._disco_id
        if self._session_state:
            headers["x-wbd-session-state"] = self._session_state
        if self._wbd_ace:
            headers["x-wbd-ace"] = self._wbd_ace

        return headers

    def _get_auth_headers(self) -> Dict[str, str]:
        """
        Get headers for authentication request.

        Returns:
            Dictionary of HTTP headers
        """
        return self._build_base_headers()

    def _build_authenticated_headers(self, token: BaseAuthToken) -> Dict[str, str]:
        """
        Build headers for post-auth requests (bootstrap, CMS, playback).

        Combines session headers (populated during /token negotiation) with:
          - Authorization: Bearer <token>
          - Content-Type: application/json
          - Origin / Referer (required by bootstrap)
          - x-wbd-session-state updated to include the token segment, which
            the server expects after authentication completes. The session
            state is a semicolon-separated list of named JWT segments; we
            append/replace the "token:" segment with the current access token.

        Args:
            token: Successfully obtained authentication token

        Returns:
            Headers dict ready for bootstrap, CMS, and playback requests
        """
        headers = self._build_base_headers()  # picks up _disco_id etc.
        headers["Authorization"] = f"Bearer {token.access_token}"
        headers["Content-Type"] = "application/json"
        headers["Origin"] = DISCOVERY_AUTH_ORIGIN
        headers["Referer"] = DISCOVERY_AUTH_REFERER

        # NOTE: x-wbd-session-state is a server-issued encrypted blob returned
        # in the /token 400 response headers. It cannot be constructed from the
        # access_token. On a stored-token path _session_state is None and
        # _build_base_headers() will not add this header — that is correct.
        # The Authorization: Bearer header is sufficient for bootstrap.

        return headers

    def _build_auth_payload(self) -> Dict[str, Any]:
        """
        Build authentication payload based on credential type.

        Returns:
            Authentication payload dictionary

        Raises:
            InvalidCredentialsError: If no credentials available
            UnsupportedCredentialTypeError: If credential type not supported
        """
        if not self.credentials:
            raise InvalidCredentialsError("No credentials available")

        if isinstance(self.credentials, DiscoveryAnonymousCredentials):
            return {}
        elif isinstance(self.credentials, DiscoveryUserCredentials):
            return self.credentials.to_login_payload()
        else:
            raise UnsupportedCredentialTypeError(type(self.credentials).__name__)

    def _create_token_from_response(
            self,
            response_data: Dict[str, Any],
            response=None,
    ) -> BaseAuthToken:
        """
        Create token object from API response.

        Args:
            response_data: Parsed JSON body from the auth response
            response: Raw requests.Response for cookie extraction

        Returns:
            Initialized token with auth level classified
        """
        token = DiscoveryAuthToken.from_token_response(response_data, response=response)
        token.auth_level = self._classify_token(token)
        return token

    def get_fallback_credentials(self) -> DiscoveryAnonymousCredentials:
        """
        Get fallback credentials (anonymous).

        Returns:
            Anonymous credentials instance
        """
        return DiscoveryAnonymousCredentials(realm=DEFAULT_REALM)

    def _perform_authentication(self) -> BaseAuthToken:
        """
        Perform authentication using appropriate flow based on credential type.

        Returns:
            Authenticated token

        Raises:
            InvalidCredentialsError: If no credentials available
            UnsupportedCredentialTypeError: If credential type not supported
        """
        if isinstance(self.credentials, DiscoveryAnonymousCredentials):
            return self._perform_anonymous_auth()
        elif isinstance(self.credentials, DiscoveryUserCredentials):
            return self._perform_user_auth()
        else:
            raise UnsupportedCredentialTypeError(type(self.credentials).__name__)

    def _perform_anonymous_auth(self) -> BaseAuthToken:
        """
        Perform anonymous authentication with two-step header negotiation.

        Step 1: GET /token with no session headers → 400 response whose
                headers contain x-disco-id, x-wbd-session-state, x-wbd-ace.
        Step 2: GET /token again with those three headers → 200 with token.

        Returns:
            Anonymous authentication token
        """
        logger.info(
            f"Performing two-step anonymous authentication for {self.provider_name}"
        )

        # Step 1 headers: base headers only, no session headers yet
        base_headers = {
            "User-Agent": DISCOVERY_USER_AGENT,
            "x-device-info": self._build_device_info(),
            "x-disco-client": DISCOVERY_DISCO_CLIENT,
            "x-disco-client-id": self._build_client_id(),
            "x-disco-params": DISCOVERY_DISCO_PARAMS,
            "x-gisdk": f"clientId={DISCOVERY_GISDK_CLIENT_ID}",
            "x-wbd-device-consent": DISCOVERY_DEVICE_CONSENT,
            "x-wbd-preferred-language": f"{self.country.lower()}-DE",
            "x-wbd-time-zone": DISCOVERY_DEFAULT_TIMEZONE,
        }

        params = {"realm": "bolt"}

        # Step 1: Initial request — we expect 400 + session headers in response
        logger.debug("Step 1: Making initial token request (expecting 400)")
        response = self.http_manager.get(
            self.token_endpoint,
            operation="auth",
            headers=base_headers,
            params=params,
            allow_redirects=False,
        )

        if response.status_code == 400:
            # Extract required session headers from the 400 response
            disco_id = response.headers.get("x-disco-id")
            session_state = response.headers.get("x-wbd-session-state")
            wbd_ace = response.headers.get("x-wbd-ace")

            if not all([disco_id, session_state, wbd_ace]):
                missing = [
                    h for h, v in [
                        ("x-disco-id", disco_id),
                        ("x-wbd-session-state", session_state),
                        ("x-wbd-ace", wbd_ace),
                    ] if not v
                ]
                logger.error(
                    f"Missing required headers in 400 response: {missing}"
                )
                logger.debug(f"Response headers: {dict(response.headers)}")
                response.raise_for_status()

            logger.debug(f"Received x-disco-id: {disco_id}")
            logger.debug(f"Received x-wbd-ace: {wbd_ace[:50]}...")
            logger.debug(f"Received x-wbd-session-state: {session_state[:100]}...")

            # Persist session headers for future requests (CMS, playback, etc.)
            self._disco_id = disco_id
            self._session_state = session_state
            self._wbd_ace = wbd_ace

            # Step 2: Repeat the request with all three session headers
            logger.debug("Step 2: Making second token request with session headers")
            second_headers = base_headers.copy()
            second_headers["x-disco-id"] = disco_id
            second_headers["x-wbd-session-state"] = session_state
            second_headers["x-wbd-ace"] = wbd_ace

            response = self.http_manager.get(
                self.token_endpoint,
                operation="auth",
                headers=second_headers,
                params=params,
            )
            response.raise_for_status()
            token_data = response.json()

            logger.info("Anonymous authentication successful")
            token = self._create_token_from_response(token_data, response=response)

            if token.st_cookie:
                logger.debug("Captured st= session cookie from /token response")
            else:
                logger.warning("No st= cookie in /token response — session may not persist")

            # Bootstrap with authenticated session to discover country-specific
            # endpoints. Must happen after token is obtained.
            self._discover_endpoints(self._build_authenticated_headers(token))

            return token

        elif response.status_code == 200:
            # Fallback: server skipped header negotiation (uncommon)
            logger.debug("Received 200 directly without header negotiation")
            token_data = response.json()
            token = self._create_token_from_response(token_data, response=response)
            self._discover_endpoints(self._build_authenticated_headers(token))
            return token

        else:
            logger.error(f"Unexpected response status: {response.status_code}")
            response.raise_for_status()

    def _solve_arkose(self, blob: str) -> str:
        """
        Exchange the Arkose blob for a solved FunCaptcha token using
        Discovery+'s own hosted Arkose endpoint.

        Flow:
          POST https://a4gds3vfh.discoveryplus.com/fc/gt2/public_key/<sitekey>
          Content-Type: application/x-www-form-urlencoded
          Body (form-encoded):
            public_key=<sitekey>
            ...
            data[blob]=<blob from /users/arkose/data>

        The x-ark-esync-value header is the current Unix timestamp rounded
        down to the nearest hour, which is the sync value Arkose expects.

        Args:
            blob: Arkose data blob from /users/arkose/data

        Returns:
            Solved Arkose token string

        Raises:
            Exception: If the token exchange fails
        """
        import math

        # esync value = current time rounded down to the nearest hour
        esync_value = str(int(math.floor(time.time() / 3600) * 3600))

        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Origin": DISCOVERY_AUTH_ORIGIN,
            "Referer": DISCOVERY_AUTH_REFERER,
            "User-Agent": DISCOVERY_USER_AGENT,
            "x-ark-esync-value": esync_value,
        }

        # Full form payload mirrors what the browser sends
        payload = {
            "public_key": DISCOVERY_ARKOSE_SITEKEY,
            "capi_version": "3.7.8",
            "capi_mode": "lightbox",
            "style_theme": "dplus",
            "site": "null",
            "userbrowser": DISCOVERY_USER_AGENT,
            "language": "de-DE",
            "data[blob]": blob,
        }

        logger.debug("Exchanging Arkose blob for FC token")
        response = self.http_manager.post(
            DISCOVERY_ARKOSE_FC_URL,
            operation="auth",
            data=payload,
            headers=headers,
        )
        response.raise_for_status()

        data = response.json()
        token = data.get("token")
        if not token:
            raise Exception(f"No token in Arkose FC response: {data}")

        logger.debug("Arkose FC token obtained successfully")
        return token

    def _fetch_arkose_blob(self) -> str:
        """
        Fetch the Arkose data blob required before POST /login.

        Discovery+ requires a solved Arkose (FunCaptcha) token on every /login
        request. The blob returned here is passed to your Arkose solver which
        returns the final token to include in x-disco-arkose-token.

        Returns:
            Arkose blob string

        Raises:
            Exception: If the blob cannot be fetched
        """
        headers = self._build_base_headers()
        headers["Authorization"] = f"Bearer {self._current_anon_token}"
        headers["Content-Type"] = "application/json"
        headers["Origin"] = DISCOVERY_AUTH_ORIGIN
        headers["Referer"] = DISCOVERY_AUTH_REFERER

        response = self.http_manager.post(
            DISCOVERY_ARKOSE_DATA_URL,
            operation="auth",
            headers=headers,
            json_data=DISCOVERY_ARKOSE_DATA_PAYLOAD,
        )
        response.raise_for_status()
        data = response.json()
        blob = data["data"]["attributes"]["blob"]
        logger.debug(f"Fetched Arkose blob (length={len(blob)})")
        return blob

    def _perform_user_auth(self) -> BaseAuthToken:
        """
        Perform user authentication by upgrading an anonymous token.

        Discovery+ does not accept a bare credentials POST to /login.
        The session must first be established anonymously, then the anonymous
        token is used as a Bearer token to POST credentials to /login, which
        returns a new token with anonymous=False and full user entitlements.

        Flow:
          1. Obtain anonymous token via two-step header negotiation (reuses
             _perform_anonymous_auth, which also populates session headers).
          2. POST /login with Authorization: Bearer <anon_token> and the
             username/password payload to upgrade to a user token.

        Returns:
            User-level authentication token (anonymous=False)

        Raises:
            InvalidCredentialsError: If credentials are missing or rejected
        """
        if not isinstance(self.credentials, DiscoveryUserCredentials):
            raise InvalidCredentialsError(
                "User credentials required for user authentication"
            )

        logger.info(
            f"Performing user authentication for {self.provider_name} "
            f"(user: {self.credentials.username})"
        )

        # Step 1+2: Obtain anonymous token (also populates session headers
        # self._disco_id / self._session_state / self._wbd_ace).
        logger.debug("Obtaining anonymous base token for user auth upgrade")
        anon_token = self._perform_anonymous_auth()

        # Step 3: Fetch Arkose blob and solve the challenge.
        # Discovery+ rejects /login with 400 arkose.required without a valid token.
        logger.debug("Fetching Arkose blob for login challenge")
        self._current_anon_token = anon_token.access_token
        arkose_blob = self._fetch_arkose_blob()

        arkose_token = self._solve_arkose(arkose_blob)
        logger.debug("Arkose challenge solved")

        # Step 4: Upgrade anonymous session to user session
        logger.debug(
            f"Upgrading anonymous token to user token for "
            f"{self.credentials.username}"
        )

        # Build headers: session headers + Bearer anon token + Origin/Referer + Arkose
        upgrade_headers = self._build_base_headers()  # includes session headers
        upgrade_headers["Authorization"] = f"Bearer {anon_token.access_token}"
        upgrade_headers["Content-Type"] = "application/json"
        upgrade_headers["Origin"] = DISCOVERY_AUTH_ORIGIN
        upgrade_headers["Referer"] = DISCOVERY_AUTH_REFERER
        upgrade_headers["x-disco-arkose-sitekey"] = DISCOVERY_ARKOSE_SITEKEY
        upgrade_headers["x-disco-arkose-token"] = arkose_token

        payload = self.credentials.to_login_payload()

        response = self.http_manager.post(
            self.login_endpoint,
            operation="auth",
            headers=upgrade_headers,
            json_data=payload,
        )

        if response.status_code == 401:
            raise InvalidCredentialsError(
                f"Invalid credentials for user {self.credentials.username}"
            )

        response.raise_for_status()
        token_data = response.json()

        user_token = self._create_token_from_response(token_data, response=response)

        if user_token.st_cookie:
            logger.debug("Captured st= session cookie from /login response")
        else:
            logger.warning("No st= cookie in /login response — user session may not persist")

        if getattr(user_token, "anonymous", True):
            # Login succeeded but token still anonymous — credentials were
            # accepted but the account may lack an active subscription.
            logger.warning(
                f"Login succeeded for {self.credentials.username} but token "
                "is still anonymous — account may lack an active subscription"
            )
        else:
            logger.info(
                f"User authentication successful for {self.credentials.username}"
            )

        # Re-run bootstrap with the user token so endpoints reflect full
        # user entitlements (country routing may differ from anonymous session).
        self._discover_endpoints(self._build_authenticated_headers(user_token))

        return user_token

    def _refresh_token(self) -> Optional[BaseAuthToken]:
        """
        Token refresh — Discovery+ tokens have no refresh_token mechanism.
        Returning None triggers a full re-authentication in the base class.

        Returns:
            None (triggers re-authentication)
        """
        logger.debug(
            f"No refresh token support for {self.provider_name}, "
            "re-authenticating"
        )
        return None

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        """
        Classify Discovery+ token based on authentication level.

        Args:
            token: Token to classify

        Returns:
            Token authentication level
        """
        if hasattr(token, "anonymous") and not token.anonymous:
            return TokenAuthLevel.USER_AUTHENTICATED
        return TokenAuthLevel.ANONYMOUS

    def _establish_session(self) -> None:
        """
        Establish a live session (session headers + endpoints) using whatever
        credentials are available, without replacing the currently stored token.

        Called on the stored-token path when session headers are missing.
        The st= cookie (if present in the jar) causes /token to return the
        previously authenticated token rather than a fresh anonymous one.

        Flow:
          1. Run /token two-step → populates session headers + captures token
          2. If result is anonymous but we have user credentials → re-login
          3. Either way → bootstrap runs at the end of the auth method
        """
        if isinstance(self.credentials, DiscoveryUserCredentials):
            # Run the full user flow: /token two-step + /login upgrade.
            # If the st= cookie is still valid, /token already returns the user
            # token and /login may be skipped by the server — but we still call
            # it to be safe and to guarantee session headers are correct.
            logger.debug(
                "User credentials available — running full user auth to "
                "establish session"
            )
            self._perform_user_auth()
        else:
            # Anonymous path — just the /token two-step
            logger.debug(
                "No user credentials — running anonymous /token negotiation "
                "to establish session for bootstrap"
            )
            self._perform_anonymous_auth()

    def _restore_session_cookie(self, st_cookie: str) -> None:
        """
        Inject a stored st= cookie back into the http_manager session.

        The st= cookie is the true session credential for Discovery+. Without
        it in the active cookie jar, /token returns a fresh anonymous token
        regardless of what Authorization header we send.

        Args:
            st_cookie: The raw st= cookie value from storage
        """
        jar = self.http_manager._session.cookies
        if jar.get("st"):
            return  # Already present — nothing to do

        jar.set("st", st_cookie, domain="api.discoveryplus.com", path="/")
        logger.debug("Restored st= session cookie into http_manager cookie jar")

    def get_bearer_token(self, force_refresh: bool = False) -> str:
        """
        Get bearer token for API requests.

        Handles three stored-token scenarios before returning:
          1. Stored token is anonymous but we have user credentials → upgrade
             via login so the caller always gets a user-level token.
          2. Stored token is already a user token → use as-is.
          3. Stored token is anonymous and no user credentials → use as-is.

        Also ensures endpoint discovery (bootstrap) has run regardless of
        whether the token came from storage or a fresh auth flow.

        Args:
            force_refresh: Force token refresh

        Returns:
            Bearer token string
        """
        token = self.authenticate(force_refresh=force_refresh)

        # Restore the st= cookie into the http_manager session if we have one
        # stored but it's not yet in the active cookie jar. This must happen
        # before any subsequent requests so the server recognises our session.
        if isinstance(token, DiscoveryAuthToken) and token.st_cookie:
            self._restore_session_cookie(token.st_cookie)

        # Upgrade anonymous stored token when user credentials are available.
        # The base class may return a BaseAuthToken (not DiscoveryAuthToken) when
        # loading from storage, so we read the anonymous flag from the raw token
        # info dict rather than inspecting the object type.
        token_info = self.get_token_info() or {}
        is_anonymous_token = token_info.get("anonymous", True)
        has_user_credentials = isinstance(self.credentials, DiscoveryUserCredentials)

        logger.debug(
            f"Token state: anonymous={is_anonymous_token}, "
            f"has_user_credentials={has_user_credentials}"
        )

        if is_anonymous_token and has_user_credentials:
            logger.info(
                "Stored token is anonymous but user credentials are available "
                "— upgrading to user token"
            )
            token = self._perform_user_auth()
        elif not self._endpoints:
            # No upgrade needed, but bootstrap hasn't run yet.
            # Happens when token was loaded from storage (auth flow bypassed)
            # or when a previous bootstrap attempt failed.
            logger.debug(
                "Endpoints not yet discovered — establishing session for bootstrap"
            )
            if not self._session_state:
                # No live session headers — need to run auth flow to get them.
                # _establish_session routes to the right flow by credential type
                # and always calls _discover_endpoints at the end.
                self._establish_session()
            else:
                self._discover_endpoints(self._build_authenticated_headers(token))

        return token.bearer_token

    def is_authenticated(self) -> bool:
        """
        Check if currently authenticated with valid token.

        Returns:
            True if authenticated with valid token
        """
        return (
            self._current_token is not None and
            not self._current_token.is_expired
        )

    def invalidate_token(self) -> None:
        """Invalidate current token and clear from storage"""
        self._current_token = None
        # Clear session headers so next auth starts fresh
        self._disco_id = None
        self._session_state = None
        self._wbd_ace = None
        # Clear the st= cookie from the session jar
        try:
            self.http_manager._session.cookies.clear(
                domain="api.discoveryplus.com", path="/", name="st"
            )
        except Exception:
            pass
        try:
            self.settings_manager.clear_token(self.provider_name, self.country)
        except (AttributeError, KeyError, IOError, OSError):
            pass