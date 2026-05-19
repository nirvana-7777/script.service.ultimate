# streaming_providers/providers/joyn/auth.py
# -*- coding: utf-8 -*-
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from ...base.auth.base_auth import BaseAuthenticator, BaseAuthToken, TokenAuthLevel
from ...base.auth.credentials import ClientCredentials, UserPasswordCredentials
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger
from .constants import (
    COUNTRY_TENANT_MAPPING,
    DEFAULT_COUNTRY,
    DEFAULT_PLATFORM,
    DEFAULT_REQUEST_TIMEOUT,
    DEVICE_IDS,
    JOYN_AUTH_ENDPOINTS,
    JOYN_CLIENT_VERSION,
    JOYN_DOMAINS,
    JOYN_SSO_DISCOVERY_URL,
    JOYN_USER_AGENT,
    SUPPORTED_COUNTRIES,
)


class JoynSSODiscovery:
    """Service to discover SSO endpoints dynamically"""

    def __init__(
        self,
        http_manager,
        country: str = DEFAULT_COUNTRY,
        platform: str = DEFAULT_PLATFORM,
    ):
        self.http_manager = http_manager
        self.country = country
        self.platform = platform
        self._endpoints_cache = None
        self._cache_timestamp = None
        self._cache_ttl = 3600

    @staticmethod
    def get_fallback_endpoints() -> Dict[str, str]:
        return {
            "device-login": "https://sso.joyn.de/ci",
            "device-register": "https://sso.joyn.de/cr",
            "web-login": "https://auth.7pass.de/authz-srv/authz",
            "redeem-token": "https://auth.joyn.de/auth/7pass/token",
        }

    def get_endpoints(self, force_refresh: bool = False) -> Dict[str, str]:
        if self._endpoints_cache and not force_refresh and time.time() - self._cache_timestamp < self._cache_ttl:
            return self._endpoints_cache

        try:
            params = {
                "client_id": DEVICE_IDS[self.platform],
                "client_name": self.platform,
            }
            response = self.http_manager.get(JOYN_SSO_DISCOVERY_URL, operation="sso_discovery", params=params)
            response.raise_for_status()
            self._endpoints_cache = response.json()
            self._cache_timestamp = time.time()
            return self._endpoints_cache
        except Exception as e:
            logger.warning(f"SSO discovery failed, using fallback: {e}")
            return self.get_fallback_endpoints()

    def get_auth_endpoint(self, auth_type: str = None) -> str:
        if auth_type is None:
            auth_type = f"{self.platform}-login"
        endpoints = self.get_endpoints()
        endpoint = endpoints.get(auth_type)
        if not endpoint:
            fallback = self.get_fallback_endpoints()
            endpoint = fallback.get(auth_type) or fallback.get(f"{self.platform}-login") or fallback.get("web-login", "")
        return endpoint


@dataclass
class JoynCredentials(ClientCredentials):
    client_name: str = DEFAULT_PLATFORM
    country: str = DEFAULT_COUNTRY
    distribution_tenant: Optional[str] = field(default=None)

    def __post_init__(self):
        if not self.client_id:
            self.client_id = DEVICE_IDS.get(self.client_name, DEVICE_IDS[DEFAULT_PLATFORM])
        if not self.distribution_tenant and self.country in COUNTRY_TENANT_MAPPING:
            self.distribution_tenant = COUNTRY_TENANT_MAPPING[self.country]

    def validate(self) -> bool:
        if not self.client_id or not self.client_name:
            return False
        if self.country not in SUPPORTED_COUNTRIES:
            return False
        return True

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
        try:
            if not self.access_token:
                return None
            parts = self.access_token.split(".")
            if len(parts) != 3:
                return None
            import base64
            import json
            payload_b64 = parts[1]
            padding = len(payload_b64) % 4
            if padding:
                payload_b64 += "=" * (4 - padding)
            payload_json = base64.b64decode(payload_b64).decode("utf-8")
            return json.loads(payload_json)
        except Exception as e:
            logger.debug(f"Failed to extract JWT claims: {e}")
            return None


class JoynAuthConfig:
    def __init__(self, country: str, distribution_tenant: str, http_manager, platform: str = DEFAULT_PLATFORM):
        self.country = country
        self.distribution_tenant = distribution_tenant
        self.platform = platform
        self.user_agent = JOYN_USER_AGENT
        self.timeout = DEFAULT_REQUEST_TIMEOUT
        self.http_manager = http_manager
        if http_manager is not None:
            self.sso_discovery = JoynSSODiscovery(http_manager, country, platform)
        else:
            self.sso_discovery = None

    def get_token_redeem_endpoint(self) -> str:
        if self.sso_discovery:
            return self.sso_discovery.get_auth_endpoint("redeem-token")
        return JoynSSODiscovery.get_fallback_endpoints()["redeem-token"]

    def get_authorize_endpoint(self) -> str:
        if self.sso_discovery:
            return self.sso_discovery.get_auth_endpoint(f"{self.platform}-login")
        fallback = JoynSSODiscovery.get_fallback_endpoints()
        return fallback.get(f"{self.platform}-login") or fallback.get("web-login", "")

    def get_base_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": JOYN_DOMAINS.get(self.country, JOYN_DOMAINS["de"]),
        }

    def get_auth_headers(self) -> Dict[str, str]:
        headers = self.get_base_headers()
        headers.update({
            "joyn-client-version": JOYN_CLIENT_VERSION,
            "joyn-country": self.country.upper(),
            "joyn-distribution-tenant": self.distribution_tenant,
            "joyn-platform": self.platform,
            "joyn-request-id": str(uuid.uuid4()),
        })
        return headers


class JoynAuthenticator(BaseAuthenticator):
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
        self.distribution_tenant = COUNTRY_TENANT_MAPPING[country]
        self._http_manager = http_manager
        self._proxy_config = proxy_config
        self._config = JoynAuthConfig(self.country, self.distribution_tenant, self._http_manager, self.platform)
        self._client_id = self._extract_client_id_from_endpoints()

        super().__init__(
            provider_name="joyn",
            settings_manager=settings_manager,
            credentials=credentials,
            country=country,
            config_dir=config_dir,
            enable_kodi_integration=True,
        )

    @property
    def http_manager(self):
        return self._http_manager

    @property
    def auth_endpoint(self) -> str:
        from ...base.auth.credentials import UserPasswordCredentials
        if isinstance(self.credentials, UserPasswordCredentials):
            return self._config.get_token_redeem_endpoint()
        return JOYN_AUTH_ENDPOINTS["ANONYMOUS"]

    def _get_auth_headers(self) -> Dict[str, str]:
        return self._config.get_auth_headers()

    def _get_joyn_auth_headers(self) -> Dict[str, str]:
        from .constants import JOYN_AUTH_HEADERS_BASE
        headers = JOYN_AUTH_HEADERS_BASE.copy()
        headers["Origin"] = f"https://www.joyn.{self.country.lower()}"
        headers.update({
            "joyn-country": self.country.upper(),
            "joyn-distribution-tenant": self.distribution_tenant,
            "joyn-platform": self.platform,
            "joyn-request-id": str(uuid.uuid4()),
        })
        return headers

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
        logger.debug(f"Token created and classified as: {token.auth_level.value}")
        return token

    def get_fallback_credentials(self) -> JoynCredentials:
        return JoynCredentials(
            client_id=self._client_id,
            client_secret="",
            country=self.country,
        )

    def get_token_redeem_url(self) -> str:
        """Get token redemption URL for OAuth flows"""
        return self._config.get_token_redeem_endpoint()

    def _extract_client_id_from_endpoints(self) -> str:
        try:
            endpoints = self._config.sso_discovery.get_endpoints()
            platform_key = f"{self.platform}-login"
            login_url = endpoints.get(platform_key)
            if not login_url:
                login_url = endpoints.get("web-login")
            if not login_url:
                raise Exception("No login endpoint found")
            parsed_url = urlparse(login_url)
            query_params = parse_qs(parsed_url.query)
            client_id = query_params.get("client_id", [None])[0]
            if not client_id:
                raise Exception("No client_id found")
            return client_id
        except Exception as e:
            logger.error(f"Error extracting client_id: {e}, using fallback")
            return DEVICE_IDS.get(self.platform, DEVICE_IDS[DEFAULT_PLATFORM])

    def _get_sso_endpoints(self) -> Dict[str, str]:
        params = {
            "client_id": DEVICE_IDS[self.platform],
            "client_name": self.platform,
        }
        response = self.http_manager.get(JOYN_SSO_DISCOVERY_URL, operation="sso_discovery", params=params)
        response.raise_for_status()
        return response.json()

    def _perform_oauth_client_credentials_flow(self) -> Dict[str, Any]:
        try:
            headers = self._get_auth_headers()
            payload = self._build_auth_payload()
            response = self.http_manager.post(self.auth_endpoint, operation="auth", headers=headers, json_data=payload)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Client credentials flow failed: {e}")
            raise

    def _perform_oauth_authorization_code_flow(self, username: str, password: str) -> Dict[str, Any]:
        try:
            logger.debug("Starting Joyn form-based login flow")
            endpoints = self._get_sso_endpoints()
            web_login_url = endpoints.get('web-login')
            parsed = urlparse(web_login_url)
            query_params = parse_qs(parsed.query)
            client_id = query_params.get('client_id', [None])[0]
            if not client_id:
                raise Exception("Could not extract client_id from web-login URL")

            # Clear cookies
            if hasattr(self.http_manager, 'clear_cookies'):
                self.http_manager.clear_cookies()

            # Add browser headers
            if hasattr(self.http_manager, '_session'):
                self.http_manager._session.headers.update({
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "de-DE,de;q=0.9,en;q=0.8",
                    "Upgrade-Insecure-Requests": "1",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-User": "?1",
                })

            # Step 1: Get request_id
            response = self.http_manager.get(web_login_url, operation="oauth", allow_redirects=True)
            final_url = response.url
            parsed_url = urlparse(final_url)
            request_id = parse_qs(parsed_url.query).get('requestId', [None])[0]
            if not request_id:
                request_match = re.search(r'requestId["\']?\s*:\s*["\']([^"\']+)', response.text)
                if request_match:
                    request_id = request_match.group(1)
                else:
                    raise Exception("Could not extract request_id")

            # Step 2-4: Setup flow
            lang_url = f'https://auth.7pass.de/registration-setup-srv/public/list?acceptlanguage=undefined&requestId={request_id}'
            self.http_manager.get(lang_url, operation="oauth").raise_for_status()
            check_url = f'https://auth.7pass.de/users-srv/user/checkexists/{request_id}'
            self.http_manager.post(check_url, operation="oauth", json_data={"email": username, "requestId": request_id}).raise_for_status()
            verify_url = 'https://auth.7pass.de/verification-srv/v2/setup/public/configured/list'
            self.http_manager.post(verify_url, operation="oauth", json_data={"email": username, "request_id": request_id}).raise_for_status()

            # Step 5: Submit password
            login_url = 'https://auth.7pass.de/login-srv/login'
            login_data = {"username": username, "password": password, "requestId": request_id}
            response = self.http_manager._session.post(
                login_url, data=login_data,
                headers={"Content-Type": "application/x-www-form-urlencoded", "Referer": final_url, "Origin": "https://signin.7pass.de"},
                timeout=self.http_manager.config.timeout, allow_redirects=False
            )
            if response.status_code in [302, 303]:
                redirect_url = response.headers.get('Location')
                response = self.http_manager.get(redirect_url, operation="oauth")
                redirect_url = response.url
            else:
                redirect_url = response.url

            # Step 6-7: Extract codes and handle consent
            parsed = urlparse(redirect_url)
            id_dict = parse_qs(parsed.query)
            if 'code' not in id_dict:
                sub = id_dict.get('sub', [None])[0]
                if sub:
                    consent_url = 'https://auth.7pass.de/consent-management-srv/consent/scope/accept'
                    self.http_manager.post(consent_url, operation="oauth", json_data={"sub": sub, "client_id": client_id, "scopes": [{"offline_access": "denied"}]}).raise_for_status()
                track_id = id_dict.get('track_id', [None])[0] or id_dict.get('cd1', [None])[0]
                if track_id:
                    continue_url = f'https://auth.7pass.de/login-srv/precheck/continue/{track_id}'
                    response = self.http_manager.get(continue_url, operation="oauth", allow_redirects=False)
                    if response.status_code in [302, 303] and response.headers.get('Location'):
                        response = self.http_manager.get(response.headers['Location'], operation="oauth")
                    parsed = urlparse(response.url)
                    id_dict = parse_qs(parsed.query)

            # Step 8: Exchange code for token
            code = id_dict.get('code', [None])[0]
            if not code:
                raise Exception("No authorization code found")
            tracking_id = id_dict.get('cd1', [None])[0] or id_dict.get('track_id', [None])[0]
            token_data = {
                "client_id": client_id, "code": code, "code_verifier": "",
                "redirect_uri": f"https://www.joyn.{self.country}/oauth",
                "tracking_id": tracking_id, "tracking_name": "web"
            }
            token_endpoint = endpoints.get('redeem-token')
            response = self.http_manager.post(token_endpoint, operation="auth", json_data=token_data)
            response.raise_for_status()
            auth_token = response.json()
            auth_token['has_account'] = True
            auth_token['issued_at'] = time.time()
            return auth_token
        except Exception as e:
            logger.error(f"Joyn form-based login failed: {e}")
            raise

    def _perform_authentication(self) -> BaseAuthToken:
        if isinstance(self.credentials, UserPasswordCredentials):
            token_data = self._perform_oauth_authorization_code_flow(self.credentials.username, self.credentials.password)
        else:
            token_data = self._perform_oauth_client_credentials_flow()
        return self._create_token_from_response(token_data)

    def _refresh_token(self) -> Optional[BaseAuthToken]:
        """Refresh the current token using refresh token"""
        if not self._current_token or not self._current_token.refresh_token:
            logger.debug(f"No refresh token available for {self.provider_name}")
            return None

        try:
            logger.debug(f"Refreshing token for {self.provider_name}")
            payload = {
                "client_id": DEVICE_IDS.get(self.platform, DEVICE_IDS[DEFAULT_PLATFORM]),
                "client_name": self.platform,
                "grant_type": "Bearer",
                "refresh_token": self._current_token.refresh_token,
            }
            headers = self._get_joyn_auth_headers()
            refresh_endpoint = JOYN_AUTH_ENDPOINTS["REFRESH"]
            response = self.http_manager.post(refresh_endpoint, operation="auth", headers=headers, json_data=payload, timeout=self._config.timeout)
            response.raise_for_status()
            new_token_data = response.json()
            refreshed_token = self._create_token_from_response(new_token_data)
            logger.info(f"Token refresh successful for {self.provider_name}")
            return refreshed_token
        except Exception as e:
            logger.warning(f"Token refresh failed for {self.provider_name}: {e}")
            return None

    def _classify_token(self, token: BaseAuthToken) -> TokenAuthLevel:
        """Classify Joyn token based on JWT claims"""
        try:
            if not token or not token.access_token:
                return TokenAuthLevel.UNKNOWN

            # Parse JWT token
            try:
                parts = token.access_token.split(".")
                if len(parts) != 3:
                    return TokenAuthLevel.UNKNOWN
                import base64
                import json
                payload_b64 = parts[1]
                padding = len(payload_b64) % 4
                if padding:
                    payload_b64 += "=" * (4 - padding)
                payload_json = base64.b64decode(payload_b64).decode("utf-8")
                claims = json.loads(payload_json)
            except Exception as e:
                logger.warning(f"Failed to parse JWT: {e}")
                return TokenAuthLevel.UNKNOWN

            # Classification logic
            jidc = claims.get("jIdC", "")
            if jidc.startswith("JNAA-"):
                return TokenAuthLevel.CLIENT_CREDENTIALS
            elif jidc.startswith("JNDE-"):
                return TokenAuthLevel.USER_AUTHENTICATED

            if "social_id" in claims:
                return TokenAuthLevel.USER_AUTHENTICATED

            client_id = claims.get("cId", "")
            known_client_ids = {DEVICE_IDS["web"], DEVICE_IDS["android"], DEVICE_IDS["ios"]}
            if client_id in known_client_ids:
                return TokenAuthLevel.CLIENT_CREDENTIALS

            subject = claims.get("sub", "")
            if subject and len(subject) == 36:
                return TokenAuthLevel.CLIENT_CREDENTIALS

            scope = claims.get("scope", "")
            if scope:
                scopes = scope.split()
                if "offline_access" in scopes and "profile" in scopes:
                    return TokenAuthLevel.USER_AUTHENTICATED
                elif "openid" in scopes and len(scopes) <= 2:
                    return TokenAuthLevel.CLIENT_CREDENTIALS

            return TokenAuthLevel.UNKNOWN
        except Exception as e:
            logger.error(f"Error classifying token: {e}")
            return TokenAuthLevel.UNKNOWN

    def is_authenticated(self) -> bool:
        """Check if currently authenticated with valid token"""
        return self._current_token is not None and not self._current_token.is_expired

    def invalidate_token(self) -> None:
        """Invalidate current token"""
        self._current_token = None
        try:
            self.settings_manager.clear_token(self.provider_name, self.country)
        except (AttributeError, KeyError, TypeError):
            try:
                self.settings_manager.clear_token(self.provider_name)
            except (AttributeError, KeyError):
                pass

    def debug_token_classification(self) -> Dict[str, Any]:
        """Debug method to analyze current token classification"""
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
                "sub": claims.get("sub", "MISSING")[:8] + "..." if claims.get("sub") else "MISSING",
                "scope": claims.get("scope", "MISSING"),
            } if claims else {}
        }