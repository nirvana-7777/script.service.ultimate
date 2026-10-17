# streaming_providers/base/models/proxy_models.py
import re
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class ProxyType(Enum):
    """Supported proxy types"""

    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS4A = "socks4a"  # hostname resolved by the proxy
    SOCKS5 = "socks5"
    SOCKS5H = "socks5h"  # hostname resolved by the proxy


# The `operation=` values HTTPManager.get/post/put/delete understand for proxy
# scoping. Any other string (v1 providers pass ad-hoc names such as
# "live_manifest") is NOT an error: it is proxied whenever the master switch
# `ProxyScope.all` is on, regardless of the per-operation flags.
KNOWN_OPERATIONS = ("api", "auth", "manifest", "license")


def _redact_url_credentials(url: str) -> str:
    """Hide everything between '//' and the last '@' (user:password)."""
    return re.sub(r"//.*@", "//***@", url)


@dataclass
class ProxyScope:
    """
    Define which network operations should use proxy
    Allows granular control per provider
    """

    api_calls: bool = True  # GraphQL, REST API calls
    authentication: bool = True  # Auth endpoints
    manifests: bool = True  # Manifest/playlist downloads
    license: bool = True  # DRM license requests
    all: bool = True  # Master switch - overrides all others

    def should_use_proxy_for(self, operation: str) -> bool:
        """
        Check if proxy should be used for specific operation.

        Known operations: see KNOWN_OPERATIONS. Unknown operation names fall
        back to True (proxied) as long as the master switch `all` is on --
        they are never matched against the per-operation flags.
        """
        if not self.all:
            return False

        operation_map = {
            "api": self.api_calls,
            "auth": self.authentication,
            "manifest": self.manifests,
            "license": self.license,
        }

        return operation_map.get(operation, True)


@dataclass
class ProxyAuth:
    """Proxy authentication details (password is hidden from repr/logs)"""

    username: str
    password: str = field(repr=False)

    def to_auth_string(self) -> str:
        """Raw 'username:password' (NOT URL-encoded, never log this)"""
        return f"{self.username}:{self.password}"

    def to_url_userinfo(self) -> str:
        """Percent-encoded 'username:password' for use inside a proxy URL"""
        user = urllib.parse.quote(self.username, safe="")
        password = urllib.parse.quote(self.password, safe="")
        return f"{user}:{password}"


@dataclass
class ProxyConfig:
    """
    Comprehensive proxy configuration
    Supports different proxy types and authentication
    """

    # Basic proxy settings
    host: str
    port: int
    proxy_type: ProxyType = ProxyType.HTTP

    # Authentication (optional)
    auth: Optional[ProxyAuth] = None

    # Scope control
    scope: ProxyScope = field(default_factory=ProxyScope)

    # Advanced settings
    timeout: int = 30
    verify_ssl: bool = True

    # Provider-specific overrides
    provider_specific: Dict[str, Any] = field(default_factory=dict)

    def _host_for_url(self) -> str:
        """Host as it must appear in a URL (IPv6 literals need brackets)"""
        if ":" in self.host and not self.host.startswith("["):
            return f"[{self.host}]"
        return self.host

    def to_proxy_dict(self) -> Dict[str, str]:
        """
        Convert to requests-compatible proxy dictionary

        Returns:
            Dict in format {'http': 'proxy_url', 'https': 'proxy_url'}
        """
        proxy_url = self.to_proxy_url()
        return {"http": proxy_url, "https": proxy_url}

    def to_proxy_url(self) -> str:
        """
        Get single proxy URL string.

        Contains the password (percent-encoded). Use to_safe_url() for
        anything that is logged or displayed.
        """
        userinfo = f"{self.auth.to_url_userinfo()}@" if self.auth else ""
        return (
            f"{self.proxy_type.value}://{userinfo}"
            f"{self._host_for_url()}:{self.port}"
        )

    def to_safe_url(self) -> str:
        """Proxy URL with the password masked -- safe for logs and UIs"""
        userinfo = ""
        if self.auth:
            user = urllib.parse.quote(self.auth.username, safe="")
            userinfo = f"{user}:***@"
        return (
            f"{self.proxy_type.value}://{userinfo}"
            f"{self._host_for_url()}:{self.port}"
        )

    def validate(self) -> bool:
        """Validate proxy configuration"""
        if not self.host or not self.port:
            return False
        if self.port < 1 or self.port > 65535:
            return False
        if self.timeout < 1:
            return False
        return True

    def to_dict(self, redact: bool = False) -> Dict[str, Any]:
        """
        Convert to dictionary for serialization.

        Args:
            redact: mask the proxy password ("***"). Use for logs/UI; the
                default keeps the password so from_dict() round-trips.
        """
        result = {
            "host": self.host,
            "port": self.port,
            "proxy_type": self.proxy_type.value,
            "timeout": self.timeout,
            "verify_ssl": self.verify_ssl,
            "scope": {
                "api_calls": self.scope.api_calls,
                "authentication": self.scope.authentication,
                "manifests": self.scope.manifests,
                "license": self.scope.license,
                "all": self.scope.all,
            },
            "provider_specific": self.provider_specific,
        }

        if self.auth:
            result["auth"] = {
                "username": self.auth.username,
                "password": "***" if redact else self.auth.password,
            }

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProxyConfig":
        """Create ProxyConfig from dictionary"""
        auth = None
        if "auth" in data and data["auth"]:
            auth = ProxyAuth(
                username=data["auth"]["username"], password=data["auth"]["password"]
            )

        scope_data = data.get("scope", {})
        scope = ProxyScope(
            api_calls=scope_data.get("api_calls", True),
            authentication=scope_data.get("authentication", True),
            manifests=scope_data.get("manifests", True),
            license=scope_data.get("license", True),
            all=scope_data.get("all", True),
        )

        return cls(
            host=data["host"],
            port=data["port"],
            proxy_type=ProxyType(data.get("proxy_type", "http")),
            auth=auth,
            scope=scope,
            timeout=data.get("timeout", 30),
            verify_ssl=data.get("verify_ssl", True),
            provider_specific=data.get("provider_specific", {}),
        )

    @classmethod
    def from_url(
        cls, proxy_url: str, scope: Optional[ProxyScope] = None
    ) -> "ProxyConfig":
        """
        Create ProxyConfig from proxy URL string

        Args:
            proxy_url: Proxy URL like "http://user:pass@proxy.example.com:8080".
                Credentials may be percent-encoded (they are decoded here).
            scope: Optional scope configuration

        Returns:
            ProxyConfig instance

        Raises:
            ValueError: missing host/port or unsupported scheme. Error
                messages never contain the credentials.
        """
        safe = _redact_url_credentials(proxy_url)
        parsed = urllib.parse.urlparse(proxy_url)

        try:
            port = parsed.port
        except ValueError:
            raise ValueError(f"Invalid proxy URL (bad port): {safe}") from None
        if not parsed.hostname or not port:
            raise ValueError(f"Invalid proxy URL: {safe}")

        auth = None
        if parsed.username:
            auth = ProxyAuth(
                username=urllib.parse.unquote(parsed.username),
                password=urllib.parse.unquote(parsed.password or ""),
            )

        proxy_type = ProxyType.HTTP
        if parsed.scheme:
            try:
                proxy_type = ProxyType(parsed.scheme.lower())
            except ValueError:
                # Silently falling back to HTTP turned e.g. socks5h:// into a
                # broken HTTP proxy; refuse instead.
                raise ValueError(
                    f"Unsupported proxy scheme '{parsed.scheme}' in {safe}"
                ) from None

        return cls(
            host=parsed.hostname,
            port=port,
            proxy_type=proxy_type,
            auth=auth,
            scope=scope or ProxyScope(),
        )


@dataclass
class RequestConfig:
    """
    Configuration for HTTP requests including proxy settings
    Used by HTTPManager for consistent request handling
    """

    # Proxy settings
    proxy_config: Optional[ProxyConfig] = None

    # Request settings
    timeout: float = 30
    verify_ssl: bool = True
    max_retries: int = 3
    retry_delay: float = 1.0

    # Headers
    default_headers: Dict[str, str] = field(default_factory=dict)
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    )
    # Optional header overrides — when set, HTTPManager will add them to the
    # session in browser-natural order. Left as None by default so the class
    # imposes no opinion on callers that don't need them.
    accept: Optional[str] = None
    accept_language: Optional[str] = None
    accept_encoding: Optional[str] = None

    # When True, HTTPManager injects an Origin header derived from the
    # request URL. Opt-in only — some APIs reject unexpected Origin headers.
    inject_origin: bool = False

    # Provider-specific settings
    provider: str = ""

    use_tls_impersonation: bool = False  # curl_cffi Chrome impersonation; ignored under Kodi

    # When True, HTTPManager sends the previous response URL as Referer.
    # Opt-in: WAFs (e.g. Akamai) flag API calls that carry backend API URLs
    # as Referer. (New fields are appended last so positional construction
    # of the fields above keeps working.)
    inject_referer: bool = False

    # Retry POST requests on 429 / connection errors. Default True keeps the
    # historical behaviour; set False for providers where a replayed POST
    # (e.g. after a read timeout) would duplicate a write.
    retry_post: bool = True

    def get_request_kwargs(self, operation: str = "api") -> Dict[str, Any]:
        """
        Get kwargs for requests library call

        Args:
            operation: Type of operation (api, auth, manifest, license)

        Returns:
            Dictionary of kwargs for requests
        """
        kwargs = {
            "timeout": self.timeout,
            "verify": self.verify_ssl,
            "headers": self._get_headers(),
        }

        # Add proxy if configured and enabled for this operation
        if self.proxy_config and self.proxy_config.scope.should_use_proxy_for(
            operation
        ):
            kwargs["proxies"] = self.proxy_config.to_proxy_dict()

        return kwargs

    def _get_headers(self) -> Dict[str, str]:
        """Build headers with user agent"""
        headers = self.default_headers.copy()
        if "User-Agent" not in headers:
            headers["User-Agent"] = self.user_agent
        return headers

    def to_dict(self, redact: bool = False) -> Dict[str, Any]:
        """Convert to dictionary (redact=True masks the proxy password)"""
        result = {
            "timeout": self.timeout,
            "verify_ssl": self.verify_ssl,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "default_headers": self.default_headers,
            "user_agent": self.user_agent,
            "accept": self.accept,
            "accept_language": self.accept_language,
            "accept_encoding": self.accept_encoding,
            "inject_origin": self.inject_origin,
            "inject_referer": self.inject_referer,
            "retry_post": self.retry_post,
            "use_tls_impersonation": self.use_tls_impersonation,
            "provider": self.provider,
        }

        if self.proxy_config:
            result["proxy_config"] = self.proxy_config.to_dict(redact=redact)

        return result