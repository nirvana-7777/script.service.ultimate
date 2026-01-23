# streaming_providers/base/models/proxy_models.py
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class ProxyType(Enum):
    """Supported proxy types"""

    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


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
        """Check if proxy should be used for specific operation"""
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
    """Proxy authentication details"""

    username: str
    password: str

    def to_auth_string(self) -> str:
        """Convert to authentication string for proxy URL"""
        return f"{self.username}:{self.password}"


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

    def to_proxy_dict(self) -> Dict[str, str]:
        """
        Convert to requests-compatible proxy dictionary

        Returns:
            Dict in format {'http': 'proxy_url', 'https': 'proxy_url'}
        """
        # Build proxy URL
        auth_part = ""
        if self.auth:
            auth_part = f"{self.auth.to_auth_string()}@"

        proxy_url = f"{self.proxy_type.value}://{auth_part}{self.host}:{self.port}"

        # Return both HTTP and HTTPS proxy settings
        return {"http": proxy_url, "https": proxy_url}

    def to_proxy_url(self) -> str:
        """Get single proxy URL string"""
        auth_part = ""
        if self.auth:
            auth_part = f"{self.auth.to_auth_string()}@"

        return f"{self.proxy_type.value}://{auth_part}{self.host}:{self.port}"

    def validate(self) -> bool:
        """Validate proxy configuration"""
        if not self.host or not self.port:
            return False
        if self.port < 1 or self.port > 65535:
            return False
        if self.timeout < 1:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
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
                "password": self.auth.password,
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
            proxy_url: Proxy URL like "http://user:pass@proxy.example.com:8080"
            scope: Optional scope configuration

        Returns:
            ProxyConfig instance
        """
        import urllib.parse

        parsed = urllib.parse.urlparse(proxy_url)

        if not parsed.hostname or not parsed.port:
            raise ValueError(f"Invalid proxy URL: {proxy_url}")

        auth = None
        if parsed.username and parsed.password:
            auth = ProxyAuth(username=parsed.username, password=parsed.password)

        proxy_type = ProxyType.HTTP
        if parsed.scheme:
            try:
                proxy_type = ProxyType(parsed.scheme.lower())
            except ValueError:
                # Default to HTTP if scheme not recognized
                pass

        return cls(
            host=parsed.hostname,
            port=parsed.port,
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
    timeout: int = 30
    verify_ssl: bool = True
    max_retries: int = 3
    retry_delay: float = 1.0

    # Headers
    default_headers: Dict[str, str] = field(default_factory=dict)
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
    )

    # Provider-specific settings
    provider: str = ""

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

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = {
            "timeout": self.timeout,
            "verify_ssl": self.verify_ssl,
            "max_retries": self.max_retries,
            "retry_delay": self.retry_delay,
            "default_headers": self.default_headers,
            "user_agent": self.user_agent,
            "provider": self.provider,
        }

        if self.proxy_config:
            result["proxy_config"] = self.proxy_config.to_dict()

        return result
