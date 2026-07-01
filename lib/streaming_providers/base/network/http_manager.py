# streaming_providers/base/network/http_manager.py
import json
import logging
import time
import urllib.parse
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..models.proxy_models import ProxyConfig, RequestConfig
from ..utils.logger import logger

# Suppress urllib3 connection pool logging to prevent "Closing connection" messages
# This affects all providers using HTTPManager
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)


class HTTPManager:
    """
    Centralized HTTP request manager with proxy support

    Handles all HTTP requests for streaming providers with:
    - Proxy configuration per operation type
    - Retry logic
    - Error handling
    - Request/response logging with redirect chain visibility
    - Automatic Referer and Origin injection
    - Provider-specific configurations
    - Cookie jar access for external persistence (e.g. Kodi VFS)
    """

    def __init__(self, config: Optional[RequestConfig] = None):
        """
        Initialize HTTP manager

        Args:
            config: Request configuration including proxy settings
        """
        self.config = config or RequestConfig()
        self._session = None
        self._last_url: Optional[str] = None  # Tracks last response URL for Referer injection
        self._setup_session()

    def _setup_session(self) -> None:
        self._using_cffi = False

        if self.config.use_tls_impersonation:
            from streaming_providers.base.utils.environment import is_kodi_environment
            if not is_kodi_environment():
                try:
                    from curl_cffi import requests as cffi_requests

                    proxies = {}
                    if self.config.proxy_config:
                        proxy_url = self.config.proxy_config.to_proxy_url()
                        proxies = {"http": proxy_url, "https": proxy_url}

                    self._session = cffi_requests.Session(
                        impersonate="chrome124",
                        proxies=proxies or None,
                    )
                    self._using_cffi = True
                    logger.debug(
                        f"{self.config.provider}: using curl_cffi Chrome TLS impersonation"
                        + (f" via proxy {proxies.get('https')}" if proxies else "")
                    )
                except ImportError:
                    logger.warning(
                        f"{self.config.provider}: curl_cffi requested but not installed, "
                        "falling back to requests"
                    )

        if not self._using_cffi:
            self._session = requests.Session()
            retry_strategy = Retry(
                total=self.config.max_retries,
                backoff_factor=self.config.retry_delay,
                status_forcelist=[429],
                allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self._session.mount("http://", adapter)
            self._session.mount("https://", adapter)

        self._session.headers.clear()
        base_headers: Dict[str, str] = {}
        if self.config.user_agent:
            base_headers["User-Agent"] = self.config.user_agent
        if self.config.accept:
            base_headers["Accept"] = self.config.accept
        if self.config.accept_language:
            base_headers["Accept-Language"] = self.config.accept_language
        if self.config.accept_encoding:
            base_headers["Accept-Encoding"] = self.config.accept_encoding
        base_headers["Connection"] = "keep-alive"
        self._session.headers.update(base_headers)

    def update_config(self, config: RequestConfig) -> None:
        """
        Update request configuration and rebuild session.

        Existing cookies are preserved across the rebuild so that an in-flight
        auth session survives a mid-session config change (e.g. proxy swap).

        Args:
            config: New request configuration
        """
        # Snapshot cookies before tearing down the old session
        old_cookies = self._session.cookies if self._session else None

        self.config = config
        self._last_url = None
        self._setup_session()

        # Restore cookies into the new session.
        # requests_cookies.update() accepts a RequestsCookieJar directly;
        # we pass the jar (not a plain dict) so domain/path/expiry metadata
        # is preserved rather than flattened.
        if old_cookies is not None:
            self._session.cookies.update(old_cookies)  # type: ignore[arg-type]

    def update_proxy(self, proxy_config: Optional[ProxyConfig]) -> None:
        """
        Update just the proxy configuration

        Args:
            proxy_config: New proxy configuration (None to disable proxy)
        """
        self.config.proxy_config = proxy_config

    def reset_referer(self) -> None:
        """
        Reset the tracked referer URL.

        Call this between logically separate request flows (e.g. after login
        completes and before starting a manifest fetch) so that Referer headers
        don't bleed across unrelated flows.
        """
        self._last_url = None

    # ------------------------------------------------------------------
    # Public request methods
    # ------------------------------------------------------------------

    def get(self, url: str, operation: str = "api", **kwargs) -> requests.Response:
        """
        Perform GET request with proxy support

        Args:
            url: Request URL
            operation: Operation type (api, auth, manifest, license) for proxy scoping
            **kwargs: Additional arguments for requests

        Returns:
            requests.Response object

        Raises:
            requests.exceptions.RequestException: On request failure
        """
        return self._make_request("GET", url, operation, **kwargs)

    def post(
        self,
        url: str,
        operation: str = "api",
        data: Any = None,
        json_data: Any = None,
        **kwargs,
    ) -> requests.Response:
        """
        Perform POST request with proxy support

        Args:
            url: Request URL
            operation: Operation type for proxy scoping
            data: Request data (form data or raw)
            json_data: JSON data to send
            **kwargs: Additional arguments for requests

        Returns:
            requests.Response object
        """
        if json_data is not None:
            kwargs["json"] = json_data
        elif data is not None:
            kwargs["data"] = data

        return self._make_request("POST", url, operation, **kwargs)

    def put(self, url: str, operation: str = "api", **kwargs) -> requests.Response:
        """Perform PUT request with proxy support"""
        return self._make_request("PUT", url, operation, **kwargs)

    def delete(self, url: str, operation: str = "api", **kwargs) -> requests.Response:
        """Perform DELETE request with proxy support"""
        return self._make_request("DELETE", url, operation, **kwargs)

    # ------------------------------------------------------------------
    # Core request logic
    # ------------------------------------------------------------------

    def _make_request(self, method: str, url: str, operation: str, **kwargs) -> requests.Response:
        """
        Make HTTP request with full configuration support.

        Injects Referer from the previous response URL and Origin derived from
        the target URL, unless the caller has already set those headers explicitly.
        Logs the redirect chain when providers set cookies mid-redirect.
        """
        # Get base request configuration
        request_kwargs = self.config.get_request_kwargs(operation)

        # Merge with any additional kwargs (caller overrides win)
        request_kwargs.update(kwargs)

        # Inject Referer from last response URL if not already set by caller.
        # NOTE: Auto-injecting Referer is disabled by default because WAFs (like Akamai)
        # flag API requests that have backend API URLs as the Referer.
        # Providers should explicitly set the Referer header in their own header factories if needed.
        headers = request_kwargs.setdefault("headers", {})

        # Inject Origin derived from target URL only when explicitly requested.
        # Origin injection is opt-in because some non-browser APIs reject
        # requests that carry an unexpected Origin header.
        if self.config.inject_origin and "Origin" not in headers:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme and parsed.netloc:
                headers["Origin"] = f"{parsed.scheme}://{parsed.netloc}"

        # Log request details (excluding sensitive data)
        self._log_request(method, url, operation, request_kwargs)

        try:
            # curl_cffi session has proxy baked in at construction — strip it from
            # per-request kwargs to prevent conflicts / double-proxy application
            if self._using_cffi:
                request_kwargs.pop("proxies", None)

            response = self._session.request(method, url, **request_kwargs)

            # Log redirect chain — cookies set on intermediate responses are
            # otherwise invisible, making auth flow debugging very painful
            if response.history:
                for r in response.history:
                    cookie_keys = list(r.cookies.keys())
                    logger.debug(
                        f"{self.config.provider}: Redirect {r.status_code} {r.url}"
                        + (f" -> cookies set: {cookie_keys}" if cookie_keys else "")
                    )

            # Log final response
            self._log_response(response)

            # Track final URL (after redirects) for next request's Referer
            self._last_url = response.url

            # Raise for 4xx/5xx
            response.raise_for_status()

            return response

        except requests.exceptions.ProxyError as e:
            logger.error(
                f"{self.config.provider}: Proxy error for {operation} request to {url}: {e}"
            )
            raise

        except requests.exceptions.Timeout as e:
            logger.error(
                f"{self.config.provider}: Timeout ({request_kwargs.get('timeout', 'unknown')}s) "
                f"for {operation} request to {url}: {e}"
            )
            raise

        except requests.exceptions.ConnectionError as e:
            logger.error(
                f"{self.config.provider}: Connection error for {operation} request to {url}: {e}"
            )
            raise

        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response else "unknown"
            logger.error(
                f"{self.config.provider}: HTTP {status} error for {operation} request to {url}: {e}"
            )
            if e.response is not None and 400 <= e.response.status_code < 500:
                try:
                    body = e.response.json()
                except Exception:
                    body = e.response.text
                logger.debug(
                    f"{self.config.provider}: {status} response body: {body}"
                )
            raise

        except requests.exceptions.RequestException as e:
            logger.error(
                f"{self.config.provider}: Request error for {operation} request to {url}: {e}"
            )
            raise

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def _log_request(self, method: str, url: str, operation: str, kwargs: Dict[str, Any]) -> None:
        """Log request details with comprehensive proxy and referer information"""

        # Build proxy information string
        proxy_info = ""
        if self.config.proxy_config:
            if self.config.proxy_config.scope.should_use_proxy_for(operation):
                proxy_host = f"{self.config.proxy_config.host}:{self.config.proxy_config.port}"
                proxy_type = self.config.proxy_config.proxy_type.value
                has_auth = "authenticated" if self.config.proxy_config.auth else "no-auth"
                proxy_info = f" [proxy: {proxy_type}://{proxy_host} ({has_auth})]"
            else:
                proxy_info = f" [proxy: disabled for operation '{operation}']"
        else:
            proxy_info = " [proxy: none]"

        # Referer info for traceability
        referer = kwargs.get("headers", {}).get("Referer")
        referer_info = f" [referer: {referer}]" if referer else ""

        timeout = kwargs.get("timeout", self.config.timeout)
        display_url = url if len(url) <= 100 else f"{url[:80]}...{url[-17:]}"

        logger.debug(
            f"{self.config.provider}: {method} {operation} -> {display_url}"
            f"{proxy_info}{referer_info} [timeout: {timeout}s]"
        )

    def _log_response(self, response: requests.Response) -> None:
        """
        Log response details with timing information.

        Uses Content-Length header instead of buffering response.content,
        so this is safe to call before consuming streaming responses.
        """
        elapsed = ""
        if hasattr(response, "elapsed"):
            elapsed = f" [{int(response.elapsed.total_seconds() * 1000)}ms]"

        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            size = int(content_length)
            if size > 1024 * 1024:
                size_display = f"{size / (1024 * 1024):.2f} MB"
            elif size > 1024:
                size_display = f"{size / 1024:.2f} KB"
            else:
                size_display = f"{size} bytes"
        else:
            size_display = "unknown size"

        content_type = response.headers.get("Content-Type", "unknown")

        logger.debug(
            f"{self.config.provider}: Response {response.status_code} "
            f"({size_display}, {content_type}){elapsed}"
        )

    # ------------------------------------------------------------------
    # Connection test
    # ------------------------------------------------------------------

    def test_connection(
        self, test_url: str = "https://httpbin.org/ip", operation: str = "api"
    ) -> Dict[str, Any]:
        """
        Test network connection and proxy configuration

        Args:
            test_url: URL to test connection with
            operation: Operation type for proxy scoping

        Returns:
            Dictionary with test results
        """
        result = {
            "success": False,
            "proxy_used": False,
            "response_time": 0.0,
            "error": None,
            "ip_info": None,
        }

        try:
            start_time = time.time()
            response = self.get(test_url, operation=operation)
            end_time = time.time()

            result["success"] = True
            result["response_time"] = end_time - start_time
            result["proxy_used"] = bool(
                self.config.proxy_config
                and self.config.proxy_config.scope.should_use_proxy_for(operation)
            )

            try:
                result["ip_info"] = response.json()
            except (json.JSONDecodeError, AttributeError):
                result["ip_info"] = {"response": response.text[:100]}

        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Connection test failed: {e}")

        return result

    # ------------------------------------------------------------------
    # Cookie management
    #
    # HTTPManager intentionally has no file I/O here. Persistence is the
    # caller's responsibility so this class stays platform-agnostic
    # (plain filesystem, Kodi VFS, or anything else).
    #
    # Kodi callers should use get_cookie_jar() / set_cookie_jar() together
    # with xbmcvfs for serialisation — see addon layer documentation.
    # ------------------------------------------------------------------

    def get_cookie_jar(self):
        """
        Return the raw requests CookieJar for external serialisation.

        Typical Kodi usage:
            jar = manager.get_cookie_jar()
            with xbmcvfs.File(cookie_path, 'wb') as f:
                f.write(pickle.dumps(jar))
        """
        return self._session.cookies if self._session else None

    def set_cookie_jar(self, jar) -> None:
        """
        Replace the session cookie jar with a previously serialised one.

        Typical Kodi usage:
            with xbmcvfs.File(cookie_path, 'rb') as f:
                manager.set_cookie_jar(pickle.loads(f.read()))
        """
        if self._session:
            self._session.cookies = jar

    def get_cookies(self) -> Dict[str, str]:
        """Return all current cookies as a plain dict"""
        if self._session:
            return requests.utils.dict_from_cookiejar(self._session.cookies)
        return {}

    def get_cookies_for_domain(self, domain: str) -> Dict[str, str]:
        """
        Return cookies scoped to a specific domain.

        Useful for inspecting auth state per provider without exposing
        cookies from other domains in the same session.

        Args:
            domain: Domain string to match (partial match, e.g. 'joyn.de')
        """
        if not self._session:
            return {}
        return {
            c.name: c.value
            for c in self._session.cookies
            if domain in c.domain
        }

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """Merge a dict of cookies into the session"""
        if self._session:
            self._session.cookies.update(cookies)

    def clear_cookies(self) -> None:
        """Clear all cookies from the session"""
        if self._session:
            self._session.cookies.clear()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def close(self) -> None:
        """
        Close the session and reset internal state.

        After close(), any further request calls will raise AttributeError
        rather than silently operating on a closed session.
        """
        if self._session:
            self._session.close()
            self._session = None
        self._last_url = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class HTTPManagerFactory:
    """
    Factory for creating HTTP managers with provider-specific configurations
    """

    @staticmethod
    def create_for_provider(
        provider_name: str, proxy_config: Optional[ProxyConfig] = None, **config_kwargs
    ) -> HTTPManager:
        """
        Create HTTP manager configured for specific provider

        Args:
            provider_name: Name of the provider
            proxy_config: Proxy configuration
            **config_kwargs: Additional RequestConfig parameters

        Returns:
            Configured HTTPManager instance
        """
        # Provider-specific defaults cover only neutral network behaviour
        # (timeouts, retry counts). User-Agent, Accept-Language, and any
        # other opinionated or locale-specific headers must be passed in
        # via config_kwargs by the caller — this layer has no opinion on them.
        provider_defaults = {
            "joyn": {
                "timeout": 30,
                "max_retries": 3,
            },
            "zdf": {
                "timeout": 25,
                "max_retries": 2,
            },
            # Add more providers as needed
        }

        defaults = provider_defaults.get(provider_name, {})
        defaults.update(config_kwargs)
        defaults["provider"] = provider_name

        config = RequestConfig(proxy_config=proxy_config, **defaults)
        return HTTPManager(config)

    @staticmethod
    def create_with_proxy_url(provider_name: str, proxy_url: str, **kwargs) -> HTTPManager:
        """
        Create HTTP manager with proxy from URL string

        Args:
            provider_name: Name of the provider
            proxy_url: Proxy URL (e.g., "http://proxy.example.com:8080")
            **kwargs: Additional configuration

        Returns:
            Configured HTTPManager instance
        """
        proxy_config = ProxyConfig.from_url(proxy_url)
        return HTTPManagerFactory.create_for_provider(provider_name, proxy_config, **kwargs)