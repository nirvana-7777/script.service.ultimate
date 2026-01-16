# streaming_providers/base/network/http_manager.py
import json
import time
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..models.proxy_models import ProxyConfig, RequestConfig
from ..utils.logger import logger


class HTTPManager:
    """
    Centralized HTTP request manager with proxy support

    Handles all HTTP requests for streaming providers with:
    - Proxy configuration per operation type
    - Retry logic
    - Error handling
    - Request/response logging
    - Provider-specific configurations
    """

    def __init__(self, config: Optional[RequestConfig] = None):
        """
        Initialize HTTP manager

        Args:
            config: Request configuration including proxy settings
        """
        self.config = config or RequestConfig()
        self._session = None
        self._setup_session()

    def _setup_session(self) -> None:
        """Setup requests session with retry strategy"""
        self._session = requests.Session()

        # Setup retry strategy
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=self.config.retry_delay,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT", "DELETE"],
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    def update_config(self, config: RequestConfig) -> None:
        """
        Update request configuration

        Args:
            config: New request configuration
        """
        self.config = config
        self._setup_session()

    def update_proxy(self, proxy_config: Optional[ProxyConfig]) -> None:
        """
        Update just the proxy configuration

        Args:
            proxy_config: New proxy configuration (None to disable proxy)
        """
        self.config.proxy_config = proxy_config

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

    def _make_request(self, method: str, url: str, operation: str, **kwargs) -> requests.Response:
        """
        Make HTTP request with full configuration support
        """
        # Get base request configuration
        request_kwargs = self.config.get_request_kwargs(operation)

        # Merge with any additional kwargs (allows overrides)
        request_kwargs.update(kwargs)

        # Log request details (excluding sensitive data)
        self._log_request(method, url, operation, request_kwargs)

        try:
            # Make the request
            response = self._session.request(method, url, **request_kwargs)

            # Log response
            self._log_response(response)

            # Check for HTTP errors (will raise for 4xx/5xx)
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
            # Additional context for HTTP errors
            status = e.response.status_code if e.response else "unknown"
            logger.error(
                f"{self.config.provider}: HTTP {status} error for {operation} request to {url}: {e}"
            )
            raise

        except requests.exceptions.RequestException as e:
            logger.error(
                f"{self.config.provider}: Request error for {operation} request to {url}: {e}"
            )
            raise

    def _log_request(self, method: str, url: str, operation: str, kwargs: Dict[str, Any]) -> None:
        """Log request details with comprehensive proxy information"""

        # Build proxy information string
        proxy_info = ""
        if self.config.proxy_config:
            if self.config.proxy_config.scope.should_use_proxy_for(operation):
                # Proxy is configured and will be used
                proxy_host = f"{self.config.proxy_config.host}:{self.config.proxy_config.port}"
                proxy_type = self.config.proxy_config.proxy_type.value
                has_auth = "authenticated" if self.config.proxy_config.auth else "no-auth"
                proxy_info = f" [proxy: {proxy_type}://{proxy_host} ({has_auth})]"
            else:
                # Proxy is configured but not used for this operation
                proxy_info = f" [proxy: disabled for operation '{operation}']"
        else:
            # No proxy configured
            proxy_info = " [proxy: none]"

        # Get timeout info
        timeout = kwargs.get("timeout", self.config.timeout)

        # Truncate URL for readability if very long
        display_url = url if len(url) <= 100 else f"{url[:80]}...{url[-17:]}"

        logger.debug(
            f"{self.config.provider}: {method} {operation} -> {display_url}"
            f"{proxy_info} [timeout: {timeout}s]"
        )

    def _log_response(self, response: requests.Response) -> None:
        """Log response details with timing information"""

        # Get response time if available
        elapsed = ""
        if hasattr(response, "elapsed"):
            elapsed_ms = int(response.elapsed.total_seconds() * 1000)
            elapsed = f" [{elapsed_ms}ms]"

        # Content type for context
        content_type = response.headers.get("Content-Type", "unknown")

        # Size info
        size = len(response.content)
        size_display = f"{size} bytes"
        if size > 1024 * 1024:  # > 1MB
            size_display = f"{size / (1024 * 1024):.2f} MB"
        elif size > 1024:  # > 1KB
            size_display = f"{size / 1024:.2f} KB"

        logger.debug(
            f"{self.config.provider}: Response {response.status_code} "
            f"({size_display}, {content_type}){elapsed}"
        )

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

            # Try to parse IP info if using httpbin
            try:
                result["ip_info"] = response.json()
            except (json.JSONDecodeError, AttributeError):
                result["ip_info"] = {"response": response.text[:100]}

        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Connection test failed: {e}")

        return result

    def close(self) -> None:
        """Close the session"""
        if self._session:
            self._session.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
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
        # Provider-specific defaults
        provider_defaults = {
            "joyn": {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
                "timeout": 30,
                "max_retries": 3,
            },
            "zdf": {
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "timeout": 25,
                "max_retries": 2,
            },
            # Add more providers as needed
        }

        # Get provider-specific defaults
        defaults = provider_defaults.get(provider_name, {})
        defaults.update(config_kwargs)
        defaults["provider"] = provider_name

        # Create request config
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
