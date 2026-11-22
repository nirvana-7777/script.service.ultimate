# streaming_providers/base/network/http_manager.py
import json
import logging
import time
import urllib.parse
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ..errors import parse_retry_after
from ..models.proxy_models import ProxyConfig, RequestConfig
from ..utils.logger import logger

# Suppress urllib3 connection pool logging to prevent "Closing connection" messages
# This affects all providers using HTTPManager
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)

# Methods retried on 429 / connection errors. POST is added on top of these
# when RequestConfig.retry_post is True (the default).
_IDEMPOTENT_METHODS = ("HEAD", "GET", "OPTIONS", "PUT", "DELETE")

# Upper bound for any single wait caused by a Retry-After header. The server's
# full hint is still reported to callers (RateLimitError.retry_after); we just
# refuse to block a worker thread for minutes inside the transport layer.
_MAX_RETRY_AFTER_SECONDS = 30.0


class _CappedRetry(Retry):
    """urllib3 Retry that never sleeps longer than _MAX_RETRY_AFTER_SECONDS."""

    def get_retry_after(self, response):
        value = super().get_retry_after(response)
        if value is None:
            return None
        return min(value, _MAX_RETRY_AFTER_SECONDS)


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

    Error contract (identical on the requests and the curl_cffi backend):
    - HTTP status >= 400 RAISES requests.exceptions.HTTPError with `.response`
      set (an error response is never returned) -- unless the call passes
      `raise_for_status=False`.
    - Network failures raise requests.exceptions.ProxyError / Timeout /
      SSLError / ConnectionError / RequestException (curl_cffi's own
      exceptions are translated, they do not subclass the requests ones).
    - 429 is retried up to `config.max_retries` (Retry-After honoured, each
      wait capped); when retries are exhausted the last 429 is raised as a
      normal HTTPError, never as RetryError.
    - Map to typed provider errors with base.errors.error_from_exception().
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
        logger.debug(
            f"{self.config.provider}: _setup_session called, use_tls_impersonation={self.config.use_tls_impersonation}")

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
                        + (
                            f" via proxy {self.config.proxy_config.to_safe_url()}"
                            if proxies
                            else ""
                        )
                    )
                except ImportError:
                    logger.warning(
                        f"{self.config.provider}: curl_cffi requested but not installed, "
                        "falling back to requests"
                    )

        if not self._using_cffi:
            self._session = requests.Session()
            retry_methods = list(_IDEMPOTENT_METHODS)
            if self.config.retry_post:
                retry_methods.append("POST")
            # raise_on_status=False: once retries are exhausted the last 429
            # is returned and surfaces as a normal HTTPError (with .response)
            # instead of requests' RetryError (which has no response).
            retry_strategy = _CappedRetry(
                total=self.config.max_retries,
                backoff_factor=self.config.retry_delay,
                status_forcelist=[429],
                allowed_methods=retry_methods,
                raise_on_status=False,
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
        self.config = config
        self._last_url = None
        self._rebuild_session()

    def _rebuild_session(self) -> None:
        """
        Build a fresh session, carry the cookies over and close the old one.

        requests_cookies.update() accepts a RequestsCookieJar directly; we
        pass the jar (not a plain dict) so domain/path/expiry metadata is
        preserved rather than flattened. The old session is closed after the
        cookies were copied, otherwise its connection pool (or curl handle)
        leaks on every proxy/config change.
        """
        old_session = self._session
        old_cookies = old_session.cookies if old_session else None

        self._setup_session()

        if old_cookies is not None:
            self._session.cookies.update(old_cookies)  # type: ignore[arg-type]

        if old_session is not None:
            try:
                old_session.close()
            except Exception as e:  # never let cleanup break a config change
                logger.debug(f"{self.config.provider}: closing old session failed: {e}")

    def update_proxy(self, proxy_config: Optional[ProxyConfig]) -> None:
        """
        Update just the proxy configuration

        For plain `requests` sessions the proxy is resolved per-request from
        self.config.proxy_config (via get_request_kwargs), so updating the
        config alone is sufficient.

        For curl_cffi sessions the proxy is baked into the Session object at
        construction time (see _setup_session), so simply updating the config
        would silently leave the session using the old proxy. In that case we
        rebuild the session, preserving cookies across the rebuild.

        Args:
            proxy_config: New proxy configuration (None to disable proxy)
        """
        self.config.proxy_config = proxy_config

        if self._using_cffi:
            self._rebuild_session()

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
            operation: Operation type for proxy scoping: "api", "auth",
                "manifest" or "license" (see proxy_models.KNOWN_OPERATIONS).
                Any other string is proxied whenever the proxy master switch
                is on.
            **kwargs: Additional arguments for requests. The extra keyword
                `raise_for_status=False` returns 4xx/5xx responses instead of
                raising (use it when you need to read an error body).

        Returns:
            requests.Response object

        Raises:
            requests.exceptions.HTTPError: status >= 400 (`.response` is set)
            requests.exceptions.RequestException: any other request failure
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

    def patch(self, url: str, operation: str = "api", **kwargs) -> requests.Response:
        """Perform PATCH request with proxy support.

        Not retried on 429 (PATCH is not idempotent, see _IDEMPOTENT_METHODS).
        Takes the same kwargs as put(), including `raise_for_status=False`."""
        return self._make_request("PATCH", url, operation, **kwargs)

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
        logger.debug(f"{self.config.provider}: _using_cffi={self._using_cffi} for {method} {url}")

        # Not a requests kwarg: controls whether status >= 400 raises
        raise_for_status = kwargs.pop("raise_for_status", True)

        # Get base request configuration
        request_kwargs = self.config.get_request_kwargs(operation)

        # Merge with any additional kwargs (caller overrides win)
        request_kwargs.update(kwargs)

        # Work on a copy: the injections below must never mutate a headers
        # dict the caller keeps and reuses across requests (a stale Origin
        # from the first host would otherwise stick to every later call).
        headers = dict(request_kwargs.get("headers") or {})
        request_kwargs["headers"] = headers
        header_names = {name.lower() for name in headers}

        # Inject Referer from the last response URL, but only when the caller
        # opts in via config.inject_referer (mirrors inject_origin below).
        # Disabled by default because WAFs (like Akamai) flag API requests
        # that carry backend API URLs as the Referer. Providers that want
        # this should set inject_referer=True in their RequestConfig, or
        # continue setting Referer explicitly in their own header factories.
        if self.config.inject_referer and self._last_url and "referer" not in header_names:
            headers["Referer"] = self._last_url

        # Inject Origin derived from target URL only when explicitly requested.
        # Origin injection is opt-in because some non-browser APIs reject
        # requests that carry an unexpected Origin header.
        if self.config.inject_origin and "origin" not in header_names:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme and parsed.netloc:
                headers["Origin"] = f"{parsed.scheme}://{parsed.netloc}"

        # Log request details (excluding sensitive data)
        self._log_request(method, url, operation, request_kwargs)

        try:
            response = self._send(method, url, request_kwargs)

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

            # Raise for 4xx/5xx. Done here (not via response.raise_for_status())
            # so both backends raise the *requests* HTTPError; curl_cffi's own
            # HTTPError does not subclass it and would bypass every handler.
            if raise_for_status and response.status_code >= 400:
                raise requests.exceptions.HTTPError(
                    self._http_error_message(response), response=response
                )

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
            # NB: never `if e.response:` -- Response.__bool__ is `.ok`, which
            # is False for every 4xx/5xx, so the status used to log "unknown".
            response = e.response
            status = response.status_code if response is not None else "unknown"
            logger.error(
                f"{self.config.provider}: HTTP {status} error for {operation} request to {url}: {e}"
            )
            if response is not None:
                logger.debug(
                    f"{self.config.provider}: {status} response body: "
                    f"{self._body_snippet(response)}"
                )
            raise

        except requests.exceptions.RequestException as e:
            logger.error(
                f"{self.config.provider}: Request error for {operation} request to {url}: {e}"
            )
            raise

    def _send(self, method: str, url: str, request_kwargs: Dict[str, Any]):
        """
        Send one request on the active backend.

        requests: retries (429) are done by the mounted urllib3 adapter.
        curl_cffi: no adapter exists, so 429 retries are done here with the
        same limits, and curl_cffi exceptions are translated to their
        requests equivalents.
        """
        if not self._using_cffi:
            return self._session.request(method, url, **request_kwargs)

        # curl_cffi session has proxy baked in at construction — strip it from
        # per-request kwargs to prevent conflicts / double-proxy application
        request_kwargs.pop("proxies", None)

        attempt = 0
        while True:
            try:
                response = self._session.request(method, url, **request_kwargs)
            except requests.exceptions.RequestException:
                raise
            except Exception as exc:
                translated = self._translate_cffi_exception(exc)
                if translated is exc:
                    raise
                raise translated from exc

            if (
                response.status_code != 429
                or attempt >= self.config.max_retries
                or not self._method_is_retryable(method)
            ):
                return response

            delay = self._retry_delay_seconds(response, attempt)
            logger.warning(
                f"{self.config.provider}: HTTP 429 for {method} {url}; "
                f"retry {attempt + 1}/{self.config.max_retries} in {delay:.1f}s"
            )
            time.sleep(delay)
            attempt += 1

    def _method_is_retryable(self, method: str) -> bool:
        method = method.upper()
        if method in _IDEMPOTENT_METHODS:
            return True
        return method == "POST" and self.config.retry_post

    def _retry_delay_seconds(self, response, attempt: int) -> float:
        """Retry-After if present, else exponential backoff; always capped."""
        hinted = parse_retry_after(
            response.headers.get("Retry-After"), max_seconds=_MAX_RETRY_AFTER_SECONDS
        )
        if hinted is not None:
            return hinted
        return min(self.config.retry_delay * (2 ** attempt), _MAX_RETRY_AFTER_SECONDS)

    @staticmethod
    def _translate_cffi_exception(exc: Exception) -> Exception:
        """
        Map a curl_cffi exception to the matching requests exception.

        curl_cffi's exception classes do not inherit from requests', so
        without this every `except requests.exceptions.*` (here and in the
        providers) misses them. Unknown exceptions are returned unchanged.
        """
        try:
            from curl_cffi import CurlError
            from curl_cffi.requests import exceptions as cffi_exc
        except ImportError:
            return exc

        # Most specific first; names are looked up defensively because the
        # exact set differs between curl_cffi versions.
        pairs = (
            ("ProxyError", requests.exceptions.ProxyError),
            ("SSLError", requests.exceptions.SSLError),
            ("Timeout", requests.exceptions.Timeout),
            ("ConnectionError", requests.exceptions.ConnectionError),
            ("RequestException", requests.exceptions.RequestException),
        )
        for name, target in pairs:
            source = getattr(cffi_exc, name, None)
            if isinstance(source, type) and isinstance(exc, source):
                return target(str(exc))
        if isinstance(exc, CurlError):
            return requests.exceptions.RequestException(str(exc))
        return exc

    @staticmethod
    def _http_error_message(response) -> str:
        status = response.status_code
        kind = "Client" if status < 500 else "Server"
        reason = getattr(response, "reason", "") or ""
        return f"{status} {kind} Error: {reason} for url: {response.url}"

    @staticmethod
    def _body_snippet(response, limit: int = 500) -> str:
        """Truncated response text for debug logs (never raises)."""
        try:
            text = response.text or ""
        except Exception:
            return "<unreadable body>"
        if len(text) > limit:
            return f"{text[:limit]}... [{len(text) - limit} more chars]"
        return text

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
        # `elapsed` is a timedelta on requests but a plain float (seconds) on
        # some curl_cffi versions; a malformed Content-Length must not break
        # the request either -- this is only logging.
        elapsed = ""
        elapsed_attr = getattr(response, "elapsed", None)
        if elapsed_attr is not None:
            try:
                seconds = (
                    elapsed_attr.total_seconds()
                    if hasattr(elapsed_attr, "total_seconds")
                    else float(elapsed_attr)
                )
                elapsed = f" [{int(seconds * 1000)}ms]"
            except (TypeError, ValueError):
                pass

        size_display = "unknown size"
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                size = int(content_length)
            except (TypeError, ValueError):
                size = None
            if size is not None:
                if size > 1024 * 1024:
                    size_display = f"{size / (1024 * 1024):.2f} MB"
                elif size > 1024:
                    size_display = f"{size / 1024:.2f} KB"
                else:
                    size_display = f"{size} bytes"

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

        defaults = dict(provider_defaults.get(provider_name, {}))
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