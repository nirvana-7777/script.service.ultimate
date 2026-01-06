# streaming_providers/base/network/__init__.py
from .http_manager import HTTPManager, HTTPManagerFactory
from .proxy_manager import ProxyConfigManager

# Only export what consumers should use
__all__ = ["HTTPManager", "HTTPManagerFactory", "ProxyConfigManager"]
