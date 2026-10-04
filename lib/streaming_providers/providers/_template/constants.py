# streaming_providers/providers/_template/constants.py
"""
{TODO: Provider name} constants.

All URLs, endpoint paths, static header values, parameter names, and
default parameters live here so no other file contains magic strings.
That includes the provider's machine name: provider.py, auth.py and any
persistence keys read PROVIDER_NAME from here.

Structure:
  * YourDefaults -- class-level constants.
  * YourConfig   -- instance config with override support, plus header
                    and URL builder methods.
"""

from typing import Dict, Optional


class YourDefaults:
    # Lowercase, no spaces; must equal the plugin directory name.
    PROVIDER_NAME = "TODO"
    PROVIDER_LOGO = "TODO: url"

    BASE_URL = "TODO: https://..."
    # Multi-country providers: per-country overrides, keyed by the
    # lowercase country code. Missing country -> BASE_URL.
    BASE_URLS: Dict[str, str] = {}
    WEBSITE = "TODO: https://..."

    PATH_LOGIN = "/api/login"
    PATH_CHANNELS = "/api/channels"
    # ... etc

    USER_AGENT = "TODO"
    TIMEOUT = 30

    # If the token travels in the URL or body instead of a header, keep
    # the parameter names here (they may differ per endpoint) and let
    # auth.with_token(url, param=...) pick one. Never hardcode them.
    TOKEN_PARAM = "token"

    # Static values the API expects (partner ids, client versions, ...).


class YourConfig:
    """
    Per-instance configuration.

    Attributes the template's provider.py and auth.py rely on:
        user_agent -- string, passed to _setup_http_manager.
        timeout    -- int seconds, passed to _setup_http_manager.
        base_url   -- resolved for the instance's country.
    """

    def __init__(
        self, config_dict: Optional[dict] = None, country: Optional[str] = None
    ):
        config = config_dict or {}
        self.country = (country or "").lower()
        default_base = YourDefaults.BASE_URLS.get(
            self.country, YourDefaults.BASE_URL
        )
        self.base_url = config.get("base_url", default_base)
        self.user_agent = config.get("user_agent", YourDefaults.USER_AGENT)
        self.timeout = config.get("timeout", YourDefaults.TIMEOUT)
        # ... any other provider-specific config fields

    # ----- Header builders -----

    def get_base_headers(self) -> dict:
        """Static, non-auth headers. Auth.build_headers() starts from this."""
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
        }

    # ----- URL builders -----

    def login_url(self) -> str:
        return f"{self.base_url}{YourDefaults.PATH_LOGIN}"

    def channels_url(self) -> str:
        return f"{self.base_url}{YourDefaults.PATH_CHANNELS}"