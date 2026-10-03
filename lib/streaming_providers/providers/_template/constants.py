# streaming_providers/providers/_template/constants.py
"""
{TODO: Provider name} constants.

All URLs, endpoint paths, static header values, and default parameters
live here so no other file contains magic strings.

Structure:
  * YourDefaults -- class-level constants.
  * YourConfig   -- instance config with override support, plus header
                    and URL builder methods.
"""


class YourDefaults:
    PROVIDER_NAME = "TODO"
    PROVIDER_LOGO = "TODO: url"

    BASE_URL = "TODO: https://..."
    WEBSITE = "TODO: https://..."

    PATH_LOGIN = "/api/login"
    PATH_CHANNELS = "/api/channels"
    # ... etc

    USER_AGENT = "TODO"
    TIMEOUT = 30

    # Static values the API expects (partner ids, client versions, ...).


class YourConfig:
    """
    Per-instance configuration.

    Attributes the template's provider.py relies on:
        user_agent -- string, passed to _setup_http_manager.
        timeout    -- int seconds, passed to _setup_http_manager.
    """

    def __init__(self, config_dict: dict = None):
        config = config_dict or {}
        self.base_url = config.get("base_url", YourDefaults.BASE_URL)
        self.user_agent = config.get("user_agent", YourDefaults.USER_AGENT)
        self.timeout = config.get("timeout", YourDefaults.TIMEOUT)
        # ... any other provider-specific config fields

    # ----- Header builders -----

    def get_base_headers(self) -> dict:
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
        }

    # ----- URL builders -----

    def login_url(self) -> str:
        return f"{self.base_url}{YourDefaults.PATH_LOGIN}"

    def channels_url(self) -> str:
        return f"{self.base_url}{YourDefaults.PATH_CHANNELS}"