# streaming_providers/providers/example/constants.py
"""
Example constants -- the SINGLE SOURCE OF TRUTH for every URL, header value,
identifier and default of this provider. No magic strings anywhere else
(managers, drm.py and auth.py all read from here).

Identity rule (the one that bites): ONE id, used everywhere
    directory name == AVAILABLE_PROVIDERS key == provider_name
    == PROVIDER_NAME == credentials / session / enable-setting key
Never rename it after release (stored credentials and enable flags are
keyed by it).
"""

from typing import Optional


class ExampleDefaults:
    PROVIDER_NAME = "example"
    PROVIDER_LABEL = "Example"          # shown in the UI, without country
    PROVIDER_LOGO = "https://example.invalid/logo.png"

    # SUPPORTED_COUNTRIES semantics (see README §Countries):
    #   ()/[]      single-country provider, default country
    #   ("DE",)    exactly one: the registry pins the construction country
    #              to this entry (UPPERCASE, verbatim)
    #   ("DE","AT") several: the registry fans out example_de, example_at
    #              (lowercase)
    SUPPORTED_COUNTRIES = ("DE",)

    # --- Hosts / paths -------------------------------------------------
    BASE_URL = "https://api.example.invalid"
    ORIGIN = "https://www.example.invalid"
    PATH_LOGIN = "/v1/login"
    PATH_CHANNELS = "/v1/channels"
    PATH_PLAYOUT = "/v1/playout/{channel_id}"

    # --- Headers -------------------------------------------------------
    USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"
    TIMEOUT = 30

    # --- Auth ----------------------------------------------------------
    # Fallback only: prefer the expiry the login response carries.
    TOKEN_LIFETIME_SECONDS = 3600
    # Re-login this long before the token really expires.
    TOKEN_REFRESH_BUFFER_SECONDS = 300

    # --- Caches --------------------------------------------------------
    PLAYOUT_CACHE_TTL = 5.0     # manifest + DRM share one playout call


class ExampleConfig:
    """
    Per-instance configuration.

    ONE instance is created by the provider and SHARED with auth, managers
    and drm.py. Never rebuild a second config from a subset of values --
    that is how header drift between layers happens.
    """

    def __init__(self, config_dict: Optional[dict] = None):
        config = config_dict or {}
        self.base_url = config.get("base_url", ExampleDefaults.BASE_URL)
        self.user_agent = config.get("user_agent", ExampleDefaults.USER_AGENT)
        self.timeout = config.get("timeout", ExampleDefaults.TIMEOUT)

    # ----- URL builders (no f-strings with hosts anywhere else) --------
    def url(self, path: str, **fmt) -> str:
        return f"{self.base_url}{path.format(**fmt)}"

    # ----- Header builders ---------------------------------------------
    def api_headers(self, access_token: Optional[str] = None) -> dict:
        """Headers for the provider's JSON API (NOT for the CDN)."""
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": ExampleDefaults.ORIGIN,
        }
        if access_token:
            headers["Authorization"] = f"Bearer {access_token}"
        return headers

    def stream_headers(self) -> dict:
        """
        Headers for MPD / segment fetches by the player (CDN).

        Keep this separate from api_headers(): the CDN usually wants only
        User-Agent / Origin / Referer, and sending API headers (JSON
        Content-Type, tenant ids, tokens) to it is noise at best and a
        token leak at worst.
        """
        return {
            "User-Agent": self.user_agent,
            "Origin": ExampleDefaults.ORIGIN,
        }
