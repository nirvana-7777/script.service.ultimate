# streaming_providers/providers/zdf/constants.py
"""
ZDF constants -- the SINGLE SOURCE OF TRUTH for every URL, header value,
identifier and default of this provider (README §4, §10).

Identity rule: ONE id, used everywhere
    directory name == AVAILABLE_PROVIDERS key == provider_name
    == PROVIDER_NAME == credentials / session / enable-setting key
Never rename it after release.

Upstream flow (all against api.zdf.de, no user account, no DRM):
    1. GET  /graphql  getActiveLiveStreams (persisted query)  -> channel list
    2. POST /graphql  VideoByCanonical (only if the ptmd path is not cached)
    3. GET  /tmd/2/<player>/live/ptmd/<id>                    -> DASH manifest URL

The two ``api-auth`` bearer values are the PUBLIC client tokens of the ZDF web
player (visible in any browser capture), not user credentials. ZDF rotates them
from time to time: override via the provider config dict
(``api_token`` / ``list_token`` / ``app_id``) instead of editing this file.
They must never be logged.
"""

import json
from typing import Optional


class ZdfDefaults:
    PROVIDER_NAME = "zdf"
    PROVIDER_LABEL = "ZDF"              # shown in the UI, without country
    PROVIDER_LOGO = ""                  # no verified logo URL available

    # Single entry: the registry pins the construction country to "DE"
    # (UPPERCASE); the provider lower-cases it for the storage managers.
    SUPPORTED_COUNTRIES = ("DE",)

    # --- Hosts / paths -------------------------------------------------
    BASE_URL = "https://api.zdf.de"
    ORIGIN = "https://www.zdf.de"
    REFERER = "https://www.zdf.de/"
    PATH_GRAPHQL = "/graphql"

    # --- GraphQL (channel list = persisted query) -------------------------
    LIST_OPERATION = "getActiveLiveStreams"
    LIST_QUERY_HASH = "b2a5abbc0551e5206f26c571d9ed3a413c45513ec099785ad9280718c9d82423"
    CLIENT_LIBRARY = {"name": "@apollo/client", "version": "4.1.9"}

    # --- PTMD (playout metadata) -----------------------------------------
    # The channel list delivers e.g. "/tmd/2/{playerId}/live/ptmd/247onAir-203";
    # the web player substitutes the placeholder with this id.
    PLAYER_ID = "ngplayer_2_5"
    PLAYER_ID_PLACEHOLDER = "{playerId}"
    # Real 24/7 channels point to ".../live/ptmd/247onAir-<n>". Event streams
    # (sports, services) and test items do not, and are not channels.
    LIVE247_MARKER = "/live/ptmd/247onAir-"

    # --- DASH selection ----------------------------------------------------
    # Only DASH is wanted (no HLS). A formitaet counts as DASH when its
    # mimeType contains "dash" or its type contains "mpd".
    DASH_MIME_MARKER = "dash"
    DASH_TYPE_MARKER = "mpd"
    # Preferred quality entries, best first ("auto" = the adaptive master).
    DASH_QUALITY_ORDER = ("auto", "veryhigh", "high", "hd", "med", "low")
    AUDIO_CLASS_PREFERRED = "main"      # not "ad" (audio description)
    AUDIO_LANGUAGE_PREFERRED = "deu"

    # --- Public web-client identity (override via config, never log) -----------
    LIST_TOKEN = "aa3noh4ohz9eeboo8shiesheec9ciequ9Quah7el"
    API_TOKEN = "ahBaeMeekaiy5ohsai4bee4ki6Oopoi5quailieb"
    APP_ID = "ffw-mt-web-37e8d3ae"

    # --- Headers -------------------------------------------------------
    USER_AGENT = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36"
    )
    ACCEPT_LIST = "application/graphql-response+json,application/json;q=0.9"
    ACCEPT_PTMD = "application/vnd.de.zdf.v1.0+json"
    ACCEPT_LANGUAGE = "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7"
    TIMEOUT = 30

    # --- Caches --------------------------------------------------------
    # canonical -> resolved ptmd path (filled by get_channels, so most zaps
    # need no VideoByCanonical round-trip).
    PTMD_PATH_CACHE_TTL = 300.0

    # --- Cosmetics -----------------------------------------------------
    # `tvService` of the list is used as channel name; these fix the spelling.
    CHANNEL_NAME_OVERRIDES = {
        "KI.KA": "KiKA",
        "PHOENIX": "phoenix",
        "arte": "ARTE",
    }


# Minimal query: only the fields the provider reads (all of them appear in the
# web player's own VideoByCanonical request).
VIDEO_BY_CANONICAL_QUERY = """
query VideoByCanonical($canonical: String!) {
  videoByCanonical(canonical: $canonical) {
    id
    canonical
    title
    currentMediaType
    currentMedia {
      nodes {
        ptmdTemplate
        ... on LiveMedia {
          geoLocation
          tvService
          encryption
          liveMediaType
        }
        id
      }
    }
  }
}
"""


class ZdfConfig:
    """
    Per-instance configuration.

    ONE instance is created by the provider and SHARED with auth and the
    manager. Never rebuild a second config from a subset of values.
    """

    def __init__(self, config_dict: Optional[dict] = None):
        config = config_dict or {}
        self.base_url = config.get("base_url", ZdfDefaults.BASE_URL)
        self.user_agent = config.get("user_agent", ZdfDefaults.USER_AGENT)
        self.timeout = config.get("timeout", ZdfDefaults.TIMEOUT)
        self.api_token = config.get("api_token", ZdfDefaults.API_TOKEN)
        self.list_token = config.get("list_token", ZdfDefaults.LIST_TOKEN)
        self.app_id = config.get("app_id", ZdfDefaults.APP_ID)

    # ----- URL / query builders -----------------------------------------
    def url(self, path: str, **fmt) -> str:
        return f"{self.base_url}{path.format(**fmt)}"

    def list_query_params(self) -> dict:
        """Query string of the persisted-query GET (compact JSON, like the web client)."""
        extensions = {
            "clientLibrary": ZdfDefaults.CLIENT_LIBRARY,
            "persistedQuery": {"version": 1, "sha256Hash": ZdfDefaults.LIST_QUERY_HASH},
        }
        return {
            "operationName": ZdfDefaults.LIST_OPERATION,
            "variables": "{}",
            "extensions": json.dumps(extensions, separators=(",", ":")),
        }

    # ----- Header builders ------------------------------------------------
    def _base_headers(self) -> dict:
        return {
            "User-Agent": self.user_agent,
            "Accept-Language": ZdfDefaults.ACCEPT_LANGUAGE,
            "Origin": ZdfDefaults.ORIGIN,
            "Referer": ZdfDefaults.REFERER,
        }

    def list_headers(self) -> dict:
        """Persisted-query GET (channel list)."""
        headers = self._base_headers()
        headers["Accept"] = ZdfDefaults.ACCEPT_LIST
        headers["Content-Type"] = "application/json"
        headers["api-auth"] = f"Bearer {self.list_token}"
        headers["zdf-app-id"] = self.app_id
        return headers

    def graphql_headers(self) -> dict:
        """VideoByCanonical POST."""
        headers = self._base_headers()
        headers["Accept"] = "*/*"
        headers["Content-Type"] = "application/json"
        headers["api-auth"] = f"Bearer {self.api_token}"
        return headers

    def ptmd_headers(self) -> dict:
        """PTMD GET."""
        headers = self._base_headers()
        headers["Accept"] = ZdfDefaults.ACCEPT_PTMD
        headers["api-auth"] = f"Bearer {self.api_token}"
        return headers

    def stream_headers(self) -> dict:
        """
        Headers for MPD / segment fetches by the player (CDN).

        Deliberately WITHOUT api-auth / zdf-app-id: the CDN does not need them
        and sending them would leak the client token to the edge.
        """
        return {
            "User-Agent": self.user_agent,
            "Origin": ZdfDefaults.ORIGIN,
            "Referer": ZdfDefaults.REFERER,
        }
