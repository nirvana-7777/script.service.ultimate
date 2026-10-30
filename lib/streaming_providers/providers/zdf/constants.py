# streaming_providers/providers/zdf/constants.py
"""
ZDF constants -- the SINGLE SOURCE OF TRUTH for every URL, header value,
identifier and default of this provider (README §4, §10).

Identity rule: ONE id, used everywhere
    directory name == AVAILABLE_PROVIDERS key == provider_name
    == PROVIDER_NAME == credentials / session / enable-setting key
Never rename it after release.

Upstream flow (all against api.zdf.de, no user account, no DRM):
    0. GET  https://www.zdf.de/  -> videoToken + appToken (auth.py, cached)
    1. GET  /graphql  getActiveLiveStreams (persisted query)  -> channel list
    2. POST /graphql  VideoByCanonical (only if the ptmd path is not cached)
    3. GET  /tmd/2/<player>/live/ptmd/<id>                    -> HLS manifest URL

The ``api-auth`` bearer values are the PUBLIC, expiring client tokens of the
ZDF web player, not user credentials. auth.py fetches them from the web page;
the static values below are only the FALLBACK when that fetch fails (they
stop working when ZDF rotates them). Override via the provider config dict
(``api_token`` / ``list_token`` / ``app_id``). Tokens must never be logged.
"""

import json
from typing import Optional

from ..globals import get_identity


class ZdfDefaults:
    PROVIDER_NAME = "zdf"
    PROVIDER_LABEL = "ZDF"              # shown in the UI, without country
    PROVIDER_LOGO = "https://thumb.wikimedia.org/wikipedia/commons/thumb/c/c1/ZDF_logo.svg/1280px-ZDF_logo.svg.png"                  # no verified logo URL available

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

    # --- HLS selection -------------------------------------------------------
    # The 24/7 channels were only seen with HLS formitaeten (no DASH), so
    # HLS is returned. A formitaet counts as HLS when its mimeType contains
    # "mpegurl" or its type contains "m3u8". Matching is case-insensitive.
    HLS_MIME_MARKER = "mpegurl"
    HLS_TYPE_MARKER = "m3u8"
    # Preferred quality entries, best first. "auto" is the master ZDF itself
    # lists first (and the one the web player / other clients use).
    HLS_QUALITY_ORDER = ("auto", "veryhigh", "high", "hd", "med", "low")
    AUDIO_CLASS_PREFERRED = "main"      # not "ad" (audio description)
    AUDIO_LANGUAGE_PREFERRED = "deu"

    # --- Token source ---------------------------------------------------------
    # The page embeds the tokens in Next.js "flight" chunks:
    #   self.__next_f.push([1,"...\"videoToken\":{\"apiToken\":\"..\",\"expiresAt\":\"..\"}..."])
    # videoToken -> GraphQL POST + PTMD ("api"), appToken -> channel list ("app").
    WEB_URL = "https://www.zdf.de/"
    TOKEN_KIND_API = "api"
    TOKEN_KIND_LIST = "app"
    FLIGHT_TOKEN_NAMES = {"videoToken": "api", "appToken": "app"}
    # Refresh this long before the token really expires.
    TOKEN_REFRESH_BUFFER_SECONDS = 300
    # After a failed token fetch use the static fallback and do not retry
    # before this many seconds have passed.
    TOKEN_FETCH_BACKOFF_SECONDS = 60

    # --- Fallback client identity (override via config, never log) --------------
    LIST_TOKEN = "aa3noh4ohz9eeboo8shiesheec9ciequ9Quah7el"
    API_TOKEN = "ahBaeMeekaiy5ohsai4bee4ki6Oopoi5quailieb"
    APP_ID = "ffw-mt-web-37e8d3ae"

    # --- Headers -------------------------------------------------------
    # UA is derived from the central registry so it cannot go stale. ZDF's
    # page / GraphQL / PTMD endpoints only read the UA as a plausibility
    # signal (no sec-ch-ua checks observed), so macOS Chrome is a safe
    # impersonation target. VERIFY: re-confirm no WAF appeared if this
    # provider ever starts failing on the page fetch.
    USER_AGENT = get_identity("macos", "chrome").user_agent
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
    # The token always comes from auth.py (fresh or fallback), never from here.
    def _base_headers(self) -> dict:
        return {
            "User-Agent": self.user_agent,
            "Accept-Language": ZdfDefaults.ACCEPT_LANGUAGE,
            "Origin": ZdfDefaults.ORIGIN,
            "Referer": ZdfDefaults.REFERER,
        }

    def page_headers(self) -> dict:
        """Plain page fetch of the token source (no api-auth)."""
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": ZdfDefaults.ACCEPT_LANGUAGE,
        }

    def list_headers(self, token: str) -> dict:
        """Persisted-query GET (channel list): appToken + app id."""
        headers = self._base_headers()
        headers["Accept"] = ZdfDefaults.ACCEPT_LIST
        headers["Content-Type"] = "application/json"
        headers["api-auth"] = f"Bearer {token}"
        headers["zdf-app-id"] = self.app_id
        return headers

    def graphql_headers(self, token: str) -> dict:
        """VideoByCanonical POST: videoToken."""
        headers = self._base_headers()
        headers["Accept"] = "*/*"
        headers["Content-Type"] = "application/json"
        headers["api-auth"] = f"Bearer {token}"
        return headers

    def ptmd_headers(self, token: str) -> dict:
        """PTMD GET: videoToken."""
        headers = self._base_headers()
        headers["Accept"] = ZdfDefaults.ACCEPT_PTMD
        headers["api-auth"] = f"Bearer {token}"
        return headers

    def stream_headers(self) -> dict:
        """
        Headers for manifest / segment fetches by the player (CDN).

        Deliberately WITHOUT api-auth / zdf-app-id: the CDN does not need them
        and sending them would leak the client token to the edge.
        """
        return {
            "User-Agent": self.user_agent,
            "Origin": ZdfDefaults.ORIGIN,
            "Referer": ZdfDefaults.REFERER,
        }