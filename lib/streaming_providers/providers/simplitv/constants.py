# streaming_providers/providers/simplitv/constants.py
"""
simpliTV constants.

All URLs, endpoint paths, static header values, and default parameters
live here so no other file contains magic strings.
"""

from typing import Optional


class SimpliTVDefaults:
    PROVIDER_NAME = "simplitv"
    PROVIDER_LOGO = "https://files.app.simplitv.at/files/orf1-hd-bunt.png"

    BASE_URL = "https://api.app.simplitv.at"
    WEBSITE = "https://streaming.simplitv.at"

    # --- Endpoint paths ------------------------------------------------
    PATH_AUTHENTICATE = "/v1/OrsUser/Authenticate"
    PATH_GET_DEVICES = "/v1/Devices/GetDevices"
    PATH_REGISTER_DEVICE = "/v1/Devices/RegisterDevice"
    PATH_CHANNEL_TILES = "/v1/EpgTile/FilterChannelTiles"
    PATH_PROGRAM_TILES = "/v1/EpgTile/FilterProgramTiles"
    PATH_TILE_DETAILS = "/v2/Tile/GetTiles"
    PATH_ACQUIRE_CONTENT = "/v1/Player/AcquireContent"
    PATH_GET_RECORDINGS = "/v2/Pvr/GetRecordings"
    PATH_SCHEDULE_RECORDING = "/v1/Pvr/ScheduleRecording"
    PATH_DELETE_RECORDING = "/v1/Pvr/DeleteRecording"

    # --- Token transport -----------------------------------------------
    # Most endpoints take `token`; GetRecordings (v2) takes `tokenValue`.
    TOKEN_PARAM = "token"
    TOKEN_PARAM_RECORDINGS = "tokenValue"

    # The existing addon sends the headers a second time as a `$headers`
    # query parameter on the two anonymous EPG endpoints. Mirrored here
    # because it is known to work.
    EPG_HEADERS_QUERY = (
        "$headers=%7B%22Content-Type%22:%22application%2Fjson%3B"
        "charset%3Dutf-8%22,%22X-Api-Date-Format%22:%22iso%22,"
        "%22X-Api-Camel-Case%22:true%7D"
    )

    # --- Platform / device identity ------------------------------------
    PLATFORM_CODENAME = "www"
    DEVICE_NAME = "Firefox"
    DEVICE_GENERAL_TYPE = "2"
    DEVICE_OS = "Windows"
    DEVICE_OS_VERSION = "10"

    # --- Headers -------------------------------------------------------
    USER_AGENT = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) "
        "Gecko/20100101 Firefox/110.0"
    )
    HEADER_API_DATE_FORMAT = "iso"
    HEADER_API_CAMEL_CASE = "true"

    TIMEOUT = 30

    # --- DRM -----------------------------------------------------------
    # DrmInfo indices in the AcquireContent response:
    # [0] = PlayReady, [1] = Widevine.
    DRM_INDEX_PLAYREADY = 0
    DRM_INDEX_WIDEVINE = 1

    # --- Auth ----------------------------------------------------------
    # simpliTV does not return expires_in; refresh well inside any
    # plausible server-side expiry.
    TOKEN_LIFETIME_SECONDS = 12 * 3600

    # --- Caches --------------------------------------------------------
    PLAYBACK_CACHE_TTL = 60          # AcquireContent responses, seconds
    PLAYBACK_CACHE_MAX = 256
    EPG_CACHE_TTL = 300              # EPG day-windows, seconds
    EPG_CACHE_MAX = 64

    # --- EPG -----------------------------------------------------------
    EPG_PAST_DAYS = 7
    EPG_FUTURE_DAYS = 7
    # The API is queried in day-sized windows, like the existing addon.
    EPG_CHUNK_HOURS = 24

    # --- Content-id grammar -------------------------------------------
    # live:<channel codename>         -> SimpliTVChannelManager
    # rec:<programme codename>        -> SimpliTVChannelManager (same
    #                                    AcquireContent call as live)
    # prog:<programme codename>       -> SimpliTVChannelManager (EPG
    #                                    programme replay; also the id
    #                                    form scheduling a recording
    #                                    needs)
    # catchup:<channel>@<unix_ts>     -> SimpliTVCatchupManager
    #                                    (restart-from-beginning)
    LIVE_PREFIX = "live:"
    RECORDING_PREFIX = "rec:"
    PROGRAMME_PREFIX = "prog:"
    CATCHUP_PREFIX = "catchup:"
    CATCHUP_TS_SEPARATOR = "@"

    # EPG broadcast ids: simplitv:<channel codename>:<start>:<programme
    # codename>. The last segment is what catchup takes as epg_id.
    BROADCAST_ID_PREFIX = "simplitv:"

    # --- Catchup -------------------------------------------------------
    # "Restart" plays the live manifest, which carries a 3 hour DVR
    # window; the player seeks (window - age - margin) seconds into it.
    CATCHUP_WINDOW_HOURS = 3
    CATCHUP_SEEK_MARGIN_SECONDS = 35


class SimpliTVConfig:
    """
    Per-instance configuration.

    Attributes relied on by provider.py / managers:
        user_agent        -- passed to _setup_http_manager.
        timeout           -- passed to _setup_http_manager.
        prefer_playready  -- selects PlayReady (True) or Widevine (False)
                             in get_channel_drm. Defaults to Widevine.
    """

    def __init__(self, config_dict: Optional[dict] = None):
        config = config_dict or {}
        self.base_url = config.get("base_url", SimpliTVDefaults.BASE_URL)
        self.user_agent = config.get("user_agent", SimpliTVDefaults.USER_AGENT)
        self.timeout = config.get("timeout", SimpliTVDefaults.TIMEOUT)
        self.prefer_playready = bool(config.get("prefer_playready", False))
        self.platform_codename = config.get(
            "platform_codename", SimpliTVDefaults.PLATFORM_CODENAME
        )

    # ----- Header builders --------------------------------------------

    def get_api_headers(self) -> dict:
        """
        Headers for the JSON API endpoints.

        These are *base* headers only -- the simpliTV token is not a
        header (see auth.py). Callers put the token in the query string
        (auth.with_token) or the body (auth.auth_body).
        """
        return {
            "User-Agent": self.user_agent,
            "Content-type": "application/json;charset=utf-8",
            "X-Api-Date-Format": SimpliTVDefaults.HEADER_API_DATE_FORMAT,
            "X-Api-Camel-Case": SimpliTVDefaults.HEADER_API_CAMEL_CASE,
            "Referer": f"{SimpliTVDefaults.WEBSITE}/",
        }

    def get_manifest_headers(self) -> dict:
        """Headers for /Player/AcquireContent (same UA as the API)."""
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
        }

    def get_stream_headers(self) -> dict:
        """
        Headers for manifest and segment requests made by the player.

        The addon gives inputstream the User-Agent and nothing else: the
        token is NOT part of the manifest URL (it only authenticates the
        AcquireContent request) and the CDN does not authenticate
        segments. Do not derive these from build_headers(), which carries
        JSON / X-Api-* / Referer headers the CDN never saw from the addon.
        """
        return {"User-Agent": self.user_agent}

    def get_license_headers(self, challenge: Optional[str] = None) -> dict:
        """
        Headers for the DRM licence request.

        The challenge custom data travels as a *header*, URL-quoted; the
        body is the raw CDM challenge (see channel_manager.get_channel_drm).
        """
        from urllib.parse import quote

        headers = {
            "User-Agent": self.user_agent,
            "Referer": f"{SimpliTVDefaults.WEBSITE}/",
            "Content-Type": "application/octet-stream",
        }
        if challenge:
            headers["drmchallengecustomdata"] = quote(challenge)
        return headers

    # ----- URL builders -----------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def authenticate_url(self) -> str:
        return self._url(SimpliTVDefaults.PATH_AUTHENTICATE)

    def get_devices_url(self) -> str:
        return self._url(SimpliTVDefaults.PATH_GET_DEVICES)

    def register_device_url(self) -> str:
        return self._url(SimpliTVDefaults.PATH_REGISTER_DEVICE)

    def channel_tiles_url(self) -> str:
        return self._url(SimpliTVDefaults.PATH_CHANNEL_TILES)

    def program_tiles_url(self) -> str:
        return (
            f"{self._url(SimpliTVDefaults.PATH_PROGRAM_TILES)}"
            f"?{SimpliTVDefaults.EPG_HEADERS_QUERY}"
        )

    def tile_details_url(self) -> str:
        return (
            f"{self._url(SimpliTVDefaults.PATH_TILE_DETAILS)}"
            f"?{SimpliTVDefaults.EPG_HEADERS_QUERY}"
        )

    def acquire_content_url(self) -> str:
        return self._url(SimpliTVDefaults.PATH_ACQUIRE_CONTENT)

    def get_recordings_url(self) -> str:
        return self._url(SimpliTVDefaults.PATH_GET_RECORDINGS)

    def schedule_recording_url(self) -> str:
        return self._url(SimpliTVDefaults.PATH_SCHEDULE_RECORDING)

    def delete_recording_url(self) -> str:
        return self._url(SimpliTVDefaults.PATH_DELETE_RECORDING)
