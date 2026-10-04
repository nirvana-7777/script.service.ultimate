# streaming_providers/providers/simpli/constants.py
"""
simpliTV constants.

All URLs, endpoint paths, static header values, and default parameters
live here so no other file contains magic strings.
"""

from typing import Optional


class SimpliTVDefaults:
    PROVIDER_NAME = "simpli"
    PROVIDER_LOGO = "https://files.app.simplitv.at/files/orf1-hd-bunt.png"

    # --- Endpoints / hosts ---------------------------------------------
    # Confirmed against the browser capture: the API host is
    # api.app.austrostream.at (multi-tenant; simpliTV is the
    # X-Tenant-Codename: simpli tenant). The web app itself lives on
    # streaming.simpli.at, NOT streaming.simpli.at.
    BASE_URL = "https://api.app.austrostream.at"
    WEBSITE = "https://streaming.simpli.at"

    # --- Endpoint paths ------------------------------------------------
    PATH_AUTHENTICATE = "/v1/OrsUser/Authenticate"
    PATH_GET_DEVICES = "/v1/Devices/GetDevices"
    PATH_REGISTER_DEVICE = "/v1/Devices/RegisterDevice"
    PATH_CHANNEL_TILES = "/v1/EpgTile/FilterChannelTiles"
    PATH_PROGRAM_TILES = "/v1/EpgTile/FilterProgramTiles"
    PATH_EPG_AVAILABLE_DAYS = "/v1/EpgTile/GetAvailableDays"
    PATH_TILE_DETAILS = "/v2/Tile/GetTiles"
    PATH_ACQUIRE_CONTENT = "/v1/Player/AcquireContent"
    PATH_GET_RECORDINGS = "/v2/Pvr/GetRecordings"
    PATH_SCHEDULE_RECORDING = "/v1/Pvr/ScheduleRecording"
    PATH_DELETE_RECORDING = "/v1/Pvr/DeleteRecording"
    PATH_GET_USER_PRODUCTS = "/v1/IpottTransaction/GetUserProducts"
    PATH_GET_ALL_REMINDERS = "/v1/Reminder/GetAllReminders"

    # --- Token transport -----------------------------------------------
    # Most endpoints take `token`; GetRecordings (v2) takes `tokenValue`.
    TOKEN_PARAM = "token"
    TOKEN_PARAM_RECORDINGS = "tokenValue"

    # The API expects a `$headers` query parameter carrying a JSON blob
    # of the request headers. Two shapes appear in the browser capture:
    #
    #   * WITH Content-Type  — Authenticate, FilterChannelTiles,
    #                          GetAvailableDays, RegisterDevice
    #   * WITHOUT Content-Type — GetUserProducts, GetRecordings,
    #                          GetAllReminders, FilterProgramTiles
    #
    # Pre-encoded (percent-escaped) so they can be appended verbatim.
    EPG_HEADERS_QUERY_WITH_CT = (
        "$headers=%7B%22Content-Type%22:%22application%2Fjson%3B"
        "charset%3Dutf-8%22,%22X-Api-Date-Format%22:%22iso%22,"
        "%22X-Api-Resource-Language-Context%22:%22de%22,"
        "%22X-Api-Camel-Case%22:true%7D"
    )
    EPG_HEADERS_QUERY_NO_CT = (
        "$headers=%7B%22X-Api-Date-Format%22:%22iso%22,"
        "%22X-Api-Resource-Language-Context%22:%22de%22,"
        "%22X-Api-Camel-Case%22:true%7D"
    )

    # --- Platform / device identity ------------------------------------
    PLATFORM_CODENAME = "www"
    TENANT_CODENAME = "simpli"
    RESOURCE_LANGUAGE_CONTEXT = "de"

    DEVICE_NAME = "Firefox"
    DEVICE_BROWSER_VERSION = "110.0"
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
    # DrmInfo is returned as a list of objects with a `DrmSystem` string
    # (PlayReady / Widevine / FairPlay). Kodi cannot play FairPlay, and
    # Widevine is more broadly available than PlayReady, so we emit:
    #
    #   Widevine  priority 1
    #   PlayReady priority 2
    #
    # inputstream.adaptive picks the lowest-numbered system whose CDM is
    # actually present on the platform, so this ordering is safe even on
    # a PlayReady-only device.
    DRM_SYSTEM_WIDEVINE = "Widevine"
    DRM_SYSTEM_PLAYREADY = "PlayReady"
    DRM_PRIORITY_WIDEVINE = 1
    DRM_PRIORITY_PLAYREADY = 2

    # ISA placeholder for the raw CDM challenge in the license body.
    # LicenseConfig auto-base64-encodes plain strings, so "{CHA-RAW}"
    # is stored (and sent to ISA) as its base64 form; ISA decodes it
    # back to the literal placeholder and substitutes the challenge.
    REQ_DATA_CHA_RAW = "{CHA-RAW}"

    # MediaFiles[].Formats[].Type values in AcquireContent responses.
    FORMAT_TYPE_HLS = 2
    FORMAT_TYPE_DASH = 9

    # --- Auth ----------------------------------------------------------
    # Fallback only: the response now carries `tokenExpirationTime`,
    # which is preferred when present.
    TOKEN_LIFETIME_SECONDS = 12 * 3600

    # --- Caches --------------------------------------------------------
    PLAYBACK_CACHE_TTL = 60          # AcquireContent responses, seconds
    PLAYBACK_CACHE_MAX = 256
    EPG_CACHE_TTL = 300              # EPG day-windows, seconds
    EPG_CACHE_MAX = 64

    # --- EPG -----------------------------------------------------------
    # The server advertises its actual window via GetAvailableDays;
    # these are fallbacks used only when that call fails.
    EPG_PAST_DAYS = 7
    EPG_FUTURE_DAYS = 14
    EPG_CHUNK_HOURS = 24

    # --- Content-id grammar -------------------------------------------
    LIVE_PREFIX = "live:"
    RECORDING_PREFIX = "rec:"
    PROGRAMME_PREFIX = "prog:"
    CATCHUP_PREFIX = "catchup:"
    CATCHUP_TS_SEPARATOR = "@"
    BROADCAST_ID_PREFIX = "simpli:"

    # --- Catchup / timeshift ------------------------------------------
    # The DVR window is per-channel (AdditionalInfo.Epg_TimeshiftSeconds
    # in AcquireContent; 7200, 10800 and 14400 in the browser capture).
    # SimpliTVCatchupManager reads the per-channel value and falls back
    # to its own _MIN_TIMESHIFT_HOURS when the field is missing -- there
    # is deliberately no global "catchup window" constant, because the
    # API has none.
    CATCHUP_SEEK_MARGIN_SECONDS = 35


class SimpliTVConfig:
    """
    Per-instance configuration.

    Attributes relied on by provider.py / managers:
        user_agent  -- passed to _setup_http_manager.
        timeout     -- passed to _setup_http_manager.
    """

    def __init__(self, config_dict: Optional[dict] = None):
        config = config_dict or {}
        self.base_url = config.get("base_url", SimpliTVDefaults.BASE_URL)
        self.user_agent = config.get("user_agent", SimpliTVDefaults.USER_AGENT)
        self.timeout = config.get("timeout", SimpliTVDefaults.TIMEOUT)
        self.platform_codename = config.get(
            "platform_codename", SimpliTVDefaults.PLATFORM_CODENAME
        )

    # ----- Header builders --------------------------------------------

    def get_api_headers(self) -> dict:
        """
        Headers for the JSON API endpoints.

        The simpliTV token is NOT a header (see auth.py): it is passed
        as a URL query parameter or body field. These are the base
        headers the browser sends alongside every API call.
        """
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json;charset=utf-8",
            "X-Api-Date-Format": SimpliTVDefaults.HEADER_API_DATE_FORMAT,
            "X-Api-Camel-Case": SimpliTVDefaults.HEADER_API_CAMEL_CASE,
            "X-Api-Resource-Language-Context":
                SimpliTVDefaults.RESOURCE_LANGUAGE_CONTEXT,
            "X-Tenant-Codename": SimpliTVDefaults.TENANT_CODENAME,
            "Origin": SimpliTVDefaults.WEBSITE,
            "Referer": f"{SimpliTVDefaults.WEBSITE}/",
        }

    def get_manifest_headers(self) -> dict:
        """Headers for /Player/AcquireContent (UA + JSON accept)."""
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "X-Tenant-Codename": SimpliTVDefaults.TENANT_CODENAME,
            "Origin": SimpliTVDefaults.WEBSITE,
        }

    def get_stream_headers(self) -> dict:
        """
        Headers for manifest and segment requests made by the player.

        The CDN does not authenticate: the addon gives inputstream only
        the User-Agent. The token in the AcquireContent URL
        authenticates the API call, not the CDN fetch. Origin is added
        to match the browser capture; the CDN sends
        access-control-allow-origin: * so it is not required.
        """
        return {
            "User-Agent": self.user_agent,
            "Origin": SimpliTVDefaults.WEBSITE,
        }

    def get_license_headers(self, challenge: Optional[str] = None) -> dict:
        """
        Headers for the DRM licence request.

        The challenge custom data travels as a *header*, sent raw: the
        value is already base64 and must not be URL-quoted. The request
        body is the raw CDM challenge, injected by ISA via the
        {CHA-RAW} placeholder.

        The dict is passed to LicenseConfig, which urlencodes it for
        the inputstream.adaptive DRM JSON. ISA decodes the
        percent-encoding before sending the header, so the DRM server
        sees the raw base64 -- matching the browser. If a real device
        ever rejects the licence, the first thing to check is whether
        ISA truly decodes req_headers values.
        """
        headers = {
            "User-Agent": self.user_agent,
            "Origin": SimpliTVDefaults.WEBSITE,
            "Content-Type": "application/octet-stream",
        }
        if challenge:
            headers["drmchallengecustomdata"] = challenge
        return headers

    # ----- URL builders -----------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def _url_with_headers(self, path: str, *, include_ct: bool = True) -> str:
        """Append the pre-encoded `$headers=` query string to `path`."""
        q = (
            SimpliTVDefaults.EPG_HEADERS_QUERY_WITH_CT
            if include_ct
            else SimpliTVDefaults.EPG_HEADERS_QUERY_NO_CT
        )
        return f"{self._url(path)}?{q}"

    def authenticate_url(self) -> str:
        return self._url_with_headers(
            SimpliTVDefaults.PATH_AUTHENTICATE, include_ct=True
        )

    def get_devices_url(self) -> str:
        return self._url_with_headers(
            SimpliTVDefaults.PATH_GET_DEVICES, include_ct=False
        )

    def register_device_url(self) -> str:
        return self._url_with_headers(
            SimpliTVDefaults.PATH_REGISTER_DEVICE, include_ct=True
        )

    def channel_tiles_url(self) -> str:
        return self._url_with_headers(
            SimpliTVDefaults.PATH_CHANNEL_TILES, include_ct=True
        )

    def program_tiles_url(self) -> str:
        # FilterProgramTiles: no Content-Type in its $headers blob.
        return self._url_with_headers(
            SimpliTVDefaults.PATH_PROGRAM_TILES, include_ct=False
        )

    def epg_available_days_url(self) -> str:
        return self._url_with_headers(
            SimpliTVDefaults.PATH_EPG_AVAILABLE_DAYS, include_ct=True
        )

    def tile_details_url(self) -> str:
        return self._url_with_headers(
            SimpliTVDefaults.PATH_TILE_DETAILS, include_ct=False
        )

    def acquire_content_url(self) -> str:
        # AcquireContent does NOT use $headers; it carries the token
        # and deviceKey directly in the query string.
        return self._url(SimpliTVDefaults.PATH_ACQUIRE_CONTENT)

    def get_recordings_url(self) -> str:
        return self._url_with_headers(
            SimpliTVDefaults.PATH_GET_RECORDINGS, include_ct=False
        )

    def schedule_recording_url(self) -> str:
        return self._url_with_headers(
            SimpliTVDefaults.PATH_SCHEDULE_RECORDING, include_ct=True
        )

    def delete_recording_url(self) -> str:
        return self._url_with_headers(
            SimpliTVDefaults.PATH_DELETE_RECORDING, include_ct=True
        )

    def user_products_url(self) -> str:
        return self._url_with_headers(
            SimpliTVDefaults.PATH_GET_USER_PRODUCTS, include_ct=False
        )

    def reminders_url(self) -> str:
        return self._url_with_headers(
            SimpliTVDefaults.PATH_GET_ALL_REMINDERS, include_ct=False
        )