# streaming_providers/providers/magenta2/constants.py
from typing import Optional

# ============================================================================
# Magenta2 Configuration
# ============================================================================

# Supported countries (Magenta2 is Germany-specific)
SUPPORTED_COUNTRIES = ["de"]

# Default country
DEFAULT_COUNTRY = "de"

MAGENTA2_LOGO = "https://upload.wikimedia.org/wikipedia/commons/thumb/e/e4/Magenta_TV_Logo_2024.svg/2339px-Magenta_TV_Logo_2024.svg.png"

# Platform configuration
#
# Each entry describes only what's needed to build the bootstrap/manifest
# request and the User-Agent. Everything else (client_model, device_model,
# sam3_client_id, all endpoint URLs) comes from the server's bootstrap/
# manifest response — see config_models.BootstrapConfig / ManifestConfig.
#
# Versions below are confirmed from real-device captures/logs:
#   - android-tv / atv-launcher: 3.180.7748 (Sebastian's current AndroidTV,
#     shape confirmed against real AndroidTV request logs). SMIL, DRM and
#     concurrency request *shapes* were only ever captured on atv-launcher
#     (v3.136.4682) — carried over to android-tv on the assumption the
#     selector/concurrency service doesn't vary by config_group. Treat that
#     part as unverified for android-tv specifically until confirmed by a
#     live-play capture.
#   - web: 2.128.5 (MacBook web client capture).
DEFAULT_PLATFORM = "android-tv"

MAGENTA2_PLATFORMS = {
    "android-tv": {
        "config_group": "atv-androidtv",
        "subscriber_type": "FTV_OTT_DT",
        "application_model": "DT:ATV-AndroidTV",
        "api_level": "30",
        "android_version": "11",
        "device_name": "SHIELD Android TV",
        "build_id": "RQ1A.210105.003",
        "build_flavor": "mdarcy",
        "version": "3.180.7748",
        "ua_template_plain": (
            "Dalvik/2.1.0 (Linux; U; Android {android_version}; "
            "{device_name} Build/{build_id}) "
            "((2.00T_ATV::{version}::{build_flavor}::))"
        ),
        "ua_template_subscriber": (
            "Dalvik/2.1.0 (Linux; U; Android {android_version}; "
            "{device_name} Build/{build_id}) "
            "((2.00T_ATV::{version}::{build_flavor}::{subscriber_type}))"
        ),
    },

    "atv-launcher": {
        "config_group": "atv-launcher",
        "subscriber_type": "FTV_OTT_DT",
        "application_model": "DT:ATV-Launcher",
        "api_level": "30",
        "android_version": "11",
        "device_name": "SHIELD Android TV",
        "build_id": "RQ1A.210105.003",
        "build_flavor": "mdarcy",
        "version": "3.180.7748",
        "ua_template_plain": (
            "Dalvik/2.1.0 (Linux; U; Android {android_version}; "
            "{device_name} Build/{build_id}) "
            "((2.00T_ATV::{version}::{build_flavor}::))"
        ),
        "ua_template_subscriber": (
            "Dalvik/2.1.0 (Linux; U; Android {android_version}; "
            "{device_name} Build/{build_id}) "
            "((2.00T_ATV::{version}::{build_flavor}::{subscriber_type}))"
        ),
    },

    "web": {
        "config_group": "web-mtv",
        "subscriber_type": "FTV_OTT_DT",
        "application_model": "DT:WEB",
        "api_level": "0",
        "android_version": "",           # unused for web
        "device_name": "",
        "build_id": "",
        "build_flavor": "",
        "version": "2.128.5",
        "ua_template_plain": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "ua_template_subscriber": None,  # web UA never has a suffix
    },
}


def render_user_agent(
    platform: str,
    subscriber_suffix: bool = False,
    version_override: Optional[str] = None,
) -> str:
    """
    Render the User-Agent string for a platform.

    Args:
        platform: key into MAGENTA2_PLATFORMS.
        subscriber_suffix: if True, use the template with the subscriber_type
            suffix (SMIL and DRM requests). If False, use the plain template
            (bootstrap, manifest, DCM requests).
        version_override: optional; replaces the platform's configured version.

    Raises:
        ValueError: if `platform` is not a known key in MAGENTA2_PLATFORMS.
    """
    cfg = MAGENTA2_PLATFORMS.get(platform)
    if cfg is None:
        raise ValueError(f"Unknown platform: {platform}")

    template = (
        cfg["ua_template_subscriber"] if subscriber_suffix
        else cfg["ua_template_plain"]
    )
    if template is None:
        template = cfg["ua_template_plain"]

    version = version_override or cfg["version"]

    if "{" not in template:
        return template

    return template.format(
        android_version=cfg["android_version"],
        device_name=cfg["device_name"],
        build_id=cfg["build_id"],
        build_flavor=cfg["build_flavor"],
        version=version,
        subscriber_type=cfg["subscriber_type"],
    )

# ============================================================================
# API Configuration - MINIMAL HARDCODING
# ============================================================================

# Only bootstrap endpoint is hardcoded - everything else discovered dynamically
MAGENTA2_BASE_URL = "https://prod.dcm.telekom-dienste.de/v1"
MAGENTA2_BOOTSTRAP_URL = MAGENTA2_BASE_URL + "/settings/{config_group}/bootstrap"
MAGENTA2_MANIFEST_URL = MAGENTA2_BASE_URL + "/settings/{config_group}/manifest"

# Fallback endpoints if discovery fails
MAGENTA2_FALLBACK_ENDPOINTS = {
    "OPENID_CONFIG": "https://accounts.login.idm.telekom.com/.well-known/openid-configuration",
    "TAA_AUTH": "https://taa.p7s1.io/api/v1/taa",
    "ENTITLEMENT": "https://entitlement.p7s1.io/api/user/entitlement-token",
}

# Emergency last-resort fallback ONLY — should never be reached in production
# since the account ID is extracted dynamically from the manifest's pvrBaseUrl.
# If this value is being used, it means both manifest and bootstrap discovery failed.
MAGENTA2_FALLBACK_ACCOUNT_URI = "http://access.auth.theplatform.com/data/Account/2709353023"

# ============================================================================
# Application Configuration
# ============================================================================

# Application identifiers
IDM = "TDGIDM"
# NOTE: no separate app-version constant. auth.py::to_taa_payload reads
# MAGENTA2_PLATFORMS[platform]["version"] directly, confirmed by a real TAA
# capture to be identical to the version embedded in the User-Agent — a
# previously separate APPVERSION2 constant here could drift from that value.

SSO_URL = "https://ssom.magentatv.de/login"
# SSO User Agent
SSO_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ============================================================================
# OAuth2 Configuration
# ============================================================================

# Legacy UUIDv4 client IDs.
#
# Used ONLY as a last-resort fallback if the bootstrap response fails to
# return a sam3ClientId — which in practice never happens, because a missing
# sam3ClientId already makes BootstrapConfig.from_api_response raise (see
# config_models.py), so discovery itself fails before this table would be
# consulted. Modern clients read sam3ClientId from the bootstrap response
# (baseSettings.sam3ClientId), not from this table.
MAGENTA2_LEGACY_CLIENT_IDS = {
    "web": "709115c2-f87e-4bad-9b94-28ac08d72cd9",
    "android-tv": "05f5f3df-1130-4707-a761-c04d0c50b7f2",
}

# OAuth2 scopes
MAGENTA2_OAUTH_SCOPE = "openid profile offline_access tvhubs"

# OAuth2 redirect URI
MAGENTA2_REDIRECT_URI = "https://web2.magentatv.de/authn/idm"

# ============================================================================
# Request Headers Configuration
# ============================================================================

# Headers for different API endpoints
MAGENTA2_HEADERS = {
    "DEFAULT": {"Content-Type": "application/json", "Accept": "application/json"},
    "SSO": {
        "User-Agent": SSO_USER_AGENT,
        "Content-Type": "application/json",
        "origin": "https://web2.magentatv.de",
        "referer": "https://web2.magentatv.de/",
    },
    "DCM": {"Content-Type": "application/json", "Accept": "application/json"},
    "OAUTH2": {"Content-Type": "application/x-www-form-urlencoded"},
}

# ============================================================================
# Authentication Configuration
# ============================================================================

# Grant types
GRANT_TYPES = {
    "LINE_AUTH": "urn:com:telekom:ott-app-services:access-auth",
    "AUTH_CODE": "authorization_code",
    "PASSWORD": "password",
    "REFRESH_TOKEN": "refresh_token",
    "REMOTE_LOGIN": "urn:telekom:com:grant-type:remote-login",
    "CLIENT_CREDENTIALS": "client_credentials",
}

# ============================================================================
# Content Configuration
# ============================================================================

# Content types
CONTENT_TYPE_LIVE = "LIVE"
CONTENT_TYPE_VOD = "VOD"

# Stream modes
MODE_LIVE = "live"
MODE_VOD = "vod"

# ============================================================================
# DRM Configuration
# ============================================================================

# DRM system
DRM_SYSTEM_WIDEVINE = "widevine"

# DRM request headers
DRM_REQUEST_HEADERS = {"Content-Type": "application/octet-stream"}

# ============================================================================
# Request Configuration
# ============================================================================

# Default timeout for HTTP requests (seconds)
DEFAULT_REQUEST_TIMEOUT = 30

# Default maximum retries for failed requests
DEFAULT_MAX_RETRIES = 3

# Default time window for EPG queries (hours)
DEFAULT_EPG_WINDOW_HOURS = 3

# Cache durations (seconds)
BOOTSTRAP_CACHE_DURATION = 3600   # 1 hour
OPENID_CONFIG_CACHE_DURATION = 86400  # 24 hours
MANIFEST_CACHE_DURATION = 7200    # 2 hours
SMIL_CACHE_DURATION = 3600        # 1 hour

# ============================================================================
# Error Codes
# ============================================================================

# Known error codes from Magenta2 API
ERROR_CODES = {
    "DEVICE_LIMIT_EXCEEDED": "deviceLimitExceeded",
    "PLAYBACK_RESTRICTED": "ENT_RVOD_Playback_Restricted",
    "UNAUTHORIZED": "ENT_Unauthorized",
    "INVALID_TOKEN": "INVALID_TOKEN",
    "SESSION_EXPIRED": "SESSION_EXPIRED",
}

# ============================================================================
# TAA Configuration
# ============================================================================

# TAA request template.
# NOTE: no "appVersion" key here — it must vary by platform (each platform
# has its own version in MAGENTA2_PLATFORMS), so auth.py::to_taa_payload
# sets it dynamically from platform_config["version"] instead of baking in
# a single fixed value that couldn't be correct for every platform.
TAA_REQUEST_TEMPLATE = {
    "accessTokenSource": IDM,
    "channel": {"id": "Tv"},
    "natco": "DE",
    "type": "telekom",
}

# ============================================================================
# Bootstrap Configuration
# ============================================================================

# Bootstrap parameters
BOOTSTRAP_PARAMS = {"$redirect": "false"}

# REMOVED: Old BOOTSTRAP_KEYS - now handled in config_models.py

# ============================================================================
# Quality Configuration
# ============================================================================

# Ordered quality preference fallback chains used by both live-channel selection
# and VOD playback.  Key = desired quality; value = ordered list to try.
QUALITY_FALLBACK: dict = {
    "UHDHDR": ["UHDHDR", "UHD", "HD", "SD"],
    "UHD":    ["UHD",    "HD",  "SD"],
    "HD":     ["HD",     "SD"],
    "SD":     ["SD"],
}

# Integer rank per quality label.
#
# NOTE: no longer used for live-channel dedup in channel_manager.py —
# SD/HD/UHD variants of a station have distinct station_ids in the entitled-
# channels feed, so a rank-based "keep the highest quality" merge in
# _fetch_station_metadata never actually fired on real data and has been
# removed (first entry wins for a genuinely duplicate station_id, with a
# debug log). Kept here because it may still be read by VOD quality
# selection alongside QUALITY_FALLBACK above — grep before deleting.
QUALITY_RANK: dict = {
    "SD":     1,
    "HD":     2,
    "UHD":    3,
    "UHDHDR": 4,
    "4K":     3,  # treat 4K as equivalent to UHD for ranking purposes
}

# ============================================================================
# VOD Configuration
# ============================================================================

# tvhubs base URL template — {client_model} is resolved at runtime from
# BootstrapConfig.client_model (server-provided). This URL is only a
# fallback; the live value should come from the manifest's
# tv_hubs.base_urls["ftv"] (or equivalent) via ProviderConfig.get_resolved_tvhub_url().
TVHUBS_BASE_URL = "https://tvhubs.t-online.de/v3/{client_model}"

# Flex IDs for the VOD catalogue.
# FLEX_ID_VOD_HOME is only used when personal-bar discovery fails (i.e. no
# homeUrl was obtained from bootstrap/manifest).
# FLEX_ID_VOD_DETAILS is stable across platforms — no discovery equivalent.
VOD_FLEX_ID_HOME = "164035"      # StructuredGrid fallback for VOD home screen
VOD_FLEX_ID_DETAILS = "202887"   # VodDetails flex ID
VOD_FLEX_ID_PLAYER = "202889"    # VodPlayer flex ID

# Pagination default for UnstructuredGrid lane requests
VOD_DEFAULT_PAGE_SIZE = 36

# Content-ID prefixes — used to route get_children() to the correct handler
VOD_PREFIX_SERIES = "GN_SERIES_"
VOD_PREFIX_SEASON = "GN_SEASON_"
VOD_PREFIX_EPISODE = "GN_EP"
VOD_PREFIX_MOVIE_MV = "GN_MV"
VOD_PREFIX_MOVIE_SH = "GN_SH"

# ============================================================================
# PVR / Recordings Configuration
# ============================================================================

# nPVR API endpoint path (appended to pvrBaseUrl from manifest)
PVR_GET_RECORDINGS_PATH = "/get-recordings"
PVR_RECORDINGS_PATH = "/recordings"

# recordings are deleted with HTTP DELETE on this listing-GUID-based path (returns 202 Accepted), 
# NOT via DELETE /recordings/{id} (which 404s for every identifier).
PVR_DELETE_RECORDING_FOR_LISTING_PATH = "/delete-recording-for-listing"

# Default and maximum page sizes for the nPVR get-recordings endpoint
PVR_DEFAULT_PAGE_LIMIT = 500
PVR_MAX_PAGE_LIMIT = 500

# Recording statuses used in the byRecordingStatus query parameter.
# The API accepts a pipe-separated list.
#
# Active statuses (exclude soft-deleted recordings) — used by default:
PVR_RECORDING_STATUSES_ACTIVE = [
    "SCHEDULED",
    "RECORDING",
    "RECORDED",
    "GENERATED",
    "FAILED",
]

# All statuses including soft-deleted — used when include_deleted=True:
PVR_RECORDING_STATUSES_ALL = [
    "SCHEDULED",
    "RECORDING",
    "RECORDED",
    "GENERATED",
    "FAILED",
    "TO_DELETE",
    "DELETED",
]

# Accept header required by the nPVR API (differs from standard JSON endpoints)
PVR_ACCEPT_HEADER = "application/json; v=2; charset=utf-8"

# Timer type IDs — used by TimersManager and get_timer_types()
PVR_TIMER_TYPE_EPG_ONE_SHOT = 1

# Recording statuses that represent pending timers (not yet captured).
# Used as the byRecordingStatus filter in TimersManager.get_timers().
# Kept as a list (like the STATUSES_ACTIVE/ALL siblings) for easy pipe-joining.
PVR_RECORDING_STATUSES_TIMERS = ["SCHEDULED"]

# ============================================================================
# Distribution Package Names
# ============================================================================

# Maps distribution IDs (returned by getApplicableDistributionRights) to
# human-readable package names.  Used only for logging — the raw IDs are still
# passed to the entitled-channels feed as before.
DISTRIBUTION_PACKAGE_NAMES: dict = {
    366135709: "All",
    268235282: "Magenta TV Basic",
    268235291: "HD & UHD Package",
    376449962: "FAST Channels",
    347334781: "MagentaSport & UHD Package",
    326643267: "Sky Sport + Bundesliga",
    424231094: "Sky Sport",
    424239773: "Sky Sport Bundesliga",
    268235273: "MagentaSport / myTeamTV",
    268236341: "Turkish Basic",
    268234936: "Turkish Premium",
    268235877: "Italian",
    268234482: "Polish",
    268234476: "RTL Premium",
    338937809: "Sky Sport News",
    452131099: "Fußball TV UHD",
    376449959: "Empty",
}