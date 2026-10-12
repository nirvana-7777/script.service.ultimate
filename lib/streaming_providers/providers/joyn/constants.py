# streaming_providers/providers/joyn/constants.py
# -*- coding: utf-8 -*-
"""
Joyn provider constants - Cleaned and organized
"""

# ============================================================================
# Provider Metadata
# ============================================================================

# The one id: directory name == registry key == provider_name == credentials key.
PROVIDER_NAME = "joyn"

JOYN_LOGO = "https://upload.wikimedia.org/wikipedia/de/thumb/7/74/Joyn_%28Streaminganbieter%29_logo.svg/2560px-Joyn_%28Streaminganbieter%29_logo.svg.png"

# ============================================================================
# Authentication - 7pass OIDC
# ============================================================================

JOYN_7PASS_BASE_URL = "https://auth.7pass.de"

# 7pass OIDC endpoints — reference only. auth.py's login flow hardcodes these same
# paths inline (verified against working traffic) rather than importing this dict;
# keep the two in sync if you change one.
JOYN_7PASS_ENDPOINTS = {
    "AUTHORIZE": f"{JOYN_7PASS_BASE_URL}/authz-srv/authz",
    "TOKEN": f"{JOYN_7PASS_BASE_URL}/token",
    "LOGIN": f"{JOYN_7PASS_BASE_URL}/login-srv/login",
    "CONSENT_ACCEPT": f"{JOYN_7PASS_BASE_URL}/consent-management-srv/consent/scope/accept",
    "PRECHECK_CONTINUE": f"{JOYN_7PASS_BASE_URL}/login-srv/precheck/continue",
    "USER_CHECK_EXISTS": f"{JOYN_7PASS_BASE_URL}/users-srv/user/checkexists",
    "REGISTRATION_SETUP": f"{JOYN_7PASS_BASE_URL}/registration-setup-srv/public/list",
    "VERIFICATION_CONFIGURED": f"{JOYN_7PASS_BASE_URL}/verification-srv/v2/setup/public/configured/list",
}

# Joyn auth endpoints (non-OIDC)
JOYN_AUTH_ENDPOINTS = {
    "REFRESH": "https://auth.joyn.de/auth/refresh",  # Token refresh endpoint
}

# OAuth2 Configuration
JOYN_OAUTH_SCOPE = "openid email profile offline_access"

# Device IDs for different platforms (fallback for client identification)
DEVICE_IDS = {
    "web": "655e06a5-829b-40c7-8084-077b87d26f8c",
    "android": "05f5f3df-1130-4707-a761-c04d0c50b7f2",
    "ios": "21218403-52ec-4a65-abf4-f36a0eadd631",
}

# ============================================================================
# HTTP Headers & User Agent
# ============================================================================

# Chrome 154 — matches the current reference web client.
# The User-Agent AND the client hints (sec-ch-ua*) are derived from the same
# values: the Cloudflare WAF in front of 7pass / the license host compares them,
# and a UA that says "Chrome 154 / Windows" next to hints that say "Chrome 153 /
# macOS" is a classic bot signature. Bump JOYN_BROWSER_MAJOR, nothing else.
JOYN_BROWSER_MAJOR = "154"
JOYN_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    f"(KHTML, like Gecko) Chrome/{JOYN_BROWSER_MAJOR}.0.0.0 Safari/537.36"
)
JOYN_SEC_CH_UA = (
    f'"Google Chrome";v="{JOYN_BROWSER_MAJOR}", "Not_A Brand";v="8", '
    f'"Chromium";v="{JOYN_BROWSER_MAJOR}"'
)
JOYN_SEC_CH_UA_PLATFORM = '"Windows"'
JOYN_CLIENT_VERSION = "5.1592.3"
DEFAULT_PLATFORM = "web"

# Base authentication headers (without dynamic values)
JOYN_AUTH_HEADERS_BASE = {
    "User-Agent": JOYN_USER_AGENT,
    "Accept": "application/json",
    "Content-Type": "application/json",
    "Origin": "https://www.joyn.de",  # Base origin, overridden per country
    "joyn-client-version": JOYN_CLIENT_VERSION,
}

# Base API headers (without auth token)
JOYN_API_BASE_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": JOYN_USER_AGENT,
}

# ============================================================================
# GraphQL Configuration
# ============================================================================

JOYN_GRAPHQL_BASE_URL = "https://api.joyn.de/graphql"

# Persisted-query registry. Every GraphQL operation the provider uses lives
# here, hash and operation name side by side, so a reader sees both at once
# and they cannot drift apart. Callers name an operation by its key; the
# URL builder (graphql.py) reads both dicts.
#
# Adding a new operation:
#   1. Capture the request in a browser (DevTools → Network → the GraphQL call)
#   2. Copy the sha256Hash from the `extensions` query parameter here
#   3. Copy the operationName (or the operationName query parameter) here
#   4. Note where the hash came from, in a comment, so a future maintainer
#      can tell whether it is a captured value or a legacy const.py import.
GRAPHQL_QUERY_HASHES = {
    # --- Live TV ---
    "LIVE_PLAYER":          "52b37a3cf5bc75e56026aed7b0d234874eeabd2eccd369d0cd3d3a6ea15ef566",
    "LIVE_CHANNELS":        "b7703103ddd0516be6b49ed66186092a6c6f6d815ccc502a9f50800a8cc18dd2",
    "LIVESTREAM_BY_BRAND":  "333399353bead5c153684c1c326504e82e7494ae2e89ca1d11d4ad76a16a839e",
    "LIVESTREAM_OVERVIEW":  "5a094812b90747ed18d2eac87f8b29a82e403a02f329d03478f7b2a5cf6ca463",
    "PLAYABLE_LIVESTREAM":  "2057248fde6948eebc02b03bb4244a1361707c96ed8bab25027d1f3a80ea0cb8",

    # --- VOD ---
    "NAVIGATION":           "818622ff5afe143664241034ba0c537650ec9a2eeae4d568830b47d8de605b7e",
    "LANDING_PAGE":         "5838ac6b328cda91a70da264d5be09d4735cf95de8d9ee00cec60e77fcc3df08",
    "LANDING_BLOCKS":       "1655591f83b0dc1508ad4d52c5f37f72d410f48ad08c3e5f2de8622f86a21c68",
    "GET_ME_STATE":         "55ebb3812b45628017ee6c7f36f0b88a94e9778b9f11ad8a6fc05849182c07ec",
    "LIVE_LANE":            "51659c62d4e4a6628d1e512190a3b0659486478b12be494875bef5a83dcb79ed",
    "HERO_RESUME":          "d3b7e480f593ba4866598f8cfe95185b3e400fcff112c026dc4e1b5ad4b0d537",
    "COLLECTION_QUERY":     "bdf4e08de65351750eefb2165a58af50c9e4b3526b78cd75e2066df2bc7ec8d8",
    "PAGE_OVERVIEW_GENRE":  "37ba6d0dde470df3f8999d49bcd24bc5c72b8e7192768026d82447c664c6ab7f",
    "SEASON":               "ee2396bb1b7c9f800e5cefd0b341271b7213fceb4ebe18d5a30dab41d703009f",
    "MOVIE_DETAIL":         "9ae6bcd8c45a5e350438d1cc415a022fe053e938c93438509f60ae3abb425fa7",
    "PLAYABLE_ASSET":       "e2db6e6f9090f14848d3989920a1342f6813099c65ee7faef1e334f23e390970",
    # Recovered from the legacy addon's const.py (SEARCH.HASH) — not captured
    # independently from live traffic like the hashes above, so keep an eye on
    # this if Joyn ever rotates persisted-query hashes.
    "SEARCH":               "bb2bab6cbe17321d7eddd5006e7f40765faedd79790b193a59d83f4640694856",
}

GRAPHQL_OPERATIONS = {
    "LIVE_PLAYER":          "PageLivePlayerClientSide",
    "LIVE_CHANNELS":        "LiveChannelsAndEpg",
    "LIVESTREAM_BY_BRAND":  "LivestreamIdByBrand",
    "LIVESTREAM_OVERVIEW":  "LivestreamOverviewByBrand",
    "PLAYABLE_LIVESTREAM":  "PlayableLivestream",
    "NAVIGATION":           "Navigation",
    "LANDING_PAGE":         "LandingPageClient",
    "LANDING_BLOCKS":       "LandingBlocks",
    "GET_ME_STATE":         "GetMeState",
    "LIVE_LANE":            "LiveLane",
    "HERO_RESUME":          "HeroLandingResumePositionsWithToken",
    "COLLECTION_QUERY":     "PageOverviewCollectionQuery",
    "PAGE_OVERVIEW_GENRE":  "PageOverviewGenre",
    "SEASON":               "Season",
    "MOVIE_DETAIL":         "PageMovieDetailStatic",
    "PLAYABLE_ASSET":       "PlayableAssetWithToken",
    # Legacy const.py names this operation "SearchQ", not "Search".
    "SEARCH":               "SearchQ",
}

# Base GraphQL headers (the shared header set without the per-call additions
# built by JoynConfig.graphql_headers()).
JOYN_GRAPHQL_BASE_HEADERS = {
    "X-Api-Key": "4f0fd9f18abbe3cf0e87fdb556bc39c8",
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": JOYN_USER_AGENT,
}

# GraphQL query defaults (used by the channel and EPG managers)
GRAPHQL_PERSISTED_QUERY_VERSION = 1
GRAPHQL_LIVE_CHANNELS_FILTER = "DEFAULT"
GRAPHQL_MAX_RESULTS = 5000
GRAPHQL_OFFSET = 0

# ============================================================================
# Streaming Configuration
# ============================================================================

JOYN_STREAMING_ENDPOINTS = {
    "ENTITLEMENT": "https://entitlements-service-alb.prd.platform.s.joyn.de/api/user/entitlement-token",
    "PLAYLIST": "https://api.vod-prd.s.joyn.de/v1/channel/{channel_id}/playlist",
    "ASSET_PLAYLIST": "https://api.vod-prd.s.joyn.de/v1/asset/{asset_id}/playlist",
}

# Default video configuration for playlist requests.
#
# IMPORTANT: the playlist request is signed over the *exact* JSON string built
# from this dict (see create_video_payload). If you change any key or value
# here, the signature sent to api.vod-prd.s.joyn.de will change with it.
DEFAULT_VIDEO_CONFIG = {
    "enableDolbyAtmos": True,
    "enableSubtitles": True,
    "manufacturer": "",
    "maxResolution": 2160,
    "model": "",
    "platform": "android-tv",
    "protectionSystem": "widevine",
    "streamingFormat": "dash",
    "variantName": "",
    "version": "v1",
    "maxSecurityLevel": 5,
}

# Signature secret key (base64 encoded).
#
# Decodes to a digit-string secret used as-is. The signing algorithm is:
#     sha1(f"{payload_json},{entitlement_token}{secret}")
#
# NOTE: This is the ORIGINAL key from before the reference-alignment pass.
# Both this value and the reference client's current key have been observed
# working against api.vod-prd.s.joyn.de in production traffic. Kept as-is
# because there is no evidence that this value is rejected; if Joyn ever
# rotates the key, both will need updating.
SIGNATURE_SECRET_KEY = "MzU0MzM3MzgzMzM4MzMzNjM1NDMzNzM4MzYzNDM2MzYzNTQzMzczODM2MzYzMzM4MzIzNjM1NDMzNzM4MzMzMDM2MzQzNTM5MzU0MzM3MzgzMzM5MzMzNTMyMzQzNTQzMzczODM2MzUzMzM5MzU0MzM3MzgzMzM4MzMzMjMzNDYzNTQzMzczODM2MzYzMzMzMzM0NDMzNDIzNTQzMzczODMzMzgzNjM2MzMzNQ=="

# ============================================================================
# Content Types & Modes
# ============================================================================

CONTENT_TYPE_LIVE = "LIVE"
CONTENT_TYPE_VOD = "VOD"

STREAM_TYPE_LINEAR = "LINEAR"
STREAM_TYPE_EVENT = "EVENT"
STREAM_TYPE_ON_DEMAND = "ON_DEMAND"

DEFAULT_LIVESTREAM_TYPES = ["EVENT", "LINEAR", "ON_DEMAND"]

MODE_LIVE = "live"
MODE_VOD = "vod"

# ----------------------------------------------------------------------------
# Content-id grammar (parsed in ONE place: ids.py)
#   live:  bare channel slugs            "sat1-de", "sat1-de-hd"
#   VOD:   a_<id>   playable video asset  (what the asset playlist wants)
#          b_<id>   movie, c_<id> season, d_<id> episode
#          block-<n> lazy landing-page block
#          anything containing "/" (browse path) or ":" (v1 block-id form)
# A live id never starts with these prefixes and never contains "/" or ":".
# ----------------------------------------------------------------------------
VOD_ID_PREFIXES = ("a_", "b_", "c_", "d_", "block-")

# ============================================================================
# Error Codes
# ============================================================================

ERROR_CODES = {
    "PLAYBACK_RESTRICTED": "ENT_RVOD_Playback_Restricted",
    "BUSINESS_MODEL_NOT_SUITABLE": "ENT_BUSINESS_MODEL_NOT_SUITABLE",
    "UNAUTHORIZED": "ENT_Unauthorized",
    "NOT_FOUND": "ENT_Not_Found",
    "GEOBLOCKED": "ENT_Geoblocked",
    "VALIDATION_ERROR": "VALIDATION_ERROR",
    "INVALID_JWT": "INVALID_JWT",
}

# ============================================================================
# Country Configuration
# ============================================================================

SUPPORTED_COUNTRIES = ["de", "at", "ch"]
DEFAULT_COUNTRY = "de"

# GraphQL / streaming API tenant values.
# Used by provider.py and channel_manager._get_graphql_headers.
COUNTRY_TENANT_MAPPING = {
    "de": "JOYN",
    "at": "JOYN_AT",
    "ch": "JOYN_CH",
}

JOYN_DOMAINS = {
    "de": "https://www.joyn.de",
    "at": "https://www.joyn.at",
    "ch": "https://www.joyn.ch",
}


def get_oauth_redirect_uri(country: str) -> str:
    """Get country-specific OAuth redirect URI"""
    return f"https://www.joyn.{country}/oauth"


# ============================================================================
# DRM Configuration
# ============================================================================

DRM_SYSTEM_WIDEVINE = "widevine"

DRM_REQUEST_HEADERS = {
    "Content-Type": "application/octet-stream",
    "User-Agent": JOYN_USER_AGENT,
}

DRM_LICENSE_HEADERS_BASE = {
    "Content-Type": "application/octet-stream",
    "User-Agent": JOYN_USER_AGENT,
}

# ============================================================================
# Request Configuration
# ============================================================================

DEFAULT_REQUEST_TIMEOUT = 30
DEFAULT_MAX_RETRIES = 3
DEFAULT_EPG_WINDOW_HOURS = 3

# ============================================================================
# Cache Configuration
# ============================================================================

# Manifest and DRM share one playlist call per zap. Five seconds is long
# enough for the two backend calls (get_manifest and get_drm arrive within
# milliseconds of each other in the DRM pipeline), short enough that a
# channel switch does not see a stale manifest URL.
PLAYOUT_CACHE_TTL = 5.0

# Entitlement tokens are short-lived; the token itself is not cached (the
# entitlement service has its own session concept), but the *resolution*
# of a channel id to its "-hd" variant is cached for the process lifetime
# in JoynEntitlement._resolved_channel_variants.

# ============================================================================
# Channel Configuration
# ============================================================================

DEFAULT_CHANNEL_CONFIG = {
    "video": "best",
    "on_demand": True,
    "speed_up": True,
    "use_cdm": True,
    "cdm_mode": "external",
    "session_manifest": False,
}

DEFAULT_LANGUAGE = "de"