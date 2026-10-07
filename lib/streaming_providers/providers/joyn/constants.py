# streaming_providers/providers/joyn/constants.py
# -*- coding: utf-8 -*-
"""
Joyn provider constants - Cleaned and organized
"""

import os

# ============================================================================
# Provider Metadata
# ============================================================================

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

# Bumped to match the working reference client (Chrome 154).
JOYN_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36"
# Bumped to match the working reference client.
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

# GraphQL persisted query hashes
GRAPHQL_QUERY_HASHES = {
    "LIVE_PLAYER": "52b37a3cf5bc75e56026aed7b0d234874eeabd2eccd369d0cd3d3a6ea15ef566",
    "LIVE_CHANNELS": "b7703103ddd0516be6b49ed66186092a6c6f6d815ccc502a9f50800a8cc18dd2",
}

# GraphQL endpoints with full URLs
JOYN_GRAPHQL_ENDPOINTS = {
    "LIVE_PLAYER": f'{JOYN_GRAPHQL_BASE_URL}?operationName=PageLivePlayerClientSide&enable_user_location=true&watch_assistant_variant=true&extensions=%7B%22persistedQuery%22%3A%7B%22version%22%3A1%2C%22sha256Hash%22%3A%22{GRAPHQL_QUERY_HASHES["LIVE_PLAYER"]}%22%7D%7D',
    "LIVE_CHANNELS": f"{JOYN_GRAPHQL_BASE_URL}?operationName=LiveChannelsAndEpg&enable_user_location=true&watch_assistant_variant=true",
}

# Base GraphQL headers
JOYN_GRAPHQL_BASE_HEADERS = {
    "X-Api-Key": "4f0fd9f18abbe3cf0e87fdb556bc39c8",
    "Accept": "application/json",
    "Content-Type": "application/json",
    "User-Agent": JOYN_USER_AGENT,
}

# GraphQL query defaults
GRAPHQL_PERSISTED_QUERY_VERSION = 1
GRAPHQL_LIVE_CHANNELS_FILTER = "DEFAULT"
GRAPHQL_MAX_RESULTS = 5000
GRAPHQL_OFFSET = 0

# ============================================================================
# Streaming Configuration
# ============================================================================

# Entitlement host is overridable so a future Joyn migration (they already
# moved once, from entitlement.p7s1.io) does not require a code change.
# Set JOYN_ENTITLEMENT_URL in the environment to override.
_DEFAULT_ENTITLEMENT_URL = (
    "https://entitlements-service-alb.prd.platform.s.joyn.de/api/user/entitlement-token"
)
_ENTITLEMENT_URL = os.environ.get("JOYN_ENTITLEMENT_URL", _DEFAULT_ENTITLEMENT_URL).strip() \
    or _DEFAULT_ENTITLEMENT_URL

JOYN_STREAMING_ENDPOINTS = {
    "ENTITLEMENT": _ENTITLEMENT_URL,
    "PLAYLIST": "https://api.vod-prd.s.joyn.de/v1/channel/{channel_id}/playlist",
}

# Default video configuration for playlist requests.
#
# IMPORTANT: the playlist request is signed over the *exact* JSON string built
# from this dict (see create_video_payload). If you change any key or value
# here, the signature sent to api.vod-prd.s.joyn.de will change with it. If
# the server validates the signature against its own expected payload shape,
# a mismatch here produces 403 on every live and VOD playback request.
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
# matching the working reference client exactly.
#
# This constant is intentionally NOT configurable: it must byte-match the
# value embedded in Joyn's own web client. If Joyn rotates it, the fix is a
# new constant shipped in an update, not a user setting.
SIGNATURE_SECRET_KEY = "MzU0MzM3MzgzMzM4MzMzNjM1NDMzNzM4MzYzNDM2MzYzNTQzMzk3MzgzNjM2MzMzODMyMzYzNTQzMzc3MzgzMzMwMzYzNDM1MzkzNTQzMzc3MzgzMzM5MzMzNTMyMzQzNTQzMzc3MzgzNjM1MzMzOTM1NDMzNzM4MzMzODMzMjMzNDYzNTQzMzc4MzYzNjMzMzMzMzQ0MzM0NDMyNzA2NTQzMzczODMzMzgzNjM2MzMzMw=="

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

# Auth (7pass / auth.joyn.de) tenant values.
#
# NOTE: Joyn sends a *different* tenant on auth calls than on GraphQL calls —
# Germany is "JOYN_DE" on auth, but plain "JOYN" on GraphQL. These must stay
# separate; using the GraphQL map on auth calls silently downgrades the
# session to anonymous.
#
# NOT YET WIRED UP: auth.py still reads COUNTRY_TENANT_MAPPING. The switch is
# part of the auth rework batch. Kept here so the two maps stay visible
# together.
AUTH_TENANT_MAPPING = {
    "de": "JOYN_DE",
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