# streaming_providers/providers/livgolf/constants.py
# -*- coding: utf-8 -*-
# ============================================================================
# LIV Golf Configuration
# ============================================================================

from typing import Dict, List

# ============================================================================
# Provider Identity
# ============================================================================

PROVIDER_NAME = "livgolf"
PROVIDER_LABEL = "LIV Golf"
PROVIDER_LOGO = "https://fr.wikipedia.org/wiki/Fichier:LIVGOLF_logo_v2.png"

# ============================================================================
# Application / Device Configuration
# ============================================================================

SITE = "liv-golf"
PLATFORM = "web_browser"
DEVICE_TYPE = "web_browser"
CONTENT_CONSUMPTION = "web"

BROWSER = "Chrome"
BROWSER_VERSION = "147"
OS = "Linux"

USER_AGENT = (
    f"Mozilla/5.0 (X11; {OS} x86_64) AppleWebKit/537.36 "
    f"(KHTML, like Gecko) {BROWSER}/{BROWSER_VERSION}.0.0.0 Safari/537.36"
)

ORIGIN = "https://www.livgolf.com"
REFERER = "https://www.livgolf.com/"

# Static API key — present in all browser requests as x-api-key header
API_KEY = "79613f5e-52ac-45e7-a8a0-99ea2beb3540"

# ============================================================================
# API Endpoints
# ============================================================================

API_BASE_URL = "https://liv-golf.api.viewlift.com"

API_ENDPOINTS = {
    # Anonymous token — no credentials required
    "ANONYMOUS_TOKEN": (
        API_BASE_URL
        + "/identity/anonymous-token"
        + "?site={site}&platform={platform}&deviceId={device_id}"
    ),
    # Regional CDN clusters — used to pick the closest edge node
    "REGIONS": API_BASE_URL + "/v3/content/champions/mobii/regions",
    # Team-camera streams for a given champion (tournament) ID
    "TEAM_STREAMS": API_BASE_URL + "/v3/content/champions/{champion_id}/team/streams",
    # Group-camera streams for a given champion (tournament) ID
    "GROUP_STREAMS": API_BASE_URL + "/v3/content/champions/{champion_id}/group/streams",
    # Entitlement / stream URL check for a single video id
    "ENTITLEMENT": (
        API_BASE_URL
        + "/v3/entitlement/video/status"
        + "?id={video_id}&deviceType={device_type}&contentConsumption={content_consumption}&ssaiDisable=false"
    ),
}

# Champion ID used when no override is given.
# 59 is the current live tournament champion seen in the captured traffic.
DEFAULT_CHAMPION_ID = "59"

# ============================================================================
# Streaming Configuration
# ============================================================================

STREAMING_FORMAT_DASH = "dash"
CONTENT_TYPE_LIVE = "LIVE"

# ============================================================================
# Regional CDN — preference order for closest-edge selection.
#
# The /mobii/regions endpoint returns a list of regions. We rank them by the
# abbreviation prefix so that, e.g., a European client prefers
# gcp-edge-eu-w > gcp-edge-uk-s > gcp-edge-us-* etc.
# The list below is ordered from "most preferred for EU" to "last resort".
# ============================================================================

REGION_PREFERENCE_ORDER: List[str] = [
    "gcp-edge-eu-w",   # GCP Europe West (Zurich)      — closest for most EU users
    "gcp-edge-uk-s",   # GCP Europe West (London)
    "gcp-edge-me-c",   # GCP Middle East (Doha)
    "gcp-edge-za-n",   # GCP South Africa (Johannesburg)
    "gcp-edge-a-m",    # GCP Asia South (Mumbai)
    "gcp-edge-au-s",   # GCP Australia South East
    "gcp-edge-sa-e",   # GCP South America East
    "gcp-edge-us-e",   # GCP East US
    "gcp-edge-us-c",   # GCP Central US                — default fallback seen in captures
]

# Fallback CDN base URL when region discovery fails entirely
FALLBACK_CDN_BASE = "https://gcp-edge-eu-w.mobii.com"

# ============================================================================
# Request Configuration
# ============================================================================

DEFAULT_REQUEST_TIMEOUT = 30
DEFAULT_MAX_RETRIES = 3

# Token TTL margin — refresh the anonymous token this many seconds before it expires
TOKEN_EXPIRY_MARGIN_SECONDS = 300

# ============================================================================
# Headers helpers
# ============================================================================


def get_base_headers() -> Dict[str, str]:
    """Minimal headers required for all LIV Golf API calls."""
    return {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/plain, */*",
        "Origin": ORIGIN,
        "Referer": REFERER,
    }


def get_authenticated_headers(authorization: str) -> Dict[str, str]:
    """Headers that include the anonymous JWT token and the static API key."""
    headers = get_base_headers()
    headers.update(
        {
            "Authorization": authorization,
            "x-api-key": API_KEY,
        }
    )
    return headers