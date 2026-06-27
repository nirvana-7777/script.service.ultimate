# streaming_providers/providers/lib_theplatform.py
"""
Shared theplatform playback utilities.

Both magenta2 (DE) and magentaeu (AT/PL/HR/HU/ME) ultimately deliver the
same three playback artefacts for every live channel:

    mpd_url       – the MPEG-DASH manifest URL
    release_pid   – the Widevine releasePid for licence acquisition
    station_id    – the theplatform Station URI (used as the channel key)

They obtain those artefacts differently:

    magenta2   → getApplicableDistributionRights  → entitled-channels feed
    magentaeu  → bifrost /epg/channel

This module contains the logic that is identical once the artefacts are in
hand:

    TheplatformChannel          – canonical dataclass for one channel's data
    parse_entitled_channels_feed()  – parses the magenta2 JSON feed
    parse_bifrost_epg_channel()     – parses one magentaeu bifrost entry
    build_catchup_url()         – appends begin/end to any manifest URL
    build_widevine_drm_config() – builds a DRMConfig from a licence URL
    build_licence_url()         – assembles the theplatform WV licence URL
    extract_persona_jwt()       – decodes Base64 persona token → raw JWT

Usage (magenta2):
    channels = parse_entitled_channels_feed(feed_json)
    drm      = build_widevine_drm_config(
                   build_licence_url(widevine_endpoint, ch.release_pid,
                                     extract_persona_jwt(persona_token),
                                     account_uri),
                   user_agent)

Usage (magentaeu):
    ch  = parse_bifrost_epg_channel(entry)
    drm = build_widevine_drm_config(
              build_licence_url(WV_URL, ch.release_pid,
                                persona_token_from_jwt_claim,
                                account_uri),
              USER_AGENT)
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import quote

from ..base.models import DRMConfig, DRMSystem, LicenseConfig
from ..base.utils.logger import logger
from ..base.utils.timestamp_converter import TimestampConverter

class PaginationError(Exception):
    """
    Raised when a page fetch fails outright. Carries whatever entries were
    successfully collected before the failure, so callers can choose to use
    partial data — but they have to choose explicitly, rather than a failed
    fetch silently masquerading as "end of data".
    """

    def __init__(self, message: str, partial_entries: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message)
        self.partial_entries = partial_entries or []


def paginate_feed(
    fetch_page: Callable[[int, int], Optional[Dict[str, Any]]],
    items_per_page: int = 100,
    max_pages: int = 20,
    start_index: int = 1,
    feed_name: str = "feed",
) -> List[Dict[str, Any]]:
    """
    Args:
        fetch_page: callable(start_index, items_per_page) -> response dict
            with an "entries" key, or None on failure. This callable owns
            headers, retries, the `operation` tag, and raise_for_status —
            pagination here is HTTP-agnostic by design.
        items_per_page: page size requested via `range=`.
        max_pages: safety cap. Hitting it is logged at ERROR (not silently
            swallowed) since it usually means termination isn't firing or
            the feed grew beyond expectations.
        feed_name: for logging only.

    Returns:
        Combined entries across all pages.

    Raises:
        PaginationError if a page fetch fails. exc.partial_entries holds
        whatever was collected before the failure.
    """
    all_entries: List[Dict[str, Any]] = []
    index = start_index
    page = 0

    while page < max_pages:
        page += 1
        response = fetch_page(index, items_per_page)

        if response is None:
            raise PaginationError(
                f"{feed_name}: page {page} (range={index}-{index + items_per_page - 1}) "
                f"fetch failed",
                partial_entries=all_entries,
            )

        entries = response.get("entries", [])
        all_entries.extend(entries)

        logger.debug(
            f"{feed_name}: page {page} range={index}-{index + items_per_page - 1} -> "
            f"{len(entries)} entries (entryCount={response.get('entryCount')!r})"
        )

        # Termination based on what THIS page actually returned, never on
        # entryCount — its meaning varies by feed and isn't worth trusting.
        if len(entries) < items_per_page:
            break

        index += items_per_page
    else:
        logger.error(
            f"{feed_name}: hit max_pages={max_pages} safety cap with "
            f"{len(all_entries)} entries collected — feed may be larger than "
            f"expected, or termination isn't triggering. Returning partial data."
        )

    logger.info(f"{feed_name}: {len(all_entries)} entries across {page} page(s)")
    return all_entries

# ---------------------------------------------------------------------------
# Canonical channel dataclass
# ---------------------------------------------------------------------------

@dataclass
class TheplatformChannel:
    """
    Normalised live-channel record produced by both provider families.

    Attributes:
        station_id:  theplatform Station URI
                     e.g. "http://data.entertainment.tv.theplatform.eu/…/Station/12345"
                     Used as the channel's stable content_id.
        mpd_url:     Pre-resolved MPEG-DASH manifest URL.
        release_pid: Widevine releasePid for licence acquisition.
        hls_url:     HLS manifest URL (optional – present when available).
        channel_number: Logical channel number (optional).
    """

    station_id: str
    mpd_url: str
    release_pid: str
    hls_url: Optional[str] = None
    channel_number: Optional[int] = None
    extra: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Feed parsers
# ---------------------------------------------------------------------------

def parse_entitled_channels_feed(feed: dict) -> List[TheplatformChannel]:
    """
    Parse the magenta2 entitled-channels feed response.

    Expected shape (one entry):
        {
          "media": [{"content": [
              {"format": "MPEG-DASH",
               "releases": [{"pid": "uEkSomCvvBMX"}],
               "streamingUrl": "https://…/DASH/index.mpd"},
              {"format": "M3U",
               "releases": [{"pid": "bMchet033yZ0"}],
               "streamingUrl": "https://…/HLS_CMAF/index.m3u8"}
          ]}],
          "listings": [{"stationId": "http://…/Station/265808936224"}],
          "dt$channelNumber": 880
        }
    """
    channels: List[TheplatformChannel] = []

    for entry in feed.get("entries", []):
        try:
            # Station ID
            listings = entry.get("listings", [])
            if not listings:
                continue
            station_id = listings[0].get("stationId", "")
            if not station_id:
                continue

            # Content items
            content_items = (entry.get("media") or [{}])[0].get("content", [])

            mpd_url = ""
            release_pid = ""
            hls_url = None

            for item in content_items:
                fmt = item.get("format", "")
                url = item.get("streamingUrl", "")
                pid = (item.get("releases") or [{}])[0].get("pid", "")

                if fmt == "MPEG-DASH" and url:
                    mpd_url = url
                    release_pid = pid
                elif fmt == "M3U" and url:
                    hls_url = url

            if not mpd_url:
                logger.debug(f"lib_theplatform: no DASH URL for station {station_id}, skipping")
                continue

            channels.append(TheplatformChannel(
                station_id=station_id,
                mpd_url=mpd_url,
                release_pid=release_pid,
                hls_url=hls_url,
                channel_number=entry.get("dt$channelNumber"),
                extra={"distributionRightIds": entry.get("distributionRightIds", [])},
            ))

        except Exception as exc:
            logger.warning(f"lib_theplatform: error parsing feed entry: {exc}")

    logger.debug(f"lib_theplatform: parsed {len(channels)} channels from entitled-channels feed")
    return channels


def parse_bifrost_epg_channel(entry: dict) -> Optional[TheplatformChannel]:
    """
    Parse a single channel entry from the magentaeu bifrost /epg/channel response.

    Expected shape:
        {
          "station_id":    "http://…/Station/12345",   (or "stationId")
          "video_src_dash": "https://…/DASH/index.mpd",
          "pid_dash":       "uEkSomCvvBMX",
          "channel_number": 28
        }

    Both snake_case (bifrost) and camelCase (older variants) field names are
    handled so this function is robust to minor API variations.
    """
    try:
        station_id = (
            entry.get("station_id")
            or entry.get("stationId")
            or ""
        )
        mpd_url = (
            entry.get("video_src_dash")
            or entry.get("videoDashUrl")
            or ""
        )
        release_pid = (
            entry.get("pid_dash")
            or entry.get("pidDash")
            or ""
        )
        hls_url = entry.get("video_src_hls") or entry.get("videoHlsUrl")
        channel_number = entry.get("channel_number") or entry.get("channelNumber")

        if not mpd_url:
            return None

        return TheplatformChannel(
            station_id=station_id,
            mpd_url=mpd_url,
            release_pid=release_pid,
            hls_url=hls_url,
            channel_number=channel_number,
        )

    except Exception as exc:
        logger.warning(f"lib_theplatform: error parsing bifrost entry: {exc}")
        return None


# ---------------------------------------------------------------------------
# Distribution-rights helper (magenta2)
# ---------------------------------------------------------------------------

def fetch_distribution_rights(
    http_manager,
    rights_url: str,
    cid: str,
    user_agent: str,
    timeout: int = 30,
    extra_headers: Optional[dict] = None,
) -> List[str]:
    """
    Call getApplicableDistributionRights and return the list of right URLs.

    Args:
        http_manager:  HTTPManager instance.
        rights_url:    manifest.mpx.license_service_url
                       (basicUrlGetApplicableDistributionRights)
        cid:           Correlation ID string  "session_id::call_id"
        user_agent:    Platform user-agent string.
        timeout:       HTTP timeout in seconds.
        extra_headers: Optional additional headers merged on top of the
                       default set (e.g. Authorization, Origin, Referer).
                       Caller-supplied keys take precedence.

    Returns:
        List of DistributionRight URL strings, empty on failure.
    """
    try:
        headers = {"User-Agent": user_agent, "Accept": "application/json"}
        if extra_headers:
            headers.update(extra_headers)
        response = http_manager.get(
            rights_url,
            operation="get_distribution_rights",
            headers=headers,
            params={"form": "json", "schema": "1.2", "cid": cid},
            timeout=timeout,
        )
        if response.status_code != 200:
            logger.error(
                f"lib_theplatform: distribution rights request failed [{response.status_code}]"
            )
            return []

        data = response.json()
        rights = data.get("getApplicableDistributionRightsResponse", [])
        logger.debug(f"lib_theplatform: obtained {len(rights)} distribution rights")
        return rights

    except Exception as exc:
        logger.error(f"lib_theplatform: error fetching distribution rights: {exc}")
        return []


def fetch_entitled_channels_feed(
    http_manager,
    feed_url: str,
    distribution_rights: List[str],
    cid: str,
    user_agent: str,
    timeout: int = 30,
) -> List[TheplatformChannel]:
    if not distribution_rights:
        logger.warning("lib_theplatform: no distribution rights — cannot fetch entitled channels")
        return []

    rights_param = "|".join(distribution_rights)
    headers = {"User-Agent": user_agent, "Accept": "application/json"}

    def fetch_page(start_index: int, page_size: int) -> Optional[Dict[str, Any]]:
        params = {
            "byDistributionRightId": rights_param,
            "range": f"{start_index}-{start_index + page_size - 1}",
            "cid": cid,
        }
        try:
            response = http_manager.get(
                feed_url,
                operation="entitled_channels_feed",
                headers=headers,
                params=params,
                timeout=timeout,
            )
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            logger.warning(f"lib_theplatform: entitled channels page fetch failed: {exc}")
            return None

    try:
        entries = paginate_feed(
            fetch_page, items_per_page=100, max_pages=20, feed_name="entitled_channels"
        )
    except PaginationError as exc:
        if not exc.partial_entries:
            logger.error(f"lib_theplatform: {exc} — no entitled channels fetched")
            raise
        logger.error(
            f"lib_theplatform: {exc} — channel lineup INCOMPLETE, "
            f"using {len(exc.partial_entries)} raw entries fetched before failure"
        )
        entries = exc.partial_entries

    channels = parse_entitled_channels_feed({"entries": entries})
    logger.info(f"lib_theplatform: fetched {len(channels)} entitled channels total")
    return channels


# ---------------------------------------------------------------------------
# DRM helpers
# ---------------------------------------------------------------------------

def extract_persona_jwt(persona_token: str) -> Optional[str]:
    """
    Extract the raw JWT from a Base64-encoded persona token.

    Persona token format:  Base64( account_uri + ":" + jwt )

    This is the magenta2 format returned by the theplatform persona endpoint.
    The magentaeu provider reads the JWT directly from the dc_cts_personaToken
    JWT claim and therefore does not need this function.

    Returns:
        Raw JWT string starting with "eyJ", or None on failure.
    """
    try:
        decoded = base64.b64decode(persona_token).decode("utf-8")
        idx = decoded.rfind(":")
        if idx == -1:
            logger.error("lib_theplatform: no colon in decoded persona token")
            return None
        jwt = decoded[idx + 1:]
        if not jwt.startswith("eyJ"):
            logger.error("lib_theplatform: extracted token does not look like a JWT")
            return None
        return jwt
    except Exception as exc:
        logger.error(f"lib_theplatform: error extracting persona JWT: {exc}")
        return None


def build_licence_url(
    widevine_endpoint: str,
    release_pid: str,
    persona_jwt: str,
    account_uri: str,
) -> str:
    """
    Assemble the theplatform Widevine licence acquisition URL.

    Args:
        widevine_endpoint: Base WV endpoint URL, e.g.
            "https://widevine.entitlement.theplatform.eu/wv/web/ModularDrm/getRawWidevineLicense"
        release_pid:       releasePid extracted from the SMIL or channel feed.
        persona_jwt:       Raw JWT (not Base64-wrapped) for the authenticated user.
        account_uri:       MPX account URI, e.g.
            "http://access.auth.theplatform.com/data/Account/2709353023"

    Returns:
        Complete licence URL string.
    """
    sep = "&" if "?" in widevine_endpoint else "?"
    return (
        f"{widevine_endpoint}{sep}"
        f"schema=1.0&"
        f"releasePid={release_pid}&"
        f"token={persona_jwt}&"
        f"account={quote(account_uri, safe='')}"
    )


def build_widevine_drm_config(
    licence_url: str,
    user_agent: str,
    origin: Optional[str] = None,
) -> DRMConfig:
    """
    Build a Widevine DRMConfig for theplatform licence acquisition.

    Args:
        licence_url:  Complete licence URL (from build_licence_url).
        user_agent:   Platform user-agent string for the licence request.
        origin:       Optional Origin header value (used by magentaeu to set
                      the country base URL; omit for magenta2).

    Returns:
        DRMConfig ready for use by the base streaming provider.
    """
    headers: dict = {
        "User-Agent": user_agent,
        "Content-Type": "application/octet-stream",
    }
    if origin:
        headers["Origin"] = origin
        headers["Referer"] = f"{origin}/"

    return DRMConfig(
        system=DRMSystem.WIDEVINE,
        priority=2,
        license=LicenseConfig(
            req_data="{CHA-RAW}",
            server_url=licence_url,
            server_certificate=None,
            req_headers=headers,
            use_http_get_request=False,
        ),
    )


# ---------------------------------------------------------------------------
# Catchup helper
# ---------------------------------------------------------------------------

def build_catchup_url(base_manifest: str, start_time: int, end_time: int) -> str:
    """
    Append begin/end query parameters to a live manifest URL for catchup.

    Args:
        base_manifest: Live DASH manifest URL (with or without existing params).
        start_time:    Catchup start as Unix epoch seconds.
        end_time:      Catchup end as Unix epoch seconds.

    Returns:
        Manifest URL extended with ?begin=YYYYMMDDTHHMMSSZ&end=YYYYMMDDTHHMMSSZ
    """
    start_iso = TimestampConverter.epoch_to_iso(start_time, format_type="basic", as_utc=True)
    end_iso = TimestampConverter.epoch_to_iso(end_time, format_type="basic", as_utc=True)
    sep = "&" if "?" in base_manifest else "?"
    return f"{base_manifest}{sep}begin={start_iso}&end={end_iso}"