# streaming_providers/providers/zdf/models.py
"""
Provider-local data models and pure parsers. No business logic, no network.

Parsing is STRICT on purpose (KeyError on missing required fields); the manager
parses entry-by-entry and skips malformed entries, so one bad channel cannot
take the whole list down.

The channel list of ZDF contains MANY non-channels (test items, event streams,
scheduled shows); `is_channel_node` is the one place that decides what counts
as a channel.
"""

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ...base.models import Channel
from .constants import ZdfDefaults


# ----------------------------------------------------------------------
# GraphQL helpers
# ----------------------------------------------------------------------
def _raise_on_graphql_errors(payload: Any) -> Dict[str, Any]:
    """Return payload["data"] or raise ValueError (-> ServerError via transport_errors)."""
    if not isinstance(payload, dict):
        raise ValueError("GraphQL response is not a JSON object")
    data = payload.get("data")
    errors = payload.get("errors")
    if errors and not data:
        first = errors[0] if isinstance(errors, list) and errors else errors
        message = first.get("message") if isinstance(first, dict) else str(first)
        raise ValueError(f"GraphQL error: {message}")
    if not isinstance(data, dict):
        raise ValueError("GraphQL response has no data")
    return data


def extract_video_nodes(payload: Any) -> List[Dict[str, Any]]:
    """data.videos.nodes of the getActiveLiveStreams response."""
    data = _raise_on_graphql_errors(payload)
    nodes = (data.get("videos") or {}).get("nodes")
    if not isinstance(nodes, list):
        raise ValueError("channel list response is missing data.videos.nodes")
    return nodes


def resolve_ptmd_path(template: str) -> str:
    """'/tmd/2/{playerId}/live/ptmd/247onAir-203' -> '/tmd/2/ngplayer_2_5/live/ptmd/247onAir-203'."""
    path = template.replace(ZdfDefaults.PLAYER_ID_PLACEHOLDER, ZdfDefaults.PLAYER_ID)
    if not path.startswith("/tmd/"):
        raise ValueError(f"unexpected ptmdTemplate: {template!r}")
    return path


def ptmd_path_from_video(payload: Any) -> Optional[str]:
    """
    ptmd path from a VideoByCanonical response.

    None  = the video does not exist or currently has no live media
            (the manager turns that into NotFoundError).
    raise = malformed payload.
    """
    data = _raise_on_graphql_errors(payload)
    video = data.get("videoByCanonical")
    if not video:
        return None
    for media in (video.get("currentMedia") or {}).get("nodes") or []:
        template = media.get("ptmdTemplate")
        if template:
            return resolve_ptmd_path(template)
    return None


# ----------------------------------------------------------------------
# Channels
# ----------------------------------------------------------------------
def is_channel_node(node: Dict[str, Any]) -> bool:
    """
    True for a real 24/7 channel of the getActiveLiveStreams list.

    A channel is: currently LIVE, not hidden from the index (all "Testsammlung"
    / smoke-test items are), on air, and backed by a 24/7 ptmd id. Scheduled
    shows (currentMediaType NOVIDEO) and event streams fail this on purpose.
    """
    if not isinstance(node, dict):
        return False
    if node.get("currentMediaType") != "LIVE" or node.get("excludeFromIndex"):
        return False
    media = (node.get("currentMedia") or {}).get("nodes") or []
    if not media or not isinstance(media[0], dict):
        return False
    first = media[0]
    template = first.get("ptmdTemplate") or ""
    return first.get("state") == "onair" and ZdfDefaults.LIVE247_MARKER in template


@dataclass
class ZdfChannel:
    canonical: str          # content_id: stable editorial id, e.g. "zdfinfo-live-beitrag-100"
    name: str
    ptmd_path: str          # resolved, ready for config.url()
    geo_location: Optional[str] = None

    @classmethod
    def from_api_response(cls, node: Dict[str, Any]) -> "ZdfChannel":
        media = node["currentMedia"]["nodes"][0]
        service = media.get("tvService") or node["teaser"]["title"]
        name = ZdfDefaults.CHANNEL_NAME_OVERRIDES.get(service, service)
        return cls(
            canonical=node["canonical"],
            name=name,
            ptmd_path=resolve_ptmd_path(media["ptmdTemplate"]),
            geo_location=media.get("geoLocation"),
        )

    def to_channel(self, provider_name: str) -> Channel:
        # NOTE the factory parameter names: create_live_channel takes
        # `channel_id`, create_vod_channel takes `content_id`.
        channel = Channel.create_live_channel(
            name=self.name, channel_id=self.canonical, provider=provider_name
        )
        channel.catchup_hours = 0   # set only when catchup is really offered
        return channel


# ----------------------------------------------------------------------
# Playout (PTMD)
# ----------------------------------------------------------------------
def _attr(attributes: Dict[str, Any], name: str) -> Optional[str]:
    entry = attributes.get(name)
    return entry.get("value") if isinstance(entry, dict) else None


def _is_dash(formitaet: Dict[str, Any]) -> bool:
    mime = (formitaet.get("mimeType") or "").lower()
    kind = (formitaet.get("type") or "").lower()
    return ZdfDefaults.DASH_MIME_MARKER in mime or ZdfDefaults.DASH_TYPE_MARKER in kind


def _rank(order: Tuple[str, ...], value: Optional[str]) -> int:
    return order.index(value) if value in order else len(order)


def pick_dash_url(priority_list: Iterable[Dict[str, Any]]) -> Tuple[Optional[str], List[str]]:
    """
    Choose ONE DASH manifest URL. Returns (url or None, offered formats).

    Order of preference: earlier priorityList item, then quality
    (DASH_QUALITY_ORDER, "auto" first), then main-class German audio track,
    then https. HLS and everything else is ignored.
    """
    offered: List[str] = []
    best: Optional[Tuple[Tuple[int, int, int, int], str]] = None
    for p_idx, item in enumerate(priority_list or []):
        for formitaet in item.get("formitaeten") or []:
            offered.append(formitaet.get("mimeType") or formitaet.get("type") or "?")
            if not _is_dash(formitaet):
                continue
            for quality in formitaet.get("qualities") or []:
                q_rank = _rank(ZdfDefaults.DASH_QUALITY_ORDER, quality.get("quality"))
                for track in (quality.get("audio") or {}).get("tracks") or []:
                    uri = track.get("uri")
                    if not uri:
                        continue
                    t_rank = 0 if (
                        track.get("class") == ZdfDefaults.AUDIO_CLASS_PREFERRED
                        and track.get("language") == ZdfDefaults.AUDIO_LANGUAGE_PREFERRED
                    ) else 1
                    key = (p_idx, q_rank, t_rank, 0 if uri.startswith("https://") else 1)
                    if best is None or key < best[0]:
                        best = (key, uri)
    return (best[1] if best else None), offered


@dataclass
class ZdfPlayout:
    """Response of the ptmd endpoint, reduced to what playback needs."""

    manifest_url: str
    ptmd_id: str
    station: Optional[str] = None

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "ZdfPlayout":
        if not isinstance(data, dict):
            raise ValueError("ptmd response is not a JSON object")
        attributes = data.get("attributes") or {}
        encryption = _attr(attributes, "encryption")
        if encryption not in (None, "none"):
            raise ValueError(f"encrypted stream ({encryption}) is not supported")
        url, offered = pick_dash_url(data.get("priorityList") or [])
        if not url:
            raise ValueError(
                f"ptmd response offers no DASH stream (offered: {sorted(set(offered))})"
            )
        return cls(
            manifest_url=url,
            ptmd_id=data.get("id") or "",
            station=_attr(attributes, "station"),
        )
