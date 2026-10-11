# streaming_providers/providers/joyn/channel_manager.py
# -*- coding: utf-8 -*-
"""
Joyn Channel Manager.

Four required collaborators (`http_manager`, `auth`, `country`, `config`) plus
two declared extras:
  * `entitlement`   — the shared JoynEntitlement helper (README §5.1)
  * `playout_cache` — provider-owned dict, borrowed by reference; makes
                      get_channel_manifest and get_channel_drm share ONE
                      playlist call per zap

Headers come from `self.config`; the bearer comes from
`self.auth.get_access_token()`. Never through the provider.

Routing: handles_content_id() is the cheap pure pre-filter (README §7). It is the
mirror image of JoynVodManager.handles_content_id — both call ids.is_vod_id() —
so a VOD id is never handed to this manager first.
"""

import json
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from ...base.errors import BadRequestError
from ...base.managers import ChannelManager
from ...base.models import DRMConfig
from ...base.utils.logger import logger
from ...base.utils.transport import transport_errors
from .constants import (
    CONTENT_TYPE_LIVE,
    CONTENT_TYPE_VOD,
    DEFAULT_EPG_WINDOW_HOURS,
    DEFAULT_LIVESTREAM_TYPES,
    DEFAULT_REQUEST_TIMEOUT,
    GRAPHQL_LIVE_CHANNELS_FILTER,
    GRAPHQL_MAX_RESULTS,
    GRAPHQL_OFFSET,
    GRAPHQL_PERSISTED_QUERY_VERSION,
    GRAPHQL_QUERY_HASHES,
    JOYN_GRAPHQL_ENDPOINTS,
    JOYN_STREAMING_ENDPOINTS,
    MODE_LIVE,
    MODE_VOD,
    PLAYOUT_CACHE_TTL,
    PROVIDER_NAME,
)
from .drm import build_widevine_config
from .ids import is_live_id, is_vod_id
from .models import JoynChannel, JoynPlayout
from .signing import (  # noqa: F401  (re-exported: external callers imported these from here)
    build_signature,
    create_video_payload,
    video_config_fingerprint,
)


class JoynChannelManager(ChannelManager):
    def __init__(
        self,
        *,
        http_manager: Any,
        auth: Any,
        country: str,
        config: Any,
        entitlement: Any,
        playout_cache: Optional[Dict[str, Tuple[JoynPlayout, float]]] = None,
    ):
        super().__init__(
            http_manager=http_manager, auth=auth, country=country, config=config
        )
        # extras AFTER super(), never passed to it
        self._entitlement = entitlement
        self._playout_cache = playout_cache if playout_cache is not None else {}
        logger.info(f"[JoynChannelManager] Initialised for country={self.country}")

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def handles_content_id(self, content_id: str) -> bool:
        """Live ids are bare channel slugs. Pure, no I/O (README §7)."""
        return is_live_id(content_id)

    # ------------------------------------------------------------------
    # Headers
    # ------------------------------------------------------------------

    def _graphql_headers(self) -> Dict[str, str]:
        # get_access_token() RAISES a typed error if no session can be had
        # (README §8). An anonymous token is a normal, valid result when no
        # credentials are stored; a permanent failure (MFA, rejected credentials)
        # must surface here, not silently degrade to an anonymous channel list
        # that then fails at playback.
        token = self.auth.get_access_token()
        return self.config.graphql_headers(token=token, authenticated=True)

    def get_channel_manifest_headers(self, content_id: str, **kw: Any) -> Dict[str, str]:
        # CDN headers: no Authorization. The manifest URL carries its own
        # signature; the bearer yields "400 InvalidArgument: Unsupported
        # Authorization Type". get_segment_headers is NOT overridden: the ABC
        # default returns these, which is what the CDN segments need.
        return self.config.cdn_headers()

    # ------------------------------------------------------------------
    # Playout (shared by manifest and DRM)
    # ------------------------------------------------------------------

    def clear_playout_cache(self) -> None:
        self._playout_cache.clear()

    def _playout(self, content_id: str, video_config: Optional[Dict] = None) -> JoynPlayout:
        if is_vod_id(content_id):
            # handles_content_id() should have kept this out; reaching it means a
            # caller bypassed the router. A malformed *request*, not a server fault.
            raise BadRequestError(
                f"Joyn: {content_id!r} is a VOD id, not a live channel id"
            )

        now = time.time()
        key = f"{content_id}:{video_config_fingerprint(video_config)}"
        cached = self._playout_cache.get(key)
        if cached and (now - cached[1]) < PLAYOUT_CACHE_TTL:
            return cached[0]

        with transport_errors(f"playout for {content_id}", "Joyn"):
            resolved_id, entitlement_token = self._entitlement.get_channel_entitlement_token(
                content_id
            )
            video_payload = create_video_payload(video_config)
            signature = build_signature(entitlement_token, video_payload)
            url = JOYN_STREAMING_ENDPOINTS["PLAYLIST"].format(channel_id=resolved_id)
            url += f"?signature={signature}"
            response = self.http_manager.post(
                url,
                operation="manifest",
                headers=self.config.api_headers(entitlement_token),
                data=video_payload,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()   # no-op when the HTTP manager already raised
            playout = JoynPlayout.from_playlist_response(
                response.json(), entitlement_token
            )

        # Evict expired entries on insert: the dict is keyed by id x video-config
        # and would otherwise only ever grow.
        for stale in [k for k, (_, ts) in self._playout_cache.items()
                      if (now - ts) >= PLAYOUT_CACHE_TTL]:
            self._playout_cache.pop(stale, None)
        self._playout_cache[key] = (playout, now)
        return playout

    # ------------------------------------------------------------------
    # Manifest / DRM
    # ------------------------------------------------------------------

    def get_channel_manifest(self, content_id: str, **kw: Any) -> Optional[str]:
        return self._playout(content_id, kw.get("video_config")).manifest_url

    def get_channel_drm(self, content_id: str, **kw: Any) -> List[DRMConfig]:
        playout = self._playout(content_id, kw.get("video_config"))
        if not playout.license_url:
            return []
        return [build_widevine_config(self.config, playout.license_url, playout.certificate_url)]

    # ------------------------------------------------------------------
    # Channels
    # ------------------------------------------------------------------

    def get_channels(
        self,
        time_window_hours: int = DEFAULT_EPG_WINDOW_HOURS,
        **kw: Any,
    ) -> List:
        """
        Fetch and parse the GraphQL channel list.

        Malformed entries are skipped with a warning — one bad upstream item must
        not empty the whole list (README §12.5).
        """
        with transport_errors("get_channels", "Joyn"):
            headers = self._graphql_headers()
            current_time = int(time.time())
            end_time = current_time + (time_window_hours * 3600)
            variables = {
                "liveStreamGroupFilter": GRAPHQL_LIVE_CHANNELS_FILTER,
                "first": GRAPHQL_MAX_RESULTS,
                "offset": GRAPHQL_OFFSET,
                "livestreamTypes": DEFAULT_LIVESTREAM_TYPES,
                "from": current_time,
                "to": end_time,
            }
            variables_encoded = urllib.parse.quote(json.dumps(variables))
            extensions_encoded = urllib.parse.quote(json.dumps({
                "persistedQuery": {
                    "version": GRAPHQL_PERSISTED_QUERY_VERSION,
                    "sha256Hash": GRAPHQL_QUERY_HASHES["LIVE_CHANNELS"],
                }
            }))
            url = (
                f"{JOYN_GRAPHQL_ENDPOINTS['LIVE_CHANNELS']}"
                f"&variables={variables_encoded}&extensions={extensions_encoded}"
            )
            response = self.http_manager.get(
                url, operation="api", headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()   # no-op when the HTTP manager already raised
            data = response.json()

        channels = []
        for stream_data in (data.get("data") or {}).get("liveStreams") or []:
            try:
                channel = self._parse_channel_entry(stream_data)
            except (KeyError, TypeError, AttributeError, ValueError) as exc:
                logger.warning(f"Joyn: skipping malformed channel entry: {exc!r}")
                continue
            channels.append(channel.to_streaming_channel(provider_name=PROVIDER_NAME))
        logger.info(f"Joyn: fetched {len(channels)} channels for country {self.country}")
        return channels

    def _parse_channel_entry(self, stream_data: Dict) -> JoynChannel:
        channel_id = stream_data["id"]
        title = stream_data.get("title", "Unknown Channel")
        stream_type = stream_data.get("type", "LINEAR")
        quality = stream_data.get("quality", "")
        logo_url = (stream_data.get("logo") or {}).get("url")

        content_type = CONTENT_TYPE_LIVE if stream_type == "LINEAR" else CONTENT_TYPE_VOD
        mode = MODE_LIVE if stream_type == "LINEAR" else MODE_VOD

        channel = JoynChannel(
            name=f"{title} ({quality})" if quality else title,
            channel_id=channel_id,
            logo_url=logo_url,
            mode=mode,
            content_type=content_type,
            country=self.country,
            raw_data=stream_data,
        )
        if "brand" in stream_data and "brand_id" in stream_data["brand"]:
            channel.raw_data["brand_id"] = stream_data["brand"]["brand_id"]
        if stream_data.get("eventStream"):
            channel.raw_data["is_event_stream"] = True
        return channel