# streaming_providers/providers/zdf/channel_manager.py
"""
ZDF channel manager -- the only manager (live TV, clear HLS, no DRM).

Contract (ChannelManager ABC; README §6.1):
  * get_channels()                -> List[Channel]
  * get_channel_manifest(id)      -> HLS master.m3u8 url; raises on real failures
  * get_channel_manifest_headers  -> CDN headers (HEADERS_FROM_MANAGERS = True)
  * get_segment_headers           -> inherited (= manifest headers)
  * get_channel_drm               -> inherited ([] = no DRM; ZDF streams are clear)

content_id == the video's `canonical` ("zdf-live-beitrag-100"). It resolves to
a ptmd path via a small TTL cache that get_channels() fills; on a miss one
VideoByCanonical request fills it. Failure semantics:
  * canonical unknown / no live media  -> NotFoundError
  * ptmd without an HLS stream, or encrypted -> ServerError (raised as
    ValueError inside transport_errors); the message lists what was offered.
  * API refuses a request (AuthError / EntitlementError, i.e. 401/403) ->
    one refetch of the web-client tokens and exactly one retry, only if the
    tokens really changed; otherwise the original error propagates.
"""

import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from ...base.errors import AuthError, EntitlementError, NotFoundError
from ...base.managers import ChannelManager
from ...base.models import Channel
from ...base.utils.logger import logger
from ...base.utils.transport import transport_errors
from .constants import VIDEO_BY_CANONICAL_QUERY, ZdfDefaults
from .models import (
    ZdfChannel,
    ZdfPlayout,
    extract_video_nodes,
    is_channel_node,
    ptmd_path_from_video,
)

_PROVIDER = ZdfDefaults.PROVIDER_LABEL


class ZdfChannelManager(ChannelManager):
    def __init__(
        self,
        *,
        http_manager: Any,
        auth: Any,
        country: str,
        config: Any,
        ptmd_cache: Optional[Dict[str, Tuple[str, float]]] = None,
    ):
        # Extra collaborators are keyword-only, stored AFTER super().__init__,
        # and super() gets ONLY the four required ones.
        super().__init__(
            http_manager=http_manager, auth=auth, country=country, config=config
        )
        # Provider-owned dict, borrowed by reference: canonical -> (ptmd path, ts).
        self._ptmd_cache = ptmd_cache if ptmd_cache is not None else {}

    # ------------------------------------------------------------------
    # Request helper: one retry after a token rejection
    # ------------------------------------------------------------------
    def _send(self, send: Callable[[], Any]) -> Any:
        """
        Run `send` (which must build its headers inside, so a retry picks up
        the new token). A 401/403 may mean an expired web-client token: refetch
        once and retry once, but only if the tokens actually changed.
        """
        try:
            return send()
        except (AuthError, EntitlementError):
            if not self.auth.refresh_after_rejection():
                raise
            return send()

    # ------------------------------------------------------------------
    # Channels
    # ------------------------------------------------------------------
    def get_channels(self, **kw: Any) -> List[Channel]:
        with transport_errors("get_channels", _PROVIDER):
            resp = self._send(lambda: self.http_manager.get(
                self.config.url(ZdfDefaults.PATH_GRAPHQL),
                params=self.config.list_query_params(),
                headers=self.auth.build_list_headers(),
                operation="api",
            ))
            nodes = extract_video_nodes(resp.json())

        channels: List[ZdfChannel] = []
        seen = set()
        now = time.time()
        for node in nodes:
            if not is_channel_node(node):
                continue    # test items, scheduled shows, event streams: not channels
            try:
                channel = ZdfChannel.from_api_response(node)
            except (KeyError, TypeError, AttributeError, ValueError) as exc:
                logger.warning(f"{_PROVIDER}: skipping malformed channel entry: {exc!r}")
                continue
            if channel.canonical in seen:
                continue
            seen.add(channel.canonical)
            self._ptmd_cache[channel.canonical] = (channel.ptmd_path, now)
            channels.append(channel)
        return [c.to_channel(ZdfDefaults.PROVIDER_NAME) for c in channels]

    def clear_ptmd_cache(self) -> None:
        self._ptmd_cache.clear()

    # ------------------------------------------------------------------
    # canonical -> ptmd path
    # ------------------------------------------------------------------
    def _ptmd_path(self, canonical: str) -> str:
        now = time.time()
        cached = self._ptmd_cache.get(canonical)
        if cached and (now - cached[1]) < ZdfDefaults.PTMD_PATH_CACHE_TTL:
            return cached[0]
        with transport_errors(f"VideoByCanonical {canonical}", _PROVIDER):
            resp = self._send(lambda: self.http_manager.post(
                self.config.url(ZdfDefaults.PATH_GRAPHQL),
                json={
                    "operationName": "VideoByCanonical",
                    "query": VIDEO_BY_CANONICAL_QUERY,
                    "variables": {"canonical": canonical},
                },
                headers=self.auth.build_headers(),
                operation="api",
            ))
            path = ptmd_path_from_video(resp.json())
        if path is None:
            raise NotFoundError(f"{_PROVIDER}: no live stream for {canonical}")
        self._ptmd_cache[canonical] = (path, now)
        return path

    # ------------------------------------------------------------------
    # Manifest / headers
    # ------------------------------------------------------------------
    def get_channel_manifest(self, content_id: str, **kw: Any) -> Optional[str]:
        ptmd_path = self._ptmd_path(content_id)
        with transport_errors(f"ptmd for {content_id}", _PROVIDER):
            resp = self._send(lambda: self.http_manager.get(
                self.config.url(ptmd_path),
                headers=self.auth.build_ptmd_headers(),
                operation="api",
            ))
            playout = ZdfPlayout.from_api_response(resp.json())
        return playout.manifest_url

    def get_channel_manifest_headers(self, content_id: str, **kw: Any) -> Dict[str, str]:
        # CDN headers, NOT the API headers the ABC default would return.
        # Only effective with HEADERS_FROM_MANAGERS = True.
        return self.config.stream_headers()
