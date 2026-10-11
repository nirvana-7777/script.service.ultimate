# streaming_providers/providers/example/channel_manager.py
"""
Example channel manager -- the one manager every live provider needs.

Contract (ChannelManager ABC; see README §Managers):
  * get_channels()                -> List[Channel]      [abstract]
  * get_channel_manifest(id)      -> Optional[str]      [abstract]
        None  = "not mine" (the router tries the next manager)
        raise = a real failure (typed error from base.errors)
  * get_channel_manifest_headers  -> headers for the MPD fetch   [override]
  * get_segment_headers           -> default = manifest headers
  * get_channel_drm               -> [] = no DRM                 [override]
  * handles_content_id            -> default True; override when ids of
                                     several managers coexist (cheap, pure,
                                     NO I/O)

Here manifest and DRM share ONE playout response, so DRM is folded into this
manager (provider: DRM_IN_MANAGERS = True) and a 5 s cache lets the two
separate backend calls (get_manifest, get_drm) share one request.
"""

import time
from typing import Any, Dict, List, Optional, Tuple

from ...base.managers import ChannelManager
from ...base.models import Channel, DRMConfig
from ...base.utils.logger import logger
from ...base.utils.transport import transport_errors
from .constants import ExampleDefaults
from .drm import create_widevine_config
from .models import ExampleChannel, ExamplePlayout

_PROVIDER = ExampleDefaults.PROVIDER_LABEL


class ExampleChannelManager(ChannelManager):
    def __init__(
        self,
        *,
        http_manager: Any,
        auth: Any,
        country: str,
        config: Any,
        playout_cache: Optional[Dict[str, Tuple[ExamplePlayout, float]]] = None,
    ):
        # Extra collaborators are keyword-only, stored AFTER super().__init__,
        # and super() gets ONLY the four required ones (no **kwargs anywhere:
        # a typo at a call site must be an immediate TypeError).
        super().__init__(
            http_manager=http_manager, auth=auth, country=country, config=config
        )
        # Provider-owned dict, borrowed by reference. The provider clears it
        # when credentials change.
        self._playout_cache = playout_cache if playout_cache is not None else {}

    # ------------------------------------------------------------------
    # Channels
    # ------------------------------------------------------------------
    def get_channels(self, **kw: Any) -> List[Channel]:
        with transport_errors("get_channels", _PROVIDER):
            # No raise_for_status(): HTTPManager raises for 4xx/5xx itself.
            resp = self.http_manager.get(
                self.config.url(ExampleDefaults.PATH_CHANNELS),
                headers=self.auth.build_headers(),   # raises AuthError etc.
                operation="api",
            )
            raw = resp.json().get("channels", [])

        channels: List[ExampleChannel] = []
        for entry in raw:
            try:
                channels.append(ExampleChannel.from_api_response(entry))
            except (KeyError, TypeError, AttributeError) as exc:
                logger.warning(f"{_PROVIDER}: skipping malformed channel entry: {exc!r}")
        return [c.to_channel(ExampleDefaults.PROVIDER_NAME) for c in channels]

    # ------------------------------------------------------------------
    # Playout (shared by manifest and DRM)
    # ------------------------------------------------------------------
    def clear_playout_cache(self) -> None:
        self._playout_cache.clear()

    def _playout(self, content_id: str) -> ExamplePlayout:
        now = time.time()
        cached = self._playout_cache.get(content_id)
        if cached and (now - cached[1]) < ExampleDefaults.PLAYOUT_CACHE_TTL:
            return cached[0]
        with transport_errors(f"playout for {content_id}", _PROVIDER):
            resp = self.http_manager.get(
                self.config.url(ExampleDefaults.PATH_PLAYOUT, channel_id=content_id),
                headers=self.auth.build_headers(),
                operation="api",
            )
            # ValueError on a malformed payload becomes a ServerError here.
            info = ExamplePlayout.from_api_response(resp.json())
        self._playout_cache[content_id] = (info, now)
        return info

    # ------------------------------------------------------------------
    # Manifest / headers
    # ------------------------------------------------------------------
    def get_channel_manifest(self, content_id: str, **kw: Any) -> Optional[str]:
        return self._playout(content_id).stream_url

    def get_channel_manifest_headers(self, content_id: str, **kw: Any) -> Dict[str, str]:
        # CDN headers, NOT the API headers the ABC default would return.
        # This override only takes effect with HEADERS_FROM_MANAGERS = True.
        return self.config.stream_headers()

    # ------------------------------------------------------------------
    # DRM (folded)
    # ------------------------------------------------------------------
    def get_channel_drm(self, content_id: str, **kw: Any) -> List[DRMConfig]:
        # The backend calls get_drm(content_id=..., **kw) with kwargs such as
        # drm_variant / preferred_quality / preferred_format (+ proxy extras)
        # and never passes content_type: accept **kw, ignore what you don't use.
        playout = self._playout(content_id)
        if not playout.license_url:
            return []                       # clear stream
        return [create_widevine_config(
            cfg=self.config,
            access_token=self.auth.get_access_token(),
            license_url=playout.license_url,
        )]
