# streaming_providers/providers/allente/channel_manager.py
"""
Allente Channel Manager.

Handles:
  * Channel list (GET /v1/channels)      — DASH only
  * Playout     (GET /v1/playout/channel/{id})
  * Widevine DRM (folded: manifest and DRM share ONE playout response)

The stream-session endpoints (/v1/stream/session/...) are NOT used in v1.
Captured logs suggest direct streaming works without them; if the
60-minute continuous playback test fails, revisit in v2 (and reintroduce
a persistent deviceId).

Collaborators (ChannelManager contract)
---------------------------------------
    auth    -> AllenteSession (AuthProtocol adapter; also exposes
               entitlement_tag and profile)
    config  -> AllenteConfig (the ONE shared instance)

Error contract
--------------
Auth / geo failures raise AuthError / GeoBlockError (from the session),
network and malformed responses raise ServerError. Nothing is swallowed
into [] / None any more -- the previous provider logged and returned an
empty result. A channel id every manager would accept is "handled": the
default handles_content_id() (True) is correct, all ids are channel ids.

Playout cache
-------------
get_manifest and get_drm are separate calls for the same channel; the
5-second cache lets them share one playout request. It is keyed by channel
id and cleared by the provider when credentials change.
"""

import time
from typing import Any, Dict, List, Optional, Tuple

from ...base.managers import ChannelManager
from ...base.models import Channel, DRMConfig
from ...base.utils.logger import logger
from ...base.utils.transport import transport_errors
from .constants import AllenteDefaults
from .drm import create_allente_widevine_config
from .models import AllenteChannel, AllentePlayoutInfo

_PROVIDER = "Allente"


class AllenteChannelManager(ChannelManager):
    """Fetches and resolves linear channels for Allente."""

    def __init__(
        self,
        *,
        http_manager: Any,
        auth: Any,
        country: str,
        config: Any,
        playout_cache: Optional[Dict[str, Tuple[AllentePlayoutInfo, float]]] = None,
    ):
        super().__init__(
            http_manager=http_manager, auth=auth, country=country, config=config
        )
        # channel_id -> (info, timestamp). Provider-owned dict, borrowed.
        self._playout_cache = playout_cache if playout_cache is not None else {}

    # ------------------------------------------------------------------
    # Channel list
    # ------------------------------------------------------------------

    def get_channels(self, **kw: Any) -> List[Channel]:
        """The user's playable channels (DASH + Widevine), [] if none."""
        self.auth.require()
        profile = self.auth.profile
        params = {
            # DASH only: playout always requests DASH, so MSS-only channels
            # would appear in the UI but fail at playback time.
            "streamType": "DASH",
            "kids": str(profile.kids).lower(),
            "parentalLevel": str(profile.parental_level),
            "profileId": profile.id,
            "entitlementTag": self.auth.entitlement_tag,
        }
        with transport_errors("get_channels", _PROVIDER):
            # No raise_for_status(): HTTPManager raises for all 4xx/5xx
            # internally; any response reaching here is 1xx–3xx.
            resp = self.http_manager.get(
                AllenteDefaults.ZULU_CHANNELS,
                params=params,
                headers=self.auth.build_headers(),
                operation="api",
            )
            raw = resp.json().get("channels", [])

        channels: List[AllenteChannel] = []
        for entry in raw:
            # Strict parser, tolerant caller: one malformed entry must not
            # take the whole list down (see AllenteChannel).
            try:
                channels.append(AllenteChannel.from_api_response(entry))
            except (KeyError, TypeError, AttributeError) as exc:
                logger.warning(f"Allente: skipping malformed channel entry: {exc!r}")
        logger.info(f"Allente: fetched {len(channels)} channels")

        # Safety net: even though the list is requested DASH-only, the
        # server could still return MSS or non-Widevine entries. Filter
        # them out rather than showing channels that die on click.
        playable = [
            c for c in channels
            if c.stream_type == "DASH" and c.stream_drm_type == "Widevine"
        ]
        dropped = len(channels) - len(playable)
        if dropped:
            logger.debug(
                f"Allente: filtered out {dropped} non-DASH/non-Widevine channels"
            )
        return [c.to_streaming_channel(AllenteDefaults.PROVIDER_NAME) for c in playable]

    # ------------------------------------------------------------------
    # Playout (shared by manifest and DRM)
    # ------------------------------------------------------------------

    def clear_playout_cache(self) -> None:
        """Drop cached playout info (streamIds may be user/token-specific)."""
        self._playout_cache.clear()

    def _playout(self, content_id: str) -> AllentePlayoutInfo:
        now = time.time()
        cached = self._playout_cache.get(content_id)
        if cached and (now - cached[1]) < AllenteDefaults.PLAYOUT_CACHE_TTL:
            return cached[0]

        self.auth.require()
        params = {
            "streamType": self.config.stream_type,
            "entitlementTag": self.auth.entitlement_tag,
            "widevineLevel": self.config.widevine_level,
        }
        url = f"{AllenteDefaults.ZULU_PLAYOUT_CHANNEL}/{content_id}"
        with transport_errors(f"playout for {content_id}", _PROVIDER):
            # No raise_for_status(): see get_channels().
            resp = self.http_manager.get(
                url,
                params=params,
                headers=self.auth.build_headers(),
                operation="api",
            )
            # ValueError for a payload without stream.url / stream.streamId
            # becomes a ServerError here.
            info = AllentePlayoutInfo.from_api_response(resp.json())
        self._playout_cache[content_id] = (info, now)
        return info

    # ------------------------------------------------------------------
    # Manifest
    # ------------------------------------------------------------------

    def get_channel_manifest(self, content_id: str, **kw: Any) -> Optional[str]:
        """The MPD URL for a channel (content_id = channel ID)."""
        return self._playout(content_id).stream_url

    def get_channel_manifest_headers(
        self, content_id: str, **kw: Any
    ) -> Dict[str, str]:
        """Headers for the MPD fetch: origin / referer / UA (Akamai gate)."""
        return self.config.stream_headers()

    # get_segment_headers: ABC default = manifest headers (what the
    # previous provider did).

    # ------------------------------------------------------------------
    # DRM (Widevine via Zulu), folded into this manager
    # ------------------------------------------------------------------

    def get_channel_drm(self, content_id: str, **kw: Any) -> List[DRMConfig]:
        """
        Widevine DRM configuration for a channel.

        drm_variant (and other backend kwargs) are accepted and ignored in
        v1 -- the Widevine security level comes from config.widevine_level.
        Mapping variants to levels (software -> L3, hardware -> L1) is a
        v1.1 candidate and would also require keying the playout cache by
        level, since widevineLevel is a playout request parameter.

        NOTE: the license config embeds the CURRENT bearer token, and ISA
        reuses it for the whole playback session. Continuous playback
        across token expiry is not supported in v1.

        Returns [] for non-Widevine channels (unsupported in v1). A broken
        DRM configuration raises (LicenseConfigError is a ConfigurationError)
        instead of being logged away.
        """
        variant = kw.get("drm_variant")
        if variant:
            logger.debug(f"Allente: get_drm drm_variant={variant!r} — ignored in v1")

        playout = self._playout(content_id)
        if playout.drm_type != "Widevine":
            logger.warning(
                f"Allente: channel {content_id} uses {playout.drm_type}, "
                f"not Widevine. Unencrypted/other-DRM playback is not "
                f"supported in v1."
            )
            return []

        return [create_allente_widevine_config(
            cfg=self.config,
            bearer_token=self.auth.get_access_token(),
            stream_id=playout.stream_id,
        )]