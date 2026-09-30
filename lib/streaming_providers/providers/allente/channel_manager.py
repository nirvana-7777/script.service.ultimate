# streaming_providers/providers/allente/channel_manager.py
"""
Allente Channel Manager.

Handles:
  * Channel list (GET /v1/channels)      — DASH only
  * Playout     (GET /v1/playout/channel/{id})

The stream-session endpoints (/v1/stream/session/...) are NOT used in v1.
Captured logs suggest direct streaming works without them; if the
60-minute continuous playback test fails, revisit in v2 (and reintroduce
a persistent deviceId).
"""

from typing import List, Optional

from ...base.models import StreamingChannel
from ...base.utils.logger import logger
from .constants import AllenteDefaults
from .models import AllenteChannel, AllentePlayoutInfo


class AllenteChannelManager:
    """Fetches and resolves linear channels for Allente."""

    def __init__(self, provider):
        self._provider = provider

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------
    @property
    def config(self):
        return self._provider.provider_config

    @property
    def http(self):
        return self._provider.http_manager

    def _zulu_headers(self) -> dict:
        return self.config.zulu_headers(self._provider.bearer_token)

    # ------------------------------------------------------------------
    # Channel list
    # ------------------------------------------------------------------
    def get_channels(self) -> List[AllenteChannel]:
        """Fetch the user's channels from /v1/channels (DASH only)."""
        ent_tag = self._provider.entitlement_tag
        profile = self._provider.get_profile()
        if not ent_tag or not profile:
            logger.error("Allente: missing entitlement_tag or profile for channels")
            return []

        params = {
            # DASH only: playout always requests DASH, so MSS-only channels
            # would appear in the UI but fail at playback time.
            "streamType": "DASH",
            "kids": str(profile.kids).lower(),
            "parentalLevel": str(profile.parental_level),
            "profileId": profile.id,
            "entitlementTag": ent_tag,
        }
        # No raise_for_status(): HTTPManager raises for all 4xx/5xx
        # internally; any response reaching here is 1xx–3xx.
        resp = self.http.get(
            AllenteDefaults.ZULU_CHANNELS,
            params=params,
            headers=self._zulu_headers(),
            operation="api",
        )
        data = resp.json()
        channels = [
            AllenteChannel.from_api_response(c)
            for c in data.get("channels", [])
        ]
        logger.info(f"Allente: fetched {len(channels)} channels")
        return channels

    def get_channels_as_streaming_channels(self) -> List[StreamingChannel]:
        """
        Convert channels for the UI, dropping anything we cannot play.

        Safety net: even though the list is requested DASH-only, the server
        could still return MSS or non-Widevine entries. Filter them out
        here rather than showing channels that die on click.
        """
        channels = self.get_channels()
        playable = [
            c for c in channels
            if c.stream_type == "DASH" and c.stream_drm_type == "Widevine"
        ]
        dropped = len(channels) - len(playable)
        if dropped:
            logger.debug(
                f"Allente: filtered out {dropped} non-DASH/non-Widevine channels"
            )
        return [
            c.to_streaming_channel(self._provider.provider_name)
            for c in playable
        ]

    # ------------------------------------------------------------------
    # Playout
    # ------------------------------------------------------------------
    def resolve_playout(self, channel_id: str) -> Optional[AllentePlayoutInfo]:
        """Ask Zulu for the playout info for a channel."""
        params = {
            "streamType": self.config.stream_type,
            "entitlementTag": self._provider.entitlement_tag,
            "widevineLevel": self.config.widevine_level,
        }
        url = f"{AllenteDefaults.ZULU_PLAYOUT_CHANNEL}/{channel_id}"
        # No raise_for_status(): see get_channels().
        resp = self.http.get(
            url,
            params=params,
            headers=self._zulu_headers(),
            operation="api",
        )
        return AllentePlayoutInfo.from_api_response(resp.json())