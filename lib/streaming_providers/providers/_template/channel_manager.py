# streaming_providers/providers/_template/channel_manager.py
"""
{TODO: Provider name} channel manager.

Subclasses base.managers.ChannelManager. See ../_template/README.md.
"""

from typing import Any, Dict, List, Optional

from ...base.managers import ChannelManager
from ...base.models import Channel, DRMConfig
from ...base.utils.logger import logger


class YourChannelManager(ChannelManager):
    """Fetches live channels for {TODO: provider name}."""

    def __init__(
        self,
        *,
        http_manager,
        auth,
        country,
        config,
        channels_cache: Optional[Dict] = None,
    ):
        # Forward ONLY the four required collaborators. Extra state goes
        # on self below. A typo at the call site (e.g. channel_cache=)
        # raises TypeError immediately.
        super().__init__(
            http_manager=http_manager,
            auth=auth,
            country=country,
            config=config,
        )
        self._channels_cache = (
            channels_cache if channels_cache is not None else {}
        )

    # ----- Abstract methods -----

    def get_channels(self, **kw) -> List[Channel]:
        raise NotImplementedError("YourChannelManager.get_channels")

    def get_channel_manifest(
        self, content_id: str, **kw
    ) -> Optional[str]:
        raise NotImplementedError(
            "YourChannelManager.get_channel_manifest"
        )

    # ----- Optional overrides -----

    # def handles_content_id(self, content_id: str) -> bool:
    #     return content_id.isdigit()