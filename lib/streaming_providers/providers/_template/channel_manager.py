# streaming_providers/providers/_template/channel_manager.py
"""
{TODO: Provider name} channel manager.

Subclasses base.managers.ChannelManager. See ../_template/README.md.

Content-id grammar parsers for the whole provider live at MODULE SCOPE in
this file (the primary content-id namespace), and other managers import
them from here. One grammar, one parser. Parsers raise BadRequestError on
malformed input (the router does not catch it, so a bad id surfaces
instead of falling through to the wrong manager). Helpers shared across
managers are public -- no leading underscore.
"""

from typing import Dict, List, Optional

from ...base.managers import ChannelManager
from ...base.models import Channel
from ...base.utils.logger import logger

# from ...base.errors import BadRequestError
# from ...base.models import DRMConfig


# ----- Content-id grammar parsers (module scope) -----
#
# def parse_live_id(content_id: str) -> str:
#     if not content_id.startswith("live:"):
#         raise BadRequestError(f"not a live id: {content_id!r}")
#     return content_id[len("live:"):]


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
    #
    # Return None / [] for "not in my domain"; raise for real failures
    # (see the README's "Return-value rule").

    def get_channels(self, **kw) -> List[Channel]:
        raise NotImplementedError("YourChannelManager.get_channels")

    def get_channel_manifest(
        self, content_id: str, **kw
    ) -> Optional[str]:
        raise NotImplementedError(
            "YourChannelManager.get_channel_manifest"
        )

    # ----- Optional overrides -----

    # Override when the provider also has a VodManager: the default
    # returns True, so without this the channel manager is tried first
    # for every id.
    #
    # def handles_content_id(self, content_id: str) -> bool:
    #     return content_id.startswith(("live:", "rec:"))

    # Folded DRM architecture (DRM shares state with the manifest step):
    # override this and the provider's implements_drm flips to True
    # automatically. Dedicated DRM manager instead? Leave it alone.
    #
    # def get_channel_drm(self, content_id: str, **kw) -> List[DRMConfig]:
    #     return []