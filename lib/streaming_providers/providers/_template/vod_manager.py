# streaming_providers/providers/_template/vod_manager.py
"""
{TODO: Provider name} VOD manager.

Subclasses base.managers.VodManager. Document the content_id grammar here.

See ../_template/README.md for the contract.

Every navigation method returns VodPage. To paginate use `page.has_more`
(NOT bool(page)); `next_cursor is None` is the authoritative end-of-list
signal and `total` is informational only.
"""

from typing import Dict, List, Optional

from ...base.managers import VodManager
from ...base.vod import VodPage
from ...base.utils.logger import logger

# from ...base.models import DRMConfig


class YourVodManager(VodManager):
    """
    VOD catalogue navigation for {TODO: provider name}.

    content_id grammar (TODO: fill in):

        ""                     root
        "folder_<id>"          browse a folder
        "details_<id>"         a single item
    """

    def __init__(
        self,
        *,
        http_manager,
        auth,
        country,
        config,
        playback_cache: Optional[Dict] = None,
    ):
        super().__init__(
            http_manager=http_manager,
            auth=auth,
            country=country,
            config=config,
        )
        self._playback_cache = (
            playback_cache if playback_cache is not None else {}
        )

    # ----- Abstract methods -----

    def get_vod_category(
        self,
        content_id: str = "",
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kw,
    ) -> VodPage:
        raise NotImplementedError("YourVodManager.get_vod_category")

    def get_vod_manifest(
        self, content_id: str, **kw
    ) -> Optional[str]:
        raise NotImplementedError("YourVodManager.get_vod_manifest")

    # ----- Optional overrides -----

    # Override when the provider also has a ChannelManager (see the
    # channel manager template for why).
    #
    # def handles_content_id(self, content_id: str) -> bool:
    #     return content_id.startswith(("details_", "clip_"))

    # Folded DRM architecture; see the channel manager template.
    #
    # def get_vod_drm(self, content_id: str, **kw) -> List[DRMConfig]:
    #     return []