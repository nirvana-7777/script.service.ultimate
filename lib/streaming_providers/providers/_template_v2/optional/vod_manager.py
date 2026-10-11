# streaming_providers/providers/example/vod_manager.py
"""
VOD manager skeleton (browseable catalogue).

--- WIRING ---
from .vod_manager import ExampleVodManager
def _build_vod(self):
    return ExampleVodManager(http_manager=self.http_manager, auth=self.auth,
                             country=self.country, config=self.provider_config)
--- END WIRING ---

Contract (VodManager ABC):
  * content_id is an OPAQUE token: you pick the grammar and document it here
    (e.g. "folder_<id>", "program_<id>", "clip_<id>"); empty string = root.
  * get_vod_category(content_id="", cursor=None, page_size=24) -> VodPage
        entries: mixed VodCategory / VodItem; next_cursor None = last page
        (that, not `total`, is the authoritative end-of-list signal). An EMPTY
        page is falsy (list semantics) -- test `page.has_more`, not `if page`.
  * get_vod_manifest(content_id) -> Optional[str]   None = "not mine"
  * handles_content_id: override as soon as live and VOD ids can collide
        (the router asks every manager; keep it cheap and I/O-free).
  * search_vod / get_vod_manifest_headers / get_segment_headers / get_vod_drm:
        concrete defaults; override what you need.
  * VodItem pricing/mode mismatches RAISE (strict), Channel only warns.
  * Slugs are derived per sibling set (see TODO D-1): do not persist them.
"""

from typing import Any, Optional

from ....base.managers import VodManager
from ....base.vod import VodPage


class ExampleVodManager(VodManager):
    def get_vod_category(
        self,
        content_id: str = "",
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kw: Any,
    ) -> VodPage:
        # TODO: fetch the children of `content_id` (root when empty) and
        # return VodPage(entries=[...], next_cursor=<token or None>, total=<int|None>)
        return VodPage()

    def get_vod_manifest(self, content_id: str, **kw: Any) -> Optional[str]:
        # TODO: return the manifest URL, or None if this id is not a VOD id.
        return None

    def handles_content_id(self, content_id: str) -> bool:
        # TODO: cheap prefix test, e.g. content_id.startswith("vod:")
        return True
