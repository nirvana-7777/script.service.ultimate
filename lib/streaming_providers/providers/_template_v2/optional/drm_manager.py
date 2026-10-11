# streaming_providers/providers/example/drm_manager.py
"""
DEDICATED DRM manager skeleton -- only when DRM does NOT share state with
the manifest step (otherwise fold DRM into the channel/VOD manager and set
DRM_IN_MANAGERS = True).

--- WIRING ---
from .drm_manager import ExampleDrmManager
def _build_drm(self):
    return ExampleDrmManager(http_manager=self.http_manager, auth=self.auth,
                             config=self.provider_config)
(and set DRM_IN_MANAGERS = False -- ManagedProvider refuses both at once)
--- END WIRING ---

Implements DrmManagerProtocol.get_drm_configs(content_id, content_type=None,
**kw) -> List[DRMConfig]. Decision tree (README §DRM):
  folded in managers (default)  -> DRM_IN_MANAGERS = True
  dedicated object              -> _build_drm(), DRM_IN_MANAGERS = False
  catchup with different DRM    -> CatchupManager.get_catchup_drm
Each config needs a distinct priority; [] = no DRM; broken config raises.
"""

from typing import Any, List, Optional


class ExampleDrmManager:
    def __init__(self, *, http_manager, auth, config):
        self.http_manager, self.auth, self.config = http_manager, auth, config

    def get_drm_configs(
        self, content_id: str, content_type: Optional[str] = None, **kw: Any
    ) -> List:
        return []            # TODO
