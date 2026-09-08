# streaming_providers/providers/joyn/catchup_manager.py
# -*- coding: utf-8 -*-
"""
Joyn Catchup Manager - Handles catchup/timeshift (to be implemented)
"""
from typing import List, Optional, Any
from ...base.models import DRMConfig
from ...base.utils.logger import logger

class JoynCatchupManager:
    def __init__(self, provider: Any):
        self.provider = provider
        logger.info(f"[JoynCatchupManager] Initialised (catchup not yet implemented)")

    @property
    def catchup_window(self) -> int:
        return 0

    @property
    def supports_catchup(self) -> bool:
        return False

    @staticmethod
    def get_catchup_manifest(
        content_id: str, start_time: int, end_time: int, epg_id: Optional[str] = None, **kwargs
    ) -> Optional[str]:
        return None

    @staticmethod
    def get_catchup_drm(
        content_id: str, start_time: int, end_time: int, epg_id: Optional[str] = None, **kwargs
    ) -> List[DRMConfig]:
        return []