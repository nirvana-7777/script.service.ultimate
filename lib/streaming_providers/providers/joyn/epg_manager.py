# streaming_providers/providers/joyn/epg_manager.py
# -*- coding: utf-8 -*-
"""
Joyn EPG Manager - Handles EPG data (to be implemented)
"""
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from ...base.utils.logger import logger

class JoynEpgManager:
    def __init__(self, provider: Any):
        self.provider = provider
        logger.info(f"[JoynEpgManager] Initialised (EPG not yet implemented)")

    @property
    def implements_epg(self) -> bool:
        return False

    @property
    def epg_window(self) -> Tuple[int, int]:
        return 0, 0

    @staticmethod
    def get_events(
        start_time: Optional[datetime] = None, end_time: Optional[datetime] = None, **kwargs
    ) -> List:
        return []

    @staticmethod
    def get_epg(
        channel_id: str, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None, **kwargs
    ) -> List:
        return []

    @staticmethod
    def get_epg_grid(
        start_time: Optional[datetime] = None, end_time: Optional[datetime] = None, channel_ids: Optional[List[str]] = None, **kwargs
    ) -> Dict[str, List]:
        return {}

    @staticmethod
    def get_program_details(program_id: str, **kwargs) -> Optional[Dict]:
        return None