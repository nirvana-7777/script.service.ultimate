# streaming_providers/base/managers/vod.py
"""
VodManager ABC.

Public interface
----------------
    handles_content_id(content_id)                     -> bool               [concrete]
    get_vod_category(content_id="", cursor=None, page_size=24, **kw)
                                                       -> VodPage            [abstract]
    get_vod_manifest(content_id, **kw)                 -> Optional[str]      [abstract]
    search_vod(query, cursor=None, page_size=24, **kw) -> VodPage            [concrete]
    get_vod_manifest_headers(content_id, **kw)         -> Dict[str, str]     [concrete]
    get_segment_headers(content_id, **kw)              -> Dict[str, str]     [concrete]
    get_vod_drm(content_id, **kw)                      -> List[DRMConfig]    [concrete]

content_id grammar
------------------
content_id is an opaque token. Each provider picks its own grammar and
documents it here. The base class does not parse content_id. Examples:

    RTL+        "folder_<id>", "program_<id>", "clip_<id>", ...
    HRTi        "catalogue_<id>", "series_<sid>--<ssid>", ...
    Discovery   "/sports", "/sports/alpine-skiing", ...
    MoveTV      ["root", "Film", "123"] encoded into a string

Constructor contract
--------------------
Four required keyword-only collaborators (see ManagerBase). No **kwargs.
Subclasses accept extra keyword-only args explicitly and call
super().__init__ with only the four required.

Return-value conventions
------------------------
get_vod_manifest / get_vod_drm return None / [] when this manager does not
handle content_id. Auth / geo / entitlement / rate-limit / server failures
propagate as exceptions from base.errors.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, Dict, List, Optional

from ..models import DRMConfig
from ..vod import VodPage
from ._base import ManagerBase


class VodManager(ManagerBase):
    """Abstract base for provider VOD managers."""

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def handles_content_id(self, content_id: str) -> bool:
        """
        True if this manager handles the given content_id.

        Default: True. Override in providers whose VOD content_ids have a
        distinguishable grammar (e.g. start with "details_" or "clip_").
        Cheap, I/O-free PRE-FILTER: False means the manager is never asked.
        """
        return True

    # ------------------------------------------------------------------
    # Abstract
    # ------------------------------------------------------------------

    @abstractmethod
    def get_vod_category(
        self,
        content_id: str = "",
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kw: Any,
    ) -> VodPage:
        """Return children of a VOD node. Empty content_id is the root."""
        raise NotImplementedError

    @abstractmethod
    def get_vod_manifest(
        self, content_id: str, **kw: Any
    ) -> Optional[str]:
        """Return the manifest URL, or None if not handled by this manager."""
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Concrete
    # ------------------------------------------------------------------

    def search_vod(
        self,
        query: str,
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kw: Any,
    ) -> VodPage:
        """Search the catalogue. Default: no results. Override if supported."""
        return VodPage()

    def get_vod_manifest_headers(
        self, content_id: str, **kw: Any
    ) -> Dict[str, str]:
        """Headers for the manifest request. Default: auth headers."""
        return self.auth.build_headers()

    def get_segment_headers(
        self, content_id: str, **kw: Any
    ) -> Dict[str, str]:
        """
        Headers for segment requests. Default: manifest headers.

        Mirrors ChannelManager.get_segment_headers so the orchestrator can
        ask any routed manager for segment headers. Override for providers
        with token-bound segment URLs.
        """
        return self.get_vod_manifest_headers(content_id, **kw)

    def get_vod_drm(
        self, content_id: str, **kw: Any
    ) -> List[DRMConfig]:
        """DRM for a VOD item. Default: no DRM."""
        return []