# streaming_providers/base/managers/channel.py
"""
ChannelManager ABC.

Public interface
----------------
    handles_content_id(content_id)                  -> bool                [concrete]
    get_channels(**kw)                              -> List[Channel]       [abstract]
    get_channel_manifest(content_id, **kw)          -> Optional[str]       [abstract]
    get_channel_manifest_headers(content_id, **kw)  -> Dict[str, str]      [concrete]
    get_segment_headers(content_id, **kw)           -> Dict[str, str]      [concrete]
    get_channel_drm(content_id, **kw)               -> List[DRMConfig]     [concrete]

Constructor contract
--------------------
Four required keyword-only collaborators. Subclasses that need extra state
declare additional keyword-only args and store them on self AFTER calling
super().__init__. The base does NOT accept **kwargs -- a typo at a call
site becomes an immediate TypeError, which is what you want.

Return-value conventions
------------------------
get_channel_manifest / get_channel_drm return None / [] when this manager
does not handle content_id. Auth / geo / entitlement / rate-limit / server
failures propagate as exceptions from base.errors.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..models import Channel, DRMConfig
from ..protocols import AuthProtocol
from ..utils.logger import logger


class ChannelManager(ABC):
    """Abstract base for provider channel managers."""

    def __init__(
        self,
        *,
        http_manager: Any,
        auth: AuthProtocol,
        country: str,
        config: Any,
    ) -> None:
        # Sanity check the Auth collaborator against the runtime_checkable
        # protocol. isinstance on a runtime_checkable Protocol only verifies
        # method presence, not signatures -- that's the intended check here.
        if not isinstance(auth, AuthProtocol):
            logger.warning(
                f"{self.__class__.__name__}: auth does not match AuthProtocol "
                f"(missing one of get_access_token / build_headers / "
                f"invalidate). Got {type(auth).__name__}."
            )
        self.http_manager = http_manager
        self.auth = auth
        self.country = country
        self.config = config

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def handles_content_id(self, content_id: str) -> bool:
        """
        True if this manager handles the given content_id.

        Default: True. Override in providers whose channel content_ids have
        a distinguishable grammar (e.g. numeric-only for live channels).
        The orchestrator uses this to route get_manifest / get_drm without
        a wasted request to the wrong manager.
        """
        return True

    # ------------------------------------------------------------------
    # Abstract
    # ------------------------------------------------------------------

    @abstractmethod
    def get_channels(self, **kw: Any) -> List[Channel]:
        """Return the provider's live channels (Channel or subclass)."""
        raise NotImplementedError

    @abstractmethod
    def get_channel_manifest(
        self, content_id: str, **kw: Any
    ) -> Optional[str]:
        """
        Return the manifest URL for a channel, or None if this manager
        doesn't handle content_id. Do NOT raise NotFoundError for "not in
        my domain" -- the router uses the None return to fall through.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Concrete
    # ------------------------------------------------------------------

    def get_channel_manifest_headers(
        self, content_id: str, **kw: Any
    ) -> Dict[str, str]:
        """Headers for the manifest request. Default: auth headers."""
        return self.auth.build_headers()

    def get_segment_headers(
        self, content_id: str, **kw: Any
    ) -> Dict[str, str]:
        """Headers for segment requests. Default: manifest headers."""
        return self.get_channel_manifest_headers(content_id, **kw)

    def get_channel_drm(
        self, content_id: str, **kw: Any
    ) -> List[DRMConfig]:
        """DRM for a channel. Default: no DRM."""
        return []