# streaming_providers/base/managers/catchup.py
"""
CatchupManager ABC.

Public interface
----------------
    catchup_window_hours                                -> int             [concrete]
    supports_catchup                                    -> bool            [concrete]
    get_catchup_manifest(content_id, start_time, end_time=None, ...)
                                                        -> Optional[str]   [abstract]
    get_catchup_manifest_headers(...)                   -> Dict[str,str]   [concrete]
    get_catchup_drm(...)                                -> List[DRMConfig] [concrete]

Constructor contract
--------------------
Four required keyword-only collaborators. Catchup usually needs
additional collaborators at construction -- the channel manager (for
live manifest lookup) and/or the EPG manager (for EPG-based manifest
resolution, as MoveTV does). Those are explicit keyword-only extras
in the subclass.

Return-value conventions
------------------------
get_catchup_manifest returns None when the provider cannot resolve a
catchup manifest for the given content and window. It does NOT raise
NotFoundError -- "no catchup for this content" is a valid result, and
callers fall back to the live manifest.

get_catchup_drm returns [] when catchup shares DRM with live (the
common case), or a provider-specific list when catchup uses different
DRM.

Return the manifest of the live stream
--------------------------------------
The catchup manifest is a *modified* live manifest URL (with time
parameters) for providers like Magenta and MoveTV, or a distinct URL
for providers whose catchup is served from a different origin. This
ABC does not constrain the shape; it just names the entry point.

Do NOT silently fall back to the live manifest URL from within
get_catchup_manifest. Callers that want the live manifest on failure
should call provider.get_manifest() themselves. Silently returning a
live URL as a "catchup" URL would cause the DRM pipeline to extract
PSSH from the live stream, which may differ from the catchup stream's
encryption context.

end_time is optional
--------------------
The ABC accepts end_time as Optional[int] because some providers'
catchup APIs only take a start timestamp (simpliTV, for example --
it appends a single "start" parameter to the manifest URL and does
not consume an end bound). Providers whose API does use both bounds
should still declare and use end_time; providers whose API does not
should accept it for signature compatibility and document that it is
ignored.

Do NOT pass a sentinel value (0, or start_time, or start_time + 1800)
when the ABC accepts None. Pass None.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..models import DRMConfig
from ..protocols import AuthProtocol
from ..utils.logger import logger


class CatchupManager(ABC):
    """Abstract base for provider catchup managers."""

    def __init__(
        self,
        *,
        http_manager: Any,
        auth: AuthProtocol,
        country: str,
        config: Any,
    ) -> None:
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
    # Capability
    # ------------------------------------------------------------------

    @property
    def catchup_window_hours(self) -> int:
        """
        Return the catchup window in hours.

        Default 0 means no catchup. Providers override.
        """
        return 0

    @property
    def supports_catchup(self) -> bool:
        """True when catchup_window_hours > 0."""
        return self.catchup_window_hours > 0

    # ------------------------------------------------------------------
    # Abstract
    # ------------------------------------------------------------------

    @abstractmethod
    def get_catchup_manifest(
        self,
        content_id: str,
        start_time: int,
        end_time: Optional[int] = None,
        epg_id: Optional[str] = None,
        **kw: Any,
    ) -> Optional[str]:
        """
        Return the catchup manifest URL for the given content and window.

        Args:
            content_id: Channel identifier.
            start_time: Window start as Unix timestamp (seconds).
            end_time:   Window end as Unix timestamp (seconds), or None
                        when the provider's API does not use an end bound
                        (or when the caller does not know it). Providers
                        that need both bounds should require the caller
                        to pass end_time and raise BadRequestError on
                        None; providers that don't should accept None
                        and ignore it.
            epg_id:     Optional EPG event id, for providers that need it.

        Return None when the provider cannot resolve catchup for the
        content or window. Do not raise NotFoundError -- "no catchup" is
        a valid result.

        Do NOT fall back to the live manifest URL here. See the module
        docstring.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Concrete
    # ------------------------------------------------------------------

    def get_catchup_manifest_headers(
        self,
        content_id: str,
        start_time: int,
        end_time: Optional[int] = None,
        epg_id: Optional[str] = None,
        **kw: Any,
    ) -> Dict[str, str]:
        """
        Headers for the catchup manifest request.

        Default: the auth headers, which is correct for most providers.
        Override when catchup requires additional or different headers.
        """
        return self.auth.build_headers()

    def get_catchup_drm(
        self,
        content_id: str,
        start_time: int,
        end_time: Optional[int] = None,
        epg_id: Optional[str] = None,
        **kw: Any,
    ) -> List[DRMConfig]:
        """
        DRM for catchup content.

        Default: []. Most providers' catchup shares DRM with live (the
        caller falls back to the channel manager's DRM), or has no DRM.

        Providers whose catchup uses a distinct DRM configuration
        (different license URL, different PSSH) override this.
        """
        return []