# streaming_providers/base/managed_provider.py
"""
ManagedProvider -- StreamingProvider plus manager composition. DRAFT (round 2).

It SUBCLASSES StreamingProvider, so registry metadata, isinstance checks in
the backend and the legacy mixins keep working. Only new/migrated providers
use it; legacy providers are untouched.

It moves out of every provider what is identical in all of them:
    * the _build_*() hooks (default None = capability absent)
    * the implements_* flags
    * _route() and the default get_manifest() / get_drm() routing
    * get_channels(), EPG + header delegation, DRM validation
    * delegation of the legacy mixin surface (VOD, recordings, favorites,
      bookmarks, catchup) to the manager ABCs -- round 2

A provider still owns: http/auth/cache setup, the _build_*() bodies, and
anything with provider-specific grammar (simplitv: the catchup: branch
and get_restart()).

Usage in a provider's __init__, after http_manager / auth / caches exist:

    self._init_managers()

and for provider-specific prefixes:

    def get_manifest(self, content_id, **kw):
        if content_id.startswith(CATCHUP_PREFIX):
            ...
        return super().get_manifest(content_id, **kw)

Routing rules
-------------
1. handles_content_id() is a cheap pre-filter; False skips the manager.
2. A manager that passes may still return None/[]; the next is tried.
3. NotFoundError is remembered and re-raised only if nobody resolves.
4. BadRequestError is never caught.
5. The manager that resolved an id is remembered (bounded, locked), so
   headers go to the same manager that produced the manifest.
6. content_type narrows only for "live" and "vod"; anything else widens.
   (The backend never passes content_type -- drm_operations calls
   get_drm(content_id=..., **kw) -- so in practice rules 1-5 decide.)

Legacy surface -> manager (round 2)
-----------------------------------
Backend call (via *Operations)             Manager method
-----------------------------------------  ------------------------------------
get_vod_category / search_vod               VodManager (VodPage -> paged dict)
get_recordings(include_deleted=)            RecordingsManager.get_recordings
delete_recording(recording_id)              RecordingsManager.delete_recording
get_favorites / add_favorite / remove_...   FavoritesManager
get_bookmarks / update_bookmark / delete_.. BookmarksManager
catchup_window / get_catchup_window_for_..  CatchupManager.catchup_window_hours /
                                            catchup_window_for_channel
get_catchup_manifest(+_headers)             CatchupManager
get_catchup_drm                             CatchupManager; [] -> NotImplementedError
                                            (see CATCHUP_DRM_FROM_LIVE)
get_segment_headers(id, start_time=...)     CatchupManager.get_catchup_segment_headers
Not delegated (no manager ABC): timers, events, subscriptions.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from datetime import datetime
from typing import Any, Callable, ClassVar, Dict, List, Optional, Tuple

from .errors import ConfigurationError, NotFoundError
from .managers import (
    BookmarksManager,
    CatchupManager,
    ChannelManager,
    EpgManager,
    FavoritesManager,
    RecordingsManager,
    VodManager,
)
from .models import StreamingChannel
from .models.bookmark import Bookmark, ContentType
from .models.favorite import Favorite, FavoriteType
from .models.recording import Recording
# Module paths below assume models/drm/{exceptions,drm_config}.py (see TODO R-1).
from .models.drm.drm_config import validate_drm_set
from .models.drm.exceptions import DRMError
from .protocols import DrmManagerProtocol
from .provider import StreamingProvider
from .vod import normalize_vod_result

_ROUTED = ("channels", "vod")


class ManagedProvider(StreamingProvider):
    # Folded DRM: managers override get_channel_drm / get_vod_drm.
    # Explicit on purpose -- no override sniffing via method identity.
    DRM_IN_MANAGERS: ClassVar[bool] = False

    # True: header hooks on the managers are honoured (default is then
    # auth.build_headers(), NOT the legacy {}). Set False to keep legacy {}.
    HEADERS_FROM_MANAGERS: ClassVar[bool] = True

    # False: an empty CatchupManager.get_catchup_drm() result raises
    # NotImplementedError, which the backend maps to "extract PSSH from the
    # catchup manifest" (the legacy mixin contract). True: reuse the live DRM
    # -- only for providers whose catchup is encrypted exactly like live.
    CATCHUP_DRM_FROM_LIVE: ClassVar[bool] = False

    ROUTE_CACHE_SIZE: ClassVar[int] = 512

    # NOTE: `self.channels` holds the ChannelManager here (template
    # convention) and shadows the legacy list set by StreamingProvider.
    # to_output_format() is overridden below for that reason.

    # ------------------------------------------------------------------
    # Wiring
    # ------------------------------------------------------------------

    def _init_managers(self) -> None:
        """Build managers in dependency order (catchup sees channels)."""
        self._route_cache: "OrderedDict[str, str]" = OrderedDict()
        self._route_lock = threading.Lock()

        self.channels = self._build_channels()
        self.vod = self._build_vod()
        self.epg = self._build_epg()
        self.recordings = self._build_recordings()
        self.favorites = self._build_favorites()
        self.bookmarks = self._build_bookmarks()
        self.catchup = self._build_catchup()
        self.drm = self._build_drm()
        self._check_wiring()

    def _build_channels(self) -> Optional[ChannelManager]:
        return None

    def _build_vod(self) -> Optional[VodManager]:
        return None

    def _build_epg(self) -> Optional[EpgManager]:
        return None

    def _build_recordings(self) -> Optional[RecordingsManager]:
        return None

    def _build_favorites(self) -> Optional[FavoritesManager]:
        return None

    def _build_bookmarks(self) -> Optional[BookmarksManager]:
        return None

    def _build_catchup(self) -> Optional[CatchupManager]:
        return None

    def _build_drm(self) -> Optional[DrmManagerProtocol]:
        return None

    def _check_wiring(self) -> None:
        expected = {
            "channels": ChannelManager,
            "vod": VodManager,
            "epg": EpgManager,
            "recordings": RecordingsManager,
            "favorites": FavoritesManager,
            "bookmarks": BookmarksManager,
            "catchup": CatchupManager,
        }
        for attr, abc_type in expected.items():
            mgr = getattr(self, attr)
            if mgr is not None and not isinstance(mgr, abc_type):
                raise ConfigurationError(
                    f"{type(self).__name__}.{attr} is {type(mgr).__name__}, "
                    f"expected a {abc_type.__name__}"
                )
        if self.drm is not None and self.DRM_IN_MANAGERS:
            raise ConfigurationError(
                f"{type(self).__name__}: use _build_drm() OR "
                f"DRM_IN_MANAGERS, not both"
            )

    # ------------------------------------------------------------------
    # Capability flags (one signal each)
    # ------------------------------------------------------------------

    @property
    def implements_channels(self) -> bool:
        return self.channels is not None

    @property
    def implements_vod(self) -> bool:
        return self.vod is not None

    @property
    def implements_epg(self) -> bool:
        # Manager present AND it reports a window (epg_window != (0, 0)).
        # NOTE: EPGOperations uses this flag to choose between the native
        # path and the generic XMLTV path, so a manager that forgets to set
        # epg_window silently switches the provider to XMLTV.
        return self.epg is not None and self.epg.implements_epg

    @property
    def implements_recordings(self) -> bool:
        return self.recordings is not None

    @property
    def implements_favorites(self) -> bool:
        return self.favorites is not None

    @property
    def implements_bookmarks(self) -> bool:
        return self.bookmarks is not None

    @property
    def implements_catchup(self) -> bool:
        return self.catchup is not None and self.catchup.supports_catchup

    @property
    def implements_drm(self) -> bool:
        return self.drm is not None or self.DRM_IN_MANAGERS

    @property
    def capabilities(self) -> Dict[str, bool]:
        """All derived flags in one dict (same keys the registry reports)."""
        return {
            name: getattr(self, f"implements_{name}")
            for name in (
                "channels", "vod", "epg", "recordings", "favorites",
                "bookmarks", "catchup", "drm",
            )
        }

    # ------------------------------------------------------------------
    # Router
    # ------------------------------------------------------------------

    def _remember(self, content_id: str, name: str) -> None:
        with self._route_lock:
            self._route_cache[content_id] = name
            self._route_cache.move_to_end(content_id)
            while len(self._route_cache) > self.ROUTE_CACHE_SIZE:
                self._route_cache.popitem(last=False)

    def _route(
        self,
        content_id: str,
        attempts: List[Tuple[str, Callable[[Any], Any]]],
    ) -> Any:
        """
        attempts: [(manager attribute name, call(manager)), ...]
        A falsy result (None, "", []) means "not mine".
        """
        last_not_found: Optional[NotFoundError] = None
        for name, call in attempts:
            manager = getattr(self, name, None)
            if manager is None or not manager.handles_content_id(content_id):
                continue
            try:
                result = call(manager)
            except NotFoundError as exc:
                last_not_found = exc
                continue
            if result:
                self._remember(content_id, name)
                return result
        if last_not_found is not None:
            raise last_not_found
        return None

    def _routed_manager(self, content_id: str) -> Tuple[Optional[str], Any]:
        """Manager that resolved this id before, else the first that accepts it."""
        with self._route_lock:
            name = self._route_cache.get(content_id)
        if name is not None:
            return name, getattr(self, name, None)
        for candidate in _ROUTED:
            mgr = getattr(self, candidate, None)
            if mgr is not None and mgr.handles_content_id(content_id):
                return candidate, mgr
        return None, None

    # ------------------------------------------------------------------
    # Public surface
    # ------------------------------------------------------------------

    def get_channels(self, **kw: Any) -> List[StreamingChannel]:
        if self.channels is None:
            return []
        return self.channels.get_channels(**kw)

    # --- EPG -----------------------------------------------------------
    # The legacy ProviderEpgMixin never looks at self.epg: epg_window is
    # (0, 0), get_epg() returns [] and get_epg_grid() returns {} unless the
    # provider overrides them. Delegate once, here.
    # EPGOperations passes limit= and country= to get_epg; `limit` travels
    # in **kw to the manager, `country` is dropped (the manager has its own).
    # It hands over timezone-aware UTC datetimes.

    @property
    def epg_window(self) -> Tuple[int, int]:
        return self.epg.epg_window if self.epg is not None else (0, 0)

    def get_epg(
        self,
        channel_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        country: Optional[str] = None,  # legacy arg; the manager has its own
        **kw: Any,
    ) -> List:
        if not self.implements_epg or not self.epg.handles_channel_id(channel_id):
            return []
        return self.epg.get_epg(
            channel_id, start_time=start_time, end_time=end_time, **kw
        )

    def get_epg_grid(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        channel_ids: Optional[List[str]] = None,
        country: Optional[str] = None,
        **kw: Any,
    ) -> Dict[str, List]:
        # Legacy order is (start, end, channel_ids); the ABC's is
        # (channel_ids, start, end). Always pass by keyword.
        if not self.implements_epg:
            return {}
        if channel_ids is None:
            # Assumes EPG channel_id == content_id; verify per provider.
            channel_ids = [c.content_id for c in self.get_channels()]
        return self.epg.get_epg_grid(
            channel_ids, start_time=start_time, end_time=end_time, **kw
        )

    def get_program_details(self, program_id: str, **kw: Any):
        if not self.implements_epg:
            return None
        return self.epg.get_program_details(program_id, **kw)

    def to_output_format(self, channels: Optional[List[StreamingChannel]] = None) -> Dict:
        # Legacy implementation iterates self.channels, which is a manager here.
        if channels is None:
            channels = self.get_channels()
        return super().to_output_format(channels)

    # --- Manifest / headers -------------------------------------------

    def get_manifest(self, content_id: str, **kw: Any) -> Optional[str]:
        return self._route(content_id, [
            ("channels", lambda m: m.get_channel_manifest(content_id, **kw)),
            ("vod", lambda m: m.get_vod_manifest(content_id, **kw)),
        ])

    def get_manifest_headers(self, content_id: str, **kw: Any) -> Dict[str, str]:
        if not self.HEADERS_FROM_MANAGERS:
            return super().get_manifest_headers(content_id, **kw)
        name, mgr = self._routed_manager(content_id)
        if name == "channels":
            return mgr.get_channel_manifest_headers(content_id, **kw)
        if name == "vod":
            return mgr.get_vod_manifest_headers(content_id, **kw)
        return super().get_manifest_headers(content_id, **kw)

    def get_segment_headers(self, content_id: str, **kw: Any) -> Dict[str, str]:
        if self.HEADERS_FROM_MANAGERS:
            # The backend's catchup DRM/segment pipeline calls
            # get_segment_headers(id, start_time=..., end_time=..., epg_id=...)
            # (drm_operations) and swallows exceptions; live calls carry no
            # start_time. start_time therefore marks a catchup request.
            if self.catchup is not None and "start_time" in kw:
                rest = dict(kw)
                start = rest.pop("start_time")
                return self.catchup.get_catchup_segment_headers(
                    content_id,
                    start,
                    end_time=rest.pop("end_time", None),
                    epg_id=rest.pop("epg_id", None),
                    **rest,
                )
            name, mgr = self._routed_manager(content_id)
            if name in _ROUTED:  # both ChannelManager and VodManager have the hook
                return mgr.get_segment_headers(content_id, **kw)
        return self.get_manifest_headers(content_id, **kw)

    # --- DRM -----------------------------------------------------------

    def get_drm(
        self,
        content_id: str,
        drm_variant: Optional[str] = None,   # same position as legacy
        content_type: Optional[str] = None,  # "live" | "vod" narrow; else widen
        **kw: Any,
    ) -> List:
        # drm_operations calls get_drm(content_id=..., **kw) with keywords
        # only (drm_variant, preferred_quality, preferred_format, proxy
        # extras) and never passes content_type.
        if drm_variant is not None:
            kw["drm_variant"] = drm_variant

        if self.drm is not None:
            configs = self.drm.get_drm_configs(
                content_id, content_type=content_type, **kw
            )
        else:
            attempts: List[Tuple[str, Callable[[Any], Any]]] = []
            if content_type != "vod":
                attempts.append(
                    ("channels", lambda m: m.get_channel_drm(content_id, **kw))
                )
            if content_type != "live":
                attempts.append(
                    ("vod", lambda m: m.get_vod_drm(content_id, **kw))
                )
            configs = self._route(content_id, attempts) or []
        return self._validate_drm(content_id, configs)

    def _validate_drm(self, content_id: str, configs: List) -> List:
        """
        Reject configs ISA would mishandle: invalid, or equal priorities.

        Delegates to validate_drm_set (models/drm/drm_config.py). Note the
        factories (create_widevine, create_playready, ...) all default to
        priority=1, so a provider returning several DRMs must assign
        priorities (or use merge_drm_configs(..., auto_priority=True)).
        """
        try:
            validate_drm_set(configs)
        except DRMError as exc:
            raise ConfigurationError(
                f"{type(self).__name__}: invalid DRM configuration for "
                f"{content_id}: {exc}"
            ) from exc
        return configs

    # --- Catchup -------------------------------------------------------
    # Legacy ProviderCatchupMixin contract (see its docstrings):
    #   * catchup_window (hours) drives supports_catchup and
    #     validate_catchup_request; it must be the provider-wide MAXIMUM.
    #   * get_catchup_window_for_channel() is the per-channel hook.
    #   * get_catchup_manifest never falls back to the live manifest.
    #   * get_catchup_drm raises NotImplementedError => the pipeline extracts
    #     PSSH from the catchup manifest.
    # Parameter names (content_id, start_time, end_time, epg_id) must stay
    # identical: the legacy get_catchup_manifest_with_headers() calls these
    # methods by keyword.

    @property
    def catchup_window(self) -> int:
        return self.catchup.catchup_window_hours if self.catchup is not None else 0

    def get_catchup_window_for_channel(self, content_id: str) -> int:
        if self.catchup is None:
            return 0
        return self.catchup.catchup_window_for_channel(content_id)

    def get_catchup_manifest(
        self,
        content_id: str,
        start_time: int,
        end_time: Optional[int] = None,
        epg_id: Optional[str] = None,
        **kw: Any,
    ) -> Optional[str]:
        if self.catchup is None:
            raise NotImplementedError(
                f"{type(self).__name__} has no catchup manager"
            )
        return self.catchup.get_catchup_manifest(
            content_id, start_time, end_time=end_time, epg_id=epg_id, **kw
        )

    def get_catchup_manifest_headers(
        self,
        content_id: str,
        start_time: int,
        end_time: Optional[int] = None,
        epg_id: Optional[str] = None,
        **kw: Any,
    ) -> Dict[str, str]:
        if not self.HEADERS_FROM_MANAGERS or self.catchup is None:
            return super().get_catchup_manifest_headers(
                content_id, start_time, end_time, epg_id, **kw
            )
        return self.catchup.get_catchup_manifest_headers(
            content_id, start_time, end_time=end_time, epg_id=epg_id, **kw
        )

    def get_catchup_drm(
        self,
        content_id: str,
        start_time: int,
        end_time: Optional[int] = None,
        epg_id: Optional[str] = None,
        drm_variant: Optional[str] = None,
        **kw: Any,
    ) -> List:
        if self.catchup is None:
            raise NotImplementedError(
                f"{type(self).__name__} has no catchup manager"
            )
        if drm_variant is not None:
            kw["drm_variant"] = drm_variant
        configs = self.catchup.get_catchup_drm(
            content_id, start_time, end_time=end_time, epg_id=epg_id, **kw
        )
        if configs:
            return self._validate_drm(content_id, configs)
        if self.CATCHUP_DRM_FROM_LIVE:
            return self.get_drm(content_id, content_type="live", **kw)
        raise NotImplementedError(
            f"{type(self).__name__}: no catchup-specific DRM; the DRM "
            f"pipeline extracts PSSH from the catchup manifest"
        )

    # --- VOD -----------------------------------------------------------
    # VodOperations reads {"entries", "next_cursor", "total"} (or a list).

    @staticmethod
    def _vod_result(result: Any) -> Dict[str, Any]:
        """
        Manager result -> the dict VodOperations reads.

        normalize_vod_result (base/vod.py) is the single bridge for VodPage,
        legacy dict, bare list and None. Entries stay model objects (as
        legacy providers returned them); VodPage.to_dict() would serialise
        them, which is the route layer's job.
        """
        page = normalize_vod_result(result)
        return {
            "entries": list(page.entries),
            "next_cursor": page.next_cursor,
            "total": page.total,
        }

    def get_vod_category(
        self,
        content_id: str = "",
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kw: Any,
    ):
        if self.vod is None:
            return super().get_vod_category(
                content_id, cursor=cursor, page_size=page_size, **kw
            )
        return self._vod_result(
            self.vod.get_vod_category(
                content_id, cursor=cursor, page_size=page_size, **kw
            )
        )

    def search_vod(
        self,
        query: str,
        cursor: Optional[str] = None,
        page_size: int = 24,
        **kw: Any,
    ):
        if self.vod is None:
            return super().search_vod(
                query, cursor=cursor, page_size=page_size, **kw
            )
        return self._vod_result(
            self.vod.search_vod(query, cursor=cursor, page_size=page_size, **kw)
        )

    # --- Recordings ----------------------------------------------------

    def get_recordings(
        self, include_deleted: bool = False, **kw: Any
    ) -> List[Recording]:
        if self.recordings is None:
            return super().get_recordings(include_deleted=include_deleted, **kw)
        return self.recordings.get_recordings(include_deleted=include_deleted, **kw)

    def delete_recording(self, recording_id: str, **kw: Any) -> None:
        if self.recordings is None:
            return super().delete_recording(recording_id, **kw)
        return self.recordings.delete_recording(recording_id, **kw)

    # --- Favorites -----------------------------------------------------

    def get_favorites(self, **kw: Any) -> List[Favorite]:
        if self.favorites is None:
            return super().get_favorites(**kw)
        return self.favorites.get_favorites(**kw)

    def add_favorite(
        self,
        content_id: str,
        favorite_type: FavoriteType,
        title: Optional[str] = None,
        **kw: Any,
    ) -> Favorite:
        if self.favorites is None:
            return super().add_favorite(content_id, favorite_type, title, **kw)
        return self.favorites.add_favorite(
            content_id, favorite_type=favorite_type, title=title, **kw
        )

    def remove_favorite(self, content_id: str, **kw: Any) -> None:
        if self.favorites is None:
            return super().remove_favorite(content_id, **kw)
        return self.favorites.remove_favorite(content_id, **kw)

    # --- Bookmarks -----------------------------------------------------
    # batch_update_bookmarks() stays the legacy implementation: it calls
    # self.update_bookmark() per item, i.e. this delegation.
    # Argument order follows the legacy mixin (position_seconds before
    # content_type); ProviderManager's facade uses the opposite order, so
    # callers must use keywords (verified: bookmark_operations calls by keyword).

    def get_bookmarks(self, **kw: Any) -> List[Bookmark]:
        if self.bookmarks is None:
            return super().get_bookmarks(**kw)
        return self.bookmarks.get_bookmarks(**kw)

    def update_bookmark(
        self,
        content_id: str,
        position_seconds: int,
        content_type: ContentType,
        duration_seconds: Optional[int] = None,
        title: Optional[str] = None,
        **kw: Any,
    ) -> Bookmark:
        if self.bookmarks is None:
            return super().update_bookmark(
                content_id, position_seconds, content_type,
                duration_seconds, title, **kw,
            )
        return self.bookmarks.update_bookmark(
            content_id,
            position_seconds=position_seconds,
            content_type=content_type,
            duration_seconds=duration_seconds,
            title=title,
            **kw,
        )

    def delete_bookmark(self, content_id: str, **kw: Any) -> None:
        if self.bookmarks is None:
            return super().delete_bookmark(content_id, **kw)
        return self.bookmarks.delete_bookmark(content_id, **kw)
