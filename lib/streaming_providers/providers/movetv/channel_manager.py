# streaming_providers/providers/movetv/channel_manager.py
"""
move.tv channel manager (live channels, live manifest, stream headers).

  * get_channels()                  -> subscribed channels (one malformed entry
                                       is skipped, the list survives)
  * get_channel_manifest(id)        -> live manifest URL
                                       None = not mine (non-numeric id, or a
                                       channel the account does not have)
  * get_channel_manifest_headers    -> CDN headers: User-Agent + X-Play-Auth
                                       (the per-stream value that comes with
                                       the manifest URL; never the API token)

The manager owns what v1 kept on the provider: the channel records
(`live_id`, catchup hours, stream uid -- fields of the old MoveTVChannel
subclass) and uses the provider-owned SourceCache shared with the catchup
manager. No DRM: `get_channel_drm` keeps the ABC default `[]`.
"""

import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ...base.errors import NotFoundError, ServerError
from ...base.managers import ChannelManager
from ...base.models import Channel
from ...base.utils.logger import logger
from .api import SourceCache, SourceInfo, api_post, fetch_source, is_fresh
from .constants import MoveTVConfig
from .ids import is_live_id

_PROVIDER = MoveTVConfig.PROVIDER_LABEL


@dataclass(frozen=True)
class ChannelRecord:
    """What the API needs about a channel beyond the Channel model."""
    live_id: int
    catchup_hours: int
    stream_uid: str


class MoveTvChannelManager(ChannelManager):
    def __init__(
        self,
        *,
        http_manager: Any,
        auth: Any,
        country: str,
        config: Any,
        source_cache: Optional[SourceCache] = None,
    ):
        super().__init__(http_manager=http_manager, auth=auth, country=country, config=config)
        # Provider-owned, borrowed by reference (shared with the catchup manager).
        self._source_cache = source_cache if source_cache is not None else SourceCache()
        self._records: Dict[str, ChannelRecord] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------
    def handles_content_id(self, content_id: str) -> bool:
        return is_live_id(content_id)

    # ------------------------------------------------------------------
    # Channels
    # ------------------------------------------------------------------
    def get_channels(self, **kw: Any) -> List[Channel]:
        data = api_post(
            self.http_manager, self.auth, self.config.channels_url(),
            lambda info: {
                "customerId": info["customer_id"],
                "customerProfileId": info["customer_profile_id"],
                "lang": self.config.DEFAULT_LANG,
                "appVersion": self.config.APP_VERSION,
            },
            what="channel list", operation="api",
        )
        if not data.get("success"):
            raise ServerError(f"{_PROVIDER}: channels endpoint returned success=false")

        channels: List[Channel] = []
        records: Dict[str, ChannelRecord] = {}
        for item in data.get("content") or []:
            parsed = self._parse_item(item)
            if parsed is None:
                continue
            channel, record = parsed
            channels.append(channel)
            records[channel.content_id] = record
        with self._lock:
            self._records = records
        logger.info(f"{_PROVIDER}: loaded {len(channels)} subscribed channels")
        return channels

    def _parse_item(self, item: Dict[str, Any]):
        try:
            if not item.get("subscribed", False):
                return None
            catalog_id = item.get("contentId")
            live_id = item.get("liveId")
            name = item.get("contentName", "")
            if not live_id or not catalog_id or not name:
                return None

            picture = item.get("picture") or {}
            catchup = item.get("catchup") or {}
            catchup_hours = int(catchup.get("duration", 0)) if catchup else 0
            is_audio = bool(item.get("audioOnly", False))

            common = dict(
                logo_url=self.config.build_logo_url(picture.get("icon")),
                session_manifest=True,
                language="sr",
                country=self.country.upper(),       # Content.country is upper-case
                catchup_hours=catchup_hours,
            )
            factory = Channel.create_radio_channel if is_audio else Channel.create_live_channel
            channel = factory(name, str(catalog_id), self.config.PROVIDER_NAME, **common)
            channel.channel_number = item.get("contentPosition")
            record = ChannelRecord(
                live_id=int(live_id),
                catchup_hours=catchup_hours,
                stream_uid=item.get("streamUid", "") or "",
            )
            return channel, record
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            logger.warning(f"{_PROVIDER}: skipping malformed channel entry: {exc!r} -- {item}")
            return None

    # ------------------------------------------------------------------
    # Records (also used by the catchup manager)
    # ------------------------------------------------------------------
    def record(self, content_id: str, *, rebuild: bool = False) -> Optional[ChannelRecord]:
        with self._lock:
            found = self._records.get(content_id)
        if found is None and rebuild:
            logger.info(f"{_PROVIDER}: channel {content_id} unknown; reloading the channel list")
            self.get_channels()
            with self._lock:
                found = self._records.get(content_id)
        return found

    def clear(self) -> None:
        """Account changed: forget channel records (provider callback)."""
        with self._lock:
            self._records = {}

    # ------------------------------------------------------------------
    # Live source (manifest + Play-Auth in ONE request, cached)
    # ------------------------------------------------------------------
    def _live_source(self, content_id: str) -> Optional[SourceInfo]:
        if not is_live_id(content_id):
            return None
        record = self.record(content_id, rebuild=True)
        if record is None:
            return None                      # not one of this account's channels
        source = fetch_source(
            http_manager=self.http_manager,
            session=self.auth,
            cache=self._source_cache,
            url=self.config.live_source_url(),
            build_payload=lambda: {"liveId": record.live_id},
            cache_key=content_id,
            operation="live_manifest",
            what=f"live source for channel {content_id}",
        )
        if source is None:
            raise ServerError(f"{_PROVIDER}: no live source for channel {content_id}")
        return source

    def get_channel_manifest(self, content_id: str, **kw: Any) -> Optional[str]:
        source = self._live_source(content_id)
        return source[0] if source else None

    def get_channel_manifest_headers(self, content_id: str, **kw: Any) -> Dict[str, str]:
        # Proxy/segment requests may hand the URL back: look it up first.
        url = kw.get("url") or kw.get("manifest_url") or kw.get("segment_url")
        if url:
            cached = self._source_cache.get(url)
            if is_fresh(cached):
                return self.config.stream_headers(cached[1])
        source = self._live_source(content_id)
        if source is None:
            raise NotFoundError(f"{_PROVIDER}: no live source for channel {content_id}")
        return self.config.stream_headers(source[1])