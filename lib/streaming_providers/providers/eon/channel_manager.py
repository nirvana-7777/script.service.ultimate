# streaming_providers/providers/eon/channel_manager.py
"""
Eon channel manager.

Live channels come from v4/channels (TV, plus RADIO when enabled); the list
order is the channel number. Manifest and DRM do not share state here: Eon
streams are clear HLS (DRM_IN_MANAGERS = False), the "manifest" is a signed,
AES-encrypted CDN URL minted locally (stream_url.py).

Return conventions (ChannelManager ABC):
  get_channel_manifest -> None for an id that is not in the channel list
                          (the router falls through); raises EntitlementError
                          for a channel the account is not subscribed to.

The URL carries a server ctime the CDN accepts for ~20 s and a session id it
will not accept twice, so URLs are cached for a few seconds only (a manifest
and a header call for the same id share one URL, nothing longer).
"""

import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from ...base.errors import (
    AuthError, EntitlementError, GeoBlockError, ProviderError, RateLimitError,
)
from ...base.managers import ChannelManager
from ...base.models import Channel
from ...base.utils.logger import logger
from .constants import EonConfig, EonDefaults
from .models import EonChannel
from .stream_url import StreamUrlParams, build_stream_url

_PROVIDER = EonDefaults.PROVIDER_LABEL


class EonChannelManager(ChannelManager):
    def __init__(
        self,
        *,
        http_manager: Any,
        auth: Any,
        country: str,
        config: EonConfig,
        api: Any,
        endpoints: Any,
        catalog: Any,
        url_cache: Optional[Dict[Tuple[str, Optional[int]], Tuple[str, float]]] = None,
    ):
        super().__init__(
            http_manager=http_manager, auth=auth, country=country, config=config
        )
        self._api = api
        self._endpoints = endpoints
        self._catalog = catalog
        # Provider-owned dict, borrowed by reference; cleared on credential change.
        self._url_cache = url_cache if url_cache is not None else {}
        self._records: Dict[str, EonChannel] = {}
        self._records_lock = threading.RLock()

    # ------------------------------------------------------------------
    # Channels
    # ------------------------------------------------------------------
    def get_channels(self, **kw: Any) -> List[Channel]:
        entries = self._fetch(EonDefaults.CHANNEL_TYPE_TV, is_radio=False, required=True)
        if self.config.include_radio:
            entries += self._fetch(EonDefaults.CHANNEL_TYPE_RADIO, is_radio=True, required=False)

        if self.config.hide_unsubscribed:
            entries = [e for e in entries if e.subscribed]

        with self._records_lock:
            self._records = {e.id: e for e in entries}

        number = self.config.channel_start_number
        channels: List[Channel] = []
        for entry in entries:
            channels.append(entry.to_channel(
                EonDefaults.PROVIDER_NAME, country=self.country or "BG",
                language=self.config.language, number=number,
                logo_url=self._endpoints.image_url(entry.logo_path),
                short_names=self.config.short_names,
            ))
            number += 1
        return channels

    def _fetch(self, channel_type: str, *, is_radio: bool, required: bool) -> List[EonChannel]:
        try:
            raw = self._api.get_json(
                EonDefaults.PATH_CHANNELS,
                params={"channelType": channel_type, "channelSort": EonDefaults.CHANNEL_SORT},
            )
        except (AuthError, RateLimitError, GeoBlockError):
            raise
        except ProviderError as exc:
            if required:
                raise
            logger.warning(f"{_PROVIDER}: {channel_type} channels unavailable: {exc}")
            return []

        parsed: List[EonChannel] = []
        for entry in raw if isinstance(raw, list) else []:
            try:
                parsed.append(EonChannel.from_api_response(entry, is_radio=is_radio))
            except (KeyError, TypeError, AttributeError, ValueError) as exc:
                logger.warning(f"{_PROVIDER}: skipping malformed channel entry: {exc!r}")
        return parsed

    def record(self, content_id: str) -> Optional[EonChannel]:
        """The parsed channel for an id (loads the list on first use)."""
        with self._records_lock:
            known = bool(self._records)
        if not known:
            self.get_channels()
        with self._records_lock:
            return self._records.get(str(content_id))

    # ------------------------------------------------------------------
    # Manifest / headers
    # ------------------------------------------------------------------
    def get_channel_manifest(self, content_id: str, **kw: Any) -> Optional[str]:
        record = self.record(content_id)
        if record is None:
            return None
        return self.stream_url(record, start_time=None)

    def get_channel_manifest_headers(self, content_id: str, **kw: Any) -> Dict[str, str]:
        # CDN headers (browser / smart-TV UA), NOT the API headers.
        # Only takes effect with HEADERS_FROM_MANAGERS = True.
        return self.config.stream_headers()

    # ------------------------------------------------------------------
    # URL minting (shared with the catchup manager)
    # ------------------------------------------------------------------
    def stream_url(self, record: EonChannel, *, start_time: Optional[int]) -> str:
        if not record.subscribed or not record.publishing_points:
            raise EntitlementError(f"{_PROVIDER}: not subscribed to {record.name}")

        key = (record.id, start_time)
        now = time.time()
        cached = self._url_cache.get(key)
        if cached and (now - cached[1]) < EonDefaults.URL_CACHE_TTL:
            return cached[0]

        point = record.publishing_points[0]
        live = start_time is None
        kind = (EonDefaults.SIG_RADIO if record.is_radio
                else EonDefaults.SIG_LIVE if live else EonDefaults.SIG_CUTV)
        sig = point.sig_for(kind) or point.sig_for(EonDefaults.SIG_LIVE) or ""

        creds = self.auth.stream_credentials()
        profile = self._catalog.best_profile(point.profile_ids, radio=record.is_radio)
        server = self._catalog.server(live=live)
        url = build_stream_url(StreamUrlParams(
            platform=self.config.platform,
            publishing_point=point.name,
            stream_profile=profile.core_stream_id,
            service_provider=self._catalog.service_provider,
            stream_user=creds.stream_user,
            stream_key=creds.stream_key,
            server_host=server.hostname,
            server_ip=server.ip,
            device_number=creds.device_number,
            sig=sig,
            aa_enabled=record.aa_enabled,
            video_bitrate=profile.video_bitrate,   # NOT the audio bitrate (AO96 -> 403.5300)
            ctime_ms=self._api.server_time(),
            session_id=str(uuid.uuid4()),
            adaptive=self.config.adaptive_hint,
            start_time=start_time,
        ))
        self._url_cache[key] = (url, now)
        return url

    def clear_url_cache(self) -> None:
        self._url_cache.clear()