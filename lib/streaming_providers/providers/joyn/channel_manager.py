# streaming_providers/providers/joyn/channel_manager.py
# -*- coding: utf-8 -*-
"""
Joyn Channel Manager - Handles channels, EPG, and streaming data
"""

import hashlib
import json
import time
import urllib.parse
from base64 import b64decode
from typing import Dict, List, Optional

from ...base.models import DRMConfig, DRMSystem, LicenseConfig, StreamingChannel
from ...base.provider import AuthType
from ...base.utils.logger import logger
from .constants import (
    CONTENT_TYPE_LIVE,
    CONTENT_TYPE_VOD,
    DEFAULT_EPG_WINDOW_HOURS,
    DEFAULT_LIVESTREAM_TYPES,
    DEFAULT_MAX_RETRIES,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_VIDEO_CONFIG,
    DRM_REQUEST_HEADERS,
    DRM_SYSTEM_WIDEVINE,
    ERROR_CODES,
    GRAPHQL_LIVE_CHANNELS_FILTER,
    GRAPHQL_MAX_RESULTS,
    GRAPHQL_OFFSET,
    GRAPHQL_PERSISTED_QUERY_VERSION,
    GRAPHQL_QUERY_HASHES,
    JOYN_API_BASE_HEADERS,
    JOYN_CLIENT_VERSION,
    JOYN_DOMAINS,
    JOYN_GRAPHQL_BASE_HEADERS,
    JOYN_GRAPHQL_ENDPOINTS,
    JOYN_STREAMING_ENDPOINTS,
    JOYN_USER_AGENT,
    MODE_LIVE,
    MODE_VOD,
    SIGNATURE_SECRET_KEY,
)
from .models import JoynChannel, JoynError, JoynEntitlementError, PlaybackRestrictedException


def create_video_payload(config: Optional[Dict] = None, compact: bool = True) -> str:
    video_config = config or DEFAULT_VIDEO_CONFIG
    payload = json.dumps(video_config)
    return payload.replace(" ", "") if compact else payload


def build_signature(
    entitlement_token: str,
    video_payload: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> str:
    if video_payload is None:
        video_payload = create_video_payload()
    if secret_key is None:
        secret_key = b64decode(SIGNATURE_SECRET_KEY).decode("utf-8")
    signature_input = f"{video_payload},{entitlement_token}{secret_key}"
    return hashlib.sha1(signature_input.encode("utf-8")).hexdigest()


class JoynChannelManager:
    """
    Owns channel/EPG streaming data AND the shared header-building + entitlement
    logic that vod_manager also depends on. vod_manager calls back into this
    manager (via self.provider.channel_manager) rather than keeping its own
    copies of _get_graphql_headers / get_api_headers / get_entitlement_token.
    """

    def __init__(self, provider):
        self.provider = provider

        self._channels_cache: Optional[List[StreamingChannel]] = None
        self._cache_timestamp: float = 0.0
        self._cache_ttl: int = 300  # 5 minutes

        logger.info(f"[JoynChannelManager] Initialised for country={provider.country}")

    @property
    def http_manager(self):
        return self.provider.http_manager

    @property
    def authenticator(self):
        return self.provider.authenticator

    @property
    def country(self) -> str:
        return self.provider.country

    @property
    def platform(self) -> str:
        return self.provider.platform

    @property
    def distribution_tenant(self) -> str:
        return self.provider.distribution_tenant

    @property
    def channels(self) -> List[StreamingChannel]:
        """Lazy-loaded channels list with TTL caching"""
        if self._channels_cache is None or (time.time() - self._cache_timestamp) > self._cache_ttl:
            self._channels_cache = self.get_channels()
            self._cache_timestamp = time.time()
        return self._channels_cache or []

    def _get_graphql_headers(self) -> Dict[str, str]:
        return self.provider._build_provider_headers(
            base_headers=JOYN_GRAPHQL_BASE_HEADERS,
            auth_type=AuthType.NONE,
            provider_headers={
                "joyn-client-version": JOYN_CLIENT_VERSION,
                "joyn-country": self.country.upper(),
                "joyn-distribution-tenant": self.distribution_tenant,
                "joyn-platform": self.platform,
                "joyn-user-state": "code=R_A",
            },
        )

    def get_api_headers(self) -> Dict[str, str]:
        # Public: vod_manager delegates to this instead of keeping its own
        # copy (see JoynVodManager._get_api_headers).
        return self.provider._build_provider_headers(
            base_headers=JOYN_API_BASE_HEADERS,
            auth_type=AuthType.BEARER,
            provider_headers={
                "joyn-client-version": JOYN_CLIENT_VERSION,
                "joyn-country": self.country.upper(),
                "joyn-distribution-tenant": self.distribution_tenant,
                "joyn-platform": self.platform,
                "joyn-b2b-context": "UNKNOWN",
                "joyn-client-os": "UNKNOWN",  # Restored missing header
                "origin": JOYN_DOMAINS.get(self.country, JOYN_DOMAINS["de"]),
            },
        )

    def get_channels(
        self,
        time_window_hours: int = DEFAULT_EPG_WINDOW_HOURS,
        fetch_manifests: bool = False,
        populate_streaming_data: bool = True,
        **kwargs,
    ) -> List[StreamingChannel]:
        try:
            headers = self._get_graphql_headers()
            current_time = int(time.time())
            end_time = current_time + (time_window_hours * 3600)

            variables = {
                "liveStreamGroupFilter": GRAPHQL_LIVE_CHANNELS_FILTER,
                "first": GRAPHQL_MAX_RESULTS,
                "offset": GRAPHQL_OFFSET,
                "livestreamTypes": DEFAULT_LIVESTREAM_TYPES,
                "from": current_time,
                "to": end_time,
            }
            variables_encoded = urllib.parse.quote(json.dumps(variables))
            extensions = {
                "persistedQuery": {
                    "version": GRAPHQL_PERSISTED_QUERY_VERSION,
                    "sha256Hash": GRAPHQL_QUERY_HASHES["LIVE_CHANNELS"],
                }
            }
            extensions_encoded = urllib.parse.quote(json.dumps(extensions))

            url = f"{JOYN_GRAPHQL_ENDPOINTS['LIVE_CHANNELS']}&variables={variables_encoded}&extensions={extensions_encoded}"

            response = self.http_manager.get(
                url, operation="api", headers=headers, timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            channel_data = response.json()

            channels = self._process_graphql_response(channel_data)

            if fetch_manifests and populate_streaming_data:
                channels = self.populate_streaming_data(channels)

            logger.info(f"Successfully fetched {len(channels)} channels for country {self.country}")
            return channels

        except Exception as e:
            logger.error(f"Error fetching channels from GraphQL: {e}")
            return []

    def _process_graphql_response(self, response_data: Dict) -> List[StreamingChannel]:
        if "data" not in response_data or "liveStreams" not in response_data["data"]:
            raise JoynError("Invalid GraphQL response structure")

        live_streams = response_data["data"]["liveStreams"]
        channels = []

        for stream_data in live_streams:
            try:
                channel_id = stream_data.get("id", "")
                title = stream_data.get("title", "Unknown Channel")
                stream_type = stream_data.get("type", "LINEAR")
                quality = stream_data.get("quality", "")

                logo_url = None
                if "logo" in stream_data and "url" in stream_data["logo"]:
                    logo_url = stream_data["logo"]["url"]

                content_type = CONTENT_TYPE_LIVE if stream_type == "LINEAR" else CONTENT_TYPE_VOD
                mode = MODE_LIVE if stream_type == "LINEAR" else MODE_VOD

                joyn_channel = JoynChannel(
                    name=title,
                    channel_id=channel_id,
                    logo_url=logo_url,
                    mode=mode,
                    content_type=content_type,
                    country=self.country,
                    raw_data=stream_data,
                )

                if quality:
                    joyn_channel.name = f"{title} ({quality})"

                if "brand" in stream_data:
                    brand_data = stream_data["brand"]
                    if "brand_id" in brand_data:
                        joyn_channel.raw_data["brand_id"] = brand_data["brand_id"]

                if stream_data.get("eventStream", False):
                    joyn_channel.raw_data["is_event_stream"] = True

                channels.append(joyn_channel.to_streaming_channel(provider_name=self.provider.provider_name))
            except Exception as e:
                logger.warning(f"Error processing channel data: {e}")

        return channels

    def get_entitlement_token(self, content_id: str, content_type: str = CONTENT_TYPE_LIVE) -> str:
        headers = self.get_api_headers()
        payload = {"content_id": content_id, "content_type": content_type}

        try:
            response = self.http_manager.post(
                JOYN_STREAMING_ENDPOINTS["ENTITLEMENT"],
                operation="auth",
                headers=headers,
                json_data=payload,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )

            if response.status_code == 400:
                try:
                    error_data = response.json()
                    if isinstance(error_data, list) and len(error_data) > 0:
                        error = error_data[0]
                        code = error.get("code", "UNKNOWN")
                        msg = error.get("msg", "No error message provided")
                        if code == ERROR_CODES["PLAYBACK_RESTRICTED"]:
                            raise PlaybackRestrictedException(f"Playback restricted for {content_id}: {msg}")
                        else:
                            raise JoynEntitlementError(f"Entitlement error for {content_id} ({code}): {msg}")
                except (json.JSONDecodeError, KeyError, IndexError) as e:
                    raise JoynEntitlementError(f"Bad response for {content_id} (400), failed to parse error: {e}")

            response.raise_for_status()
            data = response.json()
            return data["entitlement_token"]

        except PlaybackRestrictedException:
            raise
        except JoynEntitlementError:
            raise
        except KeyError:
            raise JoynEntitlementError(f"No entitlement_token in response for {content_id}")
        except Exception as e:
            raise JoynEntitlementError(f"Error getting entitlement token for {content_id}: {e}")

    def get_channel_playlist(
        self,
        channel_id: str,
        entitlement_token: str,
        video_config: Optional[Dict] = None,
    ) -> Dict:
        video_payload = create_video_payload(video_config)
        signature = build_signature(entitlement_token, video_payload)

        url = JOYN_STREAMING_ENDPOINTS["PLAYLIST"].format(channel_id=channel_id)
        url += f"?signature={signature}"

        headers = JOYN_API_BASE_HEADERS.copy()
        headers["Authorization"] = f"Bearer {entitlement_token}"

        try:
            response = self.http_manager.post(
                url,
                operation="manifest",
                headers=headers,
                data=video_payload,
                timeout=DEFAULT_REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise JoynError(f"Error getting playlist for {channel_id}: {e}")

    def get_manifest(
        self,
        content_id: str,
        content_type: str = CONTENT_TYPE_LIVE,
        video_config: Optional[Dict] = None,
        **kwargs,
    ) -> Optional[str]:
        try:
            entitlement_token = self.get_entitlement_token(content_id=content_id, content_type=content_type)
            playlist_data = self.get_channel_playlist(content_id, entitlement_token, video_config)
            return playlist_data.get("manifestUrl")
        except Exception as e:
            logger.error(f"Error getting manifest for channel {content_id}: {e}")
            return None

    def get_manifest_headers(self, content_id: str, **kwargs) -> Dict[str, str]:
        return self.get_api_headers()

    def get_drm(
        self,
        content_id: str,
        content_type: str = CONTENT_TYPE_LIVE,
        video_config: Optional[Dict] = None,
        **kwargs,
    ) -> List[DRMConfig]:
        try:
            entitlement_token = self.get_entitlement_token(content_id=content_id, content_type=content_type)
            playlist_data = self.get_channel_playlist(content_id, entitlement_token, video_config)

            license_url = playlist_data.get("licenseUrl")
            if not license_url:
                return []

            drm_config = DRMConfig(
                system=DRMSystem.WIDEVINE,
                priority=1,
                license=LicenseConfig.create_with_req_data(
                    req_data_template="{CHA-RAW}",
                    server_url=license_url,
                    server_certificate=playlist_data.get("certificateUrl"),
                    req_headers=json.dumps({
                        "Authorization": f"Bearer {self.provider.bearer_token}",
                        "Content-Type": DRM_REQUEST_HEADERS["Content-Type"],
                        "User-Agent": JOYN_USER_AGENT,
                    }),
                    use_http_get_request=False,
                ),
            )
            return [drm_config]
        except Exception as e:
            logger.error(f"Error getting DRM configs for channel {content_id}: {e}")
            return []

    def enrich_channel_data(
        self,
        channel: StreamingChannel,
        video_config: Optional[Dict] = None,
        **kwargs,
    ) -> Optional[StreamingChannel]:
        try:
            content_type = kwargs.get("content_type", channel.content_type)
            entitlement_token = self.get_entitlement_token(content_id=channel.channel_id, content_type=content_type)
            playlist_data = self.get_channel_playlist(channel.channel_id, entitlement_token, video_config)

            manifest_url = playlist_data.get("manifestUrl")
            if not manifest_url:
                return None

            channel.manifest = manifest_url
            channel.streaming_format = playlist_data.get("streamingFormat", "dash")

            license_url = playlist_data.get("licenseUrl")
            if license_url:
                drm_config = DRMConfig(
                    system=DRMSystem.WIDEVINE,
                    priority=1,
                    license=LicenseConfig(
                        server_url=license_url,
                        server_certificate=playlist_data.get("certificateUrl"),
                        req_headers=json.dumps({
                            "User-Agent": JOYN_USER_AGENT,
                            "Content-Type": DRM_REQUEST_HEADERS["Content-Type"],
                        }),
                        req_data="{CHA-RAW}",
                        use_http_get_request=False,
                    ),
                )
                channel.drm_config = drm_config
                channel.cdm_type = DRM_SYSTEM_WIDEVINE
                channel.cdm = f"pid={channel.channel_id}"

            return channel
        except Exception as e:
            logger.error(f"Error enriching channel {channel.name}: {e}")
            return None

    def populate_streaming_data(
        self,
        channels: List[StreamingChannel],
        video_config: Optional[Dict] = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ) -> List[StreamingChannel]:
        successful_channels = []

        for channel in channels:
            retries = 0
            success = False
            is_restricted = False

            while retries < max_retries and not success and not is_restricted:
                try:
                    entitlement_token = self.get_entitlement_token(
                        content_id=channel.channel_id, content_type=channel.content_type
                    )
                    playlist_data = self.get_channel_playlist(
                        channel.channel_id, entitlement_token, video_config
                    )

                    manifest_url = playlist_data.get("manifestUrl")
                    if manifest_url:
                        channel.manifest = manifest_url
                        channel.cdm_type = DRM_SYSTEM_WIDEVINE
                        channel.cdm = f"pid={channel.channel_id}"
                        channel.license_url = playlist_data.get("licenseUrl")
                        channel.certificate_url = playlist_data.get("certificateUrl")
                        channel.streaming_format = playlist_data.get("streamingFormat", "dash")

                        successful_channels.append(channel)
                        success = True
                    else:
                        raise JoynError("No manifestUrl in response")
                except PlaybackRestrictedException as e:
                    logger.warning(f"Playback restricted for {channel.name}: {e}")
                    is_restricted = True
                except Exception as e:
                    retries += 1
                    if retries < max_retries:
                        time.sleep(1)
                    else:
                        logger.error(f"Failed to get streaming data for {channel.name}: {e}")

        logger.info(f"Streaming data population complete: {len(successful_channels)}/{len(channels)}")
        return successful_channels