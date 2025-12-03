# streaming_providers/providers/joyn/provider.py
# -*- coding: utf-8 -*-
from typing import Dict, Optional, List
import json
import time
import hashlib
import urllib.parse
from datetime import datetime, timedelta
from base64 import b64decode
from json import dumps

from ...base.provider import StreamingProvider, AuthType
from ...base.models import DRMConfig, LicenseConfig, DRMSystem
from ...base.models.streaming_channel import StreamingChannel
from ...base.models.proxy_models import ProxyConfig
from ...base.utils.logger import logger
from .models import JoynChannel, PlaybackRestrictedException
from .auth import JoynAuthenticator
from .constants import (
    SIGNATURE_SECRET_KEY,
    DEFAULT_VIDEO_CONFIG,
    COUNTRY_TENANT_MAPPING,
    SUPPORTED_COUNTRIES,
    JOYN_GRAPHQL_ENDPOINTS,
    JOYN_GRAPHQL_BASE_HEADERS,
    JOYN_STREAMING_ENDPOINTS,
    JOYN_CLIENT_VERSION,
    DEFAULT_PLATFORM,
    JOYN_USER_AGENT,
    JOYN_API_BASE_HEADERS,
    JOYN_DOMAINS,
    ERROR_CODES,
    CONTENT_TYPE_LIVE,
    CONTENT_TYPE_VOD,
    DEFAULT_LIVESTREAM_TYPES,
    MODE_LIVE,
    MODE_VOD,
    DRM_SYSTEM_WIDEVINE,
    DRM_REQUEST_HEADERS,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_MAX_RETRIES,
    DEFAULT_EPG_WINDOW_HOURS,
    GRAPHQL_PERSISTED_QUERY_VERSION,
    GRAPHQL_LIVE_CHANNELS_FILTER,
    GRAPHQL_MAX_RESULTS,
    GRAPHQL_OFFSET,
    GRAPHQL_QUERY_HASHES,
    JOYN_LOGO
)


def create_video_payload(config: Optional[Dict] = None, compact: bool = True) -> str:
    """Create video data payload for requests"""
    video_config = config or DEFAULT_VIDEO_CONFIG
    payload = dumps(video_config)
    return payload.replace(' ', '') if compact else payload


def build_signature(entitlement_token: str, video_payload: Optional[str] = None,
                    secret_key: Optional[str] = None) -> str:
    """Build signature for video data requests"""
    if video_payload is None:
        video_payload = create_video_payload()

    if secret_key is None:
        secret_key = b64decode(SIGNATURE_SECRET_KEY).decode('utf-8')

    signature_input = f"{video_payload},{entitlement_token}{secret_key}"
    return hashlib.sha1(signature_input.encode('utf-8')).hexdigest()


class JoynProvider(StreamingProvider):
    """
    Joyn streaming provider implementation with centralized HTTP management
    """

    def __init__(self, country: str = 'de',
                 platform: str = DEFAULT_PLATFORM,
                 config_dir: Optional[str] = None,
                 proxy_config: Optional[ProxyConfig] = None,
                 proxy_url: Optional[str] = None):
        """
        Initialize Joyn provider

        Args:
            country: Country code ('de', 'at', 'ch')
            platform: Platform identifier
            config_dir: Optional config directory override
            proxy_config: Optional proxy configuration (highest priority)
            proxy_url: Optional proxy URL string (medium priority)
        """
        super().__init__(country=country)

        if country not in SUPPORTED_COUNTRIES:
            raise ValueError(f"Unsupported country: {country}. Must be one of: {SUPPORTED_COUNTRIES}")

        self.distribution_tenant = COUNTRY_TENANT_MAPPING[country]
        self.platform = platform

        # ✅ BEFORE: Manual proxy resolution and HTTP manager setup (15 lines)
        # self.proxy_config = (
        #     proxy_config or
        #     (ProxyConfig.from_url(proxy_url) if proxy_url else None) or
        #     self._load_proxy_from_manager(config_dir)
        # )
        #
        # if self.proxy_config:
        #     logger.info("Using proxy configuration for Joyn")
        # else:
        #     logger.debug("No proxy configuration found for Joyn")
        #
        # self.http_manager = HTTPManagerFactory.create_for_provider(
        #     provider_name='joyn',
        #     proxy_config=self.proxy_config,
        #     user_agent=JOYN_USER_AGENT,
        #     timeout=DEFAULT_REQUEST_TIMEOUT,
        #     max_retries=DEFAULT_MAX_RETRIES
        # )

        # ✅ AFTER: Using abstraction (6 lines)
        self.http_manager = self._setup_http_manager(
            provider_name='joyn',
            proxy_config=proxy_config,
            proxy_url=proxy_url,
            config_dir=config_dir,
            user_agent=JOYN_USER_AGENT,
            timeout=DEFAULT_REQUEST_TIMEOUT,
            max_retries=DEFAULT_MAX_RETRIES
        )

        # Create authenticator with shared HTTP manager
        self.authenticator = JoynAuthenticator(
            country=country,
            platform=platform,
            config_dir=config_dir,
            http_manager=self.http_manager,
            proxy_config=self.http_manager.config.proxy_config  # Use resolved proxy
        )

        # ✅ Optional: Share HTTP manager (if authenticator might have its own)
        # self.http_manager = self._share_http_manager_with_authenticator(self.authenticator)

        # Authenticate
        try:
            self.bearer_token = self.authenticator.get_bearer_token()
        except Exception as e:
            logger.warning(f"Could not authenticate during initialization: {e}")
            self.bearer_token = None

    # ✅ BEFORE: Had to implement this helper method (12 lines)
    # def _load_proxy_from_manager(self, config_dir: Optional[str]) -> Optional[ProxyConfig]:
    #     """Load proxy configuration from ProxyConfigManager"""
    #     try:
    #         proxy_manager = ProxyConfigManager(config_dir)
    #         return proxy_manager.get_proxy_config('joyn', self.country)
    #     except Exception as e:
    #         logger.warning(f"Could not load proxy from ProxyConfigManager: {e}")
    #         return None

    # ✅ AFTER: No longer needed - handled by abstraction!

    @property
    def provider_name(self) -> str:
        return 'joyn'

    @property
    def provider_label(self) -> str:
        return f'Joyn ({self.country})'

    @property
    def provider_logo(self) -> str:
        return JOYN_LOGO

    @property
    def uses_dynamic_manifests(self) -> bool:
        return False

    @property
    def implements_epg(self) -> bool:
        return False

    def authenticate(self, **kwargs) -> str:
        """Authenticate and return bearer token"""
        self.bearer_token = self.authenticator.get_bearer_token(
            force_refresh=kwargs.get('force_refresh', False)
        )
        return self.bearer_token

    def get_dynamic_manifest_params(self, channel: StreamingChannel, **kwargs) -> Optional[str]:
        return None

    def _get_graphql_headers(self) -> Dict[str, str]:
        """Get headers for GraphQL requests"""
        return self._build_provider_headers(
            base_headers=JOYN_GRAPHQL_BASE_HEADERS,
            auth_type=AuthType.NONE,  # GraphQL queries don't need auth
            provider_headers={
                'joyn-client-version': JOYN_CLIENT_VERSION,
                'joyn-country': self.country.upper(),
                'joyn-distribution-tenant': self.distribution_tenant,
                'joyn-platform': self.platform,
                'joyn-user-state': 'code=R_A'
            }
        )

    def refresh_authentication(self) -> str:
        """Force refresh authentication"""
        self.bearer_token = self.authenticator.get_bearer_token(force_refresh=True)
        return self.bearer_token

    def get_channels(self,
                       time_window_hours: int = DEFAULT_EPG_WINDOW_HOURS,
                       fetch_manifests: bool = False,
                       populate_streaming_data: bool = True,
                       **kwargs) -> List[StreamingChannel]:
        """
        Fetch available channels from Joyn GraphQL API

        Args:
            time_window_hours: EPG time window in hours
            fetch_manifests: Whether to immediately populate streaming data
            populate_streaming_data: Whether to populate streaming data when fetch_manifests is True
            **kwargs: Additional parameters

        Returns:
            List of StreamingChannel objects
        """
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
                "to": end_time
            }

            variables_encoded = urllib.parse.quote(json.dumps(variables))
            extensions = {
                "persistedQuery": {
                    "version": GRAPHQL_PERSISTED_QUERY_VERSION,
                    "sha256Hash": GRAPHQL_QUERY_HASHES['LIVE_CHANNELS']
                }
            }
            extensions_encoded = urllib.parse.quote(json.dumps(extensions))

            url = f"{JOYN_GRAPHQL_ENDPOINTS['LIVE_CHANNELS']}&variables={variables_encoded}&extensions={extensions_encoded}"

            # ✅ Already using http_manager correctly
            response = self.http_manager.get(
                url,
                operation='api',
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            channel_data = response.json()

            channels = self._process_graphql_response(channel_data)

            # Populate streaming data immediately after fetching channels
            if fetch_manifests and populate_streaming_data:
                channels = self.populate_streaming_data(channels)

            logger.info(f"Successfully fetched {len(channels)} channels for country {self.country}")
            return channels

        except Exception as e:
            raise Exception(f"Error fetching channels from GraphQL: {e}")

    def _process_graphql_response(self, response_data: Dict) -> List[StreamingChannel]:
        """Process GraphQL response and convert to StreamingChannel objects"""
        if 'data' not in response_data or 'liveStreams' not in response_data['data']:
            raise Exception("Invalid GraphQL response structure")

        live_streams = response_data['data']['liveStreams']
        channels = []

        for stream_data in live_streams:
            try:
                channel_id = stream_data.get('id', '')
                title = stream_data.get('title', 'Unknown Channel')
                stream_type = stream_data.get('type', 'LINEAR')
                quality = stream_data.get('quality', '')

                logo_url = None
                if 'logo' in stream_data and 'url' in stream_data['logo']:
                    logo_url = stream_data['logo']['url']

                content_type = CONTENT_TYPE_LIVE if stream_type == 'LINEAR' else CONTENT_TYPE_VOD
                mode = MODE_LIVE if stream_type == 'LINEAR' else MODE_VOD

                joyn_channel = JoynChannel(
                    name=title,
                    channel_id=channel_id,
                    logo_url=logo_url,
                    mode=mode,
                    content_type=content_type,
                    country=self.country,
                    raw_data=stream_data
                )

                if quality:
                    joyn_channel.name = f"{title} ({quality})"

                if 'brand' in stream_data:
                    brand_data = stream_data['brand']
                    if 'brand_id' in brand_data:
                        joyn_channel.raw_data['brand_id'] = brand_data['brand_id']

                if stream_data.get('eventStream', False):
                    joyn_channel.raw_data['is_event_stream'] = True

                streaming_channel = joyn_channel.to_streaming_channel(
                    provider_name=self.provider_name
                )
                channels.append(streaming_channel)

            except Exception as e:
                logger.warning(f"Error processing channel data: {e}")

        return channels

    def get_entitlement_token(self, content_id: str, content_type: str = CONTENT_TYPE_LIVE) -> str:
        """
        Get entitlement token for content

        Args:
            content_id: Content ID
            content_type: Content type ('LIVE' or 'VOD')

        Returns:
            Entitlement token string
        """
        headers = self._build_provider_headers(
            base_headers=JOYN_API_BASE_HEADERS,
            auth_type=AuthType.BEARER,
            provider_headers={
                'joyn-client-version': JOYN_CLIENT_VERSION,
                'joyn-country': self.country.upper(),
                'joyn-distribution-tenant': self.distribution_tenant,
                'joyn-platform': self.platform,
                'joyn-b2b-context': 'UNKNOWN',
                'joyn-client-os': 'UNKNOWN',
                'origin': JOYN_DOMAINS.get(self.country, JOYN_DOMAINS['de'])
            }
        )

        payload = {
            "content_id": content_id,
            "content_type": content_type
        }

        try:
            # ✅ Already using http_manager correctly
            response = self.http_manager.post(
                JOYN_STREAMING_ENDPOINTS['ENTITLEMENT'],
                operation='auth',
                headers=headers,
                json_data=payload,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )

            if response.status_code == 400:
                try:
                    error_data = response.json()
                    if isinstance(error_data, list) and len(error_data) > 0:
                        error = error_data[0]
                        code = error.get("code", "UNKNOWN")
                        msg = error.get("msg", "No error message provided")
                        if code == ERROR_CODES['PLAYBACK_RESTRICTED']:
                            raise PlaybackRestrictedException(f"Playback restricted for {content_id}: {msg}")
                        else:
                            raise Exception(f"Entitlement error for {content_id} ({code}): {msg}")
                except (json.JSONDecodeError, KeyError, IndexError) as e:
                    raise Exception(f"Bad response for {content_id} (400), failed to parse error: {e}")

            response.raise_for_status()
            data = response.json()
            return data['entitlement_token']

        except PlaybackRestrictedException:
            raise
        except KeyError:
            raise Exception(f"No entitlement_token in response for {content_id}")
        except Exception as e:
            raise Exception(f"Error getting entitlement token for {content_id}: {e}")

    def get_channel_playlist(self, channel_id: str, entitlement_token: str,
                             video_config: Optional[Dict] = None) -> Dict:
        """
        Get channel playlist data

        Args:
            channel_id: Channel ID
            entitlement_token: Entitlement token
            video_config: Optional video configuration override

        Returns:
            Playlist data dictionary
        """
        video_payload = create_video_payload(video_config)
        signature = build_signature(entitlement_token, video_payload)

        url = JOYN_STREAMING_ENDPOINTS['PLAYLIST'].format(channel_id=channel_id)
        url += f"?signature={signature}"

        headers = JOYN_API_BASE_HEADERS.copy()
        headers['Authorization'] = f'Bearer {entitlement_token}'

        try:
            # ✅ Already using http_manager correctly
            response = self.http_manager.post(
                url,
                operation='manifest',
                headers=headers,
                data=video_payload,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()
            return response.json()

        except Exception as e:
            raise Exception(f"Error getting playlist for {channel_id}: {e}")

    def populate_streaming_data(self, channels: List[StreamingChannel],
                                video_config: Optional[Dict] = None,
                                max_retries: int = DEFAULT_MAX_RETRIES) -> List[StreamingChannel]:
        """
        Populate streaming data (manifest, DRM) for all channels

        Args:
            channels: List of channels to populate
            video_config: Optional video configuration
            max_retries: Maximum retry attempts per channel

        Returns:
            List of successfully populated channels
        """
        successful_channels = []

        for channel in channels:
            retries = 0
            success = False
            is_restricted = False

            while retries < max_retries and not success and not is_restricted:
                try:
                    logger.debug(f"Getting entitlement token for: {channel.name} (attempt {retries + 1})")

                    entitlement_token = self.get_entitlement_token(
                        content_id=channel.channel_id,
                        content_type=channel.content_type
                    )

                    logger.debug(f"Getting playlist data for: {channel.name}")

                    playlist_data = self.get_channel_playlist(
                        channel.channel_id,
                        entitlement_token,
                        video_config
                    )

                    manifest_url = playlist_data.get('manifestUrl')
                    license_url = playlist_data.get('licenseUrl')
                    certificate_url = playlist_data.get('certificateUrl')
                    streaming_format = playlist_data.get('streamingFormat', 'dash')

                    if manifest_url:
                        channel.manifest = manifest_url
                        channel.cdm_type = DRM_SYSTEM_WIDEVINE
                        channel.cdm = f"pid={channel.channel_id}"
                        channel.license_url = license_url
                        channel.certificate_url = certificate_url
                        channel.streaming_format = streaming_format

                        logger.info(f"Streaming data populated for: {channel.name}")
                        successful_channels.append(channel)
                        success = True
                    else:
                        raise Exception("No manifestUrl in response")

                except PlaybackRestrictedException as e:
                    logger.warning(f"Playback restricted for {channel.name}: {e}")
                    is_restricted = True

                except Exception as e:
                    retries += 1
                    if retries < max_retries:
                        logger.debug(f"Retry {retries}/{max_retries} for {channel.name}: {e}")
                        time.sleep(1)
                    else:
                        logger.error(f"Failed to get streaming data for {channel.name}: {e}")

        logger.info(f"Streaming data population complete:")
        logger.info(f"  Successful: {len(successful_channels)}")
        logger.info(f"  Restricted: {len([c for c in channels if c not in successful_channels])}")
        logger.info(f"  Total: {len(channels)}")

        return successful_channels

    def enrich_channel_data(self,
                            channel: StreamingChannel,
                            video_config: Optional[Dict] = None,
                            **kwargs) -> Optional[StreamingChannel]:
        """
        Get manifest URL for a specific channel and properly configure DRM

        Args:
            channel: StreamingChannel to enrich
            video_config: Optional video configuration dictionary
            **kwargs: Additional parameters

        Returns:
            The enriched StreamingChannel with manifest and proper DRM config, or None if failed
        """
        try:
            entitlement_token = self.get_entitlement_token(
                content_id=channel.channel_id,
                content_type=channel.content_type
            )

            playlist_data = self.get_channel_playlist(
                channel.channel_id,
                entitlement_token,
                video_config
            )

            manifest_url = playlist_data.get('manifestUrl')
            if not manifest_url:
                return None

            channel.manifest = manifest_url
            channel.streaming_format = playlist_data.get('streamingFormat', 'dash')

            license_url = playlist_data.get('licenseUrl')
            if license_url:
                drm_config = DRMConfig(
                    system=DRMSystem.WIDEVINE,
                    priority=1,
                    license=LicenseConfig(
                        server_url=license_url,
                        server_certificate=playlist_data.get('certificateUrl'),
                        req_headers=json.dumps({
                            'User-Agent': JOYN_USER_AGENT,
                            'Content-Type': DRM_REQUEST_HEADERS['Content-Type']
                        }),
                        req_data="{CHA-RAW}",
                        use_http_get_request=False
                    )
                )
                channel.drm_config = drm_config
                channel.cdm_type = DRM_SYSTEM_WIDEVINE
                channel.cdm = f"pid={channel.channel_id}"

            return channel

        except Exception as e:
            logger.error(f"Error getting manifest for {channel.name}: {e}")
            return None

    def get_manifest(self,
                     channel_id: str,
                     content_type: str = CONTENT_TYPE_LIVE,
                     video_config: Optional[Dict] = None,
                     **kwargs) -> Optional[str]:
        """
        Get manifest URL for a specific channel by ID

        Args:
            channel_id: ID of the channel to get manifest for
            content_type: Content type ('LIVE' or 'VOD')
            video_config: Optional video configuration dictionary
            **kwargs: Additional parameters

        Returns:
            Manifest URL string, or None if not available
        """
        try:
            entitlement_token = self.get_entitlement_token(
                content_id=channel_id,
                content_type=content_type
            )

            playlist_data = self.get_channel_playlist(
                channel_id,
                entitlement_token,
                video_config
            )

            return playlist_data.get('manifestUrl')

        except Exception as e:
            logger.error(f"Error getting manifest for channel {channel_id}: {e}")
            return None

    def get_drm(self,
                channel_id: str,
                content_type: str = CONTENT_TYPE_LIVE,
                video_config: Optional[Dict] = None,
                **kwargs) -> List[DRMConfig]:
        """
        Get all DRM configurations for a channel by ID

        Args:
            channel_id: ID of the channel to get DRM configs
            content_type: Content type ('LIVE' or 'VOD')
            video_config: Optional video configuration dictionary
            **kwargs: Additional parameters

        Returns:
            List of DRMConfig objects (can be empty if no DRM is used)
        """
        try:
            entitlement_token = self.get_entitlement_token(
                content_id=channel_id,
                content_type=content_type
            )

            playlist_data = self.get_channel_playlist(
                channel_id,
                entitlement_token,
                video_config
            )

            license_url = playlist_data.get('licenseUrl')
            if not license_url:
                return []

            drm_config = DRMConfig(
                system=DRMSystem.WIDEVINE,
                priority=1,
                license=LicenseConfig.create_with_base64_req_data(
                    req_data_template="{CHA-RAW}",
                    server_url=license_url,
                    server_certificate=playlist_data.get('certificateUrl'),
                    req_headers=json.dumps({
                        'Authorization': f'Bearer {self.bearer_token}',
                        'Content-Type': DRM_REQUEST_HEADERS['Content-Type'],
                        'User-Agent': JOYN_USER_AGENT
                    }),
                    use_http_get_request=False
                )
            )

            return [drm_config]

        except Exception as e:
            logger.error(f"Error getting DRM configs for channel {channel_id}: {e}")
            return []

    def get_epg(self,
                channel_id: str,
                start_time: Optional[datetime] = None,
                end_time: Optional[datetime] = None,
                **kwargs) -> List[Dict]:
        """
        Get EPG data for a channel

        Args:
            channel_id: Channel ID to get EPG for
            start_time: Optional start time for EPG window
            end_time: Optional end time for EPG window
            **kwargs: Additional parameters

        Returns:
            List of EPG entries
        """
        try:
            if start_time is None:
                start_time = datetime.now()
            if end_time is None:
                end_time = datetime.now() + timedelta(hours=DEFAULT_EPG_WINDOW_HOURS)

            headers = self._get_graphql_headers()

            # Joyn EPG would require additional GraphQL queries
            logger.info(f"EPG data requested for channel {channel_id} - not yet implemented")
            return []

        except Exception as e:
            logger.error(f"Error getting EPG for channel {channel_id}: {e}")
            return []