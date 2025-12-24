# lib/streaming_providers/providers/rtlplus/provider.py
import json
from typing import Dict, List, Optional, ClassVar

import requests
from ...base.provider import StreamingProvider
from ...base.models.streaming_channel import StreamingChannel
from ...base.models import DRMConfig, LicenseConfig, DRMSystem
from .auth import RTLPlusAuthenticator
from .constants import RTLPlusDefaults, RTLPlusConfig
from ...base.utils import logger
from ...base.models.proxy_models import ProxyConfig


class RTLPlusProvider(StreamingProvider):
    # Provider constants
    PROVIDER_LABEL: ClassVar[str] = "RTL+"
    PROVIDER_LOGO: ClassVar[str] = RTLPlusDefaults.RTLPLUS_LOGO

    def __init__(self, country: str = 'DE', config: Optional[Dict] = None,
                 proxy_config: Optional[ProxyConfig] = None):
        super().__init__(country)

        # Initialize configuration
        self.rtl_config = RTLPlusConfig(config)
        self.channels_query_params = RTLPlusDefaults.CHANNELS_QUERY_PARAMS

        # ✅ Using HTTP manager abstraction
        self.http_manager = self._setup_http_manager(
            provider_name='rtlplus',
            proxy_config=proxy_config,
            user_agent=self.rtl_config.user_agent,
            timeout=self.rtl_config.timeout
        )

        # Initialize authenticator
        self.authenticator = RTLPlusAuthenticator(
            client_version=self.rtl_config.client_version,
            device_id=self.rtl_config.device_id,
            proxy_config=proxy_config,
            http_manager=self.http_manager
        )

        # ✅ Share HTTP manager with authenticator
        self.http_manager = self._share_http_manager_with_authenticator(self.authenticator)

        # Try authentication
        try:
            self.bearer_token = self.authenticator.get_bearer_token()
            logger.debug(f"RTL+ authentication successful during initialization")
        except Exception as e:
            logger.warning(f"RTL+ could not authenticate during initialization: {e}")
            self.bearer_token = None

    @property
    def provider_name(self) -> str:
        return "rtlplus"

    @property
    def provider_label(self) -> str:
        return 'RTL+'

    @property
    def provider_logo(self) -> str:
        return self.PROVIDER_LOGO

    @property
    def uses_dynamic_manifests(self) -> bool:
        # RTL+ provides relatively stable manifest URLs that can be fetched and cached
        return False

    @property
    def implements_epg(self) -> bool:
        return False

    @property
    def supported_auth_types(self) -> List[str]:
        return ['user_credentials']

    # ============================================================================
    # OPTION 1: Provider-specific method (RECOMMENDED - No signature conflict)
    # ============================================================================
    def _get_rtlplus_authenticated_headers(self) -> Dict[str, str]:
        """
        Get headers with authentication and RTL+ specific headers

        This will automatically upgrade from anonymous to user token if possible
        """
        bearer_token = self.authenticator.get_bearer_token(force_upgrade=True)
        return self.rtl_config.get_api_headers(access_token=bearer_token)

    def get_channels(self, **kwargs) -> List[StreamingChannel]:
        """
        Fetch channels from RTL+ GraphQL API with authentication
        """
        try:
            # ✅ Use provider-specific method
            headers = self._get_rtlplus_authenticated_headers()

            response = self.http_manager.get(
                self.rtl_config.graphql_endpoint,
                operation='api',
                params=self.channels_query_params,
                headers=headers
            )
            response.raise_for_status()
            data = response.json()

            channels = []
            if 'data' in data and 'liveTvStations' in data['data']:
                for station in data['data']['liveTvStations']:
                    channel = self._parse_station_to_channel(station)
                    if channel:
                        channels.append(channel)

            self.channels = channels
            return channels

        except requests.RequestException as e:
            logger.error(f"Error fetching RTL+ channels: {e}")
            # Try to refresh auth token and retry once
            try:
                logger.info("Attempting to refresh authentication and retry...")
                self.authenticator.invalidate_token()
                headers = self._get_rtlplus_authenticated_headers()

                response = self.http_manager.get(
                    self.rtl_config.graphql_endpoint,
                    operation='api',
                    params=self.channels_query_params,
                    headers=headers
                )
                response.raise_for_status()
                data = response.json()

                channels = []
                if 'data' in data and 'liveTvStations' in data['data']:
                    for station in data['data']['liveTvStations']:
                        channel = self._parse_station_to_channel(station)
                        if channel:
                            channels.append(channel)

                self.channels = channels
                return channels
            except Exception as retry_e:
                logger.error(f"Retry failed: {retry_e}")
                return []
        except Exception as e:
            logger.error(f"Error parsing RTL+ channels: {e}")
            return []

    def _parse_station_to_channel(self, station: Dict) -> Optional[StreamingChannel]:
        """
        Parse a station object from RTL+ API to StreamingChannel
        """
        try:
            # Extract basic info
            name = station.get('name', '')
            channel_id = station.get('id', '')

            if not name or not channel_id:
                return None

            # Extract logo URL
            logo_url = None
            if 'images' in station and 'alternativeLandscapeUri' in station['images']:
                logo_url = station['images']['alternativeLandscapeUri']

            # Determine if premium channel
            is_premium = station.get('isPremium', False)

            # Extract watch path for potential manifest fetching
            watch_path = None
            if 'urlData' in station and 'watchPath' in station['urlData']:
                watch_path = station['urlData']['watchPath']

            # Create channel object
            channel = StreamingChannel(
                name=name,
                channel_id=channel_id,
                provider=self.provider_name,
                logo_url=logo_url,
                mode="live",
                session_manifest=True,  # RTL+ uses dynamic manifests
                manifest=None,  # Will be set dynamically
                manifest_script=watch_path,  # Store watch path for manifest fetching
                content_type="LIVE",
                country=self.country,
                language="de"
            )

            # Set CDM settings for premium channels
            if is_premium:
                channel.use_cdm = True
                channel.cdm_type = "widevine"

            return channel

        except Exception as e:
            logger.warning(f"Error parsing station {station}: {e}")
            return None

    def enrich_channel_data(self, channel: StreamingChannel, **kwargs) -> Optional[StreamingChannel]:
        """
        Enrich channel with manifest URL and additional data
        """
        try:
            # Fetch manifest URL for this channel
            manifest_url = self.get_manifest(channel.channel_id, **kwargs)

            if manifest_url:
                # Set the manifest URL - RTL+ provides relatively stable URLs
                channel.set_static_manifest(manifest_url)

                # Check if this channel has DRM
                drm_configs = self.get_drm(channel.channel_id, **kwargs)
                if drm_configs:
                    # Set DRM configuration
                    channel.use_cdm = True
                    channel.cdm_type = "widevine"  # Default to Widevine

                    # Set license URL from first Widevine config
                    for config in drm_configs:
                        if config.system == DRMSystem.WIDEVINE:
                            channel.license_url = config.license.server_url
                            break
                else:
                    channel.use_cdm = False
                    channel.cdm_type = None

                return channel
            else:
                logger.warning(f"Could not fetch manifest for channel {channel.name} ({channel.channel_id})")
                return channel

        except Exception as e:
            logger.error(f"Error enriching channel data for {channel.name}: {e}")
            return channel

    def get_manifest(self, channel_id: str, **kwargs) -> Optional[str]:
        manifest_url = self.rtl_config.get_manifest_url(channel_id)

        try:
            logger.debug(f"RTL+ Manifest Request: GET {manifest_url}")

            headers = self.rtl_config.get_base_headers()
            response = self.http_manager.get(
                manifest_url,
                operation='manifest',
                headers=headers
            )

            logger.debug(f"RTL+ Manifest Response: Status={response.status_code}")
            logger.debug(f"RTL+ Response Headers: {dict(response.headers)}")

            response.raise_for_status()
            manifest_data = response.json()

            logger.debug(f"RTL+ Manifest Data: {self._sanitize_manifest_log(manifest_data)}")

            # Process manifest data
            quality_preference = ['dashhd', 'dashsd']

            for quality in quality_preference:
                for stream in manifest_data:
                    if stream.get('name') == quality:
                        sources = stream.get('sources', [])
                        non_yospace_sources = [s for s in sources if not s.get('isYospace', False)]

                        if non_yospace_sources:
                            selected_url = non_yospace_sources[0].get('url')
                            logger.info(f"RTL+ Selected Manifest URL: {selected_url}")
                            return selected_url

            # Fallback logic
            for stream in manifest_data:
                sources = stream.get('sources', [])
                if sources:
                    fallback_url = sources[0].get('url')
                    logger.info(f"RTL+ Using Fallback Manifest URL: {fallback_url}")
                    return fallback_url

            logger.warning("RTL+ No valid manifest URL found in response")
            return None

        except requests.RequestException as e:
            logger.error(f"RTL+ Manifest HTTP Error: {str(e)}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"RTL+ Manifest JSON Parse Error: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"RTL+ Manifest Unexpected Error: {str(e)}")
            return None

    @staticmethod
    def _sanitize_manifest_log(manifest_data: Dict) -> Dict:
        """
        Sanitize manifest data for logging (remove sensitive information)
        """
        try:
            # Create a copy to avoid modifying original
            sanitized = manifest_data.copy()

            # Remove or truncate potentially sensitive URLs
            if isinstance(sanitized, list):
                for stream in sanitized:
                    if isinstance(stream, dict):
                        if 'sources' in stream:
                            for source in stream['sources']:
                                if 'url' in source:
                                    # Truncate long URLs for logging
                                    url = source['url']
                                    if len(url) > 100:
                                        source['url'] = url[:100] + '...'
            return sanitized
        except Exception:
            return manifest_data

    def get_drm(self, channel_id: str, **kwargs) -> List[DRMConfig]:
        """
        Get DRM configurations for a channel from RTL+ streaming API
        """
        try:
            # Fetch manifest data to get license information
            manifest_url = self.rtl_config.get_manifest_url(channel_id)

            response = self.http_manager.get(
                manifest_url,
                operation='manifest'
            )
            response.raise_for_status()
            manifest_data = response.json()

            drm_configs = []

            # Get access token for license requests
            access_token = self.authenticator.get_bearer_token()

            # Look for dashhd streams (preferred quality) and extract DRM info
            for stream in manifest_data:
                if stream.get('name') == 'dashhd' and 'licenses' in stream:
                    licenses = stream.get('licenses', [])

                    for license_info in licenses:
                        license_url = license_info.get('uri', {}).get('href')
                        if not license_url:
                            continue

                        def create_drm_config(drm_system, priority, server_url, headers):
                            return DRMConfig(
                                system=drm_system,
                                priority=priority,
                                license=LicenseConfig(
                                    server_url=server_url,
                                    req_headers=json.dumps(headers),
                                    req_data="{CHA-RAW}",
                                    use_http_get_request=False
                                )
                            )

                        if license_info.get('type') == 'WIDEVINE':
                            drm_configs.append(create_drm_config(
                                DRMSystem.WIDEVINE, 1, license_url,
                                self.rtl_config.get_drm_headers(access_token)
                            ))
                        elif license_info.get('type') == 'PLAYREADY':
                            drm_configs.append(create_drm_config(
                                DRMSystem.PLAYREADY, 2, license_url,
                                self.rtl_config.get_drm_headers(access_token)
                            ))
                        elif license_info.get('type') == 'FAIRPLAY':
                            drm_configs.append(create_drm_config(
                                DRMSystem.FAIRPLAY, 3, license_url,
                                self.rtl_config.get_drm_headers(access_token)
                            ))
                    break

            return drm_configs

        except requests.RequestException as e:
            logger.error(f"Error fetching DRM configs for RTL+ channel {channel_id}: {e}")
            return []
        except Exception as e:
            logger.error(f"Error parsing DRM configs for RTL+ channel {channel_id}: {e}")
            return []

    @staticmethod
    def get_epg_data(channel_id: str, **kwargs) -> Optional[Dict]:
        """
        Get EPG data for a channel
        """
        # RTL+ EPG implementation would go here
        # This is a placeholder for future implementation
        return None

    def get_license_url(self, channel: StreamingChannel, **kwargs) -> Optional[str]:
        """
        Get license URL for a DRM-protected channel
        """
        drm_configs = self.get_drm(channel.channel_id, **kwargs)
        if drm_configs:
            # Return the first license URL found
            return drm_configs[0].license.server_url
        return None