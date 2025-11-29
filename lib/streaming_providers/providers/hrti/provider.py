# [file name]: provider.py
# [file content begin]
# lib/streaming_providers/providers/hrti/provider.py
import json
import requests
from typing import Dict, List, Optional

from ...base.provider import StreamingProvider
from ...base.models.streaming_channel import StreamingChannel
from ...base.models import DRMConfig, LicenseConfig, DRMSystem
from .auth import HRTiAuthenticator
from .constants import HRTiConfig
from ...base.utils import logger
from ...base.models.proxy_models import ProxyConfig
from ...base.network import HTTPManagerFactory


class HRTiProvider(StreamingProvider):
    def __init__(self, country: str = 'HR', config: Optional[Dict] = None, proxy_config: Optional[ProxyConfig] = None):
        super().__init__(country)

        # Initialize configuration with overrides
        self.hrti_config = HRTiConfig(config)
        self.channels_cache = None

        # Create HTTP manager
        if proxy_config is None:
            from ...base.network import ProxyConfigManager
            proxy_mgr = ProxyConfigManager()
            proxy_config = proxy_mgr.get_proxy_config('hrti')

        self.http_manager = HTTPManagerFactory.create_for_provider(
            'hrti',
            proxy_config=proxy_config,
            user_agent=self.hrti_config.user_agent,
            timeout=self.hrti_config.timeout
        )

        # Initialize authenticator and share HTTP manager
        self.auth = HRTiAuthenticator(
            proxy_config=proxy_config,
            http_manager=self.http_manager
        )

        # Share HTTP manager for consistency
        self.http_manager = self.auth.http_manager

        try:
            # Initialize authentication
            bearer_token = self.auth.get_bearer_token()
            logger.debug(f"HRTi authentication successful during initialization")
        except Exception as e:
            logger.warning(f"HRTi could not authenticate during initialization: {e}")

    @property
    def provider_name(self) -> str:
        return "hrti"

    @property
    def provider_label(self) -> str:
        return 'HRTi'

    @property
    def provider_logo(self) -> str:
        return self.hrti_config.logo

    @property
    def uses_dynamic_manifests(self) -> bool:
        # HRTi requires session authorization for manifests
        return True

    def _get_authenticated_headers(self) -> Dict[str, str]:
        """
        Get headers with HRTi authentication for API requests
        """
        bearer_token = self.auth.get_bearer_token()
        device_id = self.auth.get_device_id()
        ip_address = self.auth.get_ip_address()

        headers = {
            'User-Agent': self.hrti_config.user_agent,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'deviceid': device_id,
            'devicetypeid': self.hrti_config.device_reference_id,
            'host': 'hrti.hrt.hr',
            'ipaddress': ip_address,
            'operatorreferenceid': self.hrti_config.operator_reference_id,
            'origin': self.hrti_config.base_website,
            'referer': self.hrti_config.base_website
        }

        if bearer_token:
            headers['authorization'] = f'Client {bearer_token}'

        return headers

    def get_channels(self, **kwargs) -> List[StreamingChannel]:
        """
        Fetch channels from HRTi API
        """
        try:
            headers = self._get_authenticated_headers()

            response = self.http_manager.post(
                self.hrti_config.api_endpoints['channels'],
                operation='api',
                headers=headers,
                data=json.dumps({})
            )
            response.raise_for_status()

            channels_data = response.json()
            if 'Result' in channels_data:
                channels = []
                for channel in channels_data['Result']:
                    streaming_channel = self._parse_channel_data(channel)
                    if streaming_channel:
                        channels.append(streaming_channel)

                self.channels = channels
                return channels
            else:
                logger.warning("No channels found in HRTi response")
                return []

        except requests.RequestException as e:
            logger.error(f"Error fetching HRTi channels: {e}")
            # Try to refresh auth and retry once
            try:
                logger.info("Attempting to refresh authentication and retry...")
                self.auth.invalidate_token()
                headers = self._get_authenticated_headers()

                response = self.http_manager.post(
                    self.hrti_config.api_endpoints['channels'],
                    operation='api',
                    headers=headers,
                    data=json.dumps({})
                )
                response.raise_for_status()

                channels_data = response.json()
                if 'Result' in channels_data:
                    channels = []
                    for channel in channels_data['Result']:
                        streaming_channel = self._parse_channel_data(channel)
                        if streaming_channel:
                            channels.append(streaming_channel)

                    self.channels = channels
                    return channels

            except Exception as retry_e:
                logger.error(f"Retry failed: {retry_e}")
                return []

        except Exception as e:
            logger.error(f"Error parsing HRTi channels: {e}")
            return []

    def _parse_channel_data(self, channel_data: Dict) -> Optional[StreamingChannel]:
        """
        Parse HRTi channel data to StreamingChannel
        """
        try:
            name = channel_data.get('Name', '')
            channel_id = channel_data.get('ReferenceId', '')
            streaming_url = channel_data.get('StreamingURL', '')
            is_radio = channel_data.get('Radio', False)
            icon_url = channel_data.get('Icon', '')

            if not name or not channel_id:
                return None

            # Create channel object
            channel = StreamingChannel(
                name=name,
                channel_id=channel_id,
                provider=self.provider_name,
                logo_url=icon_url,
                mode="live",
                session_manifest=True,  # HRTi requires session authorization
                manifest=None,  # Will be set dynamically
                manifest_script=streaming_url,  # Store streaming URL for manifest fetching
                content_type="AUDIO" if is_radio else "LIVE",
                country=self.country,
                language="hr"  # Croatian
            )

            # HRTi uses DRM for most content
            channel.use_cdm = True
            channel.cdm_type = "widevine"

            return channel

        except Exception as e:
            logger.error(f"Error parsing channel {channel_data}: {e}")
            return None

    def enrich_channel_data(self, channel: StreamingChannel, **kwargs) -> Optional[StreamingChannel]:
        """
        Enrich channel with manifest URL and additional data
        """
        try:
            # For HRTi, we need to authorize a session to get the manifest
            manifest_url = self.get_manifest(channel.channel_id, **kwargs)

            if manifest_url:
                # HRTi manifests are dynamic and session-based
                channel.set_dynamic_manifest(manifest_url)

                # Set DRM configuration
                drm_configs = self.get_drm(channel.channel_id, **kwargs)
                if drm_configs:
                    channel.use_cdm = True
                    channel.cdm_type = "widevine"
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
        """
        Get manifest URL for a channel by authorizing a session
        """
        try:
            # Authorize session for this channel
            session_data = self.auth.authorize_session(
                content_type="tlive",  # TV live
                content_ref_id=channel_id,
                channel_id=channel_id
            )

            if session_data and session_data.get('Authorized', False):
                # For live channels, use the streaming URL from channel data
                # The actual manifest will be resolved during playback with session authorization
                channels = self.get_channels()
                for channel in channels:
                    if channel.channel_id == channel_id:
                        return channel.manifest_script  # This is the streaming URL

            logger.warning(f"Session authorization failed for channel {channel_id}")
            return None

        except Exception as e:
            logger.error(f"Error getting manifest for channel {channel_id}: {e}")
            return None

    def get_drm(self, channel_id: str, **kwargs) -> List[DRMConfig]:
        """
        Get DRM configurations for a channel
        """
        try:
            # Use license URL from constants
            license_url = self.hrti_config.license_url

            drm_config = DRMConfig(
                system=DRMSystem.WIDEVINE,
                priority=1,
                license=LicenseConfig(
                    server_url=license_url,
                    req_headers=json.dumps({
                        'User-Agent': self.hrti_config.user_agent,
                        'Content-Type': 'text/plain',
                        'origin': self.hrti_config.base_website,
                        'referer': self.hrti_config.base_website
                    }),
                    req_data="{CHA-RAW}",
                    use_http_get_request=False
                )
            )

            return [drm_config]

        except Exception as e:
            logger.error(f"Error getting DRM config for channel {channel_id}: {e}")
            return []

    def get_epg_data(self, channel_id: str, **kwargs) -> Optional[Dict]:
        """
        Get EPG data for a channel
        """
        try:
            headers = self._get_authenticated_headers()

            # Get current time range (4 hours before and after)
            start_time = self.auth.get_time_offset(-4)
            end_time = self.auth.get_time_offset(4)

            payload = {
                "ChannelReferenceIds": [channel_id],
                "StartTime": f"/Date({start_time})/",
                "EndTime": f"/Date({end_time})/"
            }

            response = self.http_manager.post(
                self.hrti_config.api_endpoints['programme'],
                operation='api',
                headers=headers,
                data=json.dumps(payload)
            )
            response.raise_for_status()

            epg_data = response.json()
            if 'Result' in epg_data:
                return epg_data['Result']
            return None

        except Exception as e:
            logger.error(f"Error getting EPG data for channel {channel_id}: {e}")
            return None

    def get_license_url(self, channel: StreamingChannel, **kwargs) -> Optional[str]:
        """
        Get license URL for a DRM-protected channel
        """
        drm_configs = self.get_drm(channel.channel_id, **kwargs)
        if drm_configs:
            return drm_configs[0].license.server_url
        return None
# [file content end]