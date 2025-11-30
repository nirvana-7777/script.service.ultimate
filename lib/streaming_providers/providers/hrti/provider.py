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
            'referer': f'{self.hrti_config.base_website}/login'  # Use /login for API calls
        }

        # Add authorization header with Client prefix
        if bearer_token:
            headers['authorization'] = f'Client {bearer_token}'

        logger.debug(
            f"HRTi API Headers - deviceid: {device_id[:8]}..., auth: {'present' if bearer_token else 'missing'}")
        return headers

    def get_channels(self, **kwargs) -> List[StreamingChannel]:
        """
        Fetch channels from HRTi API
        """
        try:
            headers = self._get_authenticated_headers()

            # Log the request for debugging
            logger.debug(
                f"Fetching HRTi channels with authorization: {'Client ...' if 'authorization' in headers else 'NO AUTHORIZATION'}")

            response = self.http_manager.post(
                self.hrti_config.api_endpoints['channels'],
                operation='api',
                headers=headers,
                data=json.dumps({})
            )
            response.raise_for_status()

            channels_data = response.json()
            if 'Result' in channels_data and channels_data['Result']:
                channels = []
                for channel in channels_data['Result']:
                    streaming_channel = self._parse_channel_data(channel)
                    if streaming_channel:
                        channels.append(streaming_channel)

                self.channels = channels
                logger.info(f"Successfully fetched {len(channels)} channels from HRTi")
                return channels
            else:
                logger.warning("No channels found in HRTi response")
                if 'Result' in channels_data:
                    logger.debug(f"HRTi channels response: {channels_data}")
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
                if 'Result' in channels_data and channels_data['Result']:
                    channels = []
                    for channel in channels_data['Result']:
                        streaming_channel = self._parse_channel_data(channel)
                        if streaming_channel:
                            channels.append(streaming_channel)

                    self.channels = channels
                    logger.info(f"Successfully fetched {len(channels)} channels from HRTi on retry")
                    return channels
                else:
                    logger.warning("No channels found in HRTi retry response")
                    return []

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
            # FIX: API returns 'ReferenceID' (capital ID), not 'ReferenceId'
            channel_id = channel_data.get('ReferenceID', '')
            streaming_url = channel_data.get('StreamingURL', '')
            is_radio = channel_data.get('Radio', False)
            icon_url = channel_data.get('Icon', '')

            if not name or not channel_id:
                logger.debug(f"Skipping channel - missing name or ID: {channel_data}")
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

            logger.debug(f"Parsed HRTi channel: {name} ({channel_id}) - radio: {is_radio}")
            return channel

        except Exception as e:
            logger.error(f"Error parsing channel {channel_data}: {e}")
            return None

    def enrich_channel_data(self, channel: StreamingChannel, **kwargs) -> Optional[StreamingChannel]:
        """
        Enrich channel with manifest URL and DRM configuration.
        This method pre-authorizes a session and passes session_data to get_drm().
        """
        try:
            logger.debug(f"Enriching channel: {channel.name} ({channel.channel_id})")

            # For live channels, we need to authorize a session first
            content_type = "rlive" if channel.content_type == "AUDIO" else "tlive"

            # Parse the streaming URL to get content DRM ID
            from urllib.parse import urlparse
            parts = urlparse(channel.manifest_script)
            path_parts = parts.path.strip('/').split('/')

            # Content DRM ID format: directory1_directory2
            # Example: /cdn1oiv/hrtliveorigin/... -> cdn1oiv_hrtliveorigin
            content_drm_id = None
            if len(path_parts) >= 2:
                content_drm_id = f"{path_parts[0]}_{path_parts[1]}"

            logger.debug(f"Content DRM ID for {channel.name}: {content_drm_id}")

            # Authorize session
            session_data = self.auth.authorize_session(
                content_type=content_type,
                content_ref_id=channel.channel_id,
                content_drm_id=content_drm_id,
                video_store_ids=None,
                channel_id=channel.channel_id,
                start_time=None,
                end_time=None
            )

            if not session_data:
                logger.warning(f"Failed to authorize session for channel {channel.name}")
                return channel

            # Check if authorized
            if not session_data.get('Authorized', False):
                logger.warning(f"Session not authorized for channel {channel.name}")
                return channel

            logger.debug(f"Session authorized for {channel.name}")

            # Report session event (play start) - use full SessionId
            session_id = session_data.get('SessionId')
            if session_id:
                self.auth.report_session_event(session_id, channel.channel_id)

            # Set the manifest URL - use the streaming URL from channel data
            manifest_url = channel.manifest_script
            if manifest_url:
                channel.set_dynamic_manifest(manifest_url)
                logger.debug(f"Set manifest for {channel.name}: {manifest_url}")

            # Set DRM configuration with session data
            # Pass session_data to avoid re-authorizing
            drm_configs = self.get_drm(channel.channel_id, session_data=session_data, **kwargs)
            if drm_configs:
                channel.use_cdm = True
                channel.cdm_type = "widevine"

                # Set license URL from the first Widevine config
                for config in drm_configs:
                    if config.system == DRMSystem.WIDEVINE:
                        channel.license_url = config.license.server_url

                        # Build the complete license key for inputstream.adaptive
                        # Format: server_url|req_headers|req_data|response_format
                        license_key_parts = [
                            config.license.server_url,
                            config.license.req_headers,
                            'R{SSM}',  # Placeholder - inputstream will replace with actual challenge
                            'JBlicense'  # Response is JSON, extract 'license' field
                        ]
                        channel.license_key = '|'.join(license_key_parts)

                        logger.debug(f"Set DRM config for {channel.name}")
                        logger.debug(f"License URL: {config.license.server_url}")
                        break
            else:
                logger.warning(f"No DRM config for {channel.name}")
                channel.use_cdm = False
                channel.cdm_type = None

            return channel

        except Exception as e:
            logger.error(f"Error enriching channel data for {channel.name}: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
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

    def get_drm(self, channel_id: str, session_data: Dict = None, **kwargs) -> List[DRMConfig]:
        """
        Get DRM configurations for a channel with proper license data.
        If session_data is not provided, will authorize a new session.
        """
        try:
            # If no session data provided, authorize a new session
            if not session_data:
                logger.debug(f"No session data provided for DRM - authorizing new session for channel {channel_id}")

                # Find the channel to get content type and streaming URL
                channels = self.get_channels() if not hasattr(self, 'channels') or not self.channels else self.channels
                target_channel = None
                for ch in channels:
                    if ch.channel_id == channel_id:
                        target_channel = ch
                        break

                if not target_channel:
                    logger.error(f"Channel {channel_id} not found for DRM authorization")
                    return []

                # Determine content type
                content_type = "rlive" if target_channel.content_type == "AUDIO" else "tlive"

                # Parse the streaming URL to get content DRM ID
                from urllib.parse import urlparse
                parts = urlparse(target_channel.manifest_script)
                path_parts = parts.path.strip('/').split('/')

                # Content DRM ID format: directory1_directory2
                content_drm_id = None
                if len(path_parts) >= 2:
                    content_drm_id = f"{path_parts[0]}_{path_parts[1]}"

                logger.debug(
                    f"Authorizing session for DRM - channel: {channel_id}, content_type: {content_type}, drm_id: {content_drm_id}")

                # Authorize session
                session_data = self.auth.authorize_session(
                    content_type=content_type,
                    content_ref_id=channel_id,
                    content_drm_id=content_drm_id,
                    video_store_ids=None,
                    channel_id=channel_id,
                    start_time=None,
                    end_time=None
                )

                if not session_data:
                    logger.error(f"Failed to authorize session for DRM - channel {channel_id}")
                    return []

                # Check if authorized
                if not session_data.get('Authorized', False):
                    logger.warning(f"Session not authorized for DRM - channel {channel_id}")
                    return []

                logger.debug(f"Session authorized for DRM - channel {channel_id}")

                # Report session event (use full SessionId, not DrmId)
                session_id = session_data.get('SessionId')
                if session_id:
                    self.auth.report_session_event(session_id, channel_id)

            # IMPORTANT: For license data, use DrmId (not SessionId)
            # DrmId is the short random string for DRM
            # SessionId is the full identifier like "6:hrt:userid:uuid"
            drm_id = session_data.get('DrmId')
            session_id = session_data.get('SessionId')  # Keep for session reporting

            if not drm_id:
                logger.error("No DRM ID in session data")
                logger.debug(f"Session data keys: {list(session_data.keys())}")
                return []

            logger.debug(f"Using DrmId for license: {drm_id[:20]}... (full SessionId: {session_id})")

            # Generate license data (base64 encoded) - use DrmId not SessionId
            license_data = self.auth.get_license_data(drm_id)
            if not license_data:
                logger.error("Failed to generate license data")
                return []

            logger.debug(f"Generated license data for session {session_id}")

            # Build the license request headers in the format expected by inputstream.adaptive
            # Format: Key1=Value1&Key2=Value2
            license_headers = '&'.join([
                f'User-Agent={self.hrti_config.user_agent}',
                f'origin={self.hrti_config.base_website}',
                f'referer={self.hrti_config.base_website}/',
                f'dt-custom-data={license_data}'
            ])

            # Create the license configuration
            license_config = LicenseConfig(
                server_url=self.hrti_config.license_url,
                use_http_get_request=False,
                req_headers=license_headers,
                req_data='{CHA-RAW}',  # Placeholder for license challenge - will be replaced by player
                wrapper=None,
                unwrapper=None
            )

            # Create the DRM configuration
            drm_config = DRMConfig(
                system=DRMSystem.WIDEVINE,
                priority=1,
                license=license_config
            )

            logger.debug(f"Created DRM config for channel {channel_id} with DrmId {drm_id}")
            return [drm_config]

        except Exception as e:
            logger.error(f"Error getting DRM config for channel {channel_id}: {e}")
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
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