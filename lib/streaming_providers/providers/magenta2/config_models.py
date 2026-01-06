# streaming_providers/providers/magenta2/config_models.py
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class BootstrapConfig:
    """Configuration extracted from bootstrap response"""

    client_model: str
    device_model: str
    sam3_client_id: Optional[str] = None
    taa_url: Optional[str] = None
    device_tokens_url: Optional[str] = None
    line_auth_url: Optional[str] = None
    remote_login_url: Optional[str] = None
    openid_config_url: Optional[str] = None
    account_base_url: Optional[str] = None
    consumer_accounts_url: Optional[str] = None
    login_qr_code_url: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api_response(
        cls, bootstrap_data: Dict[str, Any], platform: str
    ) -> "BootstrapConfig":
        """Create BootstrapConfig from API response"""
        base_settings = bootstrap_data.get("baseSettings", {})

        return cls(
            client_model=base_settings.get("clientModel", f"ftv-{platform}"),
            device_model=base_settings.get("deviceModel", f"{platform.upper()}_FTV"),
            sam3_client_id=base_settings.get("sam3ClientId"),
            taa_url=base_settings.get("taaUrl"),
            device_tokens_url=base_settings.get("deviceTokensUrl"),
            line_auth_url=base_settings.get("lineAuthUrl"),
            remote_login_url=base_settings.get("remoteLoginUrl"),
            openid_config_url=base_settings.get("sam3Url"),
            account_base_url=base_settings.get("accountBaseUrl"),
            consumer_accounts_url=base_settings.get("consumerAccountsBaseUrl"),
            login_qr_code_url=base_settings.get("loginQrCodeUrl"),
            raw_data=bootstrap_data,
        )

    def update_from_manifest(self, manifest_config: "ManifestConfig") -> None:
        """Update bootstrap config with data from manifest"""
        from ...base.utils.logger import logger

        # Get SAM3 client ID from manifest if not in bootstrap
        if not self.sam3_client_id:
            sam3_client_id = manifest_config.get_parameter_value("SAM3ClientId")
            if sam3_client_id:
                self.sam3_client_id = sam3_client_id
                logger.info(f"✓ SAM3 Client ID from manifest: {sam3_client_id}")

        # Get TAA URL from manifest if not in bootstrap
        if not self.taa_url:
            taa_url = manifest_config.get_parameter_value("TAA-URL")
            if taa_url:
                self.taa_url = taa_url
                logger.debug(f"TAA URL from manifest: {taa_url}")

        # Get Line Auth URL from manifest if not in bootstrap
        if not self.line_auth_url:
            line_auth_url = manifest_config.get_parameter_value("LineAuthURL")
            if line_auth_url:
                self.line_auth_url = line_auth_url
                logger.debug(f"Line Auth URL from manifest: {line_auth_url}")

        # Get Remote Login URL from manifest if not in bootstrap
        if not self.remote_login_url:
            remote_login_url = manifest_config.get_parameter_value("RemoteLoginURL")
            if remote_login_url:
                self.remote_login_url = remote_login_url
                logger.debug(f"Remote Login URL from manifest: {remote_login_url}")


@dataclass
class MpxConfig:
    """MPX (ThePlatform) configuration from manifest"""

    account_pid: str
    license_service_url: str
    selector_service_url: str
    user_profile_url: Optional[str] = None
    bookmark_base_url: Optional[str] = None
    pvr_base_url: Optional[str] = None
    feeds: Dict[str, str] = field(default_factory=dict)
    # ADD THIS: Channel stations feed
    channel_stations_feed: Optional[str] = None
    mpx_account_uri: Optional[str] = None  # Actual account URI for persona token
    mpx_basic_url_selector_service: Optional[str] = None  # MPD manifest endpoint

    @classmethod
    def from_manifest_data(cls, manifest_data: Dict[str, Any]) -> "MpxConfig":
        """Create MpxConfig from manifest data"""

        def get_param(key: str) -> Optional[str]:
            """Helper to get value from parameters array"""
            if "settings" not in manifest_data:
                return None
            settings = manifest_data["settings"]
            if "parameters" not in settings:
                return None
            for param in settings["parameters"]:
                if param.get("key") == key:
                    value = param.get("value")
                    return value if value and value != "unused" else None
            return None

        mpx_data = manifest_data.get("mpx", {})

        # Build feeds dict from parameters
        feeds = {}
        feed_keys = [
            "mpxBasicUrlAllChannelSchedulesFeed",
            "mpxBasicUrlEntitledChannelsFeed",
            "mpxAllListingsFeedUrl",
            "mpxAllProgramsFeedUrl",
        ]

        for feed_key in feed_keys:
            feed_url = get_param(feed_key)
            if feed_url:
                simple_key = (
                    feed_key.replace("mpx", "")
                    .replace("Url", "")
                    .replace("BasicUrl", "")
                )
                feeds[simple_key] = feed_url

        # ADD THIS: Extract channel stations feed
        channel_stations_feed = get_param("mpxDefaultUrlAllChannelStationsFeed")

        return cls(
            account_pid=get_param("mpxAccountPid")
            or mpx_data.get("accountPid", "mdeprod"),
            license_service_url=get_param("mpxBasicUrlGetApplicableDistributionRights")
            or mpx_data.get("licenseServiceUrl", ""),
            selector_service_url=get_param("mpxBasicUrlSelectorService")
            or mpx_data.get("selectorServiceUrl", ""),
            user_profile_url=get_param("mpxUserProfileUrl")
            or mpx_data.get("userProfileUrl"),
            bookmark_base_url=get_param("mpxBookmarkBaseUrl")
            or mpx_data.get("bookmarkBaseUrl"),
            pvr_base_url=get_param("mpxPvrBaseUrl") or mpx_data.get("pvrBaseUrl"),
            feeds=feeds,
            channel_stations_feed=channel_stations_feed,
            mpx_account_uri=get_param("mpxAccountUri"),  # Extract actual account URI
            mpx_basic_url_selector_service=get_param(
                "mpxBasicUrlSelectorService"
            ),  # Extract MPD endpoint
        )

    def get_account_uri(self) -> str:
        """
        Get MPX account URI for persona token composition
        Prefer actual mpxAccountUri, fallback to constructed format
        """
        if self.mpx_account_uri:
            return self.mpx_account_uri
        # Fallback to constructed format
        return "http://access.auth.theplatform.com/data/Account/2709353023"


@dataclass
class ImageConfig:
    """Image scaling configuration from manifest"""

    scaling_base_url: Optional[str] = None
    scaling_call_parameter: Optional[str] = None

    @classmethod
    def from_manifest_data(cls, manifest_data: Dict[str, Any]) -> "ImageConfig":
        """Create ImageConfig from manifest data"""

        def get_param(key: str) -> Optional[str]:
            """Helper to get value from parameters array"""
            if "settings" not in manifest_data:
                return None
            settings = manifest_data["settings"]
            if "parameters" not in settings:
                return None
            for param in settings["parameters"]:
                if param.get("key") == key:
                    value = param.get("value")
                    return value if value and value != "unused" else None
            return None

        return cls(
            scaling_base_url=get_param("imageScalingBasicUrl"),
            scaling_call_parameter=get_param("imageScalingCallParameter"),
        )


@dataclass
class DrmConfig:
    """DRM configuration from manifest"""

    widevine_license_url: str
    vod_widevine_license_url: Optional[str] = None
    fairplay_license_url: Optional[str] = None

    @classmethod
    def from_manifest_data(cls, manifest_data: Dict[str, Any]) -> "DrmConfig":
        """Create DrmConfig from manifest data"""
        from ...base.utils.logger import logger

        # Create a temporary helper function for this method
        def get_param(key: str) -> Optional[str]:
            """Helper to get value from parameters array"""
            if "settings" not in manifest_data:
                return None
            settings = manifest_data["settings"]
            if "parameters" not in settings:
                return None
            for param in settings["parameters"]:
                if param.get("key") == key:
                    value = param.get("value")
                    return value if value and value != "unused" else None
            return None

        # Try parameters array first (current structure)
        widevine_url = get_param("widevineLicenseAcquisitionURL")
        fairplay_url = get_param("fairplayLicenseAcquisitionURL")

        # Fallback to legacy structure
        if not widevine_url or not fairplay_url:
            livetv_drm = manifest_data.get("livetv", {}).get("drm", {})
            vod_drm = manifest_data.get("vod", {}).get("drm", {})

            if not widevine_url:
                widevine_url = livetv_drm.get("widevineLicenseAcquisitionUrl", "")
            if not fairplay_url:
                fairplay_url = livetv_drm.get("fairplayLicenseAcquisitionUrl", "")

            vod_widevine = vod_drm.get("widevineLicenseAcquisitionUrl")
        else:
            vod_widevine = None  # Not in parameters array

        logger.debug(
            f"DRM config: widevine={bool(widevine_url)}, fairplay={bool(fairplay_url)}"
        )

        return cls(
            widevine_license_url=widevine_url or "",
            vod_widevine_license_url=vod_widevine,
            fairplay_license_url=fairplay_url or "",
        )


@dataclass
class TvHubConfig:
    """TV Hub URLs configuration from manifest"""

    base_urls: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_manifest_data(cls, manifest_data: Dict[str, Any]) -> "TvHubConfig":
        """Create TvHubConfig from manifest data"""

        # Create a temporary helper function for this method
        def get_param(param_key: str) -> Optional[str]:
            """Helper to get value from parameters array"""
            if "settings" not in manifest_data:
                return None
            settings_data = manifest_data["settings"]
            if "parameters" not in settings_data:
                return None
            for param in settings_data["parameters"]:
                if param.get("key") == param_key:
                    value = param.get("value")
                    return value if value and value != "unused" else None
            return None

        base_urls = {}

        # TV Hub URLs from parameters
        tvhub_keys = [
            "homeUrl",
            "settingsMenu",
            "broadcastDetailsURL",
            "vodDetailsURL",
            "searchUrl",
            "kidsSearchURL",
            "myWatchlistUrl",
            "myMoviesURL",
        ]

        # Check settings object first
        if "settings" in manifest_data:
            settings_obj = manifest_data["settings"]
            for tvhub_key in tvhub_keys:
                if tvhub_key in settings_obj:
                    url = settings_obj.get(tvhub_key)
                    if url and url != "unused":
                        base_urls[tvhub_key] = url

        # Also check parameters array
        for tvhub_key in tvhub_keys:
            if tvhub_key not in base_urls:
                url = get_param(tvhub_key)
                if url:
                    base_urls[tvhub_key] = url

        # Legacy structure fallback
        tv_hubs = manifest_data.get("tvHubUrls", {})
        for hub_name, hub_url in tv_hubs.items():
            if (
                isinstance(hub_url, str)
                and hub_url.startswith("http")
                and hub_name not in base_urls
            ):
                base_urls[hub_name] = hub_url

        return cls(base_urls=base_urls)


@dataclass
class ManifestConfig:
    """Complete configuration from manifest discovery"""

    mpx: MpxConfig
    drm: DrmConfig
    tv_hubs: TvHubConfig
    image_config: ImageConfig
    youbora_config: Dict[str, Any] = field(default_factory=dict)
    npvr_config: Dict[str, Any] = field(default_factory=dict)
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api_response(cls, manifest_data: Dict[str, Any]) -> "ManifestConfig":
        """Create ManifestConfig from API response"""
        return cls(
            mpx=MpxConfig.from_manifest_data(manifest_data),
            drm=DrmConfig.from_manifest_data(manifest_data),
            tv_hubs=TvHubConfig.from_manifest_data(manifest_data),
            image_config=ImageConfig.from_manifest_data(manifest_data),
            youbora_config=manifest_data.get("youbora", {}),
            npvr_config=manifest_data.get("npvr", {}),
            raw_data=manifest_data,
        )

    def get_parameter_value(self, key: str) -> Optional[str]:
        """Get value from settings.parameters array by key"""
        if "settings" not in self.raw_data:
            return None

        settings = self.raw_data["settings"]
        if "parameters" not in settings or not isinstance(settings["parameters"], list):
            return None

        for param in settings["parameters"]:
            if param.get("key") == key:
                value = param.get("value")
                # Empty string or "unused" means not available
                return value if value and value != "unused" else None

        return None

    def get_device_token(self) -> Optional[str]:
        """Extract device token from raw data"""
        # Try direct path first (legacy)
        if "deviceToken" in self.raw_data:
            return self.raw_data["deviceToken"]

        # Try nested in sts object (current structure)
        if "sts" in self.raw_data and isinstance(self.raw_data["sts"], dict):
            if "deviceToken" in self.raw_data["sts"]:
                return self.raw_data["sts"]["deviceToken"]

        return None

    def get_authorize_tokens_url(self) -> Optional[str]:
        """Extract authorize tokens URL from raw data"""
        # Check in sts object first (current structure)
        if "sts" in self.raw_data and isinstance(self.raw_data["sts"], dict):
            if "authorizeTokensUrl" in self.raw_data["sts"]:
                return self.raw_data["sts"]["authorizeTokensUrl"]

        # Check direct path (legacy)
        if "authorizeTokensUrl" in self.raw_data:
            return self.raw_data["authorizeTokensUrl"]

        # Check in settings.parameters array as fallback
        line_auth_url = self.get_parameter_value("LineAuthURL")
        if line_auth_url:
            return line_auth_url

        return None


@dataclass
class OpenIDConfig:
    """OpenID Connect configuration"""

    token_endpoint: str
    authorization_endpoint: str
    userinfo_endpoint: Optional[str] = None
    revocation_endpoint: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api_response(cls, openid_data: Dict[str, Any]) -> "OpenIDConfig":
        """Create OpenIDConfig from API response"""
        return cls(
            token_endpoint=openid_data.get("token_endpoint", ""),
            authorization_endpoint=openid_data.get("authorization_endpoint", ""),
            userinfo_endpoint=openid_data.get("userinfo_endpoint"),
            revocation_endpoint=openid_data.get("revocation_endpoint"),
            raw_data=openid_data,
        )


@dataclass
class ProviderConfig:
    """Complete provider configuration assembled from all discovery sources"""

    bootstrap: BootstrapConfig
    manifest: Optional[ManifestConfig] = None
    openid: Optional[OpenIDConfig] = None
    discovered_at: datetime = field(default_factory=datetime.now)

    @property
    def is_complete(self) -> bool:
        """Check if configuration is complete enough for operation"""
        return self.bootstrap is not None and self.manifest is not None

    def get_resolved_feed_url(self, feed_name: str) -> Optional[str]:
        """Get resolved MPX feed URL with account PID substitution"""
        if not self.manifest or not self.manifest.mpx:
            return None

        feed_template = self.manifest.mpx.feeds.get(feed_name)
        if not feed_template:
            return None

        return feed_template.replace("{MpxAccountPid}", self.manifest.mpx.account_pid)

    def get_resolved_tvhub_url(
        self, hub_name: str, client_model: Optional[str] = None
    ) -> Optional[str]:
        """Get resolved TV Hub URL with client model substitution"""
        if not self.manifest:
            return None

        hub_template = self.manifest.tv_hubs.base_urls.get(hub_name)
        if not hub_template:
            return None

        resolved_client_model = client_model or self.bootstrap.client_model
        return hub_template.replace("{clientModel}", resolved_client_model)

    def get_mpx_account_uri(self) -> Optional[str]:
        """NEW: Get MPX account URI for persona token composition"""
        if not self.manifest or not self.manifest.mpx:
            return None
        return self.manifest.mpx.get_account_uri()

    def get_device_token(self) -> Optional[str]:
        """NEW: Get device token from manifest"""
        if not self.manifest:
            return None
        return self.manifest.get_device_token()

    def get_authorize_tokens_url(self) -> Optional[str]:
        """NEW: Get authorize tokens URL from manifest"""
        if not self.manifest:
            return None
        return self.manifest.get_authorize_tokens_url()
