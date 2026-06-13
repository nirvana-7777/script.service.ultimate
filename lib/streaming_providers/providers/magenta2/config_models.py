# streaming_providers/providers/magenta2/config_models.py
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional
from ...base.utils.logger import logger


@dataclass
class BootstrapConfig:
    """Configuration extracted from bootstrap response"""

    client_model: str
    device_model: str
    subscriber_type: str = "FTV_OTT_DT"  # resolved from platform via SUBSCRIBER_TYPES
    sam3_client_id: Optional[str] = None
    taa_url: Optional[str] = None
    device_tokens_url: Optional[str] = None
    manifest_base_url: Optional[str] = None
    line_auth_url: Optional[str] = None
    remote_login_url: Optional[str] = None
    openid_config_url: Optional[str] = None
    account_base_url: Optional[str] = None
    consumer_accounts_url: Optional[str] = None
    login_qr_code_url: Optional[str] = None
    # VOD / personal-bar fields from baseSettings
    home_url: Optional[str] = None  # baseSettings.homeUrl
    profile_name: Optional[str] = None  # baseSettings.profileName
    theme_id: Optional[str] = None  # baseSettings.themeId
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api_response(cls, bootstrap_data: Dict[str, Any], platform: str) -> "BootstrapConfig":
        """Create BootstrapConfig from API response"""
        from .constants import SUBSCRIBER_TYPES

        base_settings = bootstrap_data.get("baseSettings", {})
        dcm_settings = bootstrap_data.get("dcm", {})

        return cls(
            client_model=base_settings.get("clientModel", f"ftv-{platform}"),
            device_model=base_settings.get("deviceModel", f"{platform.upper()}_FTV"),
            subscriber_type=SUBSCRIBER_TYPES.get(platform, "FTV_OTT_DT"),
            sam3_client_id=base_settings.get("sam3ClientId"),
            taa_url=base_settings.get("taaUrl"),
            device_tokens_url=base_settings.get("deviceTokensUrl"),
            manifest_base_url=dcm_settings.get("manifestBaseUrl"),
            line_auth_url=base_settings.get("lineAuthUrl"),
            remote_login_url=base_settings.get("remoteLoginUrl"),
            openid_config_url=base_settings.get("sam3Url"),
            account_base_url=base_settings.get("accountBaseUrl"),
            consumer_accounts_url=base_settings.get("consumerAccountsBaseUrl"),
            login_qr_code_url=base_settings.get("loginQrCodeUrl"),
            home_url=base_settings.get("homeUrl"),
            profile_name=base_settings.get("profileName"),
            theme_id=base_settings.get("themeId"),
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
        mpx_data = manifest_data.get("mpx", {})

        license_service_url = mpx_data.get("basicUrlGetApplicableDistributionRights", "")
        selector_service_url = mpx_data.get("basicUrlSelectorService", "")
        account_pid = mpx_data.get("accountPid", "mdeprod")
        user_profile_url = mpx_data.get("userProfileUrl")
        bookmark_base_url = mpx_data.get("bookmarkBaseUrl", "")
        pvr_base_url = mpx_data.get("pvrBaseUrl", "")

        # Build feeds dict from mpx.feeds
        feeds = {}
        mpx_feeds = mpx_data.get("feeds", {})
        for feed_name, feed_url in mpx_feeds.items():
            feeds[feed_name] = feed_url

        channel_stations_feed = mpx_feeds.get("allChannelStationsFeed")

        # Extract account ID from pvrBaseUrl: ".../npvr-audience/2709353023"
        # Fall back to programGuidBaseUri if pvrBaseUrl is absent
        mpx_account_uri = mpx_data.get("accountUri")
        if not mpx_account_uri:
            account_id = None
            if pvr_base_url:
                # pvrBaseUrl ends with "/<accountId>"
                account_id = pvr_base_url.rstrip("/").split("/")[-1]
            if not account_id:
                prog_uri = mpx_data.get("programGuidBaseUri", "")
                # programGuidBaseUri contains "/guid/<accountId>/"
                parts = prog_uri.split("/guid/")
                if len(parts) == 2:
                    account_id = parts[1].split("/")[0]
            if account_id:
                mpx_account_uri = (
                    f"http://access.auth.theplatform.com/data/Account/{account_id}"
                )
                logger.debug(f"MPX account URI derived from manifest: {mpx_account_uri}")
            else:
                logger.warning("Could not derive MPX account URI from manifest")

        return cls(
            account_pid=account_pid,
            license_service_url=license_service_url,
            selector_service_url=selector_service_url,
            user_profile_url=user_profile_url,
            bookmark_base_url=bookmark_base_url,
            pvr_base_url=pvr_base_url,
            feeds=feeds,
            channel_stations_feed=channel_stations_feed,
            mpx_account_uri=mpx_account_uri,
            mpx_basic_url_selector_service=selector_service_url,
        )

    def get_account_uri(self) -> Optional[str]:
        """
        Get MPX account URI for persona token composition.
        Returns None if not available — callers must handle this case.
        """
        if self.mpx_account_uri:
            return self.mpx_account_uri
        logger.warning(
            "MPX account URI not available — "
            "pvrBaseUrl and programGuidBaseUri were both absent or unparseable in manifest"
        )
        return None


@dataclass
class ImageConfig:
    """Image scaling configuration from manifest"""
    scaling_base_url: Optional[str] = None
    scaling_call_parameter: Optional[str] = None

    @classmethod
    def from_manifest_data(cls, manifest_data: Dict[str, Any]) -> "ImageConfig":
        # FIX: Read from ngiss, not settings.parameters
        ngiss = manifest_data.get("ngiss", {})
        return cls(
            scaling_base_url=ngiss.get("basicUrl"),
            scaling_call_parameter=ngiss.get("callParameter"),
        )


@dataclass
class DrmConfig:
    """DRM configuration from manifest"""

    widevine_license_url: str
    vod_widevine_license_url: Optional[str] = None
    fairplay_license_url: Optional[str] = None

    @classmethod
    def from_manifest_data(cls, manifest_data: Dict[str, Any]) -> "DrmConfig":
        # Read from livetv.drm and vod.drm objects directly
        livetv_drm = manifest_data.get("livetv", {}).get("drm", {})
        vod_drm = manifest_data.get("vod", {}).get("drm", {})

        widevine_url = livetv_drm.get("widevineLicenseAcquisitionUrl", "")
        vod_widevine_url = vod_drm.get("widevineLicenseAcquisitionUrl", "")
        fairplay_url = livetv_drm.get("fairplayLicenseAcquisitionUrl", "")

        # Also check top-level if needed (though not in your response)
        if not widevine_url:
            widevine_url = manifest_data.get("drm", {}).get("widevineLicenseAcquisitionUrl", "")

        logger.debug(f"DRM config: widevine={bool(widevine_url)}, vod_widevine={bool(vod_widevine_url)}")

        return cls(
            widevine_license_url=widevine_url,
            vod_widevine_license_url=vod_widevine_url,
            fairplay_license_url=fairplay_url,
        )


@dataclass
class TvHubConfig:
    """TV Hub URLs configuration from manifest"""
    base_urls: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_manifest_data(cls, manifest_data: Dict[str, Any]) -> "TvHubConfig":
        tv_hubs_data = manifest_data.get("tvHubUrls", {})
        base_urls = {}

        def extract_urls(obj: Dict[str, Any], prefix: str = ""):
            """Recursively extract all URL strings from nested dict"""
            for key, value in obj.items():
                full_key = f"{prefix}{key}" if prefix else key

                if isinstance(value, str) and (value.startswith("http") or value.startswith("https")):
                    base_urls[full_key] = value
                elif isinstance(value, dict):
                    extract_urls(value, f"{full_key}.")
                # Skip non-string, non-dict values (like integers, booleans)

        extract_urls(tv_hubs_data)

        logger.debug(f"Extracted {len(base_urls)} TV Hub URLs from manifest")
        return cls(base_urls=base_urls)

    @property
    def search_url(self) -> Optional[str]:
        """Get the raw search URL template."""
        return self.base_urls.get("searchUrl")

    @property
    def vod_details_url(self) -> Optional[str]:
        """Get the raw VOD details URL template."""
        return self.base_urls.get("vodDetailsUrl")

    @property
    def unstructured_grid_url(self) -> Optional[str]:
        """Get the raw UnstructuredGrid URL template."""
        return self.base_urls.get("UnstructuredGrid")


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

    def get_resolved_tvhub_url(self, hub_name: str, resolve: bool = True) -> Optional[str]:
        """
        Get resolved TV Hub URL with client model substitution.

        Args:
            hub_name: Name of the hub URL (e.g., "searchUrl", "vodDetailsUrl")
            resolve: If True, substitute {clientModel} with actual value.
                     If False, return the raw template.
        """
        if not self.manifest or not self.bootstrap.client_model:
            return None
        template = self.manifest.tv_hubs.base_urls.get(hub_name)
        if not template:
            return None

        if not resolve:
            return template

        client_model: str = self.bootstrap.client_model
        return template.replace("{clientModel}", client_model)

    def get_search_url_template(self) -> Optional[str]:
        """
        Get the raw search URL template from manifest tvHubUrls.

        The template contains {clientModel} and {query} placeholders:
        e.g., "https://prod.tvhubs.ng.telekom.net/v3/{clientModel}/DocumentGroupRedirect/TVHS_DG_SearchGrid?q={query}"

        Returns:
            Raw template string, or None if not available.
        """
        return self.get_resolved_tvhub_url("searchUrl", resolve=False)

    def get_tvhubs_base_url(self, client_model: Optional[str] = None) -> Optional[str]:
        if not self.manifest:
            return None

        resolved_client_model = client_model or self.bootstrap.client_model
        if not resolved_client_model:
            return None  # Can't resolve without a client model

        for hub_template in self.manifest.tv_hubs.base_urls.values():
            resolved = hub_template.replace("{clientModel}", resolved_client_model)
            marker = f"/v3/{resolved_client_model}"
            idx = resolved.find(marker)
            if idx != -1:
                return resolved[: idx + len(marker)]

        return None

    def get_mpx_account_uri(self) -> Optional[str]:
        """
        Get MPX account URI for persona token composition.

        Resolution order:
          1. Manifest mpx.accountUri (direct field)
          2. Derived from manifest mpx.pvrBaseUrl / programGuidBaseUri
          3. Constructed from bootstrap accountBaseUrl + manifest-derived account ID
        """
        if not self.manifest or not self.manifest.mpx:
            return None

        uri = self.manifest.mpx.get_account_uri()
        if uri:
            return uri

        # Last resort: combine bootstrap accountBaseUrl with manifest account ID
        account_base = self.bootstrap.account_base_url  # e.g. "http://access.auth.theplatform.com/data/Account"
        if account_base:
            pvr_url = self.manifest.mpx.pvr_base_url or ""
            account_id = pvr_url.rstrip("/").split("/")[-1] if pvr_url else None
            if account_id and account_id.isdigit():
                uri = f"{account_base.rstrip('/')}/{account_id}"
                logger.debug(f"MPX account URI from bootstrap+manifest fallback: {uri}")
                return uri

        return None

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