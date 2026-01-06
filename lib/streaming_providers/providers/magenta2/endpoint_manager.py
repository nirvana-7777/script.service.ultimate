# streaming_providers/providers/magenta2/endpoint_manager.py
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from .config_models import ProviderConfig
from .constants import MAGENTA2_FALLBACK_ENDPOINTS

logger = logging.getLogger(__name__)


class EndpointCategory(Enum):
    """Categories for different types of endpoints"""

    AUTHENTICATION = "auth"
    CONTENT = "content"
    DRM = "drm"
    EPG = "epg"
    MPX = "mpx"
    TVHUBS = "tvhubs"
    USER = "user"


@dataclass
class EndpointInfo:
    """Information about a specific endpoint"""

    category: EndpointCategory
    url: str
    requires_auth: bool = False
    cache_duration: int = 3600  # seconds
    last_verified: Optional[float] = None
    is_fallback: bool = False


class EndpointManager:
    """
    Manages and resolves all dynamic endpoints for Magenta2 provider
    """

    def __init__(self, provider_config: ProviderConfig):
        self.config = provider_config
        self._endpoints: Dict[str, EndpointInfo] = {}
        self._initialize_endpoints()

    def _initialize_endpoints(self) -> None:
        """Initialize endpoints from provider configuration"""
        self._add_bootstrap_endpoints()
        self._add_manifest_endpoints()
        self._add_openid_endpoints()
        self._add_fallback_endpoints()

    def _add_bootstrap_endpoints(self) -> None:
        """Add endpoints from bootstrap configuration"""
        bootstrap = self.config.bootstrap

        # Authentication endpoints
        if bootstrap.taa_url:
            self._add_endpoint(
                "taa_auth", EndpointCategory.AUTHENTICATION, bootstrap.taa_url
            )

        if bootstrap.openid_config_url:
            self._add_endpoint(
                "openid_config",
                EndpointCategory.AUTHENTICATION,
                bootstrap.openid_config_url,
            )

        if bootstrap.line_auth_url:
            self._add_endpoint(
                "line_auth", EndpointCategory.AUTHENTICATION, bootstrap.line_auth_url
            )

        if bootstrap.remote_login_url:
            self._add_endpoint(
                "remote_login",
                EndpointCategory.AUTHENTICATION,
                bootstrap.remote_login_url,
            )

        if bootstrap.login_qr_code_url:
            self._add_endpoint(
                "login_qr_code",
                EndpointCategory.AUTHENTICATION,
                bootstrap.login_qr_code_url,
            )

        # Content endpoints
        if bootstrap.device_tokens_url:
            self._add_endpoint(
                "device_tokens", EndpointCategory.CONTENT, bootstrap.device_tokens_url
            )

        if bootstrap.account_base_url:
            self._add_endpoint(
                "account_base", EndpointCategory.USER, bootstrap.account_base_url
            )

        if bootstrap.consumer_accounts_url:
            self._add_endpoint(
                "consumer_accounts",
                EndpointCategory.USER,
                bootstrap.consumer_accounts_url,
            )

    def _add_manifest_endpoints(self) -> None:
        """Add endpoints from manifest configuration"""
        if not self.config.manifest:
            return

        manifest = self.config.manifest

        # MPX endpoints
        if manifest.mpx.license_service_url:
            self._add_endpoint(
                "mpx_license", EndpointCategory.MPX, manifest.mpx.license_service_url
            )

        if manifest.mpx.selector_service_url:
            self._add_endpoint(
                "mpx_selector", EndpointCategory.MPX, manifest.mpx.selector_service_url
            )

        if manifest.mpx.channel_stations_feed:
            self._add_endpoint(
                "channel_stations",
                EndpointCategory.CONTENT,
                manifest.mpx.channel_stations_feed,
            )
            logger.info(
                f"Channel stations feed found: {manifest.mpx.channel_stations_feed}"
            )

        # DRM endpoints
        if manifest.drm.widevine_license_url:
            self._add_endpoint(
                "widevine_license",
                EndpointCategory.DRM,
                manifest.drm.widevine_license_url,
            )

        if manifest.drm.vod_widevine_license_url:
            self._add_endpoint(
                "vod_widevine_license",
                EndpointCategory.DRM,
                manifest.drm.vod_widevine_license_url,
            )

        if manifest.drm.fairplay_license_url:
            self._add_endpoint(
                "fairplay_license",
                EndpointCategory.DRM,
                manifest.drm.fairplay_license_url,
            )

        # MPX feeds (resolved with account PID)
        for feed_name, feed_template in manifest.mpx.feeds.items():
            resolved_url = self.config.get_resolved_feed_url(feed_name)
            if resolved_url:
                self._add_endpoint(
                    f"mpx_feed_{feed_name}", EndpointCategory.MPX, resolved_url
                )

        # TV Hub URLs (resolved with client model)
        for hub_name in manifest.tv_hubs.base_urls.keys():
            resolved_url = self.config.get_resolved_tvhub_url(hub_name)
            if resolved_url:
                self._add_endpoint(
                    f"tvhub_{hub_name}", EndpointCategory.TVHUBS, resolved_url
                )

    def _add_openid_endpoints(self) -> None:
        """Add endpoints from OpenID configuration"""
        if not self.config.openid:
            return

        openid = self.config.openid

        if openid.token_endpoint:
            self._add_endpoint(
                "oauth_token",
                EndpointCategory.AUTHENTICATION,
                openid.token_endpoint,
                requires_auth=False,
            )

        if openid.authorization_endpoint:
            self._add_endpoint(
                "oauth_authorize",
                EndpointCategory.AUTHENTICATION,
                openid.authorization_endpoint,
            )

        if openid.userinfo_endpoint:
            self._add_endpoint(
                "userinfo",
                EndpointCategory.USER,
                openid.userinfo_endpoint,
                requires_auth=True,
            )

        if openid.revocation_endpoint:
            self._add_endpoint(
                "oauth_revoke",
                EndpointCategory.AUTHENTICATION,
                openid.revocation_endpoint,
            )

    def _add_fallback_endpoints(self) -> None:
        """Add fallback endpoints for critical functionality"""
        fallbacks = {
            "openid_config": MAGENTA2_FALLBACK_ENDPOINTS["OPENID_CONFIG"],
            "taa_auth": MAGENTA2_FALLBACK_ENDPOINTS["TAA_AUTH"],
            "entitlement": MAGENTA2_FALLBACK_ENDPOINTS["ENTITLEMENT"],
            "mpx_license": "https://license.entitlement.theplatform.eu/license/web/ContentAccessRules/getApplicableDistributionRights",
            "mpx_selector": "https://link.api.eu.theplatform.com/s/",
            "widevine_license": "https://widevine.entitlement.theplatform.eu/wv/web/ModularDrm/getRawWidevineLicense",
        }

        for endpoint_name, url in fallbacks.items():
            # Only add fallback if we don't already have this endpoint
            if endpoint_name not in self._endpoints:
                self._add_endpoint(
                    endpoint_name,
                    EndpointCategory.AUTHENTICATION,
                    url,
                    is_fallback=True,
                )

    def _add_endpoint(
        self,
        name: str,
        category: EndpointCategory,
        url: str,
        requires_auth: bool = False,
        is_fallback: bool = False,
    ) -> None:
        """Add an endpoint to the manager"""
        self._endpoints[name] = EndpointInfo(
            category=category,
            url=url,
            requires_auth=requires_auth,
            is_fallback=is_fallback,
        )
        logger.debug(
            f"Added endpoint: {name} -> {url} (category: {category.value}, fallback: {is_fallback})"
        )

    def get_endpoint(self, name: str) -> Optional[str]:
        """Get endpoint URL by name"""
        endpoint_info = self._endpoints.get(name)
        return endpoint_info.url if endpoint_info else None

    def get_endpoint_info(self, name: str) -> Optional[EndpointInfo]:
        """Get complete endpoint information by name"""
        return self._endpoints.get(name)

    def get_endpoints_by_category(self, category: EndpointCategory) -> Dict[str, str]:
        """Get all endpoints for a specific category"""
        return {
            name: info.url
            for name, info in self._endpoints.items()
            if info.category == category
        }

    def has_endpoint(self, name: str) -> bool:
        """Check if endpoint exists"""
        return name in self._endpoints

    def is_fallback_endpoint(self, name: str) -> bool:
        """Check if endpoint is a fallback"""
        endpoint_info = self._endpoints.get(name)
        return endpoint_info.is_fallback if endpoint_info else False

    def get_all_endpoints(self) -> Dict[str, EndpointInfo]:
        """Get all endpoints"""
        return self._endpoints.copy()

    def get_stats(self) -> Dict[str, Any]:
        """Get endpoint manager statistics"""
        total = len(self._endpoints)
        by_category = {}
        fallback_count = 0

        for info in self._endpoints.values():
            category = info.category.value
            by_category[category] = by_category.get(category, 0) + 1
            if info.is_fallback:
                fallback_count += 1

        return {
            "total_endpoints": total,
            "endpoints_by_category": by_category,
            "fallback_endpoints": fallback_count,
            "dynamic_endpoints": total - fallback_count,
            "is_complete": self.config.is_complete,
        }

    def validate_critical_endpoints(self) -> List[str]:
        """Validate that all critical endpoints are available"""
        critical_endpoints = [
            "taa_auth",
            "openid_config",
            "mpx_license",
            "widevine_license",
        ]

        missing = []
        for endpoint in critical_endpoints:
            if not self.has_endpoint(endpoint):
                missing.append(endpoint)

        return missing
