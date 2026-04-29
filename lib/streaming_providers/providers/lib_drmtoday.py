# streaming_providers/base/lib_drmtoday.py
"""
DRMToday License Server Integration

Shared utilities for providers using DRMToday as their DRM license provider.
"""

from typing import Optional
from ..base.models.drm import (
    DRMConfig,
    DRMSystem,
    LicenseConfig,
    LicenseUnwrapperParams,
)


class DRMTodayConfig:
    """Default DRMToday configuration constants"""

    # Default license server URLs
    DEFAULT_WIDEVINE_URL = "https://lic.drmtoday.com/license-proxy-widevine/cenc/"
    DEFAULT_PLAYREADY_URL = "https://lic.drmtoday.com/license-proxy-headerauth/drmtoday/RightsManager.asmx"

    # SOAP action for PlayReady
    PLAYREADY_SOAP_ACTION = "http://schemas.microsoft.com/DRM/2007/03/protocols/AcquireLicense"

    # Common unwrapper configuration for DRMToday
    UNWRAPPER = "json,base64"
    UNWRAPPER_PARAMS = {"path_data": "license"}


def create_drmtoday_widevine_config(
        upfront_token: str,
        origin: str,
        referer: str,
        user_agent: str,
        license_url: Optional[str] = None,
        priority: int = 3,
) -> DRMConfig:
    """
    Create Widevine DRM configuration for DRMToday.

    Args:
        upfront_token: DRMToday upfront token (x-dt-auth-token)
        origin: Origin header value (e.g., "https://plus.rtl.de")
        referer: Referer header value
        user_agent: User-Agent string
        license_url: Optional custom license URL (uses default if not provided)
        priority: DRM priority (default 3)

    Returns:
        DRMConfig ready for use in ISA
    """
    license_url = license_url or DRMTodayConfig.DEFAULT_WIDEVINE_URL

    headers = {
        "user-agent": user_agent,
        "origin": origin,
        "referer": referer,
        "x-dt-auth-token": upfront_token,
    }

    license_config = LicenseConfig(
        server_url=license_url,
        req_headers=headers,  # LicenseConfig will normalize this to URL-encoded
        req_data="{CHA-RAW}",
        use_http_get_request=False,
        unwrapper=DRMTodayConfig.UNWRAPPER,
        unwrapper_params=LicenseUnwrapperParams(**DRMTodayConfig.UNWRAPPER_PARAMS),
    )

    return DRMConfig(
        system=DRMSystem.WIDEVINE,
        priority=priority,
        license=license_config,
    )


def create_drmtoday_playready_config(
        upfront_token: str,
        origin: str,
        referer: str,
        user_agent: str,
        license_url: Optional[str] = None,
        priority: int = 2,
) -> DRMConfig:
    """
    Create PlayReady DRM configuration for DRMToday.

    Args:
        upfront_token: DRMToday upfront token (x-dt-auth-token)
        origin: Origin header value (e.g., "https://plus.rtl.de")
        referer: Referer header value
        user_agent: User-Agent string (often Edge for PlayReady)
        license_url: Optional custom license URL (uses default if not provided)
        priority: DRM priority (default 2)

    Returns:
        DRMConfig ready for use in ISA
    """
    license_url = license_url or DRMTodayConfig.DEFAULT_PLAYREADY_URL

    headers = {
        "Content-Type": "text/xml; charset=UTF-8",
        "SOAPAction": DRMTodayConfig.PLAYREADY_SOAP_ACTION,
        "User-Agent": user_agent,
        "origin": origin,
        "referer": referer,
        "X-Dt-Auth-Token": upfront_token,
    }

    license_config = LicenseConfig(
        server_url=license_url,
        req_headers=headers,
        req_data="{CHA-RAW}",
        use_http_get_request=False,
    )

    return DRMConfig(
        system=DRMSystem.PLAYREADY,
        priority=priority,
        license=license_config,
    )


def create_drmtoday_configs(
        upfront_token: str,
        origin: str,
        referer: str,
        user_agent: str,
        playready_user_agent: Optional[str] = None,
        widevine_url: Optional[str] = None,
        playready_url: Optional[str] = None,
        widevine_priority: int = 3,
        playready_priority: int = 2,
) -> list[DRMConfig]:
    """
    Create both Widevine and PlayReady DRM configurations for DRMToday.

    This is the most common use case - return both DRM systems so ISA can choose.

    Args:
        upfront_token: DRMToday upfront token
        origin: Origin header value
        referer: Referer header value
        user_agent: User-Agent for Widevine requests
        playready_user_agent: User-Agent for PlayReady (uses user_agent if None)
        widevine_url: Optional custom Widevine license URL
        playready_url: Optional custom PlayReady license URL
        widevine_priority: Priority for Widevine (lower = higher priority)
        playready_priority: Priority for PlayReady

    Returns:
        List of DRMConfig objects (Widevine then PlayReady)
    """
    drm_configs = []

    # Widevine config
    wv_config = create_drmtoday_widevine_config(
        upfront_token=upfront_token,
        origin=origin,
        referer=referer,
        user_agent=user_agent,
        license_url=widevine_url,
        priority=widevine_priority,
    )
    drm_configs.append(wv_config)

    # PlayReady config (use provided UA or fallback to Widevine UA)
    pr_user_agent = playready_user_agent or user_agent
    pr_config = create_drmtoday_playready_config(
        upfront_token=upfront_token,
        origin=origin,
        referer=referer,
        user_agent=pr_user_agent,
        license_url=playready_url,
        priority=playready_priority,
    )
    drm_configs.append(pr_config)

    return drm_configs