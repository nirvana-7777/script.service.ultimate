# streaming_providers/providers/joyn/models.py
# -*- coding: utf-8 -*-
"""
Joyn provider-local models and exception hierarchy.

The exceptions now subclass the base `errors` types so the backend's typed-
error handling (§8 of the template README) recognises them:

    JoynError                       (base for provider-local)
    ├── JoynAuthError               AuthError
    ├── JoynEntitlementError        EntitlementError
    │   ├── PlaybackRestrictedException
    │   └── SubscriptionRequiredException
    └── JoynMfaRequiredException    AuthError  (permanent, user-actionable)

`JoynChannel` is unchanged in shape from v1. `from_api_data` is renamed to
`from_api_response` to match the template's naming; the only caller is the
channel manager.

`JoynPlayout` is new: it is what the playout cache stores, so the manifest and
DRM methods share one entitlement + playlist call per zap. Before this, the
two methods issued the entitlement call twice.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from ...base.errors import AuthError, EntitlementError, ProviderError
from ...base.models import StreamingChannel


# ============================================================================
# Exception hierarchy
# ============================================================================

class JoynError(ProviderError):
    """Base for provider-local errors that don't fit a base category."""


class JoynAuthError(JoynError, AuthError):
    """Authentication-specific errors that are not the raw flow's exceptions."""


class JoynEntitlementError(JoynError, EntitlementError):
    """Entitlement and rights management errors (untyped)."""


class PlaybackRestrictedException(JoynEntitlementError):
    """The account is not permitted to play this content."""


class SubscriptionRequiredException(JoynEntitlementError):
    """The content requires a subscription tier the account does not hold."""


class JoynMfaRequiredException(JoynError, AuthError):
    """
    Raised when the account has two-factor authentication enabled.

    Joyn's login flow redirects to an MFA challenge page
    (signin.7pass.de/.../mfa) instead of completing with an OAuth code. The
    challenge cannot be satisfied without user interaction, so the only
    viable fix is for the user to disable MFA in their Joyn account settings.
    """


# ============================================================================
# Channel model (unchanged from v1)
# ============================================================================

@dataclass
class JoynChannel:
    """A Joyn live channel with all the streaming data the manager needs."""

    name: str
    channel_id: str
    logo_url: Optional[str] = None
    mode: str = "live"
    session_manifest: bool = False
    manifest: Optional[str] = None
    manifest_script: Optional[str] = None
    cdm_type: Optional[str] = None
    use_cdm: bool = True
    cdm: Optional[str] = None
    cdm_mode: str = "external"
    video: str = "best"
    on_demand: bool = True
    speed_up: bool = True
    content_type: str = "LIVE"
    description: Optional[str] = None
    genre: Optional[str] = None
    language: str = "de"
    country: str = "DE"
    license_url: Optional[str] = None
    certificate_url: Optional[str] = None
    streaming_format: Optional[str] = None
    raw_data: Dict = field(default_factory=dict)

    @classmethod
    def from_api_response(cls, api_data: Dict, **kwargs) -> "JoynChannel":
        channel = cls(
            name=api_data.get("title", "Unknown Channel"),
            channel_id=api_data.get("id", ""),
            content_type=api_data.get("type", "LIVE"),
            raw_data=api_data.copy(),
        )
        for key, value in kwargs.items():
            if hasattr(channel, key):
                setattr(channel, key, value)
        return channel

    def set_streaming_data(
        self,
        manifest: str,
        cdm_type: Optional[str] = None,
        pid: Optional[str] = None,
        license_url: Optional[str] = None,
        certificate_url: Optional[str] = None,
        streaming_format: Optional[str] = None,
    ) -> None:
        self.manifest = manifest
        if cdm_type:
            self.cdm_type = cdm_type
        if pid:
            self.cdm = f"pid={pid}"
        if license_url:
            self.license_url = license_url
        if certificate_url:
            self.certificate_url = certificate_url
        if streaming_format:
            self.streaming_format = streaming_format

    def to_streaming_channel(self, provider_name: str = "joyn") -> StreamingChannel:
        return StreamingChannel(
            name=self.name,
            content_id=self.channel_id,
            provider=provider_name,
            logo_url=self.logo_url,
            mode=self.mode,
            session_manifest=self.session_manifest,
            manifest=self.manifest,
            manifest_script=self.manifest_script,
            cdm_type=self.cdm_type,
            use_cdm=self.use_cdm,
            cdm=self.cdm,
            cdm_mode=self.cdm_mode,
            video=self.video,
            on_demand=self.on_demand,
            speed_up=self.speed_up,
            content_type=self.content_type,
            description=self.description,
            genre=self.genre,
            language=self.language,
            country=self.country,
            license_url=self.license_url,
            certificate_url=self.certificate_url,
            streaming_format=self.streaming_format,
        )

    def to_dict(self) -> Dict:
        return {
            "Name": self.name,
            "LogoUrl": self.logo_url,
            "Mode": self.mode,
            "SessionManifest": self.session_manifest,
            "Manifest": self.manifest,
            "ManifestScript": self.manifest_script,
            "CdmType": self.cdm_type,
            "UseCdm": self.use_cdm,
            "Cdm": self.cdm,
            "CdmMode": self.cdm_mode,
            "Video": self.video,
            "OnDemand": self.on_demand,
            "SpeedUp": self.speed_up,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


# ============================================================================
# Playout model (new — the cache entry shared by manifest and DRM)
# ============================================================================

@dataclass
class JoynPlayout:
    """
    The result of one playlist call: everything both `get_channel_manifest`
    and `get_channel_drm` need, so they share a single network round-trip
    per zap (five seconds of cache, matching PLAYOUT_CACHE_TTL).
    """

    manifest_url: str
    entitlement_token: str
    license_url: Optional[str] = None
    certificate_url: Optional[str] = None
    streaming_format: str = "dash"

    @classmethod
    def from_playlist_response(
        cls, data: Dict[str, Any], entitlement_token: str
    ) -> "JoynPlayout":
        manifest_url = data.get("manifestUrl")
        if not manifest_url:
            raise ValueError("playlist response is missing manifestUrl")
        return cls(
            manifest_url=manifest_url,
            entitlement_token=entitlement_token,
            license_url=data.get("licenseUrl"),
            certificate_url=data.get("certificateUrl"),
            streaming_format=data.get("streamingFormat", "dash"),
        )