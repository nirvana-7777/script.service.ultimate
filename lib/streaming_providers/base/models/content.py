from dataclasses import dataclass
from decimal import Decimal
from typing import Dict, List, Optional, Set

from .drm import DRMConfig
from .pricing import AccessType, PricePoint, Pricing

class StreamingMode:
    """Enum for streaming modes"""
    LIVE = "live"
    VOD = "vod"


class ContentType:
    """Enum for content types"""
    LIVE = "LIVE"
    VOD = "VOD"
    SERIES = "SERIES"
    MOVIE = "MOVIE"
    RADIO = "RADIO"

@dataclass
class Content:
    """
    Base dataclass for all provider content (channels, events, etc.)
    Contains all fields shared between content types.
    """

    # Core identification
    name: str
    content_id: str
    provider: str

    # Visual
    logo_url: Optional[str] = None

    # Streaming configuration
    mode: str = "live"
    session_manifest: bool = False
    manifest: Optional[str] = None
    manifest_script: Optional[str] = None

    # DRM/CDM settings
    cdm_type: Optional[str] = None
    use_cdm: bool = True
    cdm: Optional[str] = None
    cdm_mode: str = "external"
    drm_config: Optional[DRMConfig] = None

    # Video settings
    video: str = "best"
    on_demand: bool = True
    speed_up: bool = True

    # Metadata
    quality: Optional[str] = None
    content_type: str = "LIVE"
    description: Optional[str] = None
    genre: Optional[str] = None
    language: str = "de"
    country: str = "DE"

    # Streaming URLs
    license_url: Optional[str] = None
    certificate_url: Optional[str] = None
    streaming_format: Optional[str] = None

    # Pricing (None = UNKNOWN, NOT FREE)
    pricing: Optional[Pricing] = None

    def __post_init__(self):
        """Validate pricing and mode consistency."""
        if not self.pricing:
            return

        # Define mode mappings
        live_types: Set[AccessType] = {
            AccessType.PPV_LIVE,
            AccessType.PPV_REPLAY,
            AccessType.SVOD_PPV,
            AccessType.AVOD
        }
        vod_types: Set[AccessType] = {
            AccessType.TVOD_RENTAL,
            AccessType.TVOD_PURCHASE
        }

        # Check mode consistency
        if self.pricing.access_type in live_types and self.mode != StreamingMode.LIVE:
            raise ValueError(
                f"Content '{self.name}' has {self.pricing.access_type.value} pricing "
                f"but mode is '{self.mode}' (expected '{StreamingMode.LIVE}')"
            )
        elif self.pricing.access_type in vod_types and self.mode != StreamingMode.VOD:
            raise ValueError(
                f"Content '{self.name}' has {self.pricing.access_type.value} pricing "
                f"but mode is '{self.mode}' (expected '{StreamingMode.VOD}')"
            )

    # --- Pricing Properties ---

    @property
    def is_free(self) -> Optional[bool]:
        """Returns None if pricing is unknown."""
        if not self.pricing:
            return None
        return self.pricing.is_free_at_point_of_use

    @property
    def requires_subscription(self) -> Optional[bool]:
        if not self.pricing:
            return None
        return self.pricing.requires_subscription

    @property
    def requires_payment(self) -> Optional[bool]:
        if not self.pricing:
            return None
        return self.pricing.requires_transactional_payment

    @property
    def has_pricing(self) -> bool:
        """Check if pricing is set."""
        return self.pricing is not None

    # --- Pricing Helpers ---

    def set_free(self) -> None:
        """Mark content as free."""
        self.pricing = Pricing(access_type=AccessType.FREE)

    def set_subscription(self, tiers: Optional[List[str]] = None, bouquets: Optional[List[str]] = None) -> None:
        """Mark content as subscription-only."""
        self.pricing = Pricing(
            access_type=AccessType.SVOD,
            required_tiers=tiers or [],
            required_bouquets=bouquets or []
        )

    def set_ppv(self, amount: Decimal, currency: str = "EUR",
                access_type: AccessType = AccessType.PPV_LIVE, **kwargs) -> None:
        """Mark content as PPV (live or replay)."""
        if access_type not in (AccessType.PPV_LIVE, AccessType.PPV_REPLAY):
            raise ValueError("access_type must be PPV_LIVE or PPV_REPLAY")
        self.pricing = Pricing(
            access_type=access_type,
            price_points=[PricePoint(amount=amount, currency=currency, **kwargs)]
        )

    def set_rental(self, amount: Decimal, currency: str = "EUR",
                   rental_duration_hours: int = 48, **kwargs) -> None:
        """Mark content as TVOD rental."""
        self.pricing = Pricing(
            access_type=AccessType.TVOD_RENTAL,
            rental_duration_hours=rental_duration_hours,
            price_points=[PricePoint(amount=amount, currency=currency, **kwargs)]
        )

    def set_purchase(self, amount: Decimal, currency: str = "EUR", **kwargs) -> None:
        """Mark content as EST purchase (buy-to-own)."""
        self.pricing = Pricing(
            access_type=AccessType.TVOD_PURCHASE,
            price_points=[PricePoint(amount=amount, currency=currency, **kwargs)]
        )

    # --- Manifest & DRM Methods ---

    def set_static_manifest(self, manifest_url: str) -> None:
        """Set a static manifest URL."""
        self.manifest = manifest_url
        self.session_manifest = False
        self.manifest_script = None

    def set_dynamic_manifest(self, manifest_script_params: str) -> None:
        """Set dynamic manifest parameters fetched at request time."""
        self.manifest = None
        self.session_manifest = True
        self.manifest_script = manifest_script_params

    def get_streaming_urls(self) -> List[str]:
        """Return all relevant URLs."""
        urls = []
        if self.manifest:
            urls.append(self.manifest)
        if self.license_url:
            urls.append(self.license_url)
        if self.certificate_url:
            urls.append(self.certificate_url)
        return urls

    def requires_drm(self) -> bool:
        return bool(self.drm_config) or bool(self.license_url)

    @property
    def dynamic_manifest(self) -> bool:
        return self.session_manifest

    @dynamic_manifest.setter
    def dynamic_manifest(self, value: bool):
        self.session_manifest = value

    @property
    def requires_session_manifest(self) -> bool:
        return self.session_manifest

    # --- Serialization ---

    def to_dict(self) -> Dict:
        result = {
            "Name": self.name,
            "Id": self.content_id,
            "Provider": self.provider,
            "LogoUrl": self.logo_url,
            "Quality": self.quality,
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
            "ContentType": self.content_type,
            "Country": self.country,
            "Language": self.language,
            "StreamingFormat": self.streaming_format,
            "LicenseUrl": self.license_url,
            "CertificateUrl": self.certificate_url,
            # Pricing derived fields
            "IsFree": self.is_free,
            "RequiresSubscription": self.requires_subscription,
            "RequiresPayment": self.requires_payment,
            "HasPricing": self.has_pricing,
        }
        if self.drm_config:
            result["DrmConfig"] = self.drm_config.to_dict()
        if self.pricing:
            result["Pricing"] = self.pricing.to_dict()
        return result