# streaming_providers/base/models/pricing.py
from decimal import Decimal
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict
from .quality import Quality


class AccessType(Enum):
    """How content can be accessed monetarily."""
    FREE = "free"  # No payment, no ads
    AVOD = "avod"  # Ad-supported free
    SVOD = "svod"  # Subscription included
    TVOD_RENTAL = "tvod_rental"  # Time-limited rental
    TVOD_PURCHASE = "tvod_purchase"  # Buy-to-own (EST)
    PPV_LIVE = "ppv_live"  # Pay-per-view live event
    PPV_REPLAY = "ppv_replay"  # Pay-per-view replay window
    SVOD_PPV = "svod_ppv"  # Subscription + extra PPV surcharge


@dataclass
class PricePoint:
    """A specific price for a region/quality/time period."""
    amount: Decimal
    currency: str  # ISO 4217
    sku: Optional[str] = None  # Billing system ID
    quality: Optional[Quality] = None  # "SD", "HD", "4K"
    region: Optional[str] = None  # "DE", "AT", "CH", etc.
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    tax_inclusive: bool = True  # EU requirement

    def is_active(self, at: Optional[datetime] = None) -> bool:
        """Check if this price point is currently valid."""
        now = at or datetime.now()
        if self.valid_from and now < self.valid_from:
            return False
        if self.valid_until and now > self.valid_until:
            return False
        return True


@dataclass
class Pricing:
    """
    Monetization model for content.

    None/unknown pricing should never be treated as free - this is a revenue-leak
    risk. Always handle unknown explicitly in entitlement checks.
    """

    # Access model
    access_type: AccessType  # No default - must be explicit

    # Price points (empty for FREE/AVOD/SVOD)
    price_points: List[PricePoint] = field(default_factory=list)

    # Subscription gates (ANY grants access)
    required_tiers: List[str] = field(default_factory=list)  # "premium", "basic"
    required_bouquets: List[str] = field(default_factory=list)  # "sports", "movies"

    # Time windows (hours)
    rental_duration_hours: Optional[int] = None  # TVOD_RENTAL
    catchup_duration_hours: Optional[int] = None  # Linear catch-up feature
    replay_window_hours: Optional[int] = None  # PPV event replay
    preview_minutes: Optional[int] = None  # Free preview

    # SVOD_PPV specific
    ppv_is_surcharge: bool = True  # True = extra on top of subscription

    # Metadata
    description: Optional[str] = None  # UI display text
    tax_class: Optional[str] = None  # VAT rate group

    # --- Derived predicates ---

    @property
    def is_free_at_point_of_use(self) -> bool:
        """User pays nothing at consumption time."""
        return self.access_type in (AccessType.FREE, AccessType.AVOD)

    @property
    def requires_subscription(self) -> bool:
        """User must have an active subscription."""
        return self.access_type in (AccessType.SVOD, AccessType.SVOD_PPV)

    @property
    def requires_transactional_payment(self) -> bool:
        """User must make a one-time payment."""
        return self.access_type in (
            AccessType.TVOD_RENTAL,
            AccessType.TVOD_PURCHASE,
            AccessType.PPV_LIVE,
            AccessType.PPV_REPLAY,
            AccessType.SVOD_PPV,
        )

    @property
    def is_ad_supported(self) -> bool:
        """Content includes ads (FAST/AVOD)."""
        return self.access_type == AccessType.AVOD

    @property
    def has_time_limit(self) -> bool:
        """Access expires after a fixed time."""
        return (
                self.access_type == AccessType.TVOD_RENTAL
                or self.replay_window_hours is not None
        )

    @property
    def primary_price(self) -> Optional[PricePoint]:
        """Get the first active price point (simplified access)."""
        active = [p for p in self.price_points if p.is_active()]
        return active[0] if active else None

    def get_price_for_region(self, region: str, quality: Optional[str] = None) -> Optional[PricePoint]:
        """Get best matching price point for region/quality."""
        matches = [
            p for p in self.price_points
            if p.is_active() and p.region == region
        ]
        if quality:
            matches = [p for p in matches if p.quality == quality]
        return matches[0] if matches else None

    def to_dict(self) -> Dict:
        return {
            "access_type": self.access_type.value,
            "price_points": [
                {
                    "amount": str(p.amount),  # Decimal → str for JSON
                    "currency": p.currency,
                    "sku": p.sku,
                    "quality_label": p.quality,
                    "region": p.region,
                    "valid_from": p.valid_from.isoformat() if p.valid_from else None,
                    "valid_until": p.valid_until.isoformat() if p.valid_until else None,
                    "tax_inclusive": p.tax_inclusive,
                }
                for p in self.price_points
            ],
            "required_tiers": self.required_tiers,
            "required_bouquets": self.required_bouquets,
            "rental_duration_hours": self.rental_duration_hours,
            "catchup_duration_hours": self.catchup_duration_hours,
            "replay_window_hours": self.replay_window_hours,
            "preview_minutes": self.preview_minutes,
            "ppv_is_surcharge": self.ppv_is_surcharge,
            "description": self.description,
            "tax_class": self.tax_class,
            # Derived
            "is_free_at_point_of_use": self.is_free_at_point_of_use,
            "requires_subscription": self.requires_subscription,
            "requires_transactional_payment": self.requires_transactional_payment,
            "is_ad_supported": self.is_ad_supported,
            "has_time_limit": self.has_time_limit,
        }