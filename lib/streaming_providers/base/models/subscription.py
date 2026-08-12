# streaming_providers/base/models/subscription.py
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Any  # <-- Added Any

from .pricing import Pricing


@dataclass
class SubscriptionPackage:
    """Represents a subscription package (a purchasable bouquet/tier)."""

    package_id: str
    name: str

    tier: Optional[str] = None
    bouquet: Optional[str] = None
    pricing: Optional[Pricing] = None

    description: Optional[str] = None
    channel_ids: List[str] = field(default_factory=list)

    # Fix is here:
    metadata: Dict[str, Any] = field(default_factory=dict)
    """Provider-specific metadata"""

    @property
    def channel_count(self) -> int:
        return len(self.channel_ids)


@dataclass
class UserSubscription:
    """User's subscription status for a provider"""

    provider: str
    country: str

    active: bool = False
    """Whether the account subscription is currently active"""

    packages: List[SubscriptionPackage] = field(default_factory=list)
    """All subscription packages the user has purchased"""

    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    status_message: Optional[str] = None
    billing_status: Optional[str] = None

    def __post_init__(self):
        self._update_derived_fields()

    def _update_derived_fields(self):
        """Pre-calculate sets for fast entitlement checks"""
        self.accessible_channel_ids: Set[str] = set()
        self.active_tiers: Set[str] = set()
        self.active_bouquets: Set[str] = set()

        if not self.active or not self._is_currently_valid():
            return

        for package in self.packages:
            self.accessible_channel_ids.update(package.channel_ids)
            if package.tier:
                self.active_tiers.add(package.tier)
            if package.bouquet:
                self.active_bouquets.add(package.bouquet)

    def _is_currently_valid(self) -> bool:
        """Check if subscription is within valid date range"""
        now = datetime.now()
        if self.valid_from and now < self.valid_from:
            return False
        if self.valid_until and now > self.valid_until:
            return False
        return True

    # --- Entitlement Checks ---

    def has_tier(self, tier: str) -> bool:
        """Check if user has a specific tier"""
        return self.active and tier in self.active_tiers

    def has_bouquet(self, bouquet: str) -> bool:
        """Check if user has a specific bouquet"""
        return self.active and bouquet in self.active_bouquets

    def can_access_channel(self, channel_id: str) -> bool:
        """Check if user can access a specific channel"""
        return self.active and channel_id in self.accessible_channel_ids

    # --- Serialization ---

    def to_dict(self) -> Dict:
        return {
            "provider": self.provider,
            "country": self.country,
            "active": self.active,
            "has_packages": len(self.packages) > 0,
            "package_count": len(self.packages),
            "accessible_channel_count": len(self.accessible_channel_ids),
            "active_tiers": list(self.active_tiers),
            "active_bouquets": list(self.active_bouquets),
            "valid_from": self.valid_from.isoformat() if self.valid_from else None,
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
            "status_message": self.status_message,
            "billing_status": self.billing_status,
            "packages": [
                {
                    "package_id": pkg.package_id,
                    "name": pkg.name,
                    "tier": pkg.tier,
                    "bouquet": pkg.bouquet,
                    "pricing": pkg.pricing.to_dict() if pkg.pricing else None,
                    "channel_count": pkg.channel_count,
                }
                for pkg in self.packages
            ],
        }