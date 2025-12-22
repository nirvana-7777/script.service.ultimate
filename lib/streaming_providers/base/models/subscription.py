"""
Subscription models for provider packages and user entitlements.
"""
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SubscriptionPackage:
    """Represents a subscription package with provider-specific naming"""

    package_id: str
    """Internal ID (e.g., 'sports_package_2024', 'joyn_plus')"""

    name: str
    """Display name (e.g., 'Sports Package', 'Sky Sport', 'Joyn Plus')"""

    description: Optional[str] = None
    """Optional description of the package"""

    price_info: Optional[str] = None
    """Optional price information (e.g., '€9.99/month', 'included')"""

    channel_ids: List[str] = field(default_factory=list)
    """List of channel IDs included in this package"""

    metadata: Dict[str, any] = field(default_factory=dict)
    """Provider-specific metadata (e.g., {'sky_id': 'SPORT1', 'category': 'sports'})"""

    @property
    def channel_count(self) -> int:
        """Number of channels in this package"""
        return len(self.channel_ids)


@dataclass
class UserSubscription:
    """User's subscription status for a provider"""

    provider: str
    """Provider name (e.g., 'joyn', 'magenta')"""

    country: str
    """Country code (e.g., 'DE', 'AT')"""

    active: bool = False
    """Whether the subscription is currently active"""

    packages: List[SubscriptionPackage] = field(default_factory=list)
    """All subscription packages the user has access to"""

    accessible_channel_ids: Set[str] = field(default_factory=set)
    """Set of all channel IDs the user can access (derived from packages)"""

    valid_from: Optional[datetime] = None
    """When the subscription becomes/starts valid"""

    valid_until: Optional[datetime] = None
    """When the subscription expires"""

    status_message: Optional[str] = None
    """Human-readable status message (e.g., 'Active until 2024-12-31')"""

    billing_status: Optional[str] = None
    """Billing status (e.g., 'paid', 'trial', 'expired', 'cancelled')"""

    def __post_init__(self):
        """Populate derived fields after initialization"""
        self._update_derived_fields()

    def _update_derived_fields(self):
        """Update derived fields like accessible_channel_ids"""
        self.accessible_channel_ids.clear()
        for package in self.packages:
            self.accessible_channel_ids.update(package.channel_ids)

    @property
    def has_packages(self) -> bool:
        """Check if user has any packages"""
        return len(self.packages) > 0

    @property
    def package_count(self) -> int:
        """Number of packages"""
        return len(self.packages)

    @property
    def accessible_channel_count(self) -> int:
        """Number of accessible channels"""
        return len(self.accessible_channel_ids)

    @property
    def package_names(self) -> List[str]:
        """List of package names for display"""
        return [pkg.name for pkg in self.packages]

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'provider': self.provider,
            'country': self.country,
            'active': self.active,
            'has_packages': self.has_packages,
            'package_count': self.package_count,
            'package_names': self.package_names,
            'accessible_channel_count': self.accessible_channel_count,
            'valid_from': self.valid_from.isoformat() if self.valid_from else None,
            'valid_until': self.valid_until.isoformat() if self.valid_until else None,
            'status_message': self.status_message,
            'billing_status': self.billing_status,
            'packages': [
                {
                    'package_id': pkg.package_id,
                    'name': pkg.name,
                    'description': pkg.description,
                    'price_info': pkg.price_info,
                    'channel_count': pkg.channel_count,
                    'metadata': pkg.metadata
                }
                for pkg in self.packages
            ]
        }

    def add_package(self, package: SubscriptionPackage):
        """Add a package and update derived fields"""
        self.packages.append(package)
        self._update_derived_fields()

    def can_access_channel(self, channel_id: str) -> bool:
        """Check if user can access a specific channel"""
        return channel_id in self.accessible_channel_ids