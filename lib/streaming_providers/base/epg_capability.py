# lib/streaming_providers/base/epg_capability.py
"""
EPG capability flags and the shared legacy derivation.

Deliberately a leaf module (stdlib only): ProviderEpgMixin, ManagedProvider,
EPGOperations and the EpgManager ABC all need it, and importing it from
managers/epg.py would drag in managers/__init__ (all seven managers).
"""

from enum import Flag, auto


class EpgCapability(Flag):
    """Which EPG endpoints a provider can serve natively."""

    NONE = 0
    CHANNEL = auto()
    GRID = auto()
    DETAILS = auto()


# Flag members cannot reference each other inside the class body.
EPG_CAP_ALL = EpgCapability.CHANNEL | EpgCapability.GRID | EpgCapability.DETAILS


def derive_capabilities(owner, base, *, channel_implied: bool) -> EpgCapability:
    """
    Legacy derivation shared by EpgManager and ProviderEpgMixin: a capability
    counts when `owner`'s class overrides the matching method of `base`.

    channel_implied: True when `base.get_epg` is abstract (EpgManager): any
    implementing owner has a real get_epg, so CHANNEL is implied. False when
    `base.get_epg` has a do-nothing default (ProviderEpgMixin): it must be
    overridden to count.
    """
    if not owner.implements_epg:
        return EpgCapability.NONE
    cls = type(owner)
    caps = EpgCapability.CHANNEL if channel_implied else EpgCapability.NONE
    if cls.get_epg is not base.get_epg:
        caps |= EpgCapability.CHANNEL
    if cls.get_epg_grid is not base.get_epg_grid:
        caps |= EpgCapability.GRID
    if cls.get_program_details is not base.get_program_details:
        caps |= EpgCapability.DETAILS
    return caps
