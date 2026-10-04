# streaming_providers/providers/simpli/__init__.py
"""
simpliTV streaming provider.

Registered via directory-based discovery. The module-level import here
is what makes the provider visible to the host.
"""

from .provider import SimpliTVProvider

__all__ = ["SimpliTVProvider"]
