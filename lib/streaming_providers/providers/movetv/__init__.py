# streaming_providers/providers/movetv/__init__.py
"""
move.tv (MTS-SI) streaming provider.

Public API:
    from streaming_providers.providers.movetv import MoveTVProvider

Only the provider is public: discovery takes the FIRST StreamingProvider
subclass found in this namespace (README §5.7).
"""

from .provider import MoveTVProvider

__all__ = ["MoveTVProvider"]