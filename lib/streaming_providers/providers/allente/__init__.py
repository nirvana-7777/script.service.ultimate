# streaming_providers/providers/allente/__init__.py
"""
Allente streaming provider module (SE only in v1).

Public API:
    from streaming_providers.providers.allente import (
        AllenteProvider,
        AllenteOTPRequiredError,
    )
"""

from .auth import AllenteOTPRequiredError
from .provider import AllenteProvider

__all__ = ["AllenteProvider", "AllenteOTPRequiredError"]