"""Shared AuthType enum.

Pulled out of provider.py into its own module so that provider.py and the
provider_mixins package can both import it without a circular import
(provider.py composes the mixins; the mixins need AuthType).

`from streaming_providers.base.provider import AuthType` still works —
provider.py re-exports it — so no existing import site needs to change.
"""

from enum import Enum


class AuthType(Enum):
    """Authentication token types"""

    BEARER = "bearer"
    BASIC = "basic"
    CLIENT = "client"
    CUSTOM = "custom"
    NONE = "none"