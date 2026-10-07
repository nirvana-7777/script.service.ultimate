# streaming_providers/base/managers/_base.py
"""
ManagerBase -- private common base of the seven manager ABCs.

Before this module, the constructor and the AuthProtocol sanity check were
copy-pasted into every manager file (seven copies of the same 15 lines, the
same warning text). One copy now lives here.

Private on purpose (leading underscore, not exported from
managers/__init__.py): providers subclass ChannelManager, VodManager and
so on, never ManagerBase itself.

Constructor contract (unchanged from the per-file versions)
-----------------------------------------------------------
Four required keyword-only collaborators. No **kwargs: a typo at a call
site becomes an immediate TypeError. Subclasses that need extra state
declare additional keyword-only args, call super().__init__ with ONLY the
four required ones, and store the extras on self afterwards.
"""

from __future__ import annotations

from abc import ABC
from typing import Any

from ..protocols import AuthProtocol
from ..utils.logger import logger


class ManagerBase(ABC):
    """Shared constructor + collaborator attributes for every manager ABC."""

    def __init__(
        self,
        *,
        http_manager: Any,
        auth: AuthProtocol,
        country: str,
        config: Any,
    ) -> None:
        # isinstance on a runtime_checkable Protocol only verifies method
        # presence, not signatures -- that is the intended check here.
        if not isinstance(auth, AuthProtocol):
            logger.warning(
                f"{self.__class__.__name__}: auth does not match AuthProtocol "
                f"(missing one of get_access_token / build_headers / "
                f"invalidate). Got {type(auth).__name__}."
            )
        self.http_manager = http_manager
        self.auth = auth
        self.country = country
        self.config = config