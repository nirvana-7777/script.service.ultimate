# streaming_providers/providers/eon/persistence.py
"""
Glue between EonAuth and the framework's storage managers.

SessionStore   -- EonStore on top of SessionManager: one dict at
                  session.json[<provider>][<country>] (country LOWER-case, as
                  the managers key by it). STATELESS view: every get / set /
                  delete re-reads through SessionManager, so keys this process
                  did not write are preserved and the store never overwrites
                  the on-disk entry with a stale snapshot.
default_persistence() -- finds a SessionManager and a credentials loader the
                  way BaseAuthenticator does (injected settings manager, else
                  a SettingsManager of its own); anything missing degrades to
                  the non-durable MemoryStore / no stored credentials, with a
                  warning, never to an exception.

SessionManager logs every value of keys it does not know at INFO
(`Saving session data ...`): never hand this store a secret that can be
re-derived. EonAuth persists device identity and the refresh token only (the
refresh token is on SessionManager's mask list).

Why there is NO local cache here
--------------------------------
SessionManager.load_session re-reads session.json on every call and
save_session REPLACES the dict at session.json[provider][country]. A local
cache that is populated on the first read and written through on set would
therefore:

  * hide keys written to disk after the cache was populated (e.g. another
    provider, another process, or the same provider in a previous run), and
  * on the first set(), save the stale cache back and ERASE those keys.

That is exactly how an existing eon device identity got wiped and a new device
was registered (auth_device_forbidden). Read-modify-write on every mutation.
"""

import threading
from typing import Any, Callable, Dict, Optional, Tuple

from ...base.utils.logger import logger
from .auth import EonStore, MemoryStore


class SessionStore:
    """EonStore backed by SessionManager, with no local state.

    Each operation goes to SessionManager, which reads session.json and (for
    writes) replaces the provider/country sub-dict. The re-read inside
    set_many / delete makes the write a merge into the CURRENT on-disk state
    instead of a write-through of a snapshot taken at process start.
    """

    def __init__(self, session_manager: Any, provider: str, country: Optional[str]):
        self._sm = session_manager
        self._provider = provider
        # Normalise here: a caller passing "BA" must not open a parallel
        # eon.BA subtree next to the eon.ba one the managers use.
        self._country = country.lower() if country else None
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    def _read(self) -> Dict[str, str]:
        """Current on-disk dict for provider/country (never cached)."""
        loaded = self._sm.load_session(self._provider, self._country)
        if not loaded:
            return {}
        return {k: v for k, v in loaded.items() if isinstance(v, str)}

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            return self._read().get(key)

    def set(self, key: str, value: str) -> None:
        self.set_many({key: value})

    def set_many(self, values: Dict[str, str]) -> None:
        with self._lock:
            data = self._read()
            if all(data.get(k) == v for k, v in values.items()):
                return
            data.update(values)
            if not self._sm.save_session(self._provider, data, self._country):
                logger.warning(f"{self._provider}: could not persist the session")

    def delete(self, key: str) -> None:
        with self._lock:
            data = self._read()
            if key not in data:
                return
            del data[key]
            if not self._sm.save_session(self._provider, data, self._country):
                logger.warning(f"{self._provider}: could not persist the session")


def default_persistence(
    *, provider: str, country: str, settings_manager: Any = None,
) -> Tuple[EonStore, Optional[Callable[[], Any]]]:
    """(store, credentials_loader); never raises.

    The SessionManager is the SHARED one when the settings manager exposes it;
    a fresh SessionManager() is only a last resort (it still reads the same
    session.json via VFS) and is logged, because a silently different store is
    how a provider ends up registering a brand-new device identity.
    """
    manager = settings_manager
    if manager is None:
        try:
            from ...base.settings.settings_manager import SettingsManager
            manager = SettingsManager(config_dir=None, enable_kodi_integration=True)
        except Exception as exc:
            logger.warning(f"{provider}: no settings manager ({exc!r})")
    if manager is not None and hasattr(manager, "register_provider"):
        try:
            manager.register_provider(provider)
        except Exception as exc:
            logger.warning(f"{provider}: could not register with the settings manager: {exc!r}")

    session_manager = getattr(manager, "session_manager", None) if manager is not None else None
    if session_manager is None:
        logger.warning(
            f"{provider}: settings manager exposes no session_manager; "
            f"creating a standalone SessionManager (same session.json, different instance)"
        )
        try:
            from ...base.auth.session_manager import SessionManager
            session_manager = SessionManager()
        except Exception as exc:
            logger.warning(
                f"{provider}: no SessionManager ({exc!r}); device identity is NOT persisted"
            )

    store: EonStore = (
        SessionStore(session_manager, provider, country) if session_manager is not None
        else MemoryStore()
    )

    loader: Optional[Callable[[], Any]] = None
    if manager is not None and hasattr(manager, "get_provider_credentials"):
        loader = lambda: manager.get_provider_credentials(provider, country)  # noqa: E731
    return store, loader