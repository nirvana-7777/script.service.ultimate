# streaming_providers/providers/eon/persistence.py
"""
Glue between EonAuth and the framework's storage managers.

SessionStore   -- EonStore on top of SessionManager: one dict at
                  session.json[<provider>][<country>] (country LOWER-case, as
                  the managers key by it). Read once, written through.
default_persistence() -- finds a SessionManager and a credentials loader the
                  way BaseAuthenticator does (injected settings manager, else
                  a SettingsManager of its own); anything missing degrades to
                  the non-durable MemoryStore / no stored credentials, with a
                  warning, never to an exception.

SessionManager logs every value of keys it does not know at INFO
(`Saving session data ...`): never hand this store a secret that can be
re-derived. EonAuth persists device identity and the refresh token only (the
refresh token is on SessionManager's mask list).
"""

import threading
from typing import Any, Callable, Dict, Optional, Tuple

from ...base.utils.logger import logger
from .auth import EonStore, MemoryStore


class SessionStore:
    def __init__(self, session_manager: Any, provider: str, country: Optional[str]):
        self._sm = session_manager
        self._provider = provider
        self._country = country or None
        self._lock = threading.RLock()
        self._cache: Optional[Dict[str, str]] = None

    def _data(self) -> Dict[str, str]:
        if self._cache is None:
            loaded = self._sm.load_session(self._provider, self._country)
            self._cache = {k: v for k, v in (loaded or {}).items() if isinstance(v, str)}
        return self._cache

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            return self._data().get(key)

    def set(self, key: str, value: str) -> None:
        self.set_many({key: value})

    def set_many(self, values: Dict[str, str]) -> None:
        with self._lock:
            data = self._data()
            if all(data.get(k) == v for k, v in values.items()):
                return
            data.update(values)
            self._save()

    def delete(self, key: str) -> None:
        with self._lock:
            data = self._data()
            if key in data:
                del data[key]
                self._save()

    def _save(self) -> None:
        # save_session REPLACES the dict at that path: write the whole cache.
        if not self._sm.save_session(self._provider, dict(self._data()), self._country):
            logger.warning(f"{self._provider}: could not persist the session")


def default_persistence(
    *, provider: str, country: str, settings_manager: Any = None,
) -> Tuple[EonStore, Optional[Callable[[], Any]]]:
    """(store, credentials_loader); never raises."""
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

    session_manager = getattr(manager, "session_manager", None)
    if session_manager is None:
        try:
            from ...base.auth.session_manager import SessionManager
            session_manager = SessionManager()
        except Exception as exc:
            logger.warning(f"{provider}: no SessionManager ({exc!r}); device identity is NOT persisted")

    store: EonStore = (
        SessionStore(session_manager, provider, country) if session_manager is not None
        else MemoryStore()
    )

    loader: Optional[Callable[[], Any]] = None
    if manager is not None and hasattr(manager, "get_provider_credentials"):
        loader = lambda: manager.get_provider_credentials(provider, country)  # noqa: E731
    return store, loader