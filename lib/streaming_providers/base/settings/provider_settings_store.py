# streaming_providers/base/settings/provider_settings_store.py
"""
Small per-provider, per-country settings store (provider_settings.json).

Holds user *choices* (e.g. which client a provider emulates). Deliberately
separate from session.json (volatile state: tokens, device ids — safe to
wipe) and from credentials (secrets).

Layout mirrors session.json:  {provider: {country: {key: value}}}
"""
from typing import Any, Optional

from ..utils.logger import logger
from ..utils.vfs import VFS


class ProviderSettingsStore:
    FILE = "provider_settings.json"

    def __init__(self, config_dir: Optional[str] = None):
        self.vfs = VFS()
        if config_dir:
            self.vfs._base_path = config_dir
        self.vfs.mkdirs("")

    def get(self, provider: str, country: str, key: str, default: Any = None) -> Any:
        data = self.vfs.read_json(self.FILE) or {}
        provider_data = data.get(provider)
        country_data = provider_data.get(country) if isinstance(provider_data, dict) else None
        if not isinstance(country_data, dict):
            return default
        return country_data.get(key, default)

    def set(self, provider: str, country: str, key: str, value: Any) -> bool:
        data = self.vfs.read_json(self.FILE) or {}
        provider_data = data.get(provider)
        if not isinstance(provider_data, dict):
            provider_data = data[provider] = {}
        country_data = provider_data.get(country)
        if not isinstance(country_data, dict):
            country_data = provider_data[country] = {}
        country_data[key] = value
        ok = self.vfs.write_json(self.FILE, data)
        if not ok:
            logger.error(f"Failed to write {self.FILE}")
        return ok

    def clear(self, provider: str, country: str, key: str) -> bool:
        data = self.vfs.read_json(self.FILE) or {}
        country_data = (data.get(provider) or {}).get(country)
        if isinstance(country_data, dict) and key in country_data:
            del country_data[key]
            return self.vfs.write_json(self.FILE, data)
        return True