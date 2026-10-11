# streaming_providers/base/testing/provider_contract.py
"""
Provider contract -- checks every v2 (ManagedProvider) provider must pass.

    from streaming_providers.base.testing.provider_contract import check_provider
    problems, warnings = check_provider(ExampleProvider, "example")
    assert problems == []

It instantiates the provider with a NETWORK-DISABLED http manager (every call
raises ConnectionError), so it also proves that the constructor performs no
network I/O. Nothing here talks to a real backend.

Errors (must be fixed) vs warnings (advisory):

  errors
    * class is a ManagedProvider; explicit HEADERS_FROM_MANAGERS in the class
      body (the decision must be visible, not inherited)
    * instantiation works offline with country = first SUPPORTED_COUNTRIES
      (plus `ctor_kwargs` for providers whose constructor requires more)
    * provider_name == registry key, get_plugin_key() == registry key
    * capability flags agree with the managers that exist
    * DRM declared: a manager overrides get_*_drm  =>  DRM_IN_MANAGERS or
      _build_drm(); DRM_IN_MANAGERS=True with no manager implementing it is
      a mistake; both at once is refused by ManagedProvider itself
    * header hooks overridden on a manager  =>  HEADERS_FROM_MANAGERS must be
      True (otherwise the hooks are dead code)
    * EPG: no manager => epg_window == (0, 0); manager => implements_epg agrees
      with epg_window != (0, 0)
    * recordings: schedule_recording overridden => supports_scheduling True
    * the provider package exports only the provider in __all__ and does not
      expose ManagedProvider in its namespace (discovery picks the first
      StreamingProvider subclass it finds)
  warnings
    * country not normalised to lowercase after construction
    * empty SUPPORTED_COUNTRIES, empty PROVIDER_LABEL
"""

import sys
from contextlib import contextmanager
from typing import List, Optional, Tuple
from unittest import mock

from ..managed_provider import ManagedProvider
from ..managers import CatchupManager, ChannelManager, VodManager


class NullHttp:
    """HTTP manager that fails every call: proves 'no network in __init__'."""

    def __getattr__(self, name):
        def _blocked(*args, **kwargs):
            raise ConnectionError(f"network disabled in contract test ({name})")
        return _blocked


@contextmanager
def _offline(cls):
    with mock.patch.object(cls, "_setup_http_manager", lambda self, **kw: NullHttp(), create=True):
        yield


def _overrides(obj, abc, name) -> bool:
    return obj is not None and getattr(type(obj), name) is not getattr(abc, name)


def check_provider(cls, key: str, ctor_kwargs: Optional[dict] = None) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []

    if not (isinstance(cls, type) and issubclass(cls, ManagedProvider)):
        return [f"{cls!r} is not a ManagedProvider subclass"], warnings

    declared = [
        k for k in cls.__mro__
        if k is not ManagedProvider and issubclass(k, ManagedProvider)
        and "HEADERS_FROM_MANAGERS" in vars(k)
    ]
    if not declared:
        errors.append("HEADERS_FROM_MANAGERS is not declared in the class body "
                      "(decide: True = manager header hooks, False = legacy {})")

    countries = list(getattr(cls, "SUPPORTED_COUNTRIES", []) or [])
    if not countries:
        warnings.append("SUPPORTED_COUNTRIES is empty (single-country default)")
    if not getattr(cls, "PROVIDER_LABEL", ""):
        warnings.append("PROVIDER_LABEL is empty")

    try:
        with _offline(cls):
            # ctor_kwargs: constructor arguments a provider REQUIRES beyond
            # `country` (e.g. Joyn's config object); they override the default.
            kwargs = {"country": countries[0] if countries else "DE", **(ctor_kwargs or {})}
            inst = cls(**kwargs)
    except Exception as exc:   # noqa: BLE001 - report, don't crash the suite
        return errors + [f"cannot instantiate offline: {type(exc).__name__}: {exc}"], warnings

    if inst.provider_name != key:
        errors.append(f"provider_name {inst.provider_name!r} != registry key {key!r}")
    try:
        if cls.get_plugin_key() != key:
            errors.append(f"get_plugin_key() {cls.get_plugin_key()!r} != registry key {key!r}")
    except Exception as exc:   # noqa: BLE001
        errors.append(f"get_plugin_key() failed: {exc}")
    if inst.country != inst.country.lower():
        warnings.append(f"country {inst.country!r} is not lower-case after construction")

    # -- flags vs managers
    caps = inst.capabilities
    for name in ("channels", "vod", "recordings", "favorites", "bookmarks"):
        if caps[name] != (getattr(inst, name) is not None):
            errors.append(f"implements_{name} disagrees with the {name} manager")

    # -- DRM declaration
    folded = _overrides(inst.channels, ChannelManager, "get_channel_drm") or \
        _overrides(inst.vod, VodManager, "get_vod_drm")
    if folded and not (cls.DRM_IN_MANAGERS or inst.drm is not None):
        errors.append("a manager implements get_*_drm but DRM_IN_MANAGERS is False "
                      "and no _build_drm(): the DRM is never served")
    if cls.DRM_IN_MANAGERS and not folded:
        errors.append("DRM_IN_MANAGERS = True but no manager overrides get_channel_drm/get_vod_drm")

    # -- dead header hooks
    hooks = (
        _overrides(inst.channels, ChannelManager, "get_channel_manifest_headers"),
        _overrides(inst.channels, ChannelManager, "get_segment_headers"),
        _overrides(inst.vod, VodManager, "get_vod_manifest_headers"),
        _overrides(inst.vod, VodManager, "get_segment_headers"),
        _overrides(inst.catchup, CatchupManager, "get_catchup_manifest_headers"),
        _overrides(inst.catchup, CatchupManager, "get_catchup_segment_headers"),
    )
    if any(hooks) and not cls.HEADERS_FROM_MANAGERS:
        errors.append("a manager overrides header hooks but HEADERS_FROM_MANAGERS is False: "
                      "the hooks are dead code")

    # -- EPG
    if inst.epg is None:
        if inst.epg_window != (0, 0) or inst.implements_epg:
            errors.append("no EPG manager but epg_window != (0, 0) / implements_epg")
    elif inst.implements_epg != (inst.epg_window != (0, 0)):
        errors.append("implements_epg disagrees with epg_window != (0, 0)")

    # -- recordings
    if inst.recordings is not None:
        from ..managers import RecordingsManager
        if _overrides(inst.recordings, RecordingsManager, "schedule_recording") \
                and not inst.recordings.supports_scheduling:
            errors.append("schedule_recording is overridden but supports_scheduling is False")

    # -- package namespace (discovery safety)
    package = sys.modules.get(cls.__module__.rsplit(".", 1)[0])
    if package is not None:
        exported = getattr(package, "__all__", None)
        if exported is None or cls.__name__ not in exported:
            errors.append("package __init__ must define __all__ containing the provider class")
        if hasattr(package, "ManagedProvider"):
            errors.append("package namespace exposes ManagedProvider (discovery could pick it)")

    return errors, warnings