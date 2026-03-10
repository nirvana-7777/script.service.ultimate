# streaming_providers/providers/globals.py
# ============================================================================
# Global User Agent Registry
#
# Provides current, browser-accurate user agent strings for all providers.
# Chrome/Chromium version is fetched live from the official version API;
# other browsers track their own versioning but share the same Blink engine
# version where applicable.
#
# Usage:
#   from providers.globals import get_user_agent
#
#   get_user_agent("linux",   "chrome")          # Desktop Chrome on Linux
#   get_user_agent("windows", "edge")            # Desktop Edge on Windows
#   get_user_agent("windows", "chrome")          # Desktop Chrome on Windows
#   get_user_agent("macos",   "safari")          # Safari on macOS
#   get_user_agent("android", "chrome")          # Chrome for Android
#   get_user_agent("android", "dalvik")          # Android system HTTP client
#   get_user_agent("ios",     "safari")          # Mobile Safari on iOS
#   get_user_agent("firetv",  "chrome")          # Fire TV (AFTS) WebView
# ============================================================================

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from functools import lru_cache
from typing import Literal, Optional

from ..base.utils.logger import logger

# ---------------------------------------------------------------------------
# Version constants — updated whenever this file is refreshed.
# These serve as fallbacks when the live fetch fails.
# ---------------------------------------------------------------------------

_CHROME_FALLBACK_VERSION = "146.0.7657.48"   # Stable as of 2026-03-10
_EDGE_FALLBACK_VERSION   = "145.0.3800.97"   # Stable as of 2026-03-09
_SAFARI_FALLBACK_VERSION = "18.3"             # Safari 18.3 / WebKit 619
_WEBKIT_FALLBACK_BUILD   = "605.1.15"
_IOS_FALLBACK_VERSION    = "18.3.2"
_MACOS_FALLBACK_VERSION  = "14_4"            # Sonoma 14.4
_ANDROID_FALLBACK_VERSION = "13"

# Google VersionHistory API — https://versionhistory.googleapis.com/v1/
# Path structure: /v1/chrome/{platform}/channels/stable/versions
# Platform slugs: "linux" and "win". Edge is Chromium-based and ships the same
# version, so we reuse these fetches for Edge UA strings too.
# No auth required.
_CHROME_LINUX_VERSION_API = (
    "https://versionhistory.googleapis.com/v1/chrome/linux"
    "/channels/stable/versions?order_by=version+desc&pageSize=1"
)
_CHROME_WIN_VERSION_API = (
    "https://versionhistory.googleapis.com/v1/chrome/win"
    "/channels/stable/versions?order_by=version+desc&pageSize=1"
)

# Thread-safe one-time fetches — one slot per platform.
# Separate locks so linux and win fetches run concurrently at startup.
_linux_lock     = threading.Lock()
_win_lock       = threading.Lock()
_linux_ready    = threading.Event()
_win_ready      = threading.Event()
_linux_version: Optional[str] = None
_win_version:   Optional[str] = None


def _fetch_version_get(api_url: str, fallback: str, label: str) -> str:
    """
    Fetch a version from the Google VersionHistory API (GET).
    Response shape: {"versions": [{"version": "X.Y.Z.W", ...}]}
    Returns the fallback constant on any network or parse error.
    """
    try:
        req = urllib.request.Request(api_url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
        version = data["versions"][0]["version"]
        logger.debug(f"Fetched live {label} version: {version}")
        return version
    except Exception as exc:
        logger.warning(
            f"Could not fetch {label} version from API ({exc}); "
            f"using fallback {fallback}"
        )
        return fallback


def _fetch_linux_version() -> str:
    """Return the latest stable Chrome/linux version, fetched exactly once."""
    global _linux_version
    if not _linux_ready.is_set():
        with _linux_lock:
            if not _linux_ready.is_set():
                _linux_version = _fetch_version_get(
                    _CHROME_LINUX_VERSION_API, _CHROME_FALLBACK_VERSION, "chrome/linux"
                )
                _linux_ready.set()
        _linux_ready.wait()
    return _linux_version  # type: ignore[return-value]


def _fetch_win_version() -> str:
    """Return the latest stable Chrome/win version, fetched exactly once."""
    global _win_version
    if not _win_ready.is_set():
        with _win_lock:
            if not _win_ready.is_set():
                _win_version = _fetch_version_get(
                    _CHROME_WIN_VERSION_API, _CHROME_FALLBACK_VERSION, "chrome/win"
                )
                _win_ready.set()
        _win_ready.wait()
    return _win_version  # type: ignore[return-value]



# ---------------------------------------------------------------------------
# OS token helpers
# ---------------------------------------------------------------------------

def _win_token() -> str:
    return "Windows NT 10.0; Win64; x64"


def _linux_token() -> str:
    return "X11; Linux x86_64"


def _macos_token() -> str:
    return f"Macintosh; Intel Mac OS X {_MACOS_FALLBACK_VERSION}"


def _android_token(version: str = _ANDROID_FALLBACK_VERSION) -> str:
    return f"Linux; Android {version}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

OS  = Literal["windows", "linux", "macos", "android", "ios", "firetv", "androidtv", "androidmobile"]
UA  = Literal["chrome", "edge", "safari", "dalvik", "firefox"]


@lru_cache(maxsize=None)
def get_user_agent(os: OS, browser: UA) -> str:
    """
    Return a current, standards-compliant user agent string.

    Parameters
    ----------
    os:
        Target operating system / device class.
        One of: "windows", "linux", "macos", "android", "ios",
                "firetv", "androidtv", "androidmobile"
    browser:
        Browser / HTTP client.
        One of: "chrome", "edge", "safari", "dalvik", "firefox"

    Returns
    -------
    str
        A fully formed User-Agent string.

    Raises
    ------
    ValueError
        When the (os, browser) combination is unsupported.
    """
    cv_linux = _fetch_linux_version()          # e.g. "146.0.7657.48"
    cv_win   = _fetch_win_version()            # e.g. "146.0.7657.48" (may differ slightly)
    blink    = "537.36"                        # frozen — all Chromium UA strings use this

    # ------------------------------------------------------------------
    # Chrome on desktop
    # ------------------------------------------------------------------
    if browser == "chrome":
        if os == "linux":
            return (
                f"Mozilla/5.0 ({_linux_token()}) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_linux} Safari/{blink}"
            )
        if os == "windows":
            return (
                f"Mozilla/5.0 ({_win_token()}) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_win} Safari/{blink}"
            )
        if os == "macos":
            return (
                f"Mozilla/5.0 ({_macos_token()}) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_win} Safari/{blink}"
            )
        if os == "android":
            av = _ANDROID_FALLBACK_VERSION
            return (
                f"Mozilla/5.0 ({_android_token(av)}) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_linux} Mobile Safari/{blink}"
            )
        if os == "androidmobile":
            av = _ANDROID_FALLBACK_VERSION
            return (
                f"Mozilla/5.0 (Linux; Android {av}; SM-G991B) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_linux} Mobile Safari/{blink}"
            )
        if os == "androidtv":
            return (
                f"Mozilla/5.0 (Linux; Android {_ANDROID_FALLBACK_VERSION}; SHIELD Android TV) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_linux} Safari/{blink}"
            )
        if os == "firetv":
            return (
                f"Mozilla/5.0 (Linux; Android {_ANDROID_FALLBACK_VERSION}; AFTS Build/PPR1.180610.011) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_linux} Safari/{blink}"
            )

    # ------------------------------------------------------------------
    # Microsoft Edge (Chromium-based) — reuses Chrome versions from the
    # same VersionHistory API: win slug for Windows/macOS, linux for Linux.
    # ------------------------------------------------------------------
    if browser == "edge":
        if os == "windows":
            return (
                f"Mozilla/5.0 ({_win_token()}) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_win} Safari/{blink} "
                f"Edg/{cv_win}"
            )
        if os == "linux":
            return (
                f"Mozilla/5.0 ({_linux_token()}) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_linux} Safari/{blink} "
                f"Edg/{cv_linux}"
            )
        if os == "macos":
            return (
                f"Mozilla/5.0 ({_macos_token()}) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_win} Safari/{blink} "
                f"Edg/{cv_win}"
            )

    # ------------------------------------------------------------------
    # Apple Safari
    # ------------------------------------------------------------------
    if browser == "safari":
        if os == "macos":
            sv = _SAFARI_FALLBACK_VERSION  # "18.3"
            wk = _WEBKIT_FALLBACK_BUILD    # "605.1.15"
            return (
                f"Mozilla/5.0 ({_macos_token()}) "
                f"AppleWebKit/{wk} (KHTML, like Gecko) "
                f"Version/{sv} Safari/{wk}"
            )
        if os == "ios":
            ios = _IOS_FALLBACK_VERSION    # "18.3.2"
            ios_ua = ios.replace(".", "_")
            sv  = _SAFARI_FALLBACK_VERSION
            wk  = _WEBKIT_FALLBACK_BUILD
            return (
                f"Mozilla/5.0 (iPhone; CPU iPhone OS {ios_ua} like Mac OS X) "
                f"AppleWebKit/{wk} (KHTML, like Gecko) "
                f"Version/{sv} Mobile/15E148 Safari/{wk}"
            )

    # ------------------------------------------------------------------
    # Android Dalvik (system HTTP client — used by native Android apps)
    # ------------------------------------------------------------------
    if browser == "dalvik":
        if os in ("android", "androidtv", "androidmobile", "firetv"):
            # e.g. Dalvik/2.1.0 (Linux; U; Android 11; SHIELD Android TV …)
            build = "RQ1A.210105.003"
            return (
                f"Dalvik/2.1.0 (Linux; U; Android {_ANDROID_FALLBACK_VERSION}; "
                f"SHIELD Android TV Build/{build})"
            )

    raise ValueError(
        f"Unsupported (os={os!r}, browser={browser!r}) combination. "
        f"Supported OS values: windows, linux, macos, android, androidtv, androidmobile, ios, firetv. "
        f"Supported browser values: chrome, edge, safari, dalvik."
    )


def invalidate_version_cache() -> None:
    """
    Force a re-fetch of all versions on next call.
    Useful for long-running processes that want to pick up a new release.
    """
    global _linux_version, _win_version
    with _linux_lock:
        _linux_version = None
        _linux_ready.clear()
    with _win_lock:
        _win_version = None
        _win_ready.clear()
    get_user_agent.cache_clear()


# ---------------------------------------------------------------------------
# Eager background prefetch — runs once at import time.
# Both platform fetches run concurrently (daemon threads, never block shutdown).
# ---------------------------------------------------------------------------

def _prefetch_all() -> None:
    for target, name in (
        (_fetch_linux_version, "prefetch-chrome-linux"),
        (_fetch_win_version,   "prefetch-chrome-win"),
    ):
        threading.Thread(target=target, daemon=True, name=name).start()


_prefetch_all()