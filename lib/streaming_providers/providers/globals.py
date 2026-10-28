# streaming_providers/providers/globals.py
# ============================================================================
# Global User Agent Registry
#
# Provides current, browser-accurate user agent strings for all providers.
# Chrome/Chromium version is fetched live from the official VersionHistory
# API per platform (linux / win / mac); other browsers track their own
# versioning but share the same Blink engine version where applicable.
#
# Usage:
#   from providers.globals import get_user_agent, get_identity
#
#   get_user_agent("linux",   "chrome")          # Desktop Chrome on Linux
#   get_user_agent("windows", "edge")            # Desktop Edge on Windows
#   get_user_agent("windows", "chrome")          # Desktop Chrome on Windows
#   get_user_agent("macos",   "safari")          # Safari on macOS
#   get_user_agent("android", "chrome")          # Chrome for Android
#   get_user_agent("android", "dalvik")          # Android system HTTP client
#   get_user_agent("ios",     "safari")          # Mobile Safari on iOS
#   get_user_agent("firetv",  "chrome")          # Fire TV (AFTS) WebView
#
#   ident = get_identity("linux", "chrome")      # BrowserIdentity struct
#   ident.user_agent, ident.chrome_major, ident.sec_ch_ua, ...
# ============================================================================

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal, Optional

from ..base.utils.logger import logger

# ---------------------------------------------------------------------------
# Version constants — updated whenever this file is refreshed.
# These serve as fallbacks when the live fetch fails.
#
# Stable versions as of 2026-10-28 (VersionHistory API):
#   linux   156.0.8078.73
#   win     157.0.8103.15   (Windows channel currently ahead of the others)
#   mac     156.0.8078.74
#   mac_arm64 156.0.8078.74
# ---------------------------------------------------------------------------

_CHROME_LINUX_FALLBACK_VERSION = "156.0.8078.73"
_CHROME_WIN_FALLBACK_VERSION   = "157.0.8103.15"
_CHROME_MAC_FALLBACK_VERSION   = "156.0.8078.74"

# Retained for callers that still reference a single Chrome fallback.
_CHROME_FALLBACK_VERSION = _CHROME_LINUX_FALLBACK_VERSION

_EDGE_FALLBACK_VERSION   = "157.0.8103.15"   # Edge tracks Chromium; same line as win
_SAFARI_FALLBACK_VERSION = "18.3"             # Safari 18.3 / WebKit 619
_WEBKIT_FALLBACK_BUILD   = "605.1.15"
_IOS_FALLBACK_VERSION    = "18.3.2"
_MACOS_FALLBACK_VERSION  = "14_4"            # Sonoma 14.4
_ANDROID_FALLBACK_VERSION = "13"

# Google VersionHistory API — https://versionhistory.googleapis.com/v1/
# Path structure: /v1/chrome/platforms/{platform}/channels/stable/versions
# Platform slugs: "linux", "win", "mac", "mac_arm64". Edge is Chromium-based
# and ships the same version, so we reuse these fetches for Edge UA strings.
# No auth required.
_CHROME_LINUX_VERSION_API = (
    "https://versionhistory.googleapis.com/v1/chrome/platforms/linux"
    "/channels/stable/versions?order_by=version+desc&pageSize=1"
)
_CHROME_WIN_VERSION_API = (
    "https://versionhistory.googleapis.com/v1/chrome/platforms/win"
    "/channels/stable/versions?order_by=version+desc&pageSize=1"
)
_CHROME_MAC_VERSION_API = (
    "https://versionhistory.googleapis.com/v1/chrome/platforms/mac"
    "/channels/stable/versions?order_by=version+desc&pageSize=1"
)

# Thread-safe one-time fetches — one slot per platform.
# Separate locks so linux/win/mac fetches run concurrently at startup.
_linux_lock     = threading.Lock()
_win_lock       = threading.Lock()
_mac_lock       = threading.Lock()
_linux_ready    = threading.Event()
_win_ready      = threading.Event()
_mac_ready      = threading.Event()
_linux_version: Optional[str] = None
_win_version:   Optional[str] = None
_mac_version:   Optional[str] = None


def _fetch_version_get(api_url: str, fallback: str, label: str) -> str:
    """
    Fetch a version from the Google VersionHistory API (GET).
    Response shape: {"versions": [{"version": "X.Y.Z.W", ...}]}
    Returns the fallback constant on any network or parse error.
    """
    try:
        req = urllib.request.Request(
            api_url,
            headers={
                "Accept": "application/json",
                # A plain Accept header gets rejected by some WAFs; a plausible
                # UA keeps the endpoint reachable from restrictive networks.
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/156.0.0.0 Safari/537.36"
                ),
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
        versions = [
            v["version"] for v in data.get("versions", []) if v.get("version")
        ]
        if not versions:
            raise ValueError("empty 'versions' array in response")
        # Do not trust the server-side order_by blindly: take the numeric max.
        latest = max(
            versions, key=lambda v: [int(p) for p in v.split(".") if p.isdigit()]
        )
        logger.debug(f"Fetched live {label} version: {latest}")
        return latest
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:300]
        logger.warning(
            f"Version API HTTP {exc.code} for {label} ({api_url}): {body}; "
            f"using fallback {fallback}"
        )
        return fallback
    except Exception as exc:
        logger.warning(
            f"Could not fetch {label} version from API "
            f"({type(exc).__name__}: {exc}); using fallback {fallback}"
        )
        return fallback


def _fetch_linux_version() -> str:
    """Return the latest stable Chrome/linux version, fetched exactly once."""
    global _linux_version
    if not _linux_ready.is_set():
        with _linux_lock:
            if not _linux_ready.is_set():
                _linux_version = _fetch_version_get(
                    _CHROME_LINUX_VERSION_API,
                    _CHROME_LINUX_FALLBACK_VERSION,
                    "chrome/linux",
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
                    _CHROME_WIN_VERSION_API,
                    _CHROME_WIN_FALLBACK_VERSION,
                    "chrome/win",
                )
                _win_ready.set()
        _win_ready.wait()
    return _win_version  # type: ignore[return-value]


def _fetch_mac_version() -> str:
    """Return the latest stable Chrome/mac version, fetched exactly once."""
    global _mac_version
    if not _mac_ready.is_set():
        with _mac_lock:
            if not _mac_ready.is_set():
                _mac_version = _fetch_version_get(
                    _CHROME_MAC_VERSION_API,
                    _CHROME_MAC_FALLBACK_VERSION,
                    "chrome/mac",
                )
                _mac_ready.set()
        _mac_ready.wait()
    return _mac_version  # type: ignore[return-value]


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
# Identity struct
# ---------------------------------------------------------------------------

OS = Literal["windows", "linux", "macos", "android", "ios", "firetv", "androidtv", "androidmobile"]
UA = Literal["chrome", "edge", "safari", "dalvik", "firefox"]


@dataclass(frozen=True)
class BrowserIdentity:
    """
    A coherent browser identity: the UA string, the client-hint values and the
    version tokens all derive from the SAME fetched version, so they cannot
    drift apart (a UA that says Chrome 154 next to hints that say 156 is a
    classic bot signature).
    """
    os: str
    browser: str
    chrome_major: str        # "156"
    chrome_full: str         # "156.0.8078.73"
    blink: str               # "537.36"
    user_agent: str
    sec_ch_ua: str           # '"Google Chrome";v="156", ...'
    sec_ch_ua_platform: str  # '"Linux"' | '"Windows"' | '"macOS"'
    device_name: str         # "Chrome 156"  (eon / movetv style)


def _sec_ch_ua(major: str) -> str:
    return (
        f'"Google Chrome";v="{major}", "Not_A Brand";v="8", '
        f'"Chromium";v="{major}"'
    )


def _sec_ch_platform(os_name: str) -> str:
    return {
        "windows": '"Windows"',
        "macos": '"macOS"',
        "linux": '"Linux"',
        "android": '"Android"',
        "androidtv": '"Android"',
        "androidmobile": '"Android"',
        "firetv": '"Android"',
        "ios": '"iOS"',
    }.get(os_name, '"Unknown"')


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@lru_cache(maxsize=None)
def get_identity(os: OS, browser: UA) -> BrowserIdentity:
    """
    Return a coherent BrowserIdentity for the given (os, browser) pair.

    The version tokens (chrome_major / chrome_full), the UA string, the
    sec-ch-ua hints and device_name are all derived from the SAME fetched
    version for the target platform, so they cannot drift apart.
    """
    # Pick the platform-specific version that matches the UA token we emit.
    cv_linux = _fetch_linux_version()          # e.g. "156.0.8078.73"
    cv_win   = _fetch_win_version()            # e.g. "157.0.8103.15"
    cv_mac   = _fetch_mac_version()            # e.g. "156.0.8078.74"
    blink    = "537.36"                        # frozen — all Chromium UA strings use this

    def _ident(os_name: str, ua: str, full: str) -> BrowserIdentity:
        major = full.split(".")[0]
        return BrowserIdentity(
            os=os_name,
            browser=browser,
            chrome_major=major,
            chrome_full=full,
            blink=blink,
            user_agent=ua,
            sec_ch_ua=_sec_ch_ua(major),
            sec_ch_ua_platform=_sec_ch_platform(os_name),
            device_name=f"Chrome {major}",
        )

    # ------------------------------------------------------------------
    # Chrome on desktop
    # ------------------------------------------------------------------
    if browser == "chrome":
        if os == "linux":
            ua = (
                f"Mozilla/5.0 ({_linux_token()}) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_linux} Safari/{blink}"
            )
            return _ident("linux", ua, cv_linux)
        if os == "windows":
            ua = (
                f"Mozilla/5.0 ({_win_token()}) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_win} Safari/{blink}"
            )
            return _ident("windows", ua, cv_win)
        if os == "macos":
            ua = (
                f"Mozilla/5.0 ({_macos_token()}) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_mac} Safari/{blink}"
            )
            return _ident("macos", ua, cv_mac)
        if os == "android":
            av = _ANDROID_FALLBACK_VERSION
            ua = (
                f"Mozilla/5.0 ({_android_token(av)}) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_linux} Mobile Safari/{blink}"
            )
            return _ident("android", ua, cv_linux)
        if os == "androidmobile":
            av = _ANDROID_FALLBACK_VERSION
            ua = (
                f"Mozilla/5.0 (Linux; Android {av}; SM-G991B) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_linux} Mobile Safari/{blink}"
            )
            return _ident("androidmobile", ua, cv_linux)
        if os == "androidtv":
            ua = (
                f"Mozilla/5.0 (Linux; Android {_ANDROID_FALLBACK_VERSION}; SHIELD Android TV) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_linux} Safari/{blink}"
            )
            return _ident("androidtv", ua, cv_linux)
        if os == "firetv":
            ua = (
                f"Mozilla/5.0 (Linux; Android {_ANDROID_FALLBACK_VERSION}; AFTS Build/PPR1.180610.011) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_linux} Safari/{blink}"
            )
            return _ident("firetv", ua, cv_linux)

    # ------------------------------------------------------------------
    # Microsoft Edge (Chromium-based) — reuses Chrome versions from the
    # same VersionHistory API: win slug for Windows/macOS, linux for Linux.
    # ------------------------------------------------------------------
    if browser == "edge":
        if os == "windows":
            ua = (
                f"Mozilla/5.0 ({_win_token()}) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_win} Safari/{blink} "
                f"Edg/{cv_win}"
            )
            return _ident("windows", ua, cv_win)
        if os == "linux":
            ua = (
                f"Mozilla/5.0 ({_linux_token()}) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_linux} Safari/{blink} "
                f"Edg/{cv_linux}"
            )
            return _ident("linux", ua, cv_linux)
        if os == "macos":
            ua = (
                f"Mozilla/5.0 ({_macos_token()}) "
                f"AppleWebKit/{blink} (KHTML, like Gecko) "
                f"Chrome/{cv_mac} Safari/{blink} "
                f"Edg/{cv_mac}"
            )
            return _ident("macos", ua, cv_mac)

    # ------------------------------------------------------------------
    # Apple Safari
    # ------------------------------------------------------------------
    if browser == "safari":
        if os == "macos":
            sv = _SAFARI_FALLBACK_VERSION  # "18.3"
            wk = _WEBKIT_FALLBACK_BUILD    # "605.1.15"
            ua = (
                f"Mozilla/5.0 ({_macos_token()}) "
                f"AppleWebKit/{wk} (KHTML, like Gecko) "
                f"Version/{sv} Safari/{wk}"
            )
            return BrowserIdentity(
                os="macos",
                browser="safari",
                chrome_major="",          # Safari has no Chrome version
                chrome_full="",
                blink=wk,
                user_agent=ua,
                sec_ch_ua="",
                sec_ch_ua_platform='"macOS"',
                device_name=f"Safari {sv}",
            )
        if os == "ios":
            ios = _IOS_FALLBACK_VERSION    # "18.3.2"
            ios_ua = ios.replace(".", "_")
            sv = _SAFARI_FALLBACK_VERSION
            wk = _WEBKIT_FALLBACK_BUILD
            ua = (
                f"Mozilla/5.0 (iPhone; CPU iPhone OS {ios_ua} like Mac OS X) "
                f"AppleWebKit/{wk} (KHTML, like Gecko) "
                f"Version/{sv} Mobile/15E148 Safari/{wk}"
            )
            return BrowserIdentity(
                os="ios",
                browser="safari",
                chrome_major="",
                chrome_full="",
                blink=wk,
                user_agent=ua,
                sec_ch_ua="",
                sec_ch_ua_platform='"iOS"',
                device_name=f"Safari {sv}",
            )

    # ------------------------------------------------------------------
    # Android Dalvik (system HTTP client — used by native Android apps)
    # ------------------------------------------------------------------
    if browser == "dalvik":
        if os in ("android", "androidtv", "androidmobile", "firetv"):
            build = "RQ1A.210105.003"
            ua = (
                f"Dalvik/2.1.0 (Linux; U; Android {_ANDROID_FALLBACK_VERSION}; "
                f"SHIELD Android TV Build/{build})"
            )
            return BrowserIdentity(
                os=os,
                browser="dalvik",
                chrome_major="",
                chrome_full="",
                blink="",
                user_agent=ua,
                sec_ch_ua="",
                sec_ch_ua_platform=_sec_ch_platform(os),
                device_name="Dalvik",
            )

    raise ValueError(
        f"Unsupported (os={os!r}, browser={browser!r}) combination. "
        f"Supported OS values: windows, linux, macos, android, androidtv, "
        f"androidmobile, ios, firetv. "
        f"Supported browser values: chrome, edge, safari, dalvik."
    )


@lru_cache(maxsize=None)
def get_user_agent(os: OS, browser: UA) -> str:
    """
    Return a current, standards-compliant user agent string.

    Thin wrapper around get_identity(); kept for existing call sites and for
    providers that only need the UA string.
    """
    return get_identity(os, browser).user_agent


def invalidate_version_cache() -> None:
    """
    Force a re-fetch of all versions on next call.
    Useful for long-running processes that want to pick up a new release.
    """
    global _linux_version, _win_version, _mac_version
    with _linux_lock:
        _linux_version = None
        _linux_ready.clear()
    with _win_lock:
        _win_version = None
        _win_ready.clear()
    with _mac_lock:
        _mac_version = None
        _mac_ready.clear()
    get_identity.cache_clear()
    get_user_agent.cache_clear()


# ---------------------------------------------------------------------------
# Eager background prefetch — runs once at import time.
# All three platform fetches run concurrently (daemon threads, never block
# shutdown).
# ---------------------------------------------------------------------------

def _prefetch_all() -> None:
    for target, name in (
        (_fetch_linux_version, "prefetch-chrome-linux"),
        (_fetch_win_version,   "prefetch-chrome-win"),
        (_fetch_mac_version,   "prefetch-chrome-mac"),
    ):
        threading.Thread(target=target, daemon=True, name=name).start()


_prefetch_all()