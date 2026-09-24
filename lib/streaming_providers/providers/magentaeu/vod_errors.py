# streaming_providers/providers/magentaeu/vod_errors.py
# -*- coding: utf-8 -*-
"""
Typed exceptions for the MagentaEU VOD path.

Rationale: the bifrost API returns 4xx for several distinct conditions --
expired token, geo-block, entitlement denial, content removed -- and they
need to be handled differently. `raise_for_status()` alone collapses them
into one opaque HTTPError. VODOperations and the Kodi player layer need
to distinguish "refresh and retry" from "tell the user they can't watch
this here" from "this title is gone" from "this is actually catch-up,
not VOD -- hand it to the channel/catchup pathway instead".

Hierarchy:

    VodError                          (base, catch-all)
    ├── VodAuthError                  (401 -- token expired/invalid)
    ├── VodGeoBlockError              (403 -- not available in your region)
    ├── VodEntitlementError           (403 -- not in your subscription)
    │   └── VodAccountVodDisabledError (account-level VOD gate is off)
    ├── VodNotFoundError              (404 -- content removed)
    ├── VodRateLimitError             (429)
    ├── VodServerError                (5xx -- retryable)
    ├── VodCatchupRequiredError       (item has no watch/trailer action but
    │                                  DOES have schedules/catchup_schedules
    │                                  -- it's a linear-catchup item, not a
    │                                  playable VOD asset; see docstring)
    └── VodNotImplementedError        (feature captured-but-not-yet-mapped)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class VodError(Exception):
    """Base class for all MagentaEU VOD errors."""

    def __init__(self, message: str, *, status: Optional[int] = None,
                 url: Optional[str] = None) -> None:
        super().__init__(message)
        self.status = status
        self.url = url


class VodAuthError(VodError):
    """
    Raised on 401 or on a locally-detected expired Bff_token.

    `MagentaEUVodManager._request()` catches this internally, refreshes
    the token once via a forced re-authentication, and retries the
    request exactly once. If the retry also fails, VodAuthError
    propagates to the caller -- at that point re-auth is not going to
    fix it (credentials are likely actually invalid).
    """


class VodGeoBlockError(VodError):
    """Content is geo-blocked for the current network egress."""


class VodEntitlementError(VodError):
    """
    The subscriber is authenticated but not entitled to this content.

    Raised by the actions endpoint when `actions.watch` is empty and
    `svod_subscription_message` is present, AND the item is not a
    catchup-eligible linear item (see VodCatchupRequiredError -- that
    takes priority when both watch/trailer are empty).
    """


class VodAccountVodDisabledError(VodEntitlementError):
    """
    Account-level VOD gate is off.

    This is distinct from a per-title entitlement error: the account's
    `managed_settings["TVSOA-setting-VodEnabled"]` is "false", which
    means *no* VOD can be played, regardless of package. The captured
    HR test account ships in this state (`vod_enabled: false` at
    /user/account and echoed in every X-Account-Details header).
    Callers should surface this differently than "you need to add the
    HBO package".
    """


class VodNotFoundError(VodError):
    """Content has been removed or never existed."""


class VodBadRequestError(VodError):
    """
    400 -- malformed request for the endpoint called.

    Confirmed in production (not just capture): passing a component id
    to `/home/page/{id}` returns 400, not 404. `get_category_children()`'s
    page-then-component dispatch guess relies on this to know when its
    first guess was wrong, since content_id alone doesn't reveal
    whether it names a page or a component.
    """


class VodRateLimitError(VodError):
    """429 -- caller should back off."""


class VodServerError(VodError):
    """5xx -- retryable."""


class VodCatchupRequiredError(VodError):
    """
    This "VOD" list entry is actually a catch-up item from a linear
    channel, not a TVOD/SVOD asset.

    Evidence from capture: some rail/search items marked as VOD series
    (e.g. "Nakon poplave, serija") return `actions.watch: []` and
    `actions.trailer: []` -- same shape as a genuine entitlement denial
    -- but ALSO carry a non-empty `actions.schedules` / a `station_id`
    /`channel_number`, and the episode list includes populated
    `catchup_schedules[]` entries with their own `pid` and
    `catchup_start_utc`/`catchup_end_utc` window. Treating this as a
    plain VodEntitlementError is wrong: the content IS watchable, just
    via the existing live-channel catchup path
    (`provider.get_catchup_manifest()`), not via
    `MagentaEUVodManager.get_manifest()`.

    This exception carries the raw schedule/catchup data so a caller
    that wants to bridge into the catchup flow can do so without a
    second round-trip. Bridging itself (mapping station_id +
    catchup_start_utc/catchup_end_utc into a get_catchup_manifest()
    call) is NOT implemented here -- it needs the channel/EPG manager,
    which this module deliberately has no dependency on. Treat this as
    a routing signal, not a playback failure.
    """

    def __init__(
        self,
        message: str,
        *,
        station_id: Optional[str] = None,
        schedules: Optional[List[Dict[str, Any]]] = None,
        catchup_schedules: Optional[List[Dict[str, Any]]] = None,
        status: Optional[int] = None,
        url: Optional[str] = None,
    ) -> None:
        super().__init__(message, status=status, url=url)
        self.station_id = station_id
        self.schedules = schedules or []
        self.catchup_schedules = catchup_schedules or []


class VodNotImplementedError(VodError):
    """
    Raised by methods whose endpoint shape has not been captured yet.

    Current cases:
      * pricing resolution (needs a non-empty rent[]/purchase[] sample)
      * recommendations rails (needs the recommendations endpoint)
      * related-content parsing beyond the raw pass-through in
        get_related_content() (field shapes only partially captured)
    These raise rather than returning empty so callers can't silently
    ship with a bug they don't know about.
    """