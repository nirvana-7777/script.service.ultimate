# streaming_providers/providers/joyn/tests/test_joyn_provider.py
# -*- coding: utf-8 -*-
"""
Joyn provider tests — offline (fake HTTP, fake authenticator), README §15 pattern.

Run against the REAL package:  pytest streaming_providers/providers/joyn/tests
The one test that needs `base.testing.provider_contract` is skipped when that
module is not importable (so the file also runs in a stripped-down sandbox).
"""

import threading
import time
import types

import pytest

from streaming_providers.base.errors import (
    AuthError,
    BadRequestError,
    EntitlementError,
    NotFoundError,
    RateLimitError,
    ServerError,
)
from streaming_providers.base.vod import VodPage
from streaming_providers.providers.joyn import provider as provider_module
from streaming_providers.providers.joyn import vod_manager as vod_module
from streaming_providers.providers.joyn.constants import (
    ERROR_CODES,
    JOYN_BROWSER_MAJOR,
    JOYN_SEC_CH_UA,
    JOYN_SEC_CH_UA_PLATFORM,
    JOYN_STREAMING_ENDPOINTS,
    JOYN_USER_AGENT,
)
from streaming_providers.providers.joyn.entitlement import JoynEntitlement  # noqa: F401
from streaming_providers.providers.joyn.ids import is_live_id, is_vod_id
from streaming_providers.providers.joyn.models import (
    JoynAuthError,
    JoynEntitlementError,
    JoynMfaRequiredException,
)
from streaming_providers.providers.joyn.provider import JoynProvider
from streaming_providers.providers.joyn.session import (
    BACKOFF_BASE_SECONDS,
    JoynSession,
)


# ============================================================================
# Fakes
# ============================================================================

class FakeResponse:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = {} if body is None else body
        self.text = ""

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeHttpError(Exception):
    """What an HTTP manager that raises on 4xx looks like: it carries .response."""
    def __init__(self, response):
        super().__init__(f"HTTP {response.status_code}")
        self.response = response


class FakeHttp:
    CHANNELS = {"data": {"liveStreams": [
        {"id": "sat1-de", "title": "SAT.1", "type": "LINEAR", "quality": "HD",
         "logo": {"url": "https://logo.example/sat1.png"}},
        {"title": "entry without id"},          # malformed -> skipped
        "garbage",                              # malformed -> skipped
        {"id": "prosieben-de", "title": "ProSieben", "type": "LINEAR"},
    ]}}

    def __init__(self):
        self.calls = []                 # (method, url, headers)
        self.entitlement = {}           # content_id -> (status, body)
        self.raise_on_4xx = False       # emulate an HTTP manager that raises
        self.license_url = "https://license.example/wv"

    # -- helpers ---------------------------------------------------------
    def urls(self, needle):
        return [u for _, u, _ in self.calls if needle in u]

    # -- HTTPManager surface --------------------------------------------
    def post(self, url, operation=None, headers=None, json_data=None, data=None,
             timeout=None, **kw):
        self.calls.append(("POST", url, dict(headers or {})))
        if url == JOYN_STREAMING_ENDPOINTS["ENTITLEMENT"]:
            cid = json_data["content_id"]
            status, body = self.entitlement.get(
                cid, (200, {"entitlement_token": f"ent-{cid}"})
            )
            response = FakeResponse(status, body)
            if status >= 400 and self.raise_on_4xx:
                raise FakeHttpError(response)
            return response
        if "/playlist" in url:
            ident = url.split("/playlist")[0].rsplit("/", 1)[-1]
            return FakeResponse(200, {
                "manifestUrl": f"https://cdn.example/{ident}.mpd",
                "licenseUrl": self.license_url,
                "certificateUrl": "https://license.example/cert",
                "streamingFormat": "dash",
            })
        raise AssertionError(f"unexpected POST {url}")

    def get(self, url, operation=None, headers=None, timeout=None, **kw):
        self.calls.append(("GET", url, dict(headers or {})))
        if "LiveChannelsAndEpg" in url:
            return FakeResponse(200, self.CHANNELS)
        return FakeResponse(200, {"data": {}})   # navigation/asset: empty -> fallbacks


class FakeToken:
    def __init__(self, access_token):
        self.access_token = access_token
        self.is_expired = False


class FakeAuthenticator:
    """Stands in for JoynAuthenticator: no 7pass flow, no network, no disk."""

    def __init__(self, **ctor_kwargs):
        self.ctor_kwargs = ctor_kwargs
        self.current_token = None
        self.fail = None
        self.attempts = 0
        self.logins = 0
        self.invalidated = 0
        self.force_flags = []
        self.delay = 0.0

    def get_bearer_token(self, force_refresh=False, force_upgrade=False):
        self.force_flags.append(force_refresh)
        self.attempts += 1
        if self.delay:
            time.sleep(self.delay)
        if self.fail is not None:
            raise self.fail
        if self.current_token is None or self.current_token.is_expired:
            self.logins += 1
            self.current_token = FakeToken(f"tok-{self.logins}")
        return self.current_token.access_token

    def invalidate_token(self):
        self.current_token = None
        self.invalidated += 1


@pytest.fixture
def env(monkeypatch):
    http = FakeHttp()
    holder = types.SimpleNamespace(http=http, auth=None)

    def make_authenticator(**kw):
        holder.auth = FakeAuthenticator(**kw)
        return holder.auth

    monkeypatch.setattr(JoynProvider, "_setup_http_manager", lambda self, **kw: http)
    monkeypatch.setattr(provider_module, "JoynAuthenticator", make_authenticator)
    monkeypatch.setattr(vod_module.time, "sleep", lambda s: holder.__dict__
                        .setdefault("sleeps", []).append(s))
    return holder


@pytest.fixture
def make(env):
    def _make(country="DE"):
        return JoynProvider(country)
    return _make


# ============================================================================
# Contract, construction, identity
# ============================================================================

def test_contract(env):
    mod = pytest.importorskip("streaming_providers.base.testing.provider_contract")
    errors, warnings = mod.check_provider(JoynProvider, "joyn")
    assert errors == [], (errors, warnings)


def test_no_network_in_init(env, make):
    make()
    assert env.http.calls == []
    assert env.auth.attempts == 0           # the old eager login is gone


def test_country_is_normalised_and_unsupported_rejected(env, make):
    assert make("DE").country == "de"
    with pytest.raises(NotImplementedError):
        make("US")


def test_identity_and_exports(env, make):
    import streaming_providers.providers.joyn as pkg
    assert make().provider_name == "joyn"
    assert pkg.__all__ == ["JoynProvider"]
    assert not hasattr(pkg, "ManagedProvider")


def test_one_shared_config_reaches_the_authenticator(env, make):
    p = make("AT")
    assert env.auth.ctor_kwargs["config"] is p.provider_config
    assert p.provider_config.country == "at"
    assert p.provider_config.distribution_tenant == "JOYN_AT"


def test_client_hints_match_user_agent():
    assert f"Chrome/{JOYN_BROWSER_MAJOR}." in JOYN_USER_AGENT
    assert JOYN_SEC_CH_UA.count(JOYN_BROWSER_MAJOR) == 2
    assert "Windows" in JOYN_USER_AGENT and JOYN_SEC_CH_UA_PLATFORM == '"Windows"'


# ============================================================================
# Id grammar and routing
# ============================================================================

@pytest.mark.parametrize("cid", [
    "a_abc123", "b_movie", "c_season", "d_episode", "block-12",
    "/serien", "/serien/genre/krimi", "foo:bar",
])
def test_vod_ids(cid):
    assert is_vod_id(cid) and not is_live_id(cid)


@pytest.mark.parametrize("cid", ["sat1-de", "sat1-de-hd", "prosieben-de"])
def test_live_ids(cid):
    assert is_live_id(cid) and not is_vod_id(cid)


@pytest.mark.parametrize("cid", ["", None])
def test_empty_id_is_neither(cid):
    assert not is_vod_id(cid) and not is_live_id(cid)


def test_handles_content_id_is_pure_and_complementary(env, make):
    p = make()
    for cid in ["sat1-de", "sat1-de-hd", "a_abc123", "b_x", "c_x", "d_x",
                "block-1", "/serien/x", "x:y"]:
        assert p.channels.handles_content_id(cid) != p.vod.handles_content_id(cid), cid
    assert env.http.calls == []              # no I/O to decide ownership


def test_vod_id_reaches_the_vod_manager_not_the_channel_manager(env, make):
    p = make()
    manifest = p.get_manifest(content_id="a_abc123")
    assert manifest == "https://cdn.example/a_abc123.mpd"
    assert env.http.urls("/asset/a_abc123/playlist")
    assert not env.http.urls("/channel/")


def test_channel_manager_refuses_a_vod_id_it_is_handed_directly(env, make):
    p = make()
    with pytest.raises(BadRequestError):
        p.channels.get_channel_manifest("a_abc123")


# ============================================================================
# Playout: manifest + DRM share one call; -hd probing; cache
# ============================================================================

def test_live_manifest_and_drm_share_one_playlist_call(env, make):
    p = make()
    assert p.get_manifest(content_id="sat1-de") == "https://cdn.example/sat1-de-hd.mpd"
    drm = p.get_drm(content_id="sat1-de", drm_variant="auto")
    assert len(drm) == 1 and drm[0].priority == 1
    assert len(env.http.urls("/channel/")) == 1


def test_hd_variant_is_probed_and_resolution_is_cached(env, make):
    env.http.entitlement["sat1-de-hd"] = (
        400, [{"code": ERROR_CODES["NOT_FOUND"], "msg": "no hd"}])
    p = make()
    assert p.get_manifest(content_id="sat1-de") == "https://cdn.example/sat1-de.mpd"
    assert p._entitlement._resolved_channel_variants["sat1-de"] == "sat1-de"


def test_expired_playout_entries_are_evicted_on_insert(env, make):
    p = make()
    p._playout_cache["old:default"] = (object(), 0.0)
    p.get_manifest(content_id="sat1-de")
    assert "old:default" not in p._playout_cache


# ============================================================================
# Entitlement error mapping
# ============================================================================

def test_playback_restricted_becomes_typed_entitlement_error(env, make):
    body = (400, [{"code": ERROR_CODES["PLAYBACK_RESTRICTED"], "msg": "nope"}])
    env.http.entitlement.update({"sat1-de": body, "sat1-de-hd": body})
    with pytest.raises(EntitlementError):
        make().get_manifest(content_id="sat1-de")


def test_400_is_detected_when_the_http_manager_raises_instead_of_returning(env, make):
    env.http.raise_on_4xx = True
    body = (400, [{"code": ERROR_CODES["BUSINESS_MODEL_NOT_SUITABLE"], "msg": "plus"}])
    env.http.entitlement.update({"sat1-de": body, "sat1-de-hd": body})
    with pytest.raises(EntitlementError) as info:
        make().get_manifest(content_id="sat1-de")
    assert "Subscription required" in str(info.value)


def test_hd_probe_works_when_the_http_manager_raises_on_400(env, make):
    env.http.raise_on_4xx = True
    env.http.entitlement["sat1-de-hd"] = (
        400, [{"code": ERROR_CODES["NOT_FOUND"], "msg": "no hd"}])
    assert make().get_manifest(content_id="sat1-de") == "https://cdn.example/sat1-de.mpd"


def test_malformed_400_body_is_an_entitlement_error_not_a_crash(env, make):
    for body in ({"unexpected": 1}, [], ["x"], ValueError("not json")):
        env.http.entitlement.update({"sat1-de": (400, body), "sat1-de-hd": (400, body)})
        with pytest.raises(JoynEntitlementError):
            make().get_manifest(content_id="sat1-de")


# ============================================================================
# Headers
# ============================================================================

def test_cdn_headers_carry_no_api_headers_or_bearer(env, make):
    p = make()
    p.get_manifest(content_id="sat1-de")
    headers = p.get_manifest_headers("sat1-de")
    assert "Authorization" not in headers and "joyn-client-version" not in headers
    assert set(headers) == {"User-Agent", "Origin"}


def test_segment_headers_equal_manifest_headers(env, make):
    p = make()
    p.get_manifest(content_id="sat1-de")
    assert p.get_segment_headers("sat1-de") == p.get_manifest_headers("sat1-de")


# ============================================================================
# Channels
# ============================================================================

def test_malformed_channel_entries_are_skipped_not_fatal(env, make):
    channels = make().channels.get_channels()
    assert [c.content_id for c in channels] == ["sat1-de", "prosieben-de"]


def test_channel_list_uses_a_bearer_and_user_state(env, make):
    make().channels.get_channels()
    headers = [h for m, u, h in env.http.calls if m == "GET"][0]
    assert headers["Authorization"] == "Bearer tok-1"


# ============================================================================
# Auth failures are typed, loud and not retried
# ============================================================================

def test_mfa_raises_auth_error_not_an_anonymous_channel_list(env, make):
    p = make()
    env.auth.fail = JoynMfaRequiredException("mfa on")
    with pytest.raises(AuthError):
        p.channels.get_channels()
    assert env.http.calls == []              # no silent anonymous request


def test_mfa_is_not_retried(env, make):
    p = make()
    env.auth.fail = JoynMfaRequiredException("mfa on")
    for _ in range(3):
        with pytest.raises(AuthError):
            p.channels.get_channels()
    assert env.auth.attempts == 1


def test_rejected_credentials_are_permanent(env, make):
    p = make()
    env.auth.fail = JoynAuthError("rejected")
    for _ in range(3):
        with pytest.raises(AuthError):
            p.channels.get_channels()
    assert env.auth.attempts == 1


# ============================================================================
# Session (fake clock, no provider)
# ============================================================================

class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


@pytest.fixture
def session_parts():
    auth = FakeAuthenticator()
    clock = Clock()
    callbacks = []
    session = JoynSession(authenticator=auth, config=types.SimpleNamespace(
        api_headers=lambda t: {"Authorization": f"Bearer {t}"}),
        clock=clock, on_invalidate=lambda: callbacks.append(1))
    return types.SimpleNamespace(auth=auth, clock=clock, session=session, callbacks=callbacks)


def test_first_login_does_not_force_a_refresh(session_parts):
    assert session_parts.session.ensure() is True
    assert session_parts.auth.force_flags == [False]     # persisted token path stays usable


def test_transient_failure_backs_off_exponentially_then_recovers(session_parts):
    s, a, c = session_parts.session, session_parts.auth, session_parts.clock
    a.fail = ConnectionError("net down")
    assert s.ensure() is False and a.attempts == 1
    assert s.ensure() is False and a.attempts == 1       # inside the backoff window
    c.now = BACKOFF_BASE_SECONDS
    assert s.ensure() is False and a.attempts == 2       # window over, second failure
    c.now = BACKOFF_BASE_SECONDS + 2 * BACKOFF_BASE_SECONDS - 1
    assert s.ensure() is False and a.attempts == 2       # doubled window not over yet
    a.fail = None
    c.now = BACKOFF_BASE_SECONDS * 3
    assert s.ensure() is True and a.attempts == 3


def test_provider_error_type_is_preserved(session_parts):
    session_parts.auth.fail = RateLimitError("slow down")
    with pytest.raises(RateLimitError):
        session_parts.session.require()


def test_untyped_exception_becomes_server_error_and_last_error_keeps_the_original(session_parts):
    original = ConnectionError("boom")
    session_parts.auth.fail = original
    with pytest.raises(ServerError) as info:
        session_parts.session.require()
    assert session_parts.session.last_error is original
    assert info.value.__cause__ is original


def test_ensure_never_raises(session_parts):
    session_parts.auth.fail = RuntimeError("anything")
    assert session_parts.session.ensure() is False


def test_one_login_for_concurrent_callers(session_parts):
    session_parts.auth.delay = 0.05
    results = []
    threads = [threading.Thread(target=lambda: results.append(session_parts.session.ensure()))
               for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results == [True] * 8
    assert session_parts.auth.logins == 1


def test_invalidate_resets_backoff_and_runs_callbacks(session_parts):
    s, a = session_parts.session, session_parts.auth
    a.fail = JoynMfaRequiredException("mfa")
    assert s.ensure() is False and s.ensure() is False and a.attempts == 1
    a.fail = None
    s.invalidate()
    assert a.invalidated == 1 and session_parts.callbacks == [1]
    assert s.ensure() is True


def test_a_broken_invalidate_callback_does_not_block_invalidation(session_parts):
    def boom():
        raise RuntimeError("cache hook failed")
    session_parts.session._on_invalidate.insert(0, boom)
    session_parts.session.invalidate()
    assert session_parts.callbacks == [1]


# ============================================================================
# Credential change clears account-specific caches
# ============================================================================

def test_credentials_change_clears_playout_entitlement_and_vod_caches(env, make):
    p = make()
    p.get_manifest(content_id="sat1-de")
    p.vod._cache["video_id:b_x"] = {"timestamp": time.time(), "data": "a_x"}
    assert p._playout_cache and p._entitlement._resolved_channel_variants and p.vod._cache
    p.auth.invalidate()
    assert p._playout_cache == {}
    assert p._entitlement._resolved_channel_variants == {}
    assert p.vod._cache == {}
    assert env.auth.invalidated == 1


# ============================================================================
# VOD
# ============================================================================

def test_get_vod_category_returns_a_vodpage(env, make):
    page = make().vod.get_vod_category("")
    assert isinstance(page, VodPage)
    assert page.has_more is False and len(page.entries) >= 2     # static fallback + genres


@pytest.mark.parametrize("cid,pageable", [
    ("block-1", True), ("/serien/genre/krimi", True),
    ("c_season", False), ("/serien/some-show", False), ("/filme/some-movie", False),
    ("/neu-beliebt", False), ("/serien/genre", False), ("", False),
])
def test_only_endpoints_that_honour_offset_are_pageable(env, make, cid, pageable):
    assert make().vod._is_pageable(cid) is pageable


def test_full_pageable_page_yields_a_next_cursor(env, make, monkeypatch):
    p = make()
    monkeypatch.setattr(p.vod, "_get_vod_category_entries", lambda **kw: list(range(24)))
    assert p.vod.get_vod_category("block-1", page_size=24).next_cursor == "24"
    assert p.vod.get_vod_category("block-1", cursor="24", page_size=24).next_cursor == "48"
    monkeypatch.setattr(p.vod, "_get_vod_category_entries", lambda **kw: list(range(5)))
    assert p.vod.get_vod_category("block-1", page_size=24).next_cursor is None


def test_non_pageable_endpoints_never_claim_more_pages(env, make, monkeypatch):
    p = make()
    monkeypatch.setattr(p.vod, "_get_vod_category_entries", lambda **kw: list(range(40)))
    for cid in ("/serien/some-show", "c_season", "/neu-beliebt"):
        assert p.vod.get_vod_category(cid, page_size=24).next_cursor is None


def test_non_pageable_branches_keep_the_helpers_default_size(env, make, monkeypatch):
    p = make()
    seen = {}
    monkeypatch.setattr(p.vod, "_get_series_items_fallback",
                        lambda path, authenticated=True, **kw: seen.update(kw) or [])
    monkeypatch.setattr(p.vod, "get_collection_items",
                        lambda **kw: seen.update(block=kw) or [])
    p.vod._get_vod_category_entries(content_id="/serien/x", cursor=None,
                                    page_size=10, authenticated=True)
    assert "first" not in seen                      # helper default (v1 behaviour) applies
    p.vod._get_vod_category_entries(content_id="block-1", cursor="20",
                                    page_size=10, authenticated=True)
    assert seen["block"]["first"] == 10 and seen["block"]["offset"] == 20


def test_unresolvable_vod_id_is_not_found_not_not_mine(env, make):
    with pytest.raises(NotFoundError):
        make().vod.get_vod_manifest("b_unknown")


def test_vod_typed_errors_propagate_unchanged_and_are_not_retried(env, make):
    p = make()
    env.auth.fail = RateLimitError("slow")
    with pytest.raises(RateLimitError):
        p.vod.get_vod_manifest("a_abc")
    assert env.__dict__.get("sleeps", []) == []


def test_vod_entitlement_error_is_not_retried(env, make):
    env.http.entitlement["a_abc"] = (
        400, [{"code": ERROR_CODES["PLAYBACK_RESTRICTED"], "msg": "no"}])
    with pytest.raises(EntitlementError):
        make().vod.get_vod_manifest("a_abc")
    assert len(env.http.urls("entitlement")) == 1


def test_vod_server_errors_are_retried_then_raised(env, make):
    env.http.entitlement["a_abc"] = (503, {})
    with pytest.raises(ServerError):
        make().vod.get_vod_manifest("a_abc", max_retries=3)
    assert len(env.http.urls("entitlement")) == 3
    assert len(env.__dict__["sleeps"]) == 2


def test_get_vod_drm_returns_the_shared_widevine_config(env, make):
    drm = make().vod.get_vod_drm("a_abc")
    assert len(drm) == 1 and drm[0].license.server_url == env.http.license_url