"""
Core tests of the Example provider -- the pattern to copy for every provider
(the scaffold copies this file, renamed). They use a fake HTTP manager and
no network; adjust the fake payloads to your API.

Run:  pytest <this file>
"""

import threading
import time
from types import SimpleNamespace

import pytest

from streaming_providers.base.errors import AuthError, ServerError
from streaming_providers.base.testing.provider_contract import check_provider
from streaming_providers.providers.example.provider import ExampleProvider


class Resp:
    def __init__(self, data):
        self._d = data

    def json(self):
        return self._d


class FakeHttp:
    """Records calls; payloads mimic the (fictional) Example API."""

    def __init__(self):
        self.calls = []
        self.channels = [
            {"id": "1", "name": "One", "logoUrl": "https://x/1.png"},
            {"id": "2", "name": "Two"},
            {"name": "no id"},                      # malformed -> skipped
        ]
        self.license_url = None                     # None = clear stream
        self.logins = 0
        self.login_delay = 0.0
        self.expires_in = 3600

    def post(self, url, json=None, headers=None, operation=None):
        self.calls.append(("POST", url, headers))
        if url.endswith("/v1/login"):
            self.logins += 1
            time.sleep(self.login_delay)
            return Resp({"accessToken": f"tok{self.logins}", "expiresIn": self.expires_in})
        raise AssertionError(url)

    def get(self, url, params=None, headers=None, operation=None):
        self.calls.append(("GET", url, headers))
        if url.endswith("/v1/channels"):
            return Resp({"channels": self.channels})
        cid = url.rsplit("/", 1)[1]
        if cid == "broken":
            return Resp({"stream": {}})
        stream = {"url": f"https://cdn/{cid}.mpd", "id": f"s-{cid}"}
        if self.license_url:
            stream["licenseUrl"] = self.license_url
        return Resp({"stream": stream})

    def playouts(self):
        return [c for c in self.calls if "/v1/playout/" in c[1]]


@pytest.fixture
def http(monkeypatch):
    fake = FakeHttp()
    monkeypatch.setattr(ExampleProvider, "_setup_http_manager", lambda self, **kw: fake)
    return fake


def logged_in(http):
    p = ExampleProvider("DE")
    p.set_user_credentials("u", "p")
    http.calls.clear()
    return p


# ---- structure -------------------------------------------------------------
def test_contract(http):
    errors, _warnings = check_provider(ExampleProvider, "example")
    assert errors == []


def test_flags_identity_and_no_io_in_init(http):
    p = ExampleProvider("DE")
    assert http.calls == []                                    # lazy: nothing happened yet
    assert p.provider_name == "example" and p.country == "de"
    assert p.capabilities == {"channels": True, "vod": False, "epg": False, "recordings": False,
                              "favorites": False, "bookmarks": False, "catchup": False, "drm": True}
    assert p.epg_window == (0, 0) and p.catchup_window == 0
    assert p.channels is not None and p.channels is p.channels          # the manager, not a list


# ---- auth ------------------------------------------------------------------
def test_without_credentials_every_call_raises_auth_error(http):
    p = ExampleProvider("DE")
    for call in (p.get_channels, lambda: p.get_manifest("1"), lambda: p.get_drm(content_id="1")):
        with pytest.raises(AuthError):
            call()
    assert http.calls == []                                    # failed before any request


def test_login_is_lazy_shared_and_refreshed_on_expiry(http):
    p = logged_in(http)
    assert http.logins == 1
    p.get_channels(); p.get_channels()
    assert http.logins == 1                                    # token reused
    p.auth._expires_at = 0                                     # expire it
    p.get_channels()
    assert http.logins == 2


def test_concurrent_callers_produce_one_login(http):
    http.login_delay = 0.05
    p = ExampleProvider("DE")
    p.auth.set_credentials(SimpleNamespace(username="u", password="p"))
    threads = [threading.Thread(target=p.get_channels) for _ in range(5)]
    [t.start() for t in threads]; [t.join() for t in threads]
    assert http.logins == 1


def test_set_user_credentials_result(http):
    p = ExampleProvider("DE")
    assert p.set_user_credentials("u", "p") is True
    http.post = lambda *a, **k: (_ for _ in ()).throw(ConnectionError("down"))
    assert ExampleProvider("DE").set_user_credentials("u", "p") is False


# ---- channels / manifest / headers / drm -----------------------------------
def test_channels_skip_malformed_and_build_model_objects(http):
    chans = logged_in(http).get_channels()
    assert [c.content_id for c in chans] == ["1", "2"]
    assert chans[0].provider == "example" and chans[0].logo_url == "https://x/1.png"


def test_to_output_format_uses_the_manager(http):
    out = logged_in(http).to_output_format()
    assert out["Provider"] == "example" and len(out["Channels"]) == 2


def test_manifest_and_drm_share_one_playout_request(http):
    http.license_url = "https://lic/widevine"
    p = logged_in(http)
    assert p.get_manifest("1") == "https://cdn/1.mpd"
    configs = p.get_drm(content_id="1", drm_variant="auto", preferred_quality="hd")   # as the backend calls it
    assert len(configs) == 1 and configs[0].priority == 1
    assert len(http.playouts()) == 1


def test_clear_stream_has_no_drm(http):
    p = logged_in(http)
    assert p.get_drm(content_id="1") == []


def test_cdn_headers_carry_no_token_but_api_calls_do(http):
    p = logged_in(http)
    h = p.get_manifest_headers("1")
    assert "Authorization" not in h and "User-Agent" in h
    assert p.get_segment_headers("1") == h
    p.get_channels()
    assert http.calls[-1][2]["Authorization"].startswith("Bearer ")


def test_bad_playout_is_a_server_error_and_cache_is_cleared_on_credential_change(http):
    p = logged_in(http)
    with pytest.raises(ServerError):
        p.get_manifest("broken")
    p.get_manifest("1")
    assert p._playout_cache
    p.set_user_credentials("u", "p")
    assert p._playout_cache == {}
