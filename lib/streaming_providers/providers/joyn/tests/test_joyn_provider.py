def test_contract(http):
    errors, warnings = check_provider(JoynProvider, "joyn")
    assert errors == [], (errors, warnings)

def test_no_network_in_init(http):
    JoynProvider("DE")
    assert http.calls == []          # the old eager login is gone

def test_joyn_headers_do_not_leak_into_cdn(http):
    p = JoynProvider("DE")
    h = p.get_manifest_headers("sat1-de")
    assert "Authorization" not in h
    assert "joyn-client-version" not in h

def test_segment_headers_equal_manifest_headers(http):
    p = JoynProvider("DE")
    assert p.get_segment_headers("sat1-de") == p.get_manifest_headers("sat1-de")

def test_entitlement_400_playback_restricted_becomes_typed_error(http):
    http.entitlement_response = 400, [{"code": "ENT_RVOD_Playback_Restricted", "msg": "nope"}]
    p = JoynProvider("DE")
    with pytest.raises(EntitlementError):
        p.get_manifest("sat1-de")

def test_mfa_raises_auth_error_not_anonymous_fallback(http):
    http.login_redirect_to_mfa = True
    p = JoynProvider("DE")
    p.set_user_credentials(...) if that exists  # it doesn't, so:
    with pytest.raises(AuthError):
        p.channels.get_channels()

def test_get_vod_category_returns_vodpage(http):
    from ...base.vod import VodPage
    p = JoynProvider("DE")
    page = p.vod.get_vod_category("")
    assert isinstance(page, VodPage)

def test_handles_content_id_is_pure(http):
    p = JoynProvider("DE")
    # No HTTP call should be made for either of these
    assert p.vod.handles_content_id("a_abc123") is True
    assert p.vod.handles_content_id("sat1-de") is False
    assert http.calls == []