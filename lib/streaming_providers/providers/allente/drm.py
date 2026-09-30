# streaming_providers/providers/allente/drm.py
"""
Allente (Zulu) Widevine DRM config builder.

Provider-local module — Zulu's DRM endpoint is Allente-specific and is
NOT shared with other providers (unlike base/lib_drmtoday.py, which is
shared). It lives next to constants.py so both read the SAME source of
truth for URLs, client version, UA, and widevine level. NEVER duplicate
those constants here — when the client version is bumped in
constants.py, this module follows automatically.
"""

import json
from urllib.parse import quote, urlencode

from ...base.models.drm import (
    DRMConfig,
    DRMSystem,
    LicenseConfig,
    LicenseUnwrapperParams,
)
from .constants import AllenteConfig, AllenteDefaults


def create_allente_widevine_config(
    cfg: AllenteConfig,
    bearer_token: str,
    stream_id: str,
    priority: int = 1,
) -> DRMConfig:
    """
    Build a Widevine DRMConfig for Allente's Zulu license endpoint.

    Zulu expects:
        POST /v1/drm/widevine/{streamId}
        Body: {"playerPayload": "<base64 challenge>", "widevineLevel": "L3"}
        Resp: {"license": "<base64 license>"}

    ISA's flow with these settings (field names verified against
    base/models/drm source):

      1. req_data: create_with_req_data() base64-encodes the plain JSON
         template. (LicenseConfig would also auto-encode it — its
         _is_base64() check can never match a JSON template — but the
         explicit factory documents the intent.)
      2. ISA base64-decodes req_data back to the template:
             {"playerPayload": "{CHA-B64}", "widevineLevel": "L3"}
      3. ISA substitutes {CHA-B64} (documented placeholder) with the
         base64-encoded Widevine challenge.
      4. wrapper="none" (valid WrapperType): the substituted JSON body is
         sent as-is — no whole-body base64/urlenc wrapping.
      5. Zulu responds {"license": "<base64>"}.
      6. unwrapper="json,base64" (both valid UnwrapperType values, comma-
         separated flags): JSON-parse, extract path_data="license",
         base64-decode to raw license bytes.

    req_headers: pre-encoded here with quote_via=quote so spaces become
    %20, NOT '+'. Passing a dict would make LicenseConfig urlencode it
    with the default quote_plus — "Bearer+<token>" is only correct if
    ISA's decoder treats '+' as a space (form-encoding convention), which
    we cannot verify from here; the framework's own validator decodes
    with unquote() (not unquote_plus), i.e. treats '+' as literal. Pure
    percent-encoding is unambiguous under every decoder. Pre-encoding
    also bypasses the framework's plain-header parser, which splits on
    ';' and would corrupt the User-Agent.

    *** VERIFICATION REQUIRED BEFORE SHIPPING (checklist item) ***
    During the first live test, dump ISA's outgoing license request
    (URL, headers, body) and compare byte-for-byte against the browser
    capture. If they differ, adjust wrapper / placeholders and re-test.

    Known v1 limitation: the bearer token is embedded here at get_drm()
    time and ISA caches the DRMConfig for the entire playback session.
    Continuous playback across Zulu token expiry is NOT supported —
    a fresh channel zap re-invokes get_drm() with a fresh token.

    Known v1 limitation: this license request is made by ISA inside
    Kodi's process. A proxy configured in ProxyConfig scopes only
    Python-side HTTPManager traffic and is NOT applied to it (nor to the
    manifest/segment fetches). Geo-unblocking users must additionally
    configure Kodi's global network proxy.
    """
    license_url = f"{AllenteDefaults.ZULU_DRM_WIDEVINE}/{stream_id}"

    headers = {
        # Lowercase keys to match lib_drmtoday.py conventions.
        "content-type": "application/json",
        "user-agent": cfg.user_agent,
        "origin": AllenteDefaults.TV_WEB_ORIGIN,
        "referer": AllenteDefaults.TV_WEB_REFERER,
        "authorization": f"Bearer {bearer_token}",
        "x-allente-appvariant": AllenteDefaults.APP_VARIANT,
        "x-allente-clientversion": cfg.client_version,
        "x-allente-devicetype": AllenteDefaults.DEVICE_TYPE_WEB,
    }
    req_headers = urlencode(headers, quote_via=quote)

    req_data_template = json.dumps({
        "playerPayload": "{CHA-B64}",
        "widevineLevel": cfg.widevine_level,
    })

    license_config = LicenseConfig.create_with_req_data(
        req_data_template=req_data_template,
        server_url=license_url,
        req_headers=req_headers,
        use_http_get_request=False,      # POST (False is omitted from the ISA payload)
        wrapper="none",
        unwrapper="json,base64",
        unwrapper_params=LicenseUnwrapperParams(path_data="license"),
    )

    drm_config = DRMConfig(
        system=DRMSystem.WIDEVINE,
        priority=priority,
        license=license_config,
    )
    # Cheap self-check: source-verified to pass for this configuration
    # (priority != 0, req_data is valid base64, req_headers is URL-encoded).
    # On any future misuse it raises LicenseConfigError, which
    # provider.get_drm() catches, logs, and returns [] for.
    drm_config.validate()
    return drm_config