# streaming_providers/providers/example/drm.py
"""
Widevine DRMConfig builder (provider-local, because the license endpoint is
provider-specific). The API usage below is copied from the verified Allente
builder -- adjust the three things that vary per provider:

  1. license URL and request headers
  2. req_data template (placeholders: {CHA-RAW} raw challenge,
     {CHA-B64} base64 challenge)
  3. wrapper / unwrapper (how the license request/response is wrapped)

Rules:
  * NEVER duplicate URLs / header values here: read them from constants.py.
  * Give every DRMConfig of one content an explicit, DISTINCT priority
    (the factories default to 1; validate_drm_set rejects duplicates).
  * Pre-encode req_headers yourself with quote_via=quote (spaces -> %20)
    when a value contains spaces or ';' (User-Agent): the dict path is
    encoded by LicenseConfig and the plain-header parser splits on ';'.
  * Returning [] means "no DRM"; a broken configuration RAISES (a
    LicenseConfigError is a ConfigurationError) -- do not swallow it.
  * ISA runs outside Python's HTTPManager: a ProxyConfig does NOT apply to
    license / manifest / segment requests made by inputstream.adaptive.
  * Tokens embedded here live as long as ISA caches the config (the whole
    playback session): document the token-expiry limitation.
  * Verify on a device (dump ISA's outgoing license request and compare it
    byte-for-byte with the browser capture) before shipping.
"""

import json
from urllib.parse import quote, urlencode

from ...base.models.drm import (
    DRMConfig,
    DRMSystem,
    LicenseConfig,
    LicenseUnwrapperParams,
)
from .constants import ExampleConfig


def create_widevine_config(
    cfg: ExampleConfig,
    access_token: str,
    license_url: str,
    priority: int = 1,
) -> DRMConfig:
    headers = {
        "content-type": "application/json",
        "user-agent": cfg.user_agent,
        "authorization": f"Bearer {access_token}",
    }
    req_headers = urlencode(headers, quote_via=quote)

    license_config = LicenseConfig.create_with_req_data(
        req_data_template=json.dumps({"playerPayload": "{CHA-B64}"}),
        server_url=license_url,
        req_headers=req_headers,
        use_http_get_request=False,
        wrapper="none",
        unwrapper="json,base64",
        unwrapper_params=LicenseUnwrapperParams(path_data="license"),
    )
    drm_config = DRMConfig(
        system=DRMSystem.WIDEVINE, priority=priority, license=license_config
    )
    drm_config.validate()   # raises LicenseConfigError on misuse
    return drm_config
