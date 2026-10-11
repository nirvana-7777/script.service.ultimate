# streaming_providers/providers/joyn/drm.py
# -*- coding: utf-8 -*-
"""
Widevine config builder — one function, used by the channel AND the VOD manager
(they used to carry two identical copies).

DRM is *folded* into the managers (DRM_IN_MANAGERS = True, README §11): manifest
and licence data come from the same /playlist response. This module only builds
the DRMConfig; it does no I/O.

DEVICE CHECK REQUIRED (README §11, §12.7 step 3)
-------------------------------------------------
`req_headers` is passed as a JSON string, exactly as v1 did. README §11 only
documents two encodings as safe: a dict (the framework url-encodes it) or a
pre-encoded `urlencode(..., quote_via=quote)` string. The User-Agent contains
";" ("Windows NT 10.0; Win64; x64"), which is what the plain-text header parser
splits on. If v1 licence requests worked on a device with the JSON string, this
is correct as is; if the licence request ever shows a truncated User-Agent,
switch to `config.drm_license_headers()` (dict) here — this is the only place.
Dump ISA's outgoing request and compare against the browser capture.
"""

import json
from typing import Any, Optional

from ...base.models import DRMConfig, DRMSystem, LicenseConfig


def build_widevine_config(
    config: Any, license_url: str, certificate_url: Optional[str] = None
) -> DRMConfig:
    return DRMConfig(
        system=DRMSystem.WIDEVINE,
        priority=1,   # single system per content; explicit per README §11
        license=LicenseConfig(
            server_url=license_url,
            server_certificate=certificate_url,
            req_headers=json.dumps(config.drm_license_headers()),
            req_data="{CHA-RAW}",
            use_http_get_request=False,
        ),
    )