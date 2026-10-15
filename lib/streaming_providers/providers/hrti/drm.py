# streaming_providers/providers/hrti/drm.py
"""
Shared DRM building for the live and the VOD manager (one place to fix a
header / license-data bug).

HRTi licences go to DRMToday. The "upfront token" is NOT a bearer token: it is
base64(JSON{userId, sessionId, merchant}) bound to an authorised playback
session (AuthorizeSession -> DrmId). Sent in the ``dt-custom-data`` header.

Known limitation (README §11): the DRMConfig lives as long as inputstream.
adaptive caches it; a fresh zap re-invokes get_drm and authorises again.
"""

import base64
import json
from typing import Any, Dict, List, NamedTuple, Optional
from urllib.parse import urlparse

from ...base.errors import ServerError
from ...base.models import DRMConfig
from ...base.utils.logger import logger
from ..lib_drmtoday import create_drmtoday_widevine_config
from .constants import HRTiConfig, HRTiDefaults


class VodSessionParams(NamedTuple):
    content_ref_id: str
    content_drm_id: str


def derive_live_drm_id(streaming_url: str) -> Optional[str]:
    """First two path segments joined by '_' (/cdn1oiv/hrtliveorigin/... ->
    "cdn1oiv_hrtliveorigin"); None when the path is too short."""
    parts = urlparse(streaming_url).path.strip("/").split("/")
    if len(parts) >= 2:
        return f"{parts[0]}_{parts[1]}"
    return None


def derive_vod_session_params(file_name: str) -> VodSessionParams:
    """
    FileName = https://cdn1oiv.akamaized.net/hrtvodorigin/REF.smil/manifest.mpd
      ContentReferenceId = "REF"                    (stem without .smil)
      ContentDrmId       = "hrtvodorigin_REF.smil"
    """
    parts = urlparse(file_name).path.strip("/").split("/")
    if len(parts) < 2:
        raise ServerError(f"HRTi: cannot derive session parameters from FileName {file_name!r}")
    origin, ref_with_ext = parts[0], parts[1]
    ref_id = ref_with_ext[: -len(".smil")] if ref_with_ext.endswith(".smil") else ref_with_ext
    return VodSessionParams(content_ref_id=ref_id, content_drm_id=f"{origin}_{ref_with_ext}")


def build_license_data(user_id: str, session_id: str, merchant: str) -> str:
    payload = {"userId": user_id or "", "sessionId": session_id, "merchant": merchant}
    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8")


def build_widevine(
    config: HRTiConfig,
    user_id: str,
    session_data: Dict[str, Any],
    content_id: str,
    referer_path: str,
) -> List[DRMConfig]:
    """Widevine config from an AUTHORISED session. [] when the session has no
    DrmId (logged; the stream cannot be licensed)."""
    drm_id = session_data.get("DrmId")
    if not drm_id:
        logger.error(f"HRTi: no DrmId in session data for {content_id}")
        return []
    license_data = build_license_data(user_id, drm_id, config.get_merchant())
    drm_config = create_drmtoday_widevine_config(
        upfront_token=license_data,
        origin=config.base_website,
        referer=f"{config.base_website}{referer_path}",
        user_agent=config.user_agent,
        priority=HRTiDefaults.WIDEVINE_PRIORITY,
        auth_header_name=HRTiDefaults.DRM_AUTH_HEADER,
    )
    return [drm_config]
