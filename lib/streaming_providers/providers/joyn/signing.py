# streaming_providers/providers/joyn/signing.py
# -*- coding: utf-8 -*-
"""
Playlist request signing and video-config helpers.

Pure functions shared by the channel and the VOD manager. They used to live in
channel_manager.py, which made the VOD manager import its sibling module; a
neutral module keeps "managers do not reach into each other" true.

IMPORTANT: the playlist request is signed over the exact JSON string built by
create_video_payload(). Changing DEFAULT_VIDEO_CONFIG changes the signature.
"""

import hashlib
import json
from base64 import b64decode
from typing import Dict, Optional

from .constants import DEFAULT_VIDEO_CONFIG, SIGNATURE_SECRET_KEY


def create_video_payload(config: Optional[Dict] = None, compact: bool = True) -> str:
    video_config = config or DEFAULT_VIDEO_CONFIG
    payload = json.dumps(video_config)
    return payload.replace(" ", "") if compact else payload


def build_signature(
    entitlement_token: str,
    video_payload: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> str:
    if video_payload is None:
        video_payload = create_video_payload()
    if secret_key is None:
        secret_key = b64decode(SIGNATURE_SECRET_KEY).decode("utf-8")
    signature_input = f"{video_payload},{entitlement_token}{secret_key}"
    return hashlib.sha1(signature_input.encode("utf-8")).hexdigest()


def video_config_fingerprint(video_config: Optional[Dict]) -> str:
    """Cache-key component: different configs can yield different manifests/DRM."""
    if not video_config:
        return "default"
    normalized = json.dumps(video_config, sort_keys=True, separators=(",", ":"))
    return hashlib.sha1(normalized.encode("utf-8")).hexdigest()[:12]