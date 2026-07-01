# streaming_providers/providers/magentaeu/utils.py

import hashlib
import time
import uuid
from typing import Dict, Optional
from .constants import get_guest_headers


def _generate_txn_id(
    tracking_id: str, session_id: str, device_id: str, call_time: str
) -> str:
    """SHA-256(trackingId + sessionId + deviceId + callTime)[:32]"""
    raw = tracking_id + session_id + device_id + call_time
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def build_guest_headers(
    country: str,
    device_id: str,
    session_id: str,
    flow: str,
    step: Optional[str] = None,
    tracking_id: Optional[str] = None,
) -> Dict[str, str]:
    if tracking_id is None:
        tracking_id = str(uuid.uuid4())

    # Snapshot call_time once — x-txn-id is derived from it, so both
    # headers must use the same value.
    call_time = str(int(time.time() * 1000))

    headers = get_guest_headers(country, device_id, session_id)
    headers["x-call-time"] = call_time
    headers["x-tv-flow"] = flow
    headers["x-request-tracking-id"] = tracking_id
    headers["x-txn-id"] = _generate_txn_id(tracking_id, session_id, device_id, call_time)
    if step is not None:
        headers["x-tv-step"] = step
    return headers