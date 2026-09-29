# streaming_providers/providers/magenta2/concurrency.py
import urllib.parse

from ...base.network import HTTPManager
from ...base.utils.logger import logger


def extract_and_release_lock(
    smil_content: str,
    http_manager: HTTPManager,
    device_id: str,
    session_id: str,
    call_id_callback,
    user_agent: str,
) -> bool:
    """
    Extract concurrency lock from SMIL and immediately release it.
    Returns True if lock was found and released, False otherwise.

    We release the lock immediately rather than holding it during playback,
    so we never call the /update endpoint the real client calls every
    ~30s (per updateLockInterval in the SMIL response) to keep a lock alive.
    Implementing /update would require the playback manager to own the lock
    lifecycle — out of scope here; noted for future work.

    Args:
        smil_content: SMIL XML content.
        http_manager: HTTP manager for making requests.
        device_id: Persisted device UUID (same value used in the SMIL
            request's clientId param). Sent as player_{device_id} — matching
            format confirmed from a real ATV One capture of both the SMIL
            request and this unlock request.
        session_id: Session UUID, used in the CID header.
        call_id_callback: Callable () -> str returning a fresh UUID per request.
        user_agent: Platform-specific (subscriber-suffixed) user agent.
    """
    try:
        import xml.etree.ElementTree as ET

        # Parse SMIL XML
        root = ET.fromstring(smil_content)

        # Extract head metadata
        head = root.find("{http://www.w3.org/2005/SMIL21/Language}head")
        if head is None:
            return False

        # Extract lock parameters
        lock_params = {}
        for meta in head.findall("{http://www.w3.org/2005/SMIL21/Language}meta"):
            name = meta.get("name")
            content = meta.get("content")
            if name and content:
                lock_params[name] = content

        # Check if we have all required lock parameters
        required_params = [
            "concurrencyInstance",
            "concurrencyServiceUrl",
            "lockId",
            "lockSequenceToken",
            "lock",
        ]
        if not all(param in lock_params for param in required_params):
            logger.debug("SMIL doesn't contain complete concurrency lock")
            return False

        # player_{device_id} — same format the real client uses for both
        # the SMIL clientId param and this unlock call's _clientId param.
        client_id = f"player_{device_id}"
        cid = f"{session_id}::{call_id_callback()}"

        base_url = lock_params["concurrencyServiceUrl"].rstrip("/") + "/web/Concurrency/unlock"

        params = {
            "schema": "1.0",
            "form": "json",
            "_clientId": client_id,
            "_id": lock_params["lockId"],
            "_sequenceToken": urllib.parse.quote(lock_params["lockSequenceToken"]),
            "_encryptedLock": urllib.parse.quote(lock_params["lock"]),
        }

        param_string = "&".join([f"{k}={v}" for k, v in params.items()])
        release_url = f"{base_url}?{param_string}"

        logger.debug(
            f"Releasing concurrency lock: {lock_params['lockId']} with client: {client_id}"
        )

        headers = {
            "User-Agent": user_agent,
            "Accept": "application/json",
            "CID": cid,
            # Cookie names embed the client ID — confirmed from a real
            # unlock-request capture. Not optional; the server appears to
            # read the lock/sequence data from these cookies as well as
            # (or instead of) the query params.
            "Cookie": (
                f"LockId_{client_id}="
                f"id={lock_params['lockId']}"
                f"&sequenceToken={lock_params['lockSequenceToken']}; "
                f"LockEncr_{client_id}={lock_params['lock']}"
            ),
        }

        # Release the lock immediately
        response = http_manager.get(
            release_url, operation="concurrency_unlock", headers=headers, timeout=10
        )

        # Log the response for debugging
        logger.debug(
            f"Concurrency unlock response: Status={response.status_code}, Content={response.text}"
        )

        if response.status_code == 200:
            try:
                # Parse JSON response to verify it contains unlockResponse
                response_data = response.json()
                if "unlockResponse" in response_data:
                    logger.info(
                        f"✓ Concurrency lock released successfully with client: {client_id}"
                    )
                    return True
                else:
                    logger.warning(
                        f"Concurrency lock release failed - missing unlockResponse: {response_data}"
                    )
                    return False
            except Exception as e:
                logger.warning(
                    f"Concurrency lock release - invalid JSON response: {e}, Content: {response.text}"
                )
                return False
        else:
            logger.warning(f"Concurrency lock release failed with status: {response.status_code}")
            return False

    except Exception as e:
        logger.warning(f"Error releasing concurrency lock: {e}")
        return False