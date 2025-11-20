# streaming_providers/providers/magenta2/concurrency.py
import urllib.parse
from ...base.network import HTTPManager
from ...base.utils.logger import logger


def extract_and_release_lock(smil_content: str, http_manager: HTTPManager,
                             client_id: str, user_agent: str) -> bool:
    """
    Extract concurrency lock from SMIL and immediately release it
    Returns True if lock was found and released, False otherwise

    Args:
        smil_content: SMIL XML content
        http_manager: HTTP manager for making requests
        client_id: The client ID used in SMIL request (will be formatted as player_{client_id})
        user_agent: Platform-specific user agent
    """
    try:
        import xml.etree.ElementTree as ET

        # Parse SMIL XML
        root = ET.fromstring(smil_content)

        # Extract head metadata
        head = root.find('{http://www.w3.org/2005/SMIL21/Language}head')
        if head is None:
            return False

        # Extract lock parameters
        lock_params = {}
        for meta in head.findall('{http://www.w3.org/2005/SMIL21/Language}meta'):
            name = meta.get('name')
            content = meta.get('content')
            if name and content:
                lock_params[name] = content

        # Check if we have all required lock parameters
        required_params = ['concurrencyInstance', 'concurrencyServiceUrl', 'lockId', 'lockSequenceToken', 'lock']
        if not all(param in lock_params for param in required_params):
            logger.debug("SMIL doesn't contain complete concurrency lock")
            return False

        # Build release URL with the same client_id formatted as player_{client_id}
        base_url = lock_params['concurrencyServiceUrl'].rstrip('/') + "/web/Concurrency/unlock"
        formatted_client_id = f"player_{client_id}"

        params = {
            'schema': '1.0',
            'form': 'json',
            '_clientId': formatted_client_id,  # Use player_{smil_client_id}
            '_id': lock_params['lockId'],
            '_sequenceToken': urllib.parse.quote(lock_params['lockSequenceToken']),
            '_encryptedLock': urllib.parse.quote(lock_params['lock'])
        }

        param_string = '&'.join([f"{k}={v}" for k, v in params.items()])
        release_url = f"{base_url}?{param_string}"

        logger.debug(f"Releasing concurrency lock: {lock_params['lockId']} with client: {formatted_client_id}")

        headers = {
            'User-Agent': user_agent,  # Use platform-specific user agent
            'Accept': 'application/json'
        }

        # Release the lock immediately
        # Release the lock immediately
        response = http_manager.get(
            release_url,
            operation='concurrency_unlock',
            headers=headers,
            timeout=10
        )

        # Log the response for debugging
        logger.debug(f"Concurrency unlock response: Status={response.status_code}, Content={response.text}")

        if response.status_code == 200:
            try:
                # Parse JSON response to verify it contains unlockResponse
                response_data = response.json()
                if 'unlockResponse' in response_data:
                    logger.info(f"✓ Concurrency lock released successfully with client: {formatted_client_id}")
                    return True
                else:
                    logger.warning(f"Concurrency lock release failed - missing unlockResponse: {response_data}")
                    return False
            except Exception as e:
                logger.warning(f"Concurrency lock release - invalid JSON response: {e}, Content: {response.text}")
                return False
        else:
            logger.warning(f"Concurrency lock release failed with status: {response.status_code}")
            return False

    except Exception as e:
        logger.warning(f"Error releasing concurrency lock: {e}")
        return False