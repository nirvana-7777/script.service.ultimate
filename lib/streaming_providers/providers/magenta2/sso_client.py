# streaming_providers/providers/magenta2/sso_client.py
from typing import Dict, Optional, Any

from ...base.network import HTTPManager
from ...base.utils.logger import logger
from .constants import (
    SSO_URL,
    SSO_USER_AGENT,
    DEFAULT_REQUEST_TIMEOUT
)


class SsoClient:
    """
    SSO (Single Sign-On) client implementing the complete SSO flow from C++ code
    """

    def __init__(self, http_manager: HTTPManager, session_id: str, device_id: str):
        self.http_manager = http_manager
        self.session_id = session_id
        self.device_id = device_id

    def sso_login(self) -> str:
        """
        Get SSO login redirect URL
        Matching C++ SsoClient::SSOLogin()
        """
        try:
            logger.debug("Getting SSO login redirect URL")

            url = f"{SSO_URL}login"
            headers = self._get_sso_headers()

            response = self.http_manager.get(
                url,
                operation='sso_login',
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()

            data = response.json()

            login_redirect_url = data.get('loginRedirectUrl')
            if not login_redirect_url:
                raise Exception("No loginRedirectUrl in SSO response")

            logger.debug(f"SSO login redirect URL obtained: {login_redirect_url}")
            return login_redirect_url

        except Exception as e:
            logger.error(f"SSO login failed: {e}")
            raise Exception(f"SSO login failed: {e}")

    def sso_authenticate(self, code: str = "", state: str = "") -> Dict[str, Any]:
        """
        SSO authentication with code/state or refresh token
        Matching C++ SsoClient::SSOAuthenticate()

        Returns:
            Dict with userInfo including userId, accountId, displayName, personaToken
        """
        try:
            logger.debug("Performing SSO authentication")

            url = f"{SSO_URL}authenticate"
            headers = self._get_sso_headers()

            # Build request body matching C++ structure
            if code and state:
                # Authentication with authorization code
                body = {
                    "checkRefreshToken": True,
                    "returnCode": {
                        "code": code,
                        "state": state
                    }
                }
                logger.debug(f"SSO auth with code: {code[:8]}..., state: {state}")
            else:
                # Authentication with refresh token only
                body = {
                    "checkRefreshToken": True
                }
                logger.debug("SSO auth with refresh token only")

            response = self.http_manager.post(
                url,
                operation='sso_authenticate',
                headers=headers,
                json_data=body,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()

            data = response.json()

            # Check for userInfo in response
            if 'userInfo' not in data:
                raise Exception("No userInfo in SSO authentication response")

            user_info = data['userInfo']

            # Extract required fields with fallbacks
            result = {
                'userId': user_info.get('userId', ''),
                'accountId': user_info.get('accountId', ''),
                'displayName': user_info.get('displayName', ''),
                'personaToken': user_info.get('personaToken', ''),
                'raw_response': data
            }

            # Validate required fields
            if not result['userId'] or not result['accountId']:
                logger.warning("SSO authentication missing required user identifiers")

            if not result['personaToken']:
                logger.warning("SSO authentication did not return personaToken")

            logger.info(
                f"SSO authentication successful: "
                f"userId={result['userId']}, "
                f"accountId={result['accountId']}, "
                f"displayName={result['displayName'][:20]}... "
                f"personaToken={'YES' if result['personaToken'] else 'NO'}"
            )

            return result

        except Exception as e:
            logger.error(f"SSO authentication failed: {e}")
            raise Exception(f"SSO authentication failed: {e}")

    def sso_refresh(self) -> Dict[str, Any]:
        """
        Refresh SSO session using refresh token
        This is essentially sso_authenticate without code/state
        """
        return self.sso_authenticate()

    @staticmethod
    def validate_persona_token(self, persona_token: str) -> bool:
        """
        Validate persona token (optional enhancement)
        Not in original C++ code but useful for token management
        """
        try:
            # Simple validation - check if token has expected structure
            if not persona_token or len(persona_token) < 10:
                return False

            # Could add more sophisticated validation here
            # For now, just check if it looks like a JWT or base64 token
            parts = persona_token.split('.')
            if len(parts) == 3:
                # Looks like a JWT
                return True
            else:
                # Might be base64 encoded
                import base64
                try:
                    decoded = base64.b64decode(persona_token + '==')
                    return len(decoded) > 0
                except:
                    return False

        except Exception as e:
            logger.debug(f"Persona token validation failed: {e}")
            return False

    def get_user_profile(self) -> Optional[Dict[str, Any]]:
        """
        Get additional user profile information (optional enhancement)
        Not in original C++ code
        """
        try:
            url = f"{SSO_URL}profile"
            headers = self._get_sso_headers()

            response = self.http_manager.get(
                url,
                operation='sso_profile',
                headers=headers,
                timeout=DEFAULT_REQUEST_TIMEOUT
            )
            response.raise_for_status()

            return response.json()

        except Exception as e:
            logger.debug(f"Failed to get user profile: {e}")
            return None

    def _get_sso_headers(self) -> Dict[str, str]:
        """Get headers for SSO requests matching C++ implementation"""
        headers = {
            'User-Agent': SSO_USER_AGENT,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'origin': 'https://web2.magentatv.de',
            'referer': 'https://web2.magentatv.de/'
        }

        # Add session and device headers if available
        if self.session_id:
            headers['session-id'] = self.session_id
        if self.device_id:
            headers['device-id'] = self.device_id

        return headers

    def debug_sso_state(self) -> Dict[str, Any]:
        """Debug method to check SSO client state"""
        return {
            'session_id': self.session_id,
            'device_id': self.device_id,
            'sso_url': SSO_URL,
            'headers_configured': bool(self.session_id and self.device_id)
        }