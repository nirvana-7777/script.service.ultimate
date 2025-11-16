# streaming_providers/providers/magenta2/taa_client.py
import base64
import json
import time
from typing import Dict, Optional, Any
from dataclasses import dataclass

from ...base.network import HTTPManager
from ...base.utils.logger import logger
from .constants import (
    IDM,
    APPVERSION2,
    MAGENTA2_PLATFORMS,
    DEFAULT_PLATFORM
)


@dataclass
class YoDigitalTokens:
    """Result of yo_digital token operations"""
    access_token: str
    access_token_expires_in: int
    refresh_token: str
    refresh_token_expires_in: int
    device_limit_exceeded: bool = False
    raw_response: Optional[Dict[str, Any]] = None


@dataclass
class TaaAuthResult:
    """Result of TAA authentication (legacy - kept for compatibility)"""
    access_token: str
    refresh_token: Optional[str] = None
    dc_cts_persona_token: Optional[str] = None
    persona_id: Optional[str] = None
    account_id: Optional[str] = None
    consumer_id: Optional[str] = None
    tv_account_id: Optional[str] = None
    account_token: Optional[str] = None
    account_uri: Optional[str] = None
    token_exp: Optional[int] = None
    raw_response: Optional[Dict[str, Any]] = None
    device_limit_exceeded: bool = False


class TaaClient:
    """
    Telekom Authentication and Authorization (TAA) client
    Handles yo_digital token operations via the TAA endpoint
    """

    def __init__(self, http_manager: HTTPManager, platform: str = DEFAULT_PLATFORM):
        self.http_manager = http_manager
        self.platform = platform
        self.platform_config = MAGENTA2_PLATFORMS.get(platform, MAGENTA2_PLATFORMS[DEFAULT_PLATFORM])

    def get_yo_digital_tokens(self, taa_access_token: str, device_id: str,
                              client_model: Optional[str] = None,
                              device_model: Optional[str] = None,
                              yo_digital_endpoint: Optional[str] = None) -> Optional[YoDigitalTokens]:
        """
        Get yo_digital tokens from TAA endpoint (renamed from authenticate)

        Args:
            taa_access_token: TAA access token with 'taa' scope
            device_id: Device identifier
            client_model: Client model from bootstrap
            device_model: Device model from bootstrap
            yo_digital_endpoint: yo_digital endpoint URL (formerly taa_endpoint)

        Returns:
            YoDigitalTokens with access and refresh tokens, or None on failure
        """
        try:
            logger.debug("Getting yo_digital tokens from TAA endpoint")

            # Build complete TAA payload
            taa_payload = self._build_complete_taa_payload(
                sam3_token=taa_access_token,
                device_id=device_id,
                client_model=client_model,
                device_model=device_model
            )

            # Build headers
            headers = self._get_taa_headers()

            # Use provided endpoint or fallback
            endpoint = yo_digital_endpoint or "https://gateway-de-proxy.tv.yo-digital.com/de-idm/P/onboarding/login"

            logger.debug(f"yo_digital request to: {endpoint}")
            logger.debug(f"TAA payload keyValue: {taa_payload.get('keyValue', 'MISSING')}")

            # Perform yo_digital request
            response = self.http_manager.post(
                endpoint,
                operation='yo_digital_auth',
                headers=headers,
                json_data=taa_payload
            )

            # Log response details
            logger.debug(f"yo_digital response status: {response.status_code}")

            # Check for device limit exceeded or other errors
            if response.status_code == 400:
                try:
                    error_data = response.json()
                    logger.error(f"yo_digital 400 error response: {json.dumps(error_data, indent=2)}")

                    # Check for deviceLimitExceed (note: might be "Exceed" not "Exceeded")
                    if error_data.get('deviceLimitExceed') or error_data.get('deviceLimitExceeded'):
                        logger.error("Device limit exceeded in yo_digital authentication")
                        return YoDigitalTokens(
                            access_token="",
                            access_token_expires_in=0,
                            refresh_token="",
                            refresh_token_expires_in=0,
                            device_limit_exceeded=True
                        )

                    # Log any other error details
                    if 'error' in error_data:
                        logger.error(f"yo_digital error type: {error_data.get('error')}")
                    if 'error_description' in error_data:
                        logger.error(f"yo_digital error description: {error_data.get('error_description')}")
                    if 'message' in error_data:
                        logger.error(f"yo_digital error message: {error_data.get('message')}")

                except (ValueError, KeyError) as e:
                    logger.error(f"Could not parse 400 error response: {e}")
                    logger.error(f"Raw response text: {response.text}")

            response.raise_for_status()
            yo_digital_data = response.json()

            # Parse yo_digital response
            result = self._parse_yo_digital_response(yo_digital_data)

            logger.info("✓ yo_digital tokens obtained successfully")
            return result

        except Exception as e:
            logger.error(f"yo_digital token acquisition failed: {e}")

            # Try to extract error details if available
            if hasattr(e, 'response') and hasattr(e.response, 'text'):
                try:
                    error_body = e.response.text
                    logger.error(f"yo_digital error response body: {error_body}")
                    try:
                        error_json = e.response.json()
                        logger.error(f"yo_digital error response JSON: {json.dumps(error_json, indent=2)}")
                    except:
                        pass
                except:
                    pass

            return None

    def refresh_yo_digital_tokens(self, refresh_token: str,
                                  yo_digital_endpoint: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Refresh yo_digital tokens using refresh_token (STUB)

        Args:
            refresh_token: yo_digital refresh token
            yo_digital_endpoint: yo_digital endpoint URL

        Returns:
            Dictionary with new tokens in yo_digital format, or None on failure

        TODO: Implement actual refresh logic when endpoint/format is confirmed
        """
        try:
            logger.debug("Refreshing yo_digital tokens (STUB)")

            # STUB: Return None for now
            # When implemented, this should:
            # 1. POST to yo_digital endpoint with refresh_token
            # 2. Parse response in yo_digital format
            # 3. Return new tokens

            logger.warning("yo_digital token refresh not yet implemented")
            return None

        except Exception as e:
            logger.error(f"yo_digital token refresh failed: {e}")
            return None

    def _parse_yo_digital_response(self, yo_digital_data: Dict[str, Any]) -> Optional[YoDigitalTokens]:
        """
        Parse yo_digital response with proper field names

        yo_digital format:
        {
            "accessToken": "...",
            "accessExpiresIn": 86400,
            "refreshToken": "...",
            "refreshExpiresIn": 86400,
            "deviceLimitExceed": false,
            "tvAccountIds": null
        }
        """
        try:
            # Extract tokens using yo_digital field names
            access_token = yo_digital_data.get('accessToken')
            refresh_token = yo_digital_data.get('refreshToken')

            if not access_token or not refresh_token:
                logger.error("Missing access or refresh token in yo_digital response")
                return None

            # Extract expiry times
            access_expires_in = yo_digital_data.get('accessExpiresIn', 86400)
            refresh_expires_in = yo_digital_data.get('refreshExpiresIn', 86400)

            # Check device limit
            device_limit_exceeded = yo_digital_data.get('deviceLimitExceed', False) or \
                                    yo_digital_data.get('deviceLimitExceeded', False)

            result = YoDigitalTokens(
                access_token=access_token,
                access_token_expires_in=access_expires_in,
                refresh_token=refresh_token,
                refresh_token_expires_in=refresh_expires_in,
                device_limit_exceeded=device_limit_exceeded,
                raw_response=yo_digital_data
            )

            logger.debug(f"✓ Parsed yo_digital tokens: "
                         f"access_expires_in={access_expires_in}s, "
                         f"refresh_expires_in={refresh_expires_in}s")

            return result

        except Exception as e:
            logger.error(f"Failed to parse yo_digital response: {e}")
            return None

    # ========================================================================
    # Legacy TAA Authentication (kept for backward compatibility)
    # ========================================================================

    def authenticate(self, sam3_token: str, device_id: str, client_model: Optional[str] = None,
                     device_model: Optional[str] = None, taa_endpoint: Optional[str] = None) -> TaaAuthResult:
        """
        Legacy method - performs TAA authentication and parses JWT

        DEPRECATED: Use get_yo_digital_tokens() for new code
        This method is kept for backward compatibility with existing code
        """
        try:
            logger.debug("Starting TAA authentication (legacy method)")

            # Build complete TAA payload
            taa_payload = self._build_complete_taa_payload(
                sam3_token=sam3_token,
                device_id=device_id,
                client_model=client_model,
                device_model=device_model
            )

            # Build headers
            headers = self._get_taa_headers()

            # Use provided endpoint or fallback
            endpoint = taa_endpoint or "https://taa.telekom-dienste.de/taa/v1/token"

            logger.debug(f"TAA request to: {endpoint}")

            # Perform TAA request
            response = self.http_manager.post(
                endpoint,
                operation='taa_auth',
                headers=headers,
                json_data=taa_payload
            )

            # Check for device limit exceeded
            if response.status_code == 400:
                try:
                    error_data = response.json()
                    if error_data.get('deviceLimitExceeded'):
                        logger.error("Device limit exceeded in TAA authentication")
                        return TaaAuthResult(
                            access_token="",
                            device_limit_exceeded=True
                        )
                except:
                    pass

            response.raise_for_status()
            taa_data = response.json()

            # Parse TAA response (JWT format)
            result = self._parse_taa_response(taa_data)

            logger.info("TAA authentication successful")
            return result

        except Exception as e:
            logger.error(f"TAA authentication failed: {e}")
            raise Exception(f"TAA authentication failed: {e}")

    def _parse_taa_response(self, taa_data: Dict[str, Any]) -> TaaAuthResult:
        """
        Parse TAA response and extract all required claims from JWT
        (Legacy method for backward compatibility)
        """
        # Handle different response key formats
        access_token = taa_data.get('access_token', taa_data.get('accessToken'))
        refresh_token = taa_data.get('refresh_token', taa_data.get('refreshToken'))

        if not access_token:
            raise ValueError("No access token in TAA response")

        # Parse JWT to extract all claims
        jwt_claims = self._parse_taa_jwt_complete(access_token)

        # Create result with all extracted data
        result = TaaAuthResult(
            access_token=access_token,
            refresh_token=refresh_token,
            dc_cts_persona_token=jwt_claims.get('dc_cts_persona_token'),
            persona_id=jwt_claims.get('persona_id'),
            account_id=jwt_claims.get('account_id'),
            consumer_id=jwt_claims.get('consumer_id'),
            tv_account_id=jwt_claims.get('tv_account_id'),
            account_token=jwt_claims.get('account_token'),
            account_uri=jwt_claims.get('account_uri'),
            token_exp=jwt_claims.get('token_exp'),
            raw_response=taa_data
        )

        return result

    # ========================================================================
    # Common Methods (used by both yo_digital and legacy TAA)
    # ========================================================================

    def _build_complete_taa_payload(self, sam3_token: str, device_id: str,
                                    client_model: Optional[str] = None,
                                    device_model: Optional[str] = None) -> Dict[str, Any]:
        """
        Build complete TAA payload matching the correct format exactly

        Correct format:
        {
          "keyValue": "IDM/APPVERSION2/TokenChannelParams(id=Tv)/TokenDeviceParams(id=..., model=..., os=...)/DE/telekom",
          "accessToken": "...",
          "accessTokenSource": "IDM",
          "appVersion": "APPVERSION2",
          "channel": {"id": "Tv"},
          "device": {"id": "...", "model": "...", "os": "..."},
          "natco": "DE",
          "type": "telekom"
        }
        """
        # Use provided device model or fallback to TAA-specific device model
        resolved_device_model = device_model or self.platform_config.get('taa_device_model') or \
                                self.platform_config['device_name']

        # Get TAA-specific OS format
        resolved_os = self.platform_config.get('taa_os') or self.platform_config['firmware']

        resolved_client_model = client_model or f"ftv-{self.platform}"

        # Build keyValue string with CORRECT spacing (spaces after commas!)
        key_value_parts = [
            IDM,
            APPVERSION2,
            "TokenChannelParams(id=Tv)",
            f"TokenDeviceParams(id={device_id}, model={resolved_device_model}, os={resolved_os})",
            "DE",
            "telekom"
        ]

        key_value = "/".join(key_value_parts)

        # Build complete payload
        payload = {
            "keyValue": key_value,
            "accessToken": sam3_token,
            "accessTokenSource": IDM,
            "appVersion": APPVERSION2,
            "channel": {
                "id": "Tv"
            },
            "device": {
                "id": device_id,
                "model": resolved_device_model,
                "os": resolved_os
            },
            "natco": "DE",
            "type": "telekom"
        }

        # Add client model if available
        if resolved_client_model:
            payload["client"] = {"model": resolved_client_model}

        return payload

    @staticmethod
    def _parse_taa_jwt_complete(jwt_token: str) -> Dict[str, Any]:
        """
        Complete JWT parsing extracting ALL required fields from TAA token
        (Used by legacy authenticate method)
        """
        try:
            parts = jwt_token.split('.')
            if len(parts) != 3:
                logger.warning("Invalid JWT format in TAA token")
                return {}

            # Decode payload
            payload_b64 = parts[1]
            padding = len(payload_b64) % 4
            if padding:
                payload_b64 += '=' * (4 - padding)

            payload_json = base64.b64decode(payload_b64).decode('utf-8')
            claims = json.loads(payload_json)

            result = {}

            # Enhanced claim mappings
            claim_mappings = {
                'dc_cts_persona_token': [
                    'dc_cts_personaToken',
                    'dc_cts_persona_token',
                    'personaToken',
                    'urn:telekom:ott:dc_cts_persona_token'
                ],
                'account_uri': [
                    'dc_cts_account_uri',
                    'accountUri',
                    'urn:telekom:ott:dc_cts_account_uri',
                    'mpxAccountUri'
                ],
                'persona_id': [
                    'dc_cts_personaId',
                    'personaId',
                    'urn:telekom:ott:dc_cts_personaId'
                ],
                'account_id': [
                    'dc_cts_accountId',
                    'accountId',
                    'urn:telekom:ott:dc_cts_accountId'
                ],
                'consumer_id': [
                    'dc_cts_consumerId',
                    'consumerId',
                    'urn:telekom:ott:dc_cts_consumerId'
                ],
                'tv_account_id': [
                    'dc_tvAccountId',
                    'tvAccountId',
                    'urn:telekom:ott:dc_tvAccountId'
                ],
                'account_token': [
                    'dc_cts_account_token',
                    'accountToken',
                    'urn:telekom:ott:dc_cts_account_token'
                ],
            }

            # Extract all claims
            for target_key, source_keys in claim_mappings.items():
                for source_key in source_keys:
                    if source_key in claims:
                        result[target_key] = claims[source_key]
                        break

            # Extract token expiration
            if 'exp' in claims:
                result['token_exp'] = claims['exp']

            return result

        except Exception as e:
            logger.error(f"Failed to parse TAA JWT: {e}")
            return {}

    def _get_taa_headers(self) -> Dict[str, str]:
        """
        Get headers for TAA/yo_digital requests
        """
        import uuid

        user_agent = self.platform_config.get('user_agent')

        headers = {
            'requestId': str(uuid.uuid4()),
            'User-Agent': user_agent,
            'Accept': 'application/json',
            'Content-Type': 'application/json; charset=UTF-8'
        }

        return headers

    # ========================================================================
    # Validation and Debugging
    # ========================================================================

    def validate_taa_token(self, taa_token: str) -> bool:
        """
        Validate TAA token expiration and basic structure
        """
        try:
            if not taa_token:
                return False

            claims = self._parse_taa_jwt_complete(taa_token)
            token_exp = claims.get('token_exp')

            if token_exp and token_exp < time.time():
                logger.debug("TAA token is expired")
                return False

            if claims.get('dc_cts_persona_token') and claims.get('account_uri'):
                return True

            return False

        except Exception as e:
            logger.debug(f"TAA token validation failed: {e}")
            return False

    def debug_taa_token(self, taa_token: str) -> Dict[str, Any]:
        """
        Debug method to analyze TAA token contents
        """
        claims = self._parse_taa_jwt_complete(taa_token)

        return {
            'token_structure': 'VALID' if len(taa_token.split('.')) == 3 else 'INVALID',
            'claims_available': list(claims.keys()),
            'essential_claims': {
                'dc_cts_persona_token': bool(claims.get('dc_cts_persona_token')),
                'account_uri': bool(claims.get('account_uri')),
                'persona_id': bool(claims.get('persona_id')),
                'account_id': bool(claims.get('account_id'))
            },
            'token_expiration': {
                'exp': claims.get('token_exp'),
                'is_expired': claims.get('token_exp', 0) < time.time() if claims.get('token_exp') else None,
                'current_time': time.time()
            } if claims.get('token_exp') else None
        }