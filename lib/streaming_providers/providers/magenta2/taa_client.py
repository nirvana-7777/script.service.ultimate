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
class TaaAuthResult:
    """Result of TAA authentication"""
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
    Handles complete TAA authentication flow with proper JWT parsing
    """

    def __init__(self, http_manager: HTTPManager, platform: str = DEFAULT_PLATFORM):
        self.http_manager = http_manager
        self.platform = platform
        self.platform_config = MAGENTA2_PLATFORMS.get(platform, MAGENTA2_PLATFORMS[DEFAULT_PLATFORM])

    def authenticate(self, sam3_token: str, device_id: str, client_model: Optional[str] = None,
                     device_model: Optional[str] = None, taa_endpoint: Optional[str] = None) -> TaaAuthResult:
        """
        Perform complete TAA authentication

        Args:
            sam3_token: SAM3 access token for TAA scope
            device_id: Device identifier
            client_model: Client model from bootstrap
            device_model: Device model from bootstrap (if None, uses taa_device_model from platform config)
            taa_endpoint: TAA endpoint URL

        Returns:
            TaaAuthResult with complete authentication data
        """
        try:
            logger.debug("Starting TAA authentication")

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
            logger.debug(f"TAA payload keyValue: {taa_payload.get('keyValue', 'MISSING')}")

            # Log complete payload for debugging (mask sensitive data)
            payload_debug = taa_payload.copy()
            if 'accessToken' in payload_debug:
                payload_debug['accessToken'] = payload_debug['accessToken'][:50] + '...'
            logger.debug(f"Complete TAA payload: {json.dumps(payload_debug, indent=2)}")
            logger.debug(f"TAA headers: {headers}")

            # Perform TAA request
            response = self.http_manager.post(
                endpoint,
                operation='taa_auth',
                headers=headers,
                json_data=taa_payload
            )

            # Log response details
            logger.debug(f"TAA response status: {response.status_code}")

            # Check for device limit exceeded or other errors
            if response.status_code == 400:
                try:
                    error_data = response.json()
                    logger.error(f"TAA 400 error response: {json.dumps(error_data, indent=2)}")

                    if error_data.get('deviceLimitExceeded'):
                        logger.error("Device limit exceeded in TAA authentication")
                        return TaaAuthResult(
                            access_token="",
                            device_limit_exceeded=True
                        )

                    # Log any other error details
                    if 'error' in error_data:
                        logger.error(f"TAA error type: {error_data.get('error')}")
                    if 'error_description' in error_data:
                        logger.error(f"TAA error description: {error_data.get('error_description')}")
                    if 'message' in error_data:
                        logger.error(f"TAA error message: {error_data.get('message')}")

                except (ValueError, KeyError) as e:
                    logger.error(f"Could not parse 400 error response: {e}")
                    logger.error(f"Raw response text: {response.text}")

            response.raise_for_status()
            taa_data = response.json()

            # Parse TAA response
            result = self._parse_taa_response(taa_data)

            logger.info("TAA authentication successful")
            return result

        except Exception as e:
            logger.error(f"TAA authentication failed: {e}")

            # Try to extract error details if available (for requests.HTTPError)
            if hasattr(e, 'response') and hasattr(e.response, 'text'):
                try:
                    error_body = e.response.text
                    logger.error(f"TAA error response body: {error_body}")
                    try:
                        error_json = e.response.json()
                        logger.error(f"TAA error response JSON: {json.dumps(error_json, indent=2)}")
                    except:
                        pass
                except:
                    pass

            raise Exception(f"TAA authentication failed: {e}")

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

        CRITICAL: Note the spaces after commas in TokenDeviceParams!
        """
        # Use provided device model or fallback to TAA-specific device model from platform config
        # TAA requires specific device identification format (e.g., "SHIELD Android TV", "API level 30")
        resolved_device_model = device_model or self.platform_config.get('taa_device_model') or self.platform_config[
            'device_name']

        # Get TAA-specific OS format (e.g., "API level 30" instead of "Android 11")
        resolved_os = self.platform_config.get('taa_os') or self.platform_config['firmware']

        resolved_client_model = client_model or f"ftv-{self.platform}"

        # Build keyValue string with CORRECT spacing (spaces after commas!)
        # Format: TokenDeviceParams(id=..., model=..., os=...)
        #                                 ^         ^
        #                            spaces here!
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

        # Add client model if available (not in original C++ but useful)
        if resolved_client_model:
            payload["client"] = {"model": resolved_client_model}

        # Validate payload has all required fields
        required_fields = ["keyValue", "accessToken", "accessTokenSource", "appVersion", "channel", "device", "natco",
                           "type"]
        missing_fields = [field for field in required_fields if field not in payload]
        if missing_fields:
            logger.error(f"TAA payload missing required fields: {missing_fields}")
            raise ValueError(f"TAA payload incomplete: missing {missing_fields}")

        logger.debug(f"Built TAA payload with keyValue: {key_value}")
        logger.debug(f"Device model: {resolved_device_model}, OS: {resolved_os}")
        logger.debug(f"Payload fields: {list(payload.keys())}")

        return payload

    def _parse_taa_response(self, taa_data: Dict[str, Any]) -> TaaAuthResult:
        """
        Parse TAA response and extract all required claims from JWT
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

        # Log critical fields
        if result.dc_cts_persona_token:
            logger.debug("✓ dc_cts_persona_token found in TAA JWT")
        else:
            logger.warning("✗ dc_cts_persona_token NOT found in TAA JWT")

        if result.account_uri:
            logger.debug(f"✓ account_uri found: {result.account_uri}")
        else:
            logger.warning("✗ account_uri NOT found in TAA JWT")

        return result

    @staticmethod
    def _parse_taa_jwt_complete(jwt_token: str) -> Dict[str, Any]:
        """
        Complete JWT parsing extracting ALL required fields from TAA token
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

            logger.debug(f"TAA JWT claims: {list(claims.keys())}")

            result = {}

            # Enhanced claim mappings - ALL fields from C++ implementation
            claim_mappings = {
                # Core persona token (most important!)
                'dc_cts_persona_token': [
                    'dc_cts_personaToken',  # Capital T! This is what the API returns
                    'dc_cts_persona_token',
                    'personaToken',
                    'urn:telekom:ott:dc_cts_persona_token'
                ],

                # Account URI (needed for composition!)
                'account_uri': [
                    'dc_cts_account_uri',
                    'accountUri',
                    'urn:telekom:ott:dc_cts_account_uri',
                    'mpxAccountUri'
                ],

                # IDs
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

                # Account token
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
                        logger.debug(f"Extracted TAA claim {target_key} from {source_key}")
                        break

            # Extract token expiration
            if 'exp' in claims:
                result['token_exp'] = claims['exp']
                logger.debug(f"TAA token expires at: {claims['exp']}")

            # Extract issuance time
            if 'iat' in claims:
                result['token_iat'] = claims['iat']

            # CRITICAL CHECK: Verify we have the essential fields
            essential_fields = ['dc_cts_persona_token', 'account_uri']
            missing_essential = [field for field in essential_fields if field not in result]

            if missing_essential:
                logger.error(f"CRITICAL: Missing essential TAA claims: {missing_essential}")
                logger.debug(f"Available TAA claims: {list(claims.keys())}")
            else:
                logger.info("✓ All essential TAA claims found")

            return result

        except Exception as e:
            logger.error(f"Failed to parse TAA JWT completely: {e}")
            return {}

    def _get_taa_headers(self) -> Dict[str, str]:
        """
        Get headers for TAA requests with required requestId

        Note: The accessToken is sent in the request body, not as Authorization header.
        The TAA endpoint uses the token from the payload, not from headers.
        """
        import uuid

        # Use TAA-specific user agent if available, otherwise fallback to platform user agent
        user_agent = self.platform_config.get('user_agent')

        headers = {
            'requestId': str(uuid.uuid4()),  # Required by TAA endpoint!
            'User-Agent': user_agent,
            'Accept': 'application/json',
            'Content-Type': 'application/json; charset=UTF-8'
        }

        # NOTE: We do NOT add Authorization header here
        # The accessToken is sent in the request body payload
        # Authorization header is not needed for TAA endpoint

        return headers

    def validate_taa_token(self, taa_token: str) -> bool:
        """
        Validate TAA token expiration and basic structure
        """
        try:
            if not taa_token:
                return False

            # Check if token is expired
            claims = self._parse_taa_jwt_complete(taa_token)
            token_exp = claims.get('token_exp')

            if token_exp and token_exp < time.time():
                logger.debug("TAA token is expired")
                return False

            # Check for essential claims
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