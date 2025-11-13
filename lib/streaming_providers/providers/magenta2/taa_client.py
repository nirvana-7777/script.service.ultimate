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
            device_model: Device model from bootstrap
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
            headers = self._get_taa_headers(sam3_token)

            # Use provided endpoint or fallback
            endpoint = taa_endpoint or "https://taa.telekom-dienste.de/taa/v1/token"

            logger.debug(f"TAA request to: {endpoint}")
            logger.debug(f"TAA payload keyValue: {taa_payload.get('keyValue', 'MISSING')}")

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
                except (ValueError, KeyError):
                    pass  # Will be handled by raise_for_status below

            response.raise_for_status()
            taa_data = response.json()

            # Parse TAA response
            result = self._parse_taa_response(taa_data)

            logger.info("TAA authentication successful")
            return result

        except Exception as e:
            logger.error(f"TAA authentication failed: {e}")
            raise Exception(f"TAA authentication failed: {e}")

    def _build_complete_taa_payload(self, sam3_token: str, device_id: str,
                                    client_model: Optional[str] = None,
                                    device_model: Optional[str] = None) -> Dict[str, Any]:
        """
        Build complete TAA payload matching C++ structure exactly

        C++ structure:
        {
          "keyValue": "IDM/APPVERSION2/TokenChannelParams(id=Tv)/TokenDeviceParams(id=...,model=...,os=...)/DE/telekom",
          "accessToken": "...",
          "accessTokenSource": "IDM",
          "appVersion": "APPVERSION2",
          "channel": {"id": "Tv"},
          "device": {"id": "...", "model": "...", "os": "..."},
          "natco": "DE",
          "type": "telekom"
        }
        """
        # Use provided models or fallback to platform defaults
        resolved_device_model = device_model or self.platform_config['device_name']
        resolved_client_model = client_model or f"ftv-{self.platform}"

        # Build keyValue string matching C++ format exactly
        key_value_parts = [
            IDM,
            APPVERSION2,
            "TokenChannelParams(id=Tv)",
            f"TokenDeviceParams(id={device_id},model={resolved_device_model},os={self.platform_config['firmware']})",
            "DE",
            "telekom"
        ]

        key_value = "/".join(key_value_parts)

        # Build complete payload matching C++ structure
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
                "os": self.platform_config['firmware']
            },
            "natco": "DE",
            "type": "telekom"
        }

        # Add client model if available (not in original C++ but useful)
        if resolved_client_model:
            payload["client"] = {"model": resolved_client_model}

        logger.debug(f"Built TAA payload with keyValue: {key_value}")
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

    def _parse_taa_jwt_complete(self, jwt_token: str) -> Dict[str, Any]:
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

    def _get_taa_headers(self, sam3_token: str) -> Dict[str, str]:
        """Get headers for TAA requests"""
        return {
            'User-Agent': self.platform_config['user_agent'],
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {sam3_token}'
        }

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