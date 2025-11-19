# streaming_providers/providers/magenta2/token_utils.py
# -*- coding: utf-8 -*-
"""
Unified JWT and Persona Token utilities for Magenta2
Consolidates all JWT parsing and persona token composition logic
"""

import base64
import json
from typing import Dict, Any, Optional
from dataclasses import dataclass

from ...base.utils.logger import logger


@dataclass
class JWTClaims:
    """Structured JWT claims for Magenta2 tokens"""
    # Raw claims
    raw_claims: Dict[str, Any]

    # Persona token components
    dc_cts_persona_token: Optional[str] = None
    account_uri: Optional[str] = None

    # User identifiers
    persona_id: Optional[str] = None
    account_id: Optional[str] = None
    consumer_id: Optional[str] = None
    tv_account_id: Optional[str] = None

    # Token metadata
    account_token: Optional[str] = None
    token_exp: Optional[int] = None
    client_id: Optional[str] = None

    # SSO fields
    sso_user_id: Optional[str] = None
    sso_display_name: Optional[str] = None

    def has_persona_components(self) -> bool:
        """Check if claims contain components needed for persona token"""
        return bool(self.dc_cts_persona_token and self.account_uri)

    def is_user_token(self) -> bool:
        """Check if this is a user-authenticated token"""
        return bool(
            self.persona_id or
            self.account_id or
            self.consumer_id or
            self.tv_account_id
        )


class JWTParser:
    """Unified JWT parsing utilities"""

    # Comprehensive claim mappings for all Magenta2 token types
    CLAIM_MAPPINGS = {
        'dc_cts_persona_token': [
            'dc_cts_persona_token',
            'dc_cts_personaToken',
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

    @staticmethod
    def parse(jwt_token: str) -> Optional[JWTClaims]:
        """
        Parse JWT token and extract all Magenta2-specific claims

        Args:
            jwt_token: JWT token string

        Returns:
            JWTClaims object or None if parsing fails
        """
        try:
            # Decode JWT
            parts = jwt_token.split('.')
            if len(parts) != 3:
                logger.warning("Invalid JWT format - expected 3 parts")
                return None

            # Decode payload with padding
            payload_b64 = parts[1]
            padding = len(payload_b64) % 4
            if padding:
                payload_b64 += '=' * (4 - padding)

            payload_json = base64.b64decode(payload_b64).decode('utf-8')
            raw_claims = json.loads(payload_json)

            logger.debug(f"JWT parsed successfully - claims: {list(raw_claims.keys())}")

            # Extract structured claims
            claims = JWTClaims(raw_claims=raw_claims)

            # Map all known claims
            for target_key, source_keys in JWTParser.CLAIM_MAPPINGS.items():
                for source_key in source_keys:
                    if source_key in raw_claims:
                        setattr(claims, target_key, raw_claims[source_key])
                        logger.debug(f"Mapped {target_key} from {source_key}")
                        break

            # Extract standard JWT fields
            claims.token_exp = raw_claims.get('exp')
            claims.client_id = raw_claims.get('client_id', raw_claims.get('clientId'))

            # Log critical missing fields
            if not claims.dc_cts_persona_token:
                logger.warning("JWT missing dc_cts_persona_token")
            if not claims.account_uri:
                logger.warning("JWT missing account_uri")

            return claims

        except Exception as e:
            logger.error(f"Failed to parse JWT token: {e}")
            return None

    @staticmethod
    def extract_raw_claims(jwt_token: str) -> Optional[Dict[str, Any]]:
        """
        Extract raw claims dictionary without mapping
        Useful for debugging or custom claim extraction

        Args:
            jwt_token: JWT token string

        Returns:
            Dictionary of raw claims or None
        """
        try:
            parts = jwt_token.split('.')
            if len(parts) != 3:
                return None

            payload_b64 = parts[1]
            padding = len(payload_b64) % 4
            if padding:
                payload_b64 += '=' * (4 - padding)

            payload_json = base64.b64decode(payload_b64).decode('utf-8')
            return json.loads(payload_json)

        except Exception as e:
            logger.debug(f"Failed to extract raw JWT claims: {e}")
            return None


class PersonaTokenComposer:
    """Unified persona token composition"""

    @staticmethod
    def compose_from_jwt(jwt_token: str,
                         fallback_account_uri: Optional[str] = None) -> Optional[str]:
        """
        Compose persona token from JWT access token

        This is the PRIMARY method for persona token composition.
        Format: Base64(account_uri + ":" + dc_cts_persona_token)

        Args:
            jwt_token: JWT access token containing persona claims
            fallback_account_uri: Optional fallback account URI if not in JWT

        Returns:
            Base64-encoded persona token or None
        """
        try:
            # Parse JWT to extract claims
            claims = JWTParser.parse(jwt_token)
            if not claims:
                logger.error("Failed to parse JWT for persona token composition")
                return None

            # Get persona JWT token (the nested JWT)
            persona_jwt = claims.dc_cts_persona_token
            if not persona_jwt:
                logger.error("No dc_cts_persona_token found in JWT claims")
                return None

            # Get account URI (prefer JWT, then fallback)
            account_uri = claims.account_uri or fallback_account_uri
            if not account_uri:
                logger.error("No account_uri available for persona token composition")
                return None

            # Compose raw token
            raw_token = f"{account_uri}:{persona_jwt}"

            # Base64 encode
            persona_token = base64.b64encode(
                raw_token.encode('utf-8')
            ).decode('utf-8')

            logger.info("✓ Persona token composed successfully")
            logger.debug(f"Account URI: {account_uri}")
            logger.debug(f"Persona token length: {len(persona_token)}")
            logger.debug(f"Persona token preview: {persona_token[:50]}...")

            return persona_token

        except Exception as e:
            logger.error(f"Failed to compose persona token from JWT: {e}")
            return None

    @staticmethod
    def compose_from_components(account_uri: str,
                                dc_cts_persona_token: str) -> Optional[str]:
        """
        Compose persona token from explicit components

        Use this when you already have extracted components.

        Args:
            account_uri: Account URI (e.g., "http://access.auth.theplatform.com/...")
            dc_cts_persona_token: The persona JWT token

        Returns:
            Base64-encoded persona token or None
        """
        try:
            if not account_uri or not dc_cts_persona_token:
                logger.warning(
                    f"Cannot compose persona token - "
                    f"account_uri: {bool(account_uri)}, "
                    f"dc_cts_persona_token: {bool(dc_cts_persona_token)}"
                )
                return None

            # Compose raw token
            raw_token = f"{account_uri}:{dc_cts_persona_token}"

            # Base64 encode
            persona_token = base64.b64encode(
                raw_token.encode('utf-8')
            ).decode('utf-8')

            logger.info("✓ Persona token composed from components")
            logger.debug(f"Composed token preview: {persona_token[:50]}...")

            return persona_token

        except Exception as e:
            logger.error(f"Failed to compose persona token from components: {e}")
            return None

    @staticmethod
    def extract_components_from_persona_token(persona_token: str) -> Optional[Dict[str, str]]:
        """
        Extract components from an existing persona token
        Useful for debugging or token analysis

        Args:
            persona_token: Base64-encoded persona token

        Returns:
            Dictionary with 'account_uri' and 'persona_jwt' or None
        """
        try:
            # Decode base64
            decoded = base64.b64decode(persona_token).decode('utf-8')

            # Find the last colon (after the account URI which may contain colons)
            last_colon_index = decoded.rfind(':')

            if last_colon_index == -1:
                logger.error("No colon found in decoded persona token")
                return None

            account_uri = decoded[:last_colon_index]
            persona_jwt = decoded[last_colon_index + 1:]

            # Verify persona_jwt looks like a JWT
            if not persona_jwt.startswith('eyJ'):
                logger.warning(f"Extracted token doesn't look like a JWT: {persona_jwt[:20]}...")

            return {
                'account_uri': account_uri,
                'persona_jwt': persona_jwt
            }

        except Exception as e:
            logger.error(f"Failed to extract components from persona token: {e}")
            return None


class TokenValidator:
    """Token validation utilities"""

    @staticmethod
    def is_jwt_token(token: str) -> bool:
        """Check if string is a valid JWT token format"""
        try:
            parts = token.split('.')
            return len(parts) == 3 and parts[0].startswith('eyJ')
        except:
            return False

    @staticmethod
    def is_persona_token(token: str) -> bool:
        """Check if string is a valid persona token format"""
        try:
            # Should be base64 encoded
            decoded = base64.b64decode(token).decode('utf-8')
            # Should contain a colon and the part after should look like a JWT
            last_colon = decoded.rfind(':')
            if last_colon == -1:
                return False
            persona_jwt = decoded[last_colon + 1:]
            return persona_jwt.startswith('eyJ')
        except:
            return False
