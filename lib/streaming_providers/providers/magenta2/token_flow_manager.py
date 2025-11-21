# streaming_providers/providers/magenta2/token_flow_manager.py
"""
Hierarchical Token Flow Manager for Magenta2
Manages the complete token acquisition hierarchy:
yo_digital → taa → tvhubs → line_auth/remote_login
"""

import time
from typing import Optional, Dict, Any
from dataclasses import dataclass

from .constants import MAGENTA2_FALLBACK_ACCOUNT_URI
from ...base.utils.logger import logger
from ...base.auth.session_manager import SessionManager
from .sam3_client import Sam3Client
from .taa_client import TaaClient


@dataclass
class TokenFlowResult:
    """Result of token flow operation"""
    success: bool
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    access_token_expires_in: Optional[int] = None
    refresh_token_expires_in: Optional[int] = None
    error: Optional[str] = None
    flow_path: Optional[str] = None  # For debugging which path was taken

@dataclass
class PersonaResult:
    success: bool
    persona_token: Optional[str] = None
    expires_at: Optional[float] = None
    error: Optional[str] = None

class TokenFlowManager:
    """
    Manages hierarchical token acquisition for Magenta2

    Token Hierarchy:
    1. yo_digital tokens (goal) - access + refresh, separate expiry
    2. taa access_token (from SAM3 via refresh_token exchange)
    3. tvhubs access_token + shared refresh_token (from line_auth/remote_login)

    Flow Priority:
    1. Check yo_digital access_token (valid?) → use it ✓
    2. Check yo_digital refresh_token (valid?) → refresh yo_digital
    3. Check taa access_token (valid?) → get yo_digital
    4. Check shared refresh_token (exists?) → exchange for taa → get yo_digital
    5. Try line_auth → get tvhubs + refresh_token → chain to yo_digital
    6. Try remote_login → get tvhubs + refresh_token → chain to yo_digital
    7. All failed → ERROR
    """
    def __init__(self,
                 session_manager: SessionManager,
                 sam3_client: 'Sam3Client',
                 taa_client: 'TaaClient',
                 provider_name: str,
                 country: Optional[str] = None,
                 provider_config: Optional[Any] = None,
                 # NEW: Add optional callbacks
                 line_auth_callback: Optional[callable] = None,
                 remote_login_callback: Optional[callable] = None):
        """
        Initialize TokenFlowManager

        Args:
            session_manager: SessionManager for token storage
            sam3_client: SAM3 client for tvhubs/taa operations
            taa_client: TAA client for yo_digital operations
            provider_name: Provider name (e.g., 'magenta2')
            country: Optional country code
        """
        self.session_manager = session_manager
        self.sam3_client = sam3_client
        self.taa_client = taa_client
        self.provider_name = provider_name
        self.country = country
        self.provider_config = provider_config

        # Store callbacks
        self._line_auth_callback = line_auth_callback
        self._remote_login_callback = remote_login_callback

        logger.debug(f"TokenFlowManager initialized for {provider_name}" +
                     (f" ({country})" if country else ""))

    def get_persona_token(self, force_refresh: bool = False) -> PersonaResult:
        """Get persona token with proper JWT expiry caching"""
        logger.debug("=== GET_PERSONA_TOKEN START ===")

        # Check for cached persona token with proper expiry validation
        if not force_refresh:
            cached_result = self._get_cached_persona_token()
            if cached_result.success:
                logger.debug("=== GET_PERSONA_TOKEN SUCCESS (cached) ===")
                return cached_result

        # Get the yo_digital token
        token_result = self.get_yo_digital_token(force_refresh)

        if not token_result.success or not token_result.access_token:
            logger.debug("=== GET_PERSONA_TOKEN FAILED (token_result failed) ===")
            return PersonaResult(
                success=False,
                error=token_result.error or "No access token"
            )

        # Compose persona token with expiry information using existing method
        from .token_utils import PersonaTokenComposer
        composition_result = PersonaTokenComposer.compose_from_jwt(
            token_result.access_token,
            MAGENTA2_FALLBACK_ACCOUNT_URI
        )

        if not composition_result:
            logger.debug("=== GET_PERSONA_TOKEN FAILED (composition failed) ===")
            return PersonaResult(
                success=False,
                error="Failed to compose persona token"
            )

        # Cache with the correct expiry (from persona JWT)
        self._cache_persona_composition(composition_result)

        logger.debug("=== GET_PERSONA_TOKEN SUCCESS ===")
        return PersonaResult(
            success=True,
            persona_token=composition_result.persona_token,
            expires_at=composition_result.expires_at  # 🆕 Return expiry
        )

    def _get_cached_persona_token(self) -> PersonaResult:
        """Check for cached persona token using the actual persona JWT expiry"""
        try:
            logger.debug("🟡 Checking cached persona token...")
            persona_data = self.session_manager.load_scoped_token(
                self.provider_name,
                'persona',
                self.country
            )

            safe_persona_data = {
                'has_persona_token': 'persona_token' in persona_data,
                'has_persona_jwt': 'persona_jwt' in persona_data,
                'expires_at': persona_data.get('expires_at'),
                'composed_at': persona_data.get('composed_at')
            }
            logger.debug(f"🟡 Loaded persona_data: {safe_persona_data}")

            if (persona_data and
                    'persona_token' in persona_data and
                    'persona_jwt' in persona_data and
                    'expires_at' in persona_data):

                current_time = time.time()
                expires_at = persona_data['expires_at']

                logger.debug(f"🟡 Current time: {current_time}, Expires at: {expires_at}")

                # Check if cached token is still valid using the actual persona JWT expiry
                if current_time < (expires_at - 300):  # 5-minute buffer
                    logger.debug(f"🟡 Using cached persona token (expires at {time.ctime(expires_at)})")
                    return PersonaResult(
                        success=True,
                        persona_token=persona_data['persona_token'],
                        expires_at=expires_at  # 🆕 Return expiry
                    )
                else:
                    logger.debug(f"🟡 Cached persona token expired at {time.ctime(expires_at)}")

            else:
                logger.debug("🟡 No valid persona data in cache")

        except Exception as e:
            logger.debug(f"🟡 Error checking cached persona token: {e}")

        return PersonaResult(success=False, error="No valid cached token")

    def _cache_persona_composition(self, composition_result) -> None:
        """Cache persona composition with proper expiry"""
        persona_data = {
            'persona_token': composition_result.persona_token,
            'persona_jwt': composition_result.persona_jwt,  # Store for validation
            'expires_at': composition_result.expires_at,
            'composed_at': composition_result.composed_at
        }

        success = self.session_manager.save_scoped_token(
            self.provider_name,
            'persona',
            persona_data,
            self.country
        )

        if success:
            logger.debug(f"✓ Persona token cached until {time.ctime(composition_result.expires_at)}")
        else:
            logger.debug("✗ Failed to cache persona token")

    # Keep the existing _compose_persona_token method for backward compatibility
    @staticmethod
    def _compose_persona_token(access_token: str) -> Optional[str]:
        """Backward compatibility method - delegates to new composition"""
        from .token_utils import PersonaTokenComposer
        result = PersonaTokenComposer.compose_from_jwt(
            access_token,
            MAGENTA2_FALLBACK_ACCOUNT_URI
        )
        return result.persona_token if result else None

    def get_yo_digital_token(self, force_refresh: bool = False) -> TokenFlowResult:
        """
        Get yo_digital access token following the complete hierarchy

        Args:
            force_refresh: Skip cached tokens and force refresh

        Returns:
            TokenFlowResult with yo_digital access token or error
        """
        country_str = f" ({self.country})" if self.country else ""
        logger.info(f"Getting yo_digital token for {self.provider_name}{country_str}")

        if not force_refresh:
            # Step 1: Check existing yo_digital access_token
            result = self._check_yo_digital_access_token()
            if result.success:
                logger.info("✓ Using valid yo_digital access_token")
                return result

            # Step 2: Check yo_digital refresh_token
            result = self._refresh_yo_digital_if_possible()
            if result.success:
                logger.info("✓ Refreshed yo_digital tokens")
                return result

        # Step 3: Check taa access_token
        result = self._get_yo_digital_from_taa()
        if result.success:
            logger.info("✓ Got yo_digital tokens from taa")
            return result

        # Step 4: Check shared refresh_token
        result = self._get_yo_digital_via_taa_exchange()
        if result.success:
            logger.info("✓ Got yo_digital tokens via taa exchange")
            return result

        # Step 5: Try line_auth
        result = self._get_yo_digital_via_line_auth()
        if result.success:
            logger.info("✓ Got yo_digital tokens via line_auth")
            return result

        # Step 6: Try remote_login
        result = self._get_yo_digital_via_remote_login()
        if result.success:
            logger.info("✓ Got yo_digital tokens via remote_login")
            return result

        # All failed
        logger.error("✗ All token acquisition methods failed")
        return TokenFlowResult(
            success=False,
            error="All token acquisition methods failed",
            flow_path="all_failed"
        )

    # ========================================================================
    # Step 1: Check existing yo_digital access_token
    # ========================================================================

    def _check_yo_digital_access_token(self) -> TokenFlowResult:
        """Check if we have a valid yo_digital access_token"""
        try:
            token_data = self.session_manager.load_scoped_token(
                self.provider_name,
                'yo_digital',
                self.country
            )

            if not token_data or 'access_token' not in token_data:
                return TokenFlowResult(
                    success=False,
                    error="No yo_digital token found",
                    flow_path="check_yo_digital_access"
                )

            # Check if access_token is still valid
            if self._is_yo_digital_access_token_valid(token_data):
                return TokenFlowResult(
                    success=True,
                    access_token=token_data['access_token'],
                    refresh_token=token_data.get('refresh_token'),
                    flow_path="yo_digital_access_valid"
                )

            return TokenFlowResult(
                success=False,
                error="yo_digital access_token expired",
                flow_path="check_yo_digital_access"
            )

        except Exception as e:
            logger.debug(f"Error checking yo_digital access_token: {e}")
            return TokenFlowResult(
                success=False,
                error=str(e),
                flow_path="check_yo_digital_access"
            )

    # ========================================================================
    # Step 2: Refresh yo_digital tokens
    # ========================================================================

    def _refresh_yo_digital_if_possible(self) -> TokenFlowResult:
        """Try to refresh yo_digital tokens if refresh_token is valid"""
        try:
            token_data = self.session_manager.load_scoped_token(
                self.provider_name,
                'yo_digital',
                self.country
            )

            if not token_data or 'refresh_token' not in token_data:
                return TokenFlowResult(
                    success=False,
                    error="No yo_digital refresh_token found",
                    flow_path="refresh_yo_digital"
                )

            # Check if refresh_token is still valid
            if not self._is_yo_digital_refresh_token_valid(token_data):
                return TokenFlowResult(
                    success=False,
                    error="yo_digital refresh_token expired",
                    flow_path="refresh_yo_digital"
                )

            # Refresh via TaaClient (stub for now)
            logger.debug("Attempting to refresh yo_digital tokens")
            new_tokens_dict = self.taa_client.refresh_yo_digital_tokens(
                token_data['refresh_token']
            )

            if not new_tokens_dict:
                return TokenFlowResult(
                    success=False,
                    error="yo_digital refresh failed",
                    flow_path="refresh_yo_digital"
                )

            # Save new tokens (already in dict format from stub)
            self._save_yo_digital_tokens(new_tokens_dict)

            return TokenFlowResult(
                success=True,
                access_token=new_tokens_dict.get('accessToken') or new_tokens_dict.get('access_token'),
                refresh_token=new_tokens_dict.get('refreshToken') or new_tokens_dict.get('refresh_token'),
                flow_path="yo_digital_refreshed"
            )

        except Exception as e:
            logger.debug(f"Error refreshing yo_digital tokens: {e}")
            return TokenFlowResult(
                success=False,
                error=str(e),
                flow_path="refresh_yo_digital"
            )

    # ========================================================================
    # Step 3: Get yo_digital from taa access_token
    # ========================================================================

    def _get_yo_digital_from_taa(self) -> TokenFlowResult:
        """Get yo_digital tokens using existing taa access_token"""
        try:
            # Check if we have valid taa access_token
            taa_token_data = self.session_manager.load_scoped_token(
                self.provider_name,
                'taa',
                self.country
            )

            if not taa_token_data or 'access_token' not in taa_token_data:
                return TokenFlowResult(
                    success=False,
                    error="No taa access_token found",
                    flow_path="yo_digital_from_taa"
                )

            # Check if taa token is still valid
            if self._is_token_expired(taa_token_data):
                return TokenFlowResult(
                    success=False,
                    error="taa access_token expired",
                    flow_path="yo_digital_from_taa"
                )

            # Get yo_digital tokens from TAA endpoint
            logger.debug("Getting yo_digital tokens from taa access_token")
            yo_digital_result = self.taa_client.get_yo_digital_tokens(
                taa_access_token=taa_token_data['access_token'],
                device_id=self.session_manager.get_device_id(self.provider_name, self.country)
            )

            if not yo_digital_result:
                return TokenFlowResult(
                    success=False,
                    error="Failed to get yo_digital tokens from taa",
                    flow_path="yo_digital_from_taa"
                )

            # Convert YoDigitalTokens to dict for saving
            yo_digital_dict = {
                'accessToken': yo_digital_result.access_token,
                'accessExpiresIn': yo_digital_result.access_token_expires_in,
                'refreshToken': yo_digital_result.refresh_token,
                'refreshExpiresIn': yo_digital_result.refresh_token_expires_in
            }

            # Save yo_digital tokens
            self._save_yo_digital_tokens(yo_digital_dict)

            return TokenFlowResult(
                success=True,
                access_token=yo_digital_result.access_token,
                refresh_token=yo_digital_result.refresh_token,
                flow_path="yo_digital_from_taa"
            )

        except Exception as e:
            logger.debug(f"Error getting yo_digital from taa: {e}")
            return TokenFlowResult(
                success=False,
                error=str(e),
                flow_path="yo_digital_from_taa"
            )

    # ========================================================================
    # Step 4: Exchange shared refresh_token for taa, then yo_digital
    # ========================================================================

    def _get_yo_digital_via_taa_exchange(self) -> TokenFlowResult:
        """Exchange shared refresh_token for taa, then get yo_digital"""
        try:
            # Check if we have shared refresh_token at provider level
            session_data = self.session_manager.load_session(
                self.provider_name,
                self.country
            )

            if not session_data or 'refresh_token' not in session_data:
                return TokenFlowResult(
                    success=False,
                    error="No shared refresh_token found",
                    flow_path="yo_digital_via_taa_exchange"
                )

            # Exchange refresh_token for taa access_token
            logger.debug("Exchanging refresh_token for taa access_token")
            taa_token = self.sam3_client.get_token(
                grant_type='refresh_token',
                scope='taa',
                credential1=session_data['refresh_token']
            )

            if not taa_token:
                return TokenFlowResult(
                    success=False,
                    error="Failed to exchange refresh_token for taa",
                    flow_path="yo_digital_via_taa_exchange"
                )

            # Save taa token
            self._save_taa_token(taa_token)

            # Now get yo_digital tokens using taa
            logger.debug("Getting yo_digital tokens from exchanged taa token")
            yo_digital_result = self.taa_client.get_yo_digital_tokens(
                taa_access_token=taa_token,
                device_id=self.session_manager.get_device_id(self.provider_name, self.country)
            )

            if not yo_digital_result:
                return TokenFlowResult(
                    success=False,
                    error="Failed to get yo_digital from exchanged taa",
                    flow_path="yo_digital_via_taa_exchange"
                )

            # Convert YoDigitalTokens to dict for saving
            yo_digital_dict = {
                'accessToken': yo_digital_result.access_token,
                'accessExpiresIn': yo_digital_result.access_token_expires_in,
                'refreshToken': yo_digital_result.refresh_token,
                'refreshExpiresIn': yo_digital_result.refresh_token_expires_in
            }

            # Save yo_digital tokens
            self._save_yo_digital_tokens(yo_digital_dict)

            return TokenFlowResult(
                success=True,
                access_token=yo_digital_result.access_token,
                refresh_token=yo_digital_result.refresh_token,
                flow_path="yo_digital_via_taa_exchange"
            )

        except Exception as e:
            logger.debug(f"Error in taa exchange flow: {e}")
            return TokenFlowResult(
                success=False,
                error=str(e),
                flow_path="yo_digital_via_taa_exchange"
            )

    # ========================================================================
    # Step 5: Line auth → tvhubs + refresh → taa → yo_digital
    # ========================================================================

    def _get_yo_digital_via_line_auth(self) -> TokenFlowResult:
        """Try line_auth to get tvhubs + refresh_token, then chain to yo_digital"""
        try:
            # Check if callback is available
            if not self._line_auth_callback:
                return TokenFlowResult(
                    success=False,
                    error="line_auth callback not configured",
                    flow_path="yo_digital_via_line_auth"
                )

            logger.info("Attempting line_auth flow via callback")

            # Call the authenticator's line auth method
            line_response = self._line_auth_callback()

            if not line_response:
                return TokenFlowResult(
                    success=False,
                    error="line_auth failed",
                    flow_path="yo_digital_via_line_auth"
                )

            # Save tvhubs token
            self._save_tvhubs_token(line_response)

            # Save refresh token at provider level
            if 'refresh_token' in line_response:
                self._save_refresh_token(line_response['refresh_token'])

            # Now exchange for taa
            logger.debug("Exchanging line_auth refresh_token for taa")
            taa_token = self.sam3_client.get_token(
                grant_type='refresh_token',
                scope='taa',
                credential1=line_response['refresh_token']
            )

            if not taa_token:
                return TokenFlowResult(
                    success=False,
                    error="Failed to exchange line_auth refresh for taa",
                    flow_path="yo_digital_via_line_auth"
                )

            # Save taa token
            self._save_taa_token(taa_token)

            # Finally get yo_digital
            logger.debug("Getting yo_digital tokens from line_auth taa token")
            yo_digital_result = self.taa_client.get_yo_digital_tokens(
                taa_access_token=taa_token,
                device_id=self.session_manager.get_device_id(self.provider_name, self.country)
            )

            if not yo_digital_result:
                return TokenFlowResult(
                    success=False,
                    error="Failed to get yo_digital from line_auth taa",
                    flow_path="yo_digital_via_line_auth"
                )

            # Convert YoDigitalTokens to dict for saving
            yo_digital_dict = {
                'accessToken': yo_digital_result.access_token,
                'accessExpiresIn': yo_digital_result.access_token_expires_in,
                'refreshToken': yo_digital_result.refresh_token,
                'refreshExpiresIn': yo_digital_result.refresh_token_expires_in
            }

            # Save yo_digital tokens
            self._save_yo_digital_tokens(yo_digital_dict)

            return TokenFlowResult(
                success=True,
                access_token=yo_digital_result.access_token,
                refresh_token=yo_digital_result.refresh_token,
                flow_path="yo_digital_via_line_auth"
            )

        except Exception as e:
            logger.debug(f"Error in line_auth flow: {e}")
            return TokenFlowResult(
                success=False,
                error=str(e),
                flow_path="yo_digital_via_line_auth"
            )

    # ========================================================================
    # Step 6: Remote login → tvhubs + refresh → taa → yo_digital
    # ========================================================================

    def _get_yo_digital_via_remote_login(self) -> TokenFlowResult:
        """Try remote_login to get tvhubs + refresh_token, then chain to yo_digital"""
        try:
            # Check if remote_login is available
            if not hasattr(self.sam3_client, 'can_use_remote_login'):
                return TokenFlowResult(
                    success=False,
                    error="remote_login not available",
                    flow_path="yo_digital_via_remote_login"
                )

            if not self.sam3_client.can_use_remote_login():
                return TokenFlowResult(
                    success=False,
                    error="remote_login not configured",
                    flow_path="yo_digital_via_remote_login"
                )

            logger.info("Attempting remote_login flow")

            # Perform remote login
            remote_token_data = self.sam3_client.remote_login(
                scope="tvhubs offline_access"
            )

            if not remote_token_data:
                return TokenFlowResult(
                    success=False,
                    error="remote_login failed or timed out",
                    flow_path="yo_digital_via_remote_login"
                )

            # Save tvhubs token
            self._save_tvhubs_token(remote_token_data)

            # Save refresh token at provider level
            if 'refresh_token' in remote_token_data:
                self._save_refresh_token(remote_token_data['refresh_token'])

            # Now exchange for taa
            logger.debug("Exchanging remote_login refresh_token for taa")
            taa_token = self.sam3_client.get_token(
                grant_type='refresh_token',
                scope='taa',
                credential1=remote_token_data['refresh_token']
            )

            if not taa_token:
                return TokenFlowResult(
                    success=False,
                    error="Failed to exchange remote_login refresh for taa",
                    flow_path="yo_digital_via_remote_login"
                )

            # Save taa token
            self._save_taa_token(taa_token)

            # Finally get yo_digital
            logger.debug("Getting yo_digital tokens from remote_login taa token")
            yo_digital_result = self.taa_client.get_yo_digital_tokens(
                taa_access_token=taa_token,
                device_id=self.session_manager.get_device_id(self.provider_name, self.country)
            )

            if not yo_digital_result:
                return TokenFlowResult(
                    success=False,
                    error="Failed to get yo_digital from remote_login taa",
                    flow_path="yo_digital_via_remote_login"
                )

            # Convert YoDigitalTokens to dict for saving
            yo_digital_dict = {
                'accessToken': yo_digital_result.access_token,
                'accessExpiresIn': yo_digital_result.access_token_expires_in,
                'refreshToken': yo_digital_result.refresh_token,
                'refreshExpiresIn': yo_digital_result.refresh_token_expires_in
            }

            # Save yo_digital tokens
            self._save_yo_digital_tokens(yo_digital_dict)

            return TokenFlowResult(
                success=True,
                access_token=yo_digital_result.access_token,
                refresh_token=yo_digital_result.refresh_token,
                flow_path="yo_digital_via_remote_login"
            )

        except Exception as e:
            logger.debug(f"Error in remote_login flow: {e}")
            return TokenFlowResult(
                success=False,
                error=str(e),
                flow_path="yo_digital_via_remote_login"
            )

    # ========================================================================
    # Helper Methods - Token Validation
    # ========================================================================

    @staticmethod
    def _is_yo_digital_access_token_valid(token_data: Dict[str, Any]) -> bool:
        """Check if yo_digital access_token is still valid"""
        if 'access_token_expires_in' not in token_data or 'access_token_issued_at' not in token_data:
            return False

        expires_at = token_data['access_token_issued_at'] + token_data['access_token_expires_in']
        # Use 5 minute buffer
        return time.time() < (expires_at - 300)

    @staticmethod
    def _is_yo_digital_refresh_token_valid(token_data: Dict[str, Any]) -> bool:
        """Check if yo_digital refresh_token is still valid"""
        if 'refresh_token_expires_in' not in token_data or 'refresh_token_issued_at' not in token_data:
            return False

        expires_at = token_data['refresh_token_issued_at'] + token_data['refresh_token_expires_in']
        # Use 5 minute buffer
        return time.time() < (expires_at - 300)

    @staticmethod
    def _is_token_expired(token_data: Dict[str, Any]) -> bool:
        """Check if standard token (tvhubs/taa) is expired"""
        if 'expires_in' not in token_data or 'issued_at' not in token_data:
            return True

        expires_at = token_data['issued_at'] + token_data['expires_in']
        # Use 5 minute buffer
        return time.time() >= (expires_at - 300)

    # ========================================================================
    # Helper Methods - Token Storage
    # ========================================================================

    def _save_yo_digital_tokens(self, tokens: Dict[str, Any]) -> None:
        """Save yo_digital tokens with proper format"""
        current_time = time.time()

        token_data = {
            'access_token': tokens.get('accessToken') or tokens.get('access_token'),
            'access_token_expires_in': tokens.get('accessExpiresIn') or tokens.get('access_token_expires_in', 86400),
            'access_token_issued_at': current_time,
            'refresh_token': tokens.get('refreshToken') or tokens.get('refresh_token'),
            'refresh_token_expires_in': tokens.get('refreshExpiresIn') or tokens.get('refresh_token_expires_in', 86400),
            'refresh_token_issued_at': current_time,
            'token_type': 'Bearer'
        }

        success = self.session_manager.save_scoped_token(
            self.provider_name,
            'yo_digital',
            token_data,
            self.country
        )

        if success:
            logger.info("✓ yo_digital tokens saved")
        else:
            logger.error("✗ Failed to save yo_digital tokens")

    def _save_taa_token(self, taa_token: str) -> None:
        """Save taa access_token"""
        token_data = {
            'access_token': taa_token,
            'token_type': 'Bearer',
            'expires_in': 3600,  # Default 1 hour
            'issued_at': time.time()
        }

        self.session_manager.save_scoped_token(
            self.provider_name,
            'taa',
            token_data,
            self.country
        )
        logger.debug("taa token saved")

    def _save_tvhubs_token(self, token_data: Dict[str, Any]) -> None:
        """Save tvhubs access_token"""
        tvhubs_data = {
            'access_token': token_data.get('access_token'),
            'token_type': token_data.get('token_type', 'Bearer'),
            'expires_in': token_data.get('expires_in', 7200),
            'issued_at': time.time()
        }

        self.session_manager.save_scoped_token(
            self.provider_name,
            'tvhubs',
            tvhubs_data,
            self.country
        )
        logger.debug("tvhubs token saved")

    def _save_refresh_token(self, refresh_token: str) -> None:
        """Save shared refresh_token at provider level"""
        session_data = self.session_manager.load_session(
            self.provider_name,
            self.country
        ) or {}

        session_data['refresh_token'] = refresh_token
        session_data['device_id'] = self.session_manager.get_device_id(
            self.provider_name,
            self.country
        )

        self.session_manager.save_session(
            self.provider_name,
            session_data,
            self.country
        )
        logger.debug("Shared refresh_token saved")

    # ========================================================================
    # Public API - Debugging
    # ========================================================================

    def get_token_status(self) -> Dict[str, Any]:
        """Get comprehensive status of all tokens"""
        status = {
            'yo_digital': self._get_yo_digital_status(),
            'taa': self._get_taa_status(),
            'tvhubs': self._get_tvhubs_status(),
            'refresh_token': self._get_refresh_token_status()
        }

        return status

    def _get_yo_digital_status(self) -> Dict[str, Any]:
        """Get yo_digital token status"""
        token_data = self.session_manager.load_scoped_token(
            self.provider_name,
            'yo_digital',
            self.country
        )

        if not token_data:
            return {'exists': False}

        return {
            'exists': True,
            'has_access_token': 'access_token' in token_data,
            'access_token_valid': self._is_yo_digital_access_token_valid(token_data),
            'has_refresh_token': 'refresh_token' in token_data,
            'refresh_token_valid': self._is_yo_digital_refresh_token_valid(token_data)
        }

    def _get_taa_status(self) -> Dict[str, Any]:
        """Get taa token status"""
        token_data = self.session_manager.load_scoped_token(
            self.provider_name,
            'taa',
            self.country
        )

        if not token_data:
            return {'exists': False}

        return {
            'exists': True,
            'has_access_token': 'access_token' in token_data,
            'is_valid': not self._is_token_expired(token_data)
        }

    def _get_tvhubs_status(self) -> Dict[str, Any]:
        """Get tvhubs token status"""
        token_data = self.session_manager.load_scoped_token(
            self.provider_name,
            'tvhubs',
            self.country
        )

        if not token_data:
            return {'exists': False}

        return {
            'exists': True,
            'has_access_token': 'access_token' in token_data,
            'is_valid': not self._is_token_expired(token_data)
        }

    def _get_refresh_token_status(self) -> Dict[str, Any]:
        """Get shared refresh_token status"""
        session_data = self.session_manager.load_session(
            self.provider_name,
            self.country
        )

        if not session_data or 'refresh_token' not in session_data:
            return {'exists': False}

        return {
            'exists': True,
            'has_refresh_token': True
        }