# streaming_providers/providers/magenta2/auth_bridge.py
# -*- coding: utf-8 -*-
"""
AuthBridge — token-consumer layer between Magenta2Provider and Magenta2Authenticator.

Responsibilities:
  - In-memory persona-token cache (TTL-based, 60 s safety margin)
  - tvhubs-scoped Bearer token retrieval and refresh (via TokenFlowManager)
  - Platform-aware auth-header construction for VOD and nPVR endpoints
  - Auth-state and readiness inspection (moved from provider.py)

What this class does NOT do:
  - Token acquisition / OAuth flows  →  Magenta2Authenticator / TokenFlowManager
  - Endpoint discovery               →  DiscoveryService / EndpointManager
  - Any HTTP requests of its own

Usage (from Magenta2Provider.__init__)::

    self._auth = AuthBridge(
        authenticator=self.authenticator,
        provider_name=self.provider_name,
        country=self.country,
        platform=self.platform,
        platform_config=self.platform_config,
        provider_config=self.provider_config,
        session_id=self.session_id,
        serial_number=self.serial_number,
        generate_call_id=self._generate_call_id,
    )
"""

import time
from typing import Any, Dict, Optional, Tuple

from ...base.models.auth import AuthState
from ...base.utils.logger import logger
from .playback_manager import PlaybackManager
from .token_flow_manager import PersonaResult


class AuthBridge:
    """
    Thin token-consumer and caching façade.

    The bridge holds a reference to the authenticator but never calls into
    its private internals — all refresh work is delegated to the public
    TokenFlowManager API.
    """

    def __init__(
        self,
        authenticator: Any,
        provider_name: str,
        country: str,
        platform: str,
        platform_config: Dict[str, Any],
        provider_config: Any,
        session_id: str,
        serial_number: str,
        generate_call_id,  # callable() -> str
    ) -> None:
        self._authenticator = authenticator
        self._provider_name = provider_name
        self._country = country
        self._platform = platform
        self._platform_config = platform_config
        self._provider_config = provider_config
        self._session_id = session_id
        self._serial_number = serial_number
        self._generate_call_id = generate_call_id

        self._persona_cache: Optional[PersonaResult] = None

    # ------------------------------------------------------------------ #
    # provider_config setter — updated after configuration discovery      #
    # ------------------------------------------------------------------ #

    def update_provider_config(self, provider_config: Any) -> None:
        """Called by the provider after configuration discovery completes."""
        self._provider_config = provider_config

    # ------------------------------------------------------------------ #
    # Persona token                                                        #
    # ------------------------------------------------------------------ #

    def get_persona_token(self, force_refresh: bool = False) -> str:
        """
        Return a valid persona token, using an in-memory TTL cache.

        Raises:
            RuntimeError: If TokenFlowManager is not available.
            Exception:    If the underlying token flow fails.
        """
        if not force_refresh and self._persona_cache and self._persona_cache.success:
            expires_at: float = self._persona_cache.expires_at
            if time.time() < (expires_at - 60):
                logger.debug(
                    f"Using cached persona token (expires at {time.ctime(expires_at)})"
                )
                return self._persona_cache.persona_token
            self._persona_cache = None
            logger.debug("In-memory persona cache expired")

        tfm = self._authenticator.token_flow_manager
        if tfm is None:
            raise RuntimeError("TokenFlowManager is not available on the authenticator")

        persona_result: PersonaResult = tfm.get_persona_token(force_refresh=force_refresh)
        if not persona_result.success:
            raise Exception(f"Failed to get persona token: {persona_result.error}")

        self._persona_cache = persona_result
        logger.debug(
            f"Cached persona token (expires at {time.ctime(persona_result.expires_at)})"
        )
        return persona_result.persona_token

    def ensure_authenticated(self) -> str:
        """Return a valid persona token (lazy, no forced refresh). Callable as a callback."""
        return self.get_persona_token(force_refresh=False)

    def clear_persona_cache(self) -> None:
        """Discard the in-memory persona token cache."""
        self._persona_cache = None
        logger.debug("Cleared in-memory persona cache")

    # ------------------------------------------------------------------ #
    # tvhubs Bearer token                                                  #
    # ------------------------------------------------------------------ #

    def get_tvhubs_bearer(self) -> Optional[str]:
        """
        Return a valid tvhubs-scoped access token for use as a Bearer token.

        Delegates to TokenFlowManager.get_tvhubs_token() which owns the full
        lifecycle: cache read → TTL check → refresh → full re-auth chain fallback.
        Returns None if the token is unavailable after all attempts.
        """
        tfm = self._authenticator.token_flow_manager
        if tfm is None:
            return None

        try:
            return tfm.get_tvhubs_token()
        except Exception as exc:
            logger.debug(f"Could not obtain tvhubs token: {exc}")
            return None

    # ------------------------------------------------------------------ #
    # Auth-header builders                                                 #
    # ------------------------------------------------------------------ #

    def vod_auth_headers(self) -> Dict[str, str]:
        """
        Build auth headers for VOD endpoints, platform-aware.

        Strategy:
          1. Prefer tvhubs-scoped Bearer token.
          2. Fall back to persona JWT extracted from the composed persona token.
          3. Last resort: Basic + raw persona token.
        """
        persona_token = self.ensure_authenticated()
        tvhubs_token = self.get_tvhubs_bearer()

        if tvhubs_token:
            auth_value = f"Bearer {tvhubs_token}"
            logger.debug("VOD auth: using tvhubs token as Bearer")
        else:
            persona_jwt = PlaybackManager.extract_persona_jwt_from_token(persona_token)
            auth_value = (
                f"Bearer {persona_jwt}" if persona_jwt else f"Basic {persona_token}"
            )
            logger.debug("VOD auth: tvhubs token unavailable, falling back to persona_jwt")

        client_model: str = (
            self._provider_config.bootstrap.client_model
            if self._provider_config and self._provider_config.bootstrap
            else f"ftv-{self._platform}"
        ) or f"ftv-{self._platform}"
        is_web = client_model == "ftv-web"

        if is_web:
            return {
                "Authorization": auth_value,
                "x-mpx-authorization": f"Basic {persona_token}",
                "x-dt-session-id": self._session_id,
                "x-dt-call-id": self._generate_call_id(),
                "origin": "https://www.magenta.tv",
                "referer": "https://www.magenta.tv/",
                "user-agent": self._platform_config["user_agent"],
                "accept": "*/*",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "de-DE,de;q=0.9",
                "x-permissionflagpersonalizeduireco": "false",
            }
        else:
            return {
                "Authorization": auth_value,
                "x-mpx-authorization": f"Basic {persona_token}",
                "x-stbserialnumber": self._serial_number,
                "dt-session-id": self._session_id,
                "dt-call-id": self._generate_call_id(),
                "user-agent": self._platform_config["user_agent"],
                "accept-encoding": "gzip",
            }

    def pvr_auth_headers(self) -> Dict[str, str]:
        """Build auth headers for nPVR recording endpoints."""
        persona_token = self.ensure_authenticated()
        return {
            "Authorization": f"Basic {persona_token}",
            "User-Agent": self._platform_config["user_agent"],
            "Accept-Encoding": "gzip",
            "CID": f"{self._session_id}::{self._generate_call_id()}",
        }

    # ------------------------------------------------------------------ #
    # Auth-state introspection  (moved from provider.py)                  #
    # ------------------------------------------------------------------ #

    def calculate_auth_state(self, context: Any) -> AuthState:
        """Derive AuthState from the stored persona token."""
        persona_token = context.get_token(self._provider_name, "persona", self._country)
        if not persona_token:
            logger.debug("No persona token found")
            return AuthState.NOT_AUTHENTICATED
        if not isinstance(persona_token, dict) or "persona_token" not in persona_token:
            logger.warning("Invalid persona token structure")
            return AuthState.NOT_AUTHENTICATED
        if "expires_at" in persona_token:
            current_time = time.time()
            expires_at: float = persona_token["expires_at"]
            if current_time >= (expires_at - 300):
                logger.debug(
                    f"Persona token expired (expires_at: {expires_at}, now: {current_time})"
                )
                return AuthState.EXPIRED
        logger.debug("Persona token is valid")
        return AuthState.AUTHENTICATED

    def calculate_readiness(self, context: Any) -> Tuple[bool, str]:
        """Return (is_ready, reason) based on token availability and expiry."""
        persona_token = context.get_token(self._provider_name, "persona", self._country)
        if not persona_token:
            return False, "No persona token available"
        if not isinstance(persona_token, dict) or "persona_token" not in persona_token:
            return False, "Invalid persona token structure"

        if "expires_at" in persona_token:
            current_time = time.time()
            expires_at: float = persona_token["expires_at"]
            if current_time >= (expires_at - 300):
                yo_token = context.get_token(
                    self._provider_name, "yo_digital", self._country
                )
                if yo_token and "refresh_token" in yo_token:
                    if (
                        "refresh_token_expires_in" in yo_token
                        and "refresh_token_issued_at" in yo_token
                    ):
                        refresh_expires_at: float = (
                            yo_token["refresh_token_issued_at"]
                            + yo_token["refresh_token_expires_in"]
                        )
                        if current_time < (refresh_expires_at - 300):
                            return (
                                True,
                                "Persona token expired but can be refreshed via yo_digital",
                            )
                return False, f"Persona token expired (expired at {time.ctime(expires_at)})"

        return True, "Has valid persona token"

    def get_auth_details(self, token_scopes: list, context: Any) -> Dict[str, Any]:
        """Return per-scope token status for all provider token scopes."""
        details: Dict[str, Any] = {}
        for scope in token_scopes:
            token = context.get_token(self._provider_name, scope, self._country)
            if not token:
                details[scope] = {"available": False}
                continue

            scope_info: Dict[str, Any] = {"available": True}

            if scope == "persona":
                if "expires_at" in token:
                    current_time = time.time()
                    expires_at: float = token["expires_at"]
                    scope_info["expires_at"] = expires_at
                    scope_info["is_expired"] = current_time >= expires_at
                    scope_info["time_remaining"] = int(max(0, expires_at - current_time))
                if "composed_at" in token:
                    scope_info["composed_at"] = token["composed_at"]

            elif scope == "yo_digital":
                if "access_token_expires_in" in token and "access_token_issued_at" in token:
                    current_time = time.time()
                    at_expires: float = (
                        token["access_token_issued_at"] + token["access_token_expires_in"]
                    )
                    scope_info["access_token_expires_at"] = at_expires
                    scope_info["access_token_is_expired"] = current_time >= at_expires
                if "refresh_token_expires_in" in token and "refresh_token_issued_at" in token:
                    current_time = time.time()
                    rt_expires: float = (
                        token["refresh_token_issued_at"] + token["refresh_token_expires_in"]
                    )
                    scope_info["refresh_token_expires_at"] = rt_expires
                    scope_info["refresh_token_is_expired"] = current_time >= rt_expires
                    scope_info["has_refresh_token"] = True

            else:
                if "expires_in" in token and "issued_at" in token:
                    current_time = time.time()
                    std_expires: float = token["issued_at"] + token["expires_in"]
                    scope_info["expires_at"] = std_expires
                    scope_info["is_expired"] = current_time >= std_expires

            details[scope] = scope_info
        return details