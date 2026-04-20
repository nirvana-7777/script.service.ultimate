# streaming_providers/providers/livgolf/provider.py
# -*- coding: utf-8 -*-
"""
LIV Golf streaming provider.

Supported features
------------------
* Events (live team and group camera feeds) — no authentication required.
* No channels, no EPG, no catch-up.

Authentication
--------------
Anonymous JWT token via the ViewLift identity endpoint.  The token is
long-lived (~1 year) and is persisted between sessions by the base
authenticator's settings_manager.
"""

from typing import ClassVar, Dict, List, Optional

from ...base.models import Event, StreamingChannel
from ...base.models.proxy_models import ProxyConfig
from ...base.provider import StreamingProvider
from ...base.utils.logger import logger
from .auth import LivGolfAuthenticator
from .constants import (
    DEFAULT_CHAMPION_ID,
    DEFAULT_MAX_RETRIES,
    DEFAULT_REQUEST_TIMEOUT,
    PROVIDER_LABEL,
    PROVIDER_LOGO,
    PROVIDER_NAME,
    USER_AGENT,
)
from .event_manager import LivGolfEventManager


class LivGolfProvider(StreamingProvider):
    """
    StreamingProvider implementation for LIV Golf.

    Only ``get_events()`` is meaningful — ``get_channels()``, ``get_epg()``,
    ``get_manifest()``, ``get_catchup_manifest()``, and ``get_drm()`` all
    return empty / None, consistent with the base contract.
    """

    PROVIDER_LOGO: ClassVar[str] = PROVIDER_LOGO

    def __init__(
        self,
        config_dir: Optional[str] = None,
        proxy_config: Optional[ProxyConfig] = None,
        proxy_url: Optional[str] = None,
        # Allow callers to pin a specific tournament; defaults to the live one.
        champion_id: str = DEFAULT_CHAMPION_ID,
    ) -> None:
        logger.info("[LivGolfProvider] __init__ START")

        # StreamingProvider.__init__ expects a country; LIV Golf is global.
        super().__init__(country="global")

        self._champion_id = champion_id

        self.http_manager = self._setup_http_manager(
            provider_name=PROVIDER_NAME,
            proxy_config=proxy_config,
            proxy_url=proxy_url,
            config_dir=config_dir,
            user_agent=USER_AGENT,
            timeout=DEFAULT_REQUEST_TIMEOUT,
            max_retries=DEFAULT_MAX_RETRIES,
        )

        self.authenticator = LivGolfAuthenticator(
            config_dir=config_dir,
            http_manager=self.http_manager,
            proxy_config=self.http_manager.config.proxy_config,
        )

        self.event_manager = LivGolfEventManager(
            http_manager=self.http_manager,
            authenticator=self.authenticator,
        )

        logger.info("[LivGolfProvider] __init__ COMPLETE")

    # ------------------------------------------------------------------
    # StreamingProvider identity properties
    # ------------------------------------------------------------------

    @property
    def provider_name(self) -> str:
        return PROVIDER_NAME

    @property
    def provider_label(self) -> str:
        return PROVIDER_LABEL

    @property
    def provider_logo(self) -> str:
        return PROVIDER_LOGO

    @property
    def uses_dynamic_manifests(self) -> bool:
        # Manifest URLs are stable for the duration of a tournament round.
        return False

    @property
    def catchup_window(self) -> int:
        return 0

    @property
    def supported_auth_types(self) -> List[str]:
        # Anonymous only — no user credentials accepted.
        return ["anonymous"]

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self, **kwargs) -> str:
        """
        Obtain / refresh the anonymous token and return it as a Bearer string.
        """
        logger.info("[LivGolfProvider] authenticate() called")
        force_refresh = kwargs.get("force_refresh", False)
        token = self.authenticator.get_bearer_token(force_refresh=force_refresh)
        logger.info("[LivGolfProvider] authenticate() complete")
        return token or ""

    def refresh_authentication(self) -> str:
        return self.authenticate(force_refresh=True)

    # ------------------------------------------------------------------
    # Events — the sole data surface of this provider
    # ------------------------------------------------------------------

    def get_events(self, **kwargs) -> List[Event]:
        """
        Return all live LIV Golf camera feeds as ``Event`` objects.

        Both team-camera streams and group-camera streams are included.

        Keyword Arguments
        -----------------
        champion_id : str, optional
            Override the tournament champion ID (default: provider-level setting,
            itself defaulting to ``DEFAULT_CHAMPION_ID``).
        """
        champion_id = kwargs.get("champion_id", self._champion_id)
        logger.info(f"[LivGolfProvider] get_events(champion_id={champion_id})")

        try:
            # Ensure we have a valid anonymous token before delegating.
            if self.authenticator.is_token_expired():
                logger.info("[LivGolfProvider] Token expired — refreshing before get_events")
                self.authenticate(force_refresh=True)

            events = self.event_manager.get_events(champion_id=champion_id)
            logger.info(f"[LivGolfProvider] Returning {len(events)} events")
            return events

        except Exception as exc:
            logger.error(f"[LivGolfProvider] get_events failed: {exc}")
            raise

    # ------------------------------------------------------------------
    # Channels / EPG / manifest — not supported; satisfy base contract
    # ------------------------------------------------------------------

    def get_channels(self, **kwargs) -> List[StreamingChannel]:
        """LIV Golf has no linear channels."""
        return []

    def get_epg(self, channel_id: str, **kwargs) -> List[Dict]:
        """LIV Golf has no EPG."""
        return []

    def get_manifest(self, content_id: str, **kwargs) -> Optional[str]:
        """
        Retrieve the manifest URL for a specific event ID.

        If the event is not in the event manager's cache, it triggers a fresh
        fetch.  LIV Golf events embed the manifest URL directly.
        """
        champion_id = kwargs.get("champion_id", self._champion_id)
        logger.info(f"[LivGolfProvider] get_manifest(content_id={content_id})")

        try:
            event = self.event_manager.get_event(
                content_id, champion_id=champion_id
            )
            if event:
                logger.info(f"[LivGolfProvider] Found manifest for '{content_id}'")
                return event.manifest

            logger.warning(f"[LivGolfProvider] Event '{content_id}' not found")
            return None

        except Exception as exc:
            logger.error(f"[LivGolfProvider] get_manifest failed: {exc}")
            return None

    def get_catchup_manifest(
        self, channel_id: str, start_time: int, end_time: int, **kwargs
    ) -> Optional[str]:
        """No catch-up support."""
        return None

    def get_drm(self, content_id: str, **kwargs) -> list:
        """LIV Golf streams are DRM-free."""
        return []

    def get_dynamic_manifest_params(
        self, channel: StreamingChannel, **kwargs
    ) -> Optional[str]:
        return None

    @staticmethod
    def validate_credentials() -> bool:
        """
        Anonymous providers do not validate user credentials.
        Return True so the base class does not block provider setup.
        """
        return True

    # ------------------------------------------------------------------
    # Class-level helpers
    # ------------------------------------------------------------------

    @classmethod
    def get_static_logo(cls, country: str = None) -> str:
        return cls.PROVIDER_LOGO

    @classmethod
    def get_static_label(cls, country: str = None) -> str:
        return PROVIDER_LABEL