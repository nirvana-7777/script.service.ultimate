# streaming_providers/providers/discovery/provider.py
"""
Discovery+ Streaming Provider

Provides access to Discovery+ live channels and VOD content with proper
authentication, DRM support, and channel management.
"""
import json
import time
import uuid
import secrets
import base64
from datetime import datetime, timezone
from typing import ClassVar, Dict, List, Optional, Any

from ...base.models.proxy_models import ProxyConfig
from ...base.models import DRMConfig, DRMSystem, LicenseConfig, StreamingChannel, Event, EventStatus
from ...base.provider import AuthType, StreamingProvider
from ...base.utils.logger import logger

from .auth import (
    DiscoveryAuthenticator,
    DiscoveryAnonymousCredentials,
    DiscoveryUserCredentials,
)
from .constants import (
    DEFAULT_COUNTRY,
    DEFAULT_PLATFORM_OS,
    DISCOVERY_LOGO,
    DISCOVERY_USERS_ME_URL,
    PlatformOS,
    SUPPORTED_AUTH_TYPES,
    SUPPORTED_COUNTRIES,
    CMS_INCLUDE_PARAMS,
    CMS_PAGE_SIZE,
    CMS_ROUTE_SPORTS,
    CMS_ROUTE_SPORT_SCHEDULE,
    AIRING_BADGE_LIVE,
    AIRING_BADGE_UP_NEXT,
    AIRING_BADGE_UPCOMING_LEGACY,
    AIRING_ITEM_TYPE,
    get_default_capabilities,
    get_default_device_info,
    get_drm_request_headers,
    get_user_agent,
)
from .exceptions import (
    PlaybackRestrictedException,
    ChannelNotFoundError,
    ManifestFetchError,
)
from .models import DiscoveryChannel


class DiscoveryProvider(StreamingProvider):
    """
    Discovery+ streaming provider implementation with dynamic endpoint discovery.

    Features:
    - Multi-country support (EMEA region)
    - Anonymous and user authentication
    - Live channels and VOD content
    - DRM-protected streams (Widevine on Linux, PlayReady on Windows)
    - OS platform spoofing via PlatformOS (see constants.DEFAULT_PLATFORM_OS)
    - Provider cache pattern for efficient channel management
    - Dynamic CMS route discovery from ``/home`` navigation graph

    Event fetching uses **dynamic route selection** (``_select_event_route``):
    ``get_channels()`` parses the ``/home`` navigation graph and caches all
    available routes in ``self._cms_routes``.  ``get_events()`` then picks the
    first route whose ID contains ``sport``, ``live``, or ``event`` — no
    hardcoded route names needed.  Two parse paths are supported:

    1. /sports (CMS_ROUTE_SPORTS, default)
       The API returns ``airing`` items directly in the top-level ``included``
       array.  No nested collection traversal is needed; ``get_events()``
       detects this shape and calls ``_parse_airing_events()`` directly.

    2. /sport-schedule (CMS_ROUTE_SPORT_SCHEDULE, legacy fallback)
       Items are nested inside a collection and require the full multi-hop
       traversal: route → target page → page items → collection → paginated
       items → video.  Used automatically when the /sports route returns no
       airing items (e.g. future API layout changes).
    """

    # ============================================================================
    # STATIC METADATA
    # ============================================================================
    PROVIDER_LABEL: ClassVar[str] = "Discovery+"
    SUPPORTED_AUTH_TYPES: ClassVar[List[str]] = SUPPORTED_AUTH_TYPES
    PROVIDER_LOGO: ClassVar[str] = DISCOVERY_LOGO
    SUPPORTED_COUNTRIES: ClassVar[str] = SUPPORTED_COUNTRIES  # "*" = all countries

    def __init__(
            self,
            country: str = DEFAULT_COUNTRY,
            auth_type: str = "anonymous",
            username: Optional[str] = None,
            password: Optional[str] = None,
            config_dir: Optional[str] = None,
            settings_manager=None,
            proxy_config: Optional[ProxyConfig] = None,
            proxy_url: Optional[str] = None,
            platform_os: Optional[PlatformOS] = None,
    ):
        """
        Initialize Discovery+ provider.

        Args:
            country: Country code (e.g., 'de', 'uk', 'at')
            auth_type: Authentication type ("anonymous" or "user_credentials")
            username: Username (required for user_credentials)
            password: Password (required for user_credentials)
            config_dir: Optional config directory override
            settings_manager: Settings manager instance
            proxy_config: Optional proxy configuration
            proxy_url: Optional proxy URL string
            platform_os: OS platform to spoof (PlatformOS.LINUX or PlatformOS.WINDOWS).
                         Defaults to DEFAULT_PLATFORM_OS from constants.
                         LINUX  → Widevine + Chrome on Linux (original behaviour)
                         WINDOWS → PlayReady + Edge on Windows

        Raises:
            ValueError: If country not supported or credentials missing
        """
        if not self.validate_country(country):
            raise ValueError(
                f"Unsupported country: {country}. "
                f"Provide a valid ISO-3166-1 alpha-2 country code (e.g. 'de', 'uk')."
            )

        super().__init__(country=country)

        # OS platform used for all device/header/DRM spoofing
        self.platform_os: PlatformOS = platform_os if platform_os is not None else DEFAULT_PLATFORM_OS

        self.auth_type = auth_type
        self._settings_manager = settings_manager

        # Provider cache for DiscoveryChannel objects
        self._channels_cache: Dict[str, DiscoveryChannel] = {}

        # CMS navigation routes discovered from /home response.
        # Populated by get_channels() and used by get_events() to select the
        # best event-producing route without hardcoding names.
        # Format: { route_id: label }  e.g. {"sports": "Sport", "home": "Home"}
        self._cms_routes: Dict[str, str] = {}

        # Playback info cache: {edit_id: (expiry_timestamp, playback_data)}
        # Entries are valid until expiry_timestamp (derived from drm_expiration,
        # or 23 hours from fetch time as a safe fallback for the 24h token window).
        self._playback_cache: Dict[str, tuple] = {}

        # Setup HTTP manager using abstraction
        self.http_manager = self._setup_http_manager(
            provider_name="discovery",
            proxy_config=proxy_config,
            proxy_url=proxy_url,
            config_dir=config_dir,
            user_agent=get_user_agent(self.platform_os),
            timeout=30,
            max_retries=3,
        )

        # Create appropriate credentials.
        # Priority:
        #   1. Explicit username/password passed at construction time
        #   2. Stored user credentials from CredentialManager (same /config path
        #      the authenticator uses — does not depend on injected settings_manager)
        #   3. Anonymous fallback
        if auth_type == "user_credentials":
            if not username or not password:
                raise ValueError(
                    "Username and password required for user_credentials auth"
                )
            self.credentials = DiscoveryUserCredentials(
                username=username,
                password=password,
            )
        else:
            stored = None
            try:
                from ...base.auth.credential_manager import CredentialManager
                _cm = CredentialManager(config_dir=config_dir)
                stored = _cm.load_credentials("discovery", country)
                logger.debug(
                    f"CredentialManager lookup for discovery ({country}): "
                    f"{type(stored).__name__ if stored else 'None'}"
                )
            except Exception as e:
                logger.debug(f"Could not load stored credentials via CredentialManager: {e}")

            if stored and stored.validate() and hasattr(stored, "username"):
                logger.info(
                    f"Found stored user credentials for discovery ({country}), "
                    "upgrading from anonymous to user authentication"
                )
                self.credentials = DiscoveryUserCredentials(
                    username=stored.username,
                    password=stored.password,
                )
                self.auth_type = "user_credentials"
            else:
                logger.debug(
                    f"No stored user credentials found for discovery ({country}), "
                    "using anonymous authentication"
                )
                self.credentials = DiscoveryAnonymousCredentials()

        # Create authenticator with dynamic endpoint discovery.
        # settings_manager is intentionally not passed so the authenticator
        # self-constructs its own SettingsManager via the backward-compat path,
        # identical to how JoynAuthenticator works. This ensures it always
        # resolves the correct /config path via the environment variable.
        # Resolve stable device ID from settings manager before constructing
        # the authenticator — the authenticator intentionally receives
        # settings_manager=None so it cannot do this lookup itself.
        _device_id = None
        if self._settings_manager:
            try:
                _device_id = self._settings_manager.get_device_id(
                    "discovery", country
                )
                logger.debug(f"Resolved device_id from settings: {_device_id}")
            except Exception as e:
                logger.debug(f"Could not resolve device_id from settings: {e}")

        self.authenticator = DiscoveryAuthenticator(
            country=country,
            settings_manager=None,
            config_dir=config_dir,
            http_manager=self.http_manager,
            proxy_config=self.http_manager.config.proxy_config,
            credentials=self.credentials,
            platform_os=self.platform_os,
            device_id=_device_id,
        )

        # Authenticate
        try:
            self.bearer_token = self.authenticator.get_bearer_token()
            self.token_info = self.authenticator.get_token_info()
            logger.info(f"Authentication successful (type: {self.auth_type})")
        except Exception as e:
            logger.warning(
                f"Could not authenticate during initialization: {e}"
            )
            self.bearer_token = None
            self.token_info = None

        # Discover CMS navigation routes from /home.
        # Done eagerly so _cms_routes is populated before any call to
        # get_events() — regardless of whether get_channels() is called first.
        self._init_cms_routes()

    @property
    def provider_name(self) -> str:
        """Provider identifier"""
        return "discovery"

    @property
    def provider_label(self) -> str:
        """Return country-specific label"""
        country_map = {
            "de": "Discovery+ Germany",
            "at": "Discovery+ Austria",
            "ch": "Discovery+ Switzerland",
            "dk": "Discovery+ Denmark",
            "fi": "Discovery+ Finland",
            "no": "Discovery+ Norway",
            "se": "Discovery+ Sweden",
            "it": "Discovery+ Italy",
            "nl": "Discovery+ Netherlands",
            "es": "Discovery+ Spain",
            "uk": "Discovery+ UK",
            "ie": "Discovery+ Ireland",
        }
        return country_map.get(
            self.country,
            f"Discovery+ ({self.country.upper()})"
        )

    @property
    def provider_logo(self) -> str:
        """Provider logo URL"""
        return self.PROVIDER_LOGO

    @property
    def supported_auth_types(self) -> List[str]:
        """Supported authentication types"""
        return self.SUPPORTED_AUTH_TYPES

    @property
    def uses_dynamic_manifests(self) -> bool:
        """Discovery+ uses session-based manifests"""
        return True

    @property
    def implements_epg(self) -> bool:
        """Discovery+ does not implement native EPG"""
        return False

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get headers with authentication"""
        return self._build_provider_headers(
            base_headers={
                "User-Agent": get_user_agent(self.platform_os),
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            auth_type=AuthType.BEARER,
        )

    def authenticate(self, **kwargs) -> str:
        """Authenticate and return bearer token"""
        self.bearer_token = self.authenticator.get_bearer_token(
            force_refresh=kwargs.get("force_refresh", False)
        )
        self.token_info = self.authenticator.get_token_info()
        return self.bearer_token

    def refresh_authentication(self) -> str:
        """Force refresh authentication"""
        return self.authenticate(force_refresh=True)

    def is_anonymous(self) -> bool:
        """Check if using anonymous authentication"""
        if self.token_info:
            return self.token_info.get("anonymous", True)
        return True

    @classmethod
    def supports_multiple_countries(cls) -> bool:
        """
        Discovery+ uses a wildcard country list, but still registers one
        instance per country — so the registry must treat it as multi-country
        to produce names like ``discovery_de``.
        """
        return cls.SUPPORTED_COUNTRIES == ["*"]

    @classmethod
    def validate_country(cls, country: str) -> bool:
        """
        Override base validation.

        With the wildcard sentinel any valid ISO-3166-1 alpha-2 code is
        accepted.  The user's actual serving country is determined at runtime
        via get_user_country().
        """
        if cls.SUPPORTED_COUNTRIES == ["*"]:
            return bool(country and country.isalpha() and len(country) == 2)
        # Fallback to standard list-based check if constant is ever changed back
        return country.lower() in [c.lower() for c in cls.SUPPORTED_COUNTRIES]

    def get_user_country(self) -> Optional[str]:
        """
        Detect the user's current country by calling the /users/me endpoint.

        The API returns ``currentLocationTerritory`` (e.g. ``"DE"``) inside
        ``data.attributes``.  This method normalises the value to lowercase
        so it is consistent with the rest of the codebase (e.g. ``"de"``).

        Returns:
            Two-letter lowercase country code (e.g. ``"de"``, ``"uk"``) or
            ``None`` if the request fails or the field is absent.

        Example::

            provider = DiscoveryProvider(country="de")
            country = provider.get_user_country()
            # → "de"  (or whatever territory the server reports)
        """
        try:
            headers = self._get_auth_headers()
            response = self.http_manager.get(
                DISCOVERY_USERS_ME_URL,
                operation="users_me",
                headers=headers,
            )
            response.raise_for_status()
            data = response.json()
            territory = (
                data.get("data", {})
                    .get("attributes", {})
                    .get("currentLocationTerritory")
            )
            if territory:
                country_code = territory.lower()
                logger.debug(
                    f"Detected user country from /users/me: {country_code}"
                )
                return country_code
            logger.warning("/users/me response missing currentLocationTerritory")
            return None
        except Exception as e:
            logger.error(f"Failed to fetch user country from /users/me: {e}")
            return None

    def get_channels(
            self,
            fetch_manifests: bool = False,
            populate_streaming_data: bool = True,
            **kwargs,
    ) -> List[StreamingChannel]:
        """
        Fetch available channels from Discovery+ CMS.

        Args:
            fetch_manifests: Whether to immediately populate streaming data
            populate_streaming_data: Whether to populate streaming data
            **kwargs: Additional parameters

        Returns:
            List of StreamingChannel objects
        """
        try:
            headers = self._get_auth_headers()

            # Fetch home route with all needed includes
            url = self.authenticator.cms_home_endpoint
            params = {
                "include": CMS_INCLUDE_PARAMS,
                "decorators": "viewingHistory,isFavorite,contentAction,badges",
                "page[items.size]": CMS_PAGE_SIZE,
            }

            response = self.http_manager.get(
                url,
                operation="cms",
                headers=headers,
                params=params,
            )
            response.raise_for_status()
            data = response.json()

            # Refresh CMS route cache from this /home response.
            # _cms_routes is already populated at init, but get_channels() may
            # be called later in a session when routes could have changed.
            refreshed = self._discover_cms_routes(data)
            if refreshed:
                self._cms_routes = refreshed
                logger.debug(f"CMS routes refreshed: {list(self._cms_routes.keys())}")

            # Extract channels and cache DiscoveryChannel objects
            discovery_channels = self._extract_distribution_channels(data)

            # Cache the original DiscoveryChannel objects
            self._channels_cache = {
                ch.channel_id: ch for ch in discovery_channels
            }

            # Convert to StreamingChannel objects
            streaming_channels = [
                ch.to_streaming_channel(self.provider_name)
                for ch in discovery_channels
            ]

            logger.info(
                f"Found {len(streaming_channels)} distribution channels"
            )

            # Populate streaming data if requested
            if fetch_manifests and populate_streaming_data and streaming_channels:
                streaming_channels = self.populate_streaming_data(
                    streaming_channels
                )

            return streaming_channels

        except Exception as e:
            logger.error(f"Error fetching channels: {e}")
            return []

    def get_events(
            self,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **kwargs,
    ) -> List[Event]:
        """
        Fetch events from Discovery+ schedule.

        **Route selection** (no ``route_id`` kwarg supplied):
          Calls ``_select_event_route()`` which prefers a route discovered
          dynamically from the ``/home`` navigation graph (populated by
          ``get_channels()``).  The first route whose ID contains one of
          ``sport``, ``live``, or ``event`` wins.  If no match is found —
          e.g. ``get_channels()`` hasn't been called yet — falls back to
          ``CMS_ROUTE_SPORT_SCHEDULE`` (the full paginated schedule).

        **Parse paths** (determined by the selected route's response shape):
          1. ``/sports`` — ``airing`` items appear directly in ``included``
             (fast path, ``_parse_airing_events()``).
          2. ``/sport-schedule`` — items are nested inside a collection
             (legacy fallback, ``_fetch_events_via_collection()``).
          The fast path is attempted first; if no ``airing`` items are found
          the method retries with ``CMS_ROUTE_SPORT_SCHEDULE``.

        Args:
            start_time: Optional start time filter
            end_time: Optional end time filter
            **kwargs: Additional parameters including:
                - route_id: Override the CMS route (bypasses dynamic selection)
                - page_size: Number of items per page (collection path only)

        Returns:
            List of Event objects
        """
        events = []

        try:
            headers = self._get_auth_headers()

            # Dynamic route selection: prefer a discovered route that looks
            # event-bearing.  Falls back to CMS_ROUTE_SPORTS if get_channels()
            # hasn't been called yet (self._cms_routes is empty).
            if "route_id" not in kwargs:
                route_id = self._select_event_route()
            else:
                route_id = kwargs["route_id"]

            # Build the CMS route URL
            base_url = self.authenticator.cms_home_endpoint
            if base_url.endswith('/home'):
                url = base_url.replace('/home', f'/{route_id}')
            else:
                url = (
                    f"https://default.any-{self.authenticator.home_market}"
                    f".{self.authenticator.env}.api.discoveryplus.com"
                    f"/cms/routes/{route_id}"
                )

            params = {
                "include": CMS_INCLUDE_PARAMS,
                "decorators": "viewingHistory,isFavorite,contentAction,badges",
                "page[items.size]": kwargs.get("page_size", 10),
            }

            # Add time filters if provided
            if start_time:
                params["filter[from]"] = start_time.isoformat()
            if end_time:
                params["filter[to]"] = end_time.isoformat()

            logger.debug(f"Fetching events route: {url}")
            response = self.http_manager.get(
                url,
                operation="cms",
                headers=headers,
                params=params,
            )
            response.raise_for_status()
            data = response.json()

            # ------------------------------------------------------------------
            # Fast path: /sports route returns airing items directly in included
            # ------------------------------------------------------------------
            airing_items = [
                item for item in data.get("included", [])
                if item.get("type") == AIRING_ITEM_TYPE
            ]

            if airing_items:
                logger.debug(
                    f"Found {len(airing_items)} airing items in /sports route — "
                    "using direct airing parse path"
                )
                events = self._parse_airing_events(airing_items, start_time, end_time)
                logger.info(f"Found {len(events)} events (airing path)")
                return events

            # ------------------------------------------------------------------
            # Slow path: collection-based traversal (legacy /sport-schedule shape)
            # ------------------------------------------------------------------
            # If the caller explicitly asked for the sports route but got no
            # airings, retry once with the legacy route before giving up.
            if route_id == CMS_ROUTE_SPORTS:
                logger.debug(
                    "No airing items on /sports route — falling back to "
                    f"/{CMS_ROUTE_SPORT_SCHEDULE} collection path"
                )
                return self.get_events(
                    start_time=start_time,
                    end_time=end_time,
                    route_id=CMS_ROUTE_SPORT_SCHEDULE,
                    **{k: v for k, v in kwargs.items() if k != "route_id"},
                )

            # ---- legacy collection traversal (sport-schedule) ----------------
            events = self._fetch_events_via_collection(
                data=data,
                headers=headers,
                start_time=start_time,
                end_time=end_time,
                **kwargs,
            )
            logger.info(f"Found {len(events)} events (collection path)")

        except Exception as e:
            logger.error(f"Error fetching events: {e}")

        return events

    # =========================================================================
    # CMS route discovery
    # =========================================================================

    def _init_cms_routes(self) -> None:
        """
        Fetch ``/home`` and populate ``self._cms_routes`` eagerly.

        Called once at the end of ``__init__`` so route discovery is complete
        before any call to ``get_events()`` or ``get_channels()``.  Failures
        are caught and logged — the provider remains usable and ``get_events()``
        will fall back to ``CMS_ROUTE_SPORT_SCHEDULE``.
        """
        try:
            headers = self._get_auth_headers()
            url = self.authenticator.cms_home_endpoint
            params = {
                "include": CMS_INCLUDE_PARAMS,
                "decorators": "viewingHistory,isFavorite,contentAction,badges",
                "page[items.size]": CMS_PAGE_SIZE,
            }
            response = self.http_manager.get(
                url,
                operation="cms",
                headers=headers,
                params=params,
            )
            response.raise_for_status()
            data = response.json()
            self._cms_routes = self._discover_cms_routes(data)
            if self._cms_routes:
                logger.debug(
                    f"CMS routes discovered at init: {list(self._cms_routes.keys())}"
                )
            else:
                logger.warning(
                    "CMS route discovery returned no routes — "
                    f"get_events() will fall back to '{CMS_ROUTE_SPORT_SCHEDULE}'"
                )
        except Exception as e:
            logger.warning(f"Could not discover CMS routes at init: {e}")

    @staticmethod
    def _discover_cms_routes(data: dict) -> Dict[str, str]:
        """
        Parse a /home CMS response and return a map of all navigation routes.

        The /home response contains a ``data.relationships.navigationLinks``
        array whose entries are resolved via the top-level ``included`` list.
        Each resolved node has ``attributes.url`` (e.g. ``"/sports"``) and
        ``attributes.label`` (localised display name).

        Returns:
            dict mapping route_id → label, e.g.
            ``{"sports": "Sport", "channels": "Kanäle", "home": "Home"}``
            Returns an empty dict if the navigation graph is absent.
        """
        included_by_id: Dict[str, dict] = {
            f"{item['type']}:{item['id']}": item
            for item in data.get("included", [])
            if item.get("id") and item.get("type")
        }
        nav_refs = (
            data.get("data", {})
                .get("relationships", {})
                .get("navigationLinks", {})
                .get("data", [])
        )
        if not nav_refs:
            logger.debug("_discover_cms_routes: no navigationLinks found in /home response")
            return {}

        routes: Dict[str, str] = {}
        for ref in nav_refs:
            key = f"{ref.get('type', 'link')}:{ref['id']}"
            node = included_by_id.get(key, {})
            attrs = node.get("attributes", {})
            # Use the URL path segment as the route ID; fall back to the ref id
            url_path = attrs.get("url", "").lstrip("/")
            route_id = url_path or ref["id"]
            label = attrs.get("label", route_id)
            routes[route_id] = label

        return routes

    # Route preference order for event fetching.
    # ``sport-schedule`` (paginated full schedule, ~300 events) is preferred
    # over ``sports`` (featured/current airings only, ~14 events).
    # Order matters: the first matching route wins.
    _EVENT_ROUTE_PREFERENCE: ClassVar[tuple] = (
        CMS_ROUTE_SPORT_SCHEDULE,   # "sport-schedule" — full paginated schedule
        CMS_ROUTE_SPORTS,           # "sports"         — featured airings only (fallback)
    )
    # Generic keyword scan used when neither preferred route is discovered
    _EVENT_ROUTE_KEYWORDS: ClassVar[tuple] = ("schedule", "sport", "live", "event")

    def _select_event_route(self) -> str:
        """
        Return the best event-producing CMS route from ``self._cms_routes``.

        Preference order:
          1. ``CMS_ROUTE_SPORT_SCHEDULE`` (``sport-schedule``) — full paginated
             schedule, yields ~300 events via collection traversal.
          2. ``CMS_ROUTE_SPORTS`` (``sports``) — featured/current airings only,
             ~14 events.  Used only when sport-schedule is absent.
          3. First discovered route matching a keyword in
             ``_EVENT_ROUTE_KEYWORDS`` (generic fallback for unknown layouts).
          4. ``CMS_ROUTE_SPORT_SCHEDULE`` hard-coded constant when ``_cms_routes``
             is empty (e.g. ``get_channels()`` hasn't been called yet).
        """
        # 1 & 2: explicit preference list checked against discovered routes
        for preferred in self._EVENT_ROUTE_PREFERENCE:
            if preferred in self._cms_routes:
                logger.debug(f"_select_event_route: selected preferred route '{preferred}'")
                return preferred

        # 3: generic keyword scan for unexpected route layouts
        for keyword in self._EVENT_ROUTE_KEYWORDS:
            match = next(
                (r for r in self._cms_routes if keyword in r.lower()),
                None,
            )
            if match:
                logger.debug(
                    f"_select_event_route: selected '{match}' via keyword '{keyword}'"
                )
                return match

        # 4: hard fallback — use the full schedule route, not the featured-only /sports route
        logger.debug(
            f"_select_event_route: no event route found in {list(self._cms_routes.keys())!r}, "
            f"falling back to '{CMS_ROUTE_SPORT_SCHEDULE}'"
        )
        return CMS_ROUTE_SPORT_SCHEDULE

    # =========================================================================
    # Airing-based event parsing  (/sports route)
    # =========================================================================

    def _parse_airing_events(
            self,
            airing_items: List[Dict],
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
    ) -> List[Event]:
        """
        Parse a list of ``airing`` objects from the /sports CMS route into
        ``Event`` instances.

        The /sports route places ``airing`` items directly in the top-level
        ``included`` array.  Each airing carries:

        - ``attributes.scheduleStart / scheduleEnd``  — ISO-8601 UTC timestamps
        - ``attributes.name``                          — episode/event title
        - ``attributes.showName``                      — parent show name
        - ``attributes.description / secondaryTitle``  — optional metadata
        - ``attributes.episodeNumber / seasonNumber``  — episode metadata
        - ``relationships.badges``                     — live / up-next status
        - ``relationships.distributionChannel``        — links to channel cache

        Badge → EventStatus mapping:
          AIRING_BADGE_LIVE     ("live")                   → EventStatus.LIVE
          AIRING_BADGE_UP_NEXT  ("release-state-up-next")  → EventStatus.UPCOMING
          (fallback clock-based logic handles ENDED / LIVE for unlabelled items)

        The ``distributionChannel`` relationship ID is looked up in
        ``self._channels_cache`` so the event carries the correct channel name
        without an extra API round-trip.

        Args:
            airing_items: List of airing dicts from ``data["included"]``.
            start_time:   Optional lower bound filter (inclusive).
            end_time:     Optional upper bound filter (inclusive).

        Returns:
            List of Event objects, optionally filtered by time window.
        """
        events: List[Event] = []
        now_utc = datetime.now(timezone.utc)

        for airing in airing_items:
            try:
                attributes = airing.get("attributes", {})
                relationships = airing.get("relationships", {})

                # ---- schedule times -----------------------------------------
                schedule_start = attributes.get("scheduleStart")
                schedule_end = attributes.get("scheduleEnd")

                start_dt: Optional[datetime] = None
                end_dt: Optional[datetime] = None

                if schedule_start:
                    try:
                        start_dt = datetime.fromisoformat(
                            schedule_start.replace("Z", "+00:00")
                        )
                    except (ValueError, TypeError):
                        pass

                if schedule_end:
                    try:
                        end_dt = datetime.fromisoformat(
                            schedule_end.replace("Z", "+00:00")
                        )
                    except (ValueError, TypeError):
                        pass

                # ---- optional caller-supplied time window filter -------------
                if start_time and end_dt and end_dt < start_time:
                    continue
                if end_time and start_dt and start_dt > end_time:
                    continue

                # ---- event status from badges --------------------------------
                # Badge priority: explicit "live" wins over "up-next"; clock-
                # based logic is applied when neither badge is present.
                status = EventStatus.SCHEDULED
                badge_refs = relationships.get("badges", {}).get("data", [])
                badge_ids = {b.get("id") for b in badge_refs}

                if AIRING_BADGE_LIVE in badge_ids:
                    status = EventStatus.LIVE
                elif AIRING_BADGE_UP_NEXT in badge_ids or AIRING_BADGE_UPCOMING_LEGACY in badge_ids:
                    status = EventStatus.SCHEDULED
                elif start_dt and end_dt:
                    # Ensure tz-aware before comparison
                    _start = start_dt if start_dt.tzinfo else start_dt.replace(tzinfo=timezone.utc)
                    _end = end_dt if end_dt.tzinfo else end_dt.replace(tzinfo=timezone.utc)

                    if now_utc > _end:
                        status = EventStatus.ENDED
                    elif _start <= now_utc <= _end:
                        status = EventStatus.LIVE

                # ---- channel lookup -----------------------------------------
                # distributionChannel.data.id matches the keys in _channels_cache
                channel_name: Optional[str] = None
                dist_channel_ref = (
                    relationships.get("distributionChannel", {}).get("data", {})
                )
                dist_channel_id = dist_channel_ref.get("id") if dist_channel_ref else None

                if dist_channel_id:
                    cached_channel = self._channels_cache.get(dist_channel_id)
                    if cached_channel:
                        channel_name = cached_channel.name
                    else:
                        logger.debug(
                            f"distributionChannel {dist_channel_id} not in cache "
                            f"for airing '{attributes.get('name')}'"
                        )

                # ---- build Event --------------------------------------------
                event = Event(
                    name=attributes.get("name", "Unknown Event"),
                    content_id=airing.get("id", ""),
                    provider=self.provider_name,
                    logo_url=None,          # airing items carry image IDs only;
                                            # full URLs require a separate fetch
                    mode="live" if status == EventStatus.LIVE else "vod",
                    session_manifest=False,
                    manifest_script=None,
                    cdm=None,
                    content_type="AIRING",
                    description=attributes.get("description", ""),
                    genre=None,
                    language="de",          # airings don't expose audioTracks
                    country=self.country.upper(),
                    start_time=start_dt,
                    end_time=end_dt,
                    status=status,
                    subtitle=attributes.get("secondaryTitle"),
                    original_name=attributes.get("showName"),
                    competition=None,
                    venue=None,
                    gender=None,
                    discipline=None,
                    age_category=None,
                    master_event=None,
                    channel=channel_name,
                )

                events.append(event)

            except Exception as e:
                logger.error(
                    f"Error processing airing item {airing.get('id')}: {e}"
                )
                continue

        return events

    # =========================================================================
    # Legacy collection-based event fetching  (/sport-schedule route)
    # =========================================================================

    def _fetch_events_via_collection(
            self,
            data: Dict,
            headers: Dict,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **kwargs,
    ) -> List[Event]:
        """
        Traverse the legacy collection-based CMS shape to extract events.

        This implements the original multi-hop traversal:
          route data → target page → page items → collection →
          paginated collection items → video attributes

        Args:
            data: Parsed JSON from the initial CMS route request.
            headers: Auth headers for subsequent requests.
            start_time: Optional lower bound filter.
            end_time: Optional upper bound filter.
            **kwargs: Forwarded kwargs (page_size, etc.).

        Returns:
            List of Event objects.
        """
        events: List[Event] = []

        # Build lookup of included items by type:id
        included_by_id: Dict[str, Dict] = {}
        for item in data.get("included", []):
            item_id = item.get("id")
            item_type = item.get("type")
            if item_id and item_type:
                included_by_id[f"{item_type}:{item_id}"] = item

        # Find the target page from the route
        route_data = data.get("data", {})
        target_ref = route_data.get("relationships", {}).get("target", {}).get("data")

        if not target_ref:
            logger.error("No target page found in route response (collection path)")
            return events

        page_key = f"{target_ref.get('type')}:{target_ref.get('id')}"
        page = included_by_id.get(page_key)

        if not page:
            logger.error("Target page not found in included items (collection path)")
            return events

        # Find the collection from page items
        page_items = page.get("relationships", {}).get("items", {}).get("data", [])
        collection_id = None

        for page_item_ref in page_items:
            page_item_key = f"{page_item_ref.get('type')}:{page_item_ref.get('id')}"
            page_item = included_by_id.get(page_item_key)
            if page_item:
                collection_ref = (
                    page_item.get("relationships", {})
                    .get("collection", {})
                    .get("data")
                )
                if collection_ref:
                    collection_id = collection_ref.get("id")
                    break

        if not collection_id:
            logger.error("No collection found in page (collection path)")
            return events

        # Paginate through the collection
        collection_url = (
            f"{self.authenticator.cms_collections_endpoint}/{collection_id}"
        )
        current_page = 1

        while True:
            collection_params = {
                "include": "default",
                "decorators": "viewingHistory,isFavorite,contentAction,badges",
                "page[items.size]": kwargs.get("page_size", 30),
                "page[items.number]": current_page,
            }

            logger.debug(
                f"Fetching schedule collection page {current_page}: {collection_url}"
            )
            collection_response = self.http_manager.get(
                collection_url,
                operation="cms",
                headers=headers,
                params=collection_params,
            )
            collection_response.raise_for_status()
            collection_data = collection_response.json()

            # Build per-page included lookup
            page_included: Dict[str, Dict] = {}
            for item in collection_data.get("included", []):
                item_id = item.get("id")
                item_type = item.get("type")
                if item_id and item_type:
                    page_included[f"{item_type}:{item_id}"] = item

            items = (
                collection_data.get("data", {})
                .get("relationships", {})
                .get("items", {})
                .get("data", [])
            )

            meta = collection_data.get("meta", {})
            total_pages = meta.get("itemsTotalPages", 1)
            logger.debug(
                f"Fetched collection page {current_page}/{total_pages} "
                f"({len(items)} items)"
            )

            for item_ref in items:
                try:
                    item_key = f"{item_ref.get('type')}:{item_ref.get('id')}"
                    collection_item = page_included.get(item_key)

                    if not collection_item:
                        continue

                    # Get video reference from collection item
                    video_ref = (
                        collection_item.get("relationships", {})
                        .get("video", {})
                        .get("data")
                    )
                    if not video_ref:
                        continue

                    video_key = f"{video_ref.get('type')}:{video_ref.get('id')}"
                    video_data = page_included.get(video_key)

                    if not video_data:
                        continue

                    # Only process EVENT materialType
                    attributes = video_data.get("attributes", {})
                    relationships = video_data.get("relationships", {})

                    material_type = attributes.get("materialType")
                    if material_type != "EVENT":
                        continue

                    # ---- status from badges ----------------------------------
                    status = EventStatus.SCHEDULED
                    badge_refs = relationships.get("badges", {}).get("data", [])
                    badge_ids = {b.get("id") for b in badge_refs}

                    if AIRING_BADGE_LIVE in badge_ids:
                        status = EventStatus.LIVE
                    elif (
                        AIRING_BADGE_UP_NEXT in badge_ids
                        or AIRING_BADGE_UPCOMING_LEGACY in badge_ids
                    ):
                        status = EventStatus.SCHEDULED

                        # Also check overlays for live status
                    for badge_ref in badge_refs:
                        overlay_key = f"{badge_ref.get('type')}:{badge_ref.get('id')}"
                        overlay = page_included.get(overlay_key, {})
                        if overlay.get("id") == "live:default":
                            status = EventStatus.LIVE
                            break

                    # ---- schedule times -------------------------------------
                    schedule_start = attributes.get("scheduleStart")
                    schedule_end = attributes.get("scheduleEnd")

                    start_dt: Optional[datetime] = None
                    end_dt: Optional[datetime] = None

                    if schedule_start:
                        try:
                            start_dt = datetime.fromisoformat(
                                schedule_start.replace("Z", "+00:00")
                            )
                        except (ValueError, TypeError):
                            pass

                    if schedule_end:
                        try:
                            end_dt = datetime.fromisoformat(
                                schedule_end.replace("Z", "+00:00")
                            )
                        except (ValueError, TypeError):
                            pass

                    # Clock-based status refinement
                    if status != EventStatus.LIVE and start_dt and end_dt:
                        now_utc = datetime.now(timezone.utc)
                        _start = start_dt if start_dt.tzinfo else start_dt.replace(tzinfo=timezone.utc)
                        _end = end_dt if end_dt.tzinfo else end_dt.replace(tzinfo=timezone.utc)

                        if now_utc > _end:
                            status = EventStatus.ENDED
                        elif _start <= now_utc <= _end:
                            status = EventStatus.LIVE

                    # ---- logo -----------------------------------------------
                    logo_url = None
                    image_refs = relationships.get("images", {}).get("data", [])
                    if image_refs:
                        image_key = f"{image_refs[0].get('type')}:{image_refs[0].get('id')}"
                        image = page_included.get(image_key, {})
                        img_attrs = image.get("attributes", {})
                        logo_url = img_attrs.get("src") or img_attrs.get("url")

                    # ---- edit ID for streaming --------------------------------
                    edit_ref = relationships.get("edit", {}).get("data", {})
                    edit_id = edit_ref.get("id") if edit_ref else None

                    # ---- taxonomy lookups -----------------------------------
                    genre = self._resolve_taxonomy(
                        relationships, "txSports", page_included
                    )
                    competition = self._resolve_taxonomy(
                        relationships, "txCompetition", page_included
                    )
                    venue = self._resolve_taxonomy(
                        relationships, "txEvent", page_included
                    )
                    gender_val = self._resolve_taxonomy(
                        relationships, "txGender", page_included
                    )
                    gender = gender_val if gender_val and gender_val != "." else None

                    discipline_val = self._resolve_taxonomy(
                        relationships, "txDiscipline", page_included
                    )
                    discipline = discipline_val if discipline_val and discipline_val != "." else None

                    age_val = self._resolve_taxonomy(
                        relationships, "txAge", page_included
                    )
                    age_category = age_val if age_val and age_val != "." else None

                    master_event = self._resolve_taxonomy(
                        relationships, "txMaster-sporting-event", page_included
                    )

                    # ---- primary channel ------------------------------------
                    channel_name = None
                    channel_ref = relationships.get("primaryChannel", {}).get("data")
                    if channel_ref:
                        channel_key = f"{channel_ref.get('type')}:{channel_ref.get('id')}"
                        channel_node = page_included.get(channel_key, {})
                        channel_name = channel_node.get("attributes", {}).get("name")

                    # ---- language from audio tracks -------------------------
                    audio_tracks = attributes.get("audioTracks", [])
                    language = "de"
                    if audio_tracks:
                        if "Deutsch" in audio_tracks:
                            language = "de"
                        elif "Englisch" in audio_tracks:
                            language = "en"

                    event = Event(
                        name=attributes.get("name", "Unknown Event"),
                        content_id=video_data.get("id", ""),
                        provider=self.provider_name,
                        logo_url=logo_url,
                        mode="live" if attributes.get("videoType") == "LIVE" else "vod",
                        session_manifest=True,
                        manifest_script=f"editid={edit_id}" if edit_id else None,
                        cdm=f"editid={edit_id}" if edit_id else None,
                        content_type="EVENT",
                        description=attributes.get("description", ""),
                        genre=genre,
                        language=language,
                        country=self.country.upper(),
                        start_time=start_dt,
                        end_time=end_dt,
                        status=status,
                        subtitle=attributes.get("secondaryTitle"),
                        original_name=attributes.get("originalName"),
                        competition=competition,
                        venue=venue,
                        gender=gender,
                        discipline=discipline,
                        age_category=age_category,
                        master_event=master_event,
                        channel=channel_name,
                    )

                    events.append(event)

                except Exception as e:
                    logger.error(f"Error processing collection item: {e}")
                    continue

            if current_page >= total_pages:
                break
            current_page += 1

        return events

    @staticmethod
    def _resolve_taxonomy(
            relationships: Dict,
            key: str,
            included: Dict,
    ) -> Optional[str]:
        """
        Resolve a single taxonomy relationship to its name attribute.

        Args:
            relationships: ``relationships`` dict from a video/event item.
            key: Relationship key, e.g. ``"txSports"``, ``"txCompetition"``.
            included: Per-page included lookup (``type:id`` → item).

        Returns:
            The ``attributes.name`` string, or ``None`` if not found.
        """
        refs = relationships.get(key, {}).get("data", [])
        if not refs:
            return None
        ref = refs[0]
        node = included.get(f"{ref.get('type')}:{ref.get('id')}", {})
        return node.get("attributes", {}).get("name")

    def _extract_distribution_channels(
            self, data: Dict
    ) -> List[DiscoveryChannel]:
        """
        Extract distributionChannel objects from CMS response.

        Args:
            data: Parsed JSON response from CMS home route

        Returns:
            List of DiscoveryChannel objects (not StreamingChannel!)
        """
        channels = []

        # Build lookup of included items by ID and type
        included_by_id = {}
        for item in data.get("included", []):
            item_id = item.get("id")
            item_type = item.get("type")
            if item_id and item_type:
                key = f"{item_type}:{item_id}"
                included_by_id[key] = item

        # Find all distributionChannel objects in included
        for item in data.get("included", []):
            if item.get("type") == "distributionChannel":
                channel = self._create_discovery_channel_from_distribution(
                    item, included_by_id
                )
                if channel:
                    channels.append(channel)

        return channels

    @staticmethod
    def _create_discovery_channel_from_distribution(
            distribution_data: Dict,
            included_by_id: Dict
    ) -> Optional[DiscoveryChannel]:
        """
        Create a DiscoveryChannel from distributionChannel object.

        Args:
            distribution_data: The distributionChannel object from CMS
            included_by_id: Lookup dictionary of all included items

        Returns:
            DiscoveryChannel object or None if invalid
        """
        try:
            # Use the factory method from DiscoveryChannel
            discovery_channel = DiscoveryChannel.from_distribution_data(
                distribution_data, included_by_id
            )

            logger.debug(
                f"Created channel: {discovery_channel.name} "
                f"(edit_id: {discovery_channel.edit_id})"
            )

            return discovery_channel

        except Exception as e:
            logger.error(
                f"Error creating channel from distribution data: {e}"
            )
            return None

    def _build_playback_payload(self, edit_id: str) -> Dict[str, Any]:
        """
        Build playback payload for the API.

        Args:
            edit_id: Content edit ID

        Returns:
            Playback request payload
        """
        # Generate Google PAL nonce
        nonce = secrets.token_bytes(256)
        google_pal_nonce = base64.b64encode(nonce).decode('ascii')

        return {
            "appBundle": "dplus",
            "advertisingInfo": {
                "adBlockerDetection": False,
                "debug": {},
                "device": {},
                "googlePALNonce": google_pal_nonce,
                "server": {
                    "deviceId": "",
                    "iabTCFString": "",
                    "isLimitedAdTracking": 0,
                    "nielsenAppId": "",
                },
                "ssaiProvider": {"version": "2.2.0"},
            },
            "consumptionType": "streaming",
            "deviceInfo": get_default_device_info(
                self.platform_os,
                device_id=self.authenticator.device_id,
            ),
            "editId": edit_id,
            "capabilities": get_default_capabilities(self.platform_os),
            "gdpr": False,
            "firstPlay": False,
            "playbackSessionId": str(uuid.uuid4()),
            "applicationSessionId": str(uuid.uuid4()),
            "userPreferences": {
                "videoQuality": "best",
                "uiLanguage": f"{self.country}-DE".upper()
            },
            "features": ["mlp"],
        }

    def get_playback_info(self, edit_id: str, **kwargs) -> Dict:
        """
        Get playback information using edit_id.

        Args:
            edit_id: Edit ID for content
            **kwargs: Additional parameters

        Returns:
            Playback info dictionary

        Raises:
            ValueError: If edit_id not provided
            PlaybackRestrictedException: If playback restricted
        """
        if not edit_id:
            raise ValueError("edit_id is required for playback")

        headers = self._get_auth_headers()
        payload = self._build_playback_payload(edit_id)

        try:
            response = self.http_manager.post(
                self.authenticator.playback_endpoint,
                operation="playback",
                headers=headers,
                json=payload,
                timeout=30,
            )

            if response.status_code >= 400:
                error_text = response.text
                logger.error(f"Playback error response: {error_text}")
                if "PLAYBACK_RESTRICTED" in error_text:
                    raise PlaybackRestrictedException(
                        reason=f"Playback restricted for {edit_id}",
                        error_code="PLAYBACK_RESTRICTED"
                    )
                response.raise_for_status()

            response.raise_for_status()
            return response.json()

        except PlaybackRestrictedException:
            raise
        except Exception as e:
            raise ManifestFetchError(
                f"Error getting playback info for edit_id {edit_id}: {e}"
            )

    def _get_cached_playback_info(self, edit_id: str) -> Dict:
        """
        Return playback info for edit_id, using a cache keyed on expiry time.

        Tokens issued by Discovery+ are valid for 24 hours. The cache entry
        is kept until the drm_expiration timestamp returned in the response
        (minus a 60-second safety margin). If no expiration is present in the
        response, a fallback TTL of 23 hours is used.

        Args:
            edit_id: Content edit ID

        Returns:
            Playback info dictionary (from cache or freshly fetched)
        """
        now = time.time()
        cached = self._playback_cache.get(edit_id)

        if cached:
            expiry, data = cached
            if now < expiry:
                logger.debug(
                    f"Playback cache hit for edit_id {edit_id} "
                    f"(expires in {int(expiry - now)}s)"
                )
                return data
            else:
                logger.debug(f"Playback cache expired for edit_id {edit_id}, re-fetching")

        data = self.get_playback_info(edit_id=edit_id)

        # Determine expiry from drm_expiration field if available
        expiry = None
        try:
            drm_expiration_str = (
                data.get("drm", {}).get("expirationDate")
            )
            if drm_expiration_str:
                dt = datetime.fromisoformat(
                    drm_expiration_str.replace("Z", "+00:00")
                )
                # Apply a 60-second safety margin
                expiry = dt.timestamp() - 60
        except Exception as e:
            logger.debug(f"Could not parse drm_expiration: {e}")

        if expiry is None or expiry <= now:
            # Fallback: 23 hours from now
            expiry = now + 23 * 3600
            logger.debug(
                f"Using fallback 23h TTL for playback cache (edit_id: {edit_id})"
            )

        self._playback_cache[edit_id] = (expiry, data)
        logger.debug(
            f"Playback cache stored for edit_id {edit_id} "
            f"(expires in {int(expiry - now)}s)"
        )
        return data

    @staticmethod
    def extract_streaming_data(playback_data: Dict) -> Dict[str, Any]:
        """
        Extract streaming URLs and DRM info from playback response.

        Detects whichever DRM scheme is present in the response — either
        'widevine' (Linux/Chrome) or 'playready' (Windows/Edge) — and
        records it as ``drm_system`` so callers can build the correct DRMConfig
        without needing to know the active PlatformOS.

        Args:
            playback_data: Playback API response

        Returns:
            Dictionary with:
              manifest_url     – DASH manifest URL
              license_url      – DRM license server URL (or None)
              drm_system       – 'widevine' | 'playready' | None
              drm_auth         – JWT auth token extracted from license URL (or None)
              streaming_format – 'dash' (always for Discovery+)
              drm_expiration   – ISO-8601 expiration string (or None)
              fallback_manifest – Fallback manifest URL (or None)
        """
        result = {
            "manifest_url": None,
            "license_url": None,
            "drm_system": None,
            "drm_auth": None,
            "streaming_format": "dash",
            "drm_expiration": None,
            "fallback_manifest": None,
        }

        try:
            # Extract main manifest
            manifest = playback_data.get("manifest", {})
            if manifest:
                result["manifest_url"] = manifest.get("url")
                result["streaming_format"] = manifest.get("format", "dash")

            # Extract fallback manifest if available
            fallback = playback_data.get("fallback", {})
            if fallback:
                fallback_manifest = fallback.get("manifest", {})
                if fallback_manifest:
                    result["fallback_manifest"] = fallback_manifest.get("url")

            # Extract DRM info — check both schemes in priority order.
            # The server returns exactly the scheme(s) matching the capabilities
            # we advertised in the playback request (widevine for Linux,
            # playready for Windows). We probe both so this method stays
            # stateless and works regardless of which platform produced the response.
            drm = playback_data.get("drm", {})
            if drm:
                result["drm_expiration"] = drm.get("expirationDate")
                schemes = drm.get("schemes", {})

                # Preference order: widevine → playready (mirrors Linux default)
                scheme_priority = ["widevine", "playready"]
                for scheme_name in scheme_priority:
                    scheme = schemes.get(scheme_name, {})
                    if scheme and scheme.get("licenseUrl"):
                        result["license_url"] = scheme["licenseUrl"]
                        result["drm_system"] = scheme_name

                        # Extract JWT auth token from the license URL if present
                        if "auth=" in result["license_url"]:
                            import urllib.parse
                            parsed = urllib.parse.urlparse(result["license_url"])
                            query = urllib.parse.parse_qs(parsed.query)
                            if "auth" in query:
                                result["drm_auth"] = query["auth"][0]
                        break  # Stop at first found scheme

            # Extract CDN info
            cdn = playback_data.get("cdn", {})
            if cdn:
                result["cdn_provider"] = cdn.get("provider")

        except Exception as e:
            logger.error(f"Error extracting streaming data: {e}")

        return result

    def _build_drm_config(self, streaming_data: Dict[str, Any]) -> Optional[DRMConfig]:
        """
        Build a DRMConfig from extracted streaming data.

        Selects the correct DRMSystem based on the scheme returned by the
        server (recorded in ``streaming_data["drm_system"]``).  Falls back to
        the active ``self.platform_os`` when the scheme is absent so the caller
        never has to make this decision themselves.

        Supported schemes:
          'widevine'  → DRMSystem.WIDEVINE  (Linux/Chrome path)
          'playready' → DRMSystem.PLAYREADY (Windows/Edge path)

        Args:
            streaming_data: Dictionary returned by extract_streaming_data()

        Returns:
            DRMConfig instance or None if no license URL is available
        """
        license_url = streaming_data.get("license_url")
        if not license_url:
            return None

        # Resolve DRM system from what the server actually returned,
        # falling back to platform_os expectation if not present.
        drm_system_str = streaming_data.get("drm_system")
        if drm_system_str == "playready":
            drm_system = DRMSystem.PLAYREADY
        elif drm_system_str == "widevine":
            drm_system = DRMSystem.WIDEVINE
        else:
            # Fallback: derive from active platform
            drm_system = (
                DRMSystem.PLAYREADY
                if self.platform_os == PlatformOS.WINDOWS
                else DRMSystem.WIDEVINE
            )
            logger.debug(
                f"drm_system not in streaming_data, inferred from platform_os "
                f"({self.platform_os.value}): {drm_system.name}"
            )

        license_headers = get_drm_request_headers(self.platform_os)

        return DRMConfig(
            system=drm_system,
            priority=1,
            license=LicenseConfig(
                server_url=license_url,
                req_headers=json.dumps(license_headers),
                req_data="{CHA-RAW}",
                use_http_get_request=False,
            ),
        )

    def populate_streaming_data(
            self,
            channels: List[StreamingChannel],
            max_retries: int = 3,
    ) -> List[StreamingChannel]:
        """
        Populate streaming data for channels using cached DiscoveryChannel data.

        Args:
            channels: List of StreamingChannel objects to populate
            max_retries: Maximum retry attempts per channel

        Returns:
            List of successfully populated channels
        """
        successful_channels = []

        for channel in channels:
            retries = 0
            success = False
            is_restricted = False

            while retries < max_retries and not success and not is_restricted:
                try:
                    # Get DiscoveryChannel from cache
                    disco_channel = self._channels_cache.get(channel.channel_id)

                    if not disco_channel:
                        logger.warning(
                            f"Channel {channel.name} not in cache, skipping"
                        )
                        break

                    # Get edit_id from cached DiscoveryChannel
                    edit_id = disco_channel.edit_id

                    if not edit_id:
                        logger.warning(
                            f"No edit_id for channel {channel.name}, skipping"
                        )
                        break

                    logger.debug(
                        f"Getting playback info for: {channel.name} "
                        f"(edit_id: {edit_id}, attempt {retries + 1})"
                    )

                    playback_data = self._get_cached_playback_info(edit_id=edit_id)
                    streaming_data = self.extract_streaming_data(playback_data)

                    if streaming_data["manifest_url"]:
                        channel.manifest = streaming_data["manifest_url"]
                        channel.streaming_format = streaming_data["streaming_format"]

                        if streaming_data["license_url"]:
                            drm_config = self._build_drm_config(streaming_data)
                            if drm_config:
                                channel.drm_config = drm_config
                            channel.license_url = streaming_data["license_url"]
                            channel.cdm_type = streaming_data["drm_system"]

                            # Store DRM token in DiscoveryChannel cache
                            if streaming_data["drm_auth"]:
                                disco_channel.raw_data["drm_auth"] = (
                                    streaming_data["drm_auth"]
                                )

                        logger.info(
                            f"Streaming data populated for: {channel.name}"
                        )
                        successful_channels.append(channel)
                        success = True
                    else:
                        raise ManifestFetchError("No manifest URL in response")

                except PlaybackRestrictedException as e:
                    logger.warning(
                        f"Playback restricted for {channel.name}: {e}"
                    )
                    is_restricted = True

                except Exception as e:
                    retries += 1
                    if retries < max_retries:
                        logger.debug(
                            f"Retry {retries}/{max_retries} for "
                            f"{channel.name}: {e}"
                        )
                        time.sleep(1)
                    else:
                        logger.error(
                            f"Failed to get streaming data for "
                            f"{channel.name}: {e}"
                        )

        logger.info(
            f"Streaming data population complete: "
            f"{len(successful_channels)}/{len(channels)}"
        )
        return successful_channels

    def get_manifest(self, content_id: str, **kwargs) -> Optional[str]:
        """
        Get manifest URL for a specific channel by ID.

        Args:
            content_id: Channel identifier
            **kwargs: Additional parameters

        Returns:
            Manifest URL or None

        Raises:
            ChannelNotFoundError: If channel not in cache
        """
        try:
            # Get DiscoveryChannel from cache
            disco_channel = self._channels_cache.get(content_id)

            if not disco_channel:
                raise ChannelNotFoundError(content_id)

            edit_id = disco_channel.edit_id

            if not edit_id:
                raise ManifestFetchError(
                    f"No edit_id for channel {content_id}"
                )

            playback_data = self._get_cached_playback_info(edit_id=edit_id)
            streaming_data = self.extract_streaming_data(playback_data)
            return streaming_data.get("manifest_url")

        except (ChannelNotFoundError, ManifestFetchError):
            raise
        except Exception as e:
            logger.error(
                f"Error getting manifest for channel {content_id}: {e}"
            )
            return None

    def get_drm(self, content_id: str, **kwargs) -> List[DRMConfig]:
        """
        Get all DRM configurations for a channel by ID.

        Args:
            content_id: Channel identifier
            **kwargs: Additional parameters

        Returns:
            List of DRM configurations
        """
        try:
            # Get DiscoveryChannel from cache
            disco_channel = self._channels_cache.get(content_id)

            if not disco_channel:
                logger.warning(
                    f"Channel {content_id} not in cache for DRM"
                )
                return []

            edit_id = disco_channel.edit_id

            if not edit_id:
                return []

            playback_data = self._get_cached_playback_info(edit_id=edit_id)
            streaming_data = self.extract_streaming_data(playback_data)

            if not streaming_data["license_url"]:
                return []

            drm_config = self._build_drm_config(streaming_data)
            return [drm_config] if drm_config else []

        except Exception as e:
            logger.error(
                f"Error getting DRM configs for channel {content_id}: {e}"
            )
            return []

    def get_epg(
            self,
            channel_id: str,
            start_time: Optional[datetime] = None,
            end_time: Optional[datetime] = None,
            **kwargs,
    ) -> List[Dict]:
        """
        Get EPG data for a channel (not yet implemented).

        Args:
            channel_id: Channel identifier
            start_time: Start time for EPG data
            end_time: End time for EPG data
            **kwargs: Additional parameters

        Returns:
            Empty list (not implemented)
        """
        logger.info(
            f"EPG data requested for channel {channel_id} - "
            "not yet implemented"
        )
        return []