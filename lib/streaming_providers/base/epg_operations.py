# ============================================================================
# streaming_providers/base/epg_operations.py
"""
EPG-related operations.
"""

from typing import Dict, List, Optional
from datetime import datetime, timedelta, timezone

from .epg import EPGManager
from .utils.logger import logger
from .models.epg_models import EPGEntry, EPGProgramDetails


class EPGWindowError(Exception):
    """Raised when EPG request is outside the valid time window."""
    def __init__(self, message, requested_start=None, requested_end=None,
                 min_allowed=None, max_allowed=None, provider_window_days=None):
        self.message = message
        self.requested_start = requested_start
        self.requested_end = requested_end
        self.min_allowed = min_allowed
        self.max_allowed = max_allowed
        self.provider_window_days = provider_window_days
        super().__init__(message)


class EPGOperations:
    """Handles all EPG-related operations.

    Design note: instantiate this class ONCE (e.g. at application / route
    setup time) and reuse the same instance for every request.  Creating a
    new instance per-request causes EPGManager, EPGCache, EPGMapping and
    their VFS helpers to be re-constructed (and re-logged) on every call.
    """

    def __init__(self, registry):
        self.registry = registry
        self.epg_manager = EPGManager()
        logger.debug("EPGOperations: Initialized")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_provider(self, provider_name: str):
        """Return the provider instance or raise ValueError."""
        provider = self.registry.get_provider(provider_name)
        if not provider:
            raise ValueError(f"Provider '{provider_name}' not found or disabled")
        return provider

    def _validate_epg_window(self, provider, start_time, end_time):
        """
        Validate EPG time window against provider's supported window.

        Raises:
            EPGWindowError: If the requested window is outside the valid range.

        Returns:
            Tuple of (start_time, end_time) validated and clamped to provider's window.
        """
        if not start_time and not end_time:
            # If no times provided, use provider's default (usually today)
            return start_time, end_time

        # Get provider's EPG window (days back, days forward)
        epg_window = getattr(provider, 'epg_window', (7, 7))
        days_back, days_forward = epg_window

        now_utc = datetime.now(tz=timezone.utc)
        min_allowed = now_utc - timedelta(days=days_back)
        max_allowed = now_utc + timedelta(days=days_forward)

        # Ensure times are timezone-aware
        if start_time and start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)
        if end_time and end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)

        # Check if the requested window is completely outside the valid range
        if start_time and end_time:
            # If the entire window is outside the valid range
            if end_time < min_allowed or start_time > max_allowed:
                raise EPGWindowError(
                    message="Requested EPG time window is outside the valid range",
                    requested_start=start_time.isoformat(),
                    requested_end=end_time.isoformat(),
                    min_allowed=min_allowed.isoformat(),
                    max_allowed=max_allowed.isoformat(),
                    provider_window_days=days_back
                )

        # Clamp individual times if they're partially outside
        if start_time:
            if start_time < min_allowed:
                logger.warning(
                    f"EPG start_time {start_time} is before the minimum allowed "
                    f"({min_allowed}). Clamping to {min_allowed}"
                )
                start_time = min_allowed
            elif start_time > max_allowed:
                logger.warning(
                    f"EPG start_time {start_time} is after the maximum allowed "
                    f"({max_allowed}). Clamping to {max_allowed}"
                )
                start_time = max_allowed

        if end_time:
            if end_time < min_allowed:
                logger.warning(
                    f"EPG end_time {end_time} is before the minimum allowed "
                    f"({min_allowed}). Clamping to {min_allowed}"
                )
                end_time = min_allowed
            elif end_time > max_allowed:
                logger.warning(
                    f"EPG end_time {end_time} is after the maximum allowed "
                    f"({max_allowed}). Clamping to {max_allowed}"
                )
                end_time = max_allowed

        # Ensure start_time <= end_time
        if start_time and end_time and start_time > end_time:
            logger.warning(
                f"EPG start_time {start_time} is after end_time {end_time}. Swapping."
            )
            start_time, end_time = end_time, start_time

        return start_time, end_time

    # ------------------------------------------------------------------
    # Channel EPG
    # ------------------------------------------------------------------

    def get_channel_epg(
            self,
            provider_name: str,
            channel_id: str,
            start_time=None,
            end_time=None,
            limit: int = 100,
            country: Optional[str] = None,
    ) -> List[EPGEntry]:
        """Get EPG data for a specific channel."""
        provider = self._get_provider(provider_name)

        if provider.implements_epg:
            # Native providers hit a real upstream API per request — clamp/reject
            # out-of-window requests so we don't overwhelm it. Generic/XMLTV-backed
            # providers (epg_window == (0, 0)) read from a locally cached feed and
            # don't need this throttling.
            try:
                start_time, end_time = self._validate_epg_window(provider, start_time, end_time)
            except EPGWindowError as e:
                logger.warning(f"EPG window validation failed for {provider_name}: {e.message}")
                raise

            logger.debug(f"Using native EPG for '{provider_name}'")
            epg_data = provider.get_epg(
                channel_id,
                start_time=start_time,
                end_time=end_time,
                limit=limit,
                country=country,
            )
        else:
            logger.debug(f"Using generic EPG for '{provider_name}'")
            epg_data = self.epg_manager.get_epg(
                provider_name=provider_name,
                channel_id=channel_id,
                start_time=start_time,
                end_time=end_time,
                limit=limit,
                country=country,
            )

        if epg_data is None:
            logger.warning(
                f"get_epg() returned None for channel '{channel_id}' "
                f"on provider '{provider_name}' — treating as empty result"
            )
            epg_data = []

        logger.debug(f"Retrieved {len(epg_data)} EPG entries for '{channel_id}'")
        return epg_data

    # ------------------------------------------------------------------
    # Multi-channel grid
    # ------------------------------------------------------------------

    def get_provider_epg_grid(
            self,
            provider_name: str,
            start_time=None,
            end_time=None,
            channel_ids: Optional[List[str]] = None,
            country: Optional[str] = None,
    ) -> Dict[str, List[EPGEntry]]:
        """Get a time-windowed EPG grid across multiple channels."""
        provider = self._get_provider(provider_name)

        if provider.implements_epg:
            try:
                start_time, end_time = self._validate_epg_window(provider, start_time, end_time)
            except EPGWindowError as e:
                logger.warning(f"EPG window validation failed for {provider_name}: {e.message}")
                raise

            logger.debug(f"Using native EPG grid for '{provider_name}'")
            return provider.get_epg_grid(
                start_time=start_time,
                end_time=end_time,
                channel_ids=channel_ids,
                country=country,
            ) or {}

        # Fallback: generic EPG manager (XMLTV-backed, no native window throttling needed)
        logger.debug(f"Using generic EPG grid fallback for '{provider_name}'")
        channels = channel_ids or self.epg_manager.get_channel_ids(provider_name)
        grid: Dict[str, List[Dict]] = {}
        for cid in channels:
            entries = self.epg_manager.get_epg(
                provider_name=provider_name,
                channel_id=cid,
                start_time=start_time,
                end_time=end_time,
            ) or []
            grid[cid] = entries

        logger.debug(
            f"Grid for '{provider_name}': {len(grid)} channels, "
            f"window {start_time} – {end_time}"
        )
        return grid

    # ------------------------------------------------------------------
    # Program detail
    # ------------------------------------------------------------------

    def get_program_details(
        self,
        provider_name: str,
        program_id: str,
    ) -> Optional[EPGProgramDetails]:
        """Get full metadata for a single program.

        Args:
            provider_name: Registered provider identifier.
            program_id:    Provider-scoped program identifier.
        """
        provider = self._get_provider(provider_name)

        if provider.implements_epg:
            logger.debug(f"Using native program detail for '{provider_name}/{program_id}'")
            return provider.get_program_details(program_id)

        logger.debug(f"Using generic program detail for '{provider_name}/{program_id}'")
        # The generic EPGManager has no program-detail index; native providers
        # must implement get_program_details() to support this endpoint.
        return None

    # ------------------------------------------------------------------
    # XMLTV export
    # ------------------------------------------------------------------

    def get_provider_epg_xmltv(
        self,
        provider_name: str,
        country: Optional[str] = None,
    ) -> Optional[str]:
        """Get the complete EPG feed in XMLTV format.

        Args:
            provider_name: Registered provider identifier.
            country:       Optional country filter forwarded to the provider.
        """
        provider = self._get_provider(provider_name)

        if provider.implements_epg:
            return provider.get_epg_xmltv(country=country)

        logger.warning(f"Provider '{provider_name}' has no XMLTV EPG")
        return None

    # ------------------------------------------------------------------
    # Cache / mapping utilities
    # ------------------------------------------------------------------

    def clear_epg_cache(self) -> bool:
        """Clear the generic EPG cache."""
        return self.epg_manager.clear_cache()

    def reload_epg_mapping(self) -> bool:
        """Reload EPG channel mapping."""
        return self.epg_manager.reload_mapping()

    def get_epg_cache_info(self) -> Optional[Dict]:
        """Get EPG cache information."""
        return self.epg_manager.get_cache_info()

    def get_epg_mapping_stats(self) -> Dict:
        """Get EPG mapping statistics."""
        return self.epg_manager.get_mapping_stats()

    def has_epg_mapping(self, provider_name: str, channel_id: str) -> bool:
        """Check if an EPG mapping exists for the given channel."""
        return self.epg_manager.has_mapping_for_channel(provider_name, channel_id)