"""Provider catchup (start-over / replay) mixin."""

import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from ..models import DRMConfig


class ProviderCatchupMixin:
    @property
    def catchup_window(self) -> int:
        """
        Return the catchup window in HOURS for this provider.

        Returns:
            int: Number of hours of catchup available (0 = no catchup support)
        """
        return 0

    @property
    def supports_catchup(self) -> bool:
        """
        Check if provider supports catchup/timeshift functionality.

        Returns:
            bool: True if catchup is supported
        """
        return self.catchup_window > 0

    def get_catchup_manifest(
        self,
        content_id: str,
        start_time: int,
        end_time: int,
        epg_id: Optional[str] = None,
        **kwargs,
    ) -> Optional[str]:
        """
        Get manifest URL for catchup/timeshift content.

        Args:
            content_id: Channel identifier
            start_time: Start time as Unix timestamp
            end_time: End time as Unix timestamp
            epg_id: Optional EPG event ID (might be needed by some providers)
            **kwargs: Additional provider-specific parameters

        Returns:
            Manifest URL for catchup content, or None if not supported

        Default implementation raises NotImplementedError.
        Override in subclass to implement provider-specific catchup logic.

        Do NOT fall back to self.get_manifest() here — returning the live
        manifest URL as a catchup manifest will cause the DRM pipeline to
        extract PSSH from the live stream, which may differ from the catchup
        stream's encryption context.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__}.get_catchup_manifest() is not implemented."
        )

    def get_catchup_manifest_headers(
        self,
        content_id: str,
        start_time: int,
        end_time: int,
        epg_id: Optional[str] = None,
        **kwargs,
    ) -> Dict[str, str]:
        """
        Return HTTP headers for the catchup manifest request.

        Default implementation delegates to get_manifest_headers() since many
        providers use the same auth headers for live and catchup manifests.
        Override when catchup requires different headers (e.g. extra tokens).
        """
        return self.get_manifest_headers(content_id, **kwargs)

    def get_catchup_manifest_with_headers(
        self,
        content_id: str,
        start_time: int,
        end_time: int,
        epg_id: Optional[str] = None,
        **kwargs,
    ) -> Tuple[Optional[str], Dict[str, str]]:
        """
        Convenience method returning (catchup_manifest_url, headers).

        This is the single entry point used by CatchupOperations before
        calling into the DRM pipeline, mirroring the role that
        get_manifest_with_headers() plays for live content.

        Providers should override get_catchup_manifest() (and optionally
        get_catchup_manifest_headers()) rather than this method directly.

        Raises:
            NotImplementedError: propagated from get_catchup_manifest() if the
                provider has not implemented catchup manifest resolution.
        """
        url = self.get_catchup_manifest(
            content_id=content_id,
            start_time=start_time,
            end_time=end_time,
            epg_id=epg_id,
            **kwargs,
        )
        headers = self.get_catchup_manifest_headers(
            content_id=content_id,
            start_time=start_time,
            end_time=end_time,
            epg_id=epg_id,
            **kwargs,
        )
        return url, headers

    def get_catchup_drm(
        self,
        content_id: str,
        start_time: int,
        end_time: int,
        epg_id: Optional[str] = None,
        drm_variant: Optional[str] = None,
        **kwargs,
    ) -> List[DRMConfig]:
        """
        Get DRM configurations for catchup content.

        Args:
            content_id: Channel identifier
            start_time: Start time as Unix timestamp
            end_time: End time as Unix timestamp
            epg_id: Optional EPG event ID (might be needed for DRM licensing)
            drm_variant: Optional DRM variant ('auto', 'software', 'hardware')
            **kwargs: Additional provider-specific parameters

        Returns:
            List of DRM configurations for catchup content

        Default implementation raises NotImplementedError so that the DRM
        pipeline falls through to PSSH extraction from the catchup manifest.

        Override in subclass when catchup requires a *different* DRM
        configuration from live (e.g. a different license URL, extra request
        headers, or a static ClearKey set).  If catchup uses exactly the same
        DRM as live, implement as:

            def get_catchup_drm(self, content_id, start_time, end_time,
                                epg_id=None, drm_variant=None, **kwargs):
                return self.get_drm(content_id, drm_variant=drm_variant, **kwargs)

        Do NOT call super().get_drm() silently — that would make the pipeline
        think Phase 2 produced valid configs from the live stream context,
        which is wrong when the catchup manifest has different encryption.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__}.get_catchup_drm() is not implemented. "
            "The DRM pipeline will extract PSSH from the catchup manifest directly. "
            "Override this method only if catchup requires a custom DRM configuration."
        )

    # ============================================================================
    # CATCHUP HELPER METHODS
    # ============================================================================

    def get_catchup_window_for_channel(self, content_id: str) -> int:
        """
        Get catchup window for a specific channel in HOURS.

        Args:
            content_id: Channel identifier

        Returns:
            int: Catchup window in hours for this channel
        """
        return self.catchup_window

    def validate_catchup_request(
        self, start_time: int, end_time: int
    ) -> tuple[bool, Optional[str]]:
        """
        Validate a catchup request against provider's capabilities.

        Args:
            start_time: Start time as Unix timestamp
            end_time: End time as Unix timestamp

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.supports_catchup:
            return False, f"Provider '{self.provider_name}' does not support catchup"

        if start_time >= end_time:
            return False, "Invalid time range: start_time must be before end_time"

        now = int(time.time())
        if start_time > now:
            return False, "Cannot request future content"

        # CHANGE FROM DAYS TO HOURS HERE
        max_age_seconds = self.catchup_window * 3600  # hours to seconds
        content_age = now - start_time

        if content_age > max_age_seconds:
            hours_ago = content_age // 3600
            return False, (
                f"Content is outside catchup window "
                f"(requested: {hours_ago} hours ago, "
                f"max: {self.catchup_window} hours)"
            )

        return True, None

    def format_catchup_time_params(
        self, start_time: int, end_time: int, format_type: str = "iso"
    ) -> Dict[str, str]:
        """
        Format time parameters for provider-specific API calls.

        Different providers expect different time formats in their APIs.
        This helper converts Unix timestamps to various formats.

        Args:
            start_time: Start time as Unix timestamp
            end_time: End time as Unix timestamp
            format_type: Format type ('iso', 'unix', 'millis', 'custom')

        Returns:
            Dictionary with formatted time parameters

        Override in subclass for provider-specific formatting.
        """
        if format_type == "iso":
            # ISO 8601 format
            start_dt = datetime.fromtimestamp(start_time)
            end_dt = datetime.fromtimestamp(end_time)
            return {"start": start_dt.isoformat(), "end": end_dt.isoformat()}
        elif format_type == "unix":
            # Unix timestamps (seconds)
            return {"start": str(start_time), "end": str(end_time)}
        elif format_type == "millis":
            # Milliseconds since epoch
            return {"start": str(start_time * 1000), "end": str(end_time * 1000)}
        else:
            # Default to unix
            return {"start": str(start_time), "end": str(end_time)}

    def build_catchup_manifest_url(
        self, base_url: str, start_time: int, end_time: int, url_format: str = "query"
    ) -> str:
        """
        Build catchup manifest URL with time parameters.

        Helper method to construct manifest URLs with time parameters
        in various formats that different providers use.

        Args:
            base_url: Base manifest URL
            start_time: Start time as Unix timestamp
            end_time: End time as Unix timestamp
            url_format: Format ('query', 'path', 'fragment')

        Returns:
            Complete manifest URL with time parameters

        Override in subclass for provider-specific URL construction.
        """
        if url_format == "query":
            # Add as query parameters
            separator = "&" if "?" in base_url else "?"
            return f"{base_url}{separator}start={start_time}&end={end_time}"
        elif url_format == "path":
            # Add to path (e.g., /manifest/start/end.mpd)
            return f"{base_url}/{start_time}/{end_time}"
        elif url_format == "fragment":
            # Add as URL fragment (e.g., manifest.mpd#t=start,end)
            return f"{base_url}#t={start_time},{end_time}"
        else:
            # Default to query parameters
            separator = "&" if "?" in base_url else "?"
            return f"{base_url}{separator}start={start_time}&end={end_time}"