# streaming_providers/base/utils/timestamp_converter.py
"""
Timestamp conversion utilities for streaming providers.

Provides methods to convert between Unix epoch seconds and ISO 8601 formats,
with support for timezone handling.
"""

import datetime
from typing import Optional, Union


class TimestampConverter:
    """
    Utility class for converting between epoch seconds and ISO 8601 timestamps.

    Supports both extended (human-readable) and basic (compact) ISO 8601 formats.
    """

    # ISO 8601 format constants
    ISO_EXTENDED = "%Y-%m-%dT%H:%M:%S"
    ISO_BASIC = "%Y%m%dT%H%M%S"
    ISO_WITH_MICROSECONDS = "%Y-%m-%dT%H:%M:%S.%f"
    ISO_WITH_TIMEZONE = "%Y-%m-%dT%H:%M:%S%z"

    # UTC timezone constant (Python 3.11+ compatibility)
    if hasattr(datetime, 'UTC'):
        UTC = datetime.UTC
    else:
        UTC = datetime.timezone.utc

    @staticmethod
    def epoch_to_iso(
        epoch_seconds: Union[int, float],
        format_type: str = "extended",
        timezone: Optional[datetime.tzinfo] = None,
        as_utc: bool = True
    ) -> str:
        """
        Convert Unix epoch seconds to ISO 8601 timestamp.

        Args:
            epoch_seconds: Unix timestamp in seconds
            format_type: "extended" (2025-12-08T07:59:30), "basic" (20251208T075930),
                        "microseconds" (2025-12-08T07:59:30.000000), or
                        "with_timezone" (2025-12-08T07:59:30+00:00)
            timezone: Optional timezone object (if None and as_utc=True, uses UTC)
            as_utc: If True and no timezone provided, treat epoch as UTC

        Returns:
            ISO 8601 formatted timestamp string

        Raises:
            ValueError: If format_type is invalid
        """
        # Create timezone-aware datetime from epoch
        if as_utc and timezone is None:
            # Use UTC timezone
            dt = datetime.datetime.fromtimestamp(epoch_seconds, tz=TimestampConverter.UTC)
        elif timezone is not None:
            # Use specified timezone
            dt = datetime.datetime.fromtimestamp(epoch_seconds, tz=timezone)
        else:
            # No timezone specified and not forcing UTC - create naive datetime
            dt = datetime.datetime.fromtimestamp(epoch_seconds)

        # Choose format
        if format_type == "extended":
            format_str = TimestampConverter.ISO_EXTENDED
        elif format_type == "basic":
            format_str = TimestampConverter.ISO_BASIC
        elif format_type == "microseconds":
            format_str = TimestampConverter.ISO_WITH_MICROSECONDS
        elif format_type == "with_timezone":
            format_str = TimestampConverter.ISO_WITH_TIMEZONE
        else:
            raise ValueError(
                f"Invalid format_type: {format_type}. "
                f"Must be 'extended', 'basic', 'microseconds', or 'with_timezone'"
            )

        return dt.strftime(format_str)

    @staticmethod
    def iso_to_epoch(
        iso_string: str,
        format_type: Optional[str] = None,
        timezone: Optional[datetime.tzinfo] = None
    ) -> float:
        """
        Convert ISO 8601 timestamp to Unix epoch seconds.

        Args:
            iso_string: ISO 8601 timestamp string
            format_type: Optional format type. If None, auto-detects based on string format.
            timezone: Optional timezone object. If provided and the input string doesn't
                     have timezone info, interpret it in this timezone.

        Returns:
            Unix epoch seconds (float)

        Raises:
            ValueError: If string cannot be parsed
        """
        # First try datetime.fromisoformat() which handles many ISO formats
        try:
            # Clean up the string for fromisoformat
            cleaned = iso_string.replace('Z', '+00:00')
            dt = datetime.datetime.fromisoformat(cleaned)
            # If we got here, fromisoformat worked
        except ValueError:
            # Try our custom parsers
            dt = TimestampConverter._parse_custom_iso(iso_string, format_type)

        # If datetime is naive and timezone is provided, localize it
        if dt.tzinfo is None and timezone is not None:
            dt = dt.replace(tzinfo=timezone)

        # Convert to epoch seconds
        if dt.tzinfo is not None:
            # For timezone-aware datetimes, convert to UTC first
            dt_utc = dt.astimezone(TimestampConverter.UTC)
            return dt_utc.timestamp()
        else:
            # For naive datetimes, assume UTC
            return dt.replace(tzinfo=TimestampConverter.UTC).timestamp()

    @staticmethod
    def _parse_custom_iso(
        iso_string: str,
        format_type: Optional[str] = None
    ) -> datetime.datetime:
        """
        Parse custom ISO formats not handled by fromisoformat.

        Args:
            iso_string: ISO string to parse
            format_type: Optional format type hint

        Returns:
            datetime object
        """
        # Auto-detect format if not specified
        if format_type is None:
            if "T" in iso_string:
                if "-" in iso_string and ":" in iso_string:
                    if "." in iso_string:
                        format_type = "microseconds"
                    else:
                        format_type = "extended"
                else:
                    format_type = "basic"
            else:
                raise ValueError("String does not appear to be ISO 8601 format")

        # Map format type to format string
        format_map = {
            "extended": TimestampConverter.ISO_EXTENDED,
            "basic": TimestampConverter.ISO_BASIC,
            "microseconds": TimestampConverter.ISO_WITH_MICROSECONDS,
            "with_timezone": TimestampConverter.ISO_WITH_TIMEZONE
        }

        if format_type not in format_map:
            raise ValueError(f"Invalid format_type: {format_type}")

        format_str = format_map[format_type]

        try:
            dt = datetime.datetime.strptime(iso_string, format_str)
        except ValueError:
            # Try without microseconds if microseconds format fails
            if format_type == "microseconds":
                dt = datetime.datetime.strptime(iso_string, TimestampConverter.ISO_EXTENDED)
            else:
                raise

        return dt

    @staticmethod
    def now_iso(
        format_type: str = "extended",
        timezone: Optional[datetime.tzinfo] = None
    ) -> str:
        """
        Get current time as ISO 8601 string.

        Args:
            format_type: "extended", "basic", "microseconds", or "with_timezone"
            timezone: Optional timezone for the output (defaults to UTC)

        Returns:
            Current time as ISO 8601 string
        """
        if timezone:
            now = datetime.datetime.now(timezone)
        else:
            now = datetime.datetime.now(TimestampConverter.UTC)

        if format_type == "extended":
            format_str = TimestampConverter.ISO_EXTENDED
        elif format_type == "basic":
            format_str = TimestampConverter.ISO_BASIC
        elif format_type == "microseconds":
            format_str = TimestampConverter.ISO_WITH_MICROSECONDS
        elif format_type == "with_timezone":
            format_str = TimestampConverter.ISO_WITH_TIMEZONE
        else:
            raise ValueError(f"Invalid format_type: {format_type}")

        return now.strftime(format_str)

    @staticmethod
    def parse_flexible(timestamp: Union[int, float, str]) -> datetime.datetime:
        """
        Parse a timestamp that could be epoch seconds or ISO string.

        Args:
            timestamp: Could be epoch (int/float) or ISO string

        Returns:
            timezone-aware datetime object (in UTC if from epoch)
        """
        if isinstance(timestamp, (int, float)):
            # Create UTC-aware datetime from epoch
            return datetime.datetime.fromtimestamp(timestamp, tz=TimestampConverter.UTC)
        elif isinstance(timestamp, str):
            # Clean and parse ISO string
            cleaned = timestamp.replace("Z", "+00:00")
            try:
                dt = datetime.datetime.fromisoformat(cleaned)
                # If naive, assume UTC
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=TimestampConverter.UTC)
                return dt
            except ValueError:
                # Try our custom parser
                return TimestampConverter._parse_custom_iso(cleaned)
        else:
            raise TypeError(f"Unsupported timestamp type: {type(timestamp)}")

    @staticmethod
    def duration_between(
        start: Union[int, float, str],
        end: Union[int, float, str],
        unit: str = "seconds"
    ) -> float:
        """
        Calculate duration between two timestamps.

        Args:
            start: Start timestamp (epoch or ISO string)
            end: End timestamp (epoch or ISO string)
            unit: Output unit: "seconds", "minutes", "hours", or "days"

        Returns:
            Duration in specified unit
        """
        # Parse timestamps to timezone-aware datetime objects
        dt_start = TimestampConverter.parse_flexible(start)
        dt_end = TimestampConverter.parse_flexible(end)

        # Ensure both are in UTC for comparison
        dt_start_utc = dt_start.astimezone(TimestampConverter.UTC)
        dt_end_utc = dt_end.astimezone(TimestampConverter.UTC)

        # Calculate duration
        duration = dt_end_utc - dt_start_utc
        seconds = duration.total_seconds()

        # Convert to requested unit
        unit_conversion = {
            "seconds": 1,
            "minutes": 1/60,
            "hours": 1/3600,
            "days": 1/86400
        }

        if unit not in unit_conversion:
            raise ValueError(f"Invalid unit: {unit}")

        return seconds * unit_conversion[unit]

    @staticmethod
    def to_utc(dt: datetime.datetime) -> datetime.datetime:
        """
        Convert any datetime to UTC timezone-aware datetime.

        Args:
            dt: datetime object (naive or timezone-aware)

        Returns:
            UTC timezone-aware datetime
        """
        if dt.tzinfo is None:
            # Naive datetime - assume UTC
            return dt.replace(tzinfo=TimestampConverter.UTC)
        else:
            # Convert to UTC
            return dt.astimezone(TimestampConverter.UTC)

    @staticmethod
    def get_timezone(name: str = "UTC") -> datetime.tzinfo:
        """
        Get timezone object by name.

        Args:
            name: Timezone name (e.g., "UTC", "Europe/Berlin")

        Returns:
            timezone object

        Note:
            For named timezones beyond UTC, install pytz or use zoneinfo (Python 3.9+)
        """
        if name.upper() == "UTC":
            return TimestampConverter.UTC

        # Try zoneinfo (Python 3.9+)
        try:
            from zoneinfo import ZoneInfo
            return ZoneInfo(name)
        except ImportError:
            pass

        # Try pytz
        try:
            import pytz
            return pytz.timezone(name)
        except ImportError:
            raise ImportError(
                f"Need pytz or zoneinfo to use timezone '{name}'. "
                f"Install with: pip install pytz"
            )