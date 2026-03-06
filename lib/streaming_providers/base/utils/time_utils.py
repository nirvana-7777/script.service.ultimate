# streaming_providers/base/utils/time_utils.py
import re
from typing import Optional

# Pre-compile regex for ISO duration parsing
ISO_8601_PERIOD_RE = re.compile(
    r"P(?:(?P<years>\d+)Y)?(?:(?P<months>\d+)M)?(?:(?P<weeks>\d+)W)?(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+(?:\.\d+)?)S)?)?"
)


def parse_iso_duration(duration: str) -> int:
    """
    Parse ISO 8601 duration string to seconds.

    Args:
        duration: ISO 8601 duration string (e.g., "PT30S", "PT2M30S")

    Returns:
        Total seconds as integer
    """
    match = ISO_8601_PERIOD_RE.match(duration)
    if not match:
        return 0
    d = match.groupdict()
    return int(
        int(d.get("hours") or 0) * 3600
        + int(d.get("minutes") or 0) * 60
        + float(d.get("seconds") or 0)
    )