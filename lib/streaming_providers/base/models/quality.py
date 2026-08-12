# streaming_providers/base/models/quality.py
from enum import Enum

class Quality(str, Enum):
    """Stream quality levels."""
    SD = "SD"
    HD = "HD"
    UHD = "UHD"
    FOUR_K = "4K"
    AUDIO = "AUDIO"

class StreamingFormat(str, Enum):
    """Streaming protocol formats."""
    HLS = "hls"
    DASH = "dash"
    MSS = "mss"