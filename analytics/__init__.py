"""Analytics event emission. Optional and best-effort: it must never affect playback."""
from .emitter import (
    AnalyticsEmitter,
    configure_from_env,
    get_emitter,
    shutdown_emitter,
)
from .integration import annotate, tracked

__all__ = [
    "AnalyticsEmitter",
    "configure_from_env",
    "get_emitter",
    "shutdown_emitter",
    "annotate",
    "tracked",
]