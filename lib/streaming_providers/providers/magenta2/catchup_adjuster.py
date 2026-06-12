# streaming_providers/magenta2/catchup_adjuster.py
"""
Magenta2 catchup manifest adjuster.
"""

from datetime import datetime, timezone
from ...base.utils.logger import logger
from ...base.utils.mpd_event_rewriter import get_mpd_event_rewriter

_MAGENTA2_EPG_SCHEME = "urn:de:dtag:eit:2017"
_EVENT_MATCH_THRESHOLD_S = 300


class Magenta2CatchupAdjuster:
    """Adjusts Magenta2 catchup manifests to requested start time."""

    @staticmethod
    def adjust(mpd_content: str, requested_start_time: int) -> str:
        """
        Adjust Magenta2 catchup MPD to start at requested time.

        Returns adjusted MPD content, or original if adjustment fails.
        """
        rewriter = get_mpd_event_rewriter()
        requested_dt = datetime.fromtimestamp(requested_start_time, tz=timezone.utc)

        try:
            events, ast = rewriter.extract_events(mpd_content, _MAGENTA2_EPG_SCHEME)

            if not events:
                logger.warning("Magenta2: no events found, using buffer offset")
                return rewriter.rewrite_by_buffer_offset(mpd_content, ast, requested_dt)

            best_event, diff = rewriter.find_closest_event(events, ast, requested_dt)

            if best_event and diff <= _EVENT_MATCH_THRESHOLD_S:
                logger.info(
                    f"Magenta2: adjusting to event '{best_event.title}' "
                    f"(start={best_event.wall_clock_start(ast).isoformat()}, diff={diff:.0f}s)"
                )
                return rewriter.rewrite_for_event(
                    mpd_content, ast, best_event,
                    keep_other_events=False,
                    force_static_if_ended=False,
                )

            logger.info(f"Magenta2: no close event match (diff={diff:.0f}s), using buffer offset")
            return rewriter.rewrite_by_buffer_offset(mpd_content, ast, requested_dt)

        except ValueError as e:
            logger.warning(f"Magenta2: cannot parse events ({e}), using buffer offset")
            try:
                _, ast = rewriter.extract_events(mpd_content)  # fallback without scheme
                return rewriter.rewrite_by_buffer_offset(mpd_content, ast, requested_dt)
            except ValueError:
                logger.error("Magenta2: MPD has no availabilityStartTime")
                return mpd_content
        except Exception as e:
            logger.error(f"Magenta2: adjustment failed: {e}")
            return mpd_content