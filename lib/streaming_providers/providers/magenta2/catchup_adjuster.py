# streaming_providers/magenta2/catchup_adjuster.py
"""
Magenta2 catchup manifest adjuster.
"""

from datetime import datetime, timezone
from ...base.utils.logger import logger
from ...base.utils.mpd_event_rewriter import get_mpd_event_rewriter

_MAGENTA2_EPG_SCHEME = "urn:de:dtag:eit:2017"
_EVENT_MATCH_THRESHOLD_S = 300  # 5 minutes - still used as fallback
_SKIP_NEAR_END_THRESHOLD_S = 300  # Skip event if less than 5 minutes remaining


class Magenta2CatchupAdjuster:
    """Adjusts Magenta2 catchup manifests to requested start time."""

    @staticmethod
    def adjust(mpd_content: str, requested_start_time: int) -> str:
        """
        Adjust Magenta2 catchup MPD to start at requested time.

        Strategy for catchup seeking:
        1. Find the first event that starts AT OR AFTER the requested time
           (upcoming show) - this is what users typically want when seeking
        2. If no upcoming event exists, use the last event (requested time
           is after all events)
        3. Special case: If requested time is within an event AND that event
           has more than SKIP_NEAR_END_THRESHOLD_S remaining, join it in progress
        4. Otherwise, fall back to buffer offset calculation

        This ensures seeking to "Meister des Alltags" at 08:40 correctly jumps
        to Meister's start at 08:42:44, not to the nearly-finished Tagesschau.
        """
        rewriter = get_mpd_event_rewriter()
        requested_dt = datetime.fromtimestamp(requested_start_time, tz=timezone.utc)

        try:
            extracted = rewriter.extract_events(mpd_content, _MAGENTA2_EPG_SCHEME)
            events = extracted.events
            ast = extracted.availability_start

            if not events:
                logger.warning("Magenta2: no events found, using buffer offset")
                return rewriter.rewrite_by_buffer_offset(mpd_content, extracted, requested_dt)

            # Sort events by start time
            sorted_events = sorted(events, key=lambda ev: ev.wall_clock_start(ast))

            # First, check if requested time falls within a long-running event
            current_event = None
            for ev in sorted_events:
                ev_start = ev.wall_clock_start(ast)
                ev_end = ev.wall_clock_end(ast)
                if ev_start <= requested_dt <= ev_end:
                    current_event = ev
                    break

            if current_event:
                time_into_event = (requested_dt - current_event.wall_clock_start(ast)).total_seconds()
                time_remaining = current_event.duration_seconds() - time_into_event

                # If we're near the end of the current event, skip to next event
                if time_remaining <= _SKIP_NEAR_END_THRESHOLD_S:
                    logger.info(
                        f"Magenta2: requested time near end of '{current_event.title}' "
                        f"({time_remaining:.0f}s remaining), skipping to next event"
                    )
                    # Find next event after current_event
                    current_index = sorted_events.index(current_event)
                    if current_index + 1 < len(sorted_events):
                        best_event = sorted_events[current_index + 1]
                        ev_start = best_event.wall_clock_start(ast)
                        logger.info(
                            f"Magenta2: adjusting to next event '{best_event.title}' "
                            f"(start={ev_start.isoformat()})"
                        )
                        return rewriter.rewrite_for_event(
                            mpd_content, extracted, best_event,
                            keep_other_events=False,
                            force_static_if_ended=False,
                        )
                    else:
                        # No next event, use buffer offset
                        logger.info("Magenta2: no next event available, using buffer offset")
                        return rewriter.rewrite_by_buffer_offset(mpd_content, extracted, requested_dt)
                else:
                    # Join current event in progress (has substantial time remaining)
                    logger.info(
                        f"Magenta2: joining in-progress event '{current_event.title}' "
                        f"({time_remaining:.0f}s remaining)"
                    )
                    return rewriter.rewrite_for_event(
                        mpd_content, extracted, current_event,
                        keep_other_events=False,
                        force_static_if_ended=False,
                    )

            # Find the first event that starts AT OR AFTER requested time (upcoming show)
            best_event = None
            for ev in sorted_events:
                ev_start = ev.wall_clock_start(ast)
                if ev_start >= requested_dt:
                    best_event = ev
                    break

            # If no upcoming event (requested time is after all events), take the last event
            if best_event is None and sorted_events:
                best_event = sorted_events[-1]
                logger.info(
                    f"Magenta2: requested time after all events, using last event "
                    f"'{best_event.title}'"
                )

            if best_event:
                ev_start = best_event.wall_clock_start(ast)
                diff = (ev_start - requested_dt).total_seconds()

                # If the gap is very large (> threshold), consider buffer offset instead
                if abs(diff) <= _EVENT_MATCH_THRESHOLD_S:
                    logger.info(
                        f"Magenta2: adjusting to event '{best_event.title}' "
                        f"(start={ev_start.isoformat()}, diff={diff:.0f}s from requested)"
                    )
                    return rewriter.rewrite_for_event(
                        mpd_content, extracted, best_event,
                        keep_other_events=False,
                        force_static_if_ended=False,
                    )
                else:
                    logger.info(
                        f"Magenta2: event match diff ({diff:.0f}s) exceeds threshold "
                        f"({_EVENT_MATCH_THRESHOLD_S}s), using buffer offset"
                    )
                    return rewriter.rewrite_by_buffer_offset(mpd_content, extracted, requested_dt)

            # No suitable event found - use buffer offset
            logger.info(f"Magenta2: no suitable event found for {requested_dt.isoformat()}, using buffer offset")
            return rewriter.rewrite_by_buffer_offset(mpd_content, extracted, requested_dt)

        except ValueError as e:
            logger.warning(f"Magenta2: cannot parse events ({e}), using buffer offset")
            try:
                extracted = rewriter.extract_events(mpd_content)
                return rewriter.rewrite_by_buffer_offset(mpd_content, extracted, requested_dt)
            except ValueError:
                logger.error("Magenta2: MPD has no availabilityStartTime")
                return mpd_content
        except Exception as e:
            logger.error(f"Magenta2: adjustment failed: {e}")
            return mpd_content