# streaming_providers/base/utils/video_quality.py
from dataclasses import dataclass
from typing import Optional, Tuple, List
import xml.etree.ElementTree as ET
from .logger import logger


@dataclass
class VideoRepresentation:
    """Represents a video representation with its quality metrics."""
    element: ET.Element
    adaptation_set: ET.Element
    period: ET.Element
    bandwidth: int
    width: Optional[int] = None
    height: Optional[int] = None
    frame_rate: Optional[float] = None
    representation_id: str = ""
    period_id: str = ""
    as_id: str = ""

    def get_quality_score(self) -> Tuple[int, int, int]:
        """
        Returns a tuple for comparison: (resolution_pixels, bandwidth, frame_rate_score)
        Higher values = better quality
        """
        resolution = (self.width or 0) * (self.height or 0)
        frame_rate_score = int((self.frame_rate or 0) * 100)
        return resolution, self.bandwidth, frame_rate_score


class VideoQualityFilter:
    """Handles video quality filtering and highest quality selection."""

    NAMESPACE = {"mpd": "urn:mpeg:dash:schema:mpd:2011"}

    @staticmethod
    def is_video_adaptation_set(adaptation_set: ET.Element) -> bool:
        """Determine if an AdaptationSet is video based on mimeType or contentType."""
        mime_type = adaptation_set.get("mimeType", "")
        content_type = adaptation_set.get("contentType", "")

        # Check AdaptationSet level
        if mime_type.startswith("video/") or content_type == "video":
            return True

        # Check Representation level if not specified at AdaptationSet level
        for representation in adaptation_set.findall("mpd:Representation", VideoQualityFilter.NAMESPACE):
            rep_mime = representation.get("mimeType", "")
            if rep_mime.startswith("video/"):
                return True

        return False

    @staticmethod
    def parse_video_representation(
            representation: ET.Element,
            adaptation_set: ET.Element,
            period: ET.Element,
            period_id: str,
            as_id: str
    ) -> Optional[VideoRepresentation]:
        """Parse a Representation element and extract video quality information."""
        try:
            # Bandwidth is required
            bandwidth = int(representation.get("bandwidth", "0"))
            if bandwidth == 0:
                return None

            # Width and height (can be on Representation or AdaptationSet)
            width = representation.get("width") or adaptation_set.get("width")
            height = representation.get("height") or adaptation_set.get("height")

            width = int(width) if width else None
            height = int(height) if height else None

            # Frame rate (can be on Representation or AdaptationSet)
            frame_rate_str = representation.get("frameRate") or adaptation_set.get("frameRate")
            frame_rate = None
            if frame_rate_str:
                # Handle both "30" and "30000/1001" formats
                if "/" in frame_rate_str:
                    num, denom = frame_rate_str.split("/")
                    frame_rate = float(num) / float(denom)
                else:
                    frame_rate = float(frame_rate_str)

            representation_id = representation.get("id", "")

            return VideoRepresentation(
                element=representation,
                adaptation_set=adaptation_set,
                period=period,
                bandwidth=bandwidth,
                width=width,
                height=height,
                frame_rate=frame_rate,
                representation_id=representation_id,
                period_id=period_id,
                as_id=as_id
            )
        except (ValueError, AttributeError) as e:
            logger.warning(f"Failed to parse video representation: {e}")
            return None

    @classmethod
    def find_best_video(cls, root: ET.Element) -> Optional[VideoRepresentation]:
        """Find the highest quality video representation across all periods."""
        all_video_reps: List[VideoRepresentation] = []

        # Scan all periods and adaptation sets to find video representations
        for period in root.findall(".//mpd:Period", cls.NAMESPACE):
            period_id = period.get("id", "")

            for adaptation_set in period.findall("mpd:AdaptationSet", cls.NAMESPACE):
                if not cls.is_video_adaptation_set(adaptation_set):
                    continue

                as_id = adaptation_set.get("id", str(id(adaptation_set)))

                # Collect all representations from this video adaptation set
                for representation in adaptation_set.findall("mpd:Representation", cls.NAMESPACE):
                    video_rep = cls.parse_video_representation(
                        representation, adaptation_set, period, period_id, as_id
                    )
                    if video_rep:
                        all_video_reps.append(video_rep)

        if not all_video_reps:
            logger.warning("No video representations found for filtering")
            return None

        best_video = max(all_video_reps, key=lambda v: v.get_quality_score())
        logger.debug(
            f"Found {len(all_video_reps)} video representations, "
            f"best: {best_video.width}x{best_video.height} @ {best_video.bandwidth}bps"
        )

        return best_video