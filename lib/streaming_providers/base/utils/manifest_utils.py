# streaming_providers/base/utils/manifest_utils.py
"""
Utilities for parsing DASH manifest structure.
Extracts AdaptationSets, Representations, and other manifest elements.
"""

import re
from typing import List, Tuple, Optional
from dataclasses import dataclass

@dataclass
class AdaptationSetInfo:
    """Information about a parsed AdaptationSet."""
    content: str  # Raw XML content
    content_type: str  # "video", "audio", or "unknown"
    mime_type: str
    is_video: bool
    is_audio: bool


class ManifestUtils:
    """Utilities for parsing DASH manifest structure."""

    @staticmethod
    def parse_adaptation_sets(manifest_content: str) -> List[AdaptationSetInfo]:
        """
        Parse all AdaptationSets from manifest content.

        Args:
            manifest_content: Full manifest XML content

        Returns:
            List of AdaptationSetInfo objects
        """
        adaptation_sets = []

        # Find all AdaptationSet blocks
        ad_set_pattern = re.compile(
            r"<AdaptationSet[^>]*>.*?</AdaptationSet>",
            re.DOTALL
        )

        for match in ad_set_pattern.finditer(manifest_content):
            ad_set_content = match.group(0)

            # Extract content type and mime type
            content_type = ManifestUtils._extract_content_type(ad_set_content)
            mime_type = ManifestUtils._extract_mime_type(ad_set_content)

            is_video = content_type == "video" or mime_type.startswith("video/")
            is_audio = content_type == "audio" or mime_type.startswith("audio/")

            adaptation_sets.append(AdaptationSetInfo(
                content=ad_set_content,
                content_type=content_type,
                mime_type=mime_type,
                is_video=is_video,
                is_audio=is_audio
            ))

        return adaptation_sets

    @staticmethod
    def separate_video_audio_sets(
            adaptation_sets: List[AdaptationSetInfo]
    ) -> Tuple[List[AdaptationSetInfo], List[AdaptationSetInfo]]:
        """
        Separate adaptation sets into video and audio lists.

        Args:
            adaptation_sets: List of parsed AdaptationSets

        Returns:
            Tuple of (video_sets, audio_sets)
        """
        video_sets = [ad_set for ad_set in adaptation_sets if ad_set.is_video]
        audio_sets = [ad_set for ad_set in adaptation_sets if ad_set.is_audio]

        return video_sets, audio_sets

    @staticmethod
    def _extract_content_type(ad_set_content: str) -> str:
        """Extract contentType attribute from AdaptationSet."""
        match = re.search(r'contentType="([^"]+)"', ad_set_content)
        return match.group(1) if match else "unknown"

    @staticmethod
    def _extract_mime_type(ad_set_content: str) -> str:
        """Extract mimeType attribute from AdaptationSet or Representation."""
        # Try AdaptationSet level first
        match = re.search(r'<AdaptationSet[^>]*mimeType="([^"]+)"', ad_set_content)
        if match:
            return match.group(1)

        # Try Representation level
        match = re.search(r'<Representation[^>]*mimeType="([^"]+)"', ad_set_content)
        return match.group(1) if match else ""

    @staticmethod
    def extract_first_representation_id(ad_set_content: str) -> Optional[str]:
        """
        Extract the ID of the first Representation in an AdaptationSet.

        Args:
            ad_set_content: AdaptationSet XML content

        Returns:
            Representation ID or None if not found
        """
        match = re.search(r'<Representation[^>]*id="([^"]+)"', ad_set_content)
        return match.group(1) if match else None

    @staticmethod
    def extract_segment_template_initialization(ad_set_content: str) -> Optional[str]:
        """
        Extract initialization attribute from SegmentTemplate.

        Args:
            ad_set_content: AdaptationSet XML content

        Returns:
            Initialization template string or None if not found
        """
        match = re.search(
            r'<SegmentTemplate[^>]*initialization="([^"]+)"',
            ad_set_content,
            re.IGNORECASE
        )
        return match.group(1) if match else None

    @staticmethod
    def extract_base_urls(manifest_content: str) -> List[str]:
        """
        Extract all BaseURL elements from manifest.

        Args:
            manifest_content: Full manifest XML content

        Returns:
            List of BaseURL text contents
        """
        return re.findall(r"<BaseURL[^>]*>([^<]+)</BaseURL>", manifest_content)