# streaming_providers/base/utils/manifest_parser.py
"""
DASH manifest parser for extracting init segment URLs.
For PSSH/DRM extraction, use drm_extractor module.
"""

from typing import Optional, List

from .logger import logger
from .url_resolver import URLResolver
from .manifest_utils import ManifestUtils


class ManifestParser:
    """Parser for DASH manifests focused on segment URL extraction."""

    # ========================================================================
    # Backwards Compatibility: DRM Methods (Delegate to DRMExtractor)
    # ========================================================================
    # These methods are kept for backwards compatibility with code that calls
    # ManifestParser._extract_from_manifest_content() etc.
    # They simply delegate to DRMExtractor.

    @staticmethod
    def _extract_from_manifest_content(manifest_content: str):
        """
        DEPRECATED: Use DRMExtractor._extract_from_manifest_content() instead.
        Kept for backwards compatibility.
        """
        from .drm_extractor import DRMExtractor
        return DRMExtractor._extract_from_manifest_content(manifest_content)

    @staticmethod
    def _extract_from_single_segment(segment_url: str, expected_system_ids: List[str] = None):
        """
        DEPRECATED: Use DRMExtractor._extract_from_single_segment() instead.
        Kept for backwards compatibility.
        """
        from .drm_extractor import DRMExtractor
        return DRMExtractor._extract_from_single_segment(segment_url, expected_system_ids)

    @staticmethod
    def _merge_pssh_data(manifest_pssh: List, segment_pssh: List):
        """
        DEPRECATED: Use DRMExtractor._merge_pssh_data() instead.
        Kept for backwards compatibility.
        """
        from .drm_extractor import DRMExtractor
        return DRMExtractor._merge_pssh_data(manifest_pssh, segment_pssh)

    # ========================================================================
    # Segment URL Extraction (Primary Purpose)
    # ========================================================================

    @staticmethod
    def extract_single_init_segment_url(
            manifest_content: str,
            manifest_url: str
    ) -> Optional[str]:
        """
        Extract ONE init segment URL from DASH manifest.
        Prioritizes video representations as they typically have the same DRM as audio.

        Args:
            manifest_content: Full manifest XML content
            manifest_url: URL where the manifest was fetched from

        Returns:
            Full URL to an initialization segment, or None if not found
        """
        # Build effective base URL from manifest URL and MPD/Period-level BaseURL
        # elements only (Representation-level BaseURLs are relative media paths,
        # not base URLs, and are intentionally excluded by extract_base_urls).
        base_urls = ManifestUtils.extract_base_urls(manifest_content)
        effective_base = URLResolver.build_effective_base_url(manifest_url, base_urls)

        logger.debug(f"Effective base URL: {effective_base}")

        # Parse all adaptation sets
        adaptation_sets = ManifestUtils.parse_adaptation_sets(manifest_content)
        video_sets, audio_sets = ManifestUtils.separate_video_audio_sets(adaptation_sets)

        # Try video first, then audio
        target_sets = video_sets + audio_sets

        for ad_set_info in target_sets:
            # ------------------------------------------------------------------
            # Branch A: SegmentTemplate-based manifest (most live/VOD streams)
            # The init segment URL is expressed as a template attribute.
            # ------------------------------------------------------------------
            init_template = ManifestUtils.extract_segment_template_initialization(
                ad_set_info.content
            )

            if init_template:
                logger.debug(f"Found init template: {init_template}")

                # Get first Representation ID from this AdaptationSet
                rep_id = ManifestUtils.extract_first_representation_id(ad_set_info.content)

                if not rep_id:
                    logger.debug("No Representation ID found in AdaptationSet")
                    continue

                logger.debug(f"Using Representation ID: {rep_id}")

                # Substitute template variables with defaults
                init_url = URLResolver.substitute_template_variables(
                    init_template,
                    representation_id=rep_id,
                    bandwidth="0",
                    time="0",
                    number="1"
                )

                # Construct full URL
                full_url = URLResolver.construct_full_url(
                    effective_base,
                    init_url,
                    url_encode_filename=True
                )

                logger.info(f"Constructed init segment URL (SegmentTemplate): {full_url}")
                return full_url

            # ------------------------------------------------------------------
            # Branch B: SegmentBase manifest (on-demand, single-file MP4)
            # Each Representation has a <BaseURL> pointing to the full MP4 file.
            # The init segment is the same file, accessed via HTTP Range using
            # the range from <Initialization range="start-end"/>.
            # We return the bare MP4 URL; the caller is responsible for issuing
            # an appropriate Range request if it wants only the init bytes.
            # ------------------------------------------------------------------
            segment_base_url = ManifestUtils.extract_segment_base_url(ad_set_info.content)

            if segment_base_url:
                init_range = ManifestUtils.extract_segment_base_init_range(ad_set_info.content)

                full_url = URLResolver.construct_full_url(
                    effective_base,
                    segment_base_url,
                    url_encode_filename=False  # path is already a clean relative URL
                )

                if init_range:
                    logger.info(
                        f"Constructed init segment URL (SegmentBase): {full_url} "
                        f"[Range: bytes={init_range}]"
                    )
                else:
                    logger.info(
                        f"Constructed init segment URL (SegmentBase, no range): {full_url}"
                    )

                return full_url

        logger.warning("Could not find init segment URL in manifest")
        return None

    @staticmethod
    def extract_segment_urls(manifest_content: str, manifest_url: str) -> List[str]:
        """
        DEPRECATED: Use extract_single_init_segment_url instead.
        This extracts ALL segments which is inefficient.

        This method is kept for backwards compatibility only.
        """
        logger.warning(
            "extract_segment_urls is deprecated, use extract_single_init_segment_url"
        )
        init_url = ManifestParser.extract_single_init_segment_url(
            manifest_content, manifest_url
        )
        return [init_url] if init_url else []

    @staticmethod
    def extract_init_segment_urls(manifest_content: str, manifest_url: str) -> List[str]:
        """
        DEPRECATED: Use extract_single_init_segment_url instead.

        This method is kept for backwards compatibility only.
        """
        logger.warning(
            "extract_init_segment_urls is deprecated, use extract_single_init_segment_url"
        )
        init_url = ManifestParser.extract_single_init_segment_url(
            manifest_content, manifest_url
        )
        return [init_url] if init_url else []