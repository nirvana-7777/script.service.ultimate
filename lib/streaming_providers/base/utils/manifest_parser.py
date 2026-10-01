# streaming_providers/base/utils/manifest_parser.py
"""
DASH manifest parser for extracting init and media segment URLs.
For PSSH/DRM extraction, use drm_extractor module.
"""

from typing import Optional, List
from urllib.parse import urlsplit, urlunsplit

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
    # URL helpers: auth-token (query string) inheritance and log redaction
    # ========================================================================

    @staticmethod
    def inherit_query_string(manifest_url: str, segment_url: str) -> str:
        """Append the manifest URL's query string to a constructed segment URL.

        Query-string token CDNs (Akamai 'hdnts', '?token=...', ...) authenticate
        EVERY request, but RFC 3986 relative-reference resolution does not
        inherit query strings, so a manifest fetched as
            https://host/50114/manifest.mpd?hdnts=st=...~exp=...~acl=*/50114/*~...
        yields token-less segment URLs that the edge rejects with 403. When the
        token's ACL covers the segment paths (as above), repeating the
        manifest's query on segment requests is exactly what the CDN expects.

        Deliberately conservative:
          - manifest has no query        -> nothing to inherit
          - segment already has a query  -> keep it (the template/BaseURL
            supplied its own auth; merging could duplicate/conflict tokens)
          - different authority          -> keep it (foreign hosts carry
            their own authentication; never leak this token to them)

        The query is passed through verbatim (no re-encoding of ~, *, ...).
        """
        if not manifest_url or not segment_url:
            return segment_url
        try:
            base = urlsplit(manifest_url)
            if not base.query:
                return segment_url
            seg = urlsplit(segment_url)
            if seg.query or seg.netloc.lower() != base.netloc.lower():
                return segment_url
            merged = urlunsplit(
                (seg.scheme, seg.netloc, seg.path, base.query, seg.fragment)
            )
            logger.debug(
                f"Inherited manifest query string onto segment URL: "
                f"{ManifestParser.redact_url(merged)}"
            )
            return merged
        except (ValueError, AttributeError):
            return segment_url

    @staticmethod
    def redact_url(url: Optional[str]) -> Optional[str]:
        """Mask query-string VALUES for logging (keeps parameter names).

        Segment URLs now carry the manifest's auth token; it must not end up
        in log files. Use this for every log line that prints a URL which may
        have a query string.
        """
        if not url:
            return url
        try:
            parts = urlsplit(url)
        except ValueError:
            return url
        if not parts.query:
            return url
        names = [pair.split("=", 1)[0] for pair in parts.query.split("&") if pair]
        redacted = "&".join(f"{name}=<redacted>" for name in names)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, redacted, ""))

    # ========================================================================
    # Segment URL Extraction (Primary Purpose)
    # ========================================================================

    @staticmethod
    def extract_single_init_segment_url(
            manifest_content: str,
            manifest_url: str,
            inherit_query: bool = True,
    ) -> Optional[str]:
        """
        Extract ONE init segment URL from DASH manifest.
        Prioritizes video representations as they typically have the same DRM as audio.

        Args:
            manifest_content: Full manifest XML content
            manifest_url: URL where the manifest was fetched from. Pass the
                FINAL (post-redirect) URL when known: relative segment paths
                resolve against it, and its query string is inherited.
            inherit_query: append the manifest URL's query string (auth
                token) to the constructed segment URL; see
                inherit_query_string for the exact rules.

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

                if inherit_query:
                    full_url = ManifestParser.inherit_query_string(manifest_url, full_url)

                logger.info(
                    f"Constructed init segment URL (SegmentTemplate): "
                    f"{ManifestParser.redact_url(full_url)}"
                )
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

                if inherit_query:
                    full_url = ManifestParser.inherit_query_string(manifest_url, full_url)

                log_url = ManifestParser.redact_url(full_url)
                if init_range:
                    logger.info(
                        f"Constructed init segment URL (SegmentBase): {log_url} "
                        f"[Range: bytes={init_range}]"
                    )
                else:
                    logger.info(
                        f"Constructed init segment URL (SegmentBase, no range): {log_url}"
                    )

                return full_url

        logger.warning("Could not find init segment URL in manifest")
        return None

    @staticmethod
    def extract_media_segment_url(
            manifest_content: str,
            manifest_url: str,
            inherit_query: bool = True,
    ) -> Optional[str]:
        """
        Extract the URL of ONE media segment from a DASH manifest.

        Counterpart to extract_single_init_segment_url(), used as a PSSH
        fallback for providers that put the pssh box in the moof of each media
        segment instead of the manifest or the init segment.

        The segment is taken from the MIDDLE of the SegmentTimeline, not the
        first entry: in a live manifest the first entry sits at the very edge
        of the time-shift window and is typically evicted (404) by the time it
        is requested.

        Only SegmentTemplate manifests are supported (SegmentBase has no
        separate media segments). Template variables are resolved as follows:
          $RepresentationID$  first Representation ID of the AdaptationSet
          $Bandwidth$         bandwidth of the first Representation
          $Time$              start time of the chosen SegmentTimeline entry (else 0)
          $Number$            startNumber + index of the chosen entry (else startNumber, default 1)
        Templates with format specifiers (e.g. $Number%05d$) are not resolved
        and are skipped rather than requested with a broken URL.

        Args:
            manifest_content: Full manifest XML content
            manifest_url: URL where the manifest was fetched from. Pass the
                FINAL (post-redirect) URL when known: relative segment paths
                resolve against it, and its query string is inherited.
            inherit_query: append the manifest URL's query string (auth
                token) to the constructed segment URL; see
                inherit_query_string for the exact rules.

        Returns:
            Full URL to the chosen media segment, or None if not found
        """
        base_urls = ManifestUtils.extract_base_urls(manifest_content)
        effective_base = URLResolver.build_effective_base_url(manifest_url, base_urls)

        adaptation_sets = ManifestUtils.parse_adaptation_sets(manifest_content)
        video_sets, audio_sets = ManifestUtils.separate_video_audio_sets(adaptation_sets)

        # Try video first, then audio (same order as the init segment lookup)
        for ad_set_info in video_sets + audio_sets:
            media_template = ManifestUtils.extract_segment_template_media(
                ad_set_info.content
            )
            if not media_template:
                continue

            logger.debug(f"Found media template: {media_template}")

            rep_id = ManifestUtils.extract_first_representation_id(ad_set_info.content)
            if not rep_id:
                logger.debug("No Representation ID found in AdaptationSet")
                continue

            bandwidth = ManifestUtils.extract_first_representation_bandwidth(
                ad_set_info.content
            ) or "0"
            segment_time, segment_index = (
                ManifestUtils.extract_segment_timeline_position(ad_set_info.content)
                or (0, 0)
            )
            start_number = int(
                ManifestUtils.extract_segment_template_start_number(ad_set_info.content)
                or 1
            )

            media_url = URLResolver.substitute_template_variables(
                media_template,
                representation_id=rep_id,
                bandwidth=bandwidth,
                time=str(segment_time),
                number=str(start_number + segment_index)
            )

            if "$" in media_url:
                logger.debug(f"Unresolved template variables in media URL: {media_url}")
                continue

            full_url = URLResolver.construct_full_url(
                effective_base,
                media_url,
                url_encode_filename=True
            )

            if inherit_query:
                full_url = ManifestParser.inherit_query_string(manifest_url, full_url)

            logger.info(
                f"Constructed media segment URL (SegmentTemplate): "
                f"{ManifestParser.redact_url(full_url)}"
            )
            return full_url

        logger.debug("Could not find media segment URL in manifest")
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