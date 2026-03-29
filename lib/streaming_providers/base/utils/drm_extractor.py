# streaming_providers/base/utils/drm_extractor.py
"""
DRM-specific extraction utilities for PSSH boxes and key IDs from manifests and segments.
Separated from general manifest parsing to maintain clear separation of concerns.
"""

import base64
import re
from typing import Dict, List, Optional

from ..models.drm import PSSHData
from .logger import logger


class DRMExtractor:
    """Extracts PSSH boxes and DRM information from manifests and segments."""

    @staticmethod
    def extract_pssh_from_manifest(
            manifest_content: str,
            manifest_url: str = "",
            fallback_to_segments: bool = True,
            segment_urls: List[str] = None,
    ) -> List[PSSHData]:
        """
        Extract PSSH data from DASH manifest content.

        DEPRECATED: Use extract_single_init_segment_url from ManifestParser
        and then extract from that segment instead.
        Kept for backwards compatibility.

        Args:
            manifest_content: Full manifest XML content
            manifest_url: URL of the manifest (unused, kept for compatibility)
            fallback_to_segments: Whether to extract from segments if manifest incomplete
            segment_urls: List of segment URLs to try if fallback enabled

        Returns:
            List of PSSHData objects found
        """
        pssh_list = DRMExtractor._extract_from_manifest_content(manifest_content)

        if fallback_to_segments and segment_urls:
            incomplete_pssh = [p for p in pssh_list if not p.pssh_box or not p.key_ids]
            if incomplete_pssh:
                # No headers available in this deprecated path — callers that need
                # auth on segment requests should use _extract_from_single_segment directly.
                segment_pssh = DRMExtractor._extract_from_single_segment(
                    segment_urls[0], [p.system_id for p in incomplete_pssh]
                )
                return DRMExtractor._merge_pssh_data(pssh_list, segment_pssh)

        return pssh_list

    @staticmethod
    def _extract_from_manifest_content(manifest_content: str) -> List[PSSHData]:
        """Extract PSSH and DRM systems from manifest content."""
        # Try regex extraction first
        pssh_list = DRMExtractor._extract_with_regex(manifest_content)
        if pssh_list:
            return pssh_list

        # Fallback: extract DRM systems from schemeIdUri only
        drm_systems_found = set()
        result = []

        cp_pattern = re.compile(
            r'<ContentProtection[^>]*schemeIdUri="urn:uuid:([^"]+)"[^>]*>',
            re.IGNORECASE,
        )

        for match in cp_pattern.finditer(manifest_content):
            system_id = match.group(1).lower()

            # Skip mp4protection
            if "mp4protection" in manifest_content[max(0, match.start() - 100):match.start()]:
                continue

            # Let PSSHData handle normalization
            pssh_data = PSSHData(
                system_id=system_id,
                pssh_box="",
                key_ids=[],
                source="manifest_scheme_only",
            )

            if pssh_data.drm_system and system_id not in drm_systems_found:
                drm_systems_found.add(pssh_data.system_id)  # Use normalized ID
                result.append(pssh_data)
                logger.debug(f"Found DRM system: {pssh_data.drm_system.value}")

        return result

    @staticmethod
    def _extract_from_single_segment(
            segment_url: str,
            expected_system_ids: List[str] = None,
            headers: Optional[Dict[str, str]] = None,
    ) -> List[PSSHData]:
        """
        Extract PSSH from a single segment URL.

        Args:
            segment_url: URL of the init segment to fetch
            expected_system_ids: If provided, filter results to these DRM system IDs.
                                 Falls back to returning all PSSH if no matches found.
            headers: HTTP headers to use when fetching the segment (e.g. Authorization).
                     Providers that require auth on segment requests should supply these
                     via StreamingProvider.get_segment_headers().
        """
        from .mp4_pssh_extractor import MP4PSSHExtractor

        try:
            pssh_from_segment = MP4PSSHExtractor.extract_from_url(
                segment_url,
                headers=headers or {},
            )

            if expected_system_ids:
                # Normalize expected IDs using the model
                normalized_expected = []
                for sys_id in expected_system_ids:
                    # Create temporary PSSHData to leverage its normalization
                    temp = PSSHData(system_id=sys_id, source="filter")
                    normalized_expected.append(temp.system_id)

                filtered_pssh = [
                    p for p in pssh_from_segment
                    if p.system_id in normalized_expected
                ]

                if filtered_pssh:
                    return filtered_pssh
                else:
                    # If filtering produced no matches, return all segment PSSH
                    logger.debug(
                        f"Filtering by expected_system_ids produced no matches, "
                        f"returning all {len(pssh_from_segment)} PSSH from segment"
                    )
                    return pssh_from_segment

            # No filtering requested, return all segment PSSH
            return pssh_from_segment

        except Exception as e:
            logger.warning(f"Failed to extract PSSH from segment: {e}")

        return []

    @staticmethod
    def _merge_pssh_data(
            manifest_pssh: List[PSSHData],
            segment_pssh: List[PSSHData]
    ) -> List[PSSHData]:
        """
        Merge manifest and segment PSSH data.
        Prefer segment data as it's typically more complete.
        """
        if not manifest_pssh:
            return segment_pssh
        if not segment_pssh:
            return manifest_pssh

        merged = []
        segment_by_system = {p.system_id: p for p in segment_pssh}

        for manifest_p in manifest_pssh:
            if manifest_p.system_id in segment_by_system:
                # Use segment data (complete)
                merged.append(segment_by_system[manifest_p.system_id])
            else:
                # Keep manifest data (incomplete)
                merged.append(manifest_p)

        return merged

    @staticmethod
    def _extract_with_regex(mpd_content: str) -> List[PSSHData]:
        """Extract PSSH boxes using regex."""
        pssh_dict = {}
        global_key_ids = []

        # Compile patterns
        pssh_pattern = re.compile(r"<(?:cenc:)?pssh[^>]*>([^<]+)</(?:cenc:)?pssh>")
        default_kid_pattern = re.compile(
            r'(?:cenc:)?default_KID="([^"]+)"', re.IGNORECASE
        )
        system_id_pattern = re.compile(r'schemeIdUri="urn:uuid:([^"]+)"', re.IGNORECASE)

        # Find ContentProtection blocks
        cp_blocks = re.findall(
            r"<ContentProtection[^>]*>.*?</ContentProtection>",
            mpd_content,
            re.DOTALL
        )

        # First pass: collect all default KIDs
        for block in cp_blocks:
            kid_match = default_kid_pattern.search(block)
            if kid_match:
                clean_kid = kid_match.group(1).replace("-", "").lower()
                if clean_kid not in global_key_ids:
                    global_key_ids.append(clean_kid)

        # Second pass: extract PSSH data
        for block in cp_blocks:
            try:
                system_id = None

                # Extract system ID from schemeIdUri
                scheme_match = system_id_pattern.search(block)
                if scheme_match:
                    system_id = scheme_match.group(1).lower()

                # Extract PSSH data
                for pssh_match in pssh_pattern.finditer(block):
                    pssh_b64 = pssh_match.group(1)
                    try:
                        pssh_data = base64.b64decode(pssh_b64)

                        if len(pssh_data) >= 28:
                            # Extract system ID from PSSH if not found
                            if not system_id:
                                system_id_bytes = pssh_data[12:28]
                                system_id = "-".join([
                                    system_id_bytes[0:4].hex(),
                                    system_id_bytes[4:6].hex(),
                                    system_id_bytes[6:8].hex(),
                                    system_id_bytes[8:10].hex(),
                                    system_id_bytes[10:16].hex(),
                                ])

                            # Deduplicate by PSSH box content
                            if pssh_b64 not in pssh_dict:
                                pssh_dict[pssh_b64] = PSSHData(
                                    system_id=system_id,
                                    pssh_box=pssh_b64,
                                    key_ids=global_key_ids.copy(),
                                    source="manifest_pssh",
                                )

                    except Exception as e:
                        logger.debug(f"Error decoding PSSH: {e}")

            except Exception as e:
                logger.debug(f"Error processing ContentProtection block: {e}")

        return list(pssh_dict.values())