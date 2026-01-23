import base64
import re
from typing import List, Optional
from urllib.parse import quote, urljoin, urlparse

from ..models.drm_models import DRMSystem, PSSHData
from .logger import logger


class ManifestParser:
    @staticmethod
    def extract_pssh_from_manifest(
        manifest_content: str,
        manifest_url: str = "",
        fallback_to_segments: bool = True,
        segment_urls: List[str] = None,
    ) -> List[PSSHData]:
        """
        DEPRECATED: Use extract_single_init_segment_url instead.
        Kept for backwards compatibility.
        """
        pssh_list = ManifestParser._extract_from_manifest_content(manifest_content)

        if fallback_to_segments and segment_urls:
            incomplete_pssh = [p for p in pssh_list if not p.pssh_box or not p.key_ids]
            if incomplete_pssh:
                segment_pssh = ManifestParser._extract_from_single_segment(
                    segment_urls[0], [p.system_id for p in incomplete_pssh]
                )
                return ManifestParser._merge_pssh_data(pssh_list, segment_pssh)

        return pssh_list

    @staticmethod
    def _extract_from_manifest_content(manifest_content: str) -> List[PSSHData]:
        """Extract PSSH and DRM systems from manifest content"""
        # Try regex extraction first (handles PSSH boxes with KIDs)
        pssh_list = ManifestParser._extract_with_regex(manifest_content)
        if pssh_list:
            return pssh_list

        # Fallback: extract DRM systems from schemeIdUri only
        drm_systems_found = set()
        result = []

        # More efficient: compile regex once
        cp_pattern = re.compile(
            r'<ContentProtection[^>]*schemeIdUri="urn:uuid:([^"]+)"[^>]*>',
            re.IGNORECASE,
        )

        for match in cp_pattern.finditer(manifest_content):
            system_id = match.group(1).lower()

            # Skip mp4protection scheme
            if (
                "mp4protection"
                in manifest_content[max(0, match.start() - 100) : match.start()]
            ):
                continue

            drm_system = DRMSystem.from_uuid(system_id)
            if drm_system and system_id not in drm_systems_found:
                drm_systems_found.add(system_id)
                result.append(
                    PSSHData(
                        system_id=system_id,
                        pssh_box="",  # Empty - PSSH in segments
                        key_ids=[],
                        source="manifest_scheme_only",
                    )
                )
                logger.debug(f"Found DRM system from schemeIdUri: {drm_system.value}")

        return result

    @staticmethod
    def _extract_from_single_segment(
        segment_url: str, expected_system_ids: List[str] = None
    ) -> List[PSSHData]:
        """Extract PSSH from a single MP4 segment"""
        from .mp4_parser import MP4PSSHExtractor

        try:
            pssh_from_segment = MP4PSSHExtractor.extract_from_url(segment_url)

            # Filter for expected DRM systems if provided
            if expected_system_ids:
                filtered_pssh = [
                    p for p in pssh_from_segment if p.system_id in expected_system_ids
                ]
                if filtered_pssh:
                    logger.debug(f"Found {len(filtered_pssh)} PSSH boxes in segment")
                    return filtered_pssh
            elif pssh_from_segment:
                logger.debug(f"Found {len(pssh_from_segment)} PSSH boxes in segment")
                return pssh_from_segment

        except Exception as e:
            logger.warning(f"Failed to extract PSSH from segment: {e}")

        return []

    @staticmethod
    def _merge_pssh_data(
        manifest_pssh: List[PSSHData], segment_pssh: List[PSSHData]
    ) -> List[PSSHData]:
        """Merge manifest and segment PSSH data"""
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
        """Extract PSSH boxes using regex"""
        pssh_dict = {}
        global_key_ids = []

        # Compile patterns once
        pssh_pattern = re.compile(r"<(?:cenc:)?pssh[^>]*>([^<]+)</(?:cenc:)?pssh>")
        default_kid_pattern = re.compile(
            r'(?:cenc:)?default_KID="([^"]+)"', re.IGNORECASE
        )
        system_id_pattern = re.compile(r'schemeIdUri="urn:uuid:([^"]+)"', re.IGNORECASE)

        # Find ContentProtection blocks efficiently
        cp_blocks = re.findall(
            r"<ContentProtection[^>]*>.*?</ContentProtection>", mpd_content, re.DOTALL
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
                                system_id = "-".join(
                                    [
                                        system_id_bytes[0:4].hex(),
                                        system_id_bytes[4:6].hex(),
                                        system_id_bytes[6:8].hex(),
                                        system_id_bytes[8:10].hex(),
                                        system_id_bytes[10:16].hex(),
                                    ]
                                )

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

    @staticmethod
    def extract_single_init_segment_url(
        manifest_content: str, manifest_url: str
    ) -> Optional[str]:
        """
        Extract ONE init segment URL from DASH manifest.
        Prioritizes video representations as they typically have the same DRM as audio.
        """
        # Parse manifest base URL
        parsed = urlparse(manifest_url)
        manifest_base = (
            f"{parsed.scheme}://{parsed.netloc}{'/'.join(parsed.path.split('/')[:-1])}"
        )
        if not manifest_base.endswith("/"):
            manifest_base += "/"

        # Extract BaseURL elements (can appear at multiple levels)
        base_urls = re.findall(r"<BaseURL[^>]*>([^<]+)</BaseURL>", manifest_content)

        # Build effective base URL
        effective_base = manifest_base
        for base_url in base_urls:
            if base_url.startswith("http"):
                effective_base = base_url
            else:
                effective_base = urljoin(effective_base, base_url)

        if not effective_base.endswith("/"):
            effective_base += "/"

        logger.debug(f"Effective base URL: {effective_base}")

        # Find SegmentTemplate with initialization attribute
        # Prioritize video AdaptationSets
        adaptation_sets = re.findall(
            r"<AdaptationSet[^>]*>.*?</AdaptationSet>", manifest_content, re.DOTALL
        )

        video_sets = []
        audio_sets = []

        for ad_set in adaptation_sets:
            if 'contentType="video"' in ad_set or 'mimeType="video/' in ad_set:
                video_sets.append(ad_set)
            elif 'contentType="audio"' in ad_set or 'mimeType="audio/' in ad_set:
                audio_sets.append(ad_set)

        # Try video first, then audio
        target_sets = video_sets + audio_sets

        for ad_set in target_sets:
            # Find SegmentTemplate initialization
            seg_template_match = re.search(
                r'<SegmentTemplate[^>]*initialization="([^"]+)"', ad_set, re.IGNORECASE
            )

            if not seg_template_match:
                continue

            init_template = seg_template_match.group(1)
            logger.debug(f"Found init template: {init_template}")

            # Find first Representation in this AdaptationSet
            rep_match = re.search(r'<Representation[^>]*id="([^"]+)"', ad_set)
            if not rep_match:
                continue

            rep_id = rep_match.group(1)
            logger.debug(f"Using Representation ID: {rep_id}")

            # Substitute template variables
            init_url = init_template.replace("$RepresentationID$", rep_id)

            # Handle other common template variables
            init_url = init_url.replace("$Bandwidth$", "0")
            init_url = init_url.replace("$Time$", "0")
            init_url = init_url.replace("$Number$", "1")

            # Construct full URL
            if init_url.startswith("http"):
                full_url = init_url
            else:
                # URL encode special characters in representation ID
                # Split path and encode only the filename part
                path_parts = init_url.split("/")
                path_parts[-1] = quote(path_parts[-1], safe=".-_")
                init_url = "/".join(path_parts)

                full_url = urljoin(effective_base, init_url)

            logger.info(f"Constructed init segment URL: {full_url}")
            return full_url

        logger.warning("Could not find init segment URL in manifest")
        return None

    @staticmethod
    def extract_segment_urls(manifest_content: str, manifest_url: str) -> List[str]:
        """
        DEPRECATED: Use extract_single_init_segment_url instead.
        This extracts ALL segments which is inefficient.
        """
        logger.warning(
            "extract_segment_urls is deprecated, use extract_single_init_segment_url"
        )
        init_url = ManifestParser.extract_single_init_segment_url(
            manifest_content, manifest_url
        )
        return [init_url] if init_url else []

    @staticmethod
    def extract_init_segment_urls(
        manifest_content: str, manifest_url: str
    ) -> List[str]:
        """
        DEPRECATED: Use extract_single_init_segment_url instead.
        """
        logger.warning(
            "extract_init_segment_urls is deprecated, use extract_single_init_segment_url"
        )
        init_url = ManifestParser.extract_single_init_segment_url(
            manifest_content, manifest_url
        )
        return [init_url] if init_url else []
