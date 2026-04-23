"""
MP4 PSSH Extractor

Extracts PSSH boxes and Key IDs from MP4 segments using the refactored DRM models.
"""

import struct
from typing import Dict, List, Optional

from ..models.drm import PSSHData, TencParser, PSSHParser
from ..models.drm.exceptions import InvalidPSSHError, InvalidTencError
from .logger import logger


class MP4PSSHExtractor:
    """
    Extract PSSH boxes and Key IDs from MP4 segments.

    Uses the refactored DRM models for proper parsing and validation.
    """

    @staticmethod
    def extract_from_url(
            segment_url: str,
            timeout: int = 10,
            headers: Optional[Dict[str, str]] = None,
            http_manager=None,
    ) -> List[PSSHData]:
        """
        Download MP4 segment and extract PSSH data.

        Args:
            segment_url: URL of the MP4 segment
            timeout: Request timeout in seconds
            headers: Optional HTTP headers to include in the request.
                     Providers that require authentication on segment requests
                     (e.g. Authorization, X-Custom-Token) should supply these
                     via StreamingProvider.get_segment_headers().
            http_manager: Optional http manager to use for HTTP requests

        Returns:
            List of PSSHData objects with extracted information
        """
        try:
            if http_manager is not None:
                response = http_manager.get(segment_url, headers=headers or {}, timeout=timeout, operation="api")
            else:
                import requests
                response = requests.get(segment_url, timeout=timeout, headers=headers or {})
            response.raise_for_status()
            data = response.content[:1024 * 100]
            return MP4PSSHExtractor.extract_from_bytes(data)

        except Exception as e:
            logger.error(f"Failed to extract PSSH from {segment_url}: {e}")
            return []

    @staticmethod
    def extract_from_bytes(data: bytes) -> List[PSSHData]:
        """
        Extract PSSH boxes and encryption info from MP4 binary data.

        Optimized Process:
        1. Extract all PSSH boxes and parse them
        2. Only extract tenc KIDs if any PSSH needs fallback
        3. Merge tenc KIDs with PSSH data where needed

        Args:
            data: Raw MP4 binary data

        Returns:
            List of PSSHData objects with complete information
        """
        pssh_data_list = []
        offset = 0

        # First pass: Extract PSSH boxes
        while offset < len(data):
            try:
                # Read box size (4 bytes, big-endian)
                if offset + 8 > len(data):
                    break

                box_size = struct.unpack(">I", data[offset: offset + 4])[0]

                # Handle special box sizes
                if box_size == 0:
                    box_size = len(data) - offset  # Box extends to end
                elif box_size == 1:
                    # Extended size (64-bit) - skip for now
                    break

                if offset + box_size > len(data):
                    break

                # Read box type (4 bytes)
                box_type = data[offset + 4: offset + 8]

                if box_type == b"moov":
                    # Look for PSSH in moov container
                    moov_data = data[offset: offset + box_size]
                    pssh_in_moov = MP4PSSHExtractor._extract_from_moov(moov_data)
                    pssh_data_list.extend(pssh_in_moov)

                elif box_type == b"pssh":
                    # Found standalone PSSH box
                    pssh_box = MP4PSSHExtractor._parse_pssh_box(
                        data[offset: offset + box_size]
                    )
                    if pssh_box:
                        pssh_data_list.append(pssh_box)

                offset += box_size

            except Exception as e:
                logger.debug(f"Error parsing MP4 box at offset {offset}: {e}")
                offset += 1  # Try to recover

        # Second pass: Only extract tenc if any PSSH needs fallback
        needs_tenc = any(pssh_data.needs_tenc_fallback() for pssh_data in pssh_data_list)

        if needs_tenc:
            logger.debug("PSSH missing KIDs - extracting from tenc boxes as fallback")
            tenc_kids = MP4PSSHExtractor._extract_all_tenc_kids(data)

            if tenc_kids:
                logger.debug(f"Extracted {len(tenc_kids)} KIDs from tenc boxes")

                # Add tenc KIDs to PSSH boxes that need them
                for pssh_data in pssh_data_list:
                    if pssh_data.needs_tenc_fallback():
                        logger.debug(
                            f"Adding {len(tenc_kids)} tenc KIDs to {pssh_data.drm_system} PSSH"
                        )
                        pssh_data.add_key_ids(tenc_kids)
            else:
                logger.warning("PSSH needs KIDs but no tenc boxes found")
        else:
            logger.debug(
                f"All {len(pssh_data_list)} PSSH box(es) have KIDs from payload - skipping tenc extraction"
            )

        return pssh_data_list

    @staticmethod
    def _extract_all_tenc_kids(data: bytes) -> List[str]:
        """
        Extract all Key IDs from tenc boxes in the MP4 data.

        Uses TencParser for proper tenc box parsing.

        Args:
            data: Raw MP4 binary data

        Returns:
            List of normalized Key IDs (32 hex chars, no hyphens)
        """
        kids = []
        offset = 0

        while offset < len(data):
            try:
                if offset + 8 > len(data):
                    break

                box_size = struct.unpack(">I", data[offset: offset + 4])[0]
                box_type = data[offset + 4: offset + 8]

                if box_size < 8 or offset + box_size > len(data):
                    offset += 1
                    continue

                if box_type == b"tenc":
                    # Extract tenc box data
                    tenc_data = data[offset: offset + box_size]

                    # Use TencParser for proper parsing
                    try:
                        tenc_kids = TencParser.extract_kids_from_tenc(tenc_data)
                        for kid in tenc_kids:
                            if kid not in kids:
                                kids.append(kid)
                                logger.debug(f"Extracted KID from tenc: {kid[:8]}...")
                    except InvalidTencError as e:
                        logger.debug(f"Invalid tenc box at offset {offset}: {e}")

                elif box_size > 8:
                    # Recursively search container boxes
                    container_boxes = {
                        b"moov", b"trak", b"mdia", b"minf",
                        b"stbl", b"stsd", b"encv", b"enca",
                        b"sinf", b"schi"
                    }
                    if box_type in container_boxes:
                        # Search inside container
                        inner_data = data[offset + 8: offset + box_size]
                        inner_kids = MP4PSSHExtractor._extract_all_tenc_kids(inner_data)
                        for kid in inner_kids:
                            if kid not in kids:
                                kids.append(kid)

                offset += box_size

            except Exception as e:
                logger.debug(f"Error at offset {offset}: {e}")
                offset += 1

        return kids

    @staticmethod
    def _extract_from_moov(moov_data: bytes) -> List[PSSHData]:
        """
        Extract PSSH boxes from moov container.

        Args:
            moov_data: Raw moov box data

        Returns:
            List of PSSHData objects found in moov
        """
        pssh_list = []
        offset = 8  # Skip moov header

        while offset < len(moov_data):
            try:
                if offset + 8 > len(moov_data):
                    break

                box_size = struct.unpack(">I", moov_data[offset: offset + 4])[0]
                box_type = moov_data[offset + 4: offset + 8]

                if box_size < 8 or offset + box_size > len(moov_data):
                    break

                if box_type == b"trak":
                    # Parse track for PSSH
                    trak_data = moov_data[offset: offset + box_size]
                    pssh_in_trak = MP4PSSHExtractor._extract_from_trak(trak_data)
                    pssh_list.extend(pssh_in_trak)

                elif box_type == b"pssh":
                    # PSSH directly in moov
                    pssh_box = MP4PSSHExtractor._parse_pssh_box(
                        moov_data[offset: offset + box_size]
                    )
                    if pssh_box:
                        pssh_list.append(pssh_box)

                offset += box_size

            except Exception as e:
                logger.debug(f"Error parsing moov box at offset {offset}: {e}")
                break

        return pssh_list

    @staticmethod
    def _extract_from_trak(trak_data: bytes) -> List[PSSHData]:
        """Extract PSSH from trak box"""
        pssh_list = []
        offset = 8

        while offset < len(trak_data):
            try:
                if offset + 8 > len(trak_data):
                    break

                box_size = struct.unpack(">I", trak_data[offset: offset + 4])[0]
                box_type = trak_data[offset + 4: offset + 8]

                if box_size < 8 or offset + box_size > len(trak_data):
                    break

                if box_type == b"mdia":
                    mdia_data = trak_data[offset: offset + box_size]
                    pssh_in_mdia = MP4PSSHExtractor._extract_from_mdia(mdia_data)
                    pssh_list.extend(pssh_in_mdia)

                offset += box_size

            except Exception:
                break

        return pssh_list

    @staticmethod
    def _extract_from_mdia(mdia_data: bytes) -> List[PSSHData]:
        """Extract PSSH from mdia box"""
        pssh_list = []
        offset = 8

        while offset < len(mdia_data):
            try:
                if offset + 8 > len(mdia_data):
                    break

                box_size = struct.unpack(">I", mdia_data[offset: offset + 4])[0]
                box_type = mdia_data[offset + 4: offset + 8]

                if box_size < 8 or offset + box_size > len(mdia_data):
                    break

                if box_type == b"minf":
                    minf_data = mdia_data[offset: offset + box_size]
                    pssh_in_minf = MP4PSSHExtractor._extract_from_minf(minf_data)
                    pssh_list.extend(pssh_in_minf)

                offset += box_size

            except Exception:
                break

        return pssh_list

    @staticmethod
    def _extract_from_minf(minf_data: bytes) -> List[PSSHData]:
        """Extract PSSH from minf box"""
        pssh_list = []
        offset = 8

        while offset < len(minf_data):
            try:
                if offset + 8 > len(minf_data):
                    break

                box_size = struct.unpack(">I", minf_data[offset: offset + 4])[0]
                box_type = minf_data[offset + 4: offset + 8]

                if box_size < 8 or offset + box_size > len(minf_data):
                    break

                if box_type == b"stbl":
                    stbl_data = minf_data[offset: offset + box_size]
                    pssh_in_stbl = MP4PSSHExtractor._extract_from_stbl(stbl_data)
                    pssh_list.extend(pssh_in_stbl)

                offset += box_size

            except Exception:
                break

        return pssh_list

    @staticmethod
    def _extract_from_stbl(stbl_data: bytes) -> List[PSSHData]:
        """Extract PSSH from stbl box (where protection scheme info usually is)"""
        pssh_list = []
        offset = 8

        while offset < len(stbl_data):
            try:
                if offset + 8 > len(stbl_data):
                    break

                box_size = struct.unpack(">I", stbl_data[offset: offset + 4])[0]
                box_type = stbl_data[offset + 4: offset + 8]

                if box_size < 8 or offset + box_size > len(stbl_data):
                    break

                if box_type == b"sinf":
                    sinf_data = stbl_data[offset: offset + box_size]
                    pssh_in_sinf = MP4PSSHExtractor._extract_from_sinf(sinf_data)
                    pssh_list.extend(pssh_in_sinf)

                offset += box_size

            except Exception:
                break

        return pssh_list

    @staticmethod
    def _extract_from_sinf(sinf_data: bytes) -> List[PSSHData]:
        """Extract PSSH from sinf (protection scheme information) box"""
        pssh_list = []
        offset = 8

        while offset < len(sinf_data):
            try:
                if offset + 8 > len(sinf_data):
                    break

                box_size = struct.unpack(">I", sinf_data[offset: offset + 4])[0]
                box_type = sinf_data[offset + 4: offset + 8]

                if box_size < 8 or offset + box_size > len(sinf_data):
                    break

                if box_type == b"schi":
                    schi_data = sinf_data[offset: offset + box_size]
                    pssh_in_schi = MP4PSSHExtractor._extract_from_schi(schi_data)
                    pssh_list.extend(pssh_in_schi)

                offset += box_size

            except Exception:
                break

        return pssh_list

    @staticmethod
    def _extract_from_schi(schi_data: bytes) -> List[PSSHData]:
        """Extract PSSH from schi box (where PSSH boxes are typically stored)"""
        pssh_list = []
        offset = 8

        while offset < len(schi_data):
            try:
                if offset + 8 > len(schi_data):
                    break

                box_size = struct.unpack(">I", schi_data[offset: offset + 4])[0]
                box_type = schi_data[offset + 4: offset + 8]

                if box_size < 8 or offset + box_size > len(schi_data):
                    break

                if box_type == b"pssh":
                    pssh_box = MP4PSSHExtractor._parse_pssh_box(
                        schi_data[offset: offset + box_size]
                    )
                    if pssh_box:
                        pssh_list.append(pssh_box)

                offset += box_size

            except Exception:
                break

        return pssh_list

    @staticmethod
    def _parse_pssh_box(pssh_bytes: bytes) -> Optional[PSSHData]:
        """
        Parse PSSH box and create PSSHData object.

        Uses PSSHParser for proper parsing and validation.

        Args:
            pssh_bytes: Raw PSSH box bytes

        Returns:
            PSSHData object or None if parsing fails
        """
        try:
            # Basic validation
            if len(pssh_bytes) < 32:
                logger.debug(f"PSSH box too small: {len(pssh_bytes)} bytes")
                return None

            box_type = pssh_bytes[4:8]
            if box_type != b"pssh":
                logger.debug(f"Not a PSSH box: {box_type}")
                return None

            # Encode entire PSSH box as base64
            from ..models.drm.utils import safe_base64_encode
            pssh_b64 = safe_base64_encode(pssh_bytes)

            # Parse PSSH to get system_id and metadata
            try:
                metadata = PSSHParser.parse_pssh_box(pssh_b64)
            except InvalidPSSHError as e:
                logger.debug(f"Failed to parse PSSH: {e}")
                return None

            # Create PSSHData with parsed information
            pssh_data = PSSHData(
                system_id=metadata["system_id"],
                pssh_box=pssh_b64,
                key_ids=metadata["key_ids"],
                source="mp4_segment",
            )

            # Log what we found with source information
            drm_name = pssh_data.drm_system.name if pssh_data.drm_system else "UNKNOWN"
            kid_count = len(pssh_data.key_ids)
            version = metadata["version"]

            # Determine source of KIDs
            if version > 0 and kid_count > 0:
                source = "v1+ header"
            elif version == 0 and kid_count > 0:
                source = "v0 payload"
            else:
                source = "none (will need tenc)"

            logger.debug(
                f"Parsed PSSH: {drm_name} v{version} with {kid_count} KIDs from {source}"
            )

            return pssh_data

        except Exception as e:
            logger.debug(f"Failed to parse PSSH box: {e}")
            return None