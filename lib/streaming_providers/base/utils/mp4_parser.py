import base64
import struct
import uuid
from typing import List, Optional

from ..models.drm_models import PSSHData
from .logger import logger


class MP4PSSHExtractor:
    """Extract PSSH boxes and key IDs from MP4 segments"""

    @staticmethod
    def extract_from_url(segment_url: str, timeout: int = 10) -> List[PSSHData]:
        """Download MP4 segment and extract PSSH data"""
        import requests

        try:
            response = requests.get(segment_url, timeout=timeout)
            response.raise_for_status()

            # Only download first ~100KB for efficiency
            chunk_size = 1024 * 100
            data = response.content[:chunk_size]

            return MP4PSSHExtractor.extract_from_bytes(data)

        except Exception as e:
            logger.error(f"Failed to extract PSSH from {segment_url}: {e}")
            return []

    @staticmethod
    def extract_from_bytes(data: bytes) -> List[PSSHData]:
        """Extract PSSH boxes and encryption info from MP4 binary data"""
        pssh_data_list = []
        offset = 0

        # First, extract all tenc boxes to get default KIDs
        tenc_kids = MP4PSSHExtractor._extract_tenc_kids(data)

        while offset < len(data):
            try:
                # Read box size (4 bytes, big-endian)
                if offset + 4 > len(data):
                    break

                box_size = struct.unpack(">I", data[offset: offset + 4])[0]
                if box_size == 0:
                    box_size = len(data) - offset  # Box extends to end of file
                elif box_size == 1:
                    # Extended size (skip for now - rare in practice)
                    break

                if offset + box_size > len(data):
                    break

                # Read box type (4 bytes)
                box_type = data[offset + 4: offset + 8].decode("ascii", errors="ignore")

                if box_type == "moov":
                    # Look for PSSH in moov box
                    moov_data = data[offset: offset + box_size]
                    pssh_in_moov = MP4PSSHExtractor._extract_from_moov(moov_data)

                    # Enhance PSSH data with tenc KIDs if needed
                    for pssh in pssh_in_moov:
                        if not pssh.key_ids and tenc_kids:
                            pssh.key_ids = tenc_kids.copy()
                    pssh_data_list.extend(pssh_in_moov)

                elif box_type == "pssh":
                    # Found standalone PSSH box
                    pssh_box = MP4PSSHExtractor._parse_pssh_box(data[offset: offset + box_size])
                    if pssh_box:
                        # Add tenc KIDs if PSSH doesn't have its own
                        if not pssh_box.key_ids and tenc_kids:
                            pssh_box.key_ids = tenc_kids.copy()
                        pssh_data_list.append(pssh_box)

                offset += box_size

            except Exception as e:
                logger.debug(f"Error parsing MP4 box at offset {offset}: {e}")
                offset += 1  # Try to recover

        return pssh_data_list

    @staticmethod
    def _extract_tenc_kids(data: bytes) -> List[str]:
        """Extract default KIDs from all tenc boxes in the MP4 data"""
        kids = []
        offset = 0

        while offset < len(data):
            try:
                if offset + 8 > len(data):
                    break

                box_size = struct.unpack(">I", data[offset:offset + 4])[0]
                if box_size < 8:
                    offset += 1
                    continue

                box_type = data[offset + 4:offset + 8]

                if box_type == b'tenc':
                    # Parse tenc box
                    tenc_kid = MP4PSSHExtractor._parse_tenc_box(data[offset:offset + box_size])
                    if tenc_kid:
                        kids.append(tenc_kid)

                offset += box_size
            except:
                offset += 1

        return kids

    @staticmethod
    def _parse_tenc_box(tenc_bytes: bytes) -> Optional[str]:
        """Parse a tenc box and extract the default key ID"""
        try:
            if len(tenc_bytes) < 32:
                return None

            # tenc box structure:
            # 0-3: box size (4 bytes)
            # 4-7: box type 'tenc' (4 bytes)
            # 8: version (1 byte)
            # 9-11: flags (3 bytes)
            # 12: reserved (24 bits) + is_encrypted (1 bit)
            # 13: default_iv_size (1 byte)
            # 14-29: default_KID (16 bytes)

            # Check if box is long enough
            if len(tenc_bytes) < 30:
                return None

            # Skip to default_KID (offset 14 from start of box)
            kid_start = 14

            if kid_start + 16 > len(tenc_bytes):
                return None

            kid_bytes = tenc_bytes[kid_start:kid_start + 16]
            kid_uuid = str(uuid.UUID(bytes=kid_bytes))

            # Convert to lowercase without dashes (same format as PSSH KIDs)
            clean_kid = kid_uuid.replace("-", "").lower()

            logger.debug(f"Found KID from tenc box: {clean_kid}")
            return clean_kid

        except Exception as e:
            logger.debug(f"Failed to parse tenc box: {e}")
            return None

    @staticmethod
    def _extract_from_moov(moov_data: bytes) -> List[PSSHData]:
        """Extract PSSH boxes from moov container"""
        pssh_list = []
        offset = 8  # Skip moov header

        # First extract tenc KIDs from this moov
        tenc_kids = MP4PSSHExtractor._extract_tenc_kids(moov_data)

        while offset < len(moov_data):
            try:
                box_size = struct.unpack(">I", moov_data[offset: offset + 4])[0]
                box_type = moov_data[offset + 4: offset + 8].decode("ascii", errors="ignore")

                if box_type == "trak":
                    # Parse track for PSSH
                    trak_data = moov_data[offset: offset + box_size]
                    pssh_in_trak = MP4PSSHExtractor._extract_from_trak(trak_data)

                    # Add tenc KIDs to PSSH boxes if needed
                    for pssh in pssh_in_trak:
                        if not pssh.key_ids and tenc_kids:
                            pssh.key_ids = tenc_kids.copy()
                    pssh_list.extend(pssh_in_trak)

                elif box_type == "pssh":
                    # PSSH directly in moov
                    pssh_box = MP4PSSHExtractor._parse_pssh_box(
                        moov_data[offset: offset + box_size]
                    )
                    if pssh_box:
                        # Add tenc KIDs if PSSH doesn't have its own
                        if not pssh_box.key_ids and tenc_kids:
                            pssh_box.key_ids = tenc_kids.copy()
                        pssh_list.append(pssh_box)

                offset += box_size

            except:
                break

        return pssh_list

    @staticmethod
    def _extract_from_trak(trak_data: bytes) -> List[PSSHData]:
        """Extract PSSH from trak box"""
        pssh_list = []
        offset = 8

        while offset < len(trak_data):
            try:
                box_size = struct.unpack(">I", trak_data[offset: offset + 4])[0]
                box_type = trak_data[offset + 4: offset + 8].decode("ascii", errors="ignore")

                if box_type == "mdia":
                    mdia_data = trak_data[offset: offset + box_size]
                    pssh_in_mdia = MP4PSSHExtractor._extract_from_mdia(mdia_data)
                    pssh_list.extend(pssh_in_mdia)

                offset += box_size

            except:
                break

        return pssh_list

    @staticmethod
    def _extract_from_mdia(mdia_data: bytes) -> List[PSSHData]:
        """Extract PSSH from mdia box"""
        pssh_list = []
        offset = 8

        while offset < len(mdia_data):
            try:
                box_size = struct.unpack(">I", mdia_data[offset: offset + 4])[0]
                box_type = mdia_data[offset + 4: offset + 8].decode("ascii", errors="ignore")

                if box_type == "minf":
                    minf_data = mdia_data[offset: offset + box_size]
                    pssh_in_minf = MP4PSSHExtractor._extract_from_minf(minf_data)
                    pssh_list.extend(pssh_in_minf)

                offset += box_size

            except:
                break

        return pssh_list

    @staticmethod
    def _extract_from_minf(minf_data: bytes) -> List[PSSHData]:
        """Extract PSSH from minf box"""
        pssh_list = []
        offset = 8

        while offset < len(minf_data):
            try:
                box_size = struct.unpack(">I", minf_data[offset: offset + 4])[0]
                box_type = minf_data[offset + 4: offset + 8].decode("ascii", errors="ignore")

                if box_type == "stbl":
                    stbl_data = minf_data[offset: offset + box_size]
                    pssh_in_stbl = MP4PSSHExtractor._extract_from_stbl(stbl_data)
                    pssh_list.extend(pssh_in_stbl)

                offset += box_size

            except:
                break

        return pssh_list

    @staticmethod
    def _extract_from_stbl(stbl_data: bytes) -> List[PSSHData]:
        """Extract PSSH from stbl box (where protection scheme info usually is)"""
        pssh_list = []
        offset = 8

        while offset < len(stbl_data):
            try:
                box_size = struct.unpack(">I", stbl_data[offset: offset + 4])[0]
                box_type = stbl_data[offset + 4: offset + 8].decode("ascii", errors="ignore")

                if box_type == "sinf":
                    sinf_data = stbl_data[offset: offset + box_size]
                    pssh_in_sinf = MP4PSSHExtractor._extract_from_sinf(sinf_data)
                    pssh_list.extend(pssh_in_sinf)

                elif box_type == "tenc":
                    # Direct tenc box in stbl (unusual but possible)
                    tenc_kid = MP4PSSHExtractor._parse_tenc_box(
                        stbl_data[offset:offset + box_size]
                    )
                    if tenc_kid:
                        # If we have existing PSSH boxes without KIDs, add this KID
                        for pssh in pssh_list:
                            if not pssh.key_ids:
                                pssh.key_ids.append(tenc_kid)

                offset += box_size

            except:
                break

        return pssh_list

    @staticmethod
    def _extract_from_sinf(sinf_data: bytes) -> List[PSSHData]:
        """Extract PSSH from sinf (protection scheme information) box"""
        pssh_list = []
        offset = 8

        while offset < len(sinf_data):
            try:
                box_size = struct.unpack(">I", sinf_data[offset: offset + 4])[0]
                box_type = sinf_data[offset + 4: offset + 8].decode("ascii", errors="ignore")

                if box_type == "schi":
                    schi_data = sinf_data[offset: offset + box_size]
                    pssh_in_schi = MP4PSSHExtractor._extract_from_schi(schi_data)
                    pssh_list.extend(pssh_in_schi)

                elif box_type == "tenc":
                    # tenc box directly in sinf
                    tenc_kid = MP4PSSHExtractor._parse_tenc_box(
                        sinf_data[offset:offset + box_size]
                    )
                    if tenc_kid:
                        # If we have existing PSSH boxes without KIDs, add this KID
                        for pssh in pssh_list:
                            if not pssh.key_ids:
                                pssh.key_ids.append(tenc_kid)

                offset += box_size

            except:
                break

        return pssh_list

    @staticmethod
    def _extract_from_schi(schi_data: bytes) -> List[PSSHData]:
        """Extract PSSH from schi box (where PSSH boxes are typically stored)"""
        pssh_list = []
        offset = 8

        while offset < len(schi_data):
            try:
                box_size = struct.unpack(">I", schi_data[offset: offset + 4])[0]
                box_type = schi_data[offset + 4: offset + 8].decode("ascii", errors="ignore")

                if box_type == "pssh":
                    pssh_box = MP4PSSHExtractor._parse_pssh_box(
                        schi_data[offset: offset + box_size]
                    )
                    if pssh_box:
                        pssh_list.append(pssh_box)

                elif box_type == "tenc":
                    # tenc box in schi (common structure)
                    tenc_kid = MP4PSSHExtractor._parse_tenc_box(
                        schi_data[offset:offset + box_size]
                    )
                    if tenc_kid:
                        # If we have existing PSSH boxes without KIDs, add this KID
                        for pssh in pssh_list:
                            if not pssh.key_ids:
                                pssh.key_ids.append(tenc_kid)

                offset += box_size

            except:
                break

        return pssh_list

    @staticmethod
    def _parse_pssh_box(pssh_bytes: bytes) -> Optional[PSSHData]:
        """Parse a PSSH box and extract system_id, pssh_box, and key_ids"""
        try:
            if len(pssh_bytes) < 32:  # Minimum size for PSSH box
                return None

            # Parse box header
            box_size = struct.unpack(">I", pssh_bytes[0:4])[0]
            box_type = pssh_bytes[4:8].decode("ascii")

            if box_type != "pssh":
                return None

            version = pssh_bytes[8]
            flags = struct.unpack(">I", b"\x00" + pssh_bytes[9:12])[0]

            # Extract system ID (bytes 12-28)
            system_id_bytes = pssh_bytes[12:28]
            system_id = str(uuid.UUID(bytes=system_id_bytes))

            # Extract key IDs (if version > 0)
            key_ids = []
            current_offset = 28

            if version > 0:
                # Read KID count
                if current_offset + 4 > len(pssh_bytes):
                    return None

                kid_count = struct.unpack(">I", pssh_bytes[current_offset: current_offset + 4])[0]
                current_offset += 4

                # Read each KID
                for _ in range(kid_count):
                    if current_offset + 16 > len(pssh_bytes):
                        break

                    kid_bytes = pssh_bytes[current_offset: current_offset + 16]
                    kid_uuid = str(uuid.UUID(bytes=kid_bytes))
                    key_ids.append(kid_uuid.replace("-", "").lower())
                    current_offset += 16
            else:
                logger.debug(f"Version 0 PSSH for system {system_id}, will look for KIDs in tenc box")

            # Encode entire PSSH box as base64
            pssh_b64 = base64.b64encode(pssh_bytes[:box_size]).decode("ascii")

            return PSSHData(
                system_id=system_id,
                pssh_box=pssh_b64,
                key_ids=key_ids,
                source="mp4_segment",
            )

        except Exception as e:
            logger.debug(f"Failed to parse PSSH box: {e}")
            return None