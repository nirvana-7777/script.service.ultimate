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
        """Extract PSSH boxes from MP4 binary data"""
        pssh_data_list = []
        offset = 0

        while offset < len(data):
            try:
                # Read box size (4 bytes, big-endian)
                if offset + 4 > len(data):
                    break

                box_size = struct.unpack(">I", data[offset : offset + 4])[0]
                if box_size == 0:
                    box_size = len(data) - offset  # Box extends to end of file
                elif box_size == 1:
                    # Extended size (skip for now - rare in practice)
                    break

                if offset + box_size > len(data):
                    break

                # Read box type (4 bytes)
                box_type = data[offset + 4 : offset + 8].decode("ascii", errors="ignore")

                if box_type == "moov":
                    # Look for PSSH in moov box
                    moov_data = data[offset : offset + box_size]
                    pssh_in_moov = MP4PSSHExtractor._extract_from_moov(moov_data)
                    pssh_data_list.extend(pssh_in_moov)

                elif box_type == "pssh":
                    # Found standalone PSSH box
                    pssh_box = MP4PSSHExtractor._parse_pssh_box(data[offset : offset + box_size])
                    if pssh_box:
                        pssh_data_list.append(pssh_box)

                offset += box_size

            except Exception as e:
                logger.debug(f"Error parsing MP4 box at offset {offset}: {e}")
                offset += 1  # Try to recover

        return pssh_data_list

    @staticmethod
    def _extract_from_moov(moov_data: bytes) -> List[PSSHData]:
        """Extract PSSH boxes from moov container"""
        pssh_list = []
        offset = 8  # Skip moov header

        while offset < len(moov_data):
            try:
                box_size = struct.unpack(">I", moov_data[offset : offset + 4])[0]
                box_type = moov_data[offset + 4 : offset + 8].decode("ascii", errors="ignore")

                if box_type == "trak":
                    # Parse track for PSSH
                    trak_data = moov_data[offset : offset + box_size]
                    pssh_in_trak = MP4PSSHExtractor._extract_from_trak(trak_data)
                    pssh_list.extend(pssh_in_trak)

                elif box_type == "pssh":
                    # PSSH directly in moov
                    pssh_box = MP4PSSHExtractor._parse_pssh_box(
                        moov_data[offset : offset + box_size]
                    )
                    if pssh_box:
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
                box_size = struct.unpack(">I", trak_data[offset : offset + 4])[0]
                box_type = trak_data[offset + 4 : offset + 8].decode("ascii", errors="ignore")

                if box_type == "mdia":
                    mdia_data = trak_data[offset : offset + box_size]
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
                box_size = struct.unpack(">I", mdia_data[offset : offset + 4])[0]
                box_type = mdia_data[offset + 4 : offset + 8].decode("ascii", errors="ignore")

                if box_type == "minf":
                    minf_data = mdia_data[offset : offset + box_size]
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
                box_size = struct.unpack(">I", minf_data[offset : offset + 4])[0]
                box_type = minf_data[offset + 4 : offset + 8].decode("ascii", errors="ignore")

                if box_type == "stbl":
                    stbl_data = minf_data[offset : offset + box_size]
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
                box_size = struct.unpack(">I", stbl_data[offset : offset + 4])[0]
                box_type = stbl_data[offset + 4 : offset + 8].decode("ascii", errors="ignore")

                if box_type == "sinf":
                    sinf_data = stbl_data[offset : offset + box_size]
                    pssh_in_sinf = MP4PSSHExtractor._extract_from_sinf(sinf_data)
                    pssh_list.extend(pssh_in_sinf)

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
                box_size = struct.unpack(">I", sinf_data[offset : offset + 4])[0]
                box_type = sinf_data[offset + 4 : offset + 8].decode("ascii", errors="ignore")

                if box_type == "schi":
                    schi_data = sinf_data[offset : offset + box_size]
                    pssh_in_schi = MP4PSSHExtractor._extract_from_schi(schi_data)
                    pssh_list.extend(pssh_in_schi)

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
                box_size = struct.unpack(">I", schi_data[offset : offset + 4])[0]
                box_type = schi_data[offset + 4 : offset + 8].decode("ascii", errors="ignore")

                if box_type == "pssh":
                    pssh_box = MP4PSSHExtractor._parse_pssh_box(
                        schi_data[offset : offset + box_size]
                    )
                    if pssh_box:
                        pssh_list.append(pssh_box)

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

                kid_count = struct.unpack(">I", pssh_bytes[current_offset : current_offset + 4])[0]
                current_offset += 4

                # Read each KID
                for _ in range(kid_count):
                    if current_offset + 16 > len(pssh_bytes):
                        break

                    kid_bytes = pssh_bytes[current_offset : current_offset + 16]
                    kid_uuid = str(uuid.UUID(bytes=kid_bytes))
                    key_ids.append(kid_uuid.replace("-", "").lower())
                    current_offset += 16

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
