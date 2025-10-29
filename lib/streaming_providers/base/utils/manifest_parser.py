import re
import base64
from ..models.drm_models import PSSHData
from .logger import logger

class ManifestParser:
    @staticmethod
    def extract_pssh_from_manifest(manifest_content: str, manifest_url: str = "", return_collection: bool = True):
        logger.debug("Starting PSSH extraction from manifest")
        
        # Check if this looks like a DASH manifest
        is_dash = ('<MPD' in manifest_content) or ('mpd' in manifest_content.lower())
        logger.debug(f"Manifest appears to be DASH format: {is_dash}")
        
        if not is_dash:
            logger.debug("Not a DASH manifest, skipping PSSH extraction")
            return []
        
        try:
            pssh_list = ManifestParser._extract_with_regex(manifest_content)
            logger.debug(f"Found {len(pssh_list)} potential PSSH entries")
            
            valid_pssh = []
            for pssh in pssh_list:
                if pssh.pssh_box and pssh.system_id:
                    valid_pssh.append(pssh)
                    logger.debug(f"Valid PSSH found - System ID: {pssh.system_id}")
                else:
                    logger.debug("Invalid PSSH entry skipped")
            
            return valid_pssh
            
        except Exception as e:
            logger.error(f"Error in PSSH extraction: {str(e)}")
            return []

    @staticmethod
    def _extract_with_regex(mpd_content: str):
        """Simplified PSSH extraction using regular expressions with debug logging"""
        logger.debug("Starting regex PSSH extraction")
        
        pssh_dict = {}  # Use dict to automatically handle deduplication
        global_key_ids = []  # Collect all KIDs from the manifest
        
        # Regex patterns
        pssh_pattern = r'<(?:cenc:)?pssh[^>]*>([^<]+)</(?:cenc:)?pssh>'
        default_kid_pattern = r'(?:cenc:)?default_KID="([^"]+)"'
        system_id_pattern = r'schemeIdUri="urn:uuid:([^"]+)"'
        
        logger.debug("Searching for ContentProtection blocks")
        cp_blocks = re.findall(r'<ContentProtection[^>]*>.*?</ContentProtection>', mpd_content, re.DOTALL)
        logger.debug(f"Found {len(cp_blocks)} ContentProtection blocks")
        
        # First pass: collect all default KIDs from the entire manifest
        for block in cp_blocks:
            kid_match = re.search(default_kid_pattern, block)
            if kid_match:
                clean_kid = kid_match.group(1).replace("-", "").lower()
                if clean_kid not in global_key_ids:
                    global_key_ids.append(clean_kid)
                    logger.debug(f"Found global default KID: {clean_kid}")
        
        # Second pass: extract PSSH data
        for i, block in enumerate(cp_blocks, 1):
            try:
                logger.debug(f"Processing block {i}/{len(cp_blocks)}")
                system_id = None
                
                # Extract system ID from schemeIdUri
                scheme_match = re.search(system_id_pattern, block)
                if scheme_match:
                    system_id = scheme_match.group(1).lower()
                    logger.debug(f"Found system ID in schemeIdUri: {system_id}")
                
                # Extract PSSH data
                pssh_matches = re.findall(pssh_pattern, block)
                logger.debug(f"Found {len(pssh_matches)} PSSH elements in block")
                
                for pssh_b64 in pssh_matches:
                    try:
                        logger.debug(f"Processing PSSH (first 30 chars): {pssh_b64[:30]}...")
                        pssh_data = base64.b64decode(pssh_b64)
                        
                        if len(pssh_data) >= 28:
                            # Extract system ID from PSSH if not found in schemeIdUri
                            if not system_id:
                                system_id_bytes = pssh_data[12:28]
                                system_id = '-'.join([
                                    system_id_bytes[0:4].hex(),
                                    system_id_bytes[4:6].hex(),
                                    system_id_bytes[6:8].hex(),
                                    system_id_bytes[8:10].hex(),
                                    system_id_bytes[10:16].hex()
                                ])
                                logger.debug(f"Extracted system ID from PSSH: {system_id}")
                            
                            # Use PSSH box as key for deduplication
                            if pssh_b64 not in pssh_dict:
                                pssh_dict[pssh_b64] = PSSHData(
                                    system_id=system_id,
                                    pssh_box=pssh_b64,
                                    key_ids=global_key_ids.copy()  # Add all global KIDs to each PSSH
                                )
                                logger.debug("Successfully added new PSSH entry")
                            else:
                                logger.debug("PSSH already exists, skipping duplicate")
                            
                    except Exception as e:
                        logger.error(f"Error decoding PSSH: {str(e)}")
                        
            except Exception as e:
                logger.error(f"Error processing ContentProtection block: {str(e)}")
        
        pssh_list = list(pssh_dict.values())
        logger.debug(f"Completed PSSH extraction, found {len(pssh_list)} unique entries")
        return pssh_list
