# streaming_providers/base/utils/mpd_rewriter.py
import base64
import xml.etree.ElementTree as ET
import re
from typing import Optional, Tuple, Set, Dict
from urllib.parse import urljoin, urlparse, quote, urlencode
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from dataclasses import dataclass, field

from .logger import logger

# Pre-compile regex for ISO duration parsing at module level
ISO_8601_PERIOD_RE = re.compile(
    r"P(?:(?P<years>\d+)Y)?(?:(?P<months>\d+)M)?(?:(?P<weeks>\d+)W)?(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+(?:\.\d+)?)S)?)?"
)


@dataclass
class KeyConfiguration:
    """Configuration for DRM key management with validation and normalization."""
    keys: Dict[str, str] = field(default_factory=dict)
    single_key_mode: bool = field(init=False)
    default_kid: Optional[str] = field(init=False, default=None)
    default_key: Optional[str] = field(init=False, default=None)

    def __post_init__(self):
        """Normalize and validate keys on initialization."""
        normalized = {}
        for kid, key in self.keys.items():
            norm_kid = kid.replace("-", "").lower()
            norm_key = key.replace("-", "").lower()

            # Validate hex format (32 characters = 16 bytes)
            if len(norm_kid) != 32 or not all(c in '0123456789abcdef' for c in norm_kid):
                logger.warning(f"Invalid KID format (expected 32 hex chars): {kid}")
                continue
            if len(norm_key) != 32 or not all(c in '0123456789abcdef' for c in norm_key):
                logger.warning(f"Invalid key format for KID {kid}: {key}")
                continue

            normalized[norm_kid] = norm_key

        self.keys = normalized
        self.single_key_mode = len(self.keys) <= 1

        if self.single_key_mode and self.keys:
            self.default_kid, self.default_key = next(iter(self.keys.items()))
            logger.debug(f"Single key mode: KID={self.default_kid[:8]}...")
        elif self.keys:
            logger.debug(f"Multi-key mode: {len(self.keys)} keys available")


class MPDRewriter:
    MPD_NAMESPACE = {"mpd": "urn:mpeg:dash:schema:mpd:2011"}
    CENC_NAMESPACE = {"cenc": "urn:mpeg:cenc:2013"}

    def __init__(
            self,
            media_proxy_url: str,
            provider_proxy_url: Optional[str] = None,
            clearkey_keyids: Optional[dict] = None,
    ):
        self.media_proxy_url = media_proxy_url.rstrip("/")
        self.provider_proxy_url = provider_proxy_url
        self.key_config = KeyConfiguration(clearkey_keyids or {})

        # Pre-calculate query params that don't change to save cycles during rewrite
        self._static_params = {}
        if self.provider_proxy_url:
            self._static_params["proxy"] = self.provider_proxy_url

    @staticmethod
    def encode_url(url: str) -> str:
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").rstrip("=")

    @staticmethod
    def decode_url(encoded: str) -> str:
        padding = 4 - (len(encoded) % 4)
        if padding != 4:
            encoded += "=" * padding
        return base64.urlsafe_b64decode(encoded.encode("utf-8")).decode("utf-8")

    def build_proxy_url(
            self,
            original_url: str,
            template_pattern: Optional[str] = None,
            segment_type: Optional[str] = None,
            is_encrypted: bool = False,
            kid: Optional[str] = None,  # Specific KID for this AdaptationSet
    ) -> str:
        params = {"url": original_url, **self._static_params}

        if self.key_config.keys and is_encrypted:
            if self.key_config.single_key_mode:
                # Single key mode: use the default key for everything
                if segment_type == "initialization":
                    params["kid"] = self.key_config.default_kid
                elif segment_type == "media":
                    params["key"] = self.key_config.default_key
                else:
                    params["kid"] = self.key_config.default_kid
                    params["key"] = self.key_config.default_key
            else:
                # Multi-key mode: use specific KID if provided
                if kid and kid in self.key_config.keys:
                    key = self.key_config.keys[kid]
                    if segment_type == "initialization":
                        params["kid"] = kid
                    elif segment_type == "media":
                        params["key"] = key
                    else:
                        params["kid"] = kid
                        params["key"] = key
                else:
                    # Fallback to first key (should only happen if we couldn't extract KID)
                    if segment_type == "initialization":
                        params["kid"] = self.key_config.default_kid
                    elif segment_type == "media":
                        params["key"] = self.key_config.default_key
                    else:
                        params["kid"] = self.key_config.default_kid
                        params["key"] = self.key_config.default_key
                    logger.warning(f"No KID provided for encrypted segment, using fallback key")

        encoded = self.encode_url(urlencode(params))
        endpoint = "decrypt" if (self.key_config.keys and is_encrypted) else "proxy"
        proxy_url = f"{self.media_proxy_url}/api/{endpoint}/{encoded}"

        if template_pattern:
            proxy_url += f"/{quote(template_pattern, safe='.-_$')}"

        return proxy_url

    @staticmethod
    def split_template_url(url: str) -> Tuple[str, Optional[str]]:
        if "$" not in url:
            return url, None
        first_template_pos = url.find("$")
        last_slash_before_template = url.rfind("/", 0, first_template_pos)
        if last_slash_before_template == -1:
            return "", url
        return url[:last_slash_before_template], url[last_slash_before_template + 1:]

    def rewrite_mpd(self, mpd_content: str, manifest_url: str) -> str:
        try:
            root = ET.fromstring(mpd_content)
            ET.register_namespace("", self.MPD_NAMESPACE["mpd"])

            # Single-pass tree preparation
            encrypted_ids, as_id_to_kid = self._prepare_tree_and_extract_kids(root)

            # Filter out encrypted AdaptationSets without available keys
            if self.key_config.keys:
                self._remove_adaptationsets_without_keys(root, as_id_to_kid)
            else:
                self._remove_all_encrypted_adaptationsets(root)

            # Verify we have playable content remaining
            remaining_sets = root.findall(".//mpd:AdaptationSet", self.MPD_NAMESPACE)
            if not remaining_sets:
                raise ValueError("No AdaptationSets remain after key filtering - manifest would be empty")

            base_url = self._extract_base_url(root, manifest_url)

            # Rewrite URLs with appropriate keys
            self._rewrite_node(root, base_url, encrypted_ids, as_id_to_kid, False, None, "")

            rewritten = ET.tostring(root, encoding="unicode", method="xml")
            if not rewritten.startswith("<?xml"):
                rewritten = '<?xml version="1.0" encoding="UTF-8"?>\n' + rewritten
            return rewritten
        except Exception as e:
            logger.error(f"Failed to rewrite MPD: {e}")
            raise

    def _prepare_tree_and_extract_kids(self, root: ET.Element) -> Tuple[Set[str], Dict[str, str]]:
        """
        Single-pass optimization: clean tree, identify encrypted sets, extract KIDs.
        Returns: (encrypted_adaptation_set_ids, as_id_to_kid_mapping)
        """
        encrypted_ids = set()
        as_id_to_kid = {}

        # Process all Periods (handles multi-period manifests correctly)
        for period in root.findall(".//mpd:Period", self.MPD_NAMESPACE):
            period_id = period.get("id", "")

            # Remove Period-level BaseURL elements
            for bu in list(period.findall("mpd:BaseURL", self.MPD_NAMESPACE)):
                period.remove(bu)

            for adaptation_set in period.findall("mpd:AdaptationSet", self.MPD_NAMESPACE):
                as_id = adaptation_set.get("id")
                if not as_id:
                    as_id = str(id(adaptation_set))

                # Make ID unique across periods
                unique_id = f"{period_id}_{as_id}" if period_id else as_id

                # Remove AdaptationSet-level BaseURL elements
                for bu in list(adaptation_set.findall("mpd:BaseURL", self.MPD_NAMESPACE)):
                    adaptation_set.remove(bu)

                # Process ContentProtection
                cp_elements = list(adaptation_set.findall("mpd:ContentProtection", self.MPD_NAMESPACE))

                if cp_elements:
                    encrypted_ids.add(unique_id)

                    # Extract KID only in multi-key mode
                    if not self.key_config.single_key_mode and self.key_config.keys:
                        kid = self._extract_kid_from_contentprotection(cp_elements, adaptation_set)
                        if kid:
                            normalized_kid = kid.replace("-", "").lower()
                            as_id_to_kid[unique_id] = normalized_kid
                            logger.debug(f"AdaptationSet {unique_id} KID: {normalized_kid[:8]}...")
                        else:
                            logger.debug(f"AdaptationSet {unique_id} encrypted but no KID found")

                    # Remove ContentProtection elements
                    for cp in cp_elements:
                        adaptation_set.remove(cp)

        return encrypted_ids, as_id_to_kid

    def _extract_kid_from_contentprotection(
            self,
            cp_elements: list,
            adaptation_set: ET.Element
    ) -> Optional[str]:
        """
        Extract KID from ContentProtection elements.
        Tries multiple methods per DASH specification.
        """
        # Method 1: default_KID attribute (most common)
        for cp in cp_elements:
            default_kid = (
                    cp.get("default_KID") or
                    cp.get("{urn:mpeg:cenc:2013}default_KID") or
                    cp.get("cenc:default_KID")
            )
            if default_kid:
                return default_kid

        # Method 2: Parse PSSH box
        for cp in cp_elements:
            # Try standard cenc:pssh
            pssh_elem = cp.find("cenc:pssh", self.CENC_NAMESPACE)
            if pssh_elem is None:
                # Try without namespace
                pssh_elem = cp.find("pssh")

            if pssh_elem is not None and pssh_elem.text:
                try:
                    kid = self._extract_kid_from_pssh(pssh_elem.text.strip())
                    if kid:
                        logger.debug("Extracted KID from PSSH box")
                        return kid
                except Exception as e:
                    logger.debug(f"Failed to parse PSSH: {e}")

        # Method 3: Check Representation-level (fallback)
        rep = adaptation_set.find("mpd:Representation", self.MPD_NAMESPACE)
        if rep is not None:
            rep_cp = rep.findall("mpd:ContentProtection", self.MPD_NAMESPACE)
            if rep_cp:
                for cp in rep_cp:
                    default_kid = (
                            cp.get("default_KID") or
                            cp.get("{urn:mpeg:cenc:2013}default_KID")
                    )
                    if default_kid:
                        logger.debug("Found KID at Representation level")
                        return default_kid

        return None

    @staticmethod
    def _extract_kid_from_pssh(self, pssh_b64: str) -> Optional[str]:
        """
        Extract first KID from PSSH box (CENC specification).

        PSSH structure (version 1):
        - box_size: 4 bytes
        - box_type: 4 bytes ('pssh')
        - version: 1 byte (0 or 1)
        - flags: 3 bytes
        - system_id: 16 bytes
        - [version 1 only] kid_count: 4 bytes
        - [version 1 only] kids: 16 bytes each
        - data_size: 4 bytes
        - data: variable
        """
        try:
            pssh_data = base64.b64decode(pssh_b64)

            if len(pssh_data) < 32:
                return None

            # Check version (byte 8)
            version = pssh_data[8]

            if version == 1:
                # Version 1 includes KID list
                if len(pssh_data) < 36:
                    return None

                # KID count at bytes 28-31 (big-endian)
                kid_count = int.from_bytes(pssh_data[28:32], 'big')

                if kid_count > 0 and len(pssh_data) >= 48:
                    # First KID starts at byte 32 (16 bytes)
                    kid_bytes = pssh_data[32:48]

                    # Format as UUID string with hyphens
                    kid_hex = kid_bytes.hex()
                    kid_uuid = f"{kid_hex[0:8]}-{kid_hex[8:12]}-{kid_hex[12:16]}-{kid_hex[16:20]}-{kid_hex[20:32]}"
                    return kid_uuid

            return None

        except Exception as e:
            logger.debug(f"Error extracting KID from PSSH: {e}")
            return None

    def _remove_adaptationsets_without_keys(
            self,
            root: ET.Element,
            as_id_to_kid: Dict[str, str]
    ):
        """
        Remove encrypted AdaptationSets for which we don't have decryption keys.
        Optimized to avoid repeated getparent() calls.
        """
        if self.key_config.single_key_mode:
            # In single key mode, we can decrypt everything
            return

        removal_count = 0

        # Process each period separately to avoid expensive getparent() calls
        for period in root.findall(".//mpd:Period", self.MPD_NAMESPACE):
            period_id = period.get("id", "")
            adaptationsets_to_remove = []

            for adaptation_set in period.findall("mpd:AdaptationSet", self.MPD_NAMESPACE):
                as_id = adaptation_set.get("id")
                if not as_id:
                    as_id = str(id(adaptation_set))

                unique_id = f"{period_id}_{as_id}" if period_id else as_id

                # Check if this AdaptationSet requires a key we don't have
                if unique_id in as_id_to_kid:
                    required_kid = as_id_to_kid[unique_id]

                    if required_kid not in self.key_config.keys:
                        logger.warning(
                            f"Removing AdaptationSet {unique_id} - "
                            f"missing key for KID: {required_kid[:8]}..."
                        )
                        adaptationsets_to_remove.append(adaptation_set)

            # Remove all marked AdaptationSets from this period
            for adaptation_set in adaptationsets_to_remove:
                period.remove(adaptation_set)
                removal_count += 1

        if removal_count > 0:
            logger.info(f"Removed {removal_count} AdaptationSet(s) due to missing keys")

    def _remove_all_encrypted_adaptationsets(self, root: ET.Element):
        """Remove all encrypted AdaptationSets when we have no keys."""
        removal_count = 0

        for period in root.findall(".//mpd:Period", self.MPD_NAMESPACE):
            adaptationsets_to_remove = []

            for adaptation_set in period.findall("mpd:AdaptationSet", self.MPD_NAMESPACE):
                # Check if AdaptationSet has ContentProtection
                cp_elements = adaptation_set.findall("mpd:ContentProtection", self.MPD_NAMESPACE)
                if cp_elements:
                    adaptationsets_to_remove.append(adaptation_set)

            # Remove all encrypted AdaptationSets from this period
            for adaptation_set in adaptationsets_to_remove:
                period.remove(adaptation_set)
                removal_count += 1

        if removal_count > 0:
            logger.info(f"Removed {removal_count} encrypted AdaptationSet(s) (no keys available)")

    def _rewrite_node(
            self,
            element: ET.Element,
            base_url: str,
            encrypted_ids: Set[str],
            as_id_to_kid: Dict[str, str],
            current_encrypted: bool,
            current_kid: Optional[str] = None,
            current_period_id: str = "",
    ):
        """Recursive node rewriter with KID-aware key selection."""
        # Track period ID as we traverse
        if element.tag.endswith("Period"):
            current_period_id = element.get("id", "")

        # Update state when entering an AdaptationSet
        if element.tag.endswith("AdaptationSet"):
            as_id = element.get("id", str(id(element)))
            # Use same unique ID logic as _prepare_tree_and_extract_kids
            unique_id = f"{current_period_id}_{as_id}" if current_period_id else as_id
            current_encrypted = unique_id in encrypted_ids

            # Get specific KID for this AdaptationSet (multi-key mode only)
            if current_encrypted and not self.key_config.single_key_mode:
                current_kid = as_id_to_kid.get(unique_id)

        # Rewrite URL attributes
        attr_map = {
            "media": "media",
            "initialization": "initialization",
            "sourceURL": None,
        }

        for attr, seg_type in attr_map.items():
            if attr in element.attrib:
                val = element.attrib[attr]
                if not val:
                    continue

                resolved = urljoin(base_url, val)
                if "$" in resolved:
                    path, pattern = self.split_template_url(resolved)
                    element.attrib[attr] = self.build_proxy_url(
                        path, pattern, seg_type, current_encrypted, current_kid
                    )
                else:
                    element.attrib[attr] = self.build_proxy_url(
                        resolved, None, seg_type, current_encrypted, current_kid
                    )

        # Handle SegmentURL (always 'media' type)
        if element.tag.endswith("SegmentURL") and "media" in element.attrib:
            resolved = urljoin(base_url, element.attrib["media"])
            path, pattern = (
                self.split_template_url(resolved)
                if "$" in resolved
                else (resolved, None)
            )
            element.attrib["media"] = self.build_proxy_url(
                path, pattern, "media", current_encrypted, current_kid
            )

        # Recurse to children
        for child in element:
            self._rewrite_node(
                child, base_url, encrypted_ids, as_id_to_kid,
                current_encrypted, current_kid, current_period_id
            )

    def _extract_base_url(self, root: ET.Element, manifest_url: str) -> str:
        base_url_elem = root.find(".//mpd:BaseURL", self.MPD_NAMESPACE)

        # Check if this is one of the special services
        SPECIAL_PREFIXES = [
            "https://bpcdnmanprod.nexttv.ht.hr/bpk-tv/",
            "https://lineartv-cdn.t-mobile.pl/bpk-tv/"
        ]

        # Determine manifest directory based on service type
        if any(manifest_url.startswith(prefix) for prefix in SPECIAL_PREFIXES):
            # Special service: KEEP index.mpd
            manifest_dir = manifest_url if manifest_url.endswith('/') else f"{manifest_url}/"
        else:
            # Normal service: remove index.mpd
            parsed_manifest = urlparse(manifest_url)
            manifest_dir = f"{parsed_manifest.scheme}://{parsed_manifest.netloc}{parsed_manifest.path.rsplit('/', 1)[0]}/"

        if base_url_elem is not None and base_url_elem.text:
            base_url_text = base_url_elem.text.strip()
            if not base_url_text.startswith(("http://", "https://")):
                return urljoin(manifest_dir, base_url_text)
            return base_url_text

        # No BaseURL element
        return manifest_dir

    @staticmethod
    def extract_cache_ttl(headers: dict) -> int:
        cache_control = headers.get("Cache-Control", headers.get("cache-control", ""))
        if "max-age=" in cache_control:
            try:
                for directive in cache_control.split(","):
                    directive = directive.strip()
                    if directive.startswith("max-age="):
                        return int(directive.split("=")[1])
            except (ValueError, IndexError):
                pass

        expires = headers.get("Expires", headers.get("expires"))
        if expires:
            try:
                expires_dt = parsedate_to_datetime(expires)
                now = datetime.now(timezone.utc)
                ttl = int((expires_dt - now).total_seconds())
                if ttl > 0:
                    return ttl
            except Exception:
                pass

        return 300

    @staticmethod
    def extract_mpd_update_period(mpd_content: str) -> Optional[int]:
        try:
            root = ET.fromstring(mpd_content)
            if root.attrib.get("type") == "dynamic":
                update_period = root.attrib.get("minimumUpdatePeriod")
                if update_period:
                    return MPDRewriter._parse_iso_duration(update_period)
        except Exception:
            pass
        return None

    @staticmethod
    def _parse_iso_duration(duration: str) -> int:
        match = ISO_8601_PERIOD_RE.match(duration)
        if not match:
            return 0
        d = match.groupdict()
        return int(
            int(d["hours"] or 0) * 3600
            + int(d["minutes"] or 0) * 60
            + float(d["seconds"] or 0)
        )