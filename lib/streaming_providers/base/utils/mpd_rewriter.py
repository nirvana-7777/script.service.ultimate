# streaming_providers/base/utils/mpd_rewriter.py
import base64
import xml.etree.ElementTree as ET
import re
from typing import Optional, Tuple, Set, Dict, List
from urllib.parse import urljoin, urlparse, quote, urlencode
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from dataclasses import dataclass, field

from .logger import logger
from .vfs import get_vfs

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


class RepresentationBlocklist:
    """
    Manages blocklist of problematic Representation IDs that cause 500 errors.

    Blocklist format (JSON):
    {
        "provider_name": {
            "channel_name": ["rep_id_1", "rep_id_2"],
            "another_channel": ["rep_id_3"]
        }
    }
    """

    def __init__(self, blocklist_path: str = "representation_blocklist.json"):
        """
        Initialize blocklist manager.

        Args:
            blocklist_path: Path to JSON file containing blocklist configuration
        """
        self.blocklist_path = blocklist_path
        self.blocklist: Dict[str, Dict[str, List[str]]] = {}
        self._load_blocklist()

    def _load_blocklist(self):
        """Load blocklist from JSON file using VFS."""
        try:
            vfs = get_vfs()
            data = vfs.read_json(self.blocklist_path)

            if data:
                self.blocklist = data
                total_blocked = sum(
                    len(rep_ids)
                    for provider in self.blocklist.values()
                    for rep_ids in provider.values()
                )
                logger.info(
                    f"Loaded representation blocklist: "
                    f"{len(self.blocklist)} providers, {total_blocked} total blocked representations"
                )
            else:
                logger.info(f"No blocklist found at {self.blocklist_path}, starting with empty blocklist")

        except Exception as e:
            logger.warning(f"Failed to load representation blocklist from {self.blocklist_path}: {e}")
            self.blocklist = {}

    def is_blocked(self, provider: str, channel: str, representation_id: str) -> bool:
        """
        Check if a representation ID is blocked for a given provider/channel.

        Args:
            provider: Provider name (e.g., "magenta_tv", "ht_iptv")
            channel: Channel name/ID
            representation_id: Representation ID to check

        Returns:
            True if blocked, False otherwise
        """
        if not provider or not channel:
            return False

        provider_data = self.blocklist.get(provider, {})
        channel_data = provider_data.get(channel, [])

        return representation_id in channel_data

    def get_blocked_ids(self, provider: str, channel: str) -> Set[str]:
        """
        Get set of all blocked representation IDs for a provider/channel.

        Args:
            provider: Provider name
            channel: Channel name/ID

        Returns:
            Set of blocked representation IDs
        """
        if not provider or not channel:
            return set()

        provider_data = self.blocklist.get(provider, {})
        channel_data = provider_data.get(channel, [])

        return set(channel_data)


@dataclass
class VideoRepresentation:
    """Represents a video representation with its quality metrics."""
    element: ET.Element
    adaptation_set: ET.Element
    period: ET.Element
    bandwidth: int
    width: Optional[int] = None
    height: Optional[int] = None
    frame_rate: Optional[float] = None
    representation_id: str = ""
    period_id: str = ""
    as_id: str = ""

    def get_quality_score(self) -> Tuple[int, int, int]:
        """
        Returns a tuple for comparison: (resolution_pixels, bandwidth, frame_rate_score)
        Higher values = better quality
        """
        resolution = (self.width or 0) * (self.height or 0)
        frame_rate_score = int((self.frame_rate or 0) * 100)
        return resolution, self.bandwidth, frame_rate_score


class MPDRewriter:
    MPD_NAMESPACE = {"mpd": "urn:mpeg:dash:schema:mpd:2011"}
    CENC_NAMESPACE = {"cenc": "urn:mpeg:cenc:2013"}

    def __init__(
            self,
            media_proxy_url: str,
            provider_proxy_url: Optional[str] = None,
            clearkey_keyids: Optional[dict] = None,
            highest_quality_video_only: bool = False,  # NEW: Enable highest quality filtering
            provider: Optional[str] = None,  # NEW: Provider name for blocklist filtering
            channel: Optional[str] = None,  # NEW: Channel name for blocklist filtering
            blocklist_path: str = "representation_blocklist.json",  # NEW: Path to blocklist file
    ):
        self.media_proxy_url = media_proxy_url.rstrip("/")
        self.provider_proxy_url = provider_proxy_url
        self.key_config = KeyConfiguration(clearkey_keyids or {})
        self.highest_quality_video_only = highest_quality_video_only

        # NEW: Blocklist configuration
        self.provider = provider
        self.channel = channel
        self.blocklist = RepresentationBlocklist(blocklist_path)

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
            representation_id: Optional[str] = None,  # NEW: For template substitution
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
            # NEW: Substitute $RepresentationID$ if we have it and highest_quality_video_only is enabled
            if self.highest_quality_video_only and representation_id and "$RepresentationID$" in template_pattern:
                template_pattern = template_pattern.replace("$RepresentationID$", representation_id)

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

            # Extract MPD-level base URL before any modifications
            mpd_base_url = self._extract_mpd_base_url(root, manifest_url)

            # Single-pass tree preparation with BaseURL extraction
            encrypted_ids, as_id_to_kid, base_url_map = self._prepare_tree_and_extract_kids(root, mpd_base_url)

            # FIRST: Filter out encrypted AdaptationSets without available keys
            # This ensures we only consider decryptable content for quality selection
            if self.key_config.keys:
                self._remove_adaptationsets_without_keys(root, as_id_to_kid)
            else:
                self._remove_all_encrypted_adaptationsets(root)

            # SECOND: Filter out blocked representations that cause 500 errors
            if self.provider and self.channel:
                self._remove_blocked_representations(root)

            # THEN: Filter to highest quality video from remaining decryptable content
            best_video_info = None
            if self.highest_quality_video_only:
                best_video_info = self._filter_to_highest_quality_video(root)
                if best_video_info:
                    logger.info(
                        f"Filtered to highest quality video: {best_video_info.width}x{best_video_info.height} "
                        f"@ {best_video_info.bandwidth}bps, RepID={best_video_info.representation_id}"
                    )

            # Verify we have playable content remaining
            remaining_sets = root.findall(".//mpd:AdaptationSet", self.MPD_NAMESPACE)
            if not remaining_sets:
                raise ValueError("No AdaptationSets remain after key filtering - manifest would be empty")

            # Rewrite URLs with appropriate keys and context-aware base URLs
            self._rewrite_node(root, mpd_base_url, encrypted_ids, as_id_to_kid, base_url_map,
                               False, None, "", best_video_info)

            rewritten = ET.tostring(root, encoding="unicode", method="xml")
            if not rewritten.startswith("<?xml"):
                rewritten = '<?xml version="1.0" encoding="UTF-8"?>\n' + rewritten
            return rewritten
        except Exception as e:
            logger.error(f"Failed to rewrite MPD: {e}")
            raise

    def _filter_to_highest_quality_video(self, root: ET.Element) -> Optional[VideoRepresentation]:
        """
        Find the absolute highest quality video representation across all periods and adaptation sets.
        Remove all other video representations, keep audio/subtitles unchanged.
        Returns information about the best video representation found.
        """
        all_video_reps: List[VideoRepresentation] = []

        # Scan all periods and adaptation sets to find video representations
        for period in root.findall(".//mpd:Period", self.MPD_NAMESPACE):
            period_id = period.get("id", "")

            for adaptation_set in period.findall("mpd:AdaptationSet", self.MPD_NAMESPACE):
                # Check if this is a video adaptation set
                if not self._is_video_adaptation_set(adaptation_set):
                    continue

                as_id = adaptation_set.get("id", str(id(adaptation_set)))

                # Collect all representations from this video adaptation set
                for representation in adaptation_set.findall("mpd:Representation", self.MPD_NAMESPACE):
                    video_rep = self._parse_video_representation(
                        representation, adaptation_set, period, period_id, as_id
                    )
                    if video_rep:
                        all_video_reps.append(video_rep)

        if not all_video_reps:
            logger.warning("No video representations found for filtering")
            return None

        # Find the best video representation
        best_video = max(all_video_reps, key=lambda v: v.get_quality_score())
        logger.debug(
            f"Found {len(all_video_reps)} video representations, "
            f"best: {best_video.width}x{best_video.height} @ {best_video.bandwidth}bps"
        )

        # Now remove all video representations EXCEPT the best one
        removal_count = 0
        for period in root.findall(".//mpd:Period", self.MPD_NAMESPACE):
            period_id = period.get("id", "")
            adaptation_sets_to_remove = []

            for adaptation_set in period.findall("mpd:AdaptationSet", self.MPD_NAMESPACE):
                if not self._is_video_adaptation_set(adaptation_set):
                    continue

                as_id = adaptation_set.get("id", str(id(adaptation_set)))

                # Check if this adaptation set contains the best representation
                representations_to_remove = []
                contains_best = False

                for representation in adaptation_set.findall("mpd:Representation", self.MPD_NAMESPACE):
                    rep_id = representation.get("id", "")

                    # Is this the best representation?
                    if (period_id == best_video.period_id and
                            as_id == best_video.as_id and
                            rep_id == best_video.representation_id):
                        contains_best = True
                    else:
                        representations_to_remove.append(representation)

                # Remove non-best representations
                for rep in representations_to_remove:
                    adaptation_set.remove(rep)
                    removal_count += 1

                # If this adaptation set no longer has any representations, mark for removal
                if not contains_best:
                    adaptation_sets_to_remove.append(adaptation_set)

            # Remove empty video adaptation sets
            for adaptation_set in adaptation_sets_to_remove:
                period.remove(adaptation_set)

        logger.info(f"Removed {removal_count} video representation(s), kept highest quality only")
        return best_video

    def _is_video_adaptation_set(self, adaptation_set: ET.Element) -> bool:
        """Determine if an AdaptationSet is video based on mimeType or contentType."""
        mime_type = adaptation_set.get("mimeType", "")
        content_type = adaptation_set.get("contentType", "")

        # Check AdaptationSet level
        if mime_type.startswith("video/") or content_type == "video":
            return True

        # Check Representation level if not specified at AdaptationSet level
        for representation in adaptation_set.findall("mpd:Representation", self.MPD_NAMESPACE):
            rep_mime = representation.get("mimeType", "")
            if rep_mime.startswith("video/"):
                return True

        return False

    def _parse_video_representation(
            self,
            representation: ET.Element,
            adaptation_set: ET.Element,
            period: ET.Element,
            period_id: str,
            as_id: str
    ) -> Optional[VideoRepresentation]:
        """Parse a Representation element and extract video quality information."""
        try:
            # Bandwidth is required
            bandwidth = int(representation.get("bandwidth", "0"))
            if bandwidth == 0:
                return None

            # Width and height (can be on Representation or AdaptationSet)
            width = representation.get("width") or adaptation_set.get("width")
            height = representation.get("height") or adaptation_set.get("height")

            width = int(width) if width else None
            height = int(height) if height else None

            # Frame rate (can be on Representation or AdaptationSet)
            frame_rate_str = representation.get("frameRate") or adaptation_set.get("frameRate")
            frame_rate = None
            if frame_rate_str:
                # Handle both "30" and "30000/1001" formats
                if "/" in frame_rate_str:
                    num, denom = frame_rate_str.split("/")
                    frame_rate = float(num) / float(denom)
                else:
                    frame_rate = float(frame_rate_str)

            representation_id = representation.get("id", "")

            return VideoRepresentation(
                element=representation,
                adaptation_set=adaptation_set,
                period=period,
                bandwidth=bandwidth,
                width=width,
                height=height,
                frame_rate=frame_rate,
                representation_id=representation_id,
                period_id=period_id,
                as_id=as_id
            )
        except (ValueError, AttributeError) as e:
            logger.warning(f"Failed to parse video representation: {e}")
            return None

    def _prepare_tree_and_extract_kids(self, root: ET.Element, mpd_base_url: str) -> Tuple[
        Set[str], Dict[str, str], Dict[str, str]]:
        """
        Single-pass optimization: clean tree, identify encrypted sets, extract KIDs and BaseURLs.
        Returns: (encrypted_adaptation_set_ids, as_id_to_kid_mapping, base_url_mapping)
        """
        encrypted_ids = set()
        as_id_to_kid = {}
        base_url_map = {}  # Maps period_id:as_id -> resolved base URL

        # Process all Periods (handles multi-period manifests correctly)
        for period in root.findall(".//mpd:Period", self.MPD_NAMESPACE):
            period_id = period.get("id", "")

            # Extract Period-level BaseURL BEFORE removing it
            period_base_url = mpd_base_url
            period_base_elem = period.find("mpd:BaseURL", self.MPD_NAMESPACE)
            if period_base_elem is not None and period_base_elem.text:
                period_base_text = period_base_elem.text.strip()
                period_base_url = urljoin(mpd_base_url, period_base_text)
                logger.debug(f"Period {period_id} BaseURL: {period_base_url}")

            # Remove Period-level BaseURL elements
            for bu in list(period.findall("mpd:BaseURL", self.MPD_NAMESPACE)):
                period.remove(bu)

            for adaptation_set in period.findall("mpd:AdaptationSet", self.MPD_NAMESPACE):
                as_id = adaptation_set.get("id")
                if not as_id:
                    as_id = str(id(adaptation_set))

                unique_id = f"{period_id}_{as_id}" if period_id else as_id

                # Extract AdaptationSet-level BaseURL BEFORE removing it
                as_base_url = period_base_url
                as_base_elem = adaptation_set.find("mpd:BaseURL", self.MPD_NAMESPACE)
                if as_base_elem is not None and as_base_elem.text:
                    as_base_text = as_base_elem.text.strip()
                    as_base_url = urljoin(period_base_url, as_base_text)
                    logger.debug(f"AdaptationSet {unique_id} BaseURL: {as_base_url}")

                # Store the resolved base URL for this AdaptationSet
                base_url_map[unique_id] = as_base_url

                # Remove AdaptationSet-level BaseURL elements
                for bu in list(adaptation_set.findall("mpd:BaseURL", self.MPD_NAMESPACE)):
                    adaptation_set.remove(bu)

                # Check if encrypted
                cp_elements = adaptation_set.findall("mpd:ContentProtection", self.MPD_NAMESPACE)
                has_content_protection = len(cp_elements) > 0

                # Also check Representation-level ContentProtection
                for representation in adaptation_set.findall("mpd:Representation", self.MPD_NAMESPACE):
                    rep_cp = representation.findall("mpd:ContentProtection", self.MPD_NAMESPACE)
                    if rep_cp:
                        has_content_protection = True
                        break

                if has_content_protection:
                    encrypted_ids.add(unique_id)

                    # Extract KID
                    extracted_kid = self._extract_kid_from_adaptationset(adaptation_set)
                    if extracted_kid:
                        as_id_to_kid[unique_id] = extracted_kid
                        logger.debug(f"AdaptationSet {unique_id} KID: {extracted_kid[:8]}...")

                # Remove ContentProtection elements (we've already extracted what we need)
                for cp in list(adaptation_set.findall("mpd:ContentProtection", self.MPD_NAMESPACE)):
                    adaptation_set.remove(cp)

                for representation in adaptation_set.findall("mpd:Representation", self.MPD_NAMESPACE):
                    for cp in list(representation.findall("mpd:ContentProtection", self.MPD_NAMESPACE)):
                        representation.remove(cp)

        return encrypted_ids, as_id_to_kid, base_url_map

    def _extract_kid_from_adaptationset(self, adaptation_set: ET.Element) -> Optional[str]:
        """Extract KID from ContentProtection elements."""
        # Check AdaptationSet-level ContentProtection
        for cp in adaptation_set.findall("mpd:ContentProtection", self.MPD_NAMESPACE):
            kid = self._extract_kid_from_cp_element(cp)
            if kid:
                return kid

        # Check Representation-level ContentProtection
        for representation in adaptation_set.findall("mpd:Representation", self.MPD_NAMESPACE):
            for cp in representation.findall("mpd:ContentProtection", self.MPD_NAMESPACE):
                kid = self._extract_kid_from_cp_element(cp)
                if kid:
                    return kid

        return None

    def _extract_kid_from_cp_element(self, cp: ET.Element) -> Optional[str]:
        """Extract KID from a single ContentProtection element."""
        # Check default_KID attribute
        kid_attr = cp.get("{urn:mpeg:cenc:2013}default_KID")
        if kid_attr:
            return kid_attr.replace("-", "").lower()

        # Check cenc:pssh
        for pssh in cp.findall("cenc:pssh", self.CENC_NAMESPACE):
            if pssh.text:
                try:
                    pssh_data = base64.b64decode(pssh.text)
                    if len(pssh_data) >= 36:
                        kid_bytes = pssh_data[32:48]
                        return kid_bytes.hex()
                except Exception:
                    continue

        return None

    def _remove_adaptationsets_without_keys(self, root: ET.Element, as_id_to_kid: Dict[str, str]):
        """Remove encrypted AdaptationSets that require keys we don't have."""
        removal_count = 0

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

    def _remove_blocked_representations(self, root: ET.Element):
        """
        Remove Representation elements that are blocked for this provider/channel.
        If an AdaptationSet has only one Representation and it's blocked, remove the entire AdaptationSet.
        """
        if not self.provider or not self.channel:
            return

        blocked_ids = self.blocklist.get_blocked_ids(self.provider, self.channel)
        if not blocked_ids:
            return

        total_reps_removed = 0
        total_as_removed = 0

        for period in root.findall(".//mpd:Period", self.MPD_NAMESPACE):
            adaptationsets_to_remove = []

            for adaptation_set in period.findall("mpd:AdaptationSet", self.MPD_NAMESPACE):
                representations = adaptation_set.findall("mpd:Representation", self.MPD_NAMESPACE)
                representations_to_remove = []

                # Check each representation in this AdaptationSet
                for representation in representations:
                    rep_id = representation.get("id", "")

                    if rep_id in blocked_ids:
                        logger.info(
                            f"Blocking representation '{rep_id}' for {self.provider}/{self.channel} "
                            f"(known to cause 500 errors)"
                        )
                        representations_to_remove.append(representation)

                # If all representations are blocked, mark the entire AdaptationSet for removal
                if representations_to_remove and len(representations_to_remove) == len(representations):
                    as_id = adaptation_set.get("id", "unknown")
                    logger.info(
                        f"Removing entire AdaptationSet '{as_id}' - "
                        f"all {len(representations)} representation(s) are blocked"
                    )
                    adaptationsets_to_remove.append(adaptation_set)
                    total_as_removed += 1
                else:
                    # Remove only the blocked representations
                    for representation in representations_to_remove:
                        adaptation_set.remove(representation)
                        total_reps_removed += 1

            # Remove marked AdaptationSets
            for adaptation_set in adaptationsets_to_remove:
                period.remove(adaptation_set)

        if total_reps_removed > 0 or total_as_removed > 0:
            logger.info(
                f"Blocklist filtering complete: removed {total_reps_removed} representation(s) "
                f"and {total_as_removed} AdaptationSet(s) for {self.provider}/{self.channel}"
            )

    def _rewrite_node(
            self,
            element: ET.Element,
            base_url: str,
            encrypted_ids: Set[str],
            as_id_to_kid: Dict[str, str],
            base_url_map: Dict[str, str],
            current_encrypted: bool,
            current_kid: Optional[str] = None,
            current_period_id: str = "",
            best_video_info: Optional[VideoRepresentation] = None,  # NEW
    ):
        """Recursive node rewriter with KID-aware key selection and context-aware base URLs."""
        # Track period ID as we traverse
        if element.tag.endswith("Period"):
            current_period_id = element.get("id", "")

        # Update state when entering an AdaptationSet
        current_as_id = None
        current_rep_id = None  # NEW: Track current representation ID
        if element.tag.endswith("AdaptationSet"):
            as_id = element.get("id", str(id(element)))
            current_as_id = as_id
            # Use same unique ID logic as _prepare_tree_and_extract_kids
            unique_id = f"{current_period_id}_{as_id}" if current_period_id else as_id
            current_encrypted = unique_id in encrypted_ids

            # Update base_url to the AdaptationSet-specific base URL
            if unique_id in base_url_map:
                base_url = base_url_map[unique_id]

            # Get specific KID for this AdaptationSet (multi-key mode only)
            if current_encrypted and not self.key_config.single_key_mode:
                current_kid = as_id_to_kid.get(unique_id)

        # NEW: Track representation ID for template substitution
        if element.tag.endswith("Representation"):
            current_rep_id = element.get("id", "")

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
                        path, pattern, seg_type, current_encrypted, current_kid,
                        representation_id=current_rep_id  # NEW
                    )
                else:
                    element.attrib[attr] = self.build_proxy_url(
                        resolved, None, seg_type, current_encrypted, current_kid,
                        representation_id=current_rep_id  # NEW
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
                path, pattern, "media", current_encrypted, current_kid,
                representation_id=current_rep_id  # NEW
            )

        # Recurse to children
        for child in element:
            self._rewrite_node(
                child, base_url, encrypted_ids, as_id_to_kid, base_url_map,
                current_encrypted, current_kid, current_period_id, best_video_info  # NEW
            )

    def _extract_mpd_base_url(self, root: ET.Element, manifest_url: str) -> str:
        """Extract and resolve MPD-level BaseURL."""
        base_url_elem = root.find("mpd:BaseURL", self.MPD_NAMESPACE)

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