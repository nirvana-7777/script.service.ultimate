# streaming_providers/base/utils/mpd_rewriter.py
"""
MPD rewriter for DASH manifests.
Handles URL proxying, DRM key injection, quality filtering, and representation blocklisting.
"""

import base64
import struct
import xml.etree.ElementTree as ET
from typing import Optional, Tuple, Set, Dict
from urllib.parse import urljoin, quote, urlencode
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from .logger import logger
from .url_resolver import URLResolver
from .drm_key_manager import KeyConfiguration
from .representation_blocklist import RepresentationBlocklist
from .video_quality import VideoQualityFilter, VideoRepresentation
from .time_utils import parse_iso_duration
from ..models.drm.constants import DRM_SYSTEM_NAMES


class MPDRewriter:
    MPD_NAMESPACE = {"mpd": "urn:mpeg:dash:schema:mpd:2011"}
    CENC_NAMESPACE = {"cenc": "urn:mpeg:cenc:2013"}

    # Derive from shared DRM constants — format raw hex UUID as urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    _ck_hex = DRM_SYSTEM_NAMES["CLEARKEY"]  # e2719d58a985b3c9781ab030af78d30e
    CLEARKEY_SCHEME_URI = (
        f"urn:uuid:{_ck_hex[0:8]}-{_ck_hex[8:12]}-{_ck_hex[12:16]}-{_ck_hex[16:20]}-{_ck_hex[20:32]}"
    )

    def __init__(
            self,
            media_proxy_url: str,
            provider_proxy_url: Optional[str] = None,
            clearkey_keyids: Optional[dict] = None,
            highest_quality_video_only: bool = False,
            provider: Optional[str] = None,
            channel: Optional[str] = None,
            blocklist_path: str = "representation_blocklist.json",
            clearkey_receiver_side: bool = False,
    ):
        self.media_proxy_url = media_proxy_url.rstrip("/")
        self.provider_proxy_url = provider_proxy_url
        self.key_config = KeyConfiguration(clearkey_keyids or {})
        self.highest_quality_video_only = highest_quality_video_only
        self.clearkey_receiver_side = clearkey_receiver_side

        if self.clearkey_receiver_side and not self.key_config.keys:
            logger.warning(
                "clearkey_receiver_side=True but no keys provided; receiver will have no keys to decrypt with")

        # Blocklist configuration
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
            kid: Optional[str] = None,
            representation_id: Optional[str] = None,
    ) -> str:
        params = {"url": original_url, **self._static_params}

        if self.key_config.keys and is_encrypted and not self.clearkey_receiver_side:
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
                    # Fallback to first key
                    if segment_type == "initialization":
                        params["kid"] = self.key_config.default_kid
                    elif segment_type == "media":
                        params["key"] = self.key_config.default_key
                    else:
                        params["kid"] = self.key_config.default_kid
                        params["key"] = self.key_config.default_key
                    logger.warning(f"No KID provided for encrypted segment, using fallback key")

        encoded = self.encode_url(urlencode(params))
        decrypt_server_side = self.key_config.keys and is_encrypted and not self.clearkey_receiver_side
        endpoint = "decrypt" if decrypt_server_side else "proxy"
        proxy_url = f"{self.media_proxy_url}/api/{endpoint}/{encoded}"

        if template_pattern:
            # Substitute $RepresentationID$ if we have it and highest_quality_video_only is enabled
            if self.highest_quality_video_only and representation_id and "$RepresentationID$" in template_pattern:
                template_pattern = template_pattern.replace("$RepresentationID$", representation_id)

            proxy_url += f"/{quote(template_pattern, safe='.-_$')}"

        return proxy_url

    def rewrite_mpd(self, mpd_content: str, manifest_url: str) -> str:
        try:
            root = ET.fromstring(mpd_content)
            ET.register_namespace("", self.MPD_NAMESPACE["mpd"])
            ET.register_namespace("cenc", self.CENC_NAMESPACE["cenc"])

            # Extract MPD-level base URL using shared utility
            mpd_base_url = self._extract_mpd_base_url(root, manifest_url)

            # Single-pass tree preparation with BaseURL extraction
            encrypted_ids, as_id_to_kid, base_url_map = self._prepare_tree_and_extract_kids(root, mpd_base_url)

            # FIRST: Filter out encrypted AdaptationSets without available keys.
            # Only applies to server-side decrypt mode — we can only decrypt what
            # we have keys for, so remove sets whose KID we don't have a key for.
            #
            # Proxy-only mode (no keys): pass everything through unchanged.
            # The proxy just forwards bytes; the player uses its own DRM stack
            # (Widevine/PlayReady) to decrypt. Stripping encrypted sets in proxy
            # mode would break multi-period manifests where the main content is
            # encrypted and only a short free bumper is unencrypted.
            #
            # Receiver-side clearkey (keys + clearkey_receiver_side): keep all
            # sets; receiver will decrypt using injected keys.
            if self.key_config.keys and not self.clearkey_receiver_side:
                # Server-side decrypt: remove sets we can't decrypt
                self._remove_adaptationsets_without_keys(root, as_id_to_kid)

            # SECOND: Filter out blocked representations that cause 500 errors
            if self.provider and self.channel:
                self._remove_blocked_representations(root)

            # THEN: Filter to highest quality video from remaining decryptable content
            best_video_info = None
            if self.highest_quality_video_only:
                best_video_info = VideoQualityFilter.find_best_video(root)
                if best_video_info:
                    logger.info(
                        f"Filtered to highest quality video: {best_video_info.width}x{best_video_info.height} "
                        f"@ {best_video_info.bandwidth}bps, RepID={best_video_info.representation_id}"
                    )

                    # Remove all other video representations, keep only the best one
                    self._filter_to_single_best_video(root, best_video_info)

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

    def _filter_to_single_best_video(self, root: ET.Element, best_video: VideoRepresentation):
        """
        Remove all video representations except the best one.
        Keeps audio/subtitles unchanged.
        """
        removal_count = 0
        adaptation_sets_to_remove = []

        for period in root.findall(".//mpd:Period", self.MPD_NAMESPACE):
            period_id = period.get("id", "")

            for adaptation_set in period.findall("mpd:AdaptationSet", self.MPD_NAMESPACE):
                if not VideoQualityFilter.is_video_adaptation_set(adaptation_set):
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
        for period in root.findall(".//mpd:Period", self.MPD_NAMESPACE):
            for adaptation_set in list(period.findall("mpd:AdaptationSet", self.MPD_NAMESPACE)):
                if adaptation_set in adaptation_sets_to_remove:
                    period.remove(adaptation_set)

        logger.info(f"Removed {removal_count} video representation(s), kept highest quality only")

        # Clean up SupplementalProperty elements that reference removed AdaptationSet IDs.
        # These are used for codec-switching hints (e.g. AVC↔HEVC) and become dangling
        # after we discard all but one video AdaptationSet.
        self._cleanup_codec_switch_properties(root)

    def _cleanup_codec_switch_properties(self, root: ET.Element):
        """Remove or update SupplementalProperty elements for codec switching."""
        CODEC_SWITCH_SCHEME = "urn:mpeg:dash:adaptation-set-switching:2016"

        # Collect all surviving AdaptationSet IDs
        surviving_as_ids: Set[str] = set()
        for period in root.findall(".//mpd:Period", self.MPD_NAMESPACE):
            for adaptation_set in period.findall("mpd:AdaptationSet", self.MPD_NAMESPACE):
                as_id = adaptation_set.get("id")
                if as_id:
                    surviving_as_ids.add(as_id)

        # Clean up SupplementalProperty elements
        for period in root.findall(".//mpd:Period", self.MPD_NAMESPACE):
            for adaptation_set in period.findall("mpd:AdaptationSet", self.MPD_NAMESPACE):
                for sp in list(adaptation_set.findall("mpd:SupplementalProperty", self.MPD_NAMESPACE)):
                    if sp.get("schemeIdUri") == CODEC_SWITCH_SCHEME:
                        raw_value = sp.get("value", "")
                        # Keep only IDs that still exist in the tree
                        kept = [
                            v.strip()
                            for v in raw_value.split(",")
                            if v.strip() in surviving_as_ids
                        ]
                        if not kept:
                            # No surviving peers — remove the property entirely
                            adaptation_set.remove(sp)
                        else:
                            sp.set("value", ",".join(kept))

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
                period_base_url = self._urljoin_preserve_query(mpd_base_url, period_base_text)
                logger.debug(f"Period {period_id} BaseURL: {period_base_url}")

                # Store period-level base URL in base_url_map with a special key
                period_key = f"period_{period_id}" if period_id else "period_root"
                base_url_map[period_key] = period_base_url

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
                    as_base_url = self._urljoin_preserve_query(period_base_url, as_base_text)
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

                # Handle ContentProtection elements based on mode:
                #   - server-side decrypt: strip all (player sees plain stream)
                #   - receiver-side clearkey: replace with ClearKey signaling so player can decrypt
                #   - proxy-only (no keys): preserve as-is so player can handle DRM itself
                if self.key_config.keys and not self.clearkey_receiver_side:
                    # Server-side decrypt mode: strip everything
                    for cp in list(adaptation_set.findall("mpd:ContentProtection", self.MPD_NAMESPACE)):
                        adaptation_set.remove(cp)
                    for representation in adaptation_set.findall("mpd:Representation", self.MPD_NAMESPACE):
                        for cp in list(representation.findall("mpd:ContentProtection", self.MPD_NAMESPACE)):
                            representation.remove(cp)

                elif self.clearkey_receiver_side and has_content_protection:
                    # Receiver-side clearkey mode: strip original DRM signaling, inject ClearKey
                    for cp in list(adaptation_set.findall("mpd:ContentProtection", self.MPD_NAMESPACE)):
                        adaptation_set.remove(cp)
                    for representation in adaptation_set.findall("mpd:Representation", self.MPD_NAMESPACE):
                        for cp in list(representation.findall("mpd:ContentProtection", self.MPD_NAMESPACE)):
                            representation.remove(cp)

                    # Inject ClearKey ContentProtection element
                    kid = as_id_to_kid.get(unique_id)
                    self._inject_clearkey_content_protection(adaptation_set, kid)

                # else: proxy-only, no keys — leave ContentProtection untouched

        return encrypted_ids, as_id_to_kid, base_url_map

    def _extract_kid_from_adaptationset(self, adaptation_set: ET.Element) -> Optional[str]:
        """Extract KID from ContentProtection elements in an AdaptationSet."""
        # Try cenc:default_KID first
        for cp in adaptation_set.findall("mpd:ContentProtection", self.MPD_NAMESPACE):
            default_kid = cp.get("{urn:mpeg:cenc:2013}default_KID")
            if default_kid:
                normalized = default_kid.replace("-", "").lower()
                logger.debug(f"Extracted KID from default_KID attribute: {normalized}")
                return normalized

        # Try PSSH box
        for cp in adaptation_set.findall("mpd:ContentProtection", self.MPD_NAMESPACE):
            pssh_elem = cp.find("cenc:pssh", self.CENC_NAMESPACE)
            if pssh_elem is not None and pssh_elem.text:
                try:
                    pssh_data = base64.b64decode(pssh_elem.text)
                    logger.debug(f"PSSH box size: {len(pssh_data)} bytes")

                    if len(pssh_data) >= 36:
                        version = pssh_data[8] if len(pssh_data) > 8 else 0
                        system_id = pssh_data[12:28].hex() if len(pssh_data) >= 28 else "unknown"
                        logger.debug(f"PSSH version: {version}, System ID: {system_id}")

                        if version > 0:
                            kid_count = struct.unpack(">I", pssh_data[28:32])[0]
                            logger.debug(f"KID count from header: {kid_count}")

                            if kid_count > 0 and len(pssh_data) >= 48:
                                kid_bytes = pssh_data[32:48]
                                kid_hex = kid_bytes.hex().lower()
                                logger.debug(f"Extracted KID from PSSH header: {kid_hex}")
                                return kid_hex
                except Exception as e:
                    logger.debug(f"Error extracting KID from PSSH: {e}")

        return None

    def _inject_clearkey_content_protection(self, adaptation_set: ET.Element, kid: Optional[str]):
        """
        Inject a ClearKey ContentProtection element so the receiver can decrypt.

        If a KID is available (extracted from the original ContentProtection), it is
        formatted as a UUID and set as cenc:default_KID. Otherwise only the scheme URI
        is signaled and the receiver must derive the KID from the stream itself.
        """
        ET.register_namespace("cenc", "urn:mpeg:cenc:2013")

        attribs = {"schemeIdUri": self.CLEARKEY_SCHEME_URI}

        if kid:
            # Format 32-char hex KID as UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
            kid_uuid = f"{kid[0:8]}-{kid[8:12]}-{kid[12:16]}-{kid[16:20]}-{kid[20:32]}"
            attribs["{urn:mpeg:cenc:2013}default_KID"] = kid_uuid
            logger.debug(f"Injecting ClearKey ContentProtection with KID={kid_uuid}")
        else:
            logger.debug("Injecting ClearKey ContentProtection without KID (not found in original)")

        cp_elem = ET.Element("ContentProtection", attribs)
        # Insert at the front of the AdaptationSet so players encounter it early
        adaptation_set.insert(0, cp_elem)

    def _remove_adaptationsets_without_keys(self, root: ET.Element, as_id_to_kid: Dict[str, str]):
        """Remove encrypted AdaptationSets for which we don't have keys."""
        removed_count = 0

        # Debug: Log what keys we have
        logger.debug(f"Available keys: {list(self.key_config.keys.keys())}")

        for period in root.findall(".//mpd:Period", self.MPD_NAMESPACE):
            period_id = period.get("id", "")
            adaptationsets_to_remove = []

            for adaptation_set in period.findall("mpd:AdaptationSet", self.MPD_NAMESPACE):
                as_id = adaptation_set.get("id", str(id(adaptation_set)))
                unique_id = f"{period_id}_{as_id}" if period_id else as_id

                if unique_id in as_id_to_kid:
                    kid = as_id_to_kid[unique_id]
                    if kid not in self.key_config.keys:
                        logger.warning(
                            f"Removing AdaptationSet {unique_id} - "
                            f"missing key for KID: {kid[:8]}..."
                        )
                        adaptationsets_to_remove.append(adaptation_set)
                        removed_count += 1

            for adaptation_set in adaptationsets_to_remove:
                period.remove(adaptation_set)

        if removed_count > 0:
            logger.info(f"Removed {removed_count} AdaptationSet(s) without available keys")

    def _remove_blocked_representations(self, root: ET.Element):
        """Remove representations that are blocklisted for this provider/channel."""
        blocked_ids = self.blocklist.get_blocked_ids(self.provider, self.channel)

        if not blocked_ids:
            return

        logger.info(
            f"Applying representation blocklist for {self.provider}/{self.channel}: "
            f"{len(blocked_ids)} representation(s) blocked"
        )

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
            best_video_info: Optional[VideoRepresentation] = None,
    ):
        """Recursive node rewriter with KID-aware key selection and context-aware base URLs."""
        # Track period ID as we traverse
        if element.tag.endswith("Period"):
            current_period_id = element.get("id", "")

            # When entering a new period, check if we have a period-level base URL stored
            period_key = f"period_{current_period_id}" if current_period_id else "period_root"
            if period_key in base_url_map:
                # Update base_url to the period-specific base URL
                base_url = base_url_map[period_key]
                logger.debug(f"Period {current_period_id} using stored base URL: {base_url}")

            # Process all children of this period
            for child in list(element):
                self._rewrite_node(
                    child, base_url, encrypted_ids, as_id_to_kid, base_url_map,
                    current_encrypted, current_kid, current_period_id, best_video_info
                )
            return  # Don't process further - we've handled all children

        # Track representation ID for template substitution
        current_rep_id = None
        if element.tag.endswith("Representation"):
            current_rep_id = element.get("id", "")

        # Update state when entering an AdaptationSet
        if element.tag.endswith("AdaptationSet"):
            as_id = element.get("id", str(id(element)))
            # Use same unique ID logic as _prepare_tree_and_extract_kids
            unique_id = f"{current_period_id}_{as_id}" if current_period_id else as_id
            current_encrypted = unique_id in encrypted_ids

            # Update base_url to the AdaptationSet-specific base URL
            if unique_id in base_url_map:
                base_url = base_url_map[unique_id]
                logger.debug(f"AdaptationSet {unique_id} using stored base URL: {base_url}")

            # Get specific KID for this AdaptationSet (multi-key mode only)
            if current_encrypted and not self.key_config.single_key_mode:
                current_kid = as_id_to_kid.get(unique_id)

        # Handle BaseURL elements - THESE MUST BE REWRITTEN TO PROXY URLS
        if element.tag.endswith("BaseURL") and element.text:
            raw_url = element.text.strip()
            if raw_url:
                # Resolve the relative BaseURL against the current base
                resolved_cdn_url = self._urljoin_preserve_query(base_url, raw_url)
                logger.debug(f"Rewriting BaseURL: {raw_url} -> {resolved_cdn_url}")

                # Rewrite the BaseURL text to a proxy URL
                # In receiver-side clearkey mode, this will use /api/proxy/
                element.text = self.build_proxy_url(
                    resolved_cdn_url, None, None,
                    current_encrypted, current_kid,
                    representation_id=current_rep_id
                )
                logger.debug(f"Proxied BaseURL: {element.text}")

        # ------------------------------------------------------------------
        # Standard SegmentTemplate / SegmentList attribute rewriting.
        # Handles media/initialization/sourceURL attributes on SegmentTemplate,
        # SegmentList, etc.
        #
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

                resolved = self._urljoin_preserve_query(base_url, val)
                if "$" in resolved:
                    # Use shared utility for splitting template URLs
                    path, pattern = URLResolver.split_template_url(resolved)
                    element.attrib[attr] = self.build_proxy_url(
                        path, pattern, seg_type, current_encrypted, current_kid,
                        representation_id=current_rep_id
                    )
                else:
                    element.attrib[attr] = self.build_proxy_url(
                        resolved, None, seg_type, current_encrypted, current_kid,
                        representation_id=current_rep_id
                    )

        # Handle SegmentURL (always 'media' type)
        if element.tag.endswith("SegmentURL") and "media" in element.attrib:
            resolved = self._urljoin_preserve_query(base_url, element.attrib["media"])
            path, pattern = (
                URLResolver.split_template_url(resolved)
                if "$" in resolved
                else (resolved, None)
            )
            element.attrib["media"] = self.build_proxy_url(
                path, pattern, "media", current_encrypted, current_kid,
                representation_id=current_rep_id
            )

        # Recurse to children
        for child in element:
            self._rewrite_node(
                child, base_url, encrypted_ids, as_id_to_kid, base_url_map,
                current_encrypted, current_kid, current_period_id, best_video_info
            )

    @staticmethod
    def _urljoin_preserve_query(base: str, url: str) -> str:
        """
        Like urljoin(base, url) but preserves the query string of *base* when
        the relative *url* itself carries no query string.

        Why this is needed:
          Some CDNs (e.g. Discovery+/Max) embed the auth token in the manifest
          URL's query string (e.g. ?manifest-params=…).  The segment paths
          inside such manifests are plain relative paths like "v/0_9cd1a5/v13.mp4"
          with no query component.  Standard urljoin() discards the base query
          string when joining with a relative path (RFC 3986 §5.3 – correct
          behaviour in general, wrong here).  The CDN requires the same token on
          every segment request, so we must re-append it.

        Rules (mirrors RFC 3986 §5.3 reference-resolution):
          - If *url* is absolute (has a scheme) → plain urljoin, no query merging.
          - If *url* already has its own query string → plain urljoin; the
            relative URL's query takes full precedence.
          - If *url* has no query string and *base* does → urljoin then re-attach
            base's query string to the result.
        """
        from urllib.parse import urlparse, urlunparse

        parsed_url = urlparse(url)

        # Absolute URL: standard behaviour, no query merging.
        if parsed_url.scheme:
            return urljoin(base, url)

        # URL contains $ template variables (e.g. $RepresentationID$, $Number$):
        # these are SegmentTemplate patterns that manage their own query strings.
        # Never re-attach the base query — it would be injected into the middle of
        # the template pattern and corrupt the CDN URL the proxy encodes.
        if "$" in url:
            return urljoin(base, url)

        # URL already has its own query string — it takes full precedence.
        if parsed_url.query:
            return urljoin(base, url)

        joined = urljoin(base, url)

        # Re-attach the base query string if it has one and the result lost it.
        # This handles CDNs that embed auth tokens in the manifest URL query string
        # (e.g. ?manifest-params=...) which must be forwarded to every segment URL.
        base_query = urlparse(base).query
        if base_query:
            parsed_joined = urlparse(joined)
            if not parsed_joined.query:
                # urlunparse is typed as returning str | bytes depending on input;
                # our inputs are always str so cast to make the type checker happy.
                joined = str(urlunparse(parsed_joined._replace(query=base_query)))

        return joined

    def _extract_mpd_base_url(self, root: ET.Element, manifest_url: str) -> str:
        """
        Extract and resolve MPD-level BaseURL.
        Uses shared URLResolver utility.
        """
        base_url_elem = root.find("mpd:BaseURL", self.MPD_NAMESPACE)
        base_url_text = None

        if base_url_elem is not None and base_url_elem.text:
            base_url_text = base_url_elem.text.strip()

        # Use shared utility - it handles special service prefixes.
        # Note: URLResolver intentionally strips the manifest URL's query string
        # when deriving the base directory URL. This is correct — query strings
        # like ?manifest-params= are only for the .mpd fetch itself and must NOT
        # be forwarded to segment requests.
        return URLResolver.resolve_base_url_with_element(manifest_url, base_url_text)

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
                    return parse_iso_duration(update_period)
        except Exception:
            pass
        return None