# streaming_providers/base/utils/mpd_rewriter.py
import base64
import xml.etree.ElementTree as ET
from typing import Optional, Tuple, Set
from urllib.parse import urljoin, urlparse, quote

from .logger import logger


class MPDRewriter:
    """
    Utility for rewriting MPD (MPEG-DASH) manifest URLs to point to media proxy endpoints

    Strategy:
    - Remove all BaseURL elements
    - Convert all relative URLs to absolute URLs
    - Rewrite all absolute URLs to media proxy endpoint
    - Keep template variables visible for client-side substitution
    - When decrypting: Remove ContentProtection and only add keys to encrypted segments
    """

    # MPD namespace
    MPD_NAMESPACE = {"mpd": "urn:mpeg:dash:schema:mpd:2011"}

    def __init__(self, media_proxy_url: str, provider_proxy_url: Optional[str] = None,
                 clearkey_keyids: Optional[dict] = None):
        """
        Initialize MPD rewriter

        Args:
            media_proxy_url: Base URL of the media proxy service (e.g., http://10.77.77.7:7775)
            provider_proxy_url: Optional proxy URL for the provider (e.g., http://nordlynx_germany:8888)
            clearkey_keyids: Optional dict of kid:key pairs for decrypted playback
        """
        self.media_proxy_url = media_proxy_url.rstrip("/")
        self.provider_proxy_url = provider_proxy_url
        self.clearkey_keyids = clearkey_keyids or {}
        self.encrypted_adaptation_sets: Set[str] = set()

    @staticmethod
    def encode_url(url: str) -> str:
        """
        Encode URL to base64 for use in media proxy endpoint.
        Strips padding as required by media proxy.
        """
        encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8")
        # Strip padding
        return encoded.rstrip("=")

    @staticmethod
    def decode_url(encoded: str) -> str:
        """
        Decode base64 URL from media proxy endpoint.
        Adds back padding if needed.
        """
        # Add back padding if needed
        padding = 4 - (len(encoded) % 4)
        if padding != 4:
            encoded += "=" * padding
        return base64.urlsafe_b64decode(encoded.encode("utf-8")).decode("utf-8")

    def build_proxy_url(self, original_url: str, template_pattern: Optional[str] = None,
                        segment_type: Optional[str] = None, is_encrypted: bool = True) -> str:
        """
        Build media proxy URL for an original media URL

        Args:
            original_url: Original URL to be proxied (base path for templates)
            template_pattern: Optional template pattern to append (e.g., "segment-$Number$.m4s")
            segment_type: Optional segment type ('initialization' or 'media') for selective DRM params
            is_encrypted: Whether the segment is encrypted (has ContentProtection)

        Returns:
            Media proxy URL
        """
        encoded = self.encode_url(original_url)

        # Choose endpoint based on whether we have clearkey data AND segment is encrypted
        if self.clearkey_keyids and is_encrypted:
            proxy_url = f"{self.media_proxy_url}/api/decrypt/{encoded}"
        else:
            proxy_url = f"{self.media_proxy_url}/api/proxy/{encoded}"

        # Append template pattern if provided (keeps variables visible for client)
        if template_pattern:
            # URL encode the template pattern (same as current behavior)
            encoded_pattern = quote(template_pattern, safe=".-_$")
            proxy_url += f"/{encoded_pattern}"

        # Build query parameters
        query_params = []

        # Add clearkey parameters ONLY if present AND segment is encrypted
        if self.clearkey_keyids and is_encrypted:
            for kid, key in self.clearkey_keyids.items():
                # Initialization segments: only add kid
                # Media segments: only add key
                # Unknown/unspecified: add both (backward compatible)
                if segment_type == 'initialization':
                    query_params.append(f"kid={kid}")
                elif segment_type == 'media':
                    query_params.append(f"key={key}")
                else:
                    # Default behavior: add both
                    query_params.append(f"kid={kid}")
                    query_params.append(f"key={key}")

        # Add provider proxy parameter if configured (always, for all segments)
        if self.provider_proxy_url:
            query_params.append(f"proxy={self.provider_proxy_url}")

        # Append query string if we have parameters
        if query_params:
            proxy_url += "?" + "&".join(query_params)

        return proxy_url

    @staticmethod
    def split_template_url(url: str) -> Tuple[str, Optional[str]]:
        """
        Split a URL with template variables into base path and template pattern

        Args:
            url: URL potentially containing template variables (e.g., $Number$)

        Returns:
            Tuple of (base_path, template_pattern)
            - base_path: URL up to the last slash before any template variable
            - template_pattern: Path with template variables, or None if no templates
        """
        if "$" not in url:
            return url, None

        # Find the position of the first template variable
        first_template_pos = url.find("$")

        # Find the last slash BEFORE the first template variable
        last_slash_before_template = url.rfind("/", 0, first_template_pos)

        if last_slash_before_template == -1:
            # No slash found before template, entire URL is template (unusual but handle it)
            return "", url

        base_path = url[:last_slash_before_template]
        template_pattern = url[last_slash_before_template + 1:]

        return base_path, template_pattern

    def rewrite_mpd(self, mpd_content: str, manifest_url: str) -> str:
        """
        Rewrite MPD content to use media proxy URLs

        Strategy:
        1. Parse MPD XML
        2. Extract and remove all BaseURL elements
        3. If decrypting: Identify encrypted AdaptationSets before removing ContentProtection
        4. If decrypting: Remove ContentProtection elements
        5. Resolve all relative URLs to absolute using BaseURLs and manifest URL
        6. Rewrite all absolute URLs to media proxy endpoints
        7. Keep template variables visible for client substitution

        Args:
            mpd_content: Original MPD XML content
            manifest_url: URL where the manifest was fetched from (for relative URL resolution)

        Returns:
            Rewritten MPD XML content
        """
        try:
            # Parse XML
            root = ET.fromstring(mpd_content)

            # Register namespace to preserve it in output
            ET.register_namespace("", self.MPD_NAMESPACE["mpd"])

            # Get base URL for relative resolution
            base_url = self._extract_base_url(root, manifest_url)

            # Remove all BaseURL elements
            self._remove_base_urls(root)

            # If we're in decryption mode, identify encrypted AdaptationSets first
            if self.clearkey_keyids:
                self._identify_encrypted_adaptation_sets(root)
                logger.debug(f"Identified {len(self.encrypted_adaptation_sets)} encrypted AdaptationSets")

                # Then remove ContentProtection elements
                self._remove_content_protection(root)
                logger.debug("Removed ContentProtection elements for decrypted playback")

            # Rewrite all URLs in the MPD
            self._rewrite_urls_recursive(root, base_url)

            # Convert back to string
            rewritten = ET.tostring(root, encoding="unicode", method="xml")

            # Add XML declaration if not present
            if not rewritten.startswith("<?xml"):
                rewritten = '<?xml version="1.0" encoding="UTF-8"?>\n' + rewritten

            logger.debug(f"Successfully rewrote MPD for media proxy")
            return rewritten

        except ET.ParseError as e:
            logger.error(f"Failed to parse MPD XML: {e}")
            raise ValueError(f"Invalid MPD XML: {e}")
        except Exception as e:
            logger.error(f"Failed to rewrite MPD: {e}")
            raise

    def _extract_base_url(self, root: ET.Element, manifest_url: str) -> str:
        """
        Extract base URL from MPD or use manifest URL

        Priority:
        1. First BaseURL element in MPD (resolved relative to manifest URL if relative)
        2. Manifest URL's directory

        Args:
            root: MPD root element
            manifest_url: URL where manifest was fetched

        Returns:
            Base URL for resolving relative URLs
        """
        # Try to find BaseURL element
        base_url_elem = root.find(".//mpd:BaseURL", self.MPD_NAMESPACE)
        if base_url_elem is not None and base_url_elem.text:
            base_url_text = base_url_elem.text.strip()

            # Check if the BaseURL is relative (doesn't start with http:// or https://)
            if not base_url_text.startswith(("http://", "https://")):
                # It's a relative BaseURL, resolve it against the manifest URL's directory
                parsed_manifest = urlparse(manifest_url)
                manifest_dir = f"{parsed_manifest.scheme}://{parsed_manifest.netloc}{parsed_manifest.path.rsplit('/', 1)[0]}/"
                resolved_base = urljoin(manifest_dir, base_url_text)
                logger.debug(f"Resolved relative BaseURL '{base_url_text}' to: {resolved_base}")
                return resolved_base
            else:
                # It's already an absolute URL
                logger.debug(f"Using absolute BaseURL from MPD: {base_url_text}")
                return base_url_text

        # Fall back to manifest URL directory
        parsed = urlparse(manifest_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rsplit('/', 1)[0]}/"
        logger.debug(f"Using manifest URL directory as base: {base_url}")
        return base_url

    def _remove_base_urls(self, root: ET.Element) -> None:
        """
        Remove all BaseURL elements from MPD

        Args:
            root: MPD root element
        """
        # Find all BaseURL elements at any level
        for parent in root.findall(".//*"):
            for base_url_elem in list(parent.findall("mpd:BaseURL", self.MPD_NAMESPACE)):
                parent.remove(base_url_elem)
                logger.debug("Removed BaseURL element")

    def _identify_encrypted_adaptation_sets(self, root: ET.Element) -> None:
        """
        Identify and track which AdaptationSets have ContentProtection
        Must be called BEFORE removing ContentProtection elements

        Args:
            root: MPD root element
        """
        # Find all AdaptationSet elements
        for adaptation_set in root.findall(".//mpd:AdaptationSet", self.MPD_NAMESPACE):
            # Check if this AdaptationSet has ContentProtection
            if adaptation_set.findall("mpd:ContentProtection", self.MPD_NAMESPACE):
                # Get AdaptationSet ID for tracking
                as_id = adaptation_set.get("id", id(adaptation_set))  # Use object id as fallback
                self.encrypted_adaptation_sets.add(str(as_id))
                logger.debug(f"AdaptationSet id={as_id} is encrypted")

    def _remove_content_protection(self, root: ET.Element) -> None:
        """
        Remove all ContentProtection elements from MPD
        Called when serving decrypted content

        Args:
            root: MPD root element
        """
        # Find all ContentProtection elements at any level
        for parent in root.findall(".//*"):
            for cp_elem in list(parent.findall("mpd:ContentProtection", self.MPD_NAMESPACE)):
                parent.remove(cp_elem)
                logger.debug("Removed ContentProtection element")

    def _is_element_in_encrypted_adaptation_set(self, element: ET.Element, root: ET.Element) -> bool:
        """
        Check if an element is within an encrypted AdaptationSet

        Args:
            element: Current element
            root: MPD root element

        Returns:
            True if element is within an encrypted AdaptationSet
        """
        # Find the parent AdaptationSet
        # We need to walk up the tree to find it
        # Since ElementTree doesn't support parent traversal easily,
        # we'll search from root to find the AdaptationSet containing this element

        for adaptation_set in root.findall(".//mpd:AdaptationSet", self.MPD_NAMESPACE):
            # Check if element is a descendant of this AdaptationSet
            if self._is_descendant(adaptation_set, element):
                as_id = adaptation_set.get("id", id(adaptation_set))
                return str(as_id) in self.encrypted_adaptation_sets

        # Not in any AdaptationSet (shouldn't happen in valid MPD)
        return False

    @staticmethod
    def _is_descendant(parent: ET.Element, element: ET.Element) -> bool:
        """
        Check if element is a descendant of parent

        Args:
            parent: Potential parent element
            element: Element to check

        Returns:
            True if element is a descendant of parent
        """
        for child in parent.iter():
            if child is element:
                return True
        return False

    def _rewrite_urls_recursive(self, element: ET.Element, base_url: str, root: Optional[ET.Element] = None) -> None:
        """
        Recursively rewrite all URLs in MPD element tree

        Args:
            element: Current XML element
            base_url: Base URL for resolving relative URLs
            root: MPD root element (for checking encrypted AdaptationSets)
        """
        # Store root on first call
        if root is None:
            root = element

        # Determine if this element is in an encrypted AdaptationSet
        is_encrypted = False
        if self.clearkey_keyids:
            is_encrypted = self._is_element_in_encrypted_adaptation_set(element, root)

        # Determine segment type based on attribute name
        segment_type_map = {
            'initialization': 'initialization',
            'media': 'media',
            'sourceURL': None,  # Could be either, keep default
        }

        # Rewrite URL attributes in current element
        for attr in ['media', 'initialization', 'sourceURL']:
            if attr in element.attrib:
                original_url = element.attrib[attr]

                if not original_url:
                    continue

                # Determine segment type for selective DRM params
                segment_type = segment_type_map.get(attr)

                # Resolve to absolute URL first
                resolved = urljoin(base_url, original_url)

                # Check if URL contains template variables
                if "$" in resolved:
                    # Split into base path and template pattern
                    base_path, template_pattern = self.split_template_url(resolved)
                    element.attrib[attr] = self.build_proxy_url(
                        base_path, template_pattern, segment_type, is_encrypted
                    )
                    logger.debug(
                        f"Rewrote template URL ({attr}, encrypted={is_encrypted}): {original_url} -> media proxy"
                    )
                else:
                    # Regular URL without templates
                    element.attrib[attr] = self.build_proxy_url(
                        resolved, None, segment_type, is_encrypted
                    )
                    logger.debug(f"Rewrote URL ({attr}, encrypted={is_encrypted}): {original_url} -> media proxy")

        # Handle SegmentURL elements (used in SegmentList)
        if element.tag.endswith("SegmentURL"):
            if "media" in element.attrib:
                original_url = element.attrib["media"]
                resolved = urljoin(base_url, original_url)

                # SegmentURL media is always a media segment
                if "$" in resolved:
                    base_path, template_pattern = self.split_template_url(resolved)
                    element.attrib["media"] = self.build_proxy_url(
                        base_path, template_pattern, 'media', is_encrypted
                    )
                else:
                    element.attrib["media"] = self.build_proxy_url(
                        resolved, None, 'media', is_encrypted
                    )

        # Recurse to child elements
        for child in element:
            self._rewrite_urls_recursive(child, base_url, root)

    @staticmethod
    def extract_cache_ttl(headers: dict) -> int:
        """
        Extract cache TTL from HTTP response headers

        Priority:
        1. Cache-Control: max-age=X
        2. Expires header
        3. Default to 300 seconds (5 minutes)

        Args:
            headers: HTTP response headers dict

        Returns:
            Cache TTL in seconds
        """
        # Check Cache-Control header
        cache_control = headers.get("Cache-Control", headers.get("cache-control", ""))
        if "max-age=" in cache_control:
            try:
                # Extract max-age value
                for directive in cache_control.split(","):
                    directive = directive.strip()
                    if directive.startswith("max-age="):
                        max_age = int(directive.split("=")[1])
                        logger.debug(f"Cache TTL from Cache-Control: {max_age}s")
                        return max_age
            except (ValueError, IndexError) as e:
                logger.warning(f"Failed to parse max-age from Cache-Control: {e}")

        # Check Expires header
        expires = headers.get("Expires", headers.get("expires"))
        if expires:
            try:
                from datetime import datetime, timezone
                from email.utils import parsedate_to_datetime

                expires_dt = parsedate_to_datetime(expires)
                now = datetime.now(timezone.utc)
                ttl = int((expires_dt - now).total_seconds())

                if ttl > 0:
                    logger.debug(f"Cache TTL from Expires: {ttl}s")
                    return ttl
            except Exception as e:
                logger.warning(f"Failed to parse Expires header: {e}")

        # Default TTL
        default_ttl = 300
        logger.debug(f"Using default cache TTL: {default_ttl}s")
        return default_ttl

    @staticmethod
    def extract_mpd_update_period(mpd_content: str) -> Optional[int]:
        """
        Extract minimumUpdatePeriod from MPD as fallback TTL

        Args:
            mpd_content: MPD XML content

        Returns:
            Update period in seconds, or None if not found/applicable
        """
        try:
            root = ET.fromstring(mpd_content)

            # Check if dynamic manifest
            mpd_type = root.attrib.get("type", "static")
            if mpd_type != "dynamic":
                return None

            # Get minimumUpdatePeriod
            update_period = root.attrib.get("minimumUpdatePeriod")
            if update_period:
                # Parse ISO 8601 duration (e.g., "PT5S" = 5 seconds)
                return MPDRewriter._parse_iso_duration(update_period)

        except Exception as e:
            logger.debug(f"Could not extract MPD update period: {e}")

        return None

    @staticmethod
    def _parse_iso_duration(duration: str) -> int:
        """
        Parse ISO 8601 duration to seconds

        Supports formats like: PT5S, PT1M30S, PT1H

        Args:
            duration: ISO 8601 duration string

        Returns:
            Duration in seconds
        """
        import re

        # Remove PT prefix
        duration = duration.replace("PT", "")

        # Parse hours, minutes, seconds
        hours = minutes = seconds = 0

        h_match = re.search(r"(\d+)H", duration)
        if h_match:
            hours = int(h_match.group(1))

        m_match = re.search(r"(\d+)M", duration)
        if m_match:
            minutes = int(m_match.group(1))

        s_match = re.search(r"(\d+(?:\.\d+)?)S", duration)
        if s_match:
            seconds = float(s_match.group(1))

        total_seconds = int(hours * 3600 + minutes * 60 + seconds)
        logger.debug(f"Parsed ISO duration '{duration}' to {total_seconds}s")
        return total_seconds