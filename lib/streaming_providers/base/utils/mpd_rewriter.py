# streaming_providers/base/utils/mpd_rewriter.py
import xml.etree.ElementTree as ET
import base64
from typing import Optional, Tuple
from urllib.parse import urljoin, urlparse
from .logger import logger


class MPDRewriter:
    """
    Utility for rewriting MPD (MPEG-DASH) manifest URLs to point to proxy endpoints

    Strategy:
    - Remove all BaseURL elements
    - Convert all relative URLs to absolute URLs
    - Rewrite all absolute URLs to proxy endpoint
    - Keep template variables visible for client-side substitution
    """

    # MPD namespace
    MPD_NAMESPACE = {'mpd': 'urn:mpeg:dash:schema:mpd:2011'}

    def __init__(self, proxy_base_url: str, provider_name: str):
        """
        Initialize MPD rewriter

        Args:
            proxy_base_url: Base URL of the proxy service (e.g., http://localhost:7777)
            provider_name: Name of the provider for proxy routing
        """
        self.proxy_base_url = proxy_base_url.rstrip('/')
        self.provider_name = provider_name

    @staticmethod
    def encode_url(url: str) -> str:
        """Encode URL to base64 for use in proxy endpoint"""
        return base64.urlsafe_b64encode(url.encode('utf-8')).decode('utf-8')

    @staticmethod
    def decode_url(encoded: str) -> str:
        """Decode base64 URL from proxy endpoint"""
        return base64.urlsafe_b64decode(encoded.encode('utf-8')).decode('utf-8')

    def build_proxy_url(self, original_url: str, template_pattern: Optional[str] = None) -> str:
        """
        Build proxy URL for an original media URL

        Args:
            original_url: Original URL to be proxied (base path for templates)
            template_pattern: Optional template pattern to append (e.g., "segment-$Number$.m4s")

        Returns:
            Proxy URL
        """
        encoded = self.encode_url(original_url)
        proxy_url = f"{self.proxy_base_url}/api/proxy/{self.provider_name}/{encoded}"

        # Append template pattern if provided (keeps variables visible for client)
        if template_pattern:
            proxy_url += f"/{template_pattern}"

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
        if '$' not in url:
            return url, None

        # Find the position of the first template variable
        first_template_pos = url.find('$')

        # Find the last slash BEFORE the first template variable
        # This handles cases like:
        # - https://cdn.com/path/segment-$Number$.m4s
        # - https://cdn.com/path/$RepresentationID$/init.mp4
        last_slash_before_template = url.rfind('/', 0, first_template_pos)

        if last_slash_before_template == -1:
            # No slash found before template, entire URL is template (unusual but handle it)
            return '', url

        base_path = url[:last_slash_before_template]
        template_pattern = url[last_slash_before_template + 1:]

        return base_path, template_pattern

    def rewrite_mpd(self, mpd_content: str, manifest_url: str) -> str:
        """
        Rewrite MPD content to use proxy URLs

        Strategy:
        1. Parse MPD XML
        2. Extract and remove all BaseURL elements
        3. Resolve all relative URLs to absolute using BaseURLs and manifest URL
        4. Rewrite all absolute URLs to proxy endpoints
        5. Keep template variables visible for client substitution

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
            ET.register_namespace('', self.MPD_NAMESPACE['mpd'])

            # Get base URL for relative resolution
            base_url = self._extract_base_url(root, manifest_url)

            # Remove all BaseURL elements (Option 3 strategy)
            self._remove_base_urls(root)

            # Rewrite all URLs in the MPD
            self._rewrite_urls_recursive(root, base_url)

            # Convert back to string
            rewritten = ET.tostring(root, encoding='unicode', method='xml')

            # Add XML declaration if not present
            if not rewritten.startswith('<?xml'):
                rewritten = '<?xml version="1.0" encoding="UTF-8"?>\n' + rewritten

            logger.debug(f"Successfully rewrote MPD for provider '{self.provider_name}'")
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
        1. First BaseURL element in MPD
        2. Manifest URL's directory

        Args:
            root: MPD root element
            manifest_url: URL where manifest was fetched

        Returns:
            Base URL for resolving relative URLs
        """
        # Try to find BaseURL element
        base_url_elem = root.find('.//mpd:BaseURL', self.MPD_NAMESPACE)
        if base_url_elem is not None and base_url_elem.text:
            base_url = base_url_elem.text.strip()
            logger.debug(f"Using BaseURL from MPD: {base_url}")
            return base_url

        # Fall back to manifest URL directory
        parsed = urlparse(manifest_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rsplit('/', 1)[0]}/"
        logger.debug(f"Using manifest URL directory as base: {base_url}")
        return base_url

    def _remove_base_urls(self, root: ET.Element) -> None:
        """
        Remove all BaseURL elements from MPD (Option 3 strategy)

        Args:
            root: MPD root element
        """
        # Find all BaseURL elements at any level
        for parent in root.findall('.//*'):
            for base_url_elem in list(parent.findall('mpd:BaseURL', self.MPD_NAMESPACE)):
                parent.remove(base_url_elem)
                logger.debug("Removed BaseURL element")

    def _rewrite_urls_recursive(self, element: ET.Element, base_url: str) -> None:
        """
        Recursively rewrite all URLs in MPD element tree

        Args:
            element: Current XML element
            base_url: Base URL for resolving relative URLs
        """
        # Attributes that contain URLs
        url_attributes = [
            'media',  # SegmentTemplate
            'initialization',  # SegmentTemplate
            'sourceURL',  # Initialization, RepresentationIndex
            'indexRange',  # SegmentBase (not a URL but can be affected)
        ]

        # Rewrite URL attributes in current element
        for attr in url_attributes:
            if attr in element.attrib:
                original_url = element.attrib[attr]

                if not original_url:
                    continue

                # Resolve to absolute URL first
                resolved = urljoin(base_url, original_url)

                # Check if URL contains template variables
                if '$' in resolved:
                    # Split into base path and template pattern
                    base_path, template_pattern = self.split_template_url(resolved)
                    element.attrib[attr] = self.build_proxy_url(base_path, template_pattern)
                    logger.debug(f"Rewrote template URL: {original_url} -> proxy with template {template_pattern}")
                else:
                    # Regular URL without templates
                    element.attrib[attr] = self.build_proxy_url(resolved)
                    logger.debug(f"Rewrote URL: {original_url} -> proxy")

        # Handle SegmentURL elements (used in SegmentList)
        if element.tag.endswith('SegmentURL'):
            if 'media' in element.attrib:
                original_url = element.attrib['media']
                resolved = urljoin(base_url, original_url)

                # SegmentURL typically doesn't have templates, but handle it just in case
                if '$' in resolved:
                    base_path, template_pattern = self.split_template_url(resolved)
                    element.attrib['media'] = self.build_proxy_url(base_path, template_pattern)
                else:
                    element.attrib['media'] = self.build_proxy_url(resolved)

        # Recurse to child elements
        for child in element:
            self._rewrite_urls_recursive(child, base_url)

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
        cache_control = headers.get('Cache-Control', headers.get('cache-control', ''))
        if 'max-age=' in cache_control:
            try:
                # Extract max-age value
                for directive in cache_control.split(','):
                    directive = directive.strip()
                    if directive.startswith('max-age='):
                        max_age = int(directive.split('=')[1])
                        logger.debug(f"Cache TTL from Cache-Control: {max_age}s")
                        return max_age
            except (ValueError, IndexError) as e:
                logger.warning(f"Failed to parse max-age from Cache-Control: {e}")

        # Check Expires header
        expires = headers.get('Expires', headers.get('expires'))
        if expires:
            try:
                from email.utils import parsedate_to_datetime
                from datetime import datetime, timezone

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
            mpd_type = root.attrib.get('type', 'static')
            if mpd_type != 'dynamic':
                return None

            # Get minimumUpdatePeriod
            update_period = root.attrib.get('minimumUpdatePeriod')
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
        duration = duration.replace('PT', '')

        # Parse hours, minutes, seconds
        hours = minutes = seconds = 0

        h_match = re.search(r'(\d+)H', duration)
        if h_match:
            hours = int(h_match.group(1))

        m_match = re.search(r'(\d+)M', duration)
        if m_match:
            minutes = int(m_match.group(1))

        s_match = re.search(r'(\d+(?:\.\d+)?)S', duration)
        if s_match:
            seconds = float(s_match.group(1))

        total_seconds = int(hours * 3600 + minutes * 60 + seconds)
        logger.debug(f"Parsed ISO duration '{duration}' to {total_seconds}s")
        return total_seconds