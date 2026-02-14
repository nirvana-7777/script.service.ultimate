# streaming_providers/base/utils/url_resolver.py
"""
Shared URL resolution utilities for manifest parsing and MPD rewriting.
Centralizes URL construction, template substitution, and base URL resolution.
"""

from typing import Optional, Tuple
from urllib.parse import urljoin, urlparse, quote


class URLResolver:
    """Handles URL resolution, template substitution, and base URL extraction for DASH manifests."""

    # Special service prefixes that require different URL handling
    SPECIAL_SERVICE_PREFIXES = [
        "https://bpcdnmanprod.nexttv.ht.hr/bpk-tv/",
        "https://lineartv-cdn.t-mobile.pl/bpk-tv/"
    ]

    @staticmethod
    def extract_manifest_base_url(manifest_url: str) -> str:
        """
        Extract the base directory URL from a manifest URL.

        Special services keep 'index.mpd' in the path, while normal services remove it.

        Args:
            manifest_url: Full URL to the manifest file

        Returns:
            Base URL with trailing slash
        """
        # Check if this is a special service
        is_special_service = any(
            manifest_url.startswith(prefix)
            for prefix in URLResolver.SPECIAL_SERVICE_PREFIXES
        )

        if is_special_service:
            # Special service: KEEP index.mpd in path
            manifest_dir = manifest_url if manifest_url.endswith('/') else f"{manifest_url}/"
        else:
            # Normal service: remove index.mpd from path
            parsed = urlparse(manifest_url)
            manifest_dir = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rsplit('/', 1)[0]}/"

        return manifest_dir

    @staticmethod
    def resolve_base_url_with_element(
            manifest_url: str,
            base_url_text: Optional[str] = None
    ) -> str:
        """
        Resolve base URL considering manifest URL and optional BaseURL element text.

        Args:
            manifest_url: URL of the manifest
            base_url_text: Text content from <BaseURL> element, if present

        Returns:
            Resolved base URL with trailing slash
        """
        manifest_base = URLResolver.extract_manifest_base_url(manifest_url)

        if base_url_text:
            base_url_text = base_url_text.strip()
            if base_url_text.startswith(("http://", "https://")):
                # Absolute URL
                return base_url_text if base_url_text.endswith('/') else f"{base_url_text}/"
            else:
                # Relative URL
                resolved = urljoin(manifest_base, base_url_text)
                return resolved if resolved.endswith('/') else f"{resolved}/"

        return manifest_base

    @staticmethod
    def build_effective_base_url(
            manifest_url: str,
            base_url_elements: list[str]
    ) -> str:
        """
        Build effective base URL by chaining BaseURL elements.
        Used when multiple BaseURL elements exist at different levels.

        Args:
            manifest_url: URL of the manifest
            base_url_elements: List of BaseURL text contents in order

        Returns:
            Final effective base URL with trailing slash
        """
        effective_base = URLResolver.extract_manifest_base_url(manifest_url)

        for base_url in base_url_elements:
            if base_url.startswith("http"):
                effective_base = base_url
            else:
                effective_base = urljoin(effective_base, base_url)

        return effective_base if effective_base.endswith('/') else f"{effective_base}/"

    @staticmethod
    def substitute_template_variables(
            template: str,
            representation_id: Optional[str] = None,
            bandwidth: Optional[str] = None,
            time: Optional[str] = None,
            number: Optional[str] = None
    ) -> str:
        """
        Substitute DASH template variables with actual values.

        Common template variables:
        - $RepresentationID$ - Representation identifier
        - $Bandwidth$ - Representation bandwidth
        - $Time$ - Segment time
        - $Number$ - Segment number

        Args:
            template: URL template with $Variable$ placeholders
            representation_id: Value for $RepresentationID$
            bandwidth: Value for $Bandwidth$
            time: Value for $Time$
            number: Value for $Number$

        Returns:
            Template with variables substituted
        """
        result = template

        if representation_id is not None:
            result = result.replace("$RepresentationID$", str(representation_id))

        if bandwidth is not None:
            result = result.replace("$Bandwidth$", str(bandwidth))

        if time is not None:
            result = result.replace("$Time$", str(time))

        if number is not None:
            result = result.replace("$Number$", str(number))

        return result

    @staticmethod
    def construct_full_url(
            base_url: str,
            relative_path: str,
            url_encode_filename: bool = False
    ) -> str:
        """
        Construct full URL from base URL and relative path.

        Args:
            base_url: Base URL (should end with /)
            relative_path: Relative path to append
            url_encode_filename: If True, URL-encode the filename portion

        Returns:
            Complete URL
        """
        if relative_path.startswith("http"):
            # Already absolute
            return relative_path

        if url_encode_filename:
            # URL encode special characters in filename only
            path_parts = relative_path.split("/")
            path_parts[-1] = quote(path_parts[-1], safe=".-_")
            relative_path = "/".join(path_parts)

        return urljoin(base_url, relative_path)

    @staticmethod
    def split_template_url(url: str) -> Tuple[str, Optional[str]]:
        """
        Split a URL with template variables into base path and template pattern.

        Example:
            "https://cdn.com/path/segment-$Number$.m4s"
            -> ("https://cdn.com/path", "segment-$Number$.m4s")

        Args:
            url: URL potentially containing template variables ($Variable$)

        Returns:
            Tuple of (base_path, template_pattern)
            If no template variables found, returns (url, None)
        """
        if "$" not in url:
            return url, None

        first_template_pos = url.find("$")
        last_slash_before_template = url.rfind("/", 0, first_template_pos)

        if last_slash_before_template == -1:
            return "", url

        base_path = url[:last_slash_before_template]
        template_pattern = url[last_slash_before_template + 1:]

        return base_path, template_pattern