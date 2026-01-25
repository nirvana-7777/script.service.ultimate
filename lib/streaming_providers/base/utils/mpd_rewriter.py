# streaming_providers/base/utils/mpd_rewriter.py
import base64
import xml.etree.ElementTree as ET
import re
from typing import Optional, Tuple, Set
from urllib.parse import urljoin, urlparse, quote, urlencode
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from .logger import logger

# Pre-compile regex for ISO duration parsing at module level
ISO_8601_PERIOD_RE = re.compile(
    r"P(?:(?P<years>\d+)Y)?(?:(?P<months>\d+)M)?(?:(?P<weeks>\d+)W)?(?:(?P<days>\d+)D)?(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+(?:\.\d+)?)S)?)?"
)


class MPDRewriter:
    MPD_NAMESPACE = {"mpd": "urn:mpeg:dash:schema:mpd:2011"}

    def __init__(
        self,
        media_proxy_url: str,
        provider_proxy_url: Optional[str] = None,
        clearkey_keyids: Optional[dict] = None,
    ):
        self.media_proxy_url = media_proxy_url.rstrip("/")
        self.provider_proxy_url = provider_proxy_url
        self.clearkey_keyids = clearkey_keyids or {}
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
    ) -> str:
        params = {"url": original_url, **self._static_params}

        if self.clearkey_keyids and is_encrypted:
            # Preserved Logic: Specific keys for specific segment types
            if segment_type == "initialization":
                params["kid"] = next(iter(self.clearkey_keyids.keys()))
            elif segment_type == "media":
                params["key"] = next(iter(self.clearkey_keyids.values()))
            else:
                kid, key = next(iter(self.clearkey_keyids.items()))
                params["kid"], params["key"] = kid, key

        encoded = self.encode_url(urlencode(params))
        endpoint = "decrypt" if (self.clearkey_keyids and is_encrypted) else "proxy"
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
        return url[:last_slash_before_template], url[last_slash_before_template + 1 :]

    def rewrite_mpd(self, mpd_content: str, manifest_url: str) -> str:
        try:
            root = ET.fromstring(mpd_content)
            ET.register_namespace("", self.MPD_NAMESPACE["mpd"])

            base_url = self._extract_base_url(root, manifest_url)

            # Optimization: Single pass to clean tree and map encryption IDs
            # Eliminates need for _is_descendant and O(N^2) searches
            encrypted_as_ids = self._prepare_tree_and_get_encrypted_ids(root)

            # Recursive rewrite with state-passing
            self._rewrite_node(root, base_url, encrypted_as_ids, False)

            rewritten = ET.tostring(root, encoding="unicode", method="xml")
            if not rewritten.startswith("<?xml"):
                rewritten = '<?xml version="1.0" encoding="UTF-8"?>\n' + rewritten
            return rewritten
        except Exception as e:
            logger.error(f"Failed to rewrite MPD: {e}")
            raise

    def _prepare_tree_and_get_encrypted_ids(self, root: ET.Element) -> Set[str]:
        """Cleans BaseURL/ContentProtection and identifies encrypted sets in one pass."""
        encrypted_ids = set()
        for parent in root.iter():
            # Remove BaseURL elements
            for bu in list(parent.findall("mpd:BaseURL", self.MPD_NAMESPACE)):
                parent.remove(bu)

            # Map and remove ContentProtection
            if parent.tag.endswith("AdaptationSet"):
                cp_elements = parent.findall(
                    "mpd:ContentProtection", self.MPD_NAMESPACE
                )
                if cp_elements:
                    as_id = parent.get("id", str(id(parent)))
                    encrypted_ids.add(str(as_id))
                    for cp in cp_elements:
                        parent.remove(cp)
        return encrypted_ids

    def _rewrite_node(
        self,
        element: ET.Element,
        base_url: str,
        encrypted_ids: Set[str],
        current_encrypted: bool,
    ):
        """Recursive node rewriter using state-passing for encryption context."""
        # Update state: if we enter an AdaptationSet, check its encryption status
        if element.tag.endswith("AdaptationSet"):
            as_id = element.get("id", str(id(element)))
            current_encrypted = str(as_id) in encrypted_ids

        # Mapping of attributes to segment types for build_proxy_url
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
                        path, pattern, seg_type, current_encrypted
                    )
                else:
                    element.attrib[attr] = self.build_proxy_url(
                        resolved, None, seg_type, current_encrypted
                    )

        # Handle SegmentURL specifically (always 'media' type)
        if element.tag.endswith("SegmentURL") and "media" in element.attrib:
            resolved = urljoin(base_url, element.attrib["media"])
            path, pattern = (
                self.split_template_url(resolved)
                if "$" in resolved
                else (resolved, None)
            )
            element.attrib["media"] = self.build_proxy_url(
                path, pattern, "media", current_encrypted
            )

        # Recurse to children, passing the current encryption state down
        for child in element:
            self._rewrite_node(child, base_url, encrypted_ids, current_encrypted)

    def _extract_base_url(self, root: ET.Element, manifest_url: str) -> str:
        base_url_elem = root.find(".//mpd:BaseURL", self.MPD_NAMESPACE)
        if base_url_elem is not None and base_url_elem.text:
            base_url_text = base_url_elem.text.strip()
            if not base_url_text.startswith(("http://", "https://")):
                parsed_manifest = urlparse(manifest_url)
                manifest_dir = f"{parsed_manifest.scheme}://{parsed_manifest.netloc}{parsed_manifest.path.rsplit('/', 1)[0]}/"
                return urljoin(manifest_dir, base_url_text)
            return base_url_text

        parsed = urlparse(manifest_url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rsplit('/', 1)[0]}/"

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
