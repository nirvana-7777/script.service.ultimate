"""
License Configuration Models

Data classes for DRM license configuration, including server URLs,
certificates, headers, and unwrapper parameters.
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Union
from urllib.parse import urlencode, unquote

from .utils import safe_base64_decode, safe_base64_encode, normalize_key_id
from .exceptions import LicenseConfigError


class WrapperType(str, Enum):
    """License request wrapper types"""
    BASE64 = "base64"
    URLENC = "urlenc"
    NONE = "none"


class UnwrapperType(str, Enum):
    """License response unwrapper types"""
    AUTO = "auto"
    BASE64 = "base64"
    JSON = "json"
    XML = "xml"
    NONE = "none"


@dataclass
class LicenseUnwrapperParams:
    """
    Parameters for license response unwrapping.

    Used to extract license data and HDCP information from
    non-standard license server responses.

    Attributes:
        path_data: JSON/XML path to license data (e.g., "licenseresponse/data")
        path_data_traverse: Whether to traverse nested structures for data
        path_hdcp_res: JSON/XML path to HDCP resolution restriction
        path_hdcp_res_traverse: Whether to traverse for HDCP resolution
        path_hdcp_ver: JSON/XML path to HDCP version requirement
        path_hdcp_ver_traverse: Whether to traverse for HDCP version
    """

    path_data: Optional[str] = None
    path_data_traverse: bool = False
    path_hdcp_res: Optional[str] = None
    path_hdcp_res_traverse: bool = False
    path_hdcp_ver: Optional[str] = None
    path_hdcp_ver_traverse: bool = False

    def to_dict(self) -> dict:
        """Convert to dictionary, excluding None values."""
        return {
            k: v for k, v in {
                "path_data": self.path_data,
                "path_data_traverse": self.path_data_traverse,
                "path_hdcp_res": self.path_hdcp_res,
                "path_hdcp_res_traverse": self.path_hdcp_res_traverse,
                "path_hdcp_ver": self.path_hdcp_ver,
                "path_hdcp_ver_traverse": self.path_hdcp_ver_traverse,
            }.items()
            if v is not None and (not isinstance(v, bool) or v)
        }


@dataclass
class LicenseConfig:
    """
    DRM License Server Configuration.

    Contains all information needed to acquire and process DRM licenses,
    including server URLs, certificates, request customization, and
    response processing.

    All fields map directly to ISA (inputstream.adaptive) license parameters.
    The to_dict() output can be used as-is inside the inputstream.adaptive.drm
    JSON property — no further transformation is required.

    Attributes:
        server_url: License server URL. For Widevine, supports placeholders
            to inject the DRM challenge: {CHA-B64U}, {CHA-MD5}.
            For ClearKey, also accepts a URI "data" scheme:
            "data:application/json;base64,<base64>"
        server_certificate: Base64-encoded server certificate
            (Widevine, FairPlay).
        use_http_get_request: Force HTTP GET for the license request instead
            of the default POST (Widevine, PlayReady, Wiseplay only).
        req_headers: Custom HTTP headers for the license request.
            Accepts multiple formats — all are normalized to a URL-encoded
            string at construction time:
            - ``dict``: ``{"Content-Type": "application/octet-stream"}``
            - JSON string: ``'{"Content-Type": "application/octet-stream"}'``
            - ``"Key: Value"`` lines (newline/semicolon/comma-separated)
            - Already URL-encoded string: ``"Content-Type=application%2Foctet-stream"``
            Final stored value is always URL-encoded, e.g.
            ``"Content-Type=application%2Foctet-stream&User-Agent=Mozilla%2F5.0"``.
        req_params: Path extension or parameters appended to the license URL.
            Example: "/one/two/three-path"
        req_data: Base64-encoded custom request body template.
            Supports ISA placeholders: {CHA-RAW}, {CHA-B64}, {CHA-B64U},
            {CHA-DEC}, {SID-RAW}, {SID-B64}, {SID-B64U}, {KID-UUID},
            {KID-HEX}, {PSSH-B64}, {PSSH-B64U}.
        wrapper: Request body wrapper flags, comma-separated:
            "base64" | "urlenc" | "none"
        unwrapper: Response unwrapper flags, comma-separated:
            "auto" | "base64" | "json" | "xml" | "none"
        unwrapper_params: Parameters for JSON/XML response unwrapping
            (required when unwrapper includes "json" or "xml").
        keyids: ClearKey only. Map of KID -> Key pairs in hex format
            (32 hex chars each).
    """

    server_url: Optional[str] = None
    server_certificate: Optional[str] = None
    use_http_get_request: bool = False
    req_headers: Optional[Union[str, Dict[str, str]]] = None
    req_params: Optional[str] = None
    req_data: Optional[str] = None
    wrapper: Optional[str] = None
    unwrapper: Optional[str] = None
    unwrapper_params: Optional[LicenseUnwrapperParams] = None
    keyids: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        """Normalize req_headers to URL-encoded string and key IDs in keyids mapping."""
        self.req_headers = self._normalize_headers(self.req_headers)

        if self.keyids:
            normalized_keyids = {}
            for kid, key in self.keyids.items():
                try:
                    norm_kid = normalize_key_id(kid)
                    norm_key = key.lower().replace("-", "")
                    normalized_keyids[norm_kid] = norm_key
                except Exception:
                    pass
            self.keyids = normalized_keyids

    def validate(self) -> None:
        """
        Validate the license configuration.

        Raises:
            LicenseConfigError: If configuration is invalid
        """
        if self.server_certificate:
            try:
                safe_base64_decode(self.server_certificate)
            except Exception as e:
                raise LicenseConfigError(
                    f"server_certificate must be valid base64: {e}"
                ) from e

        if self.req_data:
            try:
                safe_base64_decode(self.req_data)
            except Exception as e:
                raise LicenseConfigError(
                    f"req_data must be valid base64: {e}"
                ) from e

        # req_headers is always normalized to URL-encoded in __post_init__,
        # so a JSON dict arriving here would only happen if someone bypassed
        # the constructor. Warn but don't hard-fail so validate() stays useful
        # even on partially-constructed instances.
        if self.req_headers and self.req_headers.strip().startswith("{"):
            raise LicenseConfigError(
                "req_headers must be a URL-encoded string after normalization — "
                "this indicates _normalize_headers was not called. "
                "Construct via the normal dataclass constructor to ensure normalization."
            )

        if self.keyids:
            for kid, key in self.keyids.items():
                if len(kid) != 32:
                    raise LicenseConfigError(
                        f"Invalid KID length: {kid} (must be 32 hex chars)"
                    )
                if len(key) != 32:
                    raise LicenseConfigError(
                        f"Invalid KEY length for KID {kid}: {key} (must be 32 hex chars)"
                    )
                if not all(c in "0123456789abcdef" for c in kid):
                    raise LicenseConfigError(f"KID contains non-hex characters: {kid}")
                if not all(c in "0123456789abcdef" for c in key):
                    raise LicenseConfigError(
                        f"KEY contains non-hex characters for KID {kid}: {key}"
                    )

    @classmethod
    def create_with_req_data(cls, req_data_template: str, **kwargs) -> "LicenseConfig":
        """
        Helper to create LicenseConfig with base64-encoded req_data.

        Args:
            req_data_template: Plain text request data template (may contain
                ISA placeholders like {CHA-B64}, {SID-RAW}, {KID-HEX}, etc.)
            **kwargs: Other LicenseConfig parameters

        Returns:
            LicenseConfig instance with encoded req_data
        """
        req_data_encoded = safe_base64_encode(req_data_template.encode("utf-8"))
        return cls(req_data=req_data_encoded, **kwargs)

    @classmethod
    def create_with_base64_req_data(cls, req_data_template: str, **kwargs) -> "LicenseConfig":
        """Deprecated: Use create_with_req_data() instead."""
        import warnings
        warnings.warn(
            "create_with_base64_req_data is deprecated, use create_with_req_data instead",
            DeprecationWarning,
            stacklevel=2
        )
        return cls.create_with_req_data(req_data_template, **kwargs)

    def _normalize_headers(
        self, headers: Optional[Union[str, Dict[str, str]]]
    ) -> Optional[str]:
        """
        Normalize any supported header format to a URL-encoded string.

        Accepted inputs:
        - ``None``                    → ``None``
        - ``dict``                    → URL-encoded string via ``urlencode()``
        - JSON string                 → parsed to dict, then URL-encoded
        - Already URL-encoded string  → validated and returned as-is
        - ``"Key: Value"`` lines      → parsed and URL-encoded

        Args:
            headers: Headers in any of the formats above.

        Returns:
            URL-encoded string (``"K1=V1&K2=V2"``) or ``None``.

        Raises:
            LicenseConfigError: If the format is unrecognised or malformed.
        """
        if headers is None:
            return None

        # Case 1: Already a dict
        if isinstance(headers, dict):
            return urlencode(headers)

        # Case 2: String input
        if isinstance(headers, str):
            headers = headers.strip()
            if not headers:
                return None

            # Try to parse as JSON object
            if headers.startswith("{"):
                try:
                    header_dict = json.loads(headers)
                    if isinstance(header_dict, dict):
                        return urlencode(header_dict)
                except json.JSONDecodeError as e:
                    raise LicenseConfigError(
                        f"Invalid JSON in req_headers: {e}"
                    ) from e

            # Already URL-encoded: contains '=' and at least one '&' or ';'
            if "=" in headers and ("&" in headers or ";" in headers):
                self._validate_urlencoded_headers(headers)
                return headers

            # "Key: Value" plain-text format (no '=' present)
            if ":" in headers and "=" not in headers:
                return self._parse_plain_headers(headers)

            raise LicenseConfigError(
                f"Invalid req_headers format: '{headers}'. "
                f"Must be a dict, JSON string, URL-encoded string, "
                f"or 'Key: Value' lines."
            )

        raise LicenseConfigError(
            f"req_headers must be dict, string, or None, got {type(headers).__name__}"
        )

    @staticmethod
    def _validate_urlencoded_headers(headers: str) -> None:
        """
        Validate the structure of an already URL-encoded header string.

        Checks that every ``key=value`` pair has a non-empty key and a
        value that can be URL-decoded without error.  Does *not* decode
        or transform the string.

        Args:
            headers: URL-encoded header string (``"K1=V1&K2=V2"``).

        Raises:
            LicenseConfigError: If any pair is malformed.
        """
        for pair in re.split(r"[&;]", headers):
            if "=" not in pair:
                raise LicenseConfigError(
                    f"Invalid URL-encoded header pair: '{pair}'. "
                    f"Expected format: 'key=value'."
                )
            key, value = pair.split("=", 1)
            if not key.strip():
                raise LicenseConfigError(f"Empty header key in pair: '{pair}'")
            try:
                unquote(value)  # Raises if the percent-encoding is broken
            except Exception as e:
                raise LicenseConfigError(
                    f"Header value is not properly URL-encoded: '{value}'"
                ) from e

    @staticmethod
    def _parse_plain_headers(headers: str) -> str:
        """
        Convert ``"Key: Value"`` lines to a URL-encoded string.

        Lines may be separated by newlines, carriage-returns, semicolons,
        or commas.  Blank lines are silently skipped.

        Example::

            "User-Agent: Mozilla/5.0\\nContent-Type: text/plain"
            → "User-Agent=Mozilla%2F5.0&Content-Type=text%2Fplain"

        Args:
            headers: One or more ``"Key: Value"`` lines.

        Returns:
            URL-encoded string.

        Raises:
            LicenseConfigError: If any non-blank line lacks a ``':'``.
        """
        header_dict: Dict[str, str] = {}
        for line in re.split(r"[\n\r;,]+", headers):
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                raise LicenseConfigError(
                    f"Invalid plain header format: '{line}'. Expected 'Key: Value'."
                )
            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key and value:
                header_dict[key] = value
        return urlencode(header_dict)

    def to_dict(self) -> dict:
        """
        Convert to dictionary ready for the inputstream.adaptive.drm JSON payload.

        Output maps directly to ISA license parameters — no further
        transformation is needed before json.dumps().

        Returns:
            Dictionary with only non-empty/non-False values included.
        """
        result = {}

        if self.server_url:
            result["server_url"] = self.server_url
        if self.server_certificate:
            result["server_certificate"] = self.server_certificate
        if self.use_http_get_request:
            result["use_http_get_request"] = self.use_http_get_request
        if self.req_headers:
            result["req_headers"] = self.req_headers
        if self.req_params:
            result["req_params"] = self.req_params
        if self.req_data:
            result["req_data"] = self.req_data
        if self.wrapper:
            result["wrapper"] = self.wrapper
        if self.unwrapper:
            result["unwrapper"] = self.unwrapper
        if self.unwrapper_params:
            result["unwrapper_params"] = self.unwrapper_params.to_dict()
        if self.keyids:
            result["keyids"] = self.keyids

        return result