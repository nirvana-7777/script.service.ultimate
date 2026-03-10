"""
License Configuration Models

Data classes for DRM license configuration, including server URLs,
certificates, headers, and unwrapper parameters.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

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
        req_headers: Custom HTTP headers as a URL-encoded string.
            Format: "Header1=Value1&Header2=Value2" where values are
            URL-encoded (use urllib.parse.urlencode() or quote_plus()).
            Example: "Content-Type=application%2Foctet-stream&User-Agent=Mozilla%2F5.0"
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
    req_headers: Optional[str] = None
    req_params: Optional[str] = None
    req_data: Optional[str] = None
    wrapper: Optional[str] = None
    unwrapper: Optional[str] = None
    unwrapper_params: Optional[LicenseUnwrapperParams] = None
    keyids: dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        """Normalize key IDs in keyids mapping."""
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

        # req_headers must be a URL-encoded string, NOT a JSON dict
        if self.req_headers and self.req_headers.strip().startswith("{"):
            raise LicenseConfigError(
                "req_headers must be a URL-encoded string "
                "(e.g. 'Content-Type=application%2Foctet-stream'), not a JSON dict. "
                "Use urllib.parse.urlencode() to encode headers."
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