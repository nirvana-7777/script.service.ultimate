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
        path_data: JSON/XML path to license data (e.g., "license.data")
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

    Attributes:
        server_url: License server URL
        server_certificate: Base64-encoded server certificate (for FairPlay, etc.)
        use_http_get_request: Use GET instead of POST for license requests
        req_headers: Custom HTTP headers as JSON string
        req_params: URL query parameters as JSON string
        req_data: Base64-encoded custom request body data
        wrapper: Request body wrapper type
        unwrapper: Response unwrapper type
        unwrapper_params: Parameters for response unwrapping
        keyids: ClearKey key mappings (KID -> Key in hex)
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
            # Normalize all KIDs and keys to lowercase hex
            normalized_keyids = {}
            for kid, key in self.keyids.items():
                try:
                    norm_kid = normalize_key_id(kid)
                    norm_key = key.lower().replace("-", "")
                    normalized_keyids[norm_kid] = norm_key
                except Exception:
                    # Skip invalid entries
                    pass
            self.keyids = normalized_keyids

    def validate(self) -> None:
        """
        Validate the license configuration.

        Raises:
            LicenseConfigError: If configuration is invalid
        """
        # Validate server_certificate if present
        if self.server_certificate:
            try:
                safe_base64_decode(self.server_certificate)
            except Exception as e:
                raise LicenseConfigError(
                    f"server_certificate must be valid base64: {e}"
                ) from e

        # Validate req_data if present
        if self.req_data:
            try:
                safe_base64_decode(self.req_data)
            except Exception as e:
                raise LicenseConfigError(
                    f"req_data must be valid base64: {e}"
                ) from e

        # Validate keyids format (for ClearKey)
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
            req_data_template: Plain text request data template
            **kwargs: Other LicenseConfig parameters

        Returns:
            LicenseConfig instance with encoded req_data
        """
        req_data_encoded = safe_base64_encode(req_data_template.encode("utf-8"))
        return cls(req_data=req_data_encoded, **kwargs)

    def to_dict(self) -> dict:
        """
        Convert to dictionary, excluding None/empty values.

        Returns:
            Dictionary representation
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