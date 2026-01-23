# streaming_providers/base/models/drm_models.py
import base64
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class DRMSystem(str, Enum):
    WIDEVINE = "com.widevine.alpha"
    PLAYREADY = "com.microsoft.playready"
    WISEPLAY = "com.huawei.wiseplay"
    CLEARKEY = "org.w3.clearkey"
    FAIRPLAY = "com.apple.fps"
    GENERIC = "generic"
    NONE = "none"

    @property
    def system_uuid(self) -> str:
        """Get the standard UUID for this DRM system"""
        uuid_mapping = {
            self.WIDEVINE: "edef8ba9-79d6-4ace-a3c8-27dcd51d21ed",
            self.PLAYREADY: "9a04f079-9840-4286-ab92-e65be0885f95",
            self.CLEARKEY: "e2719d58-a985-b3c9-781a-b030af78d30e",
            self.WISEPLAY: "3d5e6d35-9b9a-41e8-b843-dd3c6e72c42c",
            self.FAIRPLAY: "94ce86fb-07ff-4f43-adb8-93d2fa968ca2",
            self.GENERIC: "",  # No UUID for generic plugins
            self.NONE: "",  # No UUID for unencrypted
        }
        return uuid_mapping.get(self, "")

    @classmethod
    def from_uuid(cls, uuid: str) -> Optional["DRMSystem"]:
        """Get DRM system from UUID"""
        uuid_lower = uuid.lower().replace("-", "")
        uuid_mapping = {
            "edef8ba979d64acea3c827dcd51d21ed": cls.WIDEVINE,
            "9a04f07998404286ab92e65be0885f95": cls.PLAYREADY,
            "e2719d58a985b3c9781ab030af78d30e": cls.CLEARKEY,
            "3d5e6d359b9a41e8b843dd3c6e72c42c": cls.WISEPLAY,
        }
        return uuid_mapping.get(uuid_lower)


class WrapperType(str, Enum):
    BASE64 = "base64"
    URLENC = "urlenc"
    NONE = "none"


@dataclass
class PSSHData:
    system_id: str
    pssh_box: str = ""  # Base64 encoded PSSH box
    key_ids: List[str] = field(default_factory=list)
    source: str = "manifest"  # "manifest", "mp4_segment", "unknown"

    @property
    def needs_extraction(self) -> bool:
        """Check if PSSH/key_ids need to be extracted from segments"""
        return not self.pssh_box or not self.key_ids

    @property
    def drm_system(self) -> Optional[DRMSystem]:
        """Get the corresponding DRM system for this PSSH"""
        return DRMSystem.from_uuid(self.system_id)

    def validate(self):
        """Validate the PSSH data"""
        if not self.system_id:
            raise ValueError("system_id is required")

        # FIX: pssh_box can be empty (PSSH in segments)
        if self.pssh_box:  # Only validate if not empty
            try:
                base64.b64decode(self.pssh_box)
            except Exception:
                raise ValueError("pssh_box must be valid base64")

        # Validate key IDs if present
        for kid in self.key_ids:
            if not all(c in "0123456789abcdefABCDEF-" for c in kid):
                raise ValueError(f"Invalid key ID format: {kid}")


class UnwrapperType(str, Enum):
    AUTO = "auto"
    BASE64 = "base64"
    JSON = "json"
    XML = "xml"
    NONE = "none"


@dataclass
class LicenseUnwrapperParams:
    path_data: Optional[str] = None
    path_data_traverse: bool = False
    path_hdcp_res: Optional[str] = None
    path_hdcp_res_traverse: bool = False
    path_hdcp_ver: Optional[str] = None
    path_hdcp_ver_traverse: bool = False


@dataclass
class LicenseConfig:
    server_url: Optional[str] = None
    server_certificate: Optional[str] = None
    use_http_get_request: bool = False
    req_headers: Optional[str] = None
    req_params: Optional[str] = None
    req_data: Optional[str] = None
    wrapper: Optional[str] = None
    unwrapper: Optional[str] = None
    unwrapper_params: Optional[LicenseUnwrapperParams] = None
    keyids: Dict[str, str] = field(default_factory=dict)  # For ClearKey

    def validate(self):
        """Validate the license configuration"""
        if self.server_certificate:
            try:
                base64.b64decode(self.server_certificate)
            except Exception:
                raise ValueError("server_certificate must be valid base64")

        if self.req_data:
            try:
                base64.b64decode(self.req_data)
            except Exception:
                raise ValueError("req_data must be valid base64")

        if self.keyids:
            for kid, key in self.keyids.items():
                if not all(c in "0123456789abcdefABCDEF" for c in kid):
                    raise ValueError(f"Invalid KID format: {kid}")
                if not all(c in "0123456789abcdefABCDEF" for c in key):
                    raise ValueError(f"Invalid KEY format: {key}")

    @classmethod
    def create_with_base64_req_data(cls, req_data_template: str, **kwargs):
        """Helper to ensure req_data is base64 encoded"""
        import base64

        req_data_encoded = base64.b64encode(req_data_template.encode("utf-8")).decode(
            "utf-8"
        )
        return cls(req_data=req_data_encoded, **kwargs)


@dataclass
class DRMConfig:
    system: DRMSystem
    priority: int = 0
    license: Optional[LicenseConfig] = None

    def validate(self):
        """Validate the DRM configuration"""
        if self.license:
            self.license.validate()

    def to_dict(self) -> Dict:
        """Convert to dictionary format expected by players"""
        result = {
            str(self.system.value): {  # Use .value to get the actual string
                "priority": self.priority
            }
        }

        if self.license:
            license_dict = {}
            if self.license.server_url:
                license_dict["server_url"] = self.license.server_url
            if self.license.server_certificate:
                license_dict["server_certificate"] = self.license.server_certificate
            if self.license.use_http_get_request:
                license_dict["use_http_get_request"] = self.license.use_http_get_request
            if self.license.req_headers:
                license_dict["req_headers"] = self.license.req_headers
            if self.license.req_params:
                license_dict["req_params"] = self.license.req_params
            if self.license.req_data:
                license_dict["req_data"] = self.license.req_data
            if self.license.wrapper:
                license_dict["wrapper"] = self.license.wrapper
            if self.license.unwrapper:
                license_dict["unwrapper"] = self.license.unwrapper
            if self.license.unwrapper_params:
                license_dict["unwrapper_params"] = {
                    k: v
                    for k, v in vars(self.license.unwrapper_params).items()
                    if v is not None
                }
            if self.license.keyids:
                license_dict["keyids"] = self.license.keyids

            if license_dict:
                result[str(self.system.value)]["license"] = license_dict

        return result
