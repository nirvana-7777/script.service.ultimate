"""
DRM Configuration Model

Main configuration class that combines DRM system, PSSH data, and license config.
"""

from dataclasses import dataclass
from typing import Optional

from .drm_systems import DRMSystem
from .license_config import LicenseConfig
from .exceptions import LicenseConfigError


@dataclass
class DRMConfig:
    """
    Complete DRM Configuration for a single DRM system.

    Produces output compatible with the inputstream.adaptive.drm JSON property
    (Kodi 22+). The to_dict() output can be merged with other DRMConfig dicts
    and passed directly to json.dumps() — no further transformation needed.

    Top-level ISA parameters (outside "license"):

    Attributes:
        system: DRM system type.
        priority: DRM priority in multi-DRM scenarios. Lower number = higher
            priority. Must be >= 1; 0 is invalid per ISA spec. Two DRMs must
            not share the same priority value.
        license: License server configuration.
        init_data: Custom initialization data (PSSH box) encoded as base64.
            Replaces any PSSH provided by the manifest. For Widevine, also
            accepts raw Widevine PSSH data with optional placeholders:
            {KID} (KID as bytes), {UUID} (KID as UUID string) — both must
            be encoded as base64 together with the surrounding data.
        pre_init_data: Widevine only. Pre-initialize a DRM session for
            licensed manifests. Format: "PSSH_base64|KID_base64".
            Requires priority=1 and a proxy server in the add-on.
        persistent_storage: Enable CDM persistent state (store session data
            locally). Only enable if the streaming service requires it.
        secure_decoder: Force-enable (True) or force-disable (False) the
            secure decoder, overriding the ISA add-on user setting.
            Omit (None) to leave the user setting untouched.
        force_single_session: Force a single DRM session for all tracks.
            Saves license round-trips but may cause playback issues if the
            backend does not return all keys in one response.
        optional_key_req_params: CDM-specific key request parameters.
            PlayReady: {"custom_data": "..."} sets PRCustomData.
    """

    system: DRMSystem
    priority: int = 1
    license: Optional[LicenseConfig] = None
    init_data: Optional[str] = None
    pre_init_data: Optional[str] = None
    persistent_storage: Optional[bool] = None
    secure_decoder: Optional[bool] = None
    force_single_session: Optional[bool] = None
    optional_key_req_params: Optional[dict] = None

    def validate(self) -> None:
        """
        Validate the DRM configuration.

        Raises:
            LicenseConfigError: If configuration is invalid
        """
        if not isinstance(self.system, DRMSystem):
            raise LicenseConfigError(
                f"system must be a DRMSystem enum, got {type(self.system)}"
            )

        # priority=0 is explicitly invalid per ISA spec
        if self.priority == 0:
            raise LicenseConfigError(
                "priority=0 is invalid per ISA spec. Use priority >= 1 "
                "(lower number = higher priority)."
            )

        if self.pre_init_data and self.priority != 1:
            raise LicenseConfigError(
                "pre_init_data requires priority=1 per ISA spec."
            )

        if self.license:
            self.license.validate()

    def to_dict(self) -> dict[str, dict]:
        """
        Convert to the dictionary format expected by inputstream.adaptive.drm.

        Returns:
            {
                "com.widevine.alpha": {
                    "priority": 1,
                    "license": { ... },        # if set
                    "init_data": "...",         # if set
                    "pre_init_data": "...",     # if set
                    "persistent_storage": True, # if set
                    "secure_decoder": False,    # if set
                    "force_single_session": True, # if set
                    "optional_key_req_params": {...} # if set
                }
            }
        """
        cfg: dict = {"priority": self.priority}

        if self.license:
            license_dict = self.license.to_dict()
            if license_dict:
                cfg["license"] = license_dict

        if self.init_data is not None:
            cfg["init_data"] = self.init_data
        if self.pre_init_data is not None:
            cfg["pre_init_data"] = self.pre_init_data
        if self.persistent_storage is not None:
            cfg["persistent_storage"] = self.persistent_storage
        if self.secure_decoder is not None:
            cfg["secure_decoder"] = self.secure_decoder
        if self.force_single_session is not None:
            cfg["force_single_session"] = self.force_single_session
        if self.optional_key_req_params:
            cfg["optional_key_req_params"] = self.optional_key_req_params

        return {self.system.value: cfg}

    # ------------------------------------------------------------------
    # Factory helpers
    # ------------------------------------------------------------------

    @classmethod
    def create_widevine(
        cls,
        server_url: str,
        priority: int = 1,
        **license_kwargs
    ) -> "DRMConfig":
        """
        Create a Widevine DRM configuration.

        Args:
            server_url: Widevine license server URL. Supports {CHA-B64U},
                {CHA-MD5} placeholders to inject the challenge in the URL.
            priority: Priority (default: 1).
            **license_kwargs: Additional LicenseConfig parameters.
        """
        license_config = LicenseConfig(server_url=server_url, **license_kwargs)
        return cls(system=DRMSystem.WIDEVINE, priority=priority, license=license_config)

    @classmethod
    def create_playready(
        cls,
        server_url: str,
        priority: int = 1,
        **license_kwargs
    ) -> "DRMConfig":
        """
        Create a PlayReady DRM configuration.

        Args:
            server_url: PlayReady license server URL.
            priority: Priority (default: 1).
            **license_kwargs: Additional LicenseConfig parameters.
        """
        license_config = LicenseConfig(server_url=server_url, **license_kwargs)
        return cls(system=DRMSystem.PLAYREADY, priority=priority, license=license_config)

    @classmethod
    def create_clearkey(
        cls,
        keyids: dict[str, str],
        priority: int = 1,
        **license_kwargs
    ) -> "DRMConfig":
        """
        Create a ClearKey DRM configuration.

        Args:
            keyids: Mapping of Key IDs to Keys (hex strings, 32 chars each).
            priority: Priority (default: 1).
            **license_kwargs: Additional LicenseConfig parameters.
        """
        license_config = LicenseConfig(keyids=keyids, **license_kwargs)
        return cls(system=DRMSystem.CLEARKEY, priority=priority, license=license_config)

    @classmethod
    def create_fairplay(
        cls,
        server_url: str,
        server_certificate: str,
        priority: int = 1,
        **license_kwargs
    ) -> "DRMConfig":
        """
        Create a FairPlay DRM configuration.

        Args:
            server_url: FairPlay license server URL (skd://).
            server_certificate: Base64-encoded FairPlay certificate.
            priority: Priority (default: 1).
            **license_kwargs: Additional LicenseConfig parameters.
        """
        license_config = LicenseConfig(
            server_url=server_url,
            server_certificate=server_certificate,
            **license_kwargs
        )
        return cls(system=DRMSystem.FAIRPLAY, priority=priority, license=license_config)

    def __repr__(self) -> str:
        has_license = "with license" if self.license else "no license"
        return (
            f"<DRMConfig({self.system.name}, priority={self.priority}, {has_license})>"
        )