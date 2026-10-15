# streaming_providers/providers/hrti/models.py
"""
Provider-local models: credentials, auth token, and strict parsers for the
live-channel and VOD-details responses. Parsing is STRICT (KeyError /
ValueError on missing required fields); the managers parse entry by entry and
skip malformed entries, so one bad entry cannot take a whole list down.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from ...base.auth.base_auth import BaseAuthToken
from ...base.auth.credentials import UserPasswordCredentials
from ...base.models import Channel
from .constants import HRTiDefaults


@dataclass
class HRTiCredentials(UserPasswordCredentials):
    """HRTi username/password credentials."""

    def __init__(self, username: str, password: str):
        super().__init__(username=username, password=password)

    def to_auth_payload(self) -> Dict[str, Any]:
        return {
            "Username": self.username,
            "Password": self.password,
            "OperatorReferenceId": HRTiDefaults.OPERATOR_REFERENCE_ID,
        }

    def validate(self) -> bool:
        return bool(self.username and self.password)


class HRTiAuthToken(BaseAuthToken):
    """HRTi authentication token (persisted flat via to_dict / from_dict)."""

    def __init__(
        self,
        access_token: str,
        token_type: str,
        expires_in: int,
        issued_at: float,
        user_id: str = "",
        valid_from: str = "",
        valid_to: str = "",
        refresh_token: Optional[str] = None,
    ):
        super().__init__(
            access_token=access_token,
            token_type=token_type,
            expires_in=expires_in,
            issued_at=issued_at,
            refresh_token=refresh_token,
        )
        self.user_id = user_id
        self.valid_from = valid_from
        self.valid_to = valid_to

    def to_dict(self) -> Dict[str, Any]:
        base_dict = {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "issued_at": self.issued_at,
            "refresh_token": self.refresh_token or "",
            "user_id": self.user_id,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
        }
        if hasattr(self, "auth_level") and self.auth_level:
            base_dict["auth_level"] = self.auth_level.value
        return base_dict

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HRTiAuthToken":
        return cls(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Client"),
            expires_in=data.get("expires_in", HRTiDefaults.TOKEN_LIFETIME_SECONDS),
            issued_at=data.get("issued_at", 0),
            user_id=data.get("user_id", ""),
            valid_from=data.get("valid_from", ""),
            valid_to=data.get("valid_to", ""),
            refresh_token=data.get("refresh_token") or None,
        )


@dataclass
class LiveChannelInfo:
    """One entry of GetChannels. The record stays in the ChannelManager."""

    content_id: str
    name: str
    stream_url: str = ""
    is_radio: bool = False
    icon_url: str = ""

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "LiveChannelInfo":
        # The API spells it 'ReferenceID' (capital ID) here.
        name = data["Name"]
        content_id = data["ReferenceID"]
        if not name or not content_id:
            raise ValueError("channel entry without name or ReferenceID")
        return cls(
            content_id=str(content_id),
            name=name,
            stream_url=data.get("StreamingURL") or "",
            is_radio=bool(data.get("Radio", False)),
            icon_url=data.get("Icon") or "",
        )

    def to_channel(self, provider_name: str, country: str) -> Channel:
        """Same fields as v1: a session-manifest channel whose manifest_script
        carries the stream URL; radio keeps content_type "AUDIO" (the clients
        and the v1 code distinguish radio by it)."""
        return Channel(
            name=self.name,
            content_id=self.content_id,
            provider=provider_name,
            logo_url=self.icon_url,
            mode="live",
            session_manifest=True,
            manifest=None,
            manifest_script=self.stream_url,
            content_type="AUDIO" if self.is_radio else "LIVE",
            country=country,
            is_radio=self.is_radio,
            language="hr",
            use_cdm=True,
            cdm_type="widevine",
        )


@dataclass
class VodDetails:
    """Playback-relevant part of GetVodDetails."""

    ref_id: str
    file_name: str = ""                       # the DASH manifest URL
    svod_stores: List[str] = field(default_factory=list)

    @classmethod
    def from_api_response(cls, data: Dict[str, Any]) -> "VodDetails":
        ref_id = data.get("ReferenceID") or data.get("ReferenceId")
        if not ref_id:
            raise ValueError("GetVodDetails response without ReferenceID")
        return cls(
            ref_id=str(ref_id),
            file_name=data.get("FileName") or "",
            svod_stores=list(data.get("SVODVideostores") or []),
        )
