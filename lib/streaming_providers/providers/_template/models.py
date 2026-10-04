# streaming_providers/providers/_template/models.py
"""
{TODO: Provider name} models.

What is needed:
  * A custom AuthToken subclass -- MANDATORY for any provider with auth.
    BaseAuthToken is an ABC with an abstract to_dict(), so it cannot be
    instantiated directly. The minimal subclass below is live code, not
    an example; auth.py imports it.
  * A custom Channel subclass -- optional (extra per-channel fields; see
    MoveTV's MoveTVChannel, Discovery's DiscoveryChannel, simpliTV's
    SimpliTVChannel).
  * A custom Credentials subclass -- optional (unusual login payload; see
    HRTi's HRTiCredentials).

A provider WITHOUT auth can delete the AuthToken subclass. A provider that
uses plain Channel and UserPasswordCredentials needs nothing else here.

Rules
-----
* When overriding to_dict(), call super().to_dict() and add your fields.
  Channel.to_dict() chains correctly. BaseAuthToken.to_dict() is abstract,
  so an AuthToken subclass implements it in full.
* to_dict() keys on Channel subclasses are TitleCase, no underscores
  ("YourField"), matching the base serializer.
* Custom Channel subclasses are returned from ChannelManager.get_channels()
  as-is; nothing in the base inspects the concrete type. Use the inherited
  factories (create_live_channel / create_vod_channel / create_radio_channel);
  they use cls(...) and therefore return your subclass.
* Custom AuthToken subclasses are returned from your Auth's
  _perform_authentication(); the base never inspects their type beyond the
  attributes it needs (access_token, expires_in, is_expired).
"""

from dataclasses import dataclass
from typing import Any, Dict

from ...base.auth.base_auth import BaseAuthToken

# from ...base.models import Channel
# from ...base.auth.credentials import UserPasswordCredentials


# ---------------------------------------------------------------------------
# AuthToken subclass (mandatory when the provider has auth)
# ---------------------------------------------------------------------------

@dataclass
class YourAuthToken(BaseAuthToken):
    """
    Minimal concrete token.

    Add provider-specific claims as new fields WITH DEFAULTS, after the
    base fields, and include them in to_dict()/from_dict().

    to_dict() must exist even if you never persist tokens (the ABC
    requires it). Implement it for real so enabling persistence later
    needs no follow-up edit.

    VERIFY against base/auth/base_auth.py: the field list below mirrors
    the README example. If BaseAuthToken has required fields not listed
    here, add them to to_dict() and from_dict().
    """

    def to_dict(self) -> Dict[str, Any]:
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "expires_in": self.expires_in,
            "issued_at": self.issued_at,
            "refresh_token": self.refresh_token,
            "refresh_expires_in": self.refresh_expires_in,
            "auth_level": self.auth_level.value,
            "credential_type": self.credential_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "YourAuthToken":
        """
        Reconstruct from a persisted dict. Used by Auth._load_session().

        Mirror to_dict(). auth_level is serialized via `.value`, so it
        must be converted back to its enum here (see base_auth.py);
        until you do, keep persistence off or let _load_session() return
        None -- a failed load only costs one re-authentication.
        """
        return cls(
            access_token=data["access_token"],
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in", 0),
            issued_at=data.get("issued_at", 0),
            refresh_token=data.get("refresh_token"),
            refresh_expires_in=data.get("refresh_expires_in", 0),
            # TODO: auth_level=..., credential_type=...
        )


# ---------------------------------------------------------------------------
# Example: custom Channel subclass
# ---------------------------------------------------------------------------

# @dataclass
# class YourChannel(Channel):
#     """
#     Channel with provider-specific extra fields.
#
#     Keep the base class's field names and defaults; add new fields after
#     them so positional construction still works. Never remove or rename
#     base fields -- downstream consumers read them.
#     """
#
#     codename: str = ""
#     recording_id: str = ""
#
#     def to_dict(self) -> Dict[str, Any]:
#         result = super().to_dict()
#         result["Codename"] = self.codename
#         result["RecordingId"] = self.recording_id
#         return result


# ---------------------------------------------------------------------------
# Example: custom Credentials subclass
# ---------------------------------------------------------------------------

# @dataclass
# class YourCredentials(UserPasswordCredentials):
#     """
#     Credentials with a provider-specific payload shape.
#
#     Only needed when the login payload isn't the usual
#     {username, password} (HRTi's grant_access takes
#     {Username, Password, OperatorReferenceId}, for example).
#     """
#
#     operator_reference_id: str = "default"
#
#     def to_auth_payload(self) -> Dict[str, Any]:
#         return {
#             "Username": self.username,
#             "Password": self.password,
#             "OperatorReferenceId": self.operator_reference_id,
#         }