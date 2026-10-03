# streaming_providers/providers/_template/models.py
"""
{TODO: Provider name} models.

Only needed if your provider requires:
  * A custom Channel subclass (extra fields on channels — see MoveTV's
    MoveTVChannel and Discovery's DiscoveryChannel).
  * A custom AuthToken subclass (extra claims on the token — most existing
    providers have one: RTLPlusAuthToken, MagentaAuthToken, MoveTVAuthToken,
    DiscoveryAuthToken, HRTiAuthToken).
  * A custom Credentials subclass (unusual auth payload — see HRTi's
    HRTiCredentials).

If your provider can be expressed with the base Channel / BaseAuthToken and
a plain UserPasswordCredentials, you don't need this file.

Rules
-----
* When overriding to_dict(), call super().to_dict() and add your fields.
  Both Channel.to_dict() and BaseAuthToken.to_dict() chain correctly.
* Custom Channel subclasses are returned from ChannelManager.get_channels()
  as-is; nothing in the base inspects the concrete type.
* Custom AuthToken subclasses are returned from your Auth's
  _perform_authentication(); the base never inspects their type beyond the
  attributes it needs (access_token, expires_in, is_expired).
"""

# ---------------------------------------------------------------------------
# Example: custom Channel subclass
# ---------------------------------------------------------------------------

# from dataclasses import dataclass
# from typing import Any, Dict
#
# from ...base.models import Channel
#
#
# @dataclass
# class YourChannel(Channel):
#     """
#     Channel with provider-specific extra fields.
#
#     Keep the base class's field names and defaults; add new fields after
#     them so positional construction still works if any caller relies on it.
#     Keyword construction is preferred.
#     """
#
#     # Provider-specific extras.
#     your_field: str = ""
#     your_expires_at: float = 0.0
#
#     def to_dict(self) -> Dict[str, Any]:
#         result = super().to_dict()
#         result["YourField"] = self.your_field
#         result["YourExpiresAt"] = self.your_expires_at
#         return result


# ---------------------------------------------------------------------------
# Example: custom AuthToken subclass
# ---------------------------------------------------------------------------

# from typing import Any, Dict, Optional
#
# from ...base.auth.base_auth import BaseAuthToken
#
#
# class YourAuthToken(BaseAuthToken):
#     """
#     AuthToken with provider-specific fields.
#
#     BaseAuthToken.__init__ takes:
#         access_token, token_type, expires_in, issued_at,
#         refresh_token=None, refresh_expires_in=0
#
#     Add your fields as keyword args with sensible defaults.
#     """
#
#     def __init__(
#         self,
#         *,
#         access_token: str,
#         token_type: str,
#         expires_in: int,
#         issued_at: float,
#         your_extra: str = "",
#         refresh_token: Optional[str] = None,
#         refresh_expires_in: int = 0,
#     ):
#         super().__init__(
#             access_token=access_token,
#             token_type=token_type,
#             expires_in=expires_in,
#             issued_at=issued_at,
#             refresh_token=refresh_token,
#             refresh_expires_in=refresh_expires_in,
#         )
#         self.your_extra = your_extra
#
#     def to_dict(self) -> Dict[str, Any]:
#         result = super().to_dict()
#         result["your_extra"] = self.your_extra
#         return result
#
#     @classmethod
#     def from_dict(cls, data: Dict[str, Any]) -> "YourAuthToken":
#         """Reconstruct from a persisted dict. Used by _load_session()."""
#         return cls(
#             access_token=data["access_token"],
#             token_type=data.get("token_type", "Bearer"),
#             expires_in=data.get("expires_in", 0),
#             issued_at=data.get("issued_at", 0),
#             your_extra=data.get("your_extra", ""),
#             refresh_token=data.get("refresh_token"),
#             refresh_expires_in=data.get("refresh_expires_in", 0),
#         )


# ---------------------------------------------------------------------------
# Example: custom Credentials subclass
# ---------------------------------------------------------------------------

# from dataclasses import dataclass
# from typing import Any, Dict
#
# from ...base.auth.credentials import UserPasswordCredentials
#
#
# @dataclass
# class YourCredentials(UserPasswordCredentials):
#     """
#     Credentials with a provider-specific payload shape.
#
#     Only needed when the provider's login payload isn't the usual
#     {username, password} shape (HRTi's grant_access takes
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