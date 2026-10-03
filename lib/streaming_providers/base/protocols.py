# streaming_providers/base/protocols.py
"""
Structural typing protocols for provider collaborators.

These are NOT base classes. Providers match them by shape, not by
inheritance. Using them as type annotations gives IDE / mypy checking
without imposing a runtime hierarchy.

Why protocols and not ABCs
--------------------------
The Auth contract varies across providers -- RTL+ has three tokens,
Discovery has cookie-based session state, HRTi authorizes per-content
sessions. Forcing a single abstract base would require escape hatches.
A Protocol captures the *minimum shared shape* without forbidding
provider-specific extensions.

The manager ABCs (base/managers/*) are different: their interfaces are
actually shared, so they are ABCs. Only Auth, DRM, and the playback-
authorization step use protocols.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .models import DRMConfig


@runtime_checkable
class AuthProtocol(Protocol):
    """
    Minimal shared Auth interface.

    Every provider's Auth class must provide these three methods. Additional
    methods (get_scoped_token, get_session_context, authorize_playback, or
    provider-specific helpers) are allowed but not required.

    runtime_checkable means isinstance(obj, AuthProtocol) works at runtime,
    checking only for method presence -- not signatures.
    """

    def get_access_token(self, force_refresh: bool = False) -> str:
        """Return the raw token string (no scheme prefix)."""
        ...

    def build_headers(
        self, token: Optional[str] = None, **opts: Any
    ) -> Dict[str, str]:
        """
        Return request-ready headers including auth.

        If token is None, use the cached token (via get_access_token).
        """
        ...

    def invalidate(self) -> None:
        """Drop cached token and session state. Called after a 401."""
        ...


@runtime_checkable
class PlaybackAuthorizationProtocol(Protocol):
    """
    Optional protocol for the provider-specific pre-playback step.

    Not every provider has this. Providers that do match this shape by
    convention when they want to expose it as a stable entry point.
    """

    def authorize_playback(
        self, content_id: str, **opts: Any
    ) -> Dict[str, Any]:
        """Perform the provider's pre-playback authorization step."""
        ...


@runtime_checkable
class DrmManagerProtocol(Protocol):
    """
    Shape for a provider's dedicated DRM manager (if it has one).

    This is a protocol, not an ABC. Providers implement it however fits
    their DRM source: as a dedicated DrmManager class, or folded into the
    channel/vod managers. The protocol exists so callers and tests have a
    name for the shape, and so type checkers can verify it if a provider
    chooses to annotate.

    Providers with no DRM do not implement this at all -- their
    provider.get_drm() returns [] and implements_drm is False.

    Two architectures are supported (see providers/_template/README.md,
    section "DRM", for when to pick which):

      * Dedicated manager:  implement get_drm_configs() on a class
                            matching this protocol, and wire it in the
                            provider's _build_drm().
      * Folded into managers: override get_channel_drm() on the
                              ChannelManager and/or get_vod_drm() on the
                              VodManager instead. The provider's
                              implements_drm flag is derived from whether
                              either override is present.

    New providers should prefer the dedicated-manager shape unless the
    DRM call shares significant state with the manifest step -- see the
    README for the tradeoff.

    Four existing patterns to model after (see
    providers/_template/drm_manager.py for file-level references):

      RTL+      per-content upfront token via lib_drmtoday.
      Magenta   licence URL constructed from token claims + /user/account.
      Discovery DRM arrives with the playbackInfo response.
      HRTi      session id becomes a base64 auth blob via lib_drmtoday.
    """

    def get_drm_configs(
        self,
        content_id: str,
        content_type: Optional[str] = None,
        **opts: Any,
    ) -> List["DRMConfig"]:
        """
        Return the DRM configuration(s) for the given content.

        content_type is an optional hint ("live" | "vod" | "event" |
        "catchup"). When None, the manager infers the type from its own
        content_id grammar -- which is the preferred mode, since the
        manager knows its own grammar better than the caller does.

        Callers that already know the type (e.g. the backend's streaming
        route, which has already resolved the item) should pass it
        explicitly so the manager skips the inference step.

        Return [] when this provider has no DRM for the content. Auth /
        geo / entitlement / rate-limit / server failures propagate as
        exceptions from base.errors.
        """
        ...