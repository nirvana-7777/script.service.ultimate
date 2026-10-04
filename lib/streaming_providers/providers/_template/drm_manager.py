# streaming_providers/providers/_template/drm_manager.py
"""
{TODO: Provider name} DRM manager (optional).

Include this file only if the provider has DRM and you are using the
dedicated-manager architecture. Providers that fold DRM into their
channel/vod managers do not need this file -- see the README section
"DRM" for how the folded architecture is wired.

There is no DRM base class, only a protocol (base/protocols.py,
DrmManagerProtocol). The shape is shared; the implementations vary enough
that a shared ABC would need more escape hatches than it saves. This file
is a scaffold and a document -- not an abstract class.

Method names (not interchangeable)
----------------------------------
    get_drm_configs   -- the dedicated DrmManager's only method
    get_channel_drm   -- folded architecture, live-channel entry point
    get_vod_drm       -- folded architecture, VOD entry point
A dedicated manager implements get_drm_configs and leaves the other two
alone; a folded provider does the opposite.

Source patterns vs. architecture
--------------------------------
"Source pattern" describes HOW a provider obtains DRM material (an
upfront token, a constructed URL, a playbackInfo response, a session id).
"Architecture" describes WHERE the code lives in the target model (a
dedicated DrmManager or folded into the channel/vod managers). The two
are orthogonal: any source pattern can be wired into either architecture.

A third shape is common in the existing providers: DRM logic in the
provider itself (methods on the provider class, not on any manager).
This is neither of the target architectures. It works, and it is not
required to migrate, but new providers should prefer one of the two
target architectures for testability.

The four source patterns described below are references for the
*mechanics* of obtaining DRM material, not for the architecture. See the
file-level pointers in each pattern for a working example.

Use the README's "DRM" section to pick the architecture first (the rule
is: fold if DRM shares state with the manifest step). Then pick the
source pattern below that most closely matches how your provider's
license URL is produced, and adapt the mechanics.

How to structure a DRM manager for a new provider
-------------------------------------------------

1. Class shape -- see YourDrmManager below. If content_type is None,
   infer it from the content_id grammar; when in doubt, widen (a wrong
   narrowing yields a silent [] for protected content).

2. Wiring
    In provider.py's __init__:
        self.drm = self._build_drm()

    And:
        def _build_drm(self) -> Optional[DrmManagerProtocol]:
            return YourDrmManager(...)

    Return None from _build_drm() for providers with no DRM.

    The provider's implements_drm property is derived (see the template's
    provider.py). implements_drm is True when either a dedicated DRM
    manager is present, or the channel/vod managers override their DRM
    methods.

    The provider's get_drm() delegates to this manager when present.

3. Source patterns -- read the referenced files before writing yours

    Pattern A -- per-content upfront token
        Files:  providers/rtlplus/provider.py
                providers/rtlplus/auth.py
                providers/lib_drmtoday.py

        Summary: fetch the layout for the content_id, extract the DRM
        asset config, call auth.get_scoped_token("upfront", content_id,
        uid), then lib_drmtoday.create_drmtoday_configs(...). Returns
        [widevine, playready] in one call.

        Requires an authenticated user (profile selected). The upfront
        token is per-content, not per-session.

    Pattern B -- constructed licence URL from token claims
        Files:  providers/magentaeu/vod_manager.py
                providers/magentaeu/provider.py
                providers/magentaeu/auth.py
                providers/lib_theplatform.py

        Summary: resolve the media item to get release_pid (via the
        /media endpoint), read persona_jwt from the access token claims,
        read account_uri from /user/account, then
        lib_theplatform.build_licence_url(...) and
        lib_theplatform.build_widevine_drm_config(...). Returns
        [widevine].

        The licence URL is CONSTRUCTED, not fetched -- three data
        sources: /media response, token claims, /user/account.

    Pattern C -- DRM arrives with the playback response
        Files:  providers/discovery/playback_manager.py
                providers/discovery/constants.py
                providers/simplitv/ (folded into the channel manager)

        Summary: during get_manifest, POST playbackInfo and cache the
        response. get_drm() is a cache lookup; no separate DRM call.
        The response carries both widevine and playready schemes with
        licenseUrl each; pick the one matching the active platform_os.
        Returns [widevine] or [playready].

        DRM and manifest share the playbackInfo cache. Do NOT re-fetch.
        drm.expirationDate governs cache invalidation.

    Pattern D -- session id becomes a base64 auth blob
        Files:  providers/hrti/provider.py
                providers/hrti/auth.py
                providers/lib_drmtoday.py

        Summary: auth.authorize_session(...) returns a session dict
        carrying "DrmId". auth.get_license_data(DrmId) returns a
        base64-encoded JSON blob. Then
        lib_drmtoday.create_drmtoday_widevine_config(..., auth_header_name=
        "dt-custom-data"). Returns [widevine].

        authorize_session must run before get_drm; the provider caches
        the session so the manifest step and the DRM step share it. The
        base64 blob is passed as a header, not a query param.

4. What to cache and where
    Every existing provider caches DRM material somewhere:
      * RTL+       no cache; the upfront token is refetched per playback.
      * Magenta    the account_info lives on the auth token.
      * Discovery  the whole playbackInfo response lives in the
                   playback_cache, keyed by edit_id, TTL from
                   drm.expirationDate.
      * HRTi       the session dict lives in a session cache, populated
                   during the manifest step.

    Pick whichever fits. If DRM shares state with manifest, put the cache
    on the provider and pass it into both managers -- that is exactly the
    signal that the folded architecture is the right choice.

5. Testing
    DRM managers take http_manager and auth by injection, so they are
    testable without network access. Provide a mock http_manager that
    returns canned licence responses, and a mock auth that returns a
    canned token with the right claims. No real DRM call needed.

6. Fields on DRMConfig
    If your provider returns something not covered by the existing
    DRMConfig fields, do NOT extend DRMConfig. Instead:
      * If it's a header, add it to license.req_headers.
      * If it's a request body format, use license.req_data.
      * If it's something structurally new, raise it before extending the
        shared model -- every provider inherits changes.
"""

from typing import List, Optional

from ...base.models import DRMConfig
from ...base.utils.logger import logger


class YourDrmManager:
    """Dedicated DRM manager. Matches DrmManagerProtocol by shape."""

    def __init__(
        self,
        *,
        http_manager,     # shared HTTPManager from the provider
        auth,             # your Auth instance (matches AuthProtocol)
        country,
        config,
        # plus whatever else this provider's DRM needs:
        #   playback_manager=None, session_cache=None, ...
    ):
        self.http_manager = http_manager
        self.auth = auth
        self.country = country
        self.config = config

    def get_drm_configs(
        self,
        content_id: str,
        content_type: Optional[str] = None,
        **opts,
    ) -> List[DRMConfig]:
        raise NotImplementedError("YourDrmManager.get_drm_configs")