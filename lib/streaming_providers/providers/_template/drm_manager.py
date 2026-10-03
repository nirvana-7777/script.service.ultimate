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

How to structure a DRM manager for a new provider
-------------------------------------------------

1. Class shape
    class YourDrmManager:
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
            ...

        def get_drm_configs(
            self,
            content_id: str,
            content_type: Optional[str] = None,
            **opts,
        ) -> List[DRMConfig]:
            # If content_type is None, infer it from content_id grammar.
            ...

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

3. Reference implementations
    The four existing patterns differ enough that picking the closest
    match and adapting it is faster than designing from scratch. Read
    the referenced files before writing yours; the description below
    is a summary, the code is the source of truth.

    Pattern A -- per-content upfront token
        Files:  providers/rtlplus/provider.py (DRM flow)
                providers/rtlplus/auth.py (upfront token)
                providers/lib_drmtoday.py (the shared library)

        Summary: fetch the layout for the content_id, extract the DRM
        asset config, call auth.get_scoped_token("upfront", content_id,
        uid), then lib_drmtoday.create_drmtoday_configs(...). Returns
        [widevine, playready] in one call.

        Requires an authenticated user (profile selected). The upfront
        token is per-content, not per-session.

    Pattern B -- construct licence URL from token claims
        Files:  providers/magentaeu/vod_manager.py (DRM flow)
                providers/magentaeu/provider.py (live DRM flow)
                providers/magentaeu/auth.py (token claims)
                providers/lib_theplatform.py (URL + config builders)

        Summary: resolve the media item to get release_pid (via the
        /media endpoint), read persona_jwt from the access token claims,
        read account_uri from /user/account, then
        lib_theplatform.build_licence_url(...) and
        lib_theplatform.build_widevine_drm_config(...). Returns
        [widevine].

        The licence URL is CONSTRUCTED, not fetched -- three data
        sources: /media response, token claims, /user/account.

    Pattern C -- DRM arrives with the playback response
        Files:  providers/discovery/playback_manager.py (playbackInfo +
                DRM extraction in one place)
                providers/discovery/constants.py (platform_os -> DRM
                system mapping)

        Summary: during get_manifest, POST playbackInfo and cache the
        response. get_drm() is a cache lookup; no separate DRM call.
        The response carries both widevine and playready schemes with
        licenseUrl each; pick the one matching the active platform_os.
        Returns [widevine] or [playready].

        DRM and manifest share the playbackInfo cache. Do NOT re-fetch.
        drm.expirationDate governs cache invalidation.

    Pattern D -- session id becomes a base64 auth blob
        Files:  providers/hrti/provider.py (both live and VOD DRM flows)
                providers/hrti/auth.py (session authorize + licence
                data generation)
                providers/lib_drmtoday.py (the shared library)

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
      * Magenta    the account_info lives on the auth token, not the
                   DRM manager.
      * Discovery  the whole playbackInfo response lives in the
                   playback_cache, keyed by edit_id, TTL from
                   drm.expirationDate.
      * HRTi       the session dict lives in a session cache, populated
                   during the manifest step.

    Pick whichever fits. If DRM shares state with manifest, put the cache
    on the provider and pass it into both managers, matching the pattern
    the other managers already use.

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