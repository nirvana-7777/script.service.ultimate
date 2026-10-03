# Provider template

Copy this directory to `providers/{your_provider}/`, rename the classes,
and fill in the stubs. Read this file first — it explains the contract.

## What you get for free

- HTTP manager setup, proxying, retries.
- Credential storage / Kodi sync via the base `settings_manager`.
- Token caching and session persistence (in your Auth class).
- Capability flags (`implements_vod`, `implements_epg`) — derived from
  whether you wire up the corresponding manager.
- Shared error types, shared `VodPage` shape, shared `Channel` base.

## What you implement

1. **Auth** — `auth.py`. Writes the three shared methods and any optional
   extensions the provider needs.
2. **Managers** — `channel_manager.py`, `vod_manager.py`, `epg_manager.py`.
   Each subclasses the corresponding ABC from `base/managers/` and
   implements the abstract methods.
3. **Provider wiring** — `provider.py`. Fills in `_build_*` factory
   methods; returns `None` for capabilities the provider doesn't have.
4. **Constants** — `constants.py`. URLs, endpoints, static headers.
5. **Models** (optional) — `models.py`. Only if you need a custom Channel
   or AuthToken subclass.

## The manager ABCs

Subclass `base.managers.ChannelManager`, `VodManager`, `EpgManager`. Each
has the same constructor contract and a small public interface.

**Constructor contract:**

    def __init__(
        self,
        *,
        http_manager,
        auth,
        country,
        config,
        your_extra_cache=None,     # any extra keyword-only args you need
    ):
        super().__init__(
            http_manager=http_manager,
            auth=auth,
            country=country,
            config=config,
        )
        self._your_extra_cache = your_extra_cache or {}

The base constructor accepts ONLY the four required collaborators. There
is no `**provider_opts` passthrough. This is deliberate: a typo at a call
site (`channel_cache=` instead of `channels_cache=`) raises `TypeError`
immediately rather than silently producing a half-configured manager.

Subclasses declare their extra keyword-only args explicitly, call
`super().__init__` with only the four required, and store extra state on
`self` after the super call.

Managers never hold a reference to the provider. If you need something
the provider owns, inject it at construction.

## Return-value rule: None vs exception

This is the single most important convention. Every manager follows it.

**Return None / [] for "not in my domain."**

`get_channel_manifest("clip_123")` from a channel manager that only
handles live channels returns `None`. Not an error — the router uses it
to fall through to the VOD manager. Same for `get_vod_manifest`,
`get_channel_drm`, `get_vod_drm`, `get_epg`.

**Raise for genuine failures.**

- `AuthError` — token expired or invalid. Caller refreshes and retries.
- `GeoBlockError` — content not available in the caller's region.
- `EntitlementError` — authenticated but not subscribed.
- `RateLimitError` — caller should back off.
- `ServerError`, `TransportError` — transient.
- `PlaybackRestrictedError` — refused for a non-entitlement reason.
- `NotFoundError` — the provider knows this content belongs in its domain
  but has been removed.
- `BadRequestError` — 400 from the wrong endpoint. Not swallowed by the
  router; providers that use 400 as a routing signal should override
  `handles_content_id()` instead.

`NotFoundError` and `None` mean different things, and the router preserves
the distinction:

    provider.get_manifest("gone_123")     -> raises NotFoundError
    provider.get_manifest("unknown_456")  -> returns None

The router tracks any `NotFoundError` raised by a manager, tries the next
manager, and re-raises the last `NotFoundError` if nobody resolved. So a
caller can distinguish "removed" from "not in anyone's domain."

Rule of thumb: **"I don't handle this" is a return value; "this is a real
failure" is an exception.**

## Routing with handles_content_id()

The orchestrator's `get_manifest` / `get_drm` try managers in order. To
avoid a wasted request, override `handles_content_id()` on managers whose
content_ids have a distinguishable shape:

    # In your VodManager:
    def handles_content_id(self, content_id: str) -> bool:
        return content_id.startswith(("details_", "clip_", "program_"))

    # In your ChannelManager:
    def handles_content_id(self, content_id: str) -> bool:
        return content_id.isdigit()

If your provider has no content_id grammar, leave it returning `True` and
the router falls back to try-and-catch.

`BadRequestError` is intentionally not caught by the router. Providers
that use a 400 response as an endpoint-dispatch signal (like Magenta's
page-vs-component guess) should override `handles_content_id()` instead,
so the router never has to guess.

## The Auth protocol

Auth is a documented protocol (see `base/protocols.py`), not an ABC.
Every provider writes:

    get_access_token(force_refresh=False) -> str
        Raw token string. No scheme prefix.

    build_headers(token=None, **opts) -> Dict[str, str]
        Request-ready headers including auth. If token is None, use the
        cached token (via get_access_token).

    invalidate() -> None
        Drop cached token and session state. Called after 401s.

Optional extensions — implement only if needed:

    get_scoped_token(scope, **opts) -> Optional[str]
        Secondary tokens. RTL+ uses this for bedrock / upfront.

    get_session_context() -> Optional[Dict[str, Any]]
        Opaque session state needed by build_headers. Magenta uses this
        for guest device/session ids; Discovery for cookie + session-state
        headers.

    authorize_playback(content_id, **opts) -> Dict[str, Any]
        Provider-specific pre-playback step. HRTi's AuthorizeSession,
        MoveTV's live-source fetch, Discovery's playbackInfo POST,
        RTL+'s upfront token, Magenta's persona JWT retrieval.

There is no fixed interface for `authorize_playback`. The name is a
convention; the shape is provider-specific.

The manager ABCs verify `auth` against `AuthProtocol` at construction
time via `isinstance` (this works because the protocol is
`@runtime_checkable`). The check confirms method *presence*, not
signatures — a mismatched signature will not be caught here.

## Conventions

- **Custom Channel / AuthToken subclasses are fine.** Call
  `super().to_dict()` in your override. MoveTV, Discovery, and HRTi all
  do this.
- **Provider owns caches; managers borrow them.** Create caches in the
  provider's `__init__`; pass them into manager constructors.
- **Content ID grammar is provider-specific.** Pick one and document it
  in the manager's docstring.
- **Playback authorization is provider-specific.** Don't force it into a
  shared interface. See the five existing providers for five shapes.

## DRM

DRM is optional. Providers with no DRM leave `_build_drm()` returning
`None` and don't override `get_channel_drm` / `get_vod_drm`. The
provider's `get_drm()` returns `[]` and `implements_drm` is `False`.

Providers with DRM make two independent choices.

### Architecture: dedicated manager vs. folded into managers

    Rule: Does the DRM step share state with the manifest step?
          yes -> fold into the channel/vod managers
          no  -> use a dedicated DRM manager

    Tie-breaker: when both work, prefer the dedicated manager, because it
    keeps DRM logic in one place. Folded exists for cases where the
    alternative would be plumbing session state, an upfront token, or a
    playbackInfo response between two managers that both need it.

"State" means any value the DRM step would otherwise have to receive
from the manifest step: a session id, an upfront token, a playbackInfo
response, an account/licence structure, and so on.

### Source pattern: how the licence URL is produced

Four source patterns appear across the existing providers. The source
pattern is orthogonal to the architecture -- any source can be wired
into either architecture. See `drm_manager.py` in this directory for
file-level references and mechanics:

    A. Per-content upfront token                    (RTL+)
    B. Constructed from token claims + /user/account  (Magenta)
    C. Arrives with the playbackInfo response         (Discovery)
    D. Session id becomes a base64 auth blob          (HRTi)

New-provider guidance: pick the architecture first (state-sharing rule
above), then pick the source pattern that most closely matches how the
provider's licence URL is produced, and adapt the mechanics.

The existing providers currently sit in a mix of shapes -- some have DRM
logic directly on the provider class, some in a playback manager, some
in a VOD manager that predates this template. "Source pattern" describes
what their code does, not what class it lives in. Migrating any provider
onto the dedicated or folded architecture is optional; when migrated,
each will map to whichever architecture the state-sharing rule selects.

### The three method names

Three names appear in the DRM path. They are not interchangeable:

    get_drm_configs   -- the dedicated DrmManager's only method
                         (matches DrmManagerProtocol)
    get_channel_drm   -- the folded architecture's live-channel entry point
    get_vod_drm       -- the folded architecture's VOD entry point

New providers using the dedicated-manager architecture implement
`get_drm_configs` and leave the other two alone. Providers using the
folded architecture override `get_channel_drm` and/or `get_vod_drm` and
leave `get_drm_configs` alone.

`StreamingProvider.get_drm(content_id, content_type=None)` is the public
method callers use; it dispatches to whichever architecture the provider
chose.

### content_type hint semantics

`content_type` is an optional hint. Pass it when you already know the
content type (e.g. the backend streaming route, which has already
resolved the item). It is a *narrowing* hint, not a required argument.

On the folded path, only two values narrow the search:

    "live"  -> channel manager only
    "vod"   -> VOD manager only

Any other value -- including None, "event", "catchup", or a typo --
tries both. This is deliberate: widening on unknown input is always
safe, but a wrong narrowing produces a silent `[]` for protected
content, which is the hardest kind of bug to trace.

On the dedicated-manager path, the hint is passed through to
`get_drm_configs`. The manager may honour it, ignore it, or infer the
type from `content_id` grammar when `content_type is None`. Managers are
encouraged to widen when in doubt, for the same reason as above.

## Errors

Raise from `base.errors`:

    AuthError, CredentialsError, SessionExpiredError,
    GeoBlockError, EntitlementError, AccountRestrictedError,
    PlaybackRestrictedError,
    NotFoundError, BadRequestError,
    RateLimitError, ServerError, TransportError,
    CatchupRequiredError, NotImplementedYetError, ConfigurationError

Subclass when you need to carry payload:

    class MyProviderCatchupError(CatchupRequiredError): ...

Existing callers that catch the base class catch your subclass too.
`ProviderError.__reduce__` preserves subclass payload across pickle and
`copy.deepcopy`, so payload-carrying subclasses are safe to pass through
queues and process boundaries.

## VOD return type

Every VOD navigation method returns `VodPage` (base/vod.py):

    return VodPage(entries=[...], next_cursor="2", total=120)
    return VodPage(entries=[...])                     # no pagination
    return VodPage()                                  # empty

Pagination rule: use `page.has_more` — NOT `bool(page)` — to decide
whether to keep paging. `bool(page)` follows list semantics (empty page
is falsy, page with entries is truthy), which is correct for "are there
entries to display?" but wrong for pagination, because a page can have
zero entries and a non-None `next_cursor`.

`total` may be `None`. It is informational; do not use it as an
end-of-list signal. `next_cursor is None` (equivalently, `not
page.has_more`) is the authoritative signal.

## Lazy auth

The template does NOT authenticate in `__init__`. The first
`build_headers()` / `get_access_token()` call triggers authentication.
This avoids network I/O in constructors and lets you create a provider
object for inspection without hitting the network.

If your provider has a strong reason to authenticate eagerly (e.g. you
need to fail fast on bad credentials), do it in the provider's `__init__`
inside a try/except and log a warning — do not raise.