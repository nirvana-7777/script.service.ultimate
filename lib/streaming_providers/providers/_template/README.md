# Provider template

Copy this directory to `providers/{your_provider}/`, rename the classes,
and fill in the stubs. Read this file first — it explains the contract.

## What you get for free

- HTTP manager setup, proxying, retries.
- Credential storage / Kodi sync via the base `settings_manager`.
- Token caching and session persistence (in your Auth class).
- Capability flags (`implements_vod`, `implements_epg`, `implements_recordings`,
  ...) — derived from whether you wire up the corresponding manager.
- Shared error types, shared `VodPage` shape, shared `Channel` base.

## What you implement

1. **Auth** — `auth.py`. Writes the three shared methods and any optional
   extensions the provider needs.
2. **Managers** — one file per capability the provider supports. Each
   subclasses the corresponding ABC from `base/managers/` and implements
   the abstract methods. See "The manager ABCs" below for the full list.
3. **Provider wiring** — `provider.py`. Fills in the `_build_*` factory
   methods; returns `None` for capabilities the provider doesn't have.
4. **Constants** — `constants.py`. URLs, endpoints, static headers.
5. **Models** (optional) — `models.py`. Only if you need a custom Channel
   or AuthToken subclass.

## The manager ABCs

There are **seven** manager ABCs. Three are required capabilities, four
are optional. Providers implement the ones their service offers and
return `None` from the corresponding `_build_*()` for the rest.

### Required capabilities

    ChannelManager     -- live channels, channel manifest, channel DRM
    VodManager         -- browseable VOD catalogue (None for live-only)
    EpgManager         -- EPG (None for providers without EPG)

### Optional capabilities

    RecordingsManager  -- cloud / network PVR
    FavoritesManager   -- user favorites on programs / channels
    BookmarksManager   -- resume positions
    CatchupManager     -- timeshift / restart

**The rule: if a capability area has a public interface in the base
layer, it gets a manager ABC.** The base layer's
`ProviderRecordingsMixin`, `ProviderFavoritesMixin`,
`ProviderBookmarksMixin`, and `ProviderCatchupMixin` correspond
one-to-one to the four optional managers. Do not fold a capability into
another manager because the data happens to come from the same
endpoint — the public interface is the contract, not the URL.

### Constructor contract

All seven managers share the same constructor contract:

    def __init__(
        self,
        *,
        http_manager,
        auth,
        country,
        config,
        your_extra_collaborator=None,     # optional, subclass-specific
    ):
        super().__init__(
            http_manager=http_manager,
            auth=auth,
            country=country,
            config=config,
        )
        self._your_extra_collaborator = your_extra_collaborator

The base constructor accepts ONLY the four required collaborators. There
is no `**provider_opts` passthrough. This is deliberate: a typo at a call
site (`channel_cache=` instead of `channels_cache=`) raises `TypeError`
immediately rather than silently producing a half-configured manager.

Subclasses declare their extra keyword-only args explicitly, call
`super().__init__` with only the four required, and store extra state on
`self` after the super call.

Managers never hold a reference to the provider. If you need something
the provider owns, inject it at construction.

### Cross-manager collaborators

Some managers need collaborators from other managers. Common cases:

* **CatchupManager** needs `channels` (to resolve a live manifest URL or
  a stream uid) and/or `epg` (to resolve an epg_id from a start_time).
* **RecordingsManager** *may* need `channels` if the provider resolves
  a recording's manifest through the channel manager (simpliTV does
  this by default; the recordings manager itself never implements
  `get_manifest`, so the collaborator is only needed if the recordings
  manager fetches supplementary channel metadata).
* **DrmManager** (dedicated architecture) may need `channels` or `vod`
  to look up an asset's DRM config.
* **FavoritesManager** and **BookmarksManager** rarely need other
  managers, but if the content_id needs resolving to a program id, they
  may need a lookup helper.

Pass these as explicit keyword-only constructor arguments. The provider
builds them in dependency order:

    self.channels = self._build_channels()
    self.epg = self._build_epg()
    self.recordings = self._build_recordings()
    self.catchup = self._build_catchup()   # sees channels + epg
    ...

Don't introduce cycles between managers. If two managers need each
other, one of them should own the shared state and the other should
borrow it via a cache argument, not via a mutual reference.

If you find that a manager needs a provider-owned cache that isn't
otherwise exposed, pass the cache dict itself as a keyword-only
collaborator (as `playback_cache` is passed to simpliTV's channel and
catchup managers). Do not reach back to the provider.

Managers may also need each other's **content-id parsers**. Put the
parsers at module scope in the primary content-id namespace file
(usually `channel_manager.py`), and import them where needed. Parsers
are pure functions — no cross-manager state is involved.

### Capability flags

The provider exposes a derived boolean per capability:

    @property
    def implements_channels(self) -> bool:
        return self.channels is not None

    @property
    def implements_vod(self) -> bool:
        return self.vod is not None

    @property
    def implements_epg(self) -> bool:
        return self.epg is not None

    @property
    def implements_recordings(self) -> bool:
        return self.recordings is not None

    @property
    def implements_favorites(self) -> bool:
        return self.favorites is not None

    @property
    def implements_bookmarks(self) -> bool:
        return self.bookmarks is not None

    @property
    def implements_catchup(self) -> bool:
        return self.catchup is not None

    @property
    def implements_drm(self) -> bool:
        # See the DRM section for the folded-vs-dedicated derivation.

The pattern is uniform: a capability is present iff its manager object is
present. There is no separate boolean to keep in sync.

## Return-value rule: None vs exception

This is the single most important convention. Every manager follows it.

**Return None / [] for "not in my domain."**

`get_channel_manifest("clip_123")` from a channel manager that only
handles live channels returns `None`. Not an error — the router uses it
to fall through to the VOD manager. Same for `get_vod_manifest`,
`get_channel_drm`, `get_vod_drm`, `get_epg`, `get_recordings`,
`get_favorites`, `get_bookmarks`.

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

The router pattern in the provider's `_route()` helper is used for
methods whose input is an **opaque content_id** with multiple possible
owners. In practice that means:

    get_manifest(content_id)  -> channel | vod | catchup (whichever owns it)
    get_drm(content_id, ...)  -> channel | vod (whichever owns it)

Not every capability needs routing:

* **Capabilities with their own ID namespace** (recordings) don't route.
  `get_recordings()` and `delete_recording(recording_id)` are named
  methods on the recordings manager. The caller names the capability
  explicitly; there is no ambiguity to resolve.
* **Capabilities that operate on all content** (EPG, favorites,
  bookmarks) don't route. `get_epg(channel_id, ...)`,
  `add_favorite(content_id)`, `update_bookmark(content_id)` are named
  methods that go straight to their manager.
* **Capabilities that need cross-manager collaborators** (catchup) route
  through the provider if their content_id namespace overlaps with
  another manager's, or are called directly on their manager otherwise.

The rule: **route when a content_id could belong to more than one
manager. Otherwise, name the capability explicitly.**

### handles_content_id

For managers that DO participate in routing, override
`handles_content_id()` when the manager's content_id grammar has a
distinguishable shape:

    # In your VodManager:
    def handles_content_id(self, content_id: str) -> bool:
        return content_id.startswith(("details_", "clip_", "program_"))

    # In your ChannelManager:
    def handles_content_id(self, content_id: str) -> bool:
        return content_id.startswith(("live:", "vod:", "series:"))

If your provider has no content_id grammar, leave it returning `True` and
the router falls back to try-and-catch.

Which managers typically override `handles_content_id`:

* **ChannelManager**, **VodManager**, **CatchupManager** — yes.
  Content-id grammar usually has a prefix or shape that discriminates.
* **EpgManager** — has `handles_channel_id()`, used internally by
  `get_epg_grid()`. Does not participate in `_route`.
* **RecordingsManager** — has `handles_recording_id()` for the case
  where multiple recordings managers exist (cloud PVR + local PVR,
  say). Does not participate in `_route` for content_id, because
  recordings have their own ID namespace.
* **FavoritesManager**, **BookmarksManager** — usually no. They operate
  on whatever content_id the caller provides; there is no grammar to
  discriminate on.

`BadRequestError` is intentionally not caught by the router. Providers
that use a 400 response as an endpoint-dispatch signal (like Magenta's
page-vs-component guess) should override `handles_content_id()` instead,
so the router never has to guess.

### Parsers vs. dispatch

Two separate concerns that look similar:

* **Grammar**: what content_id shapes a manager will accept. Exposed
  as `handles_content_id()`. A manager whose grammar covers several
  prefixes returns True for all of them.

* **Dispatch**: which manager the router tries for a given id. This is
  the router's own decision, expressed by what it passes to `_route()`
  (or by explicit prefix branches above `_route`).

They can differ. In simpliTV:

* The channel manager's grammar covers `live:` and `rec:` — it accepts
  both.
* The router routes both through `_route` uniformly, because they
  resolve to the same endpoint.
* The catchup manager's grammar covers `catchup:<codename>@<ts>` — but
  the router does NOT route catchup through `_route`, because it needs
  to parse the `@<ts>` suffix and pass it as an argument.

The rule: **route through `_route` when the manager needs only the
content_id. Add an explicit prefix branch above `_route` when the
manager needs parsed arguments (a timestamp, an episode index, a
query-like suffix).** One parser, in the router.

### Content-id grammar parsers

Put content-id grammar parsers at module scope in the file that owns
the provider's primary content-id namespace (usually
`channel_manager.py`):

    def parse_live_id(content_id): ...
    def parse_recording_id(content_id): ...
    def parse_catchup_id(content_id): ...

Other managers and the provider import them from there. Do not
duplicate the parsers per manager — one grammar, one parser, imported
everywhere it's needed.

Parsers should raise `BadRequestError` on malformed input. The router
does not catch `BadRequestError`, so a malformed id surfaces to the
caller rather than silently falling through to the wrong manager.

Parsers must live at module scope, not as class methods, so multiple
managers can import them without a circular dependency.

### Multiple managers with the same prefix

Two managers may claim the same content-id prefix if their
responsibilities are disjoint. simpliTV:

* `SimpliTVChannelManager` accepts `rec:<codename>` for manifest and
  DRM — the streaming side.
* `SimpliTVRecordingsManager` owns `get_recordings` and
  `delete_recording` — the list side.

Only one of them participates in `_route` for the prefix, and the
choice is which manager owns the manifest fetch. The provider's
`get_manifest` is the authoritative declaration of that choice.

Do not give the same prefix two router branches. Two branches for the
same prefix means two code paths for the same content, and they will
drift.

### Sentinels for unused ABC parameters

If the ABC's method signature requires a parameter your provider's API
does not use, prefer `None` for optional arguments. The
`CatchupManager.get_catchup_manifest` signature declares `end_time` as
`Optional[int]` for exactly this reason — providers whose catchup API
only takes a start bound can pass `None` and document that they ignore
it.

Never pass `None` where the ABC expects `int`. Never pass `0` without a
comment — `0` is ambiguous (a valid timestamp? a "no value" marker?).
Prefer `None` when the ABC permits it; if it doesn't, add a comment
explaining the sentinel.

### Routing for recordings manifests

Some providers (simpliTV) route a recording's manifest through the
channel manager, because the API shares the codename namespace between
a channel and its recordings. Others may route through the VOD manager
or a dedicated playback path.

The routing lives in the provider's `get_manifest`, not in the
recordings manager. The recordings manager owns the *list* and the
*delete*; manifest resolution is the router's job. See
`providers/simplitv/provider.py` for a concrete example — it routes the
`rec:` prefix to the channel manager, whose `handles_content_id`
accepts it alongside `live:`.

Do not add a `get_manifest` method to `RecordingsManager`.

### Private helpers used by multiple managers

If a helper function is used by more than one manager, it is public by
default. Name it without the underscore.

    # Bad: catchup_manager imports _prefer_dash from channel_manager
    from .channel_manager import _prefer_dash

    # Good: the helper is public
    from .channel_manager import prefer_dash

The underscore-prefixed convention is for helpers private to one file.
An underscore-prefixed name imported across modules is a signal the
helper should either be renamed public or moved to a shared module
(`constants.py`, or a new `helpers.py`).

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

**Deviation: token not in a header.** Some providers pass the token as a
URL query parameter or body field rather than an `Authorization` header.
simpliTV does this — `build_headers()` returns base headers only, and
callers attach the token via `auth.with_token(url)` / `auth.auth_body()`.
If your provider deviates this way, document it prominently in your
`auth.py` module docstring **and** add a one-line comment at every
manager call site that uses `build_headers()`, so a future reader doesn't
assume a bearer token is being sent.

The manager ABCs verify `auth` against `AuthProtocol` at construction
time via `isinstance` (this works because the protocol is
`@runtime_checkable`). The check confirms method *presence*, not
signatures — a mismatched signature will not be caught here.

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
pattern is orthogonal to the architecture — any source can be wired
into either architecture. See `drm_manager.py` in this directory for
file-level references and mechanics:

    A. Per-content upfront token                    (RTL+)
    B. Constructed from token claims + /user/account  (Magenta)
    C. Arrives with the playbackInfo response         (Discovery, simpliTV)
    D. Session id becomes a base64 auth blob          (HRTi)

New-provider guidance: pick the architecture first (state-sharing rule
above), then pick the source pattern that most closely matches how the
provider's licence URL is produced, and adapt the mechanics.

The existing providers currently sit in a mix of shapes — some have DRM
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

## Catchup

Catchup is a distinct capability with its own manager. It is optional —
providers without catchup leave `_build_catchup()` returning `None` and
`implements_catchup` is `False`.

The catchup step is a *modified* live-manifest URL (with time
parameters) for some providers, a distinct URL from a different origin
for others, and an EPG-based resolution for others. The ABC names the
entry point; the shape is provider-specific.

**Do not fall back to the live manifest.** If `get_catchup_manifest`
cannot resolve catchup for the requested window, return `None`. Do not
return the live manifest URL — the DRM pipeline would extract PSSH from
the live stream, which may differ from the catchup stream's encryption
context. Callers that want the live manifest on failure should call
`provider.get_manifest()` themselves.

`end_time` is **Optional[int]** on the ABC. Providers whose catchup API
only takes a start bound (simpliTV) pass `None` and document that they
ignore the argument. Providers whose API uses both bounds require the
caller to pass it and raise `BadRequestError` on `None`. Do not pass a
sentinel value (`0`, `start_time + 1800`) when the ABC accepts `None`.

Catchup usually needs collaborators from other managers:

* **channels** — to resolve a live manifest URL (Magenta, simpliTV) or
  a stream uid (MoveTV).
* **epg** — to resolve an `epg_id` from a `start_time` (MoveTV).

Pass these as explicit keyword-only constructor arguments. See "Cross-
manager collaborators" above.

## Recordings

Recordings are a distinct capability with their own manager. Optional.

Recording identity is separate from content identity:

* `recording_id` is what you pass to `delete_recording`.
* `content_id` is what you pass to `get_manifest` to play the recording.

These are usually different namespaces. Keep them separate.

`get_recordings()` returns `Channel` objects (or a subclass carrying
`recording_id` and programme metadata). The base Channel shape is
preserved because downstream callers expect a `content_id` and a `name`.

`delete_recording` raises `KeyError` if the recording doesn't exist and
a `ProviderError` subclass on backend failure. It does **not** silently
return on failure — deleting a recording the user asked to delete and
having the deletion fail must surface.

**No manifest method.** The recordings manager deliberately has no
`get_manifest`. Recordings are played via a content_id that the
provider's router resolves — usually through the channel manager
(simpliTV) or the VOD manager, depending on how the provider's API
exposes the manifest. See "Routing for recordings manifests" above.

**Two managers may touch the `rec:` prefix.** The channel manager
accepts `rec:` for manifest and DRM fetch (the recording shares an
endpoint with its live channel). The recordings manager owns the list
and delete. This is not a conflict — they touch disjoint concerns.
Only one of them participates in the routing; the provider's
`get_manifest` is authoritative about which. See "Multiple managers
with the same prefix" above.

## Favorites and bookmarks

Both are optional, both are user-scoped, both follow the standard
manager contract.

Favorites: `FavoriteType` on each returned `Favorite` distinguishes
program / channel / clip / live / event. Providers that only support
one type validate the incoming type in `add_favorite` and reject the
others. Removing a non-existent favorite raises `KeyError`.

Bookmarks: `update_bookmark` is called on every playback stop / pause,
often consecutively for the same position. Providers should tolerate
repeated no-op writes to the same position without erroring or firing
spurious events. `position_seconds = -1` marks the content as
completed. Deleting a non-existent bookmark raises `KeyError`.

## Conventions

- **Custom Channel / AuthToken subclasses are fine.** Call
  `super().to_dict()` in your override. MoveTV, Discovery, HRTi, and
  simpliTV all do this.
- **Provider owns caches; managers borrow them.** Create caches in the
  provider's `__init__`; pass them into manager constructors by
  reference.
- **Content ID grammar is provider-specific.** Pick one and document it
  in the manager's docstring, or in a module-scope parser (see
  "Content-id grammar parsers" above).
- **Playback authorization is provider-specific.** Don't force it into a
  shared interface. See the existing providers for examples.
- **Extra capabilities that don't fit an ABC.** If the provider has a
  capability area that doesn't correspond to a base-layer mixin and
  doesn't warrant a new ABC, put the methods on the concrete manager
  that owns the domain, and pass them through on the provider. Document
  the capability in the manager's class docstring. Don't invent an
  ad-hoc manager class.

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

## Reference providers

The six existing providers, in order of implementation complexity:

    simpliTV    -- built from this template. Recordings + catchup + folded
                   DRM. Content-id grammar with three prefixes, module-scope
                   parsers, and a router that parses the catchup timestamp.
                   Good first read.
    MoveTV      -- dynamic manifests, play-auth headers, EPG-based catchup.
    Magenta EU  -- EPG-heavy, VOD with typed errors, multi-country.
    HRTi        -- session-authorize playback, custom credentials shape.
    Discovery   -- dynamic endpoint discovery, Arkose challenge, playbackInfo.
    RTL+        -- layout-driven, three tokens, largest surface.

Read the closest one before writing a new provider. Each demonstrates a
different source pattern for DRM, a different content-id grammar, and a
different shape for playback authorization.