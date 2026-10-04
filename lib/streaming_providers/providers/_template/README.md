# Provider template

Copy this directory to `providers/{your_provider}/`, rename the classes,
and fill in the stubs. Read this file first — it explains the contract.

## What you get for free

- HTTP manager setup, proxying, retries.
- Credential storage / Kodi sync via the base `settings_manager` (if the
  provider needs credentials).
- Token caching and session persistence (in your Auth class, if you have one).
- Capability flags (`implements_vod`, `implements_epg`, `implements_recordings`,
  ...) — derived from whether you wire up the corresponding manager.
- Shared error types, shared `VodPage` shape, shared `Content`/`Channel`
  data model.

## What you implement

1. **Provider** — `provider.py`. Required. Declares the provider's class
   members, wires up whatever managers it has, and exposes the public
   interface.
2. **Auth** — `auth.py`. Optional. Required only if the provider
   authenticates requests. Free / static-key providers can omit it
   entirely, or provide a minimal `Auth` that only sets base headers.
3. **Managers** — one file per capability the provider supports. Each
   subclasses the corresponding ABC from `base/managers/` and implements
   the abstract methods. **All seven managers are optional** — a
   VOD-only provider has no `ChannelManager`; a linear-only provider has
   no `VodManager`; a favorites-sync-only provider may have neither.
   See "The manager ABCs" below.
4. **Constants** — `constants.py`. URLs, endpoints, static headers.
5. **Models** — often required. A custom `AuthToken` subclass is
   mandatory whenever the auth class returns a `BaseAuthToken`, because
   `BaseAuthToken` is an ABC with an abstract `to_dict()`. A custom
   Channel subclass is optional. See "Models" below.

## Provider class members

Every provider declares these. Some are abstract (must be implemented by
the concrete class, or the class cannot be instantiated); some are class
attributes with defaults.

### Required abstract property

    @property
    def provider_name(self) -> str: ...

**This is abstract on StreamingProvider.** A subclass that does not
override it cannot be instantiated — Python raises
`TypeError: Can't instantiate abstract class ... with abstract method
provider_name` the moment the registry calls `YourProvider(country=...)`.

The failure is silent if you don't notice it: the registry catches the
exception, logs "Failed to create instance for {name}: ..." at ERROR
level, and moves on. The provider simply does not appear in the UI. If
your provider is registered but never instantiates, this is the first
thing to check.

The value is the provider's machine identifier — lowercase, no spaces,
used in settings keys, log lines, and the `provider` field on models.
It should match the plugin directory name and the `PROVIDER_NAME`
constant in `constants.py`.

    @property
    def provider_name(self) -> str:
        return "your_provider_name"

### Required class attributes

    PROVIDER_LABEL: ClassVar[str]
        Display name, e.g. "simpliTV". Used by the registry and the UI.

    PROVIDER_LOGO: ClassVar[str]
        Logo URL.

    SUPPORTED_AUTH_TYPES: ClassVar[List[str]]
        e.g. ["user_credentials"], ["anonymous"], or ["user_credentials",
        "anonymous"] if the provider supports both.

    SUPPORTED_COUNTRIES: ClassVar[List[str]]
        ALWAYS set this. See "SUPPORTED_COUNTRIES is not optional" below.

### SUPPORTED_COUNTRIES is not optional

**Always declare `SUPPORTED_COUNTRIES`.** Never leave it at the base
default. The base class defines it as an empty list, which has a
specific meaning: "the provider does not support country-specific
instances." That meaning is easy to collide with the accidental case of
"the author forgot to declare it," and the failure mode is silent — the
provider shows up in every country's list or in none, depending on
which code path reads it.

Declare it explicitly, even for a single-country provider:

    # Single country
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = ["AT"]

    # Multi-country with per-country instances
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = ["hr", "pl", "me", "at", "hu"]

    # Multi-country with per-country instances but no explicit list —
    # the provider discovers its country at runtime (Discovery+ shape)
    SUPPORTED_COUNTRIES: ClassVar[List[str]] = ["*"]

The three cases:

* **Single country** — one-element list. The registry creates one
  instance for that country.
* **Multi-country** — one instance per listed country. `country` is a
  constructor argument; each instance is independent.
* **Wildcard** — `["*"]`. The registry creates one instance for the
  default country; the provider discovers its actual country at
  runtime (e.g. from a `/users/me` call).

An empty list is reserved for providers with no country concept at all
(a purely global, country-agnostic service). If you find yourself
wanting to leave it empty because "I'm not sure yet," declare `["*"]`
instead — it's honest about the ambiguity and behaves correctly in
both the registry and the runtime.

### Cross-check: what the registry reads

The registry's `ProviderMetadata._extract_metadata` reads these members
before any instance exists. If any are missing or wrong, the provider
misbehaves in the UI even if the runtime works.

    PROVIDER_LABEL                -> metadata.label
    PROVIDER_LOGO                 -> metadata.logo
    SUPPORTED_AUTH_TYPES          -> metadata.supported_auth_types
    SUPPORTED_COUNTRIES           -> metadata.supported_countries
    class.__name__                -> metadata.plugin_name (derived)

The plugin name is derived from the class name:
`cls.__name__.lower().replace("provider", "")`. `YourProvider` becomes
`your`. If your class name is non-standard the derived name will be
wrong — pick a class name whose lowercase form (minus the word
"provider") matches your intended plugin name.

## Models

The base package provides `Content` (the base dataclass) and its
subclass `Channel`. Both are dataclasses, and providers build on them
rather than replacing them.

### `Content` — the base dataclass

`Content` holds every field that all provider content shares: name,
id, provider, manifest URLs, DRM placeholders, metadata, pricing.
`Channel` extends it with channel-specific fields. See
`base/models/content.py` and `base/models/channel.py` for the full
field list.

**Key fields and how to set them:**

- `manifest: Optional[str]` — the static manifest URL, when the
  provider has one. Set directly, or via `set_static_manifest(url)`.
- `manifest_script: Optional[str]` — for dynamic manifests, provider-
  specific parameters fetched at request time. Set via
  `set_dynamic_manifest(params)`.
- `session_manifest: bool` — True when the manifest must be fetched
  per-session. Mutually exclusive with `manifest` in practice: if
  `session_manifest=True` and `manifest` is also set, `Channel`'s
  `_validate_fields` logs a warning and the static URL is ignored.
- `streaming_format: Optional[str]` — `"dash"`, `"hls"`, or None.
  Serialized as `"StreamingFormat"` in `to_dict()`.

**Do not set both `manifest` and `manifest_script` and expect both to
be used.** They are alternatives. If the provider fetches the manifest
per-session, use `set_dynamic_manifest` and leave `manifest` None.

**Serialization key convention.** `to_dict()` emits TitleCase keys
(`Name`, `Id`, `Provider`, `Manifest`, `StreamingFormat`, ...). A
subclass adding fields via `result["YourField"] = ...` must match this
convention — TitleCase, no underscores. Downstream consumers expect
uniform keys.

### `Channel` — the base channel dataclass

`Channel` extends `Content` with `channel_number`, `is_radio`, and
`catchup_hours`. It also provides:

**Three factory classmethods — use these, don't construct directly:**

    Channel.create_live_channel(name, channel_id, provider, **kwargs)
    Channel.create_vod_channel(name, content_id, provider, **kwargs)
    Channel.create_radio_channel(name, channel_id, provider, **kwargs)

Each sets `mode` and `content_type` (and `is_radio`/`quality` for
radio) correctly, so the resulting object never trips the
`__post_init__` consistency warnings. The factories use `cls(...)`, so
a subclass `SimpliTVChannel.create_live_channel(...)` returns a
`SimpliTVChannel`, not a base `Channel`. Subclasses should use the
inherited factories rather than construct directly.

**Note the parameter-name inconsistency:** `create_live_channel` and
`create_radio_channel` take `channel_id`, while `create_vod_channel`
takes `content_id`. All three set the dataclass field `content_id`
internally. If you call `create_vod_channel(channel_id=...)` you get
`TypeError`. Pass positionally or use the right keyword.

**`__post_init__` mutates `content_type` and `quality` for radio.** If
`is_radio=True` and `content_type="LIVE"`, the base class rewrites the
content_type to `"RADIO"` and quality to `"AUDIO"`. This happens in the
base class, so a subclass that sets these differently must account for
it (or pass `content_type` and `quality` explicitly and skip the
`is_radio=True` path). See `channel.py`'s `__post_init__`.

**`__post_init__` also logs warnings for inconsistent fields.** A
`Channel` with `mode="vod"` and `content_type="LIVE"` gets a warning,
not an exception. Same for `session_manifest=True` combined with a
static `manifest`. These are advisory — the code runs — but they
indicate a likely provider bug. Check the logs during development; a
clean startup log with no `Channel ...:` warnings is the goal.

**`detect_and_set_radio()` is heuristic and mutates in place.** It
looks at `name`, `quality`, `description`, and `genre` for radio
indicators and sets `is_radio=True` if any match. Providers whose
channel classification is authoritative (from an API field) should set
`is_radio` at construction and not call this method. Providers whose
classification comes from names or metadata can call it after
construction.

### Subclassing `Channel`

A provider that carries extra per-channel fields subclasses `Channel`
and adds them. MoveTV, Discovery, HRTi, and simpliTV all do this.

Rules:

1. **Call `super().to_dict()` and add fields in TitleCase.** The base
   serializer emits TitleCase; subclasses must match.

2. **Keep the base field names and defaults.** Add new fields at the
   end with sensible defaults, so existing construction patterns
   (positional or keyword) don't break.

3. **Do not remove or rename base fields.** Downstream consumers read
   `channel_id` / `content_id`, `name`, `manifest`, and the other base
   fields. If the provider needs a differently-named field, add it as
   a new field rather than renaming.

4. **Use the inherited factory methods.** `YourChannel.create_live_channel(...)`
   returns a `YourChannel` because the factories use `cls(...)`. Do not
   override them unless you need to change what they set.

Example:

    @dataclass
    class YourChannel(Channel):
        codename: str = ""
        recording_id: str = ""
        recording_status: str = ""

        def to_dict(self) -> Dict[str, Any]:
            result = super().to_dict()
            result["Codename"] = self.codename
            result["RecordingId"] = self.recording_id
            result["RecordingStatus"] = self.recording_status
            return result

### The `StreamingChannel` alias

`base/models/channel.py` ends with:

    StreamingChannel = Channel

`StreamingChannel` and `Channel` are the same class. Providers and
consumers may import either name; both refer to the same type.
Do not treat them as distinct classes — `isinstance(x, StreamingChannel)`
and `isinstance(x, Channel)` are identical checks.

### `StreamingMode` and `ContentType` are not Enums

`base/models/content.py` defines them as plain classes with string
class attributes:

    class StreamingMode:
        LIVE = "live"
        VOD = "vod"

    class ContentType:
        LIVE = "LIVE"
        VOD = "VOD"
        SERIES = "SERIES"
        MOVIE = "MOVIE"
        RADIO = "RADIO"

Consequences:

- Compare with `==`, not `is`. `channel.mode == StreamingMode.LIVE`
  works; `channel.mode is StreamingMode.LIVE` is fragile (string
  interning makes it usually work, but not guaranteed).
- `isinstance(x, StreamingMode)` never works. There is no instance of
  `StreamingMode` — it's a namespace, not a type.
- Do not `import Enum` and try to `StreamingMode.LIVE.value`. The
  attribute is already a string.

If you find yourself wanting stricter typing, use the string values
directly (`"live"`, `"vod"`, `"LIVE"`, ...). The classes exist for
readability and autocomplete, not type enforcement.

### `AuthToken` subclasses

`BaseAuthToken` is an ABC with an abstract `to_dict()`, so it cannot be
instantiated directly. Every provider whose `_perform_authentication()`
returns a `BaseAuthToken` needs a concrete subclass — usually tiny:

    @dataclass
    class YourAuthToken(BaseAuthToken):
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

If the provider doesn't persist tokens, `to_dict()` is never called at
runtime — but it still must exist, because the ABC requires it. Provide
a real implementation so that a future change to persist tokens works
without a follow-up edit.

### `Credentials` subclasses (optional)

Only needed when the provider's login payload isn't the usual
`{username, password}` shape. HRTi's `grant_access` takes
`{Username, Password, OperatorReferenceId}`, so it has a custom
`HRTiCredentials(UserPasswordCredentials)` with a `to_auth_payload()`
override. Most providers use `UserPasswordCredentials` directly.

## The manager ABCs

There are **seven** manager ABCs. **All seven are optional.** A provider
implements the ones its service offers and returns `None` from the
corresponding `_build_*()` for the rest.

    ChannelManager     -- live channels, channel manifest, channel DRM
    VodManager         -- browseable VOD catalogue
    EpgManager         -- EPG
    RecordingsManager  -- cloud / network PVR
    FavoritesManager   -- user favorites on programs / channels
    BookmarksManager   -- resume positions
    CatchupManager     -- timeshift / restart

**The rule: if a capability area has a public interface in the base
layer, it gets a manager ABC. If the provider has the capability, wire
the manager; if not, return `None` from the factory.** The base layer's
`ProviderRecordingsMixin`, `ProviderFavoritesMixin`,
`ProviderBookmarksMixin`, and `ProviderCatchupMixin` correspond
one-to-one to the four optional managers. Do not fold a capability into
another manager because the data happens to come from the same
endpoint — the public interface is the contract, not the URL.

### Providers vary in which managers they have

Common shapes:

    Linear-only free provider    -> ChannelManager + EpgManager
    Linear + catchup             -> ChannelManager + EpgManager + CatchupManager
    VOD-only                     -> VodManager
    VOD + linear                 -> ChannelManager + VodManager
    Linear + recordings          -> ChannelManager + RecordingsManager (+ EpgManager)
    Metadata-only (EPG feed)     -> EpgManager only
    Favorites-sync-only          -> FavoritesManager only

Do not assume "every provider has channels." Do not assume "every
provider has VOD." Do not assume "every provider has EPG." If a
capability is missing, `_build_*()` returns `None`, the capability flag
is `False`, and callers that gate on the flag skip it cleanly.

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

Do not give the same prefix two router branches. Two branches for thesame prefix means two code paths for the same content, and they will
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
**Auth is optional** — a free provider that never authenticates requests
does not need one at all.

### Providers without auth

Some providers need no authentication:

* Free, public-content providers with no user accounts.
* Static-API-key providers where the key never changes and is best
  expressed in `constants.py` headers.
* Providers where every request is anonymous and no session state is
  carried.

For these, `_build_auth()` returns `None`, `self.auth = None`, and any
manager that receives `auth=None` must not call its methods. This is
supportable but produces a warning from the manager base constructors
(the `AuthProtocol` isinstance check fires). If you are writing a
provider with no auth:

* Return `None` from `_build_auth()`.
* Either accept the warning (it is non-fatal — the manager still
  constructs and runs), or
* Provide a minimal `Auth` stub that only implements `build_headers()`
  and returns the static headers. This is usually cheaper than
  suppressing the warning, because managers that call `auth.build_headers()`
  still work.

Minimal no-auth stub:

    class YourNoAuth:
        """Auth stub for a provider with no authentication."""

        def get_access_token(self, force_refresh=False):
            return ""

        def build_headers(self, token=None, **opts):
            return {"User-Agent": "...", "Accept": "application/json"}

        def invalidate(self):
            pass

        # Credential methods are no-ops for a no-auth provider.
        def has_credentials(self):
            return True

        def set_credentials(self, username, password):
            return False

        def clear_credentials(self):
            return False

Wire it as `self.auth = YourNoAuth()` in `_build_auth()`. The manager
ABCs' isinstance check passes (all three required methods are present),
and `build_headers()` returns whatever static headers the provider
needs.

### Providers with auth

Every provider with auth writes:

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

**Thread safety.** If the host serves requests from multiple threads
(which it does), and your auth flow involves more than one HTTP call
(e.g. login + device registration, or login + feature-flags fetch), wrap
`get_access_token()` and any other stateful accessor in a
`threading.RLock`. Without it, two threads hitting a cold cache will each
start the full flow, and the second one will either duplicate the work
or observe partial state. Providers whose auth flow is a single HTTP
call can skip the lock; providers whose flow has two or more round-trips
need it.

**Token placement deviation: not in a header.** Some providers pass the
token as a URL query parameter or body field rather than an
`Authorization` header. simpliTV does this — `build_headers()` returns
base headers only, and callers attach the token via
`auth.with_token(url)` / `auth.auth_body()`. If your provider deviates
this way, document it prominently in your `auth.py` module docstring
**and** add a one-line comment at every manager call site that uses
`build_headers()`, so a future reader doesn't assume a bearer token is
being sent.

When the query-parameter name differs per endpoint (simpliTV's
`GetRecordings` uses `tokenValue` instead of `token`), put both names in
`constants.py` and give `with_token()` a `param=` keyword so the caller
can pick. Do not hardcode the parameter name in the auth class.

**Content-Type deviation: JSON body, non-JSON header.** Some endpoints
reject `Content-Type: application/json` even though the body is valid
JSON, and return a different (often empty) response when the header is
"correct". simpliTV's `/Authenticate` is the canonical example: it
requires `Content-Type: text/plain` with a JSON body. If your provider
has an endpoint like this, send the body as a raw string
(`data=json.dumps(payload)`) with the header set explicitly **for that
call only**, and add a comment explaining why — a future reader will
otherwise "fix" the header and silently break the login.

The manager ABCs verify `auth` against `AuthProtocol` at construction
time via `isinstance` (this works because the protocol is
`@runtime_checkable`). The check confirms method *presence*, not
signatures — a mismatched signature will not be caught here. A warning
from this check means the `auth` object is missing one of the three
required methods; it is not fatal, but it usually means a wiring
mistake.

### Credentials — how they get loaded, saved, and re-checked

The `AuthProtocol` names the three *token* methods. It does not name the
*credential* methods, because credentials only exist for providers that
have them. But every provider that has credentials must implement the
credential surface correctly, or the auth class works only when the
caller passes credentials directly at construction — which never happens
in the real runtime. This is the failure mode most likely to slip
through a naive implementation: the provider instantiates cleanly,
`_build_auth` returns an object, and then the first `get_access_token()`
raises `CredentialsError` because nothing ever populated the
credentials.

The three credential methods:

    has_credentials() -> bool
        Return True if this auth can authenticate right now — i.e.
        credentials are available from the constructor argument, the
        settings manager, or a fallback that always succeeds.
        Called by the UI and the registry to decide whether the
        provider is usable.

    set_credentials(username, password) -> bool
        Persist credentials via
        settings_manager.save_provider_credentials(provider_name,
        UserPasswordCredentials(username, password), country).
        Called by the settings UI when the user enters credentials.
        Return True on success.

    clear_credentials() -> bool
        Clear stored credentials via
        settings_manager.clear_provider_credentials(...) or
        credential_manager.delete_credentials(provider_name, country).
        Also call self.invalidate() to drop the cached token.
        Return True on success.

**Credentials source priority, checked in this order:**

1. **Constructor argument.** The provider's `_build_auth()` passes
   `credentials=self._credentials`, which is non-None only when the
   caller constructed the provider with explicit credentials. This is
   the case for CLI tools and tests, not for the runtime UI flow.
2. **Injected `settings_manager`.** If the host passed a
   `settings_manager` to the provider's constructor (or the provider
   forwards one to `_build_auth`), call
   `settings_manager.get_provider_credentials(provider_name, country)`.
   This reads credentials the settings UI wrote through
   `save_provider_credentials`. **This path is preferred when present,
   but is not guaranteed to be present.**
3. **`CredentialManager` (direct file read).** The host's provider
   registry constructs providers *without* a settings_manager, so in
   normal runtime the injected-manager path above is a no-op. Fall back
   to reading `credentials.json` directly:

        from ...base.auth.credential_manager import CredentialManager
        creds = CredentialManager().load_credentials(provider, country)

   `CredentialManager.load_credentials` tries the country-nested format
   (`{"provider": {"country": {...}}}`) first and falls back to the flat
   format (`{"provider": {...}}`), so a single call covers both storage
   layouts. Do not branch on the format yourself.
4. **Fallback.** Providers with anonymous or free access return a
   fallback credentials object from `get_fallback_credentials()` (as
   `BaseAuthenticator` does). The fallback is what lets the auth class
   succeed even when the user hasn't configured anything — useful for
   providers that offer a limited anonymous tier.

**Implementing this in the template `auth.py`.** Wrap paths 2 and 3 in
a single `_load_stored_credentials()` helper that tries the
settings_manager first (guarded by `hasattr` and a try/except, because
it may be None), then falls back to `CredentialManager`. The auth
class's `_resolve_credentials()` calls that helper only if
`self._credentials` is None.

**Re-read credentials on every authenticate, not just at construction.**
A user can store credentials through the UI at any time after the
provider was constructed. If your auth class caches
`self._credentials = None` at construction and never re-reads, the
provider stays broken until the app restarts. The pattern from
`BaseAuthenticator` is:

    def _ensure_credentials(self) -> bool:
        # 1. If current credentials are valid, keep them.
        if self._credentials and self._credentials.validate():
            return True
        # 2. Otherwise try the settings manager / CredentialManager,
        #    in case the user just stored them.
        fresh = self._load_stored_credentials()
        if fresh and fresh.validate():
            self._credentials = fresh
            return True
        # 3. Otherwise try the fallback.
        self._credentials = self.get_fallback_credentials()
        return self._credentials is not None and self._credentials.validate()

Call `_ensure_credentials()` at the start of `_perform_authentication()`,
before building the login payload. This makes the auth class work
whether credentials were supplied at construction, stored by the UI
before first use, or stored by the UI after the provider was already
running.

**Reference.** The full pattern lives in
`base/auth/base_auth.py`:
`_load_credentials_from_manager`, `_ensure_credentials`,
`save_credentials`, `clear_stored_credentials`, `has_stored_credentials`.
Read them before writing your auth class.

**Providers with no user credentials** (anonymous-only, static-key,
free):

* `has_credentials()` returns `True` unconditionally.
* `set_credentials()` and `clear_credentials()` are no-ops returning
  `False` (there is nothing to store).
* `_ensure_credentials()` in `_perform_authentication` is not needed —
  the login flow doesn't depend on stored credentials.

### Per-authenticate credential flow

A correct `_perform_authentication()` looks like this:

    def _perform_authentication(self):
        if not self._ensure_credentials():
            raise CredentialsError(
                f"no credentials available for {self.provider_name}"
            )
        payload = self._build_login_payload(self._credentials)
        resp = self.http_manager.post(
            self._login_url(), json=payload, headers=self.build_headers()
        )
        return self._create_token_from_response(resp.json())

The critical piece is `_ensure_credentials()`. Without it, the auth
class silently depends on the caller having passed credentials — which
the registry never does.

### Session persistence is optional

Not every provider persists tokens. simpliTV, for example, uses a plain
opaque token with no refresh flow, so re-authenticating is cheap and
the auth class caches the token in-process only. No
`_save_session()` / `_load_session()` calls.

If your provider *does* persist tokens, use the settings_manager:

    # In get_access_token, after _perform_authentication():
    self.settings_manager.save_token_data(
        provider_name, token.to_dict(), country
    )

    # At construction:
    stored = self.settings_manager.load_token_data(provider_name, country)
    if stored:
        self._cached_token = self._token_from_dict(stored)

Decide whether persistence is worth the complexity. Providers with
cheap re-auth should skip it. Providers whose auth flow is expensive
(multi-step, has a rate limit, or requires user interaction like a
device code) should persist.

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

For providers with no auth, this section does not apply — there is
nothing to authenticate.

## Reference providers

The six existing providers, in order of implementation complexity:

    simpliTV    -- built from this template. Recordings + catchup + folded
                   DRM. Content-id grammar with three prefixes, module-scope
                   parsers, and a router that parses the catchup timestamp.
                   Token-in-body deviation, per-endpoint param naming,
                   custom AuthToken subclass, direct-CredentialManager
                   credential loading. Good first read.
    MoveTV      -- dynamic manifests, play-auth headers, EPG-based catchup.
    Magenta EU  -- EPG-heavy, VOD with typed errors, multi-country.
    HRTi        -- session-authorize playback, custom credentials shape.
    Discovery   -- dynamic endpoint discovery, Arkose challenge, playbackInfo.
    RTL+        -- layout-driven, three tokens, largest surface.

Read the closest one before writing a new provider. Each demonstrates a
different source pattern for DRM, a different content-id grammar, and a
different shape for playback authorization.