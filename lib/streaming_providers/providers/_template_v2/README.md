# Provider template v2 (`_template_v2`)

The v2 way to write a streaming provider: a thin **provider class** on top of
`ManagedProvider`, one **manager** per capability, a shared **error contract**,
and a **contract test** that tells you immediately when something is wired
wrong.

`_template` (v1) stays next to it and keeps working. **New providers use v2;
existing ones are migrated over time** (§12). The two coexist because
`ManagedProvider` *is a* `StreamingProvider` — registry, backend operations and
the legacy mixins do not know the difference.

Directories starting with `_` are skipped by provider discovery, so neither
template is ever registered.

> **How reliable is this document?** Everything here was derived from the code
> of the base, the `*_operations.py` layer and two real migrations (simpli,
> Allente), and is exercised by the test suite that ships with the template
> (86 tests, in a sandbox with stubs for the modules that were never uploaded).
> Statements about things *not* seen are marked **(unverified)**. The first
> provider you migrate against this README is the real validation — please
> note every place where the README was wrong or silent, and report it.

---

## Contents

1. [What you get, in 60 seconds](#1-what-you-get-in-60-seconds)
2. [Quickstart: a new provider in 10 steps](#2-quickstart-a-new-provider-in-10-steps)
3. [The mental model](#3-the-mental-model)
4. [Identity, naming, countries](#4-identity-naming-countries)
5. [The provider class](#5-the-provider-class)
6. [Managers (one section per capability)](#6-managers)
7. [Routing and content ids](#7-routing-and-content-ids)
8. [Error contract](#8-error-contract)
9. [Authentication (two variants)](#9-authentication)
10. [HTTP, headers, proxies](#10-http-headers-proxies)
11. [DRM](#11-drm)
12. [Migrating an existing (v1) provider](#12-migrating-an-existing-v1-provider)
13. [Models, time, data rules](#13-models-time-data-rules)
14. [Caches and concurrency](#14-caches-and-concurrency)
15. [Testing](#15-testing)
16. [Traps (the list of things that already bit us)](#16-traps)
17. [Not covered / open decisions](#17-not-covered--open-decisions)
18. [Definition of done](#18-definition-of-done)
19. [Appendix](#19-appendix)

---

## 1. What you get, in 60 seconds

| You write | You inherit (do **not** re-implement) |
|---|---|
| `provider.py`: identity ClassVars, `__init__` wiring, `_build_*()` factories | the 8 `implements_*` flags (derived from the managers), `capabilities` |
| a `ChannelManager` (+ optional VOD / EPG / recordings / favorites / bookmarks / catchup managers) | `get_manifest`, `get_drm`, header delegation, content-id routing (`_route`) |
| `auth.py` (or a `session.py` adapter) | `get_channels`, `to_output_format`, EPG delegation |
| `constants.py`, `models.py`, `drm.py` | the legacy surface the backend calls: `get_recordings`, `delete_recording`, `get_favorites`…, `get_bookmarks`…, `get_vod_category`, `search_vod`, `catchup_window`, `get_catchup_*` |
| provider-specific id grammar (override + `super()`) | wiring checks at construction (wrong manager type, `DRM_IN_MANAGERS` + `_build_drm()`) |

What v2 buys compared to v1:

* **No silent gaps.** In v1 every provider copy-pasted ~130 lines of flags and
  routing, and the copies drifted. The first migration (simpli) showed that its
  EPG, recordings and catchup had *never* been reachable through the backend —
  nothing complained, because legacy mixin defaults answered. In v2 a manager
  that exists is exposed; one that doesn't is `None`.
* **One error contract** (§8) instead of "log and return `[]`".
* **A contract test** (§15) that catches the classic mistakes in one call.

---

## 2. Quickstart: a new provider in 10 steps

```bash
cd streaming_providers/providers
python _template_v2/scaffold.py joyn Joyn --label "Joyn" --country DE \
       --with epg,recordings,catchup
```

1. **Pick the id** (`joyn`): lower-case, `[a-z][a-z0-9_]*`. It is the directory
   name, the registry key, `provider_name` and the credentials key — **forever**
   (§4).
2. The scaffold copies the template to `providers/joyn/`, replaces
   `example → joyn`, `Example → Joyn`, moves the chosen optional managers next to
   `provider.py` and **prints the `_build_*()` snippets**. Paste them into
   `provider.py`. (Without the scaffold: copy the directory, replace the tokens
   by hand, move files out of `optional/`, delete `optional/` and `scaffold.py`.
   Optional files use `from ....base` one level deeper; after moving it must be
   `from ...base`.)
3. **`constants.py`**: fill in hosts, paths, headers, `SUPPORTED_COUNTRIES`.
   Nothing else may contain URLs or header values.
4. **`models.py`**: write the `from_api_response()` parsers (strict) and the
   conversion to `Channel`.
5. **Auth**: keep `auth.py` (Variant A) *or* replace it with your stateful
   authenticator + `session.py` (Variant B) — §9.
6. **`channel_manager.py`**: implement `get_channels`, `get_channel_manifest`
   (+ headers, + folded DRM if manifest and DRM share state).
7. **Decide the two flags** in `provider.py` — `DRM_IN_MANAGERS` and
   `HEADERS_FROM_MANAGERS` (§11, §10). They must be present in the class body.
8. **Optional managers**: implement what the provider really has; delete the
   rest. A capability the provider does not have is simply not built.
9. **Tests**: adapt `tests/test_<id>_provider.py` (fake HTTP, no network) and run
   the contract test (§15).
10. **Verify on a device** with the checklist in §12.7. Then done (§18).

---

## 3. The mental model

```
Kodi addon / PVR / API client
        │
        ▼
Backend routes ──► ProviderManager (facade) ──► *Operations ──► ProviderRegistry.get_provider(key)
                                                                      │
                                                                      ▼
                                                              YourProvider(ManagedProvider)
                                                    ┌───────────────┼─────────────────────────┐
                                                    ▼               ▼                         ▼
                                              ChannelManager   EpgManager … (one per capability)   auth (AuthProtocol)
                                                    │               │                         │
                                                    └── http_manager (HTTPManager, proxy-aware) ┘
```

* The **operations layer** (`channel_operations`, `epg_operations`,
  `drm_operations`, `catchup_operations`, `vod_operations`, `recording_operations`,
  `favorite_operations`, `bookmark_operations`, `timer_operations`) is the *only*
  caller of a provider. What it calls is the **legacy surface** (below). You never
  write that surface — `ManagedProvider` maps it onto your managers.
* A **manager** owns one capability. Its constructor takes four keyword-only
  collaborators — `http_manager`, `auth`, `country`, `config` — and nothing else
  unless you add explicit keyword-only extras (§6.0).
* The **provider** owns shared resources (config, HTTP manager, auth, caches) and
  builds the managers. Managers *borrow* caches by reference.
* **Auth** is a collaborator that satisfies `AuthProtocol`:
  `get_access_token() / build_headers() / invalidate()`.

### The legacy surface and where it goes

This is what the backend actually calls (verified in the operations code), and
which manager answers it:

| Backend call | → manager method |
|---|---|
| `get_channels(**kw)` | `ChannelManager.get_channels` |
| `get_manifest(content_id=…, **kw)` / `get_manifest_with_headers` | routed: `ChannelManager.get_channel_manifest`, then `VodManager.get_vod_manifest` |
| `get_manifest_headers`, `get_segment_headers(id, **kw)` | the manager that resolved the id (route cache); with `start_time=` in `kw` → `CatchupManager.get_catchup_segment_headers` |
| `get_drm(content_id=…, drm_variant=…, preferred_quality=…, preferred_format=…, <proxy extras>)` | folded: `get_channel_drm` / `get_vod_drm`; or `_build_drm().get_drm_configs` |
| `implements_epg`, `epg_window`, `get_epg(channel_id, start_time=, end_time=, limit=, country=)`, `get_epg_grid(start_time=, end_time=, channel_ids=, country=)`, `get_program_details` | `EpgManager` |
| `get_vod_category(content_id=, cursor=, page_size=)`, `search_vod(query=, cursor=, page_size=)` | `VodManager` (`VodPage` → dict) |
| `get_recordings(include_deleted=)`, `delete_recording(recording_id)` | `RecordingsManager` |
| `get_favorites()`, `add_favorite(content_id=, favorite_type=, title=)`, `remove_favorite(content_id=)` | `FavoritesManager` |
| `get_bookmarks`, `update_bookmark(content_id=, position_seconds=, …)`, `delete_bookmark(content_id=)` | `BookmarksManager` |
| `catchup_window`, `supports_catchup`, `validate_catchup_request`, `get_catchup_window_for_channel`, `get_catchup_manifest(content_id=, start_time=, end_time=, epg_id=, country=, drm_variant=)`, `get_catchup_manifest_with_headers`, `get_catchup_drm` | `CatchupManager` |
| `implements_timers`, `get_timer_types`, `get_timers`, `add_timer`, `update_timer`, `delete_timer` | **not delegated** — legacy mixin defaults (§17) |
| `get_events`, subscriptions, `enrich_channel_data` | **not delegated** (§17) |

The backend calls by **keyword** wherever it matters. That is why every manager
method takes `**kw`: the backend adds arguments (`country`, `drm_variant`,
`limit`, proxy extras) you may not care about — accept and ignore them.

---

## 4. Identity, naming, countries

### One id, everywhere

```
directory name == AVAILABLE_PROVIDERS key == provider_name == PROVIDER_NAME
               == credentials / session key == enable-flag key
```

* Define it once: `ExampleDefaults.PROVIDER_NAME` in `constants.py`;
  `provider_name` returns it.
* `AVAILABLE_PROVIDERS` is filled by discovery with the **directory name**
  (`streaming_providers/__init__.py`). `ProviderManager.get_provider_class()`
  looks providers up by that key (after stripping a `_xx` country suffix).
* The class name is **not** the id. `get_plugin_key()` (on every provider class)
  returns the key the class is registered under; the old class-name derivation
  (`SimpliTVProvider → "simplitv"`) survives only as a fallback for unregistered
  classes. Name your class `<Prefix>Provider` anyway.
* **Never rename after release**: stored credentials, sessions and enable flags
  are keyed by it, and `provider_name` also appears as `"Provider"` in the JSON
  clients receive (`to_output_format`).
* Renamed a provider once (simplitv → simpli)? Then the *only* thing to check is
  every place that derived a name from the class (`grep -rn 'replace("provider"'
  base providers`).

### Countries — three different cases

`SUPPORTED_COUNTRIES` (ClassVar, list of ISO codes):

| Value | Meaning | What the registry does |
|---|---|---|
| `[]` | single-country provider, default country | instance with the default country |
| exactly **one** entry | single-country, pinned | constructs with that entry **verbatim, UPPERCASE** (`"SE"`) |
| **several** entries | multi-country | fans out `joyn_de`, `joyn_at`, … and constructs with **lowercase** |

* `supports_multiple_countries()` is `len(SUPPORTED_COUNTRIES) > 1`. A wildcard
  `["*"]` is **not** multi-country here.
* The framework's storage managers (CredentialManager, SessionManager,
  ProxyConfigManager) key by **lowercase** country. The registry may hand you
  uppercase. **Normalise in `__init__`: `self.country = self.country.lower()`**
  (the contract test warns if you don't).
* Validate unsupported countries in `__init__` (raise `NotImplementedError`),
  as Allente does.
* `get_all_possible_instances()` hard-codes `"DE"` for single-country providers
  (known issue, §17) — do not rely on it for AT/SE/… providers.

### How the registry constructs providers — check, don't assume

What is **verified** (read in the code): the metadata side — a single-entry
`SUPPORTED_COUNTRIES` pins the construction country to that entry verbatim
(uppercase); several entries produce one instance per country
(`get_all_possible_instances()` reports `requires_country_suffix`), with registry
keys `<key>_<cc>`; `ProviderManager.get_provider_class()` strips the `_xx` suffix.

What is **not verified here** (it was documented by the Allente provider, whose
author read it, but the registry's `create_instance` source is not part of this
README): *exactly how* the instance is called — `cls(country=…)`, with a
`config` object, with extras. A provider whose constructor looks different
(Joyn: `__init__(config, **kwargs)`) is therefore **not** "wrong"; it is simply
what the registry has been feeding it.

**Procedure — do this before you touch the constructor**

```bash
python -m streaming_providers.base.testing.migration_pack <key> --repo <repo root>
```

Section 1 prints the class's `__init__` signature, `SUPPORTED_COUNTRIES`, what the
metadata mixin reports, and the **source of `create_instance` / `_extract_metadata` /
`discover_all_providers`**. Rules derived from it:

* Your migrated `__init__` must accept **exactly what the registry passes today**
  (and what the settings/credentials flow passes, if any). Keep a `config`
  argument and/or `**kwargs` if `create_instance` uses them; the template's
  `(country, config, proxy_config)` is a starting point, not a requirement.
* `country` must reach `super().__init__(country=…)` and then be lower-cased.
* The contract test builds the provider with `country=SUPPORTED_COUNTRIES[0]`; if
  your constructor **requires** more, pass it:
  `check_provider(cls, key, ctor_kwargs={"config": …})`.
* Multi-country: the *class* is registered once under `<key>`; the registry creates
  the per-country instances. `provider_name` must still equal `<key>` (not
  `<key>_<cc>`).

**Is `config`/`**kwargs` used by something other than the registry?** The registry
source does not show the settings/credentials flow. Check before dropping either:

```bash
grep -rn --include='*.py' '<Class>(' <repo root>                       # direct constructions
grep -rn --include='*.py' 'get_provider_class' <repo root>              # data-driven construction
```

A call site with `config=`/extras ⇒ keep the parameter. Nothing found ⇒ it may still
be data-driven; the safe default for a **migration** is to **keep the v1 constructor
signature unchanged** (the migration pack prints it) and change only the body.

---

## 5. The provider class

`provider.py` in this template is a complete, runnable example. Anatomy:

```python
class ExampleProvider(ManagedProvider):
    PROVIDER_LABEL, PROVIDER_LOGO, SUPPORTED_AUTH_TYPES, SUPPORTED_COUNTRIES   # static metadata
    DRM_IN_MANAGERS: ClassVar[bool] = True        # decision 1 — §11
    HEADERS_FROM_MANAGERS: ClassVar[bool] = True  # decision 2 — §10

    @property
    def provider_name(self) -> str: ...           # abstract in the base, must equal the key

    def __init__(self, country="DE", config=None, proxy_config=None):
        super().__init__(country=country)         # ONLY country — no **kwargs
        self.country = self.country.lower()
        self.provider_config = ExampleConfig(config or {})                 # 1. ONE config
        self.http_manager = self._setup_http_manager(...)                  # 2. HTTP
        self.auth = ExampleAuth(http_manager=…, config=…)                  # 3. auth, lazy
        self._playout_cache = {}                                           # 4. caches
        self._init_managers()                                              # 5. managers

    def _build_channels(self): ...                # one factory per manager you have
```

Rules:

1. **Required members**: `provider_name` (abstract), a concrete `get_manifest`
   (inherited from `ManagedProvider`). `StreamingProvider.__init__` takes only
   `country` (no `**kwargs`) — that is the **base** call. Your own `__init__`
   must accept what the **registry passes** (see §4 "How the registry constructs
   providers"; check it with the migration pack). For a **new** provider the
   template shape `(country, config, proxy_config)` has no `**kwargs` so that a
   typo fails loudly; a **migrated** provider keeps `config`/`**kwargs` if
   `create_instance` or the settings flow uses them (simpli and Joyn do).
2. **Order in `__init__`**: `super().__init__` → config → http_manager → auth →
   caches → `_init_managers()`. `_init_managers()` must come last; it builds the
   managers in the fixed order `channels, vod, epg, recordings, favorites,
   bookmarks, catchup, drm` and runs the wiring checks.
3. **`_build_*()` factories** return a manager or `None` (the default). A manager
   that needs another (catchup needs channels) reads `self.channels` in its
   factory — that is why the order is fixed.
4. **Flags are derived. Never override `implements_*`.** `implements_catchup` is
   `catchup.supports_catchup`; `implements_epg` is `epg.implements_epg`;
   `implements_drm` is `drm is not None or DRM_IN_MANAGERS`.
5. **`self.channels` is the `ChannelManager`** (it shadows the legacy list
   `StreamingProvider.__init__` creates). Never assign a list to it, never do
   `self.channels = fetched_channels`. `to_output_format()` is already overridden
   for this.
6. **No network I/O in `__init__`.** One accepted exception: an *opportunistic*
   login when credentials are already stored (Allente). The contract test runs
   your constructor with a network-disabled HTTP manager and fails on any call.
7. **`__all__ = ["YourProvider"]`** in `provider.py` **and** in the package
   `__init__.py`, and never import `ManagedProvider` into the package namespace.
   Discovery takes the *first* `StreamingProvider` subclass it finds in
   `dir(package)` (alphabetical!): an exported `ManagedProvider` sorts before
   most provider names and would be registered instead.
8. **Provider-specific id grammar** (e.g. `catchup:<channel>@<ts>`) is the one
   thing that stays in the provider: override `get_manifest` / `get_drm`, handle
   your prefix, `return super().…` for everything else.
9. **Credentials API for the settings UI** lives on the provider
   (`set_user_credentials`, `get_last_auth_error`, `get_auth_details(context)`);
   see §9.

### 5.1 Where shared state lives (the rule that prevents `provider` back-references)

A manager must never hold or call the provider (`self._provider.bearer_token`,
`self._provider.get_profile()`): that is the v1 Allente shape and it makes the
manager untestable and the state ownership unclear. State a manager needs comes in
through a **constructor collaborator**. Decide per piece of state:

| The state is … | It lives in … | Managers get it via |
|---|---|---|
| derived from the login (token, entitlement tag, profile, user id) | the **auth / session** object | `self.auth.<attr>` (Allente: `auth.entitlement_tag`, `auth.profile`) |
| fetched separately, with its own lifecycle/expiry (e.g. an entitlement or package list loaded after login) | a **small dedicated collaborator** (`JoynEntitlements`), owned by the provider | keyword-only extra `entitlements=` on every manager that needs it |
| a cache | a plain **dict owned by the provider** | keyword-only extra, borrowed by reference |
| a pure helper (id parsing, header building, URL building) | a **module-level function** or the `Config` | import it |
| needed by the **settings UI only** | the provider (thin delegate to the session) | — (managers never read it) |
| read by a **legacy mixin through `self`** (e.g. `ProviderAuthMixin` reads `self.authenticator.get_bearer_token()`; shared with every v1 provider) | **stays on the provider — do not delete it** | managers do **not** use it and do not call the mixin; they use `self.auth` and build headers from `Config` |

Threshold: **two consumers is enough** for a dedicated collaborator (live manager +
VOD manager already are two). A "provider-owned helper method that managers call"
is the back-reference in disguise — don't, not even "for the first pass": the
migration then has to be done twice. If you cannot decide between "part of the
session" and "separate type": derived from the token ⇒ session; has its own
fetch/refresh ⇒ separate type.

`python -m streaming_providers.base.testing.migration_pack <key> --repo <root>`,
section 4, lists every back-reference the v1 managers make into the provider —
each line needs one of the rows above.

---

## 6. Managers

### 6.0 Constructor contract (all managers)

```python
class YourManager(ChannelManager):              # or Vod/Epg/Recordings/Favorites/Bookmarks/Catchup
    def __init__(self, *, http_manager, auth, country, config, my_cache=None):
        super().__init__(http_manager=http_manager, auth=auth, country=country, config=config)
        self._my_cache = my_cache if my_cache is not None else {}
```

* Four required keyword-only collaborators, **no `**kwargs`** (a typo at a call
  site is an immediate `TypeError`).
* Extras are keyword-only, declared explicitly, stored **after** `super().__init__`,
  and `super()` receives **only the four**.
* `auth` is checked against `AuthProtocol` (method presence only); a mismatch is
  a logged warning, not an error.
* Managers expose `self.http_manager`, `self.auth`, `self.country`, `self.config`.
* Managers never talk to each other through the provider; a manager that needs
  another gets it as an explicit extra (`channels=`).
* **Return-value convention for all managers:**
  *"I don't handle this id"* is a **return value** (`None` / `[]`);
  *real failures* **raise** typed errors from `base.errors` (§8).

### 6.1 `ChannelManager` (every live provider)

| Method | Kind | Contract |
|---|---|---|
| `get_channels(**kw) -> List[Channel]` | abstract | `[]` if none. Parse entry-by-entry, skip malformed entries with a warning. |
| `get_channel_manifest(content_id, **kw) -> Optional[str]` | abstract | `None` = not mine (router tries the next manager); raise for real failures |
| `get_channel_manifest_headers(content_id, **kw)` | override | default = `auth.build_headers()` = **API headers**; override with the CDN headers (§10) |
| `get_segment_headers(content_id, **kw)` | concrete | default = manifest headers |
| `get_channel_drm(content_id, **kw) -> List[DRMConfig]` | concrete | default `[]` = no DRM (§11) |
| `handles_content_id(content_id)` | concrete | default `True`; override when ids of several managers coexist. **Cheap, pure, no I/O.** |

### 6.2 `VodManager`

> **Return `VodPage`, not a list.** `ManagedProvider` tolerates a list/dict/`None` at
> runtime (`normalize_vod_result`), so a v1-shaped return **does not break anything**
> — but it violates the ABC, and nothing (not even the contract test) will tell you.
> When migrating a `get_vod_category`/`search_vod` that returns a list or dict, wrap it:
> `VodPage(entries=…, next_cursor=…, total=…)`, or `normalize_vod_result(result)`.

* `get_vod_category(content_id="", cursor=None, page_size=24, **kw) -> VodPage`
  (abstract); empty `content_id` = root. `content_id` is an **opaque token** — you
  define and document the grammar (`folder_<id>`, `program_<id>`, …).
* `get_vod_manifest(content_id, **kw) -> Optional[str]` (abstract; `None` = not mine).
* `search_vod`, `get_vod_manifest_headers`, `get_segment_headers`, `get_vod_drm`:
  concrete defaults (`VodPage()`, auth headers, manifest headers, `[]`).
* `VodPage(entries, next_cursor, total)`: **`next_cursor is None` is the
  authoritative end-of-list**; `total` may be unknown. An *empty* page is falsy
  (list semantics) — test `page.has_more`, never `if page:`.
* `ManagedProvider` converts the result to the dict `VodOperations` reads
  (`normalize_vod_result` handles `VodPage`, legacy dict, plain list and `None` —
  verified by a test). So at **runtime** a manager that still returns a list works.
  The **contract**, though, is `VodPage`: new and migrated managers return
  `VodPage(entries=…, next_cursor=…, total=…)`. If the v1 code returns a list,
  the migration is one line at the manager's return:
  `return normalize_vod_result(entries)` (from `base.vod`), or build the `VodPage`.
  The provider-level `get_vod_category` of v1 is **deleted** (inherited).
* **Strictness**: `VodItem` with a pricing/mode mismatch **raises**;
  `Channel` only warns. A single bad upstream item can fail a page — guard your
  parsing.
* Slugs are derived per sibling set, so they are **not stable across pages** —
  never persist them (§17).

### 6.3 `EpgManager`

* `epg_window -> (past_days, future_days)`; **`(0, 0)` = no EPG and is the
  default**. A provider without EPG simply has **no EPG manager**; the provider's
  `epg_window` is then `(0, 0)` and `implements_epg` is `False` (contract-tested).
* `implements_epg` is `epg_window != (0, 0)`. The backend uses it to choose
  between the **native path (your manager)** and the **generic XMLTV path**.
  If `epg_window` needs a network call (server-advertised window), **override
  `implements_epg` to return `True`**: it is read on every `get_epg` call and in
  the registry listing (simpli does this).
* `get_epg(channel_id, start_time, end_time, **kw) -> List[EPGEntry]` (abstract):
  the backend hands **timezone-aware UTC `datetime`s**, already clamped to
  `epg_window`, plus `limit=` in `**kw`. `EPGEntry.start/end` are **unix seconds
  (int)**. `channel_id` is the `Channel.content_id` from `get_channels()` (strip
  your own prefixes if you add some).
* `get_epg_grid(channel_ids, …)`: the default loops `get_epg`; override with a
  native batch endpoint. `ManagedProvider` passes arguments **by keyword** (the
  legacy order is `(start, end, channel_ids)`, the ABC's `(channel_ids, start,
  end)`) and, when the backend passes no ids, builds them from `get_channels()`.
* `get_program_details(program_id) -> Optional[EPGProgramDetails]`.
* `handles_channel_id(channel_id)`: override to skip channels without EPG.

### 6.4 `RecordingsManager`

* **Return `models.recording.Recording` (or a subclass), not `Channel`.**
  `RecordingOperations` filters on `Recording.is_deleted`; a `Channel` has none.
* `get_recordings(**kw)`: `include_deleted` arrives in `**kw` (always). Honour it
  if the backend lists deleted items, otherwise ignore it.
* **Two id namespaces.** `content_id` (`rec:<x>`) is what `get_manifest` /
  `get_drm` receive — recordings play through your **channel** manager, there is no
  manifest method on this ABC. Your backend's own recording id is a second
  namespace. **`Recording.recording_id` is an alias of `content_id`, so clients
  only hold `content_id`: `delete_recording` must accept the content id** (resolve
  it through your listing) and may also accept the backend id.
* `delete_recording` raises `ItemNotFoundError` when it does not exist (it is also
  a `KeyError`, which the backend catches). Never return silently on a failed
  delete.
* Map the backend status onto `RecordingStatus`; unknown → `PENDING`.
* `schedule_recording` is optional; if you override it you **must** also override
  `supports_scheduling → True`. The legacy surface has **no entry point** for it
  (timers use `add_timer`/`Timer`), so it is unreachable until you wire it (§17).
* Known quirk: `Recording.to_dict()["ContentType"]` is `"LIVE"` (never set; §17).

### 6.5 `FavoritesManager` / `BookmarksManager`

* Empty is `[]`, not an error.
* `add_favorite(content_id, favorite_type=PROGRAM, title=None, **kw)`;
  `FavoriteType` is `PROGRAM, CLIP, LIVE, EVENT` (there is **no** `CHANNEL`).
* `update_bookmark(content_id, position_seconds, content_type, duration_seconds=None,
  title=None, **kw)` is called on **every** playback stop/pause — repeated writes
  of the same position must be harmless no-ops. `position_seconds`: `0` start,
  `-1` completed (≥95 % counts as completed on the caller's side).
* Remove/delete of something that is not there raises `ItemNotFoundError` (a
  `KeyError`: `FavoriteOperations`/`BookmarkOperations` catch `KeyError` → `False`).
  Backend refusals raise `OperationFailedError` (a `RuntimeError`).
* Argument order is `(content_id, position_seconds, content_type, …)` here but
  `(content_type, position_seconds)` in the `ProviderManager` facade — the backend
  calls by keyword; so must you if you call it.

### 6.6 `CatchupManager`

* `catchup_window_hours` = the **provider-wide maximum** (`> 0` turns the
  capability on). The backend gates on it and validates request age with it
  *without knowing the channel*. Per-channel windows: override
  `catchup_window_for_channel(content_id)` **and enforce them yourself** (return
  `None` for a start outside the channel's window). If your global value is the
  minimum, valid requests on longer channels are rejected.
* `get_catchup_manifest(content_id, start_time, end_time=None, epg_id=None, **kw)`:
  times are **unix seconds**; `end_time` is optional — pass `None`, never a sentinel
  (0, `start_time`, `start+1800`). Returns `None` when there is no catchup for that
  content. **Never fall back to the live URL**: the DRM pipeline would extract the
  live PSSH.
* `get_catchup_drm`: `[]` means "no catchup-specific DRM". `ManagedProvider` turns
  `[]` into `NotImplementedError`, which the backend reads as *"extract the PSSH
  from the catchup manifest"* (also correct for clear streams). Reusing the live
  DRM must be **explicit**: return it from the manager, or set
  `CATCHUP_DRM_FROM_LIVE = True` on the provider.
* Header hooks: the default is `auth.build_headers()` (**API headers**). If the
  catchup streams are fetched from the CDN, override `get_catchup_manifest_headers`
  and `get_catchup_segment_headers`.
* **Restart-from-beginning** (live manifest + player-side seek) cannot be
  expressed as a manifest URL. Give it its own provider method (simpli:
  `get_restart(content_id, start_time=0)` → `(url, seek_seconds)`; `start_time=0`
  means "use the `@<ts>` embedded in the id").
* `catchup:<channel>@<ts>` style ids are provider grammar: parse them in the
  provider's `get_manifest`/`get_drm` and hand the manager plain
  `(content_id, start_time)`; a malformed id raises `BadRequestError`.

### 6.7 `DRM`

See §11 — folded into `ChannelManager`/`VodManager`, or a dedicated object.

---

## 7. Routing and content ids

`ManagedProvider._route` resolves a content id for `get_manifest` and `get_drm`:

1. `handles_content_id()` is a **cheap pre-filter**; `False` skips the manager.
2. A manager that passes may still return `None`/`[]` → the **next** is tried.
3. `NotFoundError` is remembered and **re-raised only if nobody resolves** the id
   ("existed but is gone" vs "nobody handles it").
4. `BadRequestError` is **never** caught — a malformed id surfaces.
5. The manager that resolved an id is remembered (bounded, locked), so headers go
   to the manager that produced the manifest.
6. `content_type` narrows only for `"live"` and `"vod"`; anything else widens. (The
   backend never passes it, so rules 1–5 decide in practice.)

Order: channels, then VOD.

**Consequence for providers with live *and* VOD managers:** only `NotFoundError` makes
the router try the next manager. Any other exception from the first manager
**propagates and VOD is never asked**. v1 code that returned `None` on every error
used to fall through silently; in v2 the two managers must be told apart by
`handles_content_id()` (implement it on **both**: pure prefix/format test, no I/O),
otherwise a VOD id is handed to the channel manager first and fails there.

Id grammar guidance:

* Ids are opaque to the base. Use short **prefixes** when several kinds coexist
  (`live:`, `rec:`, `prog:`, `catchup:`), document the grammar in `constants.py`
  (`LIVE_PREFIX = "live:"`), and parse in **one** place (module-level
  `parse_*` helpers, unit-tested).
* `handles_content_id` must be pure; never call the network to decide ownership.
* Recording playback ids are channel-manager ids (`rec:…`); the **provider's
  router** decides — not the recordings manager.

---

## 8. Error contract

### The rule

> **"Not mine" is a return value. A failure is an exception.**

| Situation | Do |
|---|---|
| id is not handled by this manager | return `None` / `[]` |
| nothing there (empty list, no recordings) | return `[]` — not an error |
| no DRM / clear stream | return `[]` |
| missing/invalid credentials, OTP, wrong password | raise `AuthError` |
| geo block | raise `GeoBlockError` |
| rate limit | raise `RateLimitError` |
| WAF / CAPTCHA challenge (e.g. a Cloudflare interstitial, a 403 with a challenge page) | raise a `RateLimitError` subclass (provider-specific, e.g. `WafBlockedException`) — **transient**: back off, never classify as permanent |
| entitlement missing | raise `EntitlementError` |
| network down, 5xx, WAF page, malformed payload | raise `ServerError` (via `transport_errors`) |
| id syntactically wrong | raise `BadRequestError` |
| resource that existed is gone | raise `NotFoundError` / `ItemNotFoundError` |
| broken provider configuration (DRM config invalid, wiring wrong) | raise `ConfigurationError` (a `DRMError` is one) |
| backend refused a write | raise `OperationFailedError` |
| capability is not supported by design | `UnsupportedOperationError` (a `NotImplementedYetError`) |

Names marked above beyond the ones in the shipped base were taken from
docstrings and imports — **(unverified)**: check `base/errors.py` for the exact
constructors (the templates assume `Error("message")`).

### Compatibility on purpose

`ItemNotFoundError` is a `NotFoundError` **and** a `KeyError`;
`OperationFailedError` is a `ProviderError` **and** a `RuntimeError`;
`UnsupportedOperationError` is a `NotImplementedYetError`. Existing `except
KeyError` / `except RuntimeError` in the operations layer keep working.

### Helpers

* `base.utils.transport.transport_errors(what, provider="")` wraps *unexpected*
  exceptions in `ServerError` and lets typed `ProviderError`s through untouched
  (callers rely on `AuthError`/`RateLimitError` to refresh tokens or back off —
  never flatten them).
* The HTTP manager raises for 4xx/5xx itself — don't call `raise_for_status()`.
  How it types a 401/403 is **(unverified)**: map them to `AuthError` at the one
  place you call login.

### Backend behaviours you must know

* `get_all_channels` / `get_all_*` catch exceptions **per provider** and return
  `[]` for that provider; single-provider calls **propagate** your exception.
* `get_segment_headers` is called inside a `try` in the DRM pipeline whose
  exceptions are **swallowed** (falls back to manifest headers) — a bug there is
  silent. Test it.
* `NotImplementedError` from `get_catchup_drm` is **not** an error: it means
  "extract the PSSH from the catchup manifest".
* `NotImplementedError` from `get_catchup_manifest` → `None` + log.
* v1 providers typically logged and returned `[]`/`None` on auth failure. **v2
  providers raise** — a deliberate behaviour change (§12.5).

---

## 9. Authentication

Two supported shapes. Both give managers an `auth` that satisfies `AuthProtocol`.

### Rules for both

* **Lazy**: no network in `__init__`. The first caller that needs a token logs in.
* **One login for concurrent callers**: lock + re-check after acquiring it.
* **Typed errors**, never `None`/`[]`.
* `invalidate()` clears memory **and persisted storage** (otherwise a restart
  resurrects the old session; this bit `set_user_credentials`).
* The token's own expiry (`is_expired`, fixed 300 s buffer in `BaseAuthToken`) is
  the single truth — **a new provider must not add a second buffer constant.**
  **Migrating a provider that already has one** (look for `expires_in - 1800`-style
  subtractions in `_create_token_from_response`, grep `expires_in -`): do **not**
  remove it by reflex. It may be deliberate — a token embedded in a DRM config or
  header lives for the whole playback session (§11), so an early refresh can be the
  workaround that keeps playback alive. Find the reason (comment, history), keep it
  in **one** documented place (token creation) unless a device test proves it
  redundant, and record the decision in `MIGRATION_BRIEF.md`.
* Never log credentials or the dict from `to_auth_payload()`; verify the HTTP
  layer does not log request bodies at DEBUG.
* Token transport is provider-specific: header (Allente, template), query string
  or body (simpli: `with_token()`/`auth_body()` helpers, token-free headers).
  Keep `build_headers()` token-free if the token does not belong in headers.

### Variant A — the auth class *is* the `AuthProtocol` (`auth.py`)

Use for simple token flows. `ExampleAuth` shows: credentials injected, lazy
`get_access_token()` with `RLock`, expiry check, `build_headers()` with the bearer,
`invalidate()`, `transport_errors` around the login. It does **not** persist
sessions.

### Variant B — a session adapter in front of a stateful authenticator (`optional/session_adapter.py`)

Use when you already have a `BaseAuthenticator` (persisted sessions, refresh
tokens, multi-step SSO, profile selection): **don't rewrite the flow**, wrap it.

```
managers ──AuthProtocol──► Session ──► YourAuthenticator (BaseAuthenticator)
```

**Keep both objects on the provider.** `self.authenticator` (the raw authenticator)
and `self.auth`/`self.session` (the adapter). The adapter *wraps* the authenticator, it
does not replace it: legacy mixins shared with every v1 provider
(`ProviderAuthMixin`, seen reading `self.authenticator.get_bearer_token()`) still reach
for `self.authenticator`. Deleting it as "v1 leftover" breaks them silently. Managers
must never call the raw authenticator — they use the adapter.

* `ensure() -> bool` never raises (opportunistic pre-login, settings UI).
* `require()` raises typed errors (`AuthError` / `GeoBlockError` / `ServerError`).
* `last_error` keeps the **original** exception: the auth-status UI shows its type
  name (`AllenteOTPRequiredError`).
* The session also holds auth-derived state (entitlement tag, profile, …) that the
  managers read; the provider keeps thin delegates for the settings UI.
* **Retry policy** (implemented in the template adapter; the Allente constants
  describe it but its provider never did): *permanent* failure (wrong credentials,
  OTP, unsupported account) ⇒ no retry until `reset()` (credentials changed);
  *transient* failure (network, 5xx, rate limit, WAF/CAPTCHA, and any `ProviderError` the
  authenticator raises itself — the session keeps its type) ⇒ exponential backoff
  `base · 2^(n−1)` s, capped. Without it, every failing call repeats a full SSO
  login — lockout/WAF risk. Tested with an injectable clock.

### Credentials API on the provider (OPTIONAL — only if v1 has it)

**A migration preserves the v1 public surface; it never adds to it.** Of the two
migrated providers only Allente has `set_user_credentials`; the template contains
it as an *example*. Whether the settings UI (or anything else) calls it is **not
verified here**. Decision rule: `grep -rn set_user_credentials --include='*.py'`
(the migration pack does it for you). Callers found, or v1 has the method ⇒ keep
it. No callers and v1 lacks it ⇒ **do not add it** (and delete it from the
template copy). The same applies to `get_last_auth_error` and `get_auth_details`
(the latter is a hook of the legacy auth mixin, which this README has not seen
(**unverified**) — keep what v1 has, add nothing).

```python
def set_user_credentials(self, username, password) -> bool   # store, log in once, True on success
def get_last_auth_error(self) -> Optional[Exception]
def get_auth_details(self, context) -> Dict                  # hook used by the auth-status UI (free-form dict)
```

`set_user_credentials` sequence (Allente): build credentials → assign → **`invalidate`
(memory + persisted)** → reset state and playout cache → exactly **one** login →
persist only on success.

---

## 10. HTTP, headers, proxies

* `self.http_manager = self._setup_http_manager(provider_name=, proxy_config=,
  user_agent=, timeout=)`. Proxy resolution: ctor argument → ProxyConfigManager
  (`provider`, `country` lowercase) → global.
* Call it as `http_manager.get/post(url, params=, json=, headers=, operation=)`.
  `operation` is one of `"api"`, `"auth"`, `"manifest"`, `"license"` — it selects
  whether the proxy applies (`ProxyScope`).
* **A `ProxyConfig` only affects Python-side `HTTPManager` traffic.** The license
  request, the manifest fetch and all segment fetches are made by
  inputstream.adaptive **inside Kodi** and do **not** use it. Geo-unblocking users
  also need Kodi's global proxy. State this limitation in the provider docstring.
* `RequestConfig` offers `inject_origin` (opt-in Origin header),
  `use_tls_impersonation` (curl_cffi, ignored under Kodi), accept headers. Use
  them instead of ad-hoc header hacks.

### API headers vs stream (CDN) headers

Keep two builders in `constants.py`: `api_headers(token=None)` and
`stream_headers()`. The CDN usually wants only User-Agent / Origin / Referer (and
Akamai-style edges *reject* requests without a whitelisted origin/referer — Allente).
Sending API headers (JSON `Content-Type`, tenant ids, tokens) to the CDN is noise at
best and a token leak at worst.

### `HEADERS_FROM_MANAGERS` — decide explicitly

| Value | Meaning |
|---|---|
| `True` | manifest/segment requests carry the managers' header hooks (`get_channel_manifest_headers`, `get_segment_headers`, VOD and catchup equivalents). The manager default is `auth.build_headers()` = **API headers**, so **override the hooks** with `stream_headers()`. |
| `False` | keep the legacy `{}` — for a provider being migrated whose manager hooks were dead code and whose real behaviour you want to preserve first. |

The contract test fails when a manager overrides header hooks while the flag is
`False` ("dead code"), and when the flag is not declared in the class body.

Segment/manifest headers for **catchup**: `get_segment_headers(id, start_time=…)`
is routed to the catchup manager (the DRM pipeline passes `start_time`).

---

## 11. DRM

### Decision tree

```
Do manifest and DRM share state (one playout/AcquireContent response)?
├─ yes ─► fold DRM into the manager:  DRM_IN_MANAGERS = True,
│         implement get_channel_drm / get_vod_drm            (Allente, simpli — the usual case)
└─ no  ─► dedicated object:           DRM_IN_MANAGERS = False,
          _build_drm() returns an object with
          get_drm_configs(content_id, content_type=None, **kw)    (optional/drm_manager.py)
Catchup with DIFFERENT DRM? ─► CatchupManager.get_catchup_drm (§6.6)
No DRM at all? ─► DRM_IN_MANAGERS = False, no _build_drm()
```

`DRM_IN_MANAGERS = True` together with `_build_drm()` is refused at construction.
The old method-identity sniffing is gone: the choice is **declared**, and the
contract test checks the declaration against the managers.

### How the backend calls it

`provider.get_drm(content_id=<id>, **kw)` — **keyword** `content_id`; `kw` holds
`drm_variant` (`"auto"`, `"software"`, …), `preferred_quality`, `preferred_format`
and injected proxy extras. **`content_type` is never passed.** Accept `**kw` and
ignore what you don't use. `get_drm(content_id, drm_variant=None, content_type=None,
**kw)` is the signature `ManagedProvider` exposes.

### Building configs

* Factories (`create_widevine`, …) default to `priority=1`. **Give every config of
  one content an explicit, distinct priority** (lowest wins in ISA); duplicates fail
  `validate_drm_set` and surface as `ConfigurationError`. Several systems: simpli
  emits Widevine 1 / PlayReady 2 (ISA picks the lowest number whose CDM is present).
* `[]` = no DRM / unsupported system (log a warning). A **broken configuration
  raises** (`LicenseConfigError` is a `DRMError`, which is a `ConfigurationError`) —
  do not swallow it into `[]`.
* `LicenseConfig` `req_data` placeholders: `{CHA-RAW}` (raw challenge),
  `{CHA-B64}` (base64 challenge). `create_with_req_data()` base64-encodes the
  template for you; `wrapper="none"` + `unwrapper="json,base64"` +
  `LicenseUnwrapperParams(path_data="license")` is the JSON-in/JSON-out pattern.
* `req_headers` encoding: pass a dict (the framework url-encodes it) **or**
  pre-encode yourself with `urlencode(headers, quote_via=quote)` (spaces → `%20`).
  The plain-text header parser splits on `;`/`,` followed by `Name:` — a
  `User-Agent` such as `Mozilla/5.0 (X11; Linux …)` is the classic victim.
  `+` vs `%20` for spaces is **not verified on a device**; `%20` is unambiguous.
* `req_data` auto-detection (`_is_base64`) cannot tell plain text like `abcd` from
  base64; prefer `create_with_req_data()`.
* **Verify on a device**: dump ISA's outgoing license request (URL, headers, body)
  and compare byte-for-byte with the browser capture.
* **Known v1 limitation:** a bearer token embedded in the `DRMConfig` lives as
  long as ISA caches it (the whole playback session) — playback across token expiry
  is not supported; a fresh zap re-invokes `get_drm`.
* **Catchup DRM semantics**: see §6.6 (`[]` ⇒ `NotImplementedError` ⇒ PSSH
  extraction; live DRM reuse is explicit).

---

## 12. Migrating an existing (v1) provider

> **Goal:** the migrated provider behaves like the old one except for the
> deliberate changes in §12.5, and exposes the capabilities it always had but never
> wired. Plan one provider at a time; keep v1 providers untouched.

### 12.0 Preconditions

* The base patches are in (ManagedProvider, manager ABCs incl. `_base.py`,
  `base/utils/transport.py`, `base/testing/provider_contract.py`, registry
  `get_plugin_key`), and the repo's own tests are green.
* The provider has a test baseline you can run before/after (even if it is just
  "list channels, play one on a device").

### 12.0b The migration input pack (do this FIRST; hand the output to the migrator)

A migrator who only sees the provider directory cannot answer: *how does the
registry construct it?*, *what do the legacy mixin helpers it calls do?*,
*who else uses it?* Those answers live outside the directory. Generate them once
(by someone with the **whole** repo — and the Kodi/PVR/backend repos if they are
separate):

```bash
python -m streaming_providers.base.testing.migration_pack <key> \
    --repo <this repo root> --extra-root <kodi addon repo> --extra-root <pvr addon repo> \
    -o pack.txt
python -m streaming_providers.base.testing.migration_pack <key> --json before.json   # surface BEFORE
```

**Performance.** Sections 1–4 take under a second. Section 5 walks the trees you pass
in: point `--repo` at the directory **containing `streaming_providers`**, not at a whole
Kodi addon tree, and pass only the sibling repos you need as `--extra-root`. The scan
is bounded (source-like extensions only, files > 1 MB and asset directories skipped,
`--max-seconds 120` by default), prints `scanning <root> …` to stderr and writes each
section as soon as it is finished — a Ctrl-C keeps everything before section 5.
`--skip-external` skips it; the manual greps in §12.6 are the fallback.

`pack.txt` contains: (1) registry facts and the constructor source, (2) the
provider's current surface, (3) **the source of every legacy mixin/base helper the
provider calls** (`_build_provider_headers`, `_setup_http_manager`, …), (4) every
place a manager reaches into the provider, (5) every external reference to the class,
the key and the commonly moved attributes. Fill `MIGRATION_BRIEF.md` (this
directory) from it: it lists the decisions the migrator needs and nothing else
should be asked mid-migration. After the migration:

```bash
python -m streaming_providers.base.testing.migration_pack <key> --compare before.json
```

Every `REMOVED`/`CHANGED` line must be explained (deleted boilerplate is fine; a
removed public method that something calls is not), every `ADDED` line justified.

### 12.1 Inventory (10 minutes, saves hours)

```bash
cd streaming_providers/providers/<key>
grep -n "def \|class \|@property" provider.py                                  # what the provider defines
grep -rn --include='*.py' -E 'implements_|_route|self\.channels *=|def get_(manifest|drm|segment|epg|recordings|catchup)' .
grep -rn --include='*.py' '<key>' ../../base ../../providers | grep -v "providers/<key>/"   # outside users
```

Fill this table for your provider:

| Question | Answer decides |
|---|---|
| Which capabilities exist (channels, VOD, EPG, recordings, favorites, bookmarks, catchup, DRM)? | which managers you build |
| Are managers already ABC subclasses with the 4-collaborator constructor? | simpli-style (easy) vs Allente-style (constructor `(provider)` → rewrite) |
| Where does auth live? Native token class or a stateful `BaseAuthenticator`? | Variant A or B (§9) |
| Do manifest and DRM share one backend response? | `DRM_IN_MANAGERS` (§11) |
| Does the v1 provider override `get_manifest_headers`/`get_segment_headers`? Do its managers define header hooks? | `HEADERS_FROM_MANAGERS` (§10) |
| Which id prefixes/formats exist? How does v1 tell a **live id from a VOD id**? Any `catchup:`-like grammar? | `handles_content_id()` on **both** managers (§7) and provider-level overrides (§5.8) |
| What does the provider return when auth fails (`[]`/`None`/raise)? | behaviour change list (§12.5) |
| `provider_name`, directory, class name, credentials key — all equal? | §4 |
| Does anything outside the provider read its attributes (`bearer_token`, `_profile`, `channel_manager`, …)? | compatibility delegates / call-site fixes |

### 12.2 v1 → v2 mapping (what to delete, what to keep)

| In the v1 provider | In v2 |
|---|---|
| eight `implements_*` properties | **delete** (derived) |
| `implements_drm` with method-identity sniffing | **delete**; set `DRM_IN_MANAGERS = True/False` |
| `_route(...)` | **delete** (inherited) |
| `get_channels()` | **delete** (inherited) |
| the manager-assignment block (`self.channels = …; self.vod = …`) | **replace** by `self._init_managers()` (last line of `__init__`) |
| `_build_vod/_favorites/_bookmarks/_drm` returning `None` | **delete** (inherited `None`) |
| `get_manifest` with routing | **delete**, except the provider-specific prefix branch → `super()` |
| `get_drm(content_id, content_type=None, **kw)` with `_LIVE_ONLY/_VOD_ONLY` sets | **delete**, except a prefix branch (`catchup:`) |
| provider-level `get_manifest_headers` / `get_segment_headers` | **move** into manager hooks (`stream_headers()`), set `HEADERS_FROM_MANAGERS` |
| `self.channels = fetched_list` | **remove** (it clobbers the manager) |
| `get_epg/get_recordings/get_catchup_*` missing or inert | **nothing to write** — now delegated (they become reachable: §12.5) |
| v1 manager methods named after the provider API (`get_manifest`, `get_drm`, `get_manifest_headers`) | **rename** to the ABC names (`get_channel_manifest`, `get_channel_drm`, `get_channel_manifest_headers`; VOD: `get_vod_*`) — the ABC cannot be instantiated otherwise |
| `get_events` / `enrich_channel_data` overridden to delegate to an inert stub manager | **delete**; the base defaults answer `[]` / `None`. If the provider **really** implements events, keep the method on the provider with its logic (there is no events manager; §17) and do not leave it calling a manager that no longer exists |
| `get_program_details` | delegated by `ManagedProvider` to the EPG manager when one exists, `None` otherwise — nothing to write |
| `_build_provider_headers(...)` (legacy mixin) called by managers through the provider | stop calling it: build headers from `Config` (`api_headers(token)`, `stream_headers()`) with the token from `self.auth`; the mixin itself stays — the base still uses it |
| manager `__init__(self, provider)` | **rewrite** to the 4-collaborator constructor; borrow state through `auth` / explicit extras |
| provider-held auth state (`bearer_token`, `_profile`, `_last_auth_error`) | move into the session (Variant B), keep delegates |
| `try: … except Exception: log; return []` in managers | `transport_errors` + typed errors (§8) |
| recordings returned as `Channel` subclass | return `Recording` (§6.4) |
| `__init__(…, **kwargs)` | drop unless the registry needs it |
| `catchup_window_hours` = minimum of per-channel windows | **maximum**, plus `catchup_window_for_channel` (§6.6) |
| ad-hoc `get_restart()` etc. | **keep** (provider-level, outside the ABC) |

### 12.3 Step by step

1. Create a branch. Run the provider's baseline (channels list, one manifest, one DRM
   playback) and note the outputs.
2. Decide the table in §12.1.
3. Convert managers (constructor first, then `None`-vs-raise, then `transport_errors`).
4. Convert the provider: delete the boilerplate, add `DRM_IN_MANAGERS`,
   `HEADERS_FROM_MANAGERS`, `_init_managers()`, `__all__`, country normalisation.
5. Move auth behind `AuthProtocol` (Variant A or B).
6. Keep compatibility delegates for anything §12.1 found outside the provider.
7. Write/adapt the tests (§15) and run the **contract test**.
8. Run the external-reference grep (§12.6), then the device checklist (§12.7).
9. Remove the delegates once nothing uses them (separate commit).

### 12.4 What becomes reachable that never was

If the v1 provider did not define `get_epg*`, `get_recordings`/`delete_recording`,
`get_catchup_*`, `catchup_window`, manager-driven headers — those were answered by
the legacy mixin defaults (`[]`, `{}`, `NotImplementedError`, window `0`). After
migration they hit **your managers**. That is the point, and also the biggest
behaviour change: test each on a device, and expect to find bugs in managers that
were never exercised through the backend (simpli: the recording ids, the
catchup window, the EPG flag network call).

### 12.5 Deliberate behaviour changes (review each; write down yours)

| Change | Why | Revert |
|---|---|---|
| Auth/transport failures **raise** typed errors instead of `[]`/`None` | the UI can show the real reason; contract §8 | override the call with `try/except ProviderError: return []` |
| Broken DRM config raises instead of `[]` | a misconfiguration must not look like "no DRM" | — |
| Manifest/segment headers from the manager hooks (`{}` → UA+Origin) | the hooks were dead code | `HEADERS_FROM_MANAGERS = False` |
| `catchup_window` = max, per-channel hook | the backend validates with the global value | one constant |
| Recordings are `Recording` objects; delete accepts the content id | `r.is_deleted`; clients hold content ids | — |
| One malformed channel entry is skipped (before: the whole list failed) | resilience | — |
| `implements_catchup` requires `supports_catchup` | window must be > 0 | — |
| Manifest and DRM share one backend round-trip per zap (playout cache) | they used to call the entitlement/playlist endpoint twice | `PLAYOUT_CACHE_TTL = 0` |
| Managers read a **fresh token per request** from `self.auth` | a `provider.bearer_token` snapshot is stale by the first request | — |
| Eager login removed from `__init__` | network at registry-construction time; first call is now slower | restore only as the documented opportunistic login (stored credentials) |
| A second token buffer removed / kept | **needs a recorded reason either way** (§9) | — |

### 12.6 External references (needs the whole repo — the migration pack section 5 does this)

A migrator working only inside the provider directory **cannot** know this; do not
let them guess. Run the migration pack with every repo that consumes the backend
(the Kodi addon and the PVR addon refer to providers by the `"Provider"` string /
key, not by Python imports, so a Python-only grep misses them: `--extra-root`
searches XML/JSON/C++/YAML too). Manual equivalent:

```bash
grep -rn --include='*.py' -E '_last_auth_error|\._profile|<Class>Manager\(|\.channel_manager|_ensure_authenticated|_playout_cache|bearer_token|entitlement_tag' base providers | grep -v "providers/<key>/"
grep -rn --include='*.py' 'replace("provider"' base providers          # class-name derived keys
```

Anything outside the provider hitting a moved attribute needs a delegate or a
call-site fix. Check what reads `plugin_name`/`plugin` for your provider (it
changes for providers whose directory ≠ lower-cased class name minus "provider").

### 12.6b Legacy helpers (`provider_mixins/*`, `base/provider.py`)

v1 providers call helpers defined in the legacy mixins, e.g.
`_build_provider_headers(auth_type=AuthType.BEARER, …)`, `_setup_http_manager(…)`.
This README does **not** describe them (their source was not available to its
author — **unverified**). The migration pack prints the source of each one the
provider uses (section 3). Then decide, per helper:

| What the helper does | In v2 |
|---|---|
| builds request headers and **reads a token from the provider** (`self.bearer_token`, `self.authenticator.…`) | the manager builds the headers itself from `self.auth.build_headers()` / `self.auth.get_access_token()`; **tokens come from `auth`, never from a provider attribute** |
| builds request headers from static config only | move into `Config.api_headers()` / `stream_headers()` (constants.py) |
| sets up HTTP / proxy (`_setup_http_manager`) | keep calling it in `__init__` exactly as v1 does |
| anything else | keep the call if it still works; if a manager needs it, move the logic into a module function or the `Config` — a manager calling a provider method is a back-reference (§5.1) |

If a helper is used by managers through the provider, it shows up in section 4 as
well; handle it once, here.

### 12.7 Verification on a device

1. Provider shows up in the registry listing with the right `capabilities` (and
   the listing is fast — no network in flag checks).
2. Channels list loads; a malformed upstream entry does not empty it.
3. Play a clear channel and a DRM channel (license request dump compared to the
   browser capture).
4. Manifest + segment requests carry the intended headers (CDN accepts them).
5. EPG: window honoured, grid and details load; `limit` respected.
6. Catchup / restart: inside the channel window works, outside returns nothing
   (and not the live stream), DRM path (PSSH extraction when `[]`).
7. Recordings: list, play, **delete using the id the client holds**, scheduling.
8. Favorites/bookmarks: add, repeat the same bookmark write, delete missing item →
   handled as "not found".
9. Wrong password / OTP / geoblock: the UI shows the typed reason; **no login
   loop** (check the SSO traffic).
10. Credentials change: old token not resurrected after restart.

### 12.8 Rollback

Each step is a separate commit; `git revert` restores the v1 provider. v1 and v2
providers can be mixed freely.

---

## 13. Models, time, data rules

* **`Content` → `Channel` / `VodItem` / `Recording`.** `Content.pricing` of `None`
  means *unknown*, **not free**. `Channel` only *warns* about pricing/mode
  mismatches; `VodItem` (via `Content.__post_init__`) *raises*. `Recording` skips
  `Content.__post_init__` (it forces `mode="vod"`).
* Factories: `Channel.create_live_channel(name, channel_id, provider)`,
  `create_radio_channel(name, channel_id, provider)`,
  **`create_vod_channel(name, content_id, provider)`** (different parameter name).
  Construct dataclasses with `content_id=` and `provider=` (the `channel_id`
  property does not work in `__init__`).
* `Channel.catchup_hours` is the per-channel window; leave `0` unless catchup is
  really offered (do not conflate with "start-over").
* `provider` on models is the **registry key** (`PROVIDER_NAME`).
* **Time:** the backend hands **timezone-aware UTC** `datetime`s to EPG; EPG and
  catchup use **unix seconds (int)** at the manager boundary. Never mix naive and
  aware datetimes (that was a real `TypeError` in `PricePoint.is_active`). Parse
  upstream timestamps with a helper that normalises fractions/`Z`/offsets and reads
  a missing offset as UTC (see simpli `helpers.parse_iso`).
* `Quality` and similar are `(str, Enum)`: JSON-safe, compare equal to their
  string, but on Python ≥ 3.11 `f"{Quality.HD}"` gives `Quality.HD` — use `.value`
  when you format or when a non-JSON serialiser is involved.
* **Python ≥ 3.9** (PEP 585 generics are used in the base).
* `safe_base64_decode` is plain `base64.b64decode` (non-strict: silently drops
  invalid characters) — validate base64 yourself where it matters.
* Pagination: `next_cursor is None` ends a list; `total` is a hint.
* Don't persist VOD slugs; they depend on the sibling set (§17).

---

## 14. Caches and concurrency

* The host is multi-threaded. Provider-owned caches are **plain dicts created in
  the provider and borrowed by managers by reference**
  (`playout_cache=self._playout_cache`). Check-then-set races are benign for cheap
  reads (two playout calls), **not** for logins (hence the lock in auth).
* Cache keys include everything that changes the answer (id, and e.g. the DRM
  level if you ever map `drm_variant` to a level).
* **TTL cache** pattern used by simpli/Allente: `(value, timestamp)` tuples, TTL in
  `constants.py` (`PLAYOUT_CACHE_TTL = 5.0`; manifest + DRM share one request).
* **Clear caches when credentials change** (`set_user_credentials` →
  `_playout_cache.clear()`): ids/stream ids may be user- or token-specific.
* The route cache in `ManagedProvider` is bounded (`ROUTE_CACHE_SIZE = 512`) and locked.
* A shared thread-safe TTL helper does not exist yet (§17) — keep caches small and
  per-provider.

---

## 15. Testing

### What ships

| File | Purpose |
|---|---|
| `tests/test_example_provider.py` (copied by the scaffold) | the pattern: fake HTTP, no network; auth, flags, manifest/DRM sharing, headers, caches, credentials |
| `base/testing/provider_contract.py` → `check_provider(cls, key, ctor_kwargs=None)` | the **contract**: returns `(errors, warnings)` |
| `base/testing/migration_pack.py` | **before** a migration: registry facts, surface snapshot, legacy helper sources, back-references, external users (§12.0b); **after**: `--compare` |
| repo-level test (add once) | parametrise `check_provider` over every `ManagedProvider` in `AVAILABLE_PROVIDERS` |

```python
# tests/test_provider_contract.py (repo level, once)
import pytest, streaming_providers
from streaming_providers.base.managed_provider import ManagedProvider
from streaming_providers.base.testing.provider_contract import check_provider

V2 = {k: c for k, c in streaming_providers.AVAILABLE_PROVIDERS.items() if issubclass(c, ManagedProvider)}

@pytest.mark.parametrize("key", sorted(V2))
def test_contract(key):
    errors, warnings = check_provider(V2[key], key)
    assert errors == [], (errors, warnings)
```

### The contract checks (all offline — the HTTP manager raises on every call)

* subclass of `ManagedProvider`; `HEADERS_FROM_MANAGERS` declared in the class body
* instantiable with `country = SUPPORTED_COUNTRIES[0]` **without any network call** —
  the offline HTTP manager raises *and records*; an attempt swallowed by an
  `except Exception` in `__init__` is still reported (`allow_init_network=True` downgrades
  it to a warning for the documented opportunistic login)
* `provider_name == key`, `get_plugin_key() == key`
* each `implements_x` agrees with the manager; a manager overriding `get_*_drm`
  ⇒ `DRM_IN_MANAGERS` or `_build_drm()`; `DRM_IN_MANAGERS` with no manager
  implementing DRM is an error; overridden header hooks ⇒ `HEADERS_FROM_MANAGERS`
  True; EPG flag/window consistency (`(0, 0)` without a manager); overridden
  `schedule_recording` ⇒ `supports_scheduling`; package `__all__` contains the
  provider and no `ManagedProvider` in the namespace
* warnings: country not lower-case, empty `SUPPORTED_COUNTRIES`/`PROVIDER_LABEL`

### Pattern for provider tests

* `monkeypatch.setattr(YourProvider, "_setup_http_manager", lambda self, **kw: fake)`
  — works in the repo and in the sandbox.
* A `FakeHttp` records `(method, url, headers)` and returns objects with `.json()`.
  Fake payloads mimic your API; one malformed entry belongs in every list.
* Test per manager: happy path, **malformed entry skipped**, **typed error on
  failure** (no `[]`), "not mine" returns `None`/`[]`, cache hit/expiry, header
  hooks (no token in CDN headers), ids (grammar parsers as pure functions).
* Auth: no network in `__init__`; one login for N concurrent callers; expiry →
  re-login; permanent failure not retried; credentials change clears state.
* Call the provider **the way the backend does**: `get_drm(content_id=…,
  drm_variant=…, preferred_quality=…)`, `get_manifest(content_id=…)`,
  `get_catchup_manifest_with_headers(content_id=, start_time=, end_time=None,
  epg_id=, country=, drm_variant=)`.
* Run the tests of the **real** package, not only a sandbox, before trusting them.
* Providers whose constructor requires more than `country` (a config object): call
  `check_provider(cls, key, ctor_kwargs={...})`.

### How the shipped suite was built (context)

72 tests ran in a sandbox: real files for the models/ABCs/ManagedProvider, **stubs**
for modules that were never available (legacy mixins other than the ones seen,
`HTTPManager`, `errors.py`, the DRM package internals). A stub that is wrong would
make a test pass wrongly — the first run against the real package
(`V2_USE_REAL_PACKAGE=1 pytest tests`) is part of the validation.

---

## 16. Traps

Things that already cost time. Each is covered by a test or the contract unless noted.

1. `self.channels` is the manager. Assigning a list clobbers it; `to_output_format`
   would crash on the manager.
2. `provider_name` is **abstract**; a subclass without it cannot be instantiated.
3. `StreamingProvider.__init__(country)` takes **no `**kwargs`**.
4. `__all__` in `provider.py` **and** package `__init__`; never export
   `ManagedProvider` (discovery picks the first subclass alphabetically).
5. `implements_epg` is read constantly; a network call in `epg_window` makes every
   capability check an HTTP request → override `implements_epg → True`.
6. Dead header hooks: manager hooks are ignored unless `HEADERS_FROM_MANAGERS = True`.
7. The ABC header default is the **API** headers — don't send them to the CDN.
8. `catchup_window_hours` is the **max**; the global gate is used without the channel.
9. Catchup DRM `[]` ⇒ `NotImplementedError` ⇒ PSSH extraction; it is **not** "same as
   live".
10. `get_segment_headers` is swallowed in the DRM pipeline — a bug is silent.
11. Recordings are `Recording`, not `Channel`; clients hold the **content id**;
    `delete_recording` must accept it; `Recording.recording_id` is its alias.
12. `schedule_recording` needs `supports_scheduling = True` and has no legacy entry
    point.
13. Bookmark argument order differs between mixin and facade → keywords.
14. `ItemNotFoundError` (a `KeyError`) for "not there", never a bare `KeyError`.
15. `Channel.create_vod_channel` takes `content_id`, the others `channel_id`.
16. `VodItem` raises on pricing/mode mismatch; `Channel` warns; `None` pricing ≠ free.
17. Naive vs aware datetimes; EPG gets aware UTC; EPGEntry/catchup use unix seconds.
18. Country case: registry gives `"SE"` (single) or lowercase (fan-out); storage keys
    are lowercase → normalise; `["*"]` is not multi-country.
19. Class-name-derived plugin keys (`replace("provider", "")`) disagree with renamed
    providers.
20. `FavoriteType` has no `CHANNEL`.
21. LicenseConfig header encoding: `;`-splitting corrupts a UA; `+` vs `%20`
    unverified on device; ISA ignores `ProxyConfig`.
22. DRM priorities default to 1 — duplicates fail validation.
23. `safe_base64_decode` is non-strict.
24. A token embedded in a DRMConfig lives for the whole playback session.
25. Python ≥ 3.9; `(str, Enum)` formatting differs on ≥ 3.11 (use `.value`).
26. A documented policy is not an implemented policy (Allente's backoff existed only
    in comments) — implement or delete it.
27. Network I/O in `__init__` (other than an opportunistic login with stored
    credentials) — fails the contract test, **including** a call whose error is
    swallowed by `except Exception` (the offline HTTP manager records attempts).
28. `Recording.to_dict()["ContentType"]` is `"LIVE"`; `Channel.detect_and_set_radio()`
    leaves a video quality on radio channels (base issues, not yours — don't "fix"
    them in the provider).
29. A migrator who only sees the provider directory cannot know how the registry
    constructs it, what the legacy mixin helpers do, or who else calls it — run the
    migration pack (§12.0b) first; never guess.
30. Adding API a v1 provider never had (`set_user_credentials`, `get_profile`, …)
    "because the template has it" — a migration preserves the surface; compare
    with `--compare before.json`.
31. A manager calling the provider (`self._provider.x`), even "temporarily" —
    shared state belongs in `auth`/session or an explicit collaborator (§5.1).
32. Assuming `**kwargs`/`config` in a constructor are mistakes: read what the
    registry passes (§4) before changing the signature.
33. Returning a list from `get_vod_category` — works at runtime, violates the ABC;
    return `VodPage`.
34. Deleting `self.authenticator` after moving to Variant B — legacy mixins still read
    it; keep raw authenticator **and** adapter (§9).
35. Live and VOD managers without `handles_content_id()` — the first manager's
    exception stops the routing (§7); v1's "return `None` on error" hid this.
36. Removing a token buffer / constant "because the README says single truth" — the
    rule forbids *adding* one; an existing one needs a recorded reason (§9).
37. Wrapping a provider-specific exception type in `transport_errors` without
    checking that it is a `ProviderError` — it is flattened into `ServerError`; make it
    a subclass or pass it via `passthrough=(…,)`.
38. Treating the migration pack's `ADDED` lines as errors: `_build_*`,
    `DRM_IN_MANAGERS`, `HEADERS_FROM_MANAGERS` are expected additions (§12.0b).

---

## 17. Not covered / open decisions

Known gaps in the base, so you don't hunt for them:

* **Timers** (`Timer`, `TimerType`, `add_timer` …), **events** (`get_events`),
  **subscriptions**, `enrich_channel_data`, `get_epg_xmltv` have **no manager**; the
  legacy mixin defaults answer. Wire timers on the provider if you need them (a thin
  adapter onto `schedule_recording` is the recommended first step); a `TimersManager`
  only once a second provider needs it.
* **Time types** are mixed (aware `datetime` in EPG, unix `int` in catchup/EPGEntry);
  there is no shared converter module yet.
* **No shared TTL cache** with per-key locking; **no `close()`** lifecycle for HTTP
  sessions/threads.
* **VOD**: slugs are not stable across pages; `VodCategory.fetch_url` is lost
  between `get_vod_category` calls (only the opaque `content_id` arrives).
* `get_all_possible_instances()` hard-codes `"DE"` for single-country providers;
  `_is_provider_enabled` in the registry is fail-open.
* `base/provider.py` imports `providers.auth` (base depends on providers).
* `README` v1 (`_template`) describes the old shape; it is not rewritten.
* Provider-specific features outside the ABCs (restart, `get_restart`) are free-form;
  there is no `RestartInfo` type yet.

---

## 18. Definition of done

- [ ] Directory = registry key = `provider_name` = `PROVIDER_NAME` = credentials key; class `<Prefix>Provider`
- [ ] `__all__` in `provider.py` and `__init__.py`; `ManagedProvider` not exported
- [ ] `SUPPORTED_COUNTRIES` chosen deliberately; `self.country` lower-cased; unsupported country rejected
- [ ] `DRM_IN_MANAGERS` and `HEADERS_FROM_MANAGERS` declared in the class body, with a comment why
- [ ] No `implements_*` overrides, no `_route`, no `self.channels = <list>`
- [ ] All URLs/headers/ids in `constants.py`; API headers and stream headers separate
- [ ] Managers: 4-collaborator constructors, extras keyword-only, `**kw` everywhere
- [ ] Failures raise typed errors; "not mine" returns `None`/`[]`; `transport_errors` around network calls
- [ ] Malformed upstream entries are skipped, not fatal
- [ ] Auth lazy, locked, typed errors, `invalidate()` clears persisted state, no login loop
- [ ] `set_user_credentials` / `get_last_auth_error` / `get_auth_details` behave (if the UI uses them)
- [ ] EPG: `(0, 0)` without a manager; `implements_epg` free of network calls; ids match channel ids
- [ ] Catchup: global window = max, per-channel enforced, no live fallback, DRM semantics understood
- [ ] Recordings: `Recording`, content-id delete, `supports_scheduling` consistent
- [ ] Caches borrowed from the provider, cleared on credential change
- [ ] Migration pack generated before, `--compare before.json` reviewed after (no unexplained REMOVED/ADDED)
- [ ] Provider tests green; **contract test green**; repo tests green
- [ ] Device checklist §12.7 done; behaviour changes §12.5 written down in the commit message
- [ ] Provider README/docstring lists known limitations (token expiry in DRM, proxy not applied to ISA, …)

---

## 19. Appendix

### 19.1 Files in this template

```
_template_v2/
  README.md              this document
  __init__.py            exports the provider only
  provider.py            runnable orchestrator (channels + folded DRM)
  constants.py           the single source of truth (ids, URLs, headers, TTLs) + Config
  models.py              parsers + conversion to Channel
  auth.py                Variant A (native AuthProtocol)
  drm.py                 Widevine config builder (pattern from Allente)
  channel_manager.py     ChannelManager with playout cache + folded DRM
  scaffold.py            creates a provider from this template
  MIGRATION_BRIEF.md     the decisions a migrator needs, filled from the migration pack (§12.0b)
  optional/              vod, epg, recordings, catchup, favorites, bookmarks, drm managers,
                         session_adapter (Variant B incl. backoff) — each with a WIRING block
  tests/test_example_provider.py
base files this template relies on (shipped alongside):
  base/managed_provider.py, base/managers/*.py (+ _base.py), base/utils/transport.py,
  base/testing/provider_contract.py, base/testing/migration_pack.py,
  provider_mixins/metadata.py (get_plugin_key)
```

**Files the template does not ship but real providers write** (the scaffold does not
create them; nothing registers them):

* `config.py` — when header/URL building is richer than `api_headers` / `stream_headers`
  (Joyn has four header sets). `constants.py` stays the single source of the *values*.
* `session.py` — Variant B (§9); the skeleton is `optional/session_adapter.py`.
* `entitlement.py` (or similar) — a dedicated collaborator for state shared by two
  managers that is **not** derived from the token (§5.1): per-content entitlement
  tokens, a selected profile with its own lifecycle. Provider-owned, passed to the
  managers as a keyword-only extra.

### 19.2 `ManagedProvider` quick reference

| Member | Notes |
|---|---|
| `DRM_IN_MANAGERS` | declared; refused together with `_build_drm()` |
| `HEADERS_FROM_MANAGERS` | declared; default in the base is `True`, legacy was `{}` |
| `CATCHUP_DRM_FROM_LIVE` | default `False` |
| `ROUTE_CACHE_SIZE` | 512 |
| `_init_managers()` | builds `channels, vod, epg, recordings, favorites, bookmarks, catchup, drm`, then wiring checks |
| `_build_<x>()` | return a manager or `None` |
| `capabilities` | dict of the eight derived flags |
| `get_manifest / get_manifest_headers / get_segment_headers / get_drm` | routed (see §3, §7) |
| `epg_window, get_epg, get_epg_grid, get_program_details` | EPG delegation |
| `get_vod_category, search_vod` | VOD delegation (dict result) |
| `get_recordings, delete_recording` | recordings delegation |
| `get_favorites, add_favorite, remove_favorite` / `get_bookmarks, update_bookmark, delete_bookmark` | delegation |
| `catchup_window, get_catchup_window_for_channel, get_catchup_manifest(+headers), get_catchup_drm` | catchup delegation |
| `to_output_format` | uses `get_channels()` (not the shadowed list) |

### 19.3 Scaffold usage

```
python scaffold.py <key> <ClassPrefix> [--label "Display Name"] [--country DE]
                   [--with vod,epg,recordings,catchup,favorites,bookmarks,drm,session]
                   [--dest <providers dir>]
```

Refuses to overwrite an existing directory, validates `key`/`prefix`, prints the
wiring snippets. It never edits your wiring and never registers anything.

### 19.4 Glossary

* **Folded DRM** — DRM served by `get_channel_drm`/`get_vod_drm`, sharing state
  with the manifest step. **Dedicated DRM** — a separate object from `_build_drm()`.
* **Route cache** — `content_id → "channels" | "vod"`, filled when a manifest is
  resolved; headers use it.
* **None-vs-exception rule** — §8.
* **ISA** — inputstream.adaptive (Kodi).
* **Legacy surface** — what the operations layer calls (§3).
* **Variant A / B** — native `AuthProtocol` class / session adapter (§9).
