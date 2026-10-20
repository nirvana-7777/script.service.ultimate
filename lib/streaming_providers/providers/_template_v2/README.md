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
>
> **Revision note (third migration, HRTi):** nothing in the README was wrong, but it
> was silent in places that are now covered: client identity (§5.1), details endpoints
> that need a parent id (§6.3), the boundary of the required/optional rule (§8),
> server-side token invalidation, the recovery ladder and its concurrency rules (§9),
> persisted-state and logging checks, staged registration and how code is handed to a
> migrator (§12.1b, §12.3b), plus Traps 57–65. Two hedges are still unbuilt (§8, §17).

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
   `from ...base`.) Pasted snippets must work as they are: no `# ADAPT:` comment
   may survive into committed code (§12.3b, Trap 61).
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
* **Take the country from the registry, not from the constructor default.** Pack §1
  shows what the registry really passes (movetv: ctor default `"SI"`, registry
  `"DE"`, correct value `"RS"`). Ask for the provider's real country before
  writing `SUPPORTED_COUNTRIES`.
* **Changing the country (or adding the lower-casing) moves storage keys.**
  CredentialManager / SessionManager / ProxyConfigManager key by lower-case country:
  stored credentials, sessions and proxy settings of a provider that used to run
  under another country (`de`) are **not found** under the new one (`rs`). Record it
  in the brief (§12.5) and either migrate the stored key or tell users to re-enter
  the credentials. Lower-casing *before* `_setup_http_manager` can also make a stored
  proxy apply that v1 never found.
* `Content.country` / `Channel.country` are **upper-case** (`"RS"`), the manager's
  `country` collaborator is lower-case: use `self.country.upper()` for models.
* **White-label platforms: the operator ("brand") is not the country.** Eon serves
  six operators (SBB, Telemach ×3, Vivacom, Nova) from one API; brands and countries
  are not 1:1. Make the brand a **config option** (`config["brand"]`, validated in
  `EonConfig`, unknown value → `ConfigurationError`), keep `SUPPORTED_COUNTRIES` for
  the default operator, and resolve brand → host by **identifier** from the platform's
  own discovery endpoint, never by list position (the broker's list changed once and a
  position then silently meant another operator's CDN). An identifier the broker no
  longer lists falls back to the broker's own default, with a warning — not to a guess.

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
| **client identity** — who *this installation* is, independent of any account (device id, install uuid) | the **authenticator + settings manager**; persisted at creation; **deliberately never cleared with the token** | read-only `self.auth.<attr>` (e.g. `auth.device_id`) |
| needed by the **settings UI only** | the provider (thin delegate to the session) | — (managers never read it) |
| read by a **legacy mixin through `self`** (e.g. `ProviderAuthMixin` reads `self.authenticator.get_bearer_token()`; shared with every v1 provider) | **stays on the provider — do not delete it** | managers do **not** use it and do not call the mixin; they use `self.auth` and build headers from `Config` |

Threshold: **two consumers is enough** for a dedicated collaborator (live manager +
VOD manager already are two). A "provider-owned helper method that managers call"
is the back-reference in disguise — don't, not even "for the first pass": the
migration then has to be done twice. If you cannot decide between "part of the
session" and "separate type": derived from the token ⇒ session; has its own
fetch/refresh ⇒ separate type.

**Client identity is a third category.** It is not account state (which
`invalidate()` clears) and not a cache (which the `on_invalidate` callback clears on a
credential change). It is created once, persisted at creation, and survives both —
clearing it with the token makes the server see a new device after every logout.
"Caches to clear on credential change" (§14, the brief) has no line for it because
the concept had no name before. Corollary: if it is ever stale or wrong, the damage is
silent (HRTi: a stale device id made EPG return `[]` for as long as nobody looked, §8),
so every persisted identity value needs both getter **and** setter on the storage
layer (§12.1b).

**Bootstrap data splits in two (Eon).** Platforms that discover their API host first
(broker → CDN → host) and then need catalogues (rendering profiles, server list,
service-provider id) have a circular dependency if one object does both: auth needs the
host, the catalogues need auth. Split by *what the call needs*:

* `Endpoints` — host discovery only; **no login** (client credentials), lazy, resolved
  once under a lock, with `reset()`. Auth, the API helper and the managers get it.
* `Catalog` — data that needs a session; fetched through the authenticated API helper,
  cached with a TTL under a lock, **loaded on first use** (never in `__init__`). Two
  consumers (live + catchup) already justify the collaborator (threshold above).

Neither runs network code in `__init__` (§9 rule); a test builds the provider with a
fake HTTP manager and asserts **zero calls** after construction.
**Dead dependencies.** A declared keyword-only extra that no method reads is
deleted, including its comment. An extra that is passed "for later" is a
back-reference candidate nobody has reviewed.

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

* **A manager is a subclass of the ABC** (`ChannelManager`, `VodManager`, …); the
  constructor calls `super().__init__` with the four collaborators. A plain class
  with the right method names is rejected by the wiring check. When migrating,
  change the v1 class line too: keeping `class JoynChannelManager:` makes
  `super().__init__(...)` hit `object`.
* Four required keyword-only collaborators, **no `**kwargs`** (a typo at a call
  site is an immediate `TypeError`).
* Extras are keyword-only, declared explicitly, stored **after** `super().__init__`,
  and `super()` receives **only the four**.
* `auth` is checked against `AuthProtocol` (method presence only); a mismatch is
  a logged warning, not an error.
* Managers expose `self.http_manager`, `self.auth`, `self.country`, `self.config`.
* A declared extra that no method reads is deleted (§5.1).
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
| `handles_content_id(content_id)` | concrete | default `True` — **mandatory override on *every* id-taking manager as soon as more than one exists** (live + VOD, …). With the default the first manager receives *every* id, and any exception other than `NotFoundError` stops routing (§7). Keep the grammar in one pure `ids.py` that all managers call, so the tests are complementary by construction. **Cheap, pure, no I/O.** |

**Stream format.** `get_channel_manifest` returns whatever the upstream gives: a
DASH MPD URL or an HLS master-playlist URL (a CDN redirect or a tokenised URL
without extension is fine). You do not *declare* a format — the backend sniffs the
manifest (§11, "Stream format: DASH and HLS"). Do set the `streaming_format` hint on
the `Channel` where you know it at list time (§13).

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
* **Paging rules.** A `next_cursor` is only produced for endpoints that honour the
  offset. Endpoints that return a full list keep their own default size and return
  `next_cursor=None`. Never default `first=page_size` on an endpoint that v1
  returned in full — that silently truncates the list. Record per endpoint in the
  brief which ones honour the offset and what the v1 default size was.

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
* **Grid failure isolation.** The default `get_epg_grid` does not isolate a failing
  channel: one `ServerError` aborts the grid. Set the class attribute
  **`ISOLATE_GRID_FAILURES = True`** on your EpgManager (opt-in, default `False` =
  unchanged): `AuthError` / `RateLimitError` / `GeoBlockError` still abort (they hit
  every channel alike), any other `ProviderError` of ONE channel yields `[]` plus a
  warning. A manager that overrides `get_epg_grid` is not affected. (movetv carries
  its own override with the same semantics until the base change is merged.)
* **EPG-based catchup** (the catchup source is requested per programme): the catchup
  manager needs the EPG manager as an explicit keyword-only extra (`epg=`) and asks
  it for the programme at `start_time`. A provider-native window in `**kw`
  (`backwards=`/`forwards=` hours, movetv) is fine; ignore unknown kwargs such as
  `limit=` knowingly and say so in the docstring.
* **Details endpoints that need a parent id.** `get_program_details(program_id)` hands
  you one id; some upstream details endpoints need more (HRTi `GetEpgDetails` wants
  `ChannelReferenceId` **and** `ReferenceId`). Derive the parent from the grid parse:
  keep a hint map `program_id → parent id` filled while parsing grids, make it
  self-healing (a details answer that names its channel corrects the map), and document
  the empty-id fallback used when no hint exists. Expose the **raw `Result`** of the
  details call next to the ABC method (e.g. `get_program_details_raw`) for
  provider-specific fields the model cannot hold (HRTi catchup reads `FileName*` from
  it).
* **`epg_event_id` vs `program_id`** (models docstring) works as specified: a provider
  with a single per-broadcast id (HRTi) populates `program_id` and leaves
  `epg_event_id = None`.
* A failed request RAISES; "no programmes" (`success=false`, empty list) is `[]`
  (decision rule in §8, **including its boundary**: session/identity-state errors
  always raise, whatever the endpoint's classification).
* **Day-based endpoints** (Eon `v2/events/epg?cid=&date=`, one channel and one day per
  request). Work out *which* day first, from a real response: the first event of
  `date=2026-10-22` started at 00:15 **UTC** (03:15 local), i.e. a UTC day selected by
  programme **start** time (one sample — confirm with a programme that crosses the
  boundary before relying on it for another operator). Consequences: (1) a programme that began before the day
  boundary and still runs is only in the **previous** day's answer, so request
  `day(start) − 1 … day(end − 1)` and filter with `overlaps_with(start, end)`;
  (2) de-duplicate by the programme id across days; (3) clamp to the archive, and let
  **only the oldest day** tolerate a `400` (the boundary is day-granular; a `400` on any
  other day is a real error and raises); (4) skip entries `EPGEntry` rejects
  (`ValueError`: empty title, `end <= start`) and entries whose `channelId` is not the
  one asked for, each with a warning. Derive the cost up front: *days × channels*
  requests for a grid.
* **Timestamps in milliseconds** (`startTime`/`endTime`): divide by 1000 once, in the
  model parser; `EPGEntry` takes seconds.

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
* **`ManagedProvider` routes catchup arguments asymmetrically**: `get_segment_headers`
  sends a `start_time` kwarg to the catchup manager, `get_manifest_headers` does not.
  A provider whose manifest-header call carries `start_time` sets
  **`CATCHUP_HEADERS_ON_MANIFEST_CALL = True`** (opt-in, default `False` = unchanged;
  needs `HEADERS_FROM_MANAGERS = True`): `get_manifest_headers(id, start_time=…,
  end_time=…, epg_id=…)` is then routed to `get_catchup_manifest_headers` like the
  segment call. Until that base change is merged, use a provider-level
  `get_manifest_headers` override that calls the catchup manager and otherwise
  `super()` (movetv).
* **Catchup headers never fall back to the live headers** (wrong token / Play-Auth):
  raise `NotFoundError` when no catchup source can be resolved. The segment-header
  call is swallowed by the DRM pipeline (§8), so test the manifest-header path.
* Catchup that needs other managers takes them as keyword-only extras
  (`channels=`, `epg=`, a shared source cache) — still no provider reference (§5.1).
* **The window can be per channel and server-supplied** (Eon: `cutvDelay` in ms on every
  channel of the list, `cutvEnabled` as the switch). Keep `catchup_window_hours` a
  **constant maximum with no I/O** (the property is read without a channel and must not
  trigger a request) and read the real value in `catchup_window_for_channel()`; enforce
  it in `get_catchup_manifest` (outside the window, in the future, `start_time <= 0` or a
  channel without catchup → `None`).
* **Catchup that is "the live URL with a time" mints through the channel manager.**
  Eon's catchup URL is the signed live URL plus `t=<start>000` and a different server
  list. Put the minting in **one public method of the channel manager**
  (`stream_url(record, start_time=None | int)`) and give the catchup manager
  `channels=`; do not copy the signing code. `end_time` / `epg_id` the API does not use
  are accepted for the signature and documented as ignored.

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

**Rule:** `handles_content_id` is mandatory on **every** manager that takes ids once
more than one manager does. The ABC default is `True`, so a manager without the
override claims everything; the first manager (channels) then gets VOD ids and a
non-`NotFoundError` stops the routing. Put the grammar in **one pure `ids.py`**
(`is_live_id`, `is_vod_id`) that both managers call, so the two predicates are
complementary by construction, and unit-test a sample of ids of each kind: exactly
one manager must claim each.

**Ids that cannot be told apart** (live and VOD ids are both plain numerics): the
grammar cannot separate them, so decide who *owns* numeric ids. If one side has no
playback (movetv: VOD is browse-only), that manager returns `False` from
`handles_content_id` for **every** id and `None` from its manifest method; the other
claims the numerics. State this in `ids.py` and in the brief, and add the test with
sample ids of both kinds (§15). Browse-node ids (`category_<a>_<b>`) are not
playable ids and must not match the live predicate.

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

**Verified against `base/errors.py` and `base/network/http_manager.py`** (the two
standing hedges of the earlier migrations are closed):

* **Constructors.** Every `ProviderError` subclass in the base takes
  `Error(message, *, status=None, url=None, code=None)`; `Error("message")` works and
  `url=` on `AuthError` is fine — delete the `url=` hedges in `api.py` and the
  templates. `RateLimitError` additionally takes `retry_after=` (seconds, from the
  `Retry-After` header; `None` if absent). Provider subclasses with their own
  `__init__` keep working: `retry_after` is a class-level default and pickling/deepcopy
  restores every attribute.
* **`TransportError` is a `ServerError`** (connection-level failure, no HTTP status),
  so "network down → `ServerError`" and "retry only `ServerError`" hold without
  special-casing.
* **HTTP manager: status ≥ 400 always raises** `requests.exceptions.HTTPError` with
  `.response` set — on the `requests` **and** the `curl_cffi` backend. An error
  response is never *returned* (see Helpers for the one opt-out).

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
* **HTTP manager on 400/401/403/429/5xx — it raises; handle one shape.**
  `http_manager.get/post/put/delete` raise `requests.exceptions.HTTPError` whose
  `.response` carries the status, headers and body; `response.raise_for_status()` after
  the call is redundant. Network failures raise `ProxyError` / `Timeout` / `SSLError` /
  `ConnectionError` (the `curl_cffi` backend's own exceptions are translated, they do
  not subclass the `requests` ones). 429 is retried `max_retries` times (`Retry-After`
  honoured, each wait capped at 30 s); when exhausted the last 429 arrives as a normal
  `HTTPError`, never `RetryError`. To map to typed errors use
  `base.errors.error_from_exception(exc)` (`ProviderError` → unchanged, response →
  `default_error_for_status_heuristic` incl. `retry_after`, no response →
  `TransportError`) and raise it `from exc`. Two pitfalls: **never test
  `if exc.response:`** — a `requests.Response` is falsy for every 4xx/5xx; use
  `is not None`. When you must read an error body to decide (a 400 whose JSON says what
  went wrong), call with `raise_for_status=False` and inspect the returned response
  instead of catching the exception. Map 401/403 to `AuthError` at the one place you
  call login. `RequestConfig.retry_post=False` stops POSTs being replayed after a
  timeout (default `True` = historical behaviour).
* **Retry loops.** Retry only `ServerError` / untyped transport errors. Every other
  `ProviderError` (`AuthError`, `RateLimitError`, `GeoBlockError`,
  `EntitlementError`, …) propagates **immediately and unchanged**. Use
  `base.utils.transport.retry_transient(fn, attempts, sleep)` (to be shipped, §17);
  until then write the loop so that it catches `ProviderError` first and re-raises.
* **A broad `except Exception` around an auth-using call flattens
  `AuthError`/`RateLimitError`** into whatever the handler does (usually `[]` or
  `ServerError`) and the caller can no longer back off or show the real reason.
  Catch `ProviderError` first and re-raise, or use `transport_errors`.
* **`success=false` / empty answers — decide per endpoint and write it down.** There
  is no global rule; the one that worked for movetv: an endpoint whose result the
  caller cannot do without (channel list, live source) **raises** `ServerError`; an
  endpoint where "nothing there" is a valid answer (EPG, catalogue/browse, a catchup
  source that may have expired) returns `[]` / `None` with a warning. Record the
  choice per endpoint in the brief; it is the single most common silent behaviour
  change of a migration.
* **Boundary of that rule: data-availability errors only.** Required/optional decides
  what "no data" means. It never applies to **session- or identity-state errors**
  (token rejected, device session unknown to the server, stale client id): those raise
  typed errors (`AuthError` after the recovery ladder, §9) **regardless of how the
  endpoint is classified**. HRTi's EPG was `required=False`; a stale device id made it
  return `[]` — indistinguishable from "no programmes" — for however long nobody
  noticed. Test: a session-state failure on an optional endpoint raises.
* **`operation=` on `http_manager.post/get`** selects the **proxy** scope only (it does
  not change timeouts). Known values: `"api"`, `"auth"`, `"manifest"`, `"license"`
  (`proxy_models.KNOWN_OPERATIONS`). **Any other string is accepted and is proxied
  whenever the master switch `ProxyScope.all` is on, regardless of the per-operation
  flags** — v1's ad-hoc names (`"live_manifest"`, `"token_validate"`) therefore keep
  working but ignore a `manifests=False` / `authentication=False` setting. Where v1
  passed nothing the default is `"api"`; where a v1 string means manifest/auth/license
  traffic, prefer the known value and note the change in §12.5.

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
* **One login for concurrent callers**: lock + re-check after acquiring it (the
  re-check only dedupes when the repair rotates the identifier — see the recovery
  ladder below).
* **Typed errors**, never `None`/`[]`.
* `invalidate()` clears memory **and persisted storage** (otherwise a restart
  resurrects the old session; this bit `set_user_credentials`). **Client identity
  (device id / install uuid) is not part of that**: owned by the authenticator +
  settings manager, persisted at creation, never cleared with the token (§5.1).
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
  layer does not log request bodies at DEBUG. **Token fragments count** (HRTi v1
  `auth.py` printed three DEBUG lines with token fragments). Nothing scans for this
  automatically — grep during migration (§12.1b).
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

**Session adapter rules** (and `optional/session_adapter.py` must follow them):

* Keep the type of any `ProviderError` the authenticator raises (`type(exc)`); only
  *untyped* errors become `ServerError`.
* Managers call `get_access_token()` / `require()`. `ensure()` is for the settings UI
  only — a manager that uses it turns a permanent failure into silent anonymous
  requests.
* **Rejected credentials and MFA are permanent.** The authenticator must raise a
  typed `AuthError` for them. A bare `Exception("No authorization code")` ends up
  in the backoff loop and risks an account lock.
* Do not `force_refresh` on the first login — persisted tokens stay usable.
* `invalidate()` runs the registered `on_invalidate` callbacks; the **provider**
  registers one that clears every account-specific cache (playout, entitlement
  variants, VOD, …).
* **Injected config.** A wrapped `BaseAuthenticator` receives the provider's config
  object (`config=`). Do not build a second config inside it (two config
  constructions in one provider drift apart).

### Server-validated tokens (no usable expiry) — an accepted exception to "single truth"

Some authenticators cannot trust a token's expiry: movetv's login response has no
lifetime (v1 invented 365 days) and v1 asked the server to validate the token inside
**every** `authenticate()` call (one network POST per VOD/EPG/catchup request, up to
three per call). A session adapter for such a provider:

* validates **once per process** (the first `authenticate()` after start, which also
  validates a persisted token) and then trusts the token;
* on HTTP **401** (or the provider's body-level equivalent, next subsection) runs `recover()`: refresh the token, else a full login with
  `force_refresh=True`, then **exactly one** retry of the request (a shared
  `api_post` helper does this for every manager; a second 401 raises `AuthError`);
* does not remove the validation silently: record it in the brief (token decision
  row) and in §12.5, and test: first call validates, later calls do not, 401 → one
  refresh and one retry, second 401 → `AuthError`, 5xx → no retry.

The template adapter assumes `current_token`, `has_user_credentials()` and
`invalidate_token()` on the authenticator; **check them in `BaseAuthenticator`**
before wrapping, or use the provider authenticator's own getters (movetv:
`get_current_token()`).

### Server-side invalidation and the recovery ladder

Validity can end on the server without an HTTP 401 and without any expiry in the
token. The signal may sit in the **body of a 200**: HRTi's `ErrorCode 4` means "device
session unknown to the server" while the token itself is perfectly valid. The
movetv "server-validated token" pattern generalizes to a ladder:

* Detect invalidation in the **one** request helper every manager goes through
  (`api_post`-style), with a provider-defined predicate covering the HTTP status
  **and** body codes. Never in individual managers.
* Repair is a **recovery ladder**: each rung **at most once** per request, **cheapest
  repair first**, then exactly one retry of the original request:
  1. *targeted repair* (e.g. re-register the device/session) — preserves a valid token;
  2. *full refresh* (token refresh, or login with `force_refresh=True`) — also works
     (HRTi: login re-registers the device as a side effect) but throws a valid token
     away;
  3. a surviving failure → `AuthError`.
  The movetv validate-once + 401 recovery is the single-rung special case.
* Session/identity errors raise on every endpoint, optional ones included (§8 boundary).
* **Concurrency.** Repair under a lock with a re-check after acquiring it: the second
  caller compares the identifier it failed with against the current one and skips the
  repair if it changed. That dedup **only works when the repair rotates the
  identifier.** HRTi's `RegisterDevice` (re-)creates the server record for the
  `DeviceSerial` you supply — no rotation — so id comparison can never dedupe and a
  **short time window** ("repaired within the last N seconds → just retry") is
  required instead. Record in the brief which of the two applies.
* Tests: body code on a 200 → targeted repair once + one retry; targeted repair fails
  → full refresh; both fail → `AuthError` with bounded call counts; N concurrent
  callers → one repair.

### Several identities in one provider (Eon)

Some platforms need three different credentials, with different lifecycles. Keep them
apart in one auth class instead of one `token` field:

| Identity | Obtained by | Lifecycle | Cleared by `invalidate()`? |
|---|---|---|---|
| **client token** | OAuth `client_credentials` with the app's client id/secret | refetched on a `401` | no (not account state) |
| **device** (serial, device id, device number) | client-generated serial; server-minted ids at registration | persisted at creation (§5.1) | **never** |
| **user session** (access / refresh token, stream key + user) | refresh grant, else password / OTP login | server-validated (below) | yes |

* The user session is **server-validated** (no usable expiry, or none sent): treat the
  token as valid until a `401`, apply the recovery ladder once, retry once. Eon's ladder
  is: refresh-token grant → password / OTP login → **re-register the device** and log in
  again → `AuthError`. A rejected refresh token is deleted before falling through.
* **The refresh grant rotates the access token**, so the id-comparison dedup under the
  lock works here (the caller compares the token it failed with against the current
  one). Contrast HRTi's registration, which does not rotate and needs a time window.
* **A login that needs a human step is a typed, non-retryable `AuthError` subclass**
  carrying the data the UI must show (`EonOtpRequiredError(otp, expires_minutes)`). The
  ladder must not swallow it, the next attempt exchanges the confirmed code, and a code
  that was not confirmed produces a plain `AuthError` and clears the pending code.
* **Record a login failure once, after the whole ladder** (`_gated`). A rejected grant
  *inside* the ladder is a signal (stale device → re-register), not a verdict; only the
  ladder's final failure counts. Then apply the Variant B policy (`session_adapter.py`):
  wrong credentials (`EonLoginRejected`, only HTTP 400/401 — a 403 may be a WAF) are
  **permanent** until `set_credentials()`; everything else is **transient** with
  exponential backoff (30 s … 900 s) and **no network while backing off**; a pending OTP
  is neither. Without this every failing call retried a full login against the SSO.
* **Persisted state is behind a small `Store` protocol** (`get / set / set_many / delete`)
  with a non-durable `MemoryStore` default that is loudly documented as such: without a
  durable store every restart registers a new device (§12.1b). The durable one is
  `persistence.SessionStore` on top of `SessionManager` (one dict at
  `session.json[<provider>][<country>]`, country lower-case; `save_session` REPLACES that
  dict, so the store keeps a write-through cache and writes the whole thing, batched with
  `set_many`, skipped when nothing changed). `default_persistence()` finds the
  `SessionManager` and the credentials loader the way `BaseAuthenticator` does (injected
  settings manager, else its own) and degrades to `MemoryStore` with a warning, never to
  an exception. Credentials are loaded **lazily at the first login**
  (`settings_manager.get_provider_credentials(provider, country)`), not in `__init__`.
* **Persist only what cannot be re-derived.** Eon stores device serial / id / number and the
  refresh token. The stream key and stream user (the AES key of the CDN URL) come back with
  every token response, including the refresh grant, so they stay in memory.
  `SessionManager` logs the **values of keys it does not know at INFO** on every
  `save_session` / `load_session`; only its mask list (`access_token`, `refresh_token`,
  `client_secret`, `password`, `persona_*`) is hidden. `session_manager_patch.diff` masks by
  key-name fragment (`token`, `secret`, `password`, `jwt`, `serial`, `device_number`).
  Test both: a restart reuses the device and the refresh token (no password grant, no new
  device), and the stream key never appears in captured log output.
* Never log the stream key, tokens, device serial or a signed URL — not even at DEBUG.

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

**Client hints.** Derive `User-Agent` and every `sec-ch-ua*` header from **one**
constant (browser name + version + platform). A `User-Agent` that disagrees with the
client hints is a WAF signal.

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
  Record in the provider which of the three encodings (dict / `urlencode` /
  JSON string) is **proven on a device**, with the date; do not mix them.
* **One shared DRM builder.** When live and VOD managers both build `DRMConfig`s,
  put the construction in one module-level function (e.g. `drm.build_widevine(...)`)
  that both call — one place to fix a header or `req_data` bug.
* `req_data` auto-detection (`_is_base64`) cannot tell plain text like `abcd` from
  base64; prefer `create_with_req_data()`.
* **Verify on a device**: dump ISA's outgoing license request (URL, headers, body)
  and compare byte-for-byte with the browser capture.
* **Known v1 limitation:** a bearer token embedded in the `DRMConfig` lives as
  long as ISA caches it (the whole playback session) — playback across token expiry
  is not supported; a fresh zap re-invokes `get_drm`.
* **Catchup DRM semantics**: see §6.6 (`[]` ⇒ `NotImplementedError` ⇒ PSSH
  extraction; live DRM reuse is explicit).

### Stream format: DASH and HLS

The backend serves DASH and **unencrypted HLS**. A provider does not declare the
format: `drm_operations` sniffs the manifest it fetches anyway (`#EXTM3U` → HLS,
`<MPD` → DASH; the URL extension is only a fallback) and caches the result together
with the DRM configs. Clear HLS needs no DRM code: return `[]` from
`get_channel_drm` / `get_vod_drm` (or have no DRM at all). The pipeline verifies the
playlist itself — a media playlist with at least one segment and no `#EXT-X-KEY`
other than `METHOD=NONE`; for a master playlist the first variant's playlist is
fetched and checked — and answers "clear". Note the check fetches with your
`get_manifest_headers`, exactly as for DASH.

What the provider **should** do: set the `streaming_format` hint (§13) per channel /
VOD item when the format is known at list time. Playlist generation cannot fetch
thousands of manifests, so it uses the hint: HLS-hinted channels get the
`…/stream/index.m3u8` alias and, where inputstream.adaptive is activated,
`manifest_type=hls`. Decide **per item** (a provider can mix, e.g. live DASH and VOD
HLS), never per provider. Leave `None` for dynamic-manifest items — **unknown is not
DASH**; without a hint nothing changes for existing DASH providers.

**HLS limits** — state them in the provider docstring (phase 1, no HLS rewriter or
media-proxy path yet):

| Situation | Behaviour today |
|---|---|
| Clear HLS, CDN needs no proxy and no special headers | works: the backend answers with a redirect to the upstream playlist |
| `requires_manifest_context = True` | the backend fetches the playlist and makes every relative URI absolute (HLS has no `<BaseURL>`); the manifest query (token) is inherited unless `inherit_manifest_query_on_segments = False` |
| Provider needs an HTTP proxy (`needs_proxy`) | **not supported yet**: redirected anyway, a warning is logged; geo-proxied HLS will not play |
| CDN needs headers for manifest/segments | **unverified**: a redirect carries none; headers reach the client only via `x-kodi-stream-headers` / KODIPROPs. Prove it on a device before you rely on it (§12.7) |
| `METHOD=AES-128` | reported as unknown (never "clear"); passed through unchanged, the player fetches the key itself |
| `SAMPLE-AES`, Widevine/FairPlay HLS | detected as encrypted and passed through; no PSSH extraction, no server-side handling |
| Only the first variant is probed | separately encrypted audio renditions are not checked |
| `index.m3u8` alias | channels only; events, VOD and recordings still expose `index.mpd` |

**Locally minted, short-lived manifest URLs (Eon).** When the provider builds the
manifest URL itself (an AES-encrypted payload with a server `ctime` and a session id):

* The URL is valid for seconds (Eon's CDN rejects a `ctime` older than ~20 s) and the
  session id must not be reused while the CDN thinks it is active. Mint per request
  with a fresh session id; cache **only** for a few seconds, keyed by
  `(content_id, start_time)` — a live URL must never be served for a catchup key.
* **Session-capped CDNs and the sniff (verified against `drm_operations.py`).** Every GET
  on such a URL may open a CDN session and the CDN caps them (Eon: `403.5300 Streamable
  bandwidth exceeded`). What the backend does per `(provider, content_id, drm kwargs)`:
  it mints a URL (`get_manifest_with_headers`), GETs the playlist with
  `provider.http_manager` and, for a **master** playlist, GETs the **first variant** too
  (`_resolve_hls_master_encryption`); a verified-clear result (`[NONE]`) is cached for
  `cache_ttl` (default 1 h). The player's own request then mints a second URL. So a
  first tune-in costs ~3 GETs on the CDN, a repeat within the hour 1.
  * **The `streaming_format` hint does not skip the sniff** — it only drives playlist
    generation (above).
  * **A failed sniff is not cached** (empty configs = "no solution", self-heals by
    design), so a provider that is *refused* by the CDN (cap reached) is re-sniffed on
    every request and makes it worse. Check the logs for repeated sniff GETs.
  * **`inherit_manifest_query_on_segments`** (default `True`) appends the master's query
    to the variant URL for that second GET. If the master query is a token the variant
    does not need (Eon: the encrypted payload), set it `False` on the provider.
  * Counting the real GETs on a device (§12.7) remains the proof.
* Keep the cryptography in one pure module (`stream_url.py`: no network, no state, the
  IV injectable) and test it with a round trip **and** an exact-payload test per
  platform variant — layouts differ per client and a field in the wrong place is a
  `403` with no explanation.

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

**Input hygiene (each cost a round trip once):**

* **The supplied v1 files must be complete.** Search them for placeholder bodies
  before anything else: `grep -n "unchanged\|^\s*pass$" <files>`. A `pass  # ... unchanged ...`
  body (movetv `vod_manager.py`) cannot be migrated or rewritten; the migrator needs
  the real file (git history) or an explicit decision to ship it disabled.
* **Write `pack.txt` / `before.json` OUTSIDE the scanned tree** (e.g. `/tmp`): a pack
  inside `--repo` is scanned and reports itself as an "external user".
* **Never upload same-named files separately** (`provider.py`, `auth.py`,
  `constants.py`, `__init__.py`, `channel.py`, `vod.py` of several packages overwrite
  each other). Zip the directories or keep relative paths.

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
| Which manifest format(s) does it return (DASH, HLS, both; per channel or per content type)? Any `#EXT-X-KEY` besides `METHOD=NONE`? Does the CDN need a proxy or headers? | the `streaming_format` hint (§13) and whether HLS is servable yet (§11, "Stream format") |
| Does the v1 provider override `get_manifest_headers`/`get_segment_headers`? Do its managers define header hooks? | `HEADERS_FROM_MANAGERS` (§10) |
| Which id prefixes/formats exist? How does v1 tell a **live id from a VOD id**? Any `catchup:`-like grammar? | `handles_content_id()` on **both** managers (§7) and provider-level overrides (§5.8) |
| What does the provider return when auth fails (`[]`/`None`/raise)? | behaviour change list (§12.5) |
| `provider_name`, directory, class name, credentials key — all equal? | §4 |
| Does anything outside the provider read its attributes (`bearer_token`, `_profile`, `channel_manager`, …)? | compatibility delegates / call-site fixes |

### 12.1b Persisted-state and logging checks (before converting anything)

Two checks the pack does not do yet (§17); each cost a migration a surprise.

**(a) Getter *and* setter for every persisted value.** For each piece of state the
provider persists (device id, tokens, profile, …) verify that both halves exist on the
storage layer. HRTi had `get_device_id` with no `set_device_id`; it was found
mid-migration and degraded persistence to a warning.

```bash
# for each persisted key K: both lines must be found
grep -rn --include='*.py' -E 'def get_<K>\b' base streaming_providers
grep -rn --include='*.py' -E 'def set_<K>\b' base streaming_providers
```

**(b) Credential/token logging.** §9 forbids it; nothing scans for it.

```bash
grep -rn --include='*.py' -iE 'log(ger)?\.(debug|info|warning|error).*(token|password|secret|bearer|authorization|serial)' providers/<key>
```

Every hit is read, not skimmed: truncated or masked fragments (`token[:8]`) count.

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
| unreferenced v1 methods with real logic (`enrich_channel_data`, `populate_streaming_data`, …) | grep (pack §5): **no caller → delete**; **caller → move to the provider unchanged** |
| docstrings that promise wiring ("the provider wires X into Y", "see provider.py") | must be backed by code **and a test** — otherwise delete the sentence (Traps 26, 40) |
| `_build_provider_headers(...)` (legacy mixin) called by managers through the provider | stop calling it: build headers from `Config` (`api_headers(token)`, `stream_headers()`) with the token from `self.auth`; the mixin itself stays — the base still uses it |
| manager `__init__(self, provider)` | **rewrite** to the 4-collaborator constructor; borrow state through `auth` / explicit extras |
| provider-held auth state (`bearer_token`, `_profile`, `_last_auth_error`) | move into the session (Variant B), keep delegates |
| `try: … except Exception: log; return []` in managers | `transport_errors` + typed errors (§8) |
| recordings returned as `Channel` subclass | return `Recording` (§6.4) |
| `__init__(…, **kwargs)` | drop unless the registry needs it |
| `catchup_window_hours` = minimum of per-channel windows | **maximum**, plus `catchup_window_for_channel` (§6.6) |
| ad-hoc `get_restart()` etc. | **keep** (provider-level, outside the ABC) |
| `uses_dynamic_manifests`, `requires_manifest_context`, `supports_catchup`, `provider_label/_logo`, `supported_auth_types` properties | not delegated by `ManagedProvider`. Keep the two behaviour flags if v1 returns non-default values (check what the legacy mixin returns); `supports_catchup` and the label/logo/auth-type properties duplicate the ClassVars/derived flags → delete. List each in the `--compare` review |
| `class XChannel(Channel)` with API-internal ids (`live_id`, stream uid, token fields) | **no Channel subclass**: keep the records in the ChannelManager (`content_id → record`); the extra keys disappear from `Channel.to_dict()` — grep external users (also the Kodi/PVR repos) before accepting that |
| provider-local result/model types named like base types (`VodPage`) | **rename** (`VodListing`); the base name is what `get_vod_category` returns |
| a provider package `__init__` exporting auth/config/models | **reduce to `__all__ = ["XProvider"]`**; grep external imports first |
| stub bodies (`pass`, `# TODO`) in a v1 manager | raise `NotImplementedYetError` (typed) and keep the capability **unregistered** (`_build_*` returns `None`) until the body exists; never register a manager that crashes |

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

### 12.3b Rules for the migration process itself

* **Staged capability registration is fine** (channels first, EPG in step 2) — but the
  "EPG deliberately NOT registered yet" module docstring and the `# _build_epg(): step 2`
  placeholder must flip **in the same commit** as the factory. For exactly one step the
  HRTi module docstring lied about the provider's capabilities (Trap 26).
* **How code is handed to a migrator.** Insertion blocks with `# ADAPT:` comments are a
  bug vector: the block that was pasted into HRTi shipped `self.authenticator` (an
  attribute `HRTiSession` does not have) with the ADAPT comments still in the code —
  the "migration done twice" failure of §5.1, in migration form. Rule: **output
  complete files when the file is small enough; otherwise the block must name exact
  anchor symbols (what to replace / insert after) and every adaptation must be
  mechanical** (a rename the reader can grep, never a decision). Decisions belong in the
  brief, not in a comment. Gate: `grep -rn "ADAPT" providers/<key>` is empty.

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
| Per-call server token validation replaced by validate-once + 401 recovery | one network POST per request is not acceptable (§9 server-validated tokens) | validate in `_ready()` |
| Country / `SUPPORTED_COUNTRIES` changed, or lower-cased before `_setup_http_manager` | wrong or inconsistent country; storage keys move | re-enter credentials, or migrate the stored key (§4) |
| `success=false` now raises for required endpoints, stays empty for optional ones | per-endpoint rule (§8) | wrap the call |
| Per-channel catchup window enforced (outside → `None`; 0 h → `None`) | the backend only knows the global maximum (§6.6) | return the manifest regardless |
| `get_catchup_drm` returns `[]` → `ManagedProvider` raises `NotImplementedError` (PSSH from the manifest) | legacy contract (Trap 9); a v1 `[]` meant "clear" | set `CATCHUP_DRM_FROM_LIVE = True` if catchup is encrypted like live |
| Channel fields removed from `to_dict()` (no Channel subclass) | internals stay in the manager | — |
| One failing channel no longer empties the EPG grid (if you override it, §6.3) | resilience | keep the default |
| Capability exists in the code but is deliberately **not registered** (stub parsers) | a registered capability that crashes is worse than a missing one | flip the provider flag when the body exists |
| EPG goes through the session; a failed login now blocks EPG with typed errors | v1 EPG `_get_headers` read `authenticator._current_token.access_token` directly (a private-attribute back-reference, the shape §5.1 bans) and fired requests with whatever token state was lying around | — (accepted) |
| Session/identity-state errors raise on optional endpoints too | the required/optional rule covers data availability only (§8) | — |
| Server-side invalidation (status or body code) repaired by the recovery ladder | §9; v1 either failed silently or relied on expiry | — |

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
11. HLS channels: play through the `index.m3u8` URL; every rendition (audio,
    subtitles) loads; segments fetch **without** the backend's headers/Referer
    (`curl -I` the redirect target from another host); catchup redirects.

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
* **`streaming_format`** (on `Channel`, `VodItem`, …) is a *hint* of the manifest
  format: a `StreamFormat` member (`StreamFormat.DASH` / `StreamFormat.HLS`, from
  `base/stream_format.py`) or a string (`"dash"`, `"hls"`, also `"mpd"`, `"m3u8"`),
  coerced in `__post_init__`; anything unrecognised becomes `None` (= unknown, **not**
  DASH). `to_dict()["StreamingFormat"]` is `"dash"`, `"hls"` or `null`. The format the
  backend detects from the manifest wins over the hint (§11).
* **Do not subclass `Channel`** to carry API-internal ids (a v1 habit); they vanish
  from `to_dict()` in v2. Keep a small record per channel in the manager. Remember
  `Channel.country` is upper-case (§4).
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
  `_playout_cache.clear()`): ids/stream ids may be user- or token-specific. **Client
  identity (device id / install uuid) is not on that list** — it is neither account
  state nor a cache and survives a credential change (§5.1).
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
| `tests/conftest.py` (copied by the scaffold) | shared fixtures: `FakeHttp`, `FakeAuthenticator`, a fake clock and the `env` fixture (the Joyn test suite is a working template) |

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

**Required for every migrated provider:**

* The test files **parse** (`python -m py_compile`; run `pyflakes` in CI).
* **At least one test fails on the v1 shape** — e.g. a VOD id must not reach the
  channel manager. A migration whose tests all pass on the old code proves nothing.
* A **credential-change test**: after `invalidate()` every account-specific cache is empty.
* Per manager: a **"typed error propagates unchanged and is not retried"** test
  (`AuthError` / `RateLimitError` out of the retry loop, call count 1).
* Docstring promises have tests (Traps 26, 40).

### Eon: a scripted fake HTTP manager as the pattern

The Eon suite (`tests/test_eon.py`, `test_e2e.py`, `test_epg_catchup.py`) runs the whole
provider offline against a **route table**: `[(("get", "<url fragment>"), Resp | callable)]`
where a callable receives the call's kwargs (so a test can answer per `channelType`,
per `date` or per `cid`, and record what was asked). Like the real HTTP manager the fake
**raises `HTTPError` for ≥ 400 unless `raise_for_status=False`**. What it let us assert
cheaply and what you should copy:

* zero HTTP calls after constructing the provider;
* the exact **sequence** of calls of a login (client token → device registration →
  token grant), the recovery ladder rung by rung (a `400` on the grant → device
  re-registered → second grant) and that a stale-token `recover()` makes **no** call;
* per-request kwargs (the headers of the EPG call, the `params` of the channel list);
* that the **real** base ABCs are used, not stubs: copy `base/managers/*.py` and
  `base/models/epg_models.py` into the sandbox — the ABC contract (abstract methods,
  `ISOLATE_GRID_FAILURES`, `EPGEntry` validation) then fails the test instead of the
  device. Stub only what you do not have (`ManagedProvider`, `transport_errors`).

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
39. Keeping the v1 class line of a manager (`class XManager:`) — `super().__init__`
    then hits `object`; a manager must subclass its ABC (§6.0).
40. A specific case of Trap 26: docstrings that promise wiring ("the provider wires X into Y") without code and
    a test behind them (§12.2).
41. A broad `except Exception` around an auth-using call, or a retry loop that
    retries every error — flattens/repeats `AuthError`/`RateLimitError` (§8).
42. Managers calling `ensure()` instead of `get_access_token()`/`require()` — a
    permanent auth failure silently degrades to anonymous requests (§9).
43. An authenticator that raises a bare `Exception` for rejected credentials or MFA —
    it enters the backoff loop and can lock the account (§9).
44. `force_refresh` on the first login (§9), or a second config object built inside a
    wrapped authenticator (§9).
45. Defaulting `first=page_size` on an endpoint v1 returned in full — silent
    truncation (§6.2).
46. `User-Agent` and `sec-ch-ua*` derived from different constants (§10).
47. Two copies of the DRM config builder in live and VOD managers (§11).
48. Placeholder bodies (`pass  # ... unchanged ...`) in the supplied v1 file: the pack's
    line numbers match the stub, so the repo may be stubbed too — confirm before you
    migrate (§12.0b).
49. A provider-local type named like a base type (`VodPage`) — imports resolve to the
    wrong one (§12.2).
50. Changing the country or the lower-casing without migrating stored credentials,
    sessions and proxy keys (§4). The constructor default is not what the registry passes.
51. Subclassing `Channel` for API-internal ids; they silently leave `to_dict()` (§13).
52. `ManagedProvider.get_manifest_headers` does not route `start_time` to catchup (only
    `get_segment_headers` does) — v1 providers that did need a provider-level override (§6.6).
53. A hidden network call inside `authenticate()` (server-side token validation) paid on
    every request (§9).
54. `success=false` treated one way everywhere: required endpoints must raise, "no data"
    endpoints return empty (§8).
55. A registered capability whose parsers/bodies are stubs — hide it instead (§12.2).
56. Same-named files uploaded separately overwrite each other; packs written inside the
    scanned tree report themselves as external users (§12.0b).
57. Server-side session invalidation signalled in a 200 body (HRTi `ErrorCode 4`) while
    the token is valid — status-code-only detection misses it; use the ladder (§9).
58. The required/optional rule applied to session/identity errors: `required=False`
    hid a stale device id behind `[]` (§8).
59. Client identity cleared with the token, or treated as a cache (§5.1).
60. Re-check-after-lock dedup on a repair that does not rotate the identifier — it
    never dedupes; use a time window (§9).
61. `# ADAPT:` comments and non-existent attributes (`self.authenticator` on a session)
    surviving in pasted insertion blocks (§12.3b).
62. Persisted state with a getter but no setter on the storage layer — persistence
    silently degrades to a warning (§12.1b).
63. Token fragments in DEBUG log lines (§9, §12.1b).
64. Staged registration where the docstring/placeholder flips in a later commit than
    the factory (§12.3b).
65. A details endpoint that needs a parent id fed only `program_id` (§6.3).
66. Assuming a manifest URL ends in `.mpd`, or that a provider has one format: HLS
    exists, formats can mix per item, and tokenised URLs have no extension — the
    backend sniffs the content; never branch on the extension (§11).
67. Setting `streaming_format` per provider, or `"dash"` as a "default" — unknown
    is `None`; a wrong hint sends playlists to the wrong alias (§13).
68. HLS from a provider that needs an HTTP proxy or CDN headers: the redirect loses
    both; it logs a warning and does not play. Document it, do not "fix" it in the
    provider (§11).
69. Treating `METHOD=AES-128` HLS as clear (it is *unknown* to the backend) or
    returning DRM configs for it (§11).
70. Brand/operator modelled as country, or resolved by list position (§4).
71. One object that does host discovery and authenticated catalogues — circular; split
    `Endpoints` / `Catalog` (§5.1).
72. A day-based EPG endpoint asked for the window's days only: the programme crossing the
    day boundary is in the previous day's answer (§6.3). Check the day's timezone on a
    real response before writing the loop.
73. A catchup window read from the network inside `catchup_window_hours` (§6.6).
74. Signing code copied into the catchup manager instead of one public method on the
    channel manager (§6.6).
75. Caching a minted URL longer than the CDN accepts its timestamp, or under a key that
    ignores the start time (§11).
76. Not counting the backend's own manifest GETs against a session-capped CDN (§11).
77. A human-step login (OTP) flattened into a plain `AuthError`, or retried by the
    ladder (§9).
78. Using a media-metric field from the wrong side: Eon's `minvbr`/`maxvbr` are **video**
    bounds and must come from `videoBitrate` even on radio — an audio-only profile (video
    bitrate 0) sent its audio bitrate and the CDN answered `403`. Profile *choice* uses
    the audio bitrate for radio, the *bounds* never do. (Provider-specific, but the
    general rule holds: a field's name says which quantity, not which channel type.)
79. Recording a login failure inside the recovery ladder (a stale-device `400` then
    blocks the provider permanently) or treating every `AuthError` — including a WAF
    `403` — as "wrong credentials" (§9).
80. Persisting a re-derivable secret (stream key, anything the next token response
    returns) through `SessionManager`: unknown keys are logged in clear at INFO (§9).

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
* **HLS**: no HLS rewriter / media-proxy path (proxied or header-gated HLS and
  geo-proxied providers do not play), AES-128 policy undecided, encrypted HLS only
  passed through, only the first variant probed, `index.m3u8` alias for channels
  only (§11).
* **`HTTPManager` has no `patch()`** (`_make_request("PATCH", …)` exists, only the public
  wrapper is missing). Eon needs `PATCH v2/devices`; until it is added the provider
  `hasattr`-checks and falls back to the `v1` POST (which mints a *new* device number).
  `http_manager_patch.diff` (4 lines, not retried on 429 because PATCH is not in
  `_IDEMPOTENT_METHODS`) adds it. Raw/multipart bodies already work: `post(url, data=<bytes>,
  headers={"Content-Type": "multipart/form-data; boundary=…"})`, and `json=` passes
  through `**kwargs`.
* **No ready-made `Store` for Variant A providers**: `SessionManager` offers
  `load_session` / `save_session` (a dict per provider + country) and scoped tokens (which
  insist on `access_token` and expiry fields), not a key/value store, and it logs unknown
  values in clear. Eon's `persistence.SessionStore` is the adapter; moving it (and the
  masking patch) into `base/auth` would remove the per-provider glue.
* **`CatchupManager` and `EpgManager` do not say who owns "the programme at a time"** for
  day-based endpoints; Eon's `get_epg` re-filters by overlap, a shared helper would
  remove that duplication (see the deliberately-not-added `get_entry_at`).

**Tooling still to ship** (the README above already assumes it):

* `base.utils.transport.retry_transient(fn, attempts, sleep)` (§8). `response_of(exc)`
  is no longer needed: use `getattr(exc, "response", None)` with `is not None`, or
  `base.errors.error_from_exception` (§8).
* `check_provider(..., sample_ids={"channels": [...], "vod": [...]})`: for each sample
  id exactly one manager must return `True` from `handles_content_id`; verify the
  managers are instances of the ABCs (clear message instead of a late `TypeError`).
* Contract warning: a manager `__init__` takes an extra that is never read.
* `migration_pack` new sections: (a) manager base classes, (b) `handles_content_id`
  presence, (c) unused constructor params, (d) `except Exception` around `self.auth.*`
  calls, (e) literal URLs outside `constants.py`, (f) two config constructions in one
  provider, (g) docstring claims (`provider wires`, `see provider.py`) without
  matching code, (h) getter/setter pairs for every persisted key on the storage layer
  (§12.1b a), (i) credential/token logging (§12.1b b), (j) leftover `# ADAPT` comments
  (§12.3b).
* **Delete the two former hedges** (§8, now verified): the "handle both HTTP shapes"
  code and the `url=` fallbacks on `AuthError` in `api.py` and the templates (HRTi
  first). Replace them with `error_from_exception`.
* `optional/session_adapter.py` updated to the rules in §9 (including the recovery
  ladder and the time-window dedup).
* `tests/conftest.py` with `FakeHttp`, `FakeAuthenticator`, fake clock, `env` (§15).

**Base changes — every one must be additive with an unchanged default and pass the
contract test for ALL existing providers (Allente, simpli, Magenta2, Joyn, movetv, HRTi)
before it is merged. Two are implemented as patches (below); the rest are proposals:**

* **Implemented as patches, opt-in, defaults unchanged** (`managed_provider.py`,
  `managers/epg.py`; default behaviour verified identical, flags tested):
  `ManagedProvider.CATCHUP_HEADERS_ON_MANIFEST_CALL` (§6.6) and
  `EpgManager.ISOLATE_GRID_FAILURES` (§6.3). Before merging run the contract test for
  every provider and
  `grep -rn "ISOLATE_GRID_FAILURES\|CATCHUP_HEADERS_ON_MANIFEST_CALL" providers/`
  (a same-named attribute in a provider would shadow the new one).
* **Deliberately NOT added:** an `EpgManager.get_entry_at()` helper. Only movetv
  needs "the programme at a timestamp"; its matching rules (containment, tolerance)
  are provider-specific. Add it when a second provider needs the same rules.
* One shared session adapter with `recover()` (the §9 ladder) and `on_invalidate` (backwards
  compatible with the template adapter's public methods) plus the shared `api_post`
  helper (401 → one recovery → one retry, one HTTP-manager error shape) — as a new
  module; no provider is forced to switch.
* ~~Document the accepted `operation=` values~~ — done in §8.
* `migration_pack`: placeholder-body detection (`pass  # ...`), output-inside-tree
  guard, `--bundle` that keeps relative paths, and rows for the actual constructor
  country vs. the declared one.

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
- [ ] Managers subclass the ABCs (`isinstance` check passes)
- [ ] `handles_content_id` on **every** id-taking manager; one pure `ids.py`; exactly one manager claims each sample id
- [ ] No declared extra left unused
- [ ] Every docstring promise ("the provider wires …") has code and a test
- [ ] `User-Agent` and `sec-ch-ua*` derived from one constant
- [ ] One shared DRM builder when more than one manager builds DRM
- [ ] Retry loops: only `ServerError`/untyped retried, other `ProviderError`s propagate unchanged (test per manager)
- [ ] Authenticator raises typed `AuthError` for rejected credentials/MFA; managers use `require()`/`get_access_token()`, never `ensure()`
- [ ] Tests parse and run; at least one test fails on the v1 shape; credential-change cache-clearing test exists
- [ ] `SUPPORTED_COUNTRIES` and the constructor country match what the registry passes; moved storage keys handled or documented
- [ ] No placeholder/stub body is registered as a capability
- [ ] `success=false` / empty-answer decision recorded per endpoint
- [ ] No `Channel` subclass; internals live in the manager; external users of removed `to_dict()` keys checked
- [ ] No provider-local type shares a name with a base type
- [ ] Token validation model recorded (expiry-based vs. server-validated; invalidation signal: status and/or body code) and tested, including the recovery ladder (each rung at most once, then `AuthError`) and the concurrency dedup (rotated id vs. time window)
- [ ] Session/identity-state errors raise on every endpoint, optional ones included (§8)
- [ ] Client identity (device id / install uuid) owned by authenticator + settings manager, persisted at creation, never cleared with the token (§5.1)
- [ ] Every persisted key has getter **and** setter on the storage layer (§12.1b)
- [ ] No token/credential fragment in any log line (grep, §12.1b)
- [ ] No `# ADAPT` comment and no reference to a non-existent attribute left from pasted blocks (§12.3b)
- [ ] Capability docstring/placeholder flipped in the same commit as its factory (§12.3b)
- [ ] Details endpoints needing a parent id: hint map + documented fallback; raw result exposed if provider-specific fields are read (§6.3)
- [ ] Manifest format(s) recorded; `streaming_format` hint set per item where known (never a provider-wide guess); HLS limits (proxy, headers, AES-128) listed in the provider docstring and device-tested (§11, §12.7)

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
* **StreamFormat** — `DASH` / `HLS` (`base/stream_format.py`); `None` = unknown. The
  `streaming_format` field is only a hint; the backend sniffs the manifest (§11).

### 19.5 Eon — what it is the reference for

`providers/eon/` (live TV + radio, EPG, catchup, clear HLS, no DRM). Use it when you
meet one of these:

| Situation | Where | README |
|---|---|---|
| white-label platform, brand ≠ country, discovery before login | `constants.py` (`EonConfig`), `bootstrap.py` (`EonEndpoints`) | §4, §5.1 |
| catalogues that need a session, TTL + lock | `bootstrap.py` (`EonCatalog`) | §5.1 |
| client token + device + user session, recovery ladder, OTP | `auth.py`, `errors.py` | §9 |
| one place for "401 → recover → retry once" | `api.py` | §8, §9 |
| durable device identity + credentials from the settings manager | `persistence.py` | §9 |
| locally signed, short-lived manifest URL | `stream_url.py`, `channel_manager.py` | §11 |
| day-based EPG with a boundary programme | `epg_manager.py` | §6.3 |
| per-channel, server-supplied catchup window; catchup via the channel manager | `catchup_manager.py` | §6.6 |
| offline tests with a route-table fake and the real ABCs | `tests/` | §15 |