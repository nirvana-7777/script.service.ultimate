# Migration brief — `<key>` (v1 → v2)

Fill this in **from the migration pack** before the migration starts, and hand it
to the migrator together with `pack.txt` and `before.json`. A migrator should not
have to ask anything that is answered here. Anything marked ❓ that you cannot
answer is a blocker — stop and get the answer; do not guess.

```bash
python -m streaming_providers.base.testing.migration_pack <key> --repo <repo> \
    --extra-root <kodi addon> --extra-root <pvr addon> -o pack.txt
python -m streaming_providers.base.testing.migration_pack <key> --json before.json
```

## 1. Identity
| | |
|---|---|
| Directory / registry key / `provider_name` / credentials key | ❓ all equal? (§4) |
| Class name | |
| `SUPPORTED_COUNTRIES` (pack §1) | `[]` / one entry / several |
| How the registry calls the constructor (pack §1, source of `create_instance`) | ❓ `cls(country=…)`? `config`? extras? |
| Constructor signature the migrated class must keep | |
| Extra `ctor_kwargs` the contract test needs | |
| **Id grammar**: how are live ids and VOD ids told apart? (→ `handles_content_id` on both managers) | ❓ |

## 2. Capabilities (what v1 really has)
channels ☐  vod ☐  epg ☐  recordings ☐  favorites ☐  bookmarks ☐  catchup ☐  drm ☐  timers ☐(not delegated)  events ☐(not delegated)

For each: does a v1 manager class already exist? Does it follow the 4-collaborator
constructor, or take the provider (`__init__(self, provider)`)? ❓

## 3. Decisions (README reference)
| Decision | Answer | Evidence (pack section) |
|---|---|---|
| Auth variant (§9): A native / B session adapter | | where does the login live? |
| `DRM_IN_MANAGERS` (§11): folded / dedicated / none | | do manifest and DRM share one response? |
| `HEADERS_FROM_MANAGERS` (§10) | | do v1 manager header hooks exist and are they dead code? what does the legacy helper (pack §3) do? |
| Shared state: entitlement / profile / … (§5.1) | session / dedicated collaborator / cache / helper | every back-reference in pack §4 mapped to a row |
| Credentials API (`set_user_credentials`, `get_auth_details`, …) | keep / drop | callers found (pack §5) **and** does the v1 surface (`before.json`) define them? Dropping a method v1 has is a REMOVED line |
| Token buffer(s) in the authenticator (grep `expires_in -`) | keep (reason: ___) / remove (device test: ___) | never remove by reflex (§9) |
| Provider-specific exceptions callers rely on | are they `ProviderError` subclasses? if not: make them so or `passthrough=` in `transport_errors` | `issubclass(X, ProviderError)` |
| `get_events` / `enrich_channel_data` / `get_program_details` | real implementation → keep on provider; inert stub → delete | §12.2 |
| Manager method renames (`get_manifest` → `get_channel_manifest`, …) | list | §12.2 |
| Failure behaviour (§8, §12.5) | v1 returns `[]`/`None` → v2 raises | OK for the UI? |
| VOD return shape | list / dict / `VodPage` | wrap with `normalize_vod_result` |

## 4. Legacy helpers the provider calls (pack §3)
| Helper | What it does (read the source) | v2 replacement (§12.6b) |
|---|---|---|
| | | |

## 5. External users (pack §5)
| Where | What it uses | Action (delegate / call-site fix / none) |
|---|---|---|
| | | |

## 6. Behaviour changes accepted (§12.5)
☐ typed errors instead of `[]`/`None`   ☐ headers from manager hooks   ☐ capabilities now reachable (list which)   ☐ eager login removed   ☐ token buffer changed (reason recorded)   ☐ other: ______

## 7. Done when
Definition of done (README §18); `--compare before.json` reviewed — expected: REMOVED = deleted boilerplate/stubs/delegated flags, ADDED = only `_build_*`, `DRM_IN_MANAGERS`, `HEADERS_FROM_MANAGERS` (anything else is unexplained); device checklist (§12.7) signed off.
