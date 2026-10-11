# streaming_providers/base/testing/migration_pack.py
"""
Migration pack -- everything a migrator needs to know about a v1 provider
BEFORE touching it, collected automatically so nobody has to guess or ask:

    python -m streaming_providers.base.testing.migration_pack <key> \
           --repo <path to the repo root> [--extra-root <other repo> ...] \
           [-o pack.txt] [--json before.json] [--compare before.json]

Sections of the report
  1. REGISTRY       how the class is registered and how the registry builds it:
                    __init__ signature, SUPPORTED_COUNTRIES, instances the
                    metadata mixin reports, and the SOURCE of the registry
                    methods that construct providers (create_instance, ...)
  2. SURFACE        every attribute the provider classes define (below the
                    base), with kind and signature. Snapshot it before the
                    migration (--json) and compare after (--compare): a
                    migration PRESERVES the public surface, it never adds to it.
  3. LEGACY HELPERS source of every `self.<name>` the provider uses that is
                    defined in a legacy mixin / the base class (e.g.
                    _build_provider_headers, _setup_http_manager): you read
                    them here instead of asking for the files.
  4. BACK-REFERENCES managers that reach into the provider (`self._provider.x`,
                    `provider.x`): each one needs an explicit collaborator in v2.
  5. EXTERNAL USERS where the class name, the provider key and the commonly
                    moved attributes are referenced OUTSIDE the provider
                    directory (and in --extra-root repos: Kodi addon, PVR addon,
                    backend ...). Run it with ALL repos you have.

Read-only: it imports the package and reads files; it never instantiates the
provider and performs no network calls.
"""

import argparse
import ast
import inspect
import json
import os
import re
import sys
from typing import Dict, Iterable, List, Optional

MOVED_ATTRS = (
    "_last_auth_error", "_profile", "bearer_token", "entitlement_tag",
    "channel_manager", "_playout_cache", "_ensure_authenticated",
    "set_user_credentials", "get_auth_details", "get_last_auth_error",
    "authenticator", "provider_config", "http_manager", "get_profile",
)
TEXT_EXT = (".py", ".json", ".xml", ".yaml", ".yml", ".cpp", ".h", ".hpp",
            ".md", ".txt", ".po", ".ini", ".cfg", ".js", ".ts")
SKIP_DIRS = {".git", "__pycache__", "node_modules", "build", "dist", ".venv", "venv", ".idea"}
MAX_HITS = 150


# --------------------------------------------------------------------------
# 1. registry
# --------------------------------------------------------------------------
def registry_facts(cls, key: str) -> str:
    out = [f"class        {cls.__module__}.{cls.__qualname__}",
           f"registry key {key!r}",
           f"__init__     {_sig(cls.__init__)}"]
    countries = getattr(cls, "SUPPORTED_COUNTRIES", None)
    out.append(f"SUPPORTED_COUNTRIES = {countries!r}")
    for name in ("supports_multiple_countries", "get_plugin_key", "get_all_possible_instances"):
        fn = getattr(cls, name, None)
        if callable(fn):
            try:
                out.append(f"{name}() -> {fn()!r}")
            except Exception as exc:   # noqa: BLE001
                out.append(f"{name}() raised {type(exc).__name__}: {exc}")
    try:
        import importlib
        reg = importlib.import_module(cls.__module__.split(".providers.")[0] + ".base.provider_registry")
    except Exception as exc:   # noqa: BLE001
        out.append(f"\n(provider_registry not importable: {exc})")
        return "\n".join(out)
    for owner in ("ProviderMetadata", "ProviderRegistry"):
        klass = getattr(reg, owner, None)
        for meth in ("create_instance", "_extract_metadata", "discover_all_providers", "get_provider"):
            fn = getattr(klass, meth, None) if klass else None
            if fn is not None:
                out.append(f"\n--- {owner}.{meth} ---\n{_source(fn)}")
    return "\n".join(out)


# --------------------------------------------------------------------------
# 2. surface
# --------------------------------------------------------------------------
def _is_base(klass) -> bool:
    mod = getattr(klass, "__module__", "") or ""
    return klass is object or ".base." in mod + "." and (
        ".base.provider" in mod or ".base.managed_provider" in mod
        or ".provider_mixins." in mod or ".base.models" in mod or ".base.managers" in mod)


def surface(cls) -> Dict[str, dict]:
    snap: Dict[str, dict] = {}
    for klass in cls.__mro__:
        if _is_base(klass) or klass is object:
            continue
        for name, value in vars(klass).items():
            if name.startswith("__") or name in snap:
                continue
            if isinstance(value, property):
                kind, sig = "property", ""
            elif isinstance(value, classmethod):
                kind, sig = "classmethod", _sig(value.__func__)
            elif isinstance(value, staticmethod):
                kind, sig = "staticmethod", _sig(value.__func__)
            elif callable(value):
                kind, sig = "method", _sig(value)
            else:
                kind, sig = "attribute", ""
            snap[name] = {"kind": kind, "sig": sig, "defined_in": klass.__qualname__}
    return snap


def diff_surfaces(before: Dict[str, dict], after: Dict[str, dict]) -> str:
    lines = []
    for name in sorted(set(before) - set(after)):
        lines.append(f"REMOVED  {name}  ({before[name]['kind']} {before[name]['sig']})")
    for name in sorted(set(after) - set(before)):
        lines.append(f"ADDED    {name}  ({after[name]['kind']} {after[name]['sig']})")
    for name in sorted(set(before) & set(after)):
        if before[name]["kind"] != after[name]["kind"] or before[name]["sig"] != after[name]["sig"]:
            lines.append(f"CHANGED  {name}: {before[name]['kind']} {before[name]['sig']}"
                         f"  ->  {after[name]['kind']} {after[name]['sig']}")
    return "\n".join(lines) or "(no differences)"


# --------------------------------------------------------------------------
# 3 + 4. legacy helpers and back-references
# --------------------------------------------------------------------------
def _self_names(tree: ast.AST, owner: str = "self") -> List[str]:
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == owner:
            names.append(node.attr)
    return names


def _package_files(cls) -> List[str]:
    module = sys.modules.get(cls.__module__)
    path = getattr(module, "__file__", None)
    if not path:
        return []
    folder = os.path.dirname(path)
    return sorted(os.path.join(folder, f) for f in os.listdir(folder) if f.endswith(".py"))


def legacy_helpers(cls) -> str:
    own_file = inspect.getsourcefile(cls)
    names = []
    with open(own_file, encoding="utf-8") as fh:
        names = _self_names(ast.parse(fh.read()))
    seen, out = set(), []
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        for klass in cls.__mro__:
            if name in vars(klass):
                if klass is cls or not _is_base(klass) or klass.__module__.endswith("managed_provider"):
                    break
                member = vars(klass)[name]
                member = getattr(member, "fget", None) or getattr(member, "__func__", member)
                if callable(member):
                    out.append(f"--- {klass.__qualname__}.{name}  ({klass.__module__}) ---\n{_source(member)}")
                break
    return "\n\n".join(out) or "(the provider uses no legacy helper)"


def back_references(cls) -> str:
    own = inspect.getsourcefile(cls)
    hits = []
    for path in _package_files(cls):
        if os.path.abspath(path) == os.path.abspath(own):
            continue
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        for owner in ("_provider", "provider"):
            attrs = sorted(set(_self_names(tree, owner)))
        # attribute access on `self._provider.<name>`
        for node in ast.walk(tree):
            if (isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute)
                    and isinstance(node.value.value, ast.Name) and node.value.value.id == "self"
                    and node.value.attr in ("_provider", "provider")):
                hits.append(f"{os.path.basename(path)}:{node.lineno}  self.{node.value.attr}.{node.attr}")
    return "\n".join(sorted(set(hits))) or "(no manager reaches into the provider)"


# --------------------------------------------------------------------------
# 5. external users
# --------------------------------------------------------------------------
def external_references(roots: Iterable[str], key: str, class_name: str, exclude_dir: Optional[str]) -> str:
    patterns = {
        f"class name {class_name}": re.compile(rf"\b{re.escape(class_name)}\b"),
        f"provider key '{key}'": re.compile(rf"""["']{re.escape(key)}(?:_[a-z]{{2,3}})?["']"""),
        "moved/compat attributes": re.compile(r"\.(" + "|".join(map(re.escape, MOVED_ATTRS)) + r")\b"),
    }
    results = {label: [] for label in patterns}
    exclude = os.path.abspath(exclude_dir) if exclude_dir else None
    for root in roots:
        for folder, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            if exclude and os.path.abspath(folder).startswith(exclude):
                continue
            for name in files:
                if not name.endswith(TEXT_EXT):
                    continue
                path = os.path.join(folder, name)
                try:
                    with open(path, encoding="utf-8", errors="ignore") as fh:
                        for number, line in enumerate(fh, 1):
                            for label, rx in patterns.items():
                                if rx.search(line) and len(results[label]) < MAX_HITS:
                                    results[label].append(f"{path}:{number}: {line.strip()[:140]}")
                except OSError:
                    continue
    parts = []
    for label, hits in results.items():
        body = "\n".join(hits) if hits else "(none)"
        parts.append(f"## {label}\n{body}")
    return "\n\n".join(parts)


# --------------------------------------------------------------------------
# helpers / CLI
# --------------------------------------------------------------------------
def _sig(fn) -> str:
    try:
        return str(inspect.signature(fn))
    except (TypeError, ValueError):
        return "(?)"


def _source(fn) -> str:
    try:
        return inspect.getsource(fn)
    except (OSError, TypeError):
        return f"(source not available for {fn!r})"


def build_report(key: str, roots: List[str], extra: List[str]) -> str:
    import streaming_providers
    registry = getattr(streaming_providers, "AVAILABLE_PROVIDERS", {})
    if key not in registry:
        return f"unknown provider key {key!r}; registered: {sorted(registry)}"
    cls = registry[key]
    provider_dir = os.path.dirname(inspect.getsourcefile(cls))
    sections = [
        ("1. REGISTRY", registry_facts(cls, key)),
        ("2. SURFACE (snapshot with --json before, --compare after)",
         "\n".join(f"{n:34} {v['kind']:12} {v['sig']}  [{v['defined_in']}]"
                   for n, v in sorted(surface(cls).items()))),
        ("3. LEGACY HELPERS used by the provider (source)", legacy_helpers(cls)),
        ("4. BACK-REFERENCES from managers to the provider", back_references(cls)),
        ("5. EXTERNAL USERS (outside the provider directory)",
         external_references(roots + extra, key, cls.__name__, provider_dir)),
    ]
    return "\n\n".join(f"{'=' * 78}\n{title}\n{'=' * 78}\n{body}" for title, body in sections)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("key")
    ap.add_argument("--repo", action="append", default=[], help="repo root to search (repeatable)")
    ap.add_argument("--extra-root", action="append", default=[], help="additional repos (Kodi addon, PVR addon, ...)")
    ap.add_argument("-o", "--output")
    ap.add_argument("--json", help="write the surface snapshot to this file")
    ap.add_argument("--compare", help="compare the current surface with a snapshot file")
    args = ap.parse_args(argv)

    import streaming_providers
    cls = getattr(streaming_providers, "AVAILABLE_PROVIDERS", {}).get(args.key)
    if args.json or args.compare:
        if cls is None:
            print(f"unknown provider key {args.key!r}")
            return 2
        current = surface(cls)
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(current, fh, indent=2, sort_keys=True)
            print(f"surface snapshot written to {args.json} ({len(current)} names)")
        if args.compare:
            with open(args.compare, encoding="utf-8") as fh:
                print(diff_surfaces(json.load(fh), current))
        return 0

    report = build_report(args.key, args.repo, args.extra_root)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"written to {args.output}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())