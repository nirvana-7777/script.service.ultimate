#!/usr/bin/env python3
"""
Scaffold a new v2 provider from this template.

    python scaffold.py <key> <ClassPrefix> [--label "Display Name"]
                       [--country DE] [--with vod,epg,recordings,catchup,
                                               favorites,bookmarks,drm,session]
                       [--dest <providers dir>]

    key          directory name == registry key == provider_name == credentials
                 key. lower-case, [a-z][a-z0-9_]*   (e.g. joyn, magenta2)
    ClassPrefix  CamelCase prefix of the classes     (e.g. Joyn -> JoynProvider)

What it does
  * copies the template into <dest>/<key>/ (default: the template's parent
    directory, i.e. providers/), replacing  example -> key,  Example ->
    ClassPrefix,  EXAMPLE -> KEY  in file names and contents
  * moves the chosen optional/ managers next to provider.py (fixing their
    relative imports) -- session = optional/session_adapter.py -> session.py
  * copies tests/ (core provider tests)
  * prints the _build_* wiring snippet of every chosen manager: PASTE THEM
    into provider.py (the scaffold never edits your wiring)
It does not touch README.md of the template and does not register anything:
provider discovery picks the package up from the directory automatically.
"""

import argparse
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OPTIONAL = {
    "vod": ("vod_manager.py", "vod_manager.py"),
    "epg": ("epg_manager.py", "epg_manager.py"),
    "recordings": ("recordings_manager.py", "recordings_manager.py"),
    "catchup": ("catchup_manager.py", "catchup_manager.py"),
    "favorites": ("favorites_manager.py", "favorites_manager.py"),
    "bookmarks": ("bookmarks_manager.py", "bookmarks_manager.py"),
    "drm": ("drm_manager.py", "drm_manager.py"),
    "session": ("session_adapter.py", "session.py"),
}
SKIP_TOP = {"scaffold.py", "README.md"}


def _convert(text: str, key: str, prefix: str) -> str:
    return (text.replace("example", key)
                .replace("Example", prefix)
                .replace("EXAMPLE", key.upper()))


def scaffold(key, prefix, dest=None, label=None, country=None, with_=()):
    if not re.fullmatch(r"[a-z][a-z0-9_]*", key):
        raise SystemExit(f"invalid key {key!r}: use lower-case [a-z][a-z0-9_]*")
    if not re.fullmatch(r"[A-Z][A-Za-z0-9]*", prefix):
        raise SystemExit(f"invalid class prefix {prefix!r}: use CamelCase")
    unknown = [w for w in with_ if w not in OPTIONAL]
    if unknown:
        raise SystemExit(f"unknown optional manager(s): {unknown}; choose from {sorted(OPTIONAL)}")

    dest_root = Path(dest) if dest else HERE.parent
    target = dest_root / key
    if target.exists():
        raise SystemExit(f"{target} already exists")
    target.mkdir(parents=True)

    for src in sorted(HERE.glob("*.py")):
        if src.name in SKIP_TOP:
            continue
        (target / _convert(src.name, key, prefix)).write_text(
            _convert(src.read_text(), key, prefix))

    if label:
        const = target / "constants.py"
        const.write_text(re.sub(r'PROVIDER_LABEL = ".*?"', f'PROVIDER_LABEL = "{label}"',
                                const.read_text(), count=1))
    if country:
        for name, pattern, repl in (
            ("constants.py", r'SUPPORTED_COUNTRIES = \(".*?",\)', f'SUPPORTED_COUNTRIES = ("{country.upper()}",)'),
            ("provider.py", r'country: str = ".*?"', f'country: str = "{country.upper()}"'),
        ):
            f = target / name
            f.write_text(re.sub(pattern, repl, f.read_text(), count=1))

    snippets = []
    for name in with_:
        src_name, dst_name = OPTIONAL[name]
        text = _convert((HERE / "optional" / src_name).read_text(), key, prefix)
        text = text.replace("from ....base", "from ...base")
        (target / dst_name).write_text(text)
        m = re.search(r"--- WIRING ---\n(.*?)--- END WIRING ---", text, re.S)
        snippets.append((name, m.group(1).rstrip() if m else "(see the file docstring)"))

    tests = HERE / "tests"
    if tests.is_dir():
        (target / "tests").mkdir()
        for src in sorted(tests.glob("*.py")):
            (target / "tests" / _convert(src.name, key, prefix)).write_text(
                _convert(src.read_text(), key, prefix))

    print(f"created {target}")
    for name, snippet in snippets:
        print(f"\n# --- paste into {prefix}Provider ({name}) ---\n{snippet}")
    print("\nNext: README §Migrating / §Checklist; then run the provider tests "
          "and the contract test.")
    return target


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("key")
    ap.add_argument("prefix")
    ap.add_argument("--label")
    ap.add_argument("--country")
    ap.add_argument("--dest")
    ap.add_argument("--with", dest="with_", default="", help="comma separated optional managers")
    a = ap.parse_args(argv)
    scaffold(a.key, a.prefix, a.dest, a.label, a.country,
             [w for w in a.with_.split(",") if w])


if __name__ == "__main__":
    sys.exit(main())
