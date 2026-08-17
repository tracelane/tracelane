#!/usr/bin/env python3
"""The API-key scope vocabulary is written in three places. They must all agree.

WHY (2026-08-13, GWY-41). A13 shipped a deliberately CLOSED vocabulary — an
unrecognised slug grants nothing — but it is *spelled out* three times: the Rust
enum that decides, the TypeScript list the mint dialog renders, and a Postgres
column comment that documents it. Adding `ingest` for GWY-41 meant touching all
three, and nothing would have failed had one been missed.

The failure is silent and one-directional, which is the worst combination:

  * Rust gains a scope, the UI does not  -> the capability exists and no customer
    can grant it. That is the `GWY-40` kill-switch shape (an operational control
    that was documented and not operable) and the `B-137` tool-pin shape (a read
    path with no way to create the thing it reads).
  * The UI gains a scope, Rust does not  -> the checkbox mints a key carrying a
    slug that `Scope::from_slug` refuses, so the key silently has LESS access
    than the dialog just promised. The customer sees a granted permission that
    denies.

Same class as B-068 (a hand-maintained provider count that reached the marketing
site twice), B-145 (routable != storable because two provider allowlists drifted)
and the six-place alert-metric list (`check-alert-metrics-single-source.py`).

SOURCE OF TRUTH: `Scope::all()` in `crates/shared/src/api_scope.rs`. The gateway
is what actually admits or refuses a request, so a slug it does not parse is not
a scope no matter what any other layer displays — code wins (CLAUDE.md 4.0).

CHECKED AGAINST IT:
  1. `Scope::from_slug` / `as_slug` -- the parse and render arms must cover
     exactly the same set, or a scope is grantable and unnameable (or vice versa)
  2. `apps/web/components/settings/ApiKeyManager.tsx` -- `SCOPES`, the checkbox
     list a human actually ticks
  3. the newest `apps/web/db/migrations/*.sql` `COMMENT ON COLUMN api_keys.scope`
     -- documentation a future reader will believe

A FOURTH SITE EXISTS AND IS DELIBERATELY NOT CHECKED HERE:
`key_routes.rs`'s `omitted_scope_is_recorded_explicitly_not_as_null` asserts the
full set as a literal. That one is a TRIPWIRE, not a mirror — deriving it from
`Scope::all()` would make it circular and it would then pass for any vocabulary,
including a wrong one. It is supposed to go red when a scope is added, so a human
decides whether "omitted = full surface" should include the new capability. It
did exactly that for `ingest`. Do not "fix" it by pointing it at the enum.

HONEST LIMIT, and it is the same one every guard of this shape has: this proves
the three lists hold the same NAMES. It does not prove a scope is ENFORCED
anywhere. `Scope::Ingest` could exist in all three and be checked at no call
site, and this guard would stay green -- that is exactly the B-207 shape (the
A13 gate's model had 8 tests and its wiring had none). Agreement on spelling,
never on behaviour.

USAGE
  check-api-scope-single-source.py             # check
  check-api-scope-single-source.py --selftest  # prove it BLOCKS each drift
EXIT 0 agree - 1 a list disagrees - 2 bad usage / a source could not be read
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[2]

RUST = ROOT / "crates" / "shared" / "src" / "api_scope.rs"
WEB_UI = ROOT / "apps" / "web" / "components" / "settings" / "ApiKeyManager.tsx"
MIGRATIONS = ROOT / "apps" / "web" / "db" / "migrations"


def die(msg: str, code: int = 1) -> NoReturn:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(code)


def read(p: Path) -> str:
    # "I cannot see" is never "nothing is wrong" (CLAUDE.md 1.14) — an unreadable
    # source exits 2 (cannot determine), never 0.
    try:
        return p.read_text(encoding="utf-8")
    except OSError as e:
        die(f"cannot read {p.relative_to(ROOT)}: {e}", code=2)


def canonical(src: str) -> set[str]:
    """`Scope::all()` in api_scope.rs — the source of truth."""
    m = re.search(
        r"fn all\(\)\s*->\s*\[Scope;\s*\d+\]\s*\{\s*\[(.*?)\]", src, re.DOTALL
    )
    if not m:
        die("could not find `fn all() -> [Scope; N]` in api_scope.rs", code=2)
    variants = re.findall(r"Scope::(\w+)", m.group(1))
    if not variants:
        die(
            "`Scope::all()` parsed to an EMPTY set — refusing to compare against nothing",
            code=2,
        )
    # Map each variant to the slug its own `as_slug` arm returns, so the guard
    # never invents a spelling by lowercasing the variant name.
    slugs = set()
    for v in variants:
        arm = re.search(rf"Self::{v}\s*=>\s*\"([^\"]+)\"", src)
        if not arm:
            die(f"`Scope::{v}` is in all() but has no `as_slug` arm", code=1)
        slugs.add(arm.group(1))
    return slugs


def from_slug_arms(src: str) -> set[str]:
    """The slugs `from_slug` actually parses."""
    m = re.search(
        r"fn from_slug\(.*?\)\s*->\s*Option<Self>\s*\{(.*?)\n    \}", src, re.DOTALL
    )
    if not m:
        die("could not find `fn from_slug` in api_scope.rs", code=2)
    return set(re.findall(r"\"([a-z_]+)\"\s*=>\s*Some\(", m.group(1)))


def ui_scopes(src: str) -> set[str]:
    """`SCOPES` in ApiKeyManager.tsx — the checkbox list."""
    m = re.search(r"const SCOPES:[^=]*=\s*\[(.*?)\n\];", src, re.DOTALL)
    if not m:
        die("could not find `const SCOPES` in ApiKeyManager.tsx", code=2)
    found = set(re.findall(r"value:\s*\"([^\"]+)\"", m.group(1)))
    if not found:
        die("`SCOPES` parsed to an EMPTY list — a broken parser is not a pass", code=2)
    return found


def migration_comment_scopes() -> tuple[set[str], str] | tuple[None, None]:
    """The newest migration that documents the vocabulary in a column comment."""
    for path in sorted(MIGRATIONS.glob("*.sql"), reverse=True):
        src = read(path)
        # `[^;]*?` keeps the match INSIDE the statement. With `.*?` a header
        # comment mentioning the column would anchor the match and the guard would
        # read a brace from prose instead of from the statement that ships.
        m = re.search(
            r"COMMENT ON COLUMN api_keys\.scope[^;]*?\{([a-z,\s]+)\}",
            src,
            re.IGNORECASE,
        )
        if m:
            return {s.strip() for s in m.group(1).split(",") if s.strip()}, path.name
    return None, None


def check() -> int:
    rust_src = read(RUST)
    truth = canonical(rust_src)

    failures: list[str] = []

    parsed = from_slug_arms(rust_src)
    if parsed != truth:
        failures.append(
            f"`from_slug` parses {sorted(parsed)} but `all()` declares {sorted(truth)} — "
            f"missing in from_slug: {sorted(truth - parsed)}, "
            f"parseable but undeclared: {sorted(parsed - truth)}"
        )

    ui = ui_scopes(read(WEB_UI))
    if ui != truth:
        failures.append(
            f"ApiKeyManager.tsx SCOPES = {sorted(ui)} but the enum declares {sorted(truth)} — "
            f"not offerable in the UI: {sorted(truth - ui)}, "
            f"offered but not a real scope: {sorted(ui - truth)}"
        )

    doc, doc_file = migration_comment_scopes()
    if doc is None:
        failures.append(
            "no migration carries a `COMMENT ON COLUMN api_keys.scope` naming the "
            "vocabulary — the column's documentation cannot be checked"
        )
    elif doc != truth:
        failures.append(
            f"{doc_file} column comment says {sorted(doc)} but the enum declares "
            f"{sorted(truth)} — a future reader will believe the comment"
        )

    if failures:
        print(
            "FAIL: the API-key scope vocabulary disagrees across its three homes\n",
            file=sys.stderr,
        )
        for f in failures:
            print(f"  * {f}", file=sys.stderr)
        print(
            "\n  Source of truth is `Scope::all()` in crates/shared/src/api_scope.rs.",
            file=sys.stderr,
        )
        return 1

    print(
        f"api-key scopes: {sorted(truth)} — enum, from_slug, UI and column comment agree"
    )
    print(
        "\nHONEST LIMIT: this proves the lists hold the same NAMES. It does NOT prove\n"
        "any scope is ENFORCED at a call site — a scope present in all three and\n"
        "checked nowhere passes this guard."
    )
    return 0


def selftest() -> int:
    """Plant each drift in a COPY of the tree and prove the guard blocks it."""
    global RUST, WEB_UI, MIGRATIONS
    # Capture the REAL sources once. The loop below points the globals at a temp
    # dir that is then deleted, so copying from the globals works for exactly one
    # iteration and then fails on a path that no longer exists — which is how the
    # first version of this selftest died.
    real_rust, real_ui, real_migs = RUST, WEB_UI, MIGRATIONS
    cases = [
        (
            "a scope in the enum that the UI cannot offer",
            "rust_add",
        ),
        (
            "a UI checkbox for a slug that is not a real scope",
            "ui_add",
        ),
        (
            "a stale column comment after a scope is added",
            "doc_stale",
        ),
        (
            "a variant declared in all() that from_slug cannot parse",
            "unparseable",
        ),
    ]
    ok = True
    for label, kind in cases:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            rust = tmp / "api_scope.rs"
            ui = tmp / "ApiKeyManager.tsx"
            migs = tmp / "migrations"
            migs.mkdir()
            shutil.copy(real_rust, rust)
            shutil.copy(real_ui, ui)
            for m in real_migs.glob("*.sql"):
                shutil.copy(m, migs / m.name)

            if kind == "rust_add":
                s = rust.read_text()
                s = s.replace("    Admin,\n", "    Admin,\n    Bogus,\n", 1)
                s = s.replace(
                    '"admin" => Some(Self::Admin),',
                    '"admin" => Some(Self::Admin),\n            "bogus" => Some(Self::Bogus),',
                    1,
                )
                s = s.replace(
                    'Self::Admin => "admin",',
                    'Self::Admin => "admin",\n            Self::Bogus => "bogus",',
                    1,
                )
                s = re.sub(r"(fn all\(\)\s*->\s*\[Scope;\s*)\d+", r"\g<1>99", s)
                s = s.replace("Scope::Admin]", "Scope::Admin, Scope::Bogus]", 1)
                rust.write_text(s)
            elif kind == "ui_add":
                s = ui.read_text()
                s = s.replace(
                    "const SCOPES: { value: string; label: string; hint: string }[] = [\n",
                    'const SCOPES: { value: string; label: string; hint: string }[] = [\n\t{\n\t\tvalue: "superuser",\n\t\tlabel: "Superuser",\n\t\thint: "everything",\n\t},\n',
                    1,
                )
                ui.write_text(s)
            elif kind == "doc_stale":
                for m in migs.glob("*.sql"):
                    s = m.read_text()
                    if "COMMENT ON COLUMN api_keys.scope" in s:
                        m.write_text(
                            re.sub(
                                r"(COMMENT ON COLUMN api_keys\.scope[^;]*?)\{[a-z,\s]+\}",
                                r"\g<1>{chat,read}",
                                s,
                                count=1,
                                flags=re.IGNORECASE,
                            )
                        )
            elif kind == "unparseable":
                s = rust.read_text()
                # Remove ONE from_slug arm while leaving all()/as_slug intact.
                s = s.replace('            "read" => Some(Self::Read),\n', "", 1)
                rust.write_text(s)

            RUST, WEB_UI, MIGRATIONS = rust, ui, migs
            try:
                rc = check()
            except SystemExit as e:
                rc = int(e.code or 0)
            blocked = rc == 1
            print(f"  [{'BLOCKED' if blocked else 'LEAKED '}] {label}", file=sys.stderr)
            ok &= blocked

    # And prove it PASSES on the real tree, so a guard that fails everything
    # cannot masquerade as a guard that catches everything.
    RUST, WEB_UI, MIGRATIONS = real_rust, real_ui, real_migs
    try:
        clean = check() == 0
    except SystemExit as e:
        clean = int(e.code or 0) == 0
    print(
        f"  [{'PASS   ' if clean else 'FAILED '}] the real tree agrees", file=sys.stderr
    )
    ok &= clean

    print(f"\nselftest: {'OK' if ok else 'BROKEN'}", file=sys.stderr)
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--selftest", action="store_true", help="prove the guard blocks each drift"
    )
    args = ap.parse_args()
    return selftest() if args.selftest else check()


if __name__ == "__main__":
    sys.exit(main())
