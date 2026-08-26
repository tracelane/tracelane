#!/usr/bin/env python3
"""Every migration file must be in the gateway's `MIGRATIONS` list, in order.

`crates/gateway/src/db/mod.rs::apply_migrations` holds a hand-written
`include_str!` list that IS the definition of a fresh database — every
integration test that touches Postgres builds its schema from it.

**This guard was named in that function's own comment and did not exist.**
The comment reads "Pinned against the directory by
`scripts/ci/check-migration-list-complete.py`, because this list DRIFTED"
— describing a real past incident (0007-0010 silently skipped, so the only
test covering `api_keys::create` died on `column "archived_at" does not
exist`) and crediting a file nobody had written. So the list drifted AGAIN
the next time someone added a migration: `0029` landed in the directory, was
never added to the list, and `create_tenant_and_lookup_by_api_key` failed
with `column "rate_limit_rpm" does not exist` — the identical failure, from
the identical cause, with a comment in between asserting it could not happen.

A comment naming a control is not a control. This is the control.

Usage:
    check-migration-list-complete.py            fail on drift
    check-migration-list-complete.py --selftest prove it refuses drift
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MOD_RS = ROOT / "crates/gateway/src/db/mod.rs"
MIGRATIONS_DIR = ROOT / "apps/web/db/migrations"

# `include_str!("…/migrations/NAME.sql")`, tolerating rustfmt's line wrapping.
INCLUDE = re.compile(r'migrations/([0-9A-Za-z_\-.]+\.sql)"')

# A floor. A parser that suddenly finds two migrations has broken, and reporting
# "no drift" from a broken parse is the failure this file exists to stop.
MIN_EXPECTED = 20


def listed(src: str) -> list[str]:
    """Migration filenames inside the `MIGRATIONS` const, in source order."""
    m = re.search(r"const MIGRATIONS: &\[&str\] = &\[(.*?)\n    \];", src, re.DOTALL)
    if m is None:
        sys.exit(
            "FAIL — could not locate `const MIGRATIONS` in "
            f"{MOD_RS.relative_to(ROOT)}. The shape changed; update this guard "
            "rather than letting it report a clean tree it never read."
        )
    return INCLUDE.findall(m.group(1))


def on_disk() -> list[str]:
    return sorted(p.name for p in MIGRATIONS_DIR.glob("*.sql"))


def check(listed_files: list[str], disk_files: list[str]) -> list[str]:
    errs: list[str] = []
    missing = [f for f in disk_files if f not in listed_files]
    extra = [f for f in listed_files if f not in disk_files]
    for f in missing:
        errs.append(
            f"{f} is in apps/web/db/migrations/ but NOT in `MIGRATIONS` — "
            "a fresh database will not have it, and every Postgres integration "
            "test builds its schema from that list"
        )
    for f in extra:
        errs.append(
            f"`MIGRATIONS` includes {f}, which is not on disk (the build will not compile)"
        )
    # Order matters: migrations are applied in list order, and a later one may
    # depend on an earlier one's table.
    common = [f for f in listed_files if f in disk_files]
    if common != sorted(common):
        errs.append(
            "`MIGRATIONS` is not in lexical order — they are applied in LIST order, "
            f"so a dependency can be applied before the table it alters. Got: {common}"
        )
    return errs


def selftest() -> int:
    ok = True

    def case(label: str, passed: bool) -> None:
        nonlocal ok
        print(f"  {'✓' if passed else '✗'} {label}")
        ok &= passed

    base = ["0000_a.sql", "0001_b.sql", "0002_c.sql"]
    case(
        "a complete, ordered list PASSES (the check is not vacuous)",
        not check(base, base),
    )
    case(
        "a migration on disk but MISSING from the list is REFUSED",
        any("NOT in `MIGRATIONS`" in e for e in check(base[:-1], base)),
    )
    case(
        "a list entry with no file is REFUSED",
        any("not on disk" in e for e in check([*base, "0003_ghost.sql"], base)),
    )
    case(
        "an out-of-order list is REFUSED",
        any(
            "not in lexical order" in e
            for e in check(["0001_b.sql", "0000_a.sql"], base[:2])
        ),
    )
    case(
        "a `MIGRATIONS` const the parser cannot find KILLS the run",
        _dies_on_unparseable(),
    )
    print("selftest OK" if ok else "selftest FAILED")
    return 0 if ok else 1


def _dies_on_unparseable() -> bool:
    try:
        listed("fn apply_migrations() { /* no const here */ }")
    except SystemExit as e:
        return e.code != 0
    return False


def main() -> int:
    # Reject an unrecognised option rather than silently running the check.
    # A guard that ignores argv makes its own `--selftest` meaningless — a typo'd
    # flag falls through to the happy path and "passes". Enforced by
    # `scripts/ci/check-guard-selftests.py`, which caught exactly that here.
    argv = sys.argv[1:]
    for arg in argv:
        if arg != "--selftest":
            print(f"usage: {Path(sys.argv[0]).name} [--selftest]", file=sys.stderr)
            return 64

    if "--selftest" in argv:
        return selftest()

    disk_files = on_disk()
    if len(disk_files) < MIN_EXPECTED:
        print(
            f"FAIL — found only {len(disk_files)} migration file(s); expected at least "
            f"{MIN_EXPECTED}. That is a broken glob, not an empty directory.",
            file=sys.stderr,
        )
        return 1

    errs = check(listed(MOD_RS.read_text(encoding="utf-8")), disk_files)
    if errs:
        print(
            f"FAIL — `apply_migrations` disagrees with {MIGRATIONS_DIR.relative_to(ROOT)}:",
            file=sys.stderr,
        )
        for e in errs:
            print(f"  · {e}", file=sys.stderr)
        print(
            "\n  Fix: add the missing include_str!(…) line(s) to `const MIGRATIONS`\n"
            f"  in {MOD_RS.relative_to(ROOT)}, in lexical order.",
            file=sys.stderr,
        )
        return 1

    print(f"OK — all {len(disk_files)} migration(s) are in `MIGRATIONS`, in order")
    return 0


if __name__ == "__main__":
    sys.exit(main())
