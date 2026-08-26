#!/usr/bin/env python3
"""`package.json`'s `pnpm.overrides` must equal the `overrides:` block in `pnpm-lock.yaml`.

WHY THIS EXISTS, and why it is a SECURITY control rather than a hygiene one.

Eighteen entries in `pnpm.overrides` are security bumps — `hono`, `postcss`, `qs`,
`undici`, `protobufjs`, `brace-expansion`, `ip-address`, `@opentelemetry/core`,
`@hono/node-server` and more. Each one exists because an advisory fired and the fix was
to force a floor across the whole tree.

**pnpm 10 stopped reading the `pnpm` field in `package.json`.** The installed binary here
is already 11.16.0 and says so on every invocation:

    [WARN] The "pnpm" field in package.json is no longer read by pnpm.
           The following keys were ignored: "pnpm.overrides", "pnpm.auditConfig".

We are safe **by delegation, not by design**: `packageManager: pnpm@9.15.0` makes corepack
hand off to 9.15.0, which does read them — and CI pins `version: 9`. The moment that pin
moves past 9 for any reason, **all eighteen overrides stop applying on the next lockfile
regeneration and NOTHING FAILS.** No red, no alert, no advisory reappears until an audit
months later. A silent regression in the security posture, gated on a version bump someone
makes for an unrelated reason (founder ruling R131).

THE DISCRIMINATOR. `pnpm-lock.yaml` records the overrides it was actually resolved with,
in its own top-level `overrides:` block. That block is written by the pnpm that did the
install. So comparing the two answers the only question that matters: **did the pnpm that
built this lockfile actually read our overrides?** If a future pnpm ignores the field, the
block empties or drifts on the next regeneration and this goes red.

EXACT VALUES, NO FUZZY COMPARISON. A range that "looks equivalent" (`>=1.19.15 <2` vs
`^1.19.15`) is not the same constraint, and a guard that normalises them would accept a
weakened floor. Keys and values are compared as written.

HONEST LIMIT: this proves the lockfile was resolved WITH these overrides. It cannot prove
the resulting versions are free of advisories — that is `osv-scanner` and `pnpm audit`,
which run separately.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def declared_overrides(pkg: Path) -> dict[str, str]:
    """`pnpm.overrides` as written in package.json."""
    data = json.loads(pkg.read_text(encoding="utf-8"))
    return dict(data.get("pnpm", {}).get("overrides", {}))


def _unquote(tok: str) -> str:
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "'\"":
        return tok[1:-1]
    return tok


def lockfile_overrides(lock: Path) -> dict[str, str] | None:
    """The top-level `overrides:` block, or None if the lockfile has no such block.

    None and {} are DIFFERENT and the difference is the whole point: a lockfile built by a
    pnpm that ignored the field has no block at all.
    """
    if not lock.exists():
        return None
    out: dict[str, str] = {}
    seen = False
    for line in lock.read_text(encoding="utf-8").splitlines():
        if re.match(r"^overrides:\s*$", line):
            seen = True
            continue
        if seen:
            if re.match(r"^\S", line):  # dedent ends the block
                break
            if not line.strip():
                continue
            m = re.match(r"^\s+(.*?):\s*(.*)$", line)
            if m:
                out[_unquote(m.group(1))] = _unquote(m.group(2))
    return out if seen else None


def compare(declared: dict[str, str], locked: dict[str, str] | None) -> list[str]:
    if locked is None:
        return [
            (
                "pnpm-lock.yaml has NO `overrides:` block at all, but package.json "
                f"declares {len(declared)}. The pnpm that built this lockfile did NOT "
                "read `pnpm.overrides` — every security floor there is unenforced."
            )
        ]
    problems = []
    for key, want in sorted(declared.items()):
        if key not in locked:
            problems.append(f"MISSING from lockfile: {key!r} (declared {want!r})")
        elif locked[key] != want:
            problems.append(
                f"MISMATCH for {key!r}: package.json {want!r} vs lockfile {locked[key]!r}"
            )
    for key in sorted(set(locked) - set(declared)):
        problems.append(
            f"EXTRA in lockfile: {key!r} = {locked[key]!r} — not declared in package.json"
        )
    return problems


def run(pkg: Path, lock: Path, quiet: bool = False) -> int:
    declared = declared_overrides(pkg)
    locked = lockfile_overrides(lock)
    problems = compare(declared, locked)
    if problems:
        if not quiet:
            print("pnpm overrides are NOT the ones this lockfile was resolved with:")
            for p in problems:
                print(f"  ✗ {p}")
            print(
                "\nThis is a SECURITY control. Re-run `pnpm install` with a pnpm that "
                "reads `pnpm.overrides` (see `packageManager` in package.json), or move "
                "the overrides to the location the current pnpm reads."
            )
        return 1
    if not quiet:
        print(
            f"OK — all {len(declared)} pnpm override(s) match the lockfile's own "
            "`overrides:` block exactly."
        )
    return 0


def selftest() -> int:
    """Plant each failure shape and require a RED; require GREEN on the real files."""
    fails = 0
    pkg, lock = ROOT / "package.json", ROOT / "pnpm-lock.yaml"

    def check(label: str, want: int, got: int) -> None:
        nonlocal fails
        if got == want:
            print(f"  ✓ {label}")
        else:
            print(f"  ✗ {label} — expected exit {want}, got {got}")
            fails += 1

    check("the real tree is GREEN", 0, run(pkg, lock, quiet=True))

    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        data = json.loads(pkg.read_text(encoding="utf-8"))
        overrides = data["pnpm"]["overrides"]
        if not overrides:
            print("  ✗ no overrides declared — this selftest cannot prove anything")
            return 1
        victim = min(overrides)

        # 1. an override DROPPED from package.json -> lockfile has an EXTRA
        dropped = json.loads(json.dumps(data))
        del dropped["pnpm"]["overrides"][victim]
        p1 = d / "dropped.json"
        p1.write_text(json.dumps(dropped), encoding="utf-8")
        check(f"a DROPPED override ({victim}) is caught", 1, run(p1, lock, quiet=True))

        # 2. an override WEAKENED in package.json -> value mismatch
        weakened = json.loads(json.dumps(data))
        weakened["pnpm"]["overrides"][victim] = ">=0.0.1"
        p2 = d / "weakened.json"
        p2.write_text(json.dumps(weakened), encoding="utf-8")
        check("a WEAKENED override value is caught", 1, run(p2, lock, quiet=True))

        # 3. THE ONE THAT MATTERS: a lockfile with NO overrides block at all —
        #    exactly what a pnpm that ignores `pnpm.overrides` produces.
        stripped = []
        skipping = False
        for line in lock.read_text(encoding="utf-8").splitlines():
            if re.match(r"^overrides:\s*$", line):
                skipping = True
                continue
            if skipping:
                if re.match(r"^\S", line):
                    skipping = False
                else:
                    continue
            stripped.append(line)
        p3 = d / "no-overrides.lock"
        p3.write_text("\n".join(stripped), encoding="utf-8")
        check(
            "a lockfile with NO overrides block is caught (the pnpm-10 failure)",
            1,
            run(pkg, p3, quiet=True),
        )

        # 4. a clean copy still passes — the guard is not simply always-red
        p4 = d / "clean.json"
        p4.write_text(pkg.read_text(encoding="utf-8"), encoding="utf-8")
        check("an unmodified copy is still GREEN", 0, run(p4, lock, quiet=True))

    if fails:
        print(f"pnpm-overrides selftest FAILED — {fails} case(s).")
        return 1
    print("pnpm-overrides selftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true", help="prove the guard blocks")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return run(ROOT / "package.json", ROOT / "pnpm-lock.yaml")


if __name__ == "__main__":
    sys.exit(main())
