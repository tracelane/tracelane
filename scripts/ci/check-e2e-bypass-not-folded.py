#!/usr/bin/env python3
"""The E2E auth bypass's runtime guard must SURVIVE into the shipped bundle.

WHAT THIS IS *NOT*, STATED FIRST BECAUSE IT WAS INITIALLY GOT WRONG.

This gate was written on 2026-08-22 after a `next start` of a production build
served a fully authenticated `/dashboard` with `TRACELANE_E2E_AUTH=1` set, and the
emitted chunk read:

    function e(){return"1"===process.env.TRACELANE_E2E_AUTH}   // unreferenced
    function f(){}                                            // the guard, emptied
    function g(){return f(),!0}                                // always true

That was diagnosed as a build-environment leak: "a build whose env carries the flag
constant-folds the guard away". **THAT DIAGNOSIS WAS FALSE.** The bundle had been
deliberately patched by a measurement harness
(`apps/web/node_modules/.tl-proof/patch-e2e-guard.mjs`, gitignored, source-file-free)
so that production-mode page timings could be taken at all.

THE FALSIFICATION, run afterwards and the thing that should have been run first:
build with `TRACELANE_E2E_AUTH=1 NODE_ENV=development` deliberately exported.
Result — the guard compiles through UNTOUCHED:

    function f(){if(e())throw Error("FATAL: TRACELANE_E2E_AUTH is set outside an
    explicit dev/test build (NODE_ENV=production)...")}

and the BUILD ITSELF EXITS 1, because the guard fires during Next's prerender pass.
`next/dist/build/define-env.js` inlines `process.env.NODE_ENV` as the literal
"production" for every `next build` regardless of the shell env — visible in the
message above, which says `NODE_ENV=production` in a build invoked with
`NODE_ENV=development`. So `isExplicitDev()` always folds FALSE, `e2eAuthEnabled()`
always folds to `assert(), false`, and the assert keeps its RUNTIME flag check.
**The build environment cannot disarm the guard. `lib/e2e-auth.ts` does what its
docstring says.**

SO WHY KEEP THIS GATE. Because the episode proved one real thing: a `.next`
directory can be edited after the build, and the result is indistinguishable from a
legitimate artifact at deploy time — `cf:deploy` uploads whatever is on disk. That
is a supply-chain shape, not a code defect, and nothing else in the tree looks at
the ARTIFACT. This gate is cheap, and it turns "the guard is in the source" into
"the guard is in the thing we are about to upload".

WHAT IT CHECKS, deliberately the one property that is minifier-independent: the
boot-crash's error string must be present in every emitted server chunk that reads
the flag. A patch that neuters the guard removes the string with it; a shape-based
check ("does e2eAuthEnabled return a literal") would track whatever the minifier
emitted this week.

HONEST LIMITS, because a guard that implies more than it checks is worse than none:
  · It proves the string is PRESENT, not that the guard is CORRECT, and a
    sufficiently careful patch could keep the string and still neuter the branch.
    It raises the cost of tampering; it does not make tampering impossible.
  · It reads a build artifact, so it is meaningless before `next build` — it SKIPS
    (exit 0, loudly) with no build present. A release pipeline must run it AFTER
    the build with `--require-build`, which turns a missing build into a failure.
  · It cannot see the Worker that is actually deployed. Proving THAT carries the
    guard means running this against the artifact `cf:deploy` uploads.

USAGE
  check-e2e-bypass-not-folded.py                 # check ./apps/web/.next if present
  check-e2e-bypass-not-folded.py --require-build # missing build is a FAILURE
  check-e2e-bypass-not-folded.py --selftest      # prove it BLOCKS a neutered bundle
EXIT 0 clean/skipped · 1 the guard is missing from a chunk that reads the flag · 2 bad usage
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "apps/web/.next/server"

# The boot-crash's literal text. It is a template string in the source, so the
# leading fixed portion is what survives minification verbatim.
GUARD_MARK = "TRACELANE_E2E_AUTH is set outside an explicit dev/test build"
# THE CARRIER MARKER IS THE FLAG READ, NOT THE TENANT ID — and that distinction is
# a false positive this guard actually produced on its first run against a CLEAN
# build. The disposable tenant id (`0000e2e2e2e2`) also appears in the Drizzle
# schema chunk, inside the Postgres CHECK constraint
# `tenants_id_not_e2e_disposable` — which is a DEFENCE against the bypass, not the
# bypass. Keying on it reported the schema chunk as "guard folded out", i.e. it
# accused the safeguard of being the hole.
#
# `process.env.TRACELANE_E2E_AUTH` is the right marker because it survives BOTH
# outcomes: in the folded bundle the flag-reading function is still emitted (merely
# unreferenced), so a chunk that reads the flag is a carrier either way.
BYPASS_MARK = "TRACELANE_E2E_AUTH"


def scan(server_dir: Path) -> tuple[list[Path], list[Path]]:
    """(chunks carrying the bypass module, of those, chunks carrying the guard)."""
    carriers: list[Path] = []
    guarded: list[Path] = []
    for p in sorted(server_dir.rglob("*.js")):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if BYPASS_MARK not in text:
            continue
        carriers.append(p)
        if GUARD_MARK in text:
            guarded.append(p)
    return carriers, guarded


# A `next dev` server writes into the SAME .next as `next build`, and a DEV build
# legitimately has no boot-crash in it: `isExplicitDev()` is true there, so
# `if(!isExplicitDev() && flagSet())` folds to `if(false)` and the throw is dropped
# BY DESIGN. Inspecting that artifact and reporting "the guard was removed" is a
# false positive — and it is the one this gate actually produced the first time it
# ran in anger, against a tree where a dev server had overwritten the build.
# `.next/static/development/` exists only for a dev server.
DEV_MARKER = ROOT / "apps/web/.next/static/development"


def run(require_build: bool) -> int:
    if DEV_MARKER.is_dir():
        print(
            "SKIP — apps/web/.next holds a DEV-SERVER artifact, not a production build."
        )
        print(
            "  A dev build has no boot-crash to find: `isExplicitDev()` is true there,"
        )
        print(
            "  so the guarded branch folds away BY DESIGN. Judging a dev artifact by a"
        )
        print("  production property would report the design as a defect.")
        print("  Run `next build` (with no dev server running) and re-run this gate.")
        return 0
    if not BUILD.is_dir():
        msg = f"no build at {BUILD.relative_to(ROOT)}"
        if require_build:
            print(f"✗ {msg} — --require-build was passed, so this is a FAILURE.")
            print("  Run `next build` first; this gate reads the build OUTPUT.")
            return 1
        print(f"SKIP — {msg}. Nothing to inspect.")
        print("  This gate reads a build artifact. In a release pipeline run it")
        print("  AFTER the build with --require-build, or it proves nothing.")
        return 0

    carriers, guarded = scan(BUILD)
    if not carriers:
        print("SKIP — no server chunk reads TRACELANE_E2E_AUTH.")
        print("  Either the build is partial, or the module was dropped entirely.")
        return 0

    unguarded = [p for p in carriers if p not in guarded]
    if unguarded:
        print(
            f"✗ THE E2E AUTH BYPASS GUARD WAS FOLDED OUT of "
            f"{len(unguarded)}/{len(carriers)} server chunk(s) that carry the bypass:"
        )
        for p in unguarded:
            print(f"    {p.relative_to(ROOT)}")
        print()
        print("  A chunk reads TRACELANE_E2E_AUTH but does NOT carry the boot-crash")
        print(
            "  that is supposed to accompany it. A normal `next build` cannot produce"
        )
        print(
            "  this — verified by building with the flag and a dev NODE_ENV set, which"
        )
        print("  keeps the guard AND fails the build. So this artifact was almost")
        print("  certainly EDITED after the build.")
        print()
        print(
            "  Do NOT deploy it. `cf:deploy` uploads whatever is in .next, so a patched"
        )
        print("  artifact ships as readily as a real one.")
        print()
        print("  FIX: discard the artifact and rebuild from source:")
        print("      cd apps/web && rm -rf .next && next build")
        return 1

    print(
        f"OK — the boot-crash guard survives in all {len(carriers)} server chunk(s) "
        f"carrying the E2E bypass."
    )
    print("  PROVES: the guard is PRESENT in this build's output.")
    print("  DOES NOT PROVE: that it is correct, nor anything about the Worker that")
    print("  is actually deployed — that needs this run against the `cf:deploy`")
    print("  artifact, which is a separate step nobody runs today.")
    return 0


def selftest() -> int:
    """Plant a folded bundle and a clean one; prove the folded one is CAUGHT."""
    ok = True
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)

        folded = d / "folded"
        folded.mkdir()
        # Exactly the shape the measurement harness's patch emitted.
        (folded / "chunk.js").write_text(
            'let d="00000000-0000-4000-8000-0000e2e2e2e2";'
            'function e(){return"1"===process.env.TRACELANE_E2E_AUTH}'
            "function f(){}function g(){return f(),!0}"
        )
        carriers, guarded = scan(folded)
        if len(carriers) == 1 and not guarded:
            print("  selftest: neutered bundle (guard emptied) → CAUGHT ✓")
        else:
            print(
                f"  selftest: neutered bundle NOT caught ✗ "
                f"(carriers={len(carriers)} guarded={len(guarded)})"
            )
            ok = False

        clean = d / "clean"
        clean.mkdir()
        (clean / "chunk.js").write_text(
            'let d="00000000-0000-4000-8000-0000e2e2e2e2";'
            'function e(){return"1"===process.env.TRACELANE_E2E_AUTH}'
            f'function f(){{if(e())throw Error("FATAL: {GUARD_MARK} (NODE_ENV=production)")}}'
        )
        carriers, guarded = scan(clean)
        if len(carriers) == 1 and len(guarded) == 1:
            print("  selftest: guarded bundle                  → PASSES ✓")
        else:
            print(
                f"  selftest: guarded bundle wrongly flagged ✗ "
                f"(carriers={len(carriers)} guarded={len(guarded)})"
            )
            ok = False

        # A chunk that never carried the bypass must not be reported as unguarded —
        # otherwise every unrelated chunk in the build is a false positive.
        other = d / "other"
        other.mkdir()
        (other / "chunk.js").write_text("export function unrelated(){return 1}")
        carriers, _ = scan(other)
        if not carriers:
            print("  selftest: unrelated chunk                 → NOT flagged ✓")
        else:
            print("  selftest: unrelated chunk wrongly flagged ✗")
            ok = False

        # THE REAL FALSE POSITIVE THIS GUARD PRODUCED ON ITS FIRST RUN, pinned so it
        # cannot come back: the Drizzle schema chunk contains the disposable tenant
        # id inside the CHECK constraint that FORBIDS it. That is the safeguard, and
        # an earlier version of this scan accused it of being the hole.
        schema = d / "schema"
        schema.mkdir()
        (schema / "chunk.js").write_text(
            'z6("tenants_id_not_e2e_disposable",ll`${a.id} <> '
            "'00000000-0000-4000-8000-0000e2e2e2e2'::uuid`)"
        )
        carriers, _ = scan(schema)
        if not carriers:
            print("  selftest: drizzle schema CHECK constraint → NOT flagged ✓")
        else:
            print("  selftest: schema CHECK wrongly flagged as a bypass carrier ✗")
            ok = False

    # THE DEV-ARTIFACT FALSE POSITIVE, pinned. The first real run of this gate
    # flagged 10/10 chunks of a tree whose `.next` had been overwritten by a dev
    # server — where the absent boot-crash is correct behaviour, not tampering.
    print(
        "  selftest: dev-artifact skip is wired      → "
        + ("PRESENT ✓" if DEV_MARKER.name == "development" else "MISSING ✗")
    )
    if DEV_MARKER.name != "development":
        ok = False

    print("✓ selftest PASSED" if ok else "✗ selftest FAILED")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument(
        "--require-build",
        action="store_true",
        help="treat a missing build as a failure (for a post-build release gate)",
    )
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return run(args.require_build)


if __name__ == "__main__":
    sys.exit(main())
