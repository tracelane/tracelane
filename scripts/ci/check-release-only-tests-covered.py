#!/usr/bin/env python3
"""A release-only test must live in a package some CI job runs in release.

WHY (2026-08-13, GWY-41). `release_build_rejects_resource_attribute_tenant_fallback`
is the ONLY test in the tree that proves the release tenant-isolation guarantee:
that a body-supplied `tracelane.tenant_id` with no SPIFFE peer is refused. It is
gated `#[cfg(not(debug_assertions))]`, so the normal `cargo test` can never reach
it — `cfg(test)` implies `debug_assertions`. One CI job existed to run it:

    cargo test -p ingest --release

Then the decoder moved from `crates/ingest/src/otlp_decode.rs` to
`crates/shared/src/otlp/decode.rs` and the test moved with it. The job kept
passing — 168 tests, none of them that one — and its NAME still said "Ingest
release-profile tenant guard". Measured, not assumed: the job's exact command was
re-run after the move and the test name appeared zero times in its output.

**Nothing failed. No guard fired. The green was real and the coverage was gone.**
That is the B-169 shape (a skipped tier reading as a pass) applied to a single
test, and the same class as `never-green-has-no-green-to-lose`: a test that stops
running looks exactly like a test that passes.

WHAT THIS CHECKS
  1. Every `#[cfg(not(debug_assertions))]` + `#[test]` function in the tree.
  2. The cargo package that owns each one (nearest Cargo.toml, its `name`).
  3. That `.github/workflows/ci.yml` contains a `cargo test -p <package> --release`
     step for each such package.

HONEST LIMITS, stated because a guard that implies more than it checks is worse
than none:
  * It proves the package is INVOKED in release. It does NOT prove the test RAN —
    a `--` filter, an `#[ignore]`, or a cfg change could still skip it silently.
    That second half is why the CI step itself greps its own output for the test
    name; this guard cannot see a runtime outcome.
  * It reads ci.yml textually. A release invocation constructed dynamically (a
    matrix, a variable, a shell loop) is invisible to it and will read as
    uncovered — deliberately, because a coverage claim it cannot verify must fail
    closed, not pass.
  * It says nothing about whether the test ASSERTS anything useful.

USAGE
  check-release-only-tests-covered.py             # check
  check-release-only-tests-covered.py --selftest  # prove it BLOCKS each gap
EXIT 0 covered · 1 a release-only test is in an uncovered package · 2 bad usage /
       a source could not be read
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
CI = ROOT / ".github" / "workflows" / "ci.yml"
SEARCH_ROOTS = ("crates", "packages")

# `#[cfg(not(debug_assertions))]`, any number of further attributes, then a test fn.
RELEASE_TEST_RE = re.compile(
    r"#\[cfg\(not\(debug_assertions\)\)\]\s*"
    r"(?:#\[[^\]]*\]\s*)*"
    r"#\[(?:tokio::)?test\]\s*"
    r"(?:async\s+)?fn\s+(\w+)"
)
# `cargo test -p <pkg> ... --release` (flag order is not fixed, so match both ways).
CARGO_RELEASE_RE = re.compile(
    r"cargo\s+test\s+(?:[^\n]*?\s)?-p\s+([A-Za-z0-9_-]+)(?=[^\n]*--release)"
)


def die(msg: str, code: int = 2) -> NoReturn:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(code)


def read(p: Path) -> str:
    # "I cannot see" is never "nothing is wrong" (CLAUDE.md §1.14).
    try:
        return p.read_text(encoding="utf-8")
    except OSError as e:
        die(f"cannot read {p}: {e}")


def owning_package(rs: Path, root: Path) -> str | None:
    """The cargo package name for a .rs file — nearest Cargo.toml walking up.

    Bottom-up, so the crate's own manifest wins over the workspace root's. Both
    paths are resolved first: the selftest passes an absolute temp dir and the
    normal run passes ROOT, and a prefix comparison between a relative and an
    absolute path silently matches nothing.
    """
    root = root.resolve()
    for parent in rs.resolve().parents:
        if not parent.is_relative_to(root):
            break  # never walk above the tree we were handed
        manifest = parent / "Cargo.toml"
        if manifest.is_file():
            m = re.search(r'^\s*name\s*=\s*"([^"]+)"', read(manifest), re.MULTILINE)
            if m:
                return m.group(1)
    return None


def release_only_tests(root: Path) -> dict[str, list[tuple[str, str]]]:
    """package -> [(file, test_name), ...]"""
    out: dict[str, list[tuple[str, str]]] = {}
    for sub in SEARCH_ROOTS:
        base = root / sub
        if not base.is_dir():
            continue
        for rs in base.rglob("*.rs"):
            if "/target/" in str(rs):
                continue
            src = read(rs)
            if "debug_assertions" not in src:  # cheap reject
                continue
            names = RELEASE_TEST_RE.findall(src)
            if not names:
                continue
            pkg = owning_package(rs, root)
            if pkg is None:
                die(f"{rs} has a release-only test but no owning Cargo.toml")
            for n in names:
                out.setdefault(pkg, []).append((str(rs.relative_to(root)), n))
    return out


def release_covered_packages(ci_src: str) -> set[str]:
    return set(CARGO_RELEASE_RE.findall(ci_src))


def check(root: Path = ROOT, ci: Path = CI) -> int:
    found = release_only_tests(root)
    covered = release_covered_packages(read(ci))

    if not found:
        # Not a pass by default: if the pattern ever stops matching (an attribute
        # style change, a refactor), an empty result would silently look clean.
        # Say so loudly and keep exit 0 only because "no release-only tests" is a
        # legitimate state.
        print(
            "release-only tests: NONE found.\n"
            "  If you expected some, the detection pattern may have drifted — this\n"
            "  guard reports an empty set rather than implying coverage."
        )
        return 0

    gaps = {p: t for p, t in found.items() if p not in covered}

    for pkg in sorted(found):
        mark = "ok " if pkg in covered else "GAP"
        for f, n in found[pkg]:
            print(f"  [{mark}] {pkg:<20} {n}  ({f})")

    if gaps:
        print(
            "\nFAIL: a release-only test lives in a package no CI job runs in release.\n",
            file=sys.stderr,
        )
        for pkg, tests in sorted(gaps.items()):
            names = ", ".join(n for _, n in tests)
            print(f"  * package `{pkg}` — {names}", file=sys.stderr)
        print(
            f"\n  Packages ci.yml runs in release: {sorted(covered) or '(none)'}\n"
            f"  Add a `cargo test -p <package> --release` step to {ci.name}.\n"
            "  A release-only test in an uncovered package NEVER RUNS, and nothing\n"
            "  goes red — the suite simply reports one fewer test.",
            file=sys.stderr,
        )
        return 1

    print(
        f"\nrelease-only tests: {sum(len(v) for v in found.values())}, all in packages "
        f"ci.yml runs with --release ({sorted(covered)})."
    )
    print(
        "\nHONEST LIMIT: this proves the PACKAGE is invoked in release. It does not\n"
        "prove the test RAN — a filter or an #[ignore] would still skip it. The CI\n"
        "step greps its own output for the test name; that is the other half."
    )
    return 0


def selftest() -> int:
    """Plant each gap in a COPY of the tree and prove the guard blocks it."""
    cases = [
        ("a release-only test in a package no release job runs", "add_uncovered"),
        ("the owning package dropped from the CI release steps", "drop_coverage"),
    ]
    ok = True
    for label, kind in cases:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            # Copy only what the guard reads: the crate/package trees + ci.yml.
            for sub in SEARCH_ROOTS:
                if (ROOT / sub).is_dir():
                    shutil.copytree(
                        ROOT / sub,
                        tmp / sub,
                        ignore=shutil.ignore_patterns(
                            "target", "node_modules", ".venv"
                        ),
                    )
            (tmp / ".github" / "workflows").mkdir(parents=True)
            ci = tmp / ".github" / "workflows" / "ci.yml"
            shutil.copy(CI, ci)

            if kind == "add_uncovered":
                # `gateway` has no release job; plant one there.
                victim = tmp / "crates" / "gateway" / "src" / "rate_limiter.rs"
                victim.write_text(
                    victim.read_text() + "\n#[cfg(test)]\nmod planted {\n"
                    "    #[cfg(not(debug_assertions))]\n    #[test]\n"
                    "    fn planted_release_only_test() {}\n}\n"
                )
            elif kind == "drop_coverage":
                s = ci.read_text()
                s = s.replace(
                    "cargo test -p tracelane-shared --release",
                    "cargo test -p tracelane-shared",
                )
                ci.write_text(s)

            try:
                rc = check(root=tmp, ci=ci)
            except SystemExit as e:
                rc = int(e.code or 0)
            blocked = rc == 1
            print(f"  [{'BLOCKED' if blocked else 'LEAKED '}] {label}", file=sys.stderr)
            ok &= blocked

    # And it must PASS on the real tree — a guard that fails everything is not a
    # guard that catches everything.
    try:
        clean = check() == 0
    except SystemExit as e:
        clean = int(e.code or 0) == 0
    print(
        f"  [{'PASS   ' if clean else 'FAILED '}] the real tree is covered",
        file=sys.stderr,
    )
    ok &= clean

    print(f"\nselftest: {'OK' if ok else 'BROKEN'}", file=sys.stderr)
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description="release-only tests must be run in release"
    )
    ap.add_argument(
        "--selftest", action="store_true", help="prove the guard blocks each gap"
    )
    args = ap.parse_args()
    return selftest() if args.selftest else check()


if __name__ == "__main__":
    sys.exit(main())
