#!/usr/bin/env python3
"""Keep the two pre-public-push guards from drifting apart. (B-189)

There are TWO guards with the same name and different bodies:

  scripts/pre-public-push.sh          — the one people open and edit. It never
                                        enforced anything: it exits on the
                                        private remote, and the private remote
                                        is the only remote there is.
  scripts/export/pre-public-push.sh   — the one that actually gates the public
                                        surface, run by build-public-export.sh
                                        step 8 against the built export tree.

They differ by ~510 lines, so "I added the banned pattern" is ambiguous until
you say WHICH file. That ambiguity shipped a hole: `sub-10ms` was added to the
root guard, and a planted `sub-10ms` still passed the export.

This checks the one thing that must hold in both: every phrase we have decided
is banned appears in BOTH guards' pattern text. It is deliberately dumb — a
substring check over the source — because the two implementations are too
different for anything structural to be meaningful.

    python3 scripts/ci/check-guard-parity.py            # check
    python3 scripts/ci/check-guard-parity.py --selftest # falsify (both halves)
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT_GUARD = Path("scripts/pre-public-push.sh")
EXPORT_GUARD = Path("scripts/export/pre-public-push.sh")

# Every flag this script implements. A guard that silently IGNORES an unknown flag
# runs the ordinary check and exits 0 — so `--selftesst` (typo) reports PASS while no
# selftest ran, and the `--selftest` result proves nothing. Enforced by
# scripts/ci/check-guard-selftests.py.
KNOWN_FLAGS = {"--selftest"}
USAGE = "usage: check-guard-parity.py [--selftest]"


def reject_unknown_flags(argv: list[str]) -> None:
    """Exit 2 on any option this script does not implement."""
    unknown = [a for a in argv if a.startswith("-") and a not in KNOWN_FLAGS]
    if unknown:
        print(f"unknown option: {' '.join(unknown)}", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        raise SystemExit(2)


# Phrases banned from the public surface. Adding one here without adding it to
# both guards fails this check — which is the point.
#
# NOT banned, deliberately: "sub-15ms". bench/gateway/RESULTS.md measures worst
# -of-10 p99 at 11.897 ms, so sub-15ms is supported by evidence. We ban claims
# the code does not support, not claims that are merely flattering.
MUST_BE_BANNED_IN_BOTH = [
    "sub-50ms",
    "sub-millisecond",
    "sub-10ms",  # DISPROVEN by our own measurement (11.897 ms worst-of-10)
    "5K RPS",
]


def read(p: Path) -> str:
    if not p.is_file():
        print(f"❌ missing guard: {p}")
        sys.exit(1)
    return p.read_text(encoding="utf-8")


def check(root_src: str, export_src: str) -> list[str]:
    """Return a list of human-readable failures (empty == parity holds)."""
    failures = []
    for phrase in MUST_BE_BANNED_IN_BOTH:
        in_root = phrase in root_src
        in_export = phrase in export_src
        if in_root and in_export:
            continue
        missing = ROOT_GUARD if not in_root else EXPORT_GUARD
        present = EXPORT_GUARD if not in_root else ROOT_GUARD
        failures.append(
            f"banned phrase {phrase!r} is in {present} but NOT in {missing}"
        )
    return failures


def selftest() -> int:
    fails = 0

    def case(name: str, root_src: str, export_src: str, expect_ok: bool) -> None:
        nonlocal fails
        got = check(root_src, export_src)
        ok = not got
        if ok == expect_ok:
            print(f"  [PASS] {name}")
        else:
            print(
                f"  [FAIL] {name} — expected {'no' if expect_ok else 'some'} "
                f"failures, got {got}"
            )
            fails += 1

    both = " ".join(MUST_BE_BANNED_IN_BOTH)

    # HALF ONE: it must PASS when the guards agree. A checker that only ever
    # fails is the same species of useless as a guard that only ever passes —
    # this session shipped one of each.
    case("in-sync guards PASS", both, both, True)

    # HALF TWO: it must FAIL for each phrase missing from either side. This is
    # the exact shape: patched one file, not the other.
    for phrase in MUST_BE_BANNED_IN_BOTH:
        thinned = " ".join(p for p in MUST_BE_BANNED_IN_BOTH if p != phrase)
        case(f"missing {phrase!r} from EXPORT guard blocks", both, thinned, False)
        case(f"missing {phrase!r} from ROOT guard blocks", thinned, both, False)

    if fails:
        print(f"\nSELFTEST FAILED — {fails} case(s).")
        return 1
    n = 1 + 2 * len(MUST_BE_BANNED_IN_BOTH)
    print(f"\nSelftest passed — {n} cases (both halves: agrees=PASS, drift=BLOCK).")
    return 0


def main() -> int:
    reject_unknown_flags(sys.argv[1:])
    if "--selftest" in sys.argv:
        return selftest()

    # The EXPORT guard's banned phrases moved OUT of the script and into
    # docs/reference/NEVER_SAY_AGAIN.md (2026-08-10), so that adding a strike is a
    # one-line data edit rather than a script change — the reason 60 strikes had only
    # produced 9 checks. The guard's INTENT is unchanged ("the export gate covers
    # these phrases"); only where they live changed, so the effective coverage is the
    # script PLUS the list it reads. Checking the script alone would report a drift
    # that does not exist — a right check pointed at the wrong file.
    nsa_list = Path("docs/reference/NEVER_SAY_AGAIN.md")
    export_effective = read(EXPORT_GUARD)
    if nsa_list.exists():
        export_effective += "\n" + nsa_list.read_text(encoding="utf-8")
    else:
        print(f"❌ guard parity: {nsa_list} is MISSING — the export guard's phrase")
        print("   list is gone, so parity cannot be established. Fail closed.")
        return 1

    failures = check(read(ROOT_GUARD), export_effective)
    if failures:
        print("❌ pre-public-push guard parity BROKEN:")
        for f in failures:
            print(f"   {f}")
        print(
            "\n→ The two guards are separate implementations. The EXPORT one is\n"
            "  what gates the public surface; the root one is not wired to\n"
            "  anything. Add the pattern to BOTH."
        )
        return 1

    print(
        f"✅ guard parity: {len(MUST_BE_BANNED_IN_BOTH)} banned phrase(s) present "
        f"in both pre-public-push guards"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
