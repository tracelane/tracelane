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
    if "--selftest" in sys.argv:
        return selftest()

    failures = check(read(ROOT_GUARD), read(EXPORT_GUARD))
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
