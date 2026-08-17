#!/usr/bin/env python3
"""Every vulnerability suppression must carry a REVIEW date, and it must not be past.

WHY (founder ruling, 2026-08-09). Suppressing a scanner finding is a real security
decision, and this repo had ~60 of them carrying a reason but **no date of any kind** —
neither when it was accepted nor when it should be looked at again. An undated
suppression is indistinguishable from a permanent one, and the reason it was written
("bump in a future npm sweep", "tracked with the OTel-Rust upgrade") stops being true
long before anyone notices.

This is the migration-drift acknowledgement pattern applied to security
(`scripts/ci/migration-drift-acknowledged.txt`): an override without a record is not a
control (B-167), and a deferral without an expiry quietly becomes forever.

WHAT IT ENFORCES, in both scanner configs:
  * `osv-scanner.toml`  — every `[[IgnoredVulns]]` block
  * `.grype.yaml`       — every entry under `ignore:`
must be preceded by a `# REVIEW: YYYY-MM-DD` comment, and that date must be in the
future. An expired one FAILS: re-verify the reason still holds, then re-date it.

HONEST LIMIT — read before trusting a pass. This proves each suppression is dated and
unexpired. It cannot judge whether the stated REASON is true, whether the advisory is
still unreachable in our code, or whether the package is even still a dependency. It is
a forcing function for a human to look, not a substitute for looking. The 29 dead
wasmtime entries removed on 2026-08-09 — suppressing a crate that had been deleted from
Cargo.lock — are what that limit looks like in practice: they would have passed this
check and protected nothing.
"""

from __future__ import annotations

import argparse
import datetime
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OSV = ROOT / "osv-scanner.toml"
GRYPE = ROOT / ".grype.yaml"

RE_REVIEW = re.compile(r"#\s*REVIEW:\s*(\d{4}-\d{2}-\d{2})")
RE_OSV_ENTRY = re.compile(r"^\s*\[\[IgnoredVulns\]\]")
RE_GRYPE_ENTRY = re.compile(r"^  - (package|vulnerability):")


def today() -> str:
    return datetime.datetime.now(datetime.UTC).date().isoformat()


def scan(text: str, is_entry, label: str, now: str) -> tuple[int, list[str]]:
    """Every entry must be preceded by an unexpired REVIEW date."""
    lines = text.split("\n")
    errors: list[str] = []
    count = 0
    for i, line in enumerate(lines):
        if not is_entry(line):
            continue
        count += 1
        # Walk back over the contiguous comment/blank block above the entry.
        date = None
        j = i - 1
        while j >= 0 and (lines[j].strip().startswith("#") or not lines[j].strip()):
            m = RE_REVIEW.search(lines[j])
            if m:
                date = m.group(1)
                break
            j -= 1
        if date is None:
            errors.append(
                f"{label}:{i + 1}: suppression has NO `# REVIEW: YYYY-MM-DD` above it — "
                f"an undated suppression is a permanent one"
            )
        elif date < now:
            errors.append(
                f"{label}:{i + 1}: REVIEW date {date} has PASSED — re-verify the reason "
                f"still holds, then re-date it (or delete the suppression)"
            )
    return count, errors


def check(
    osv_text: str, grype_text: str, now: str | None = None
) -> tuple[int, list[str]]:
    now = now or today()
    n1, e1 = scan(osv_text, lambda ln: RE_OSV_ENTRY.match(ln), "osv-scanner.toml", now)
    n2, e2 = scan(grype_text, lambda ln: RE_GRYPE_ENTRY.match(ln), ".grype.yaml", now)
    return n1 + n2, e1 + e2


def selftest() -> int:
    ok_osv = '# REVIEW: 2999-01-01\n[[IgnoredVulns]]\nid = "X"\nreason = "r"\n'
    ok_grype = "ignore:\n  # REVIEW: 2999-01-01\n  - package:\n      name: x\n"

    n, e = check(ok_osv, ok_grype)
    assert n == 2 and not e, f"selftest: dated+unexpired must PASS, got {e}"
    print("✓ selftest: dated, unexpired suppressions pass (both files)")

    n, e = check('[[IgnoredVulns]]\nid = "X"\n', ok_grype)
    assert any("NO `# REVIEW" in x for x in e), e
    print("✓ selftest: an UNDATED osv suppression is caught")

    n, e = check(ok_osv, "ignore:\n  - package:\n      name: x\n")
    assert any("NO `# REVIEW" in x for x in e), e
    print("✓ selftest: an UNDATED grype suppression is caught")

    n, e = check('# REVIEW: 2000-01-01\n[[IgnoredVulns]]\nid = "X"\n', ok_grype)
    assert any("has PASSED" in x for x in e), e
    print("✓ selftest: an EXPIRED suppression is caught")

    # A REVIEW date belonging to the PREVIOUS entry must not satisfy the next one —
    # otherwise one date at the top of the file would cover everything below it.
    two = (
        '# REVIEW: 2999-01-01\n[[IgnoredVulns]]\nid = "A"\nreason = "r"\n\n'
        '[[IgnoredVulns]]\nid = "B"\nreason = "r"\n'
    )
    n, e = check(two, ok_grype)
    assert len(e) == 1 and "NO `# REVIEW" in e[0], (
        f"selftest: a date must not carry over past an intervening entry, got {e}"
    )
    print("✓ selftest: one date does not cover a later undated entry")

    # An empty parse would pass everything — fail loud instead.
    n, e = check("", "")
    assert n == 0 and not e
    print("✓ selftest: empty inputs parse to ZERO entries (no false coverage)")

    print("\nselftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="vulnerability-suppression review-date gate"
    )
    ap.add_argument("--selftest", action="store_true", help="prove the gate blocks")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    for p in (OSV, GRYPE):
        if not p.exists():
            print(f"FAIL: {p.name} not found", file=sys.stderr)
            return 1

    n, errors = check(
        OSV.read_text(encoding="utf-8"), GRYPE.read_text(encoding="utf-8")
    )
    for e in errors:
        print(f"FAIL {e}")
    if errors:
        print(
            f"\n{len(errors)} of {n} suppression(s) are undated or expired. Suppressing a "
            "finding is a\nsecurity DECISION: it needs the advisory, the specific reason it "
            "does not apply to us,\nand a date to look again. Without the date it is "
            "permanent by default."
        )
        return 1
    print(f"suppression reviews: {n} suppression(s), all dated and unexpired")
    return 0


if __name__ == "__main__":
    sys.exit(main())
