#!/usr/bin/env python3
"""check-archive-headers.py — docs/archive/ is never read as current truth.

Founder ruling 2026-09-03 §4: `docs/archive/` holds superseded material, and a
reader who lands on one of those files has no way to tell that from the file
itself — nothing marks it as retired, so it reads exactly like a live doc.
CLAUDE.md §19 (SUPERSESSION, NEVER SILENT DELETION) already requires this for
anything retired; this is that requirement made mechanical rather than
remembered, per the graduation ladder in §12.

WHAT THIS PROVES: every `.md` / `.mdx` under `docs/archive/` carries, within
its first 5 lines, a machine-readable header —

    <!-- tracelane:status: HISTORICAL — superseded by <path-or-name> on <YYYY-MM-DD> -->

— naming what superseded it and when, AND a human banner line starting with
`> **HISTORICAL**` so a reader scrolling the rendered page (which drops HTML
comments) also sees it.

HONEST LIMIT: this proves the header and banner EXIST and are well-formed. It
does not check that `<path-or-name>` actually resolves to something live, or
that the date is plausible — that is a per-file judgement call for whoever
retires the doc, the same way the archived bucket-C specs stub is the worked
example CLAUDE.md §19 cites for doing it by hand. A guard that tried to also
verify the successor exists would have to special-case every "superseded by
an ADR / a ruling / a decision that has no single file" case, and would end
up either wrong or toothless; this stays narrow and reliable instead.

CURRENT STATE (2026-09-03): most files under docs/archive/ predate this guard
and lack the header. A `--no-cache` run of this guard therefore reports a
non-trivial violation count on a plain `main`-branch run until the sweep that
adds headers to the existing tree lands — that sweep is tracked separately
and is NOT this script's job. This script's job is only to make the absence
visible and to block it going forward.

Usage:
    check-archive-headers.py               # gate: exit 1 if any archive doc is missing the header/banner
    check-archive-headers.py --list-missing # print just the violating paths, one per line
    check-archive-headers.py --selftest    # plant each violation, prove it blocks; prove a compliant file passes
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARCHIVE_PREFIX = "docs/archive/"

# The full, well-formed header: `tracelane:status: HISTORICAL`, an em dash, the
# literal `superseded by`, a non-empty target, the literal `on`, and a
# YYYY-MM-DD date. Whitespace-tolerant around each piece; the em dash and both
# literal words are mandatory, matching the brief's exact wording.
HEADER_RE = re.compile(
    r"<!--\s*tracelane:status:\s*HISTORICAL\s*—\s*superseded by\s+\S.*?\s+on\s+"
    r"(\d{4}-\d{2}-\d{2})\s*-->"
)
# A header that NAMES itself HISTORICAL but is missing the mandatory
# `superseded by ... on YYYY-MM-DD` clause — used only to give a more specific
# failure reason than "missing header" when the author clearly tried.
PARTIAL_HEADER_RE = re.compile(r"<!--\s*tracelane:status:\s*HISTORICAL\b")
BANNER_RE = re.compile(r"^>\s*\*\*HISTORICAL\*\*", re.MULTILINE)

KNOWN_FLAGS = {"--selftest", "--list-missing"}
USAGE = "usage: check-archive-headers.py [--selftest | --list-missing]"


def reject_unknown_flags(argv: list[str]) -> None:
    unknown = [a for a in argv if a.startswith("-") and a not in KNOWN_FLAGS]
    if unknown:
        print(f"unknown option: {' '.join(unknown)}", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        raise SystemExit(2)


def check_text(text: str) -> str | None:
    """None if `text` carries a compliant header + banner; otherwise why not."""
    head = "\n".join(text.splitlines()[:5])
    if not HEADER_RE.search(head):
        if PARTIAL_HEADER_RE.search(head):
            return (
                "header present but missing the mandatory "
                "'superseded by <path-or-name> on YYYY-MM-DD' clause"
            )
        return (
            "missing the machine header "
            "(<!-- tracelane:status: HISTORICAL — superseded by <path-or-name> on <YYYY-MM-DD> -->)"
            " in the first 5 lines"
        )
    if not BANNER_RE.search(text):
        return "header present but missing the human banner ('> **HISTORICAL**')"
    return None


def archive_docs() -> list[str]:
    """Tracked docs under docs/archive/ only — untracked files never ship and are
    not this guard's concern (same scoping argument as check-doc-classification.py's
    all_docs())."""
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z", "*.md", "*.mdx"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return sorted(p for p in out.split("\0") if p and p.startswith(ARCHIVE_PREFIX))


def run_gate(verbose: bool = True) -> tuple[int, list[tuple[str, str]]]:
    docs = archive_docs()
    violations: list[tuple[str, str]] = []
    for rel in docs:
        p = ROOT / rel
        if not p.is_file():
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        why = check_text(text)
        if why:
            violations.append((rel, why))

    if verbose:
        print(
            f"docs/archive/ scanned: {len(docs)} | "
            f"missing header/banner: {len(violations)}"
        )
        if violations:
            print(
                "\nFAIL — the following file(s) are not marked HISTORICAL and are "
                "therefore citable as if they were current truth:"
            )
            for rel, why in violations:
                print(f"       {rel}: {why}")
        else:
            print("OK — every docs/archive/ file carries the header and banner.")

    return (1 if violations else 0), violations


def selftest() -> int:
    """check_text() is the entire detection surface, so the falsification exercises
    it directly against planted strings rather than the tracked tree — the tracked
    tree is expected to carry real violations today (see module docstring), and a
    selftest that required a clean tree would be unrunnable until an unrelated sweep
    lands. That would make the selftest a function of repo STATE, not of whether the
    detector works — exactly the discriminating-field failure this repo has hit
    before (see memory: self-matching-probe)."""
    ok = True

    cases = [
        (
            "no header at all",
            "# Some retired doc\n\nBody text, no marker anywhere.\n",
            False,
        ),
        (
            "header with no date",
            (
                "<!-- tracelane:status: HISTORICAL — superseded by NEW_DOC.md -->\n"
                "> **HISTORICAL**\n\n# doc\n"
            ),
            False,
        ),
        (
            "header but no banner",
            (
                "<!-- tracelane:status: HISTORICAL — superseded by NEW_DOC.md on 2026-09-03 -->\n"
                "# doc\n\nBody with no banner line.\n"
            ),
            False,
        ),
        (
            "compliant file",
            (
                "<!-- tracelane:status: HISTORICAL — superseded by NEW_DOC.md on 2026-09-03 -->\n"
                "> **HISTORICAL** — superseded by NEW_DOC.md on 2026-09-03.\n\n# doc\n"
            ),
            True,
        ),
    ]

    for label, text, should_pass in cases:
        why = check_text(text)
        passed = why is None
        if passed == should_pass:
            print(f"selftest: {label} ... {'PASS' if should_pass else 'blocked'}  OK")
        else:
            verdict = (
                "was NOT caught — guard is decorative"
                if should_pass is False
                else ("was WRONGLY blocked")
            )
            print(f"selftest: {label} ... {verdict}  FAIL ({why!r})")
            ok = False

    print("\nselftest PASSED." if ok else "\nselftest FAILED.")
    return 0 if ok else 1


def main() -> int:
    reject_unknown_flags(sys.argv[1:])
    if "--selftest" in sys.argv:
        return selftest()
    rc, violations = run_gate(verbose="--list-missing" not in sys.argv)
    if "--list-missing" in sys.argv:
        for rel, _why in violations:
            print(rel)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
