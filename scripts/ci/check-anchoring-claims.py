#!/usr/bin/env python3
"""Anchoring granularity/timing honesty guard (ADR-062) — sentence-aware.

DO NOT SIMPLIFY THIS TO A LINE GREP. This checker is intentionally sentence/
clause-aware, not a substring match — a naive `grep -v roadmap` leaked
"real-time per-trace anchoring, roadmap" (the exact forbidden Rekor over-claim)
on 2026-07-15. The exemption must key on a deferral qualifying the SAME CLAUSE as
the over-claim. Do not simplify to a line grep; run `--selftest` after any change.
The sentence-parsing looks overcomplicated on purpose — the 12-case battery below
is what stops someone re-introducing the hole in six months.

The Rekor v2 anchor is per Merkle BATCH (every 100 events), best-effort — never
per-event/per-trace/per-call and never real-time/instant/synchronous/guaranteed.
Public copy may only make a finer-granularity/timing claim when a roadmap /
planned / opt-in / not-yet-universal DISCLAIMER qualifies THAT claim in the same
sentence-clause — the ADR-062 phrasing "universal per-run anchoring is on the
roadmap".

Why this is a Python checker and not a `grep` line in pre-public-push.sh:
a line-based scan cannot tell an honest disclaimer from an over-claim, because

  1. the disclaimer routinely lands on the NEXT physical line (prose wraps at
     ~80 cols; SVG splits one sentence across positioned <text> elements), and
  2. a bare word "roadmap" tacked onto an over-claim ("real-time per-trace
     anchoring, roadmap") must STILL block — it is not the phrase "on the
     roadmap" and does not qualify the claim.

So we recover LOGICAL sentences first (strip tags, join wrapped lines), split on
'.'/';', and block a clause that holds an over-claim token with NO deferral
phrase in that SAME clause. A deferral in a different clause/sentence does not
exempt the over-claim clause.

Run `--selftest` to execute the falsification battery (incl. the founder's
"…, roadmap" case, the cross-clause case, and the real wrapped docs lines).

Exit 0 = clean; exit 1 = offender(s) printed as "path: <clause>".
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

OVERCLAIM = re.compile(
    r"per.?(event|trace|call|run|span)[ -]?(anchor|inclusion[ -]proof)"
    r"|(anchor(ed|s)?)[ -](per|every)[ -](event|trace|call|run|span)"
    r"|(real.?time|instant(ly|aneous)?|synchronous(ly)?|guaranteed)[ -]?anchor",
    re.IGNORECASE,
)
DEFERRAL = re.compile(
    r"on the roadmap|(is|are|will be) planned|planned for|opt-in|coming soon"
    r"|not yet (universal|available|live|supported|shipped)",
    re.IGNORECASE,
)

SCAN_ROOTS = ("apps/web", "apps/docs")
SCAN_EXTS = {".mdx", ".md", ".svg", ".tsx", ".ts", ".jsx", ".js", ".astro"}
SKIP_NAMES = {"changelog.mdx"}
SKIP_DIRS = {"node_modules", ".next", "dist", "build", ".turbo", ".claude", "out"}


def clauses(text: str) -> list[str]:
    """Recover logical sentence-clauses: strip HTML/SVG tags, join wrapped
    lines into flowing text, then split on '.'/';'."""
    text = re.sub(r"<[^>]*>", " ", text)   # SVG/HTML tags -> space
    text = re.sub(r"\s+", " ", text)       # collapse newlines + runs of ws
    return re.split(r"[.;]", text)


def offenders_in(text: str) -> list[str]:
    """Return the over-claim clauses that carry no same-clause deferral."""
    hits = []
    for cl in clauses(text):
        if OVERCLAIM.search(cl) and not DEFERRAL.search(cl):
            hits.append(cl.strip())
    return hits


def iter_files(root: Path):
    for base in SCAN_ROOTS:
        d = root / base
        if not d.is_dir():
            continue
        for p in d.rglob("*"):
            if not p.is_file() or p.suffix not in SCAN_EXTS:
                continue
            if p.name in SKIP_NAMES or any(part in SKIP_DIRS for part in p.parts):
                continue
            yield p


def scan(root: Path) -> int:
    found = 0
    for p in iter_files(root):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for clause in offenders_in(text):
            found += 1
            rel = p.relative_to(root)
            snippet = clause if len(clause) <= 160 else clause[:157] + "..."
            print(f"{rel}: {snippet}")
    if found:
        print(
            f"\nBLOCKED: {found} anchoring over-claim clause(s) without a same-clause "
            "deferral (ADR-062). Reword to 'universal per-run anchoring is on the "
            "roadmap' — a bare 'roadmap', or a deferral in a different sentence, does "
            "not exempt the over-claim clause.",
            file=sys.stderr,
        )
    return 1 if found else 0


# --- falsification battery -------------------------------------------------
SELFTEST = [
    # (text, must_block)
    ("real-time per-trace anchoring, roadmap", True),                       # founder's case
    ("we anchor per-trace in real-time; dark mode is on the roadmap", True),  # cross-clause
    ("Tracelane provides real-time anchoring for compliance.", True),
    ("Every root gets guaranteed anchoring in the public log.", True),
    ("We do per-call anchoring of each request.", True),
    ("per-event inclusion proof for every request. See the roadmap.", True),  # deferral in next sentence
    ("universal per-run anchoring is on the roadmap", False),
    ("universal per-run anchoring is on the\nroadmap.", False),             # WRAPPED prose
    ("<desc>universal per-run anchoring\nis on the roadmap. Next.</desc>", False),  # SVG <desc> wrap
    ('<text>universal per-run anchoring + eIDAS QTSP</text>\n'
     '<text>timestamping remain on the roadmap.</text>', False),           # SVG multi-<text>
    ("with universal per-run anchoring and daily anchoring to an eIDAS QTSP "
     "(GlobalSign / ADACOM / Evidency) on the roadmap.", False),
    ("anchored batches carry a resolved inclusion proof, best-effort; "
     "universal per-run anchoring is on the roadmap", False),
]


def selftest() -> int:
    bad = 0
    for text, must_block in SELFTEST:
        blocked = bool(offenders_in(text))
        ok = blocked == must_block
        if not ok:
            bad += 1
        label = "ok " if ok else "FAIL"
        want = "BLOCK" if must_block else "PASS "
        got = "BLOCK" if blocked else "PASS "
        one = text.replace("\n", "\\n")
        print(f"  [{label}] want={want} got={got}  {one[:72]}")
    print(f"\nself-test: {'PASS' if bad == 0 else f'{bad} FAILED'}")
    return 1 if bad else 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    # repo root = two levels up from scripts/ci/
    sys.exit(scan(Path(__file__).resolve().parents[2]))
