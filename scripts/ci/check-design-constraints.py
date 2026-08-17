#!/usr/bin/env python3
"""ADR-074 §9's mechanical bans, as a gate instead of a paragraph.

WHY THIS EXISTS. §9 lists seven binding engineering constraints. The 2026-08-15
enumeration measured how many were enforced by anything: **zero**. All seven were prose.
And the one that is trivially greppable — *no blur / backdrop-filter* — turned out to be
**already violated in shipped code, 15 times across 8 files**, under a carve-out written
for the ADR it superseded. A constraint that is stated, believed, and false is worse than
one nobody claimed: it gets cited in review as though it held.

Three of the seven are a CONSTRUCTION you can match, so those three are gated here:

  1. no blur / backdrop-filter
  2. no mesh gradients
  3. no animated gradients (a gradient under a CSS transition/animation)

The other four are NOT gated and this script does not pretend otherwise:
  · no per-row shadows        — needs to know what a "row" is
  · no new JS dependencies    — a lockfile diff question, not a source-grep one
  · <=10KB CSS delta          — needs two builds to compare
  · 2,000-span @60fps         — needs a browser
Listing them here, unenforced, is deliberate: the gap is the finding.

SCOPE. Shipping surfaces only — `apps/web` and `packages/ui`. `docs/design/*.html` are
mockups of superseded systems and are denied from the export; gating them would be
enforcing a rule on artifacts nobody ships.

USAGE
  check-design-constraints.py            # scan
  check-design-constraints.py --selftest # prove each rule BLOCKS and that clean passes
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCAN_ROOTS = ("apps/web", "packages/ui")
SKIP_DIRS = {"node_modules", ".next", ".open-next", "dist", "e2e"}
SUFFIXES = {".tsx", ".ts", ".css", ".jsx", ".js"}

# Each rule: (id, compiled pattern, human explanation).
RULES: list[tuple[str, re.Pattern[str], str]] = [
    (
        "no-blur",
        re.compile(r"\bbackdrop-blur(?:-\w+)?\b|backdrop-filter\s*:", re.IGNORECASE),
        (
            "ADR-074 §5/§9 ban blur outright. A scrim dims with `bg-black/40`; it does "
            "not need a filter, and blur costs a compositor pass on every frame it covers."
        ),
    ),
    (
        "no-mesh-gradient",
        re.compile(r"\bmesh-gradient\b|conic-gradient\s*\(.*?,.*?,.*?,", re.IGNORECASE),
        (
            "ADR-074 §5 permits exactly three gradient forms (G1 container tint, G2 "
            "media well, G3 data fill). A mesh is none of them."
        ),
    ),
    (
        "no-animated-gradient",
        re.compile(
            r"@keyframes[^{]*\{[^}]*(?:linear|radial|conic)-gradient",
            re.IGNORECASE | re.DOTALL,
        ),
        (
            "ADR-074 §5: gradients are STATIC. An animated one repaints a large area "
            "continuously and is the cheapest way to make a data surface feel cheap."
        ),
    ),
]

# A line may opt out with a written reason. The reason is the point — an unexplained
# suppression is the carve-out that let blur survive its own ban for a year.
OPTOUT = re.compile(r"design-constraint-ok:\s*\S+")


def files() -> list[Path]:
    out: list[Path] = []
    for root in SCAN_ROOTS:
        base = ROOT / root
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if not p.is_file() or p.suffix not in SUFFIXES:
                continue
            if any(part in SKIP_DIRS for part in p.parts):
                continue
            if p.name.endswith((".test.ts", ".test.tsx")):
                continue
            out.append(p)
    return out


def strip_comments(src: str) -> str:
    """Blank out comments, preserving line numbers.

    Without this the guard flags the very comments that DOCUMENT the ban — TopBar.tsx
    saying "NO BLUR. The old bar used backdrop-blur-xl" was reported as a violation on
    its first run. A guard that cannot tell a rule from a mention of a rule is the §19
    word-vs-construction failure, and here it fires in the ANNOYING direction (false
    positives), which is the direction that gets a guard disabled.
    """
    out = re.sub(
        r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", " ", m.group(0)), src, flags=re.DOTALL
    )
    out = re.sub(r"(^|[^:\"'`])//[^\n]*", lambda m: m.group(1), out)
    return out


def scan_text(rel: str, text: str) -> list[tuple[str, str, int, str]]:
    hits: list[tuple[str, str, int, str]] = []
    raw_lines = text.splitlines()
    text = strip_comments(text)
    for rule_id, pat, _why in RULES:
        for m in pat.finditer(text):
            ln = text.count("\n", 0, m.start()) + 1
            line = raw_lines[ln - 1] if 0 < ln <= len(raw_lines) else ""
            if OPTOUT.search(line):
                continue
            hits.append((rule_id, rel, ln, line.strip()[:110]))
    return hits


def run() -> int:
    hits: list[tuple[str, str, int, str]] = []
    scanned = 0
    for p in files():
        scanned += 1
        hits.extend(
            scan_text(
                str(p.relative_to(ROOT)),
                p.read_text(encoding="utf-8", errors="replace"),
            )
        )

    if hits:
        why = {r[0]: r[2] for r in RULES}
        print(f"✗ {len(hits)} ADR-074 §9 violation(s):")
        for rule_id, rel, ln, line in hits:
            print(f"    [{rule_id}] {rel}:{ln}: {line}")
        print()
        for rid in sorted({h[0] for h in hits}):
            print(f"  {rid}: {why[rid]}")
        print()
        print("  Opt out one line with a REASON: `design-constraint-ok: <why>`.")
        return 1

    print(
        f"OK — no §9 mechanical violations ({scanned} files in {', '.join(SCAN_ROOTS)})."
    )
    print("  NOT gated here, and deliberately named: per-row shadows · new JS deps ·")
    print("  the 10KB CSS delta · the 2,000-span 60fps budget. Those need a diff, a")
    print(
        "  lockfile or a browser — a grep cannot see them, and saying so is the point."
    )
    return 0


def selftest() -> int:
    ok = True
    cases = [
        ("no-blur", '<div className="fixed inset-0 bg-black/60 backdrop-blur-sm" />'),
        ("no-blur", ".x { backdrop-filter: blur(4px); }"),
        ("no-mesh-gradient", ".x { background: conic-gradient(#a, #b, #c, #d); }"),
        (
            "no-animated-gradient",
            "@keyframes shift { 0% { background: linear-gradient(#a,#b); } }",
        ),
    ]
    for rule_id, src in cases:
        got = scan_text("fake.tsx", src)
        if any(h[0] == rule_id for h in got):
            print(f"  selftest: {rule_id:<22} → CAUGHT ✓")
        else:
            print(f"  selftest: {rule_id:<22} NOT caught ✗  ({src[:50]})")
            ok = False

    clean = '<div className="fixed inset-0 bg-black/60" />\n.y { background: linear-gradient(160deg,#f3f6fa,#fff); }'
    if not scan_text("fake.tsx", clean):
        print("  selftest: clean source (static G1 gradient) → PASSES ✓")
    else:
        print("  selftest: clean source wrongly flagged ✗")
        ok = False

    # REGRESSION: a comment DOCUMENTING the ban must not be flagged. This fired on the
    # guard's first real run against TopBar.tsx's own "NO BLUR" note.
    doc_comment = "// NO BLUR. The old bar used `backdrop-blur-xl`; ADR-074 bans it.\nconst x = 1;"
    if not scan_text("fake.tsx", doc_comment):
        print("  selftest: comment mentioning blur    → NOT flagged ✓")
    else:
        print("  selftest: a comment about the ban was flagged as a violation ✗")
        ok = False

    opted = '<div className="backdrop-blur-sm" /> {/* design-constraint-ok: B-999 legacy */}'
    if not scan_text("fake.tsx", opted):
        print("  selftest: opt-out WITH a reason honoured → PASSES ✓")
    else:
        print("  selftest: opt-out ignored ✗")
        ok = False

    if not files():
        print("  selftest: scan set is EMPTY — the guard would pass vacuously ✗")
        ok = False
    else:
        print(f"  selftest: scan set is {len(files())} file(s) → PROBE ALIVE ✓")

    print("✓ selftest PASSED" if ok else "✗ selftest FAILED")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    return selftest() if args.selftest else run()


if __name__ == "__main__":
    sys.exit(main())
