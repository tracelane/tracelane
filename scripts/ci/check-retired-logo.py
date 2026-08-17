#!/usr/bin/env python3
"""The retired Chisel mark must not come back. ADR-074 §8: "do not resurrect it."

WHY THIS EXISTS, and it is not hypothetical. On 2026-08-15 the brand workstream
generated 39 assets of the new geometric **T** monogram, verified every one by decoding
it, wired the favicons and PWA icons into `layout.tsx`/`manifest.ts`, and reported the
brand replacement as done.

**The logo COMPONENTS were never touched.** The Chisel bracket-recorder — two brackets,
a tick, a bullseye, `viewBox="0 0 76 76"` — was still rendering in FIVE places the next
morning, in production, at the top of every page:

    packages/ui/src/primitives/Logo.tsx      the app header, every screen
    apps/site/src/components/Header.astro    the marketing header
    apps/site/src/components/Footer.astro    the marketing footer
    apps/site/public/favicon.svg             the marketing tab icon
    apps/web/app/global-error.tsx            the root error boundary

The founder found it by looking at the screen. Nothing else could have: the assets were
correct, the references resolved, every test passed, and the icons decoded to a real
mark. **Generating a file is not the same as rendering it**, and no check in the repo
knew the difference.

THE DISCRIMINATOR is the mark's own path data, not the word "logo" or "chisel" — the
geometry is unmistakable and cannot be renamed away. `M30 14 L14 14` is the first
bracket; `viewBox="0 0 76 76"` is its canvas. Either is conclusive.

SCOPE: shipping surfaces only. `docs/archive/` and `docs/design/` keep the historical
record on purpose (§19: supersession, never silent deletion) — a guard that forced those
to be scrubbed would be destroying the evidence of what the brand used to be.

USAGE
  check-retired-logo.py            # scan
  check-retired-logo.py --selftest # prove it CATCHES the mark and ADMITS the new one
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# The Chisel's own geometry. Two independent signatures — either is conclusive.
RETIRED = [
    (re.compile(r"M\s*30\s+14\s+L\s*14\s+14"), "the Chisel's first bracket path"),
    (re.compile(r'viewBox\s*=\s*["\']0 0 76 76["\']'), "the Chisel's 76x76 canvas"),
]

# Historical record, deliberately preserved (CLAUDE.md §19).
EXEMPT_PREFIXES = (
    "docs/archive/",
    "docs/design/",
    "scripts/ci/check-retired-logo.py",
    "packages/ui/src/primitives/Logo.tsx",  # its docstring names what it replaced
)

SUFFIXES = {".tsx", ".ts", ".jsx", ".js", ".astro", ".svg", ".html", ".css", ".mdx"}


def tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [
        r
        for r in out.split("\0")
        if r
        and Path(r).suffix.lower() in SUFFIXES
        and not any(r.startswith(p) for p in EXEMPT_PREFIXES)
    ]


def scan_text(rel: str, text: str) -> list[tuple[str, str, int]]:
    hits = []
    for pat, what in RETIRED:
        m = pat.search(text)
        if m:
            hits.append((rel, what, text.count("\n", 0, m.start()) + 1))
    return hits


def run() -> int:
    hits, n = [], 0
    for rel in tracked():
        p = ROOT / rel
        try:
            hits.extend(scan_text(rel, p.read_text(encoding="utf-8", errors="replace")))
        except OSError:
            continue
        n += 1
    if hits:
        print(
            "✗ The RETIRED Chisel mark is still rendering. ADR-074 §8 replaced it with"
        )
        print(
            "  the geometric T monogram; generating the assets is not wiring them in."
        )
        for rel, what, ln in hits:
            print(f"    {rel}:{ln}  — {what}")
        print()
        print("  Fix: use `Logo` from @tracelanedev/ui, or copy the five paths from")
        print("  scripts/brand/build-brand-assets.py (MARK). Do not hand-draw it.")
        return 1
    print(f"OK — the retired Chisel mark appears in no shipping surface ({n} files).")
    return 0


def selftest() -> int:
    ok = True
    for src, label in [
        (
            '<svg viewBox="0 0 76 76"><path d="M30 14 L14 14 L14 62 Z"/></svg>',
            "both signatures",
        ),
        ('<path d="M30 14 L14 14 L14 62 L30 62 Z" fill="currentColor"/>', "path only"),
        ('<svg viewBox="0 0 76 76" aria-hidden="true"></svg>', "canvas only"),
    ]:
        if scan_text("fake.tsx", src):
            print(f"  selftest: chisel ({label:<16}) → CAUGHT ✓")
        else:
            print(f"  selftest: chisel ({label}) NOT caught ✗")
            ok = False

    new = '<svg viewBox="0 0 100 100"><path d="M 2,2 L 96,2 L 84,14 L 2,14 Z"/></svg>'
    if not scan_text("fake.tsx", new):
        print("  selftest: the NEW T monogram              → PASSES ✓")
    else:
        print("  selftest: the new monogram was flagged ✗")
        ok = False

    if not tracked():
        print("  selftest: scan set EMPTY — the guard would pass vacuously ✗")
        ok = False
    else:
        print(f"  selftest: scan set is {len(tracked())} file(s)   → PROBE ALIVE ✓")

    print("✓ selftest PASSED" if ok else "✗ selftest FAILED")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    return selftest() if a.selftest else run()


if __name__ == "__main__":
    sys.exit(main())
