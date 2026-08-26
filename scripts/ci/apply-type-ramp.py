#!/usr/bin/env python3
"""
Type-ramp codemod — rewrite every hardcoded `text-[Npx]` to the ADR-074 §2 ramp.

RAMP (§2): 11 / 12 / 13 / 14 / 16 / 20 / 28, base 13px.

WHY A SCRIPT AND NOT AGENTS: 345 sites across 64 files, and the ONLY property that
matters is that the same input px always produces the same output utility. That is a
mapping, not a judgement — and a mapping applied by hand or by N agents drifts.

THE FLOOR IS THE POINT. Nothing below 11px survives: 8px x1, 9px x18, 9.5px x1,
10px x106, 10.5px x4 all become 11px. tokens.css already recorded the ruling when
`.t-eyebrow` moved ("11px — ramp bottom; 10px was off-scale") and then 130 sites kept
sitting under it. 8px and 9px body text is also simply hard to read.

WHICH UTILITY NAME. tokens.css is explicit that --text-ramp-14/20/28 are plain custom
properties and deliberately NOT `--text-*` utility slots, "precisely so they cannot
collide with a stock name" — redefining `text-xl`/`text-base` would silently rescale 35
unreviewed sites. So the three upper steps are written as arbitrary values that read the
custom property, and only 11/12/13/16 have real utilities.

Run with --dry-run first; it prints every file, every replacement, and the totals.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
from collections import Counter

RAMP = [11, 12, 13, 14, 16, 20, 28]
FLOOR = 11

# The utility each ramp step is written as. Steps with a real Tailwind slot use it;
# the three `--text-ramp-*` steps are arbitrary values, because tokens.css keeps them
# out of the utility namespace on purpose (see the module docstring).
UTILITY = {
    11: "text-2xs",
    12: "text-xs",
    13: "text-sm",
    14: "text-ramp-14",
    16: "text-md",
    20: "text-ramp-20",
    28: "text-ramp-28",
}

PATTERN = re.compile(r"text-\[(\d+(?:\.\d+)?)px\]")

# ── GEOMETRY-BOUND LABELS ARE EXEMPT, AND ONLY THOSE ────────────────────────────
#
# A DOM label reflows when it grows. A label laid out against FIXED PIXEL GEOMETRY
# does not — it collides. Chart tick labels are the second kind: their x/y come from
# a scale computed in pixels, so bumping 9px -> 11px (+22%) overlaps adjacent ticks
# instead of pushing them apart. Verified present in BarChart, Lollipop, ModelDonut,
# RequestFlow, LatencyTimeline and TimeRuler.
#
# The test is per-LINE, not per-file, because the same chart file holds both kinds:
# ModelDonut.tsx:147 is an SVG tick (`fill-[var(--ink-3)] text-[9px]`) while :159 is
# a DOM legend row (`flex items-center gap-2 text-[11px]`). A file-level exemption
# would freeze the legend too, and freezing what does not need freezing is how an
# exemption list becomes permanent.
#
# TWO SIGNALS, both structural rather than stylistic:
#   `fill-`    the element is painted as SVG — it IS an <text>/<tspan>. Definitive.
#   `absolute` inside charts/ or signature/ — a label positioned by the same scale
#              that positions the marks it labels (TimeRuler ticks, AgentGraph stage
#              captions). Outside those two directories `absolute` means nothing of
#              the sort, so the directory is part of the test.
GEOMETRY_DIRS = ("packages/ui/src/charts/", "packages/ui/src/signature/")


def geometry_bound(line: str, rel: str) -> bool:
    if "fill-" in line:
        return True
    return "absolute" in line and any(d in rel for d in GEOMETRY_DIRS)


def target(px: float) -> int:
    """Nearest ramp step, with nothing allowed below the floor."""
    if px < FLOOR:
        return FLOOR
    # Ties (e.g. 15px between 14 and 16) resolve DOWN — a step smaller never
    # overflows a container, and overflow is the failure mode of this sweep.
    return min(RAMP, key=lambda r: (abs(r - px), r))


def tracked_files(root: pathlib.Path) -> list[pathlib.Path]:
    out = subprocess.run(
        ["git", "ls-files", "apps/web/**/*.tsx", "packages/ui/**/*.tsx"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [root / p for p in out]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--exempt",
        action="append",
        default=[],
        help="path substring to leave alone (charts/SVG geometry, etc.)",
    )
    args = ap.parse_args()
    root = pathlib.Path(args.root).resolve()

    moves: Counter[tuple[float, int]] = Counter()
    per_file: dict[str, int] = {}
    exempted: Counter[str] = Counter()

    for path in tracked_files(root):
        rel = str(path.relative_to(root))
        text = path.read_text(encoding="utf-8")
        if not PATTERN.search(text):
            continue
        if any(e in rel for e in args.exempt):
            exempted[rel] = len(PATTERN.findall(text))
            continue

        n = 0
        out_lines: list[str] = []
        for line in text.splitlines(keepends=True):
            if not PATTERN.search(line):
                out_lines.append(line)
                continue
            if geometry_bound(line, rel):
                exempted[rel] += len(PATTERN.findall(line))
                out_lines.append(line)
                continue

            def sub(m: re.Match[str]) -> str:
                nonlocal n
                px = float(m.group(1))
                tgt = target(px)
                moves[(px, tgt)] += 1
                n += 1
                return UTILITY[tgt]

            out_lines.append(PATTERN.sub(sub, line))

        new = "".join(out_lines)
        if new != text:
            per_file[rel] = n
            if not args.dry_run:
                path.write_text(new, encoding="utf-8")

    print(f"{'from':>8}  ->  {'to':>4}   count  utility")
    total = resized = grew = 0
    for (px, tgt), c in sorted(moves.items()):
        flag = "SAME" if px == tgt else ("UP" if tgt > px else "DOWN")
        print(f"{px:>7}px  ->  {tgt:>2}px  {c:>6}  {UTILITY[tgt]:<34} {flag}")
        total += c
        if px != tgt:
            resized += c
        if tgt > px:
            grew += c

    print(f"\n  files touched : {len(per_file)}")
    print(f"  sites rewritten: {total}   (resized {resized}, of which {grew} grew)")
    if exempted:
        print(
            f"  EXEMPT (left alone): {sum(exempted.values())} sites in {len(exempted)} files"
        )
        for f, c in sorted(exempted.items(), key=lambda kv: -kv[1]):
            print(f"      {c:>3}  {f}")
    print("\n  top files:")
    for f, c in sorted(per_file.items(), key=lambda kv: -kv[1])[:12]:
        print(f"      {c:>3}  {f}")
    if args.dry_run:
        print("\n  DRY RUN — nothing written.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
