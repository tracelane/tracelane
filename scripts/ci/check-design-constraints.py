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
    (
        "no-outline-suppressor",
        # Any variant of it: bare, `focus:`, `focus-visible:`, `hover:` …
        re.compile(r"\b(?:[a-z-]+:)?outline-none\b"),
        (
            "`outline-none` compiles to `--tw-outline-style: none`, and that custom "
            "property is what `outline-2` READS: `focus-visible:outline-2` emits "
            "`outline-style: var(--tw-outline-style); outline-width: 2px`. So an element "
            "carrying both paints a 2px ring with style `none` — INVISIBLE — while "
            "looking correct in the diff and passing any review that greps for the ring "
            "class. That was 22 controls on 2026-08-17, out of 37 suppressors total, and "
            "an unreachable focus indicator is a WCAG 2.4.7 failure. Nothing needs the "
            "suppressor now: the @layer base rule in tokens.css paints one ring for "
            "a/button/input/select/textarea/summary/[role=button]/[tabindex], and browsers "
            "only show their own default on :focus-visible anyway. DELETE it rather than "
            "pairing it with a ring."
        ),
    ),
    (
        "no-hardcoded-colour",
        # A literal hex, OR a Tailwind arbitrary-value colour (`bg-[#0d0d0d]`,
        # `fill-[#fff]`). NOT `fill-[var(--ink)]` — a var reference IS the token.
        re.compile(r"#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?\b(?![0-9a-fA-F])"),
        (
            "`apps/web/CLAUDE.md`: DESIGN TOKENS ONLY — NEVER HARDCODE HEX. "
            "packages/ui/src/styles/tokens.css is the ONE place a colour value may be "
            "written; everywhere else names a role (`bg-surface`, `text-ink-2`, "
            "`fill-chart-primary`) so a palette swap is one file, not a tree-wide grep. "
            "THIS RULE WAS PROSE UNTIL 2026-08-22, and prose let two real values "
            "survive TWO palette swaps: `apps/web/app/manifest.ts` shipped the PWA "
            "theme colour as #f4f6fa — literally the pale-blue cast the P0 brief opens "
            "by removing — and `global-error.tsx` carried a whole zinc ramp. A "
            "genuine exception (global-error.tsx replaces the document, so "
            "`var(--ink)` resolves to NOTHING exactly when it is needed) opts out on "
            "the line with `design-constraint-ok: <reason>`, which is the difference "
            "between a considered literal and a forgotten one."
        ),
    ),
    (
        "no-stock-palette",
        # Tailwind's own colour ramps, which bypass the token system entirely and are
        # invisible to a hex grep. Word-boundaried so `bg-red-soft` (not a thing) and
        # prose like "the red slice" do not match.
        re.compile(
            r"\b(?:bg|text|border|fill|stroke|ring|from|via|to|decoration|outline|divide|shadow|accent|caret|placeholder)"
            r"-(?:slate|gray|grey|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)"
            r"-(?:50|100|200|300|400|500|600|700|800|900|950)\b"
        ),
        (
            "A stock Tailwind palette utility bypasses the token system: it cannot "
            "follow a theme swap, it has no dark-mode counterpart, and it is invisible "
            "to a hex grep — `bg-blue-500` contains no `#`. The P0 brief's visual QA "
            "checklist bans blue, purple/violet, teal, olive and lava outright, and "
            "before this rule NOTHING enforced that: the guard's own output listed "
            "four things it did not gate, and hue was not even among them. Name the "
            "role instead (`bg-surface-2`, `text-danger-ink`, `fill-chart-secondary`)."
        ),
    ),
    (
        "type-ramp",
        # Deliberately matches the arbitrary-value FORM, not a list of bad sizes: the
        # failure is bypassing the scale at all, and a size that happens to land on a
        # ramp step today drifts off it the next time someone nudges it.
        re.compile(r"\btext-\[\d+(?:\.\d+)?(?:px|rem|em)\]"),
        (
            "ADR-074 §2 fixes the app ramp at 11/12/13/14/16/20/28 (base 13px), and every "
            "step has a named utility: text-2xs 11 · text-xs 12 · text-sm 13 · "
            "text-ramp-14 · text-md 16 · text-ramp-20 · text-ramp-28. This construction "
            "appeared 345 times against 52 uses of the ramp, 157 of them off the scale "
            "and 130 BELOW its 11px floor — which is most of why the app read 'basic': "
            "a ramp is what makes hierarchy, and hardcoded sizes cannot be one. "
            "A genuine exception (SVG user-space font sizes are NOT DOM font sizes) opts "
            "out on the line with `design-constraint-ok: <reason>`."
        ),
    ),
]

# A line may opt out with a written reason. The reason is the point — an unexplained
# suppression is the carve-out that let blur survive its own ban for a year.
OPTOUT = re.compile(r"design-constraint-ok:\s*\S+")


# The ONE file that is allowed to hold colour values, because it IS the palette.
# Exempting it is not a hole: every other file in the tree names a role, so a swap
# stays a one-file change — which is the property the rule exists to protect.
PALETTE_FILE = "packages/ui/src/styles/tokens.css"


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


def rules_for(rel: str) -> list[tuple[str, re.Pattern[str], str]]:
    """The rules that apply to one file.

    `no-hardcoded-colour` is skipped for the palette file alone. Doing it HERE,
    by path, rather than with a blanket opt-out comment inside tokens.css, keeps
    the exemption visible in the guard instead of buried in 900 lines of CSS —
    and means nobody can widen it by pasting the opt-out marker into a component.
    """
    if rel == PALETTE_FILE:
        return [r for r in RULES if r[0] != "no-hardcoded-colour"]
    return RULES


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
    for rule_id, pat, _why in rules_for(rel):
        for m in pat.finditer(text):
            ln = text.count("\n", 0, m.start()) + 1
            line = raw_lines[ln - 1] if 0 < ln <= len(raw_lines) else ""
            # The opt-out is honoured on the violating line OR THE ONE ABOVE IT.
            #
            # Same-line only was unusable for the case that actually needs it. A JSX
            # opening tag cannot carry a comment between its attributes — `<text
            # className="…" /* why */ x={1}>` is a parse error — so a violation living
            # in a className attribute had NOWHERE to put its reason. The 12 SVG
            # `<text>` font sizes are exactly that shape, and a guard whose escape
            # hatch is unreachable for its own main exception gets disabled instead of
            # used. Previous-line is also the convention already in this repo
            # (`biome-ignore lint/…`), so it is the form a reader expects.
            prev = raw_lines[ln - 2] if ln >= 2 else ""
            if OPTOUT.search(line) or OPTOUT.search(prev):
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
        ("type-ramp", '<span className="text-[10px] uppercase">LABEL</span>'),
        # rem and em too — the ban is on bypassing the scale, not on one unit.
        ("type-ramp", '<span className="text-[0.625rem]">x</span>'),
        # The exact shape that shipped 22 invisible focus rings: the suppressor sitting
        # NEXT TO the ring class, which is what made it survive review.
        (
            "no-outline-suppressor",
            '<button className="outline-none focus-visible:outline-2 focus-visible:outline-focus-ring" />',
        ),
        ("no-outline-suppressor", '<input className="focus:outline-none" />'),
        # The two rules added 2026-08-22. Both were prose in `apps/web/CLAUDE.md` and
        # the P0 brief's QA checklist; neither was ever a control, and each had a live
        # violation in the tree on the day it was written (`manifest.ts` #f4f6fa, the
        # `global-error.tsx` zinc ramp) — which is the argument for the rules and the
        # argument for proving they BLOCK in the same breath.
        ("no-hardcoded-colour", 'style={{ background: "#0d0e10" }}'),
        ("no-hardcoded-colour", '<div className="bg-[#f5f5f4]" />'),
        ("no-hardcoded-colour", ".x { border-color: #abc; }"),
        ("no-stock-palette", '<div className="bg-blue-500 text-white" />'),
        ("no-stock-palette", '<span className="text-violet-400" />'),
        ("no-stock-palette", '<div className="border-zinc-800 ring-teal-300" />'),
    ]
    for rule_id, src in cases:
        got = scan_text("fake.tsx", src)
        if any(h[0] == rule_id for h in got):
            print(f"  selftest: {rule_id:<22} → CAUGHT ✓")
        else:
            print(f"  selftest: {rule_id:<22} NOT caught ✗  ({src[:50]})")
            ok = False

    # The clean fixture CANNOT contain a hex any more — `no-hardcoded-colour` is a
    # rule now, and a fixture that violates one rule while proving another is exactly
    # the circular selftest this repo keeps catching. It uses token references, which
    # is what real source is required to use.
    clean = '<div className="fixed inset-0 bg-black/60" />\n.y { background: linear-gradient(160deg, var(--surface-2), var(--surface)); }'
    if not scan_text("fake.tsx", clean):
        print("  selftest: clean source (static token-referencing gradient) → PASSES ✓")
    else:
        print("  selftest: clean source wrongly flagged ✗")
        ok = False

    # The ramp rule has to let the RAMP through, or it bans the fix as well as the
    # defect. `text-[0.9em]` is the one legitimate non-px arbitrary size in the tree
    # (relative sizing inside prose, apps/web/app/(legal)/markdown.tsx) — an `em` that
    # scales with its parent is not a point on the scale and must still be catchable,
    # so it carries an opt-out rather than being pattern-exempted here.
    ramp_clean = '<p className="text-2xs">a</p><p className="text-sm">b</p><p className="text-ramp-28">c</p>'
    if not scan_text("fake.tsx", ramp_clean):
        print("  selftest: the ramp utilities themselves → PASS ✓")
    else:
        print("  selftest: the ramp's own utilities were flagged ✗")
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

    # PREVIOUS-LINE opt-out — the only form available inside a JSX opening tag.
    prev_line = (
        "{/* design-constraint-ok: SVG user space, not a DOM font size */}\n"
        '<text className="fill-ink-3 text-[9px]" x={0} />'
    )
    if not scan_text("fake.tsx", prev_line):
        print("  selftest: opt-out on the PREVIOUS line honoured → PASSES ✓")
    else:
        print("  selftest: previous-line opt-out ignored ✗")
        ok = False

    # …and it must not reach further than one line, or a marker silently covers a
    # violation someone adds underneath it later.
    two_up = (
        "{/* design-constraint-ok: reason */}\n"
        "const gap = 4;\n"
        '<text className="text-[9px]" />'
    )
    if scan_text("fake.tsx", two_up):
        print("  selftest: opt-out does NOT reach two lines down → CAUGHT ✓")
    else:
        print("  selftest: an opt-out two lines up suppressed a violation ✗")
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
