#!/usr/bin/env python3
"""Every price / allowance / rate / policy figure in customer-facing copy must
agree with `apps/web/db/plans.v3.json` — the ONE machine-readable source for
BILL-01 pricing (ADR-076, 2026-09-12; `specs/BILL-01-metering-and-tiers.md` §0).

WHY THIS EXISTS
---------------
The 2026-09-12 founder ruling replaced the entire pricing model — five tiers'
prices changed, the trace-count/hard-cap-429 overage model was retired in
favour of six continuous per-unit meters, seats went from capped to unlimited
on every paid tier, and the $999/mo Audit SKU was found (spec §10.4) not to
meet its own precondition and does not ship at all. `docs/internal/
BILL-01-PHASE0-INVENTORY.md` §A found **173 rows** across the tree still
carrying the retired numbers — proof that a repricing which touches this many
surfaces WILL drift again the next time a rate changes, unless something reads
every surface and refuses silently-stale copy.

WHAT THIS DOES NOT DO
----------------------
It has no opinion on prose, claims of capability, or anything that is not a
figure. A page can still overclaim in words this guard cannot parse — that is
`public-copy`'s job, not this one's.

THE ALLOW-COMMENT ESCAPE HATCH, AND WHY IT IS NARROW
-----------------------------------------------------
Two kinds of `$` figure legitimately appear in these trees without being a
Tracelane plan number: a competitor's own price in a comparison table
(`docs/comparisons/*`), and a historical changelog entry whose text CLAUDE.md
§19 forbids editing. Both are declared, per line, with:

    <!-- pricing-guard: allow $59 $1.20 "per 10K" reason-if-you-want -->

on the SAME line as the flagged token or the line directly above it (inside a
Markdown table row, put it inside a cell — a bare HTML-comment line between
table rows breaks the table). Every `$`-token and `"quoted phrase"` named in
the comment is excused ON THAT LINE ONLY, for both the allowed-price-set check
and the retired-figure check — nothing else on that line, and no other line,
is touched. This is not a global mute: a token not named in an `allow` comment
is still checked, and a new violation two lines away still blocks.

EXIT CODES
----------
0 clean · 1 violation(s) found · 2 usage / could not load the seed.

Falsify:  python3 scripts/ci/check-pricing-copy-vs-seed.py --selftest
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEED_PATH = ROOT / "apps" / "web" / "db" / "plans.v3.json"

SCAN_GLOBS = [
    "apps/docs/**/*.mdx",
    # Diagrams carry copy too: `prompt-promotion-flow.svg` said "Team $249+ ·
    # Builder $59" for a day after the ruling with this guard green (2026-09-14).
    "apps/docs/**/*.svg",
    "apps/site/src/**/*.astro",
    "apps/site/src/**/*.ts",
    # The dashboard is a customer surface — `settings/byok/page.tsx` said
    # "Business ($899/mo)" and `EmptyPrompts.tsx` "Team plan ($249/mo)" with this
    # guard green, because its file-type list was its blind spot (the class in
    # memory `guard-filetype-blindspot`, third instance).
    "apps/web/app/**/*.tsx",
    "apps/web/components/**/*.tsx",
    "README.md",
    "docs/guides/**/*.md",
    "packages/*/README.md",
    "CHANGELOG.public.md",
    # The rest of the root files the public export ships (`build-public-export.sh`
    # ALLOW): SECURITY.md said "`$999/mo` SKU" with this guard green (2026-09-14).
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CLAUDE.public.md",
    "crates/*/README.md",
]

# A leading digit group of 1-3, then optional COMPLETE thousands groups, so a
# trailing sentence comma ("$2,499, custom") is never slurped into the token.
DOLLAR_RE = re.compile(r"\$\d{1,3}(?:,\d{3})*(?:\.\d+)?")
# Three comment syntaxes, one marker: `<!-- … -->` (mdx/astro/svg), `/* … */` and
# `{/* … */}` (tsx), `// …` (ts/tsx, to end of line). Same token grammar in all.
ALLOW_COMMENT_RE = re.compile(
    r"(?:<!--|/\*|//)\s*pricing-guard:\s*allow\b(.*?)(?:-->|\*/|$)", re.IGNORECASE
)
ALLOW_TOKEN_RE = re.compile(r"\$\d[\d,]*(?:\.\d+)?|\"[^\"]+\"")

# Figures the OLD (retired) model expressed that must never reappear, no
# matter what the allowed-price set says — a $59 that happens to also fail
# the allowed-set check is still reported once, but these catch the ones that
# are NOT dollar tokens at all (a trace count, a seat count, a rate phrase).
RETIRED_FIGURES = [
    "$59",
    "$249",
    "$899",
    "$2,999",
    "150K traces",
    "150,000 traces",
    "1M traces",
    "5M traces",
    "25M",
    "10K traces",
    "$1.20",
    "per 10K",
    # NOT `seat_cap`: Free's cap of ONE seat is in the ruled model ("seats 1 then
    # unlimited"), and the invite route's `seat_cap_max: 1` wire field is how the
    # dashboard renders it. What is retired is the paid-tier LADDER and per-seat
    # purchase — those are the tokens below.
    # (`per-seat` is NOT retired either: the ruled copy says "never per-seat" on
    # four surfaces, and a token that flags its own negation is a false gate.)
    "seat_cap_included",
    "extra_seat",
    "10 seats",
    "25 seats",
    "50 seats",
    "$999/mo",
    "$999 per month",
    # The Audit SKU is NOT SOLD (BILL-01 §10.4, B-392): customer copy must not
    # describe it as a product at all — the verifier found it in five docs and an
    # API error with no `$` figure for the price rules to catch (2026-09-14).
    "Audit SKU",
    "Audit add-on",
    "audit add-on",
    "Audit-add-on",
    "5× hard cap",
    "hard cap",
]

# Case-sensitive per the ruling (specs/BILL-01-metering-and-tiers.md §0.1):
# "discount", "% off" and "save X%"/"Save X%" appear on NO surface.
BANNED_WORD_PATTERNS = [
    re.compile(r"discount"),
    re.compile(r"% off"),
    re.compile(r"save\s+(?=\d|%)"),
    re.compile(r"Save\s+(?=\d|%)"),
]


def money(n: float) -> set[str]:
    """Every string form we accept for a dollar amount from the seed."""
    out: set[str] = set()
    if n == int(n):
        out.add(f"${int(n):,}")
        out.add(f"${int(n):,}.00")
    else:
        out.add(f"${n:,.2f}")
    # Small per-unit rates are conventionally written with as many
    # significant decimal digits as the seed carries (e.g. $0.008), which
    # :,.2f would round away.
    s = f"{n:.10f}".rstrip("0").rstrip(".")
    if "." in s:
        out.add(f"${s}")
    return out


def load_allowed_prices(seed: dict) -> set[str]:
    allowed: set[str] = set()
    for plan in seed["plans"].values():
        for key in ("price_monthly_usd", "price_annual_month_usd", "price_from_usd"):
            v = plan.get(key)
            if v is not None:
                allowed |= money(v)
    m = seed["meters"]
    allowed |= money(m["ingest_usd_per_gb"])
    for _, _, rate in m["hot_window_usd_per_gb_month_ladder"]:
        allowed |= money(rate)
    allowed |= money(m["series_usd_per_series_month"])
    allowed |= money(m["query_usd_per_scan_unit"])
    allowed |= money(m["cold_usd_per_gb_month"])
    allowed |= money(m["eval_usd_per_judge_run"])
    p = seed["policy"]
    allowed |= money(p["enterprise_onboarding_fee_usd"])
    for pay, credit in p["prepaid_credits"]:
        allowed |= money(pay)
        allowed |= money(credit)
    return allowed


def load_allowed_allowances(seed: dict) -> set[str]:
    """Non-dollar figures the ruled model actually uses — allowances, windows,
    rate limits and seats — so a docs sweep has one list to check numbers
    against. Not enforced token-by-token (free prose describing "5 GB" would
    be indistinguishable from a stray "5" elsewhere); this exists as the
    derived reference the selftest and any future tightening reads."""
    allowed: set[str] = set()
    for plan in seed["plans"].values():
        for key in (
            "hot_gb_included",
            "ingest_gb_included",
            "series_included",
            "scan_units_included",
            "eval_runs_included",
            "indexed_window_days",
            "queryable_days",
            "ledger_days",
            "cold_archive_days",
            "rate_limit_rpm",
        ):
            v = plan.get(key)
            if v is not None:
                allowed.add(str(v))
    return allowed


def retired_figure_present(fig: str, raw: str) -> bool:
    """`fig` as a whole token in `raw`: no letter/digit/`.`/`_` touching either
    edge (a `$`/`%`-led figure has no left word edge and keeps it)."""
    left = r"(?<![\w.])" if fig[0].isalnum() else ""
    # Right edge: a WORD char continues the token (`25M12`); a sentence period
    # does not (`… the Audit add-on.` is exactly the copy this must catch).
    right = r"(?!\w)" if fig[-1].isalnum() else ""
    return re.search(left + re.escape(fig) + right, raw) is not None


def strip_allow_comments(line: str) -> tuple[str, set[str]]:
    """Return (line, locally-excused tokens) for one physical line."""
    excused: set[str] = set()
    for m in ALLOW_COMMENT_RE.finditer(line):
        for tok in ALLOW_TOKEN_RE.finditer(m.group(1)):
            t = tok.group(0)
            excused.add(t.strip('"'))
    return line, excused


def iter_files(root: Path) -> list[Path]:
    seen: set[Path] = set()
    files: list[Path] = []
    for pattern in SCAN_GLOBS:
        for p in sorted(root.glob(pattern)):
            # Test fixtures are not a customer surface (`online-evals-render.test.tsx`
            # renders a "$0.0001" cost to assert a formatter, not to price anything).
            if is_test_file(p):
                continue
            if p.is_file() and p not in seen:
                seen.add(p)
                files.append(p)
    return files


def is_test_file(p: Path) -> bool:
    return p.name.endswith((".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx"))


FENCE_RE = re.compile(r"^\s*(```|~~~)")
# A comment line inside a fence: shell/python `#`, C-style `//`, SQL `--`.
# `#` must be followed by a space so `#!/bin/bash` and `#[cfg]` stay code.
COMMENT_IN_FENCE_RE = re.compile(r"^\s*(# |// |-- )")


def scan_file(path: Path, allowed_prices: set[str]) -> list[str]:
    hits: list[str] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return hits
    in_fence = False
    for i, raw in enumerate(lines, 1):
        if FENCE_RE.match(raw):
            in_fence = not in_fence
            continue
        if in_fence and not COMMENT_IN_FENCE_RE.match(raw):
            # Fenced code (SQL, bash, JSON snippets) is not customer pricing
            # copy — `$1`/`$2` SQL bind params are the recurring false
            # positive this guard must not flag. A COMMENT inside the fence
            # is prose the customer reads, though: `# Pull your ledger as
            # NDJSON (requires the Audit add-on)` sat in a ```bash block of
            # docs/guides/quickstart.md with this guard green (2026-09-14,
            # found by the adversarial pass, not by the guard).
            continue

        _, excused = strip_allow_comments(raw)
        if i > 1:
            _, prev_excused = strip_allow_comments(lines[i - 2])
            excused |= prev_excused

        # (a) any $<number> token not in the allowed price set.
        for m in DOLLAR_RE.finditer(raw):
            tok = m.group(0)
            if tok in allowed_prices or tok in excused:
                continue
            hits.append(f"{path}:{i}: disallowed price token {tok!r}")

        # (b) retired figures, anywhere, regardless of $ shape.
        for fig in RETIRED_FIGURES:
            # Word-bounded, not substring: `25M` sat inside an SVG path
            # (`v11.25M12 9v3.75`) in `EmptyTraces.tsx` and read as the retired
            # 25M-trace allowance. A `$`-prefixed figure keeps its own left edge.
            if retired_figure_present(fig, raw) and fig not in excused:
                hits.append(f"{path}:{i}: retired figure {fig!r}")

        # (c) banned words — never excusable by an allow-comment; there is no
        # legitimate reason to write "discount" / "% off" / "save 20%" about
        # Tracelane pricing anywhere in scope.
        for pat in BANNED_WORD_PATTERNS:
            if pat.search(raw):
                hits.append(f"{path}:{i}: banned word matching {pat.pattern!r}")
    return hits


def run(root: Path) -> list[str]:
    seed = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    allowed_prices = load_allowed_prices(seed)
    load_allowed_allowances(seed)  # derived; see docstring
    hits: list[str] = []
    for f in iter_files(root):
        hits.extend(scan_file(f, allowed_prices))
    return hits


def report(hits: list[str]) -> int:
    if not hits:
        print(
            "✓ pricing copy matches apps/web/db/plans.v3.json — no retired figures, no banned words"
        )
        return 0
    print(f"❌ {len(hits)} pricing-copy violation(s):")
    for h in hits:
        print(f"   {h}")
    print(
        "\n→ Every price/rate/allowance figure in customer-facing copy must come "
        "from apps/web/db/plans.v3.json (BILL-01 / ADR-076). A legitimate "
        "non-plan figure (a competitor's price, a historical changelog entry "
        "CLAUDE.md §19 forbids editing) is excused per-line with "
        '<!-- pricing-guard: allow $X "phrase" --> — never a global mute.'
    )
    return 1


SELFTEST_FILES = {
    "clean.mdx": (
        "---\nclassification: PUBLIC\n---\n"
        "Builder is $29/mo ($24 annual). Ingest is $0.20/GB.\n"
    ),
    "retired_price.mdx": "Builder is $59/mo.\n",
    "retired_traces.mdx": "Free hosted includes 150K traces/mo.\n",
    "banned_word.mdx": "Switch to annual and save 20% today.\n",
    "unlisted_price.mdx": "The premium tier is $4,999/mo.\n",
    "retired_sku.mdx": "Independent verification is included with the Audit add-on.\n",
    # A comment INSIDE a code fence is prose the customer reads — must be red.
    "retired_sku_in_fenced_comment.mdx": (
        "```bash\n# Pull your ledger (requires the Audit add-on)\ncurl ...\n```\n"
    ),
    # Code inside the fence (a SQL bind param, a JSON figure) must stay green.
    "code_in_fence.mdx": "```sql\nSELECT $1, $2 FROM t WHERE usd = 4999\n```\n",
    "allowed_sku_history.mdx": (
        '<!-- pricing-guard: allow "Audit add-on" historical -->\n'
        "2026-06: the Audit add-on shipped its verifier.\n"
    ),
    "allowed_with_comment.mdx": (
        "Sample provider pricing.\n"
        "<!-- pricing-guard: allow $1.70 provider-rate -->\n"
        "GPT-4 costs $1.70 per million tokens on this benchmark.\n"
    ),
}


def selftest() -> int:
    failures = 0
    with tempfile.TemporaryDirectory() as td:
        fake = Path(td) / "repo"
        (fake / "apps" / "web" / "db").mkdir(parents=True, exist_ok=True)
        (fake / "apps" / "web" / "db" / "plans.v3.json").write_text(
            SEED_PATH.read_text(encoding="utf-8"), encoding="utf-8"
        )
        docs_dir = fake / "apps" / "docs"
        docs_dir.mkdir(parents=True, exist_ok=True)
        for name, body in SELFTEST_FILES.items():
            (docs_dir / name).write_text(body, encoding="utf-8")

        seed = json.loads((fake / "apps" / "web" / "db" / "plans.v3.json").read_text())
        allowed_prices = load_allowed_prices(seed)
        results: dict[str, list[str]] = {}
        for name in SELFTEST_FILES:
            results[name] = scan_file(docs_dir / name, allowed_prices)

        expectations = {
            "clean.mdx": False,
            "retired_price.mdx": True,
            "retired_traces.mdx": True,
            "banned_word.mdx": True,
            "unlisted_price.mdx": True,
            "retired_sku.mdx": True,
            "retired_sku_in_fenced_comment.mdx": True,
            "code_in_fence.mdx": False,
            "allowed_sku_history.mdx": False,
            "allowed_with_comment.mdx": False,
        }

        # The dashboard + SVG surfaces (2026-09-14): this guard was green while
        # `settings/byok/page.tsx` said "$899/mo" and five audit surfaces sold a
        # "$999/mo" SKU that is not sold, because its file-type list stopped at
        # .mdx/.astro. Each fixture below is a real shape from that sweep.
        comp_dir = fake / "apps" / "web" / "components"
        comp_dir.mkdir(parents=True, exist_ok=True)
        tsx_fixtures = {
            "RetiredPrice.tsx": 'export const x = "Business ($899/mo) and Enterprise";\n',
            "SlashAllowed.tsx": (
                "// pricing-guard: allow $1.70 provider-rate\n"
                'export const y = "GPT-4 costs $1.70 per million tokens";\n'
            ),
            "SvgPath.tsx": '<path d="M3.75 3v11.25M12 9v3.75m3-6v6" />\n',
            "FreeSeatCap.tsx": "const err = { seat_cap_max: 1, used: 1 };\n",
            "Fixture.test.tsx": 'render(<Cost usd="$0.0001" />); // $59 too\n',
        }
        for name, body in tsx_fixtures.items():
            (comp_dir / name).write_text(body, encoding="utf-8")
        (fake / "apps" / "docs" / "flow.svg").write_text(
            "<text>Full promotion workflow on Team $249+</text>\n", encoding="utf-8"
        )
        for name in tsx_fixtures:
            results[name] = scan_file(comp_dir / name, allowed_prices)
        results["flow.svg"] = scan_file(
            fake / "apps" / "docs" / "flow.svg", allowed_prices
        )
        expectations.update(
            {
                "RetiredPrice.tsx": True,
                "SlashAllowed.tsx": False,
                "SvgPath.tsx": False,
                "FreeSeatCap.tsx": False,
                "flow.svg": True,
            }
        )
        # Scope, not just scanning: the widened globs must SELECT the tsx and the
        # svg, and must NOT select the test fixture.
        picked = {p.name for p in iter_files(fake)}
        for must, name in (
            (True, "RetiredPrice.tsx"),
            (True, "flow.svg"),
            (False, "Fixture.test.tsx"),
        ):
            if (name in picked) != must:
                print(
                    f"  ✗ iter_files {'must' if must else 'must NOT'} pick {name} — picked={sorted(picked)}"
                )
                failures += 1
            else:
                print(f"  ✓ iter_files {'picks' if must else 'skips'} {name}")

        for name, must_fail in expectations.items():
            failed = bool(results[name])
            if failed != must_fail:
                verb = "FAIL" if must_fail else "PASS"
                print(f"  ✗ expected {verb} on {name} — got hits={results[name]}")
                failures += 1
            else:
                print(f"  {'✓ FAILS' if must_fail else '✓ PASSES'} {name}")

    if failures:
        print(f"\nselftest FAILED — {failures} case(s). The guard is not trustworthy.")
        return 1
    print("\nselftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not SEED_PATH.exists():
        print(f"❌ cannot find the seed of truth: {SEED_PATH}")
        return 2
    return report(run(ROOT))


if __name__ == "__main__":
    sys.exit(main())
