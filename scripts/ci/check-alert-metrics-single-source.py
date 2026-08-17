#!/usr/bin/env python3
"""The alertable-metric list is written in 6 places. They must all agree.

WHY (2026-08-09, found while instrumenting B-189). Migration
`0017_overhead_p99_alert_metric.sql` exists to make gateway-overhead p99 alertable, so a
latency-tax regression fires instead of hiding. It added `overhead_p99` to the Postgres
CHECK; `crates/gateway/src/alerts/mod.rs` accepts it; `checker.rs` has a SQL branch for
it. **And the dashboard proxy rejected it with a 422 before the request ever left
apps/web**, while the settings UI never offered it. The migration's entire purpose was
unreachable, and nothing failed — the list is hand-maintained in six places, so drift is
silent by construction.

Same shape as B-068 (a hand-maintained provider count that reached the marketing site
twice) and B-145 (routable ≠ storable because two provider allowlists drifted). The fix
is the same one: derive from ONE source and fail on disagreement.

SOURCE OF TRUTH: `METRICS` in `crates/gateway/src/alerts/mod.rs`. The gateway is what
actually evaluates a rule, so a metric it cannot compute is not alertable no matter what
any other layer accepts — code wins (CLAUDE.md §4.0).

CHECKED AGAINST IT:
  1. `checker.rs`         — a match arm per metric, else the rule silently never fires
  2. `alerts/mod.rs`      — the label/unit map, else the notification renders a raw slug
  3. Postgres CHECK       — the newest migration that rewrites `alert_rules_metric_*`
  4. `apps/web/app/api/alerts/rules/route.ts` — VALID_METRICS (the 422 that hid 0017)
  5. `AlertsManager.tsx`  — METRIC_META and the <option> list the user actually picks from

HONEST LIMIT. This proves the six lists hold the same NAMES. It does not prove the SQL
behind a metric is correct, that the CHECK migration was ever applied to production (see
audit-migration-drift.py for that), or that the metric means the same thing in each place.
Agreement on spelling, not on semantics.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[2]

RUST_MOD = ROOT / "crates" / "gateway" / "src" / "alerts" / "mod.rs"
RUST_CHECKER = ROOT / "crates" / "gateway" / "src" / "alerts" / "checker.rs"
WEB_ROUTE = ROOT / "apps" / "web" / "app" / "api" / "alerts" / "rules" / "route.ts"
WEB_UI = ROOT / "apps" / "web" / "components" / "settings" / "AlertsManager.tsx"
MIGRATIONS = ROOT / "apps" / "web" / "db" / "migrations"


def die(msg: str) -> NoReturn:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def canonical(mod_src: str) -> set[str]:
    """`METRICS` in alerts/mod.rs — the source of truth."""
    m = re.search(r"METRICS[^=]*=\s*\[(.*?)\]", mod_src, re.DOTALL)
    if not m:
        die(
            "cannot find the METRICS const in alerts/mod.rs — the source of truth moved"
        )
    names = set(re.findall(r'"([a-z0-9_]+)"', m.group(1)))
    if not names:
        die(
            "METRICS parsed as EMPTY — a parser that returns nothing passes every check"
        )
    return names


def checker_arms(src: str) -> set[str]:
    return set(re.findall(r'"([a-z0-9_]+)"\s*=>\s*self\.', src))


def label_map(mod_src: str) -> set[str]:
    tail = mod_src.split("METRICS", 1)[-1]
    return set(re.findall(r'"([a-z0-9_]+)"\s*=>\s*\(', tail))


def migration_check() -> tuple[set[str], str]:
    """The newest migration that rewrites the alert_rules metric CHECK wins."""
    best: tuple[str, set[str]] | None = None
    for path in sorted(MIGRATIONS.glob("*.sql")):
        src = path.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(
            r"CHECK\s*\(\s*metric\s+IN\s*\((.*?)\)", src, re.DOTALL | re.IGNORECASE
        ):
            best = (path.name, set(re.findall(r"'([a-z0-9_]+)'", m.group(1))))
    if best is None:
        die("no migration declares a `metric IN (...)` CHECK on alert_rules")
    return best[1], best[0]


def web_valid(src: str) -> set[str]:
    m = re.search(r"VALID_METRICS\s*=\s*new Set\(\[(.*?)\]\)", src, re.DOTALL)
    if not m:
        die("cannot find VALID_METRICS in the alerts rules route")
    return set(re.findall(r'"([a-z0-9_]+)"', m.group(1)))


def ui_meta(src: str) -> set[str]:
    m = re.search(r"METRIC_META[^=]*=\s*\{(.*?)\n\};", src, re.DOTALL)
    if not m:
        die("cannot find METRIC_META in AlertsManager.tsx")
    return set(re.findall(r"^\s*([a-z0-9_]+):\s*\{", m.group(1), re.MULTILINE))


def ui_options(src: str) -> set[str]:
    """Only the METRIC `<select>`, scoped by `id="rule-metric"`.

    Scraping every `<option>` in the file swept in the comparator (gt/lt) and
    destination-kind (slack/discord/webhook) dropdowns and reported them as bogus
    metrics — a guard that fires on correct code, which is how a guard gets disabled.
    """
    m = re.search(r'id="rule-metric"(.*?)</select>', src, re.DOTALL)
    if not m:
        die('cannot find the metric <select id="rule-metric"> in AlertsManager.tsx')
    return set(re.findall(r'<option value="([a-z0-9_]+)"', m.group(1)))


def run(sources: dict[str, str]) -> list[str]:
    truth = canonical(sources["mod"])
    mig, mig_name = (
        (sources["migration_set"], sources.get("migration_name", "<fixture>"))
        if "migration_set" in sources
        else migration_check()
    )

    layers = {
        "checker.rs match arms": checker_arms(sources["checker"]),
        "alerts/mod.rs label map": label_map(sources["mod"]),
        f"Postgres CHECK ({mig_name})": mig,
        "web route VALID_METRICS": web_valid(sources["route"]),
        "AlertsManager METRIC_META": ui_meta(sources["ui"]),
        "AlertsManager <option> list": ui_options(sources["ui"]),
    }

    errors: list[str] = []
    for name, got in layers.items():
        if missing := truth - got:
            errors.append(
                f"{name}: MISSING {sorted(missing)} — a metric the gateway accepts that "
                f"this layer rejects is unreachable (this is exactly how overhead_p99 hid)"
            )
        if extra := got - truth:
            errors.append(
                f"{name}: has {sorted(extra)} which the gateway cannot evaluate — a rule "
                f"on it would be accepted and then never fire"
            )
    return errors


def read_all() -> dict[str, str]:
    for p in (RUST_MOD, RUST_CHECKER, WEB_ROUTE, WEB_UI):
        if not p.exists():
            die(f"{p.relative_to(ROOT)} not found")
    return {
        "mod": RUST_MOD.read_text(encoding="utf-8"),
        "checker": RUST_CHECKER.read_text(encoding="utf-8"),
        "route": WEB_ROUTE.read_text(encoding="utf-8"),
        "ui": WEB_UI.read_text(encoding="utf-8"),
    }


CLEAN = {
    "mod": 'pub const METRICS: [&str; 2] = ["error_rate", "burn_rate"];\n'
    'fn label(m: &str) { match m { "error_rate" => ("error rate", "%"), '
    '"burn_rate" => ("SLO burn rate", "x"), _ => todo!() } }',
    "checker": 'match m { "error_rate" => self.a().await, "burn_rate" => self.b().await, }',
    "route": 'const VALID_METRICS = new Set([\n"error_rate",\n"burn_rate",\n]);',
    "ui": "const METRIC_META: Record<string, X> = {\n\terror_rate: { label: 'a' },\n"
    "\tburn_rate: { label: 'b' },\n};\n"
    '<select id="rule-metric">'
    '<option value="error_rate">a</option><option value="burn_rate">b</option>'
    "</select>"
    '<select id="rule-comparator"><option value="gt">gt</option></select>',
    "migration_set": {"error_rate", "burn_rate"},
}


def selftest() -> int:
    base = dict(CLEAN)
    assert not run(base), f"selftest: an agreeing set must PASS, got {run(base)}"
    print("✓ selftest: six agreeing lists pass")

    # THE REAL BUG: the gateway accepts a metric the web layer rejects.
    s = dict(base)
    s["route"] = 'const VALID_METRICS = new Set([\n"error_rate",\n]);'
    errs = run(s)
    assert any("MISSING" in e and "burn_rate" in e for e in errs), errs
    print("✓ selftest: a metric the web proxy rejects is CAUGHT (the overhead_p99 bug)")

    # The reverse: a layer offering a metric the gateway cannot evaluate.
    s = dict(base)
    s["route"] = (
        'const VALID_METRICS = new Set([\n"error_rate",\n"burn_rate",\n"ghost",\n]);'
    )
    errs = run(s)
    assert any("cannot evaluate" in e and "ghost" in e for e in errs), errs
    print("✓ selftest: a metric the gateway cannot evaluate is CAUGHT")

    # A missing checker arm — accepted everywhere, silently never fires.
    s = dict(base)
    s["checker"] = 'match m { "error_rate" => self.a().await, }'
    errs = run(s)
    assert any("checker.rs" in e and "burn_rate" in e for e in errs), errs
    print("✓ selftest: a metric with no checker arm is CAUGHT (accepted, never fires)")

    # The UI dropdown lagging its own META map.
    s = dict(base)
    s["ui"] = base["ui"].replace('<option value="burn_rate">b</option>', "")
    errs = run(s)
    assert any("<option>" in e for e in errs), errs
    print("✓ selftest: a metric missing from the dropdown is CAUGHT")

    # A parser that silently returns nothing would pass everything.
    try:
        canonical("no metrics const here")
    except SystemExit:
        print("✓ selftest: an unparseable source of truth FAILS LOUD, not empty")
    else:  # pragma: no cover
        raise AssertionError("selftest: empty parse must fail, not return an empty set")

    print("\nselftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="alert metric list single-source guard")
    ap.add_argument("--selftest", action="store_true", help="prove the guard blocks")
    args = ap.parse_args()
    if args.selftest:
        return selftest()

    errors = run(read_all())
    for e in errors:
        print(f"FAIL {e}")
    if errors:
        print(
            "\nThe alertable-metric list is written in 6 places and they disagree. "
            "Source of\ntruth is METRICS in crates/gateway/src/alerts/mod.rs — the gateway "
            "is what evaluates\na rule, so a metric it cannot compute is not alertable "
            "whatever else accepts it."
        )
        return 1
    truth = canonical(read_all()["mod"])
    print(
        f"alert metrics single-source: clean ({len(truth)} metrics agree across 6 layers)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
