#!/usr/bin/env python3
"""A deploy REFUSES when the reference tables on Neon disagree with the seed JSON (B-421).

THE GAP. `apps/web/db/plans.v3.json` is the ONE reviewed source for every price,
allowance, window, rate band and policy knob (CLAUDE.md §23, `.claude/rules/
reference-tables.md`). `apps/web/db/seed.mjs` upserts it into Neon's
`plan_entitlements` / `pricing_rates` / `billing_policy`, and the gateway's
entitlement-cache refresh reads THOSE TABLES, never the JSON. So a JSON change that
nobody seeded ships a gateway that says one thing in its docs and charges another —
and until now nothing at deploy time compared the two. The seed and the deploy are two
commands a caller has to remember to connect (the B-422 class); this makes the deploy
CHECK rather than TRUST. The comparison is the one `scripts/proofs/bill01-prod-proof.sh`
proof 1c runs BY HAND on the node, lifted into a guard with a selftest and widened to
everything the seed writes: the 13 `f_*` plan flags (parsed out of seed.mjs's PLANS
array), the 17 v3 plan columns, every current pricing band, and every billing_policy
key the seed's `policyRows` names.

THE SPLIT (same as check-deploy-schema.py): `--catalog-sql` prints ONE query that
returns the three tables as a single JSON object; the deploy script runs it where the
credentials are (the node, via the gateway container's env) and pipes the result to
`--compare`, which is pure and `--selftest`-able.

USAGE
  check-seed-vs-neon.py --expected                 # JSON: what the seed would write
  check-seed-vs-neon.py --catalog-sql              # the psql query for the live side
  check-seed-vs-neon.py --compare < live.json      # refuse on any value delta
  check-seed-vs-neon.py --selftest                 # prove it BLOCKS
EXIT 0 equal · 1 any delta (each named with both values) · 2 could not determine
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
PLANS_JSON = ROOT / "apps/web/db/plans.v3.json"
SEED_MJS = ROOT / "apps/web/db/seed.mjs"

# The 17 plan columns the seed's `update plan_entitlements set …` writes from the JSON.
V3_PLAN_COLUMNS = [
    "price_monthly_usd",
    "price_annual_month_usd",
    "price_from_usd",
    "hot_gb_included",
    "ingest_gb_included",
    "series_included",
    "scan_units_included",
    "eval_runs_included",
    "indexed_window_days",
    "queryable_days",
    "ledger_days",
    "cold_archive_days",
    "cold_gb_included",
    "unlimited_seats",
    "f_sso",
    "overage_allowed",
    "rate_limit_rpm",
]

CATALOG_SQL = r"""
SELECT json_build_object(
  'plan_entitlements', (SELECT COALESCE(json_agg(row_to_json(p)), '[]'::json) FROM plan_entitlements p),
  'pricing_rates',     (SELECT COALESCE(json_agg(row_to_json(r)), '[]'::json) FROM pricing_rates r WHERE r.is_current),
  'billing_policy',    (SELECT COALESCE(json_agg(json_build_object('key', b.key, 'value', b.value)), '[]'::json) FROM billing_policy b)
);
"""

SEED_COMMAND = (
    "cd apps/web && DATABASE_URL=<the Neon DIRECT url from the gateway container env> "
    "node db/seed.mjs"
)


# ── the seed, read from the tree ───────────────────────────────────────────────


def _js_array_literal(src: str, name: str) -> list:
    """The `const NAME = [ … ];` literal in seed.mjs as JSON (strings + booleans only).

    It is a plain data literal — every element is a string or a boolean — so once the
    comments and trailing commas are gone it IS JSON. Any other JS in it fails the
    json.loads and this returns [], which `expected()` treats as CANNOT DETERMINE.
    """
    m = re.search(rf"const\s+{name}\s*=\s*\[", src)
    if not m:
        return []
    i = m.end() - 1
    depth, j = 0, i
    while j < len(src):
        if src[j] == "[":
            depth += 1
        elif src[j] == "]":
            depth -= 1
            if depth == 0:
                break
        j += 1
    body = src[i : j + 1]
    body = re.sub(r"//[^\n]*", "", body)
    body = re.sub(r"/\*[\s\S]*?\*/", "", body)
    body = re.sub(r",\s*([\]\}])", r"\1", body)
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return []


def _seed_flag_columns(src: str) -> list[str]:
    """The column list of the seed's `insert into plan_entitlements (…) values` — the
    order the PLANS rows are bound in. Derived, not retyped, so a column added to both
    the INSERT and the rows is picked up here without an edit."""
    m = re.search(
        r"insert\s+into\s+plan_entitlements\s*\(([^)]*)\)\s*values", src, re.IGNORECASE
    )
    if not m:
        return []
    return [c.strip() for c in m.group(1).replace("\n", " ").split(",") if c.strip()]


def _seed_policy_keys(src: str) -> list[str]:
    """Every key of the seed's `const policyRows = { … }` object, in order."""
    m = re.search(r"const\s+policyRows\s*=\s*\{([\s\S]*?)\n\};", src)
    if not m:
        return []
    body = re.sub(r"//[^\n]*", "", m.group(1))
    return re.findall(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:", body, re.MULTILINE)


def _policy_rows(v3: dict) -> dict:
    """The exact value the seed writes for each billing_policy key (mirrors policyRows)."""
    pol, m = v3["policy"], v3["meters"]
    rows = {
        "burst_multiple": pol.get("burst_multiple_of_trailing_30d_avg"),
        "warn_pct_1": (pol.get("warning_thresholds_pct") or [None, None])[0],
        "warn_pct_2": (pol.get("warning_thresholds_pct") or [None, None])[1],
        "warn_pct": pol.get("warning_thresholds_pct"),
        "never_metered": m.get("never_metered"),
    }
    # Every other policyRows key is `name: pol.name` — a straight copy of the JSON key.
    # Derive those from seed.mjs so a new knob (annual_pairing_deadline_ms landed while
    # this guard was being written) is compared without an edit here.
    src = SEED_MJS.read_text(encoding="utf-8") if SEED_MJS.is_file() else ""
    for k in _seed_policy_keys(src):
        if k not in rows:
            rows[k] = pol.get(k, "<KEY ABSENT FROM plans.v3.json>")
    return rows


def expected() -> dict:
    """What the seed would write. Pure — reads the tree, nothing else."""
    if not PLANS_JSON.is_file() or not SEED_MJS.is_file():
        print(
            f"✗ CANNOT DETERMINE — {PLANS_JSON} or {SEED_MJS} not found",
            file=sys.stderr,
        )
        raise SystemExit(2)
    v3 = json.loads(PLANS_JSON.read_text(encoding="utf-8"))
    src = SEED_MJS.read_text(encoding="utf-8")
    flag_cols = _seed_flag_columns(src)
    plans_rows = _js_array_literal(src, "PLANS")
    if not flag_cols or not plans_rows or flag_cols[0] != "plan_lookup_key":
        print(
            "✗ CANNOT DETERMINE — could not parse seed.mjs's PLANS array / insert column "
            "list; an empty expectation would certify anything.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    flags: dict[str, dict] = {}
    for row in plans_rows:
        if len(row) != len(flag_cols):
            print(
                f"✗ CANNOT DETERMINE — seed.mjs PLANS row {row[0]!r} has {len(row)} values "
                f"for {len(flag_cols)} insert columns",
                file=sys.stderr,
            )
            raise SystemExit(2)
        flags[row[0]] = dict(zip(flag_cols[1:], row[1:], strict=True))
    plans: dict[str, dict] = {}
    for key, p in v3["plans"].items():
        plans[key] = {c: p.get(c) for c in V3_PLAN_COLUMNS}
        plans[key].update(flags.get(key, {}))
    for key, row_flags in flags.items():
        plans.setdefault(key, {}).update(row_flags)
    m = v3["meters"]
    rates: dict[str, float] = {
        "ingest_gb@0": m["ingest_usd_per_gb"],
        "series@0": m["series_usd_per_series_month"],
        "scan_units@0": m["query_usd_per_scan_unit"],
        "cold_gb_month@0": m["cold_usd_per_gb_month"],
        "eval_runs@0": m["eval_usd_per_judge_run"],
    }
    for lo, _hi, usd in m["hot_window_usd_per_gb_month_ladder"]:
        rates[f"hot_gb_month@{lo}"] = usd
    return {"plans": plans, "rates": rates, "policy": _policy_rows(v3)}


# ── the comparison ─────────────────────────────────────────────────────────────


def _norm(v):
    """numeric strings (Neon returns `numeric` as text) and floats compare as numbers."""
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return v
    if isinstance(v, list):
        return [_norm(x) for x in v]
    if isinstance(v, dict):
        return {k: _norm(x) for k, x in v.items()}
    return v


def compare(want: dict, have: dict) -> int:
    for k in ("plan_entitlements", "pricing_rates", "billing_policy"):
        if not isinstance(have.get(k), list):
            print(
                f"✗ CANNOT DETERMINE — the live dump carries no `{k}` array. An unread table is not an equal one (CLAUDE.md §1)."
            )
            return 2
    live_plans = {r.get("plan_lookup_key"): r for r in have["plan_entitlements"]}
    live_rates = {
        f"{r.get('meter')}@{_norm(r.get('band_lo')):g}": r.get("usd_per_unit")
        for r in have["pricing_rates"]
    }
    live_pol = {r.get("key"): r.get("value") for r in have["billing_policy"]}
    problems: list[str] = []
    for key, cols in want["plans"].items():
        row = live_plans.get(key)
        if row is None:
            problems.append(f"  plan_entitlements[{key}]: NO ROW on Neon")
            continue
        for c, v in cols.items():
            if c not in row:
                problems.append(
                    f"  plan_entitlements[{key}].{c}: column ABSENT on Neon (migration not applied?)"
                )
            elif _norm(v) != _norm(row[c]):
                problems.append(
                    f"  plan_entitlements[{key}].{c}: seed={v!r} neon={row[c]!r}"
                )
    for k, v in want["rates"].items():
        meter, lo = k.split("@")
        k2 = f"{meter}@{float(lo):g}"
        if k2 not in live_rates:
            problems.append(
                f"  pricing_rates[{meter} band_lo={lo}]: NO CURRENT ROW on Neon"
            )
        elif abs(float(_norm(live_rates[k2])) - float(v)) > 1e-9:
            problems.append(
                f"  pricing_rates[{meter} band_lo={lo}].usd_per_unit: seed={v} neon={live_rates[k2]}"
            )
    want_keys = {f"{k.split('@')[0]}@{float(k.split('@')[1]):g}" for k in want["rates"]}
    for k in live_rates:
        if k not in want_keys:
            problems.append(
                f"  pricing_rates[{k}]: CURRENT on Neon but not in the seed (a retired band still is_current)"
            )
    for k, v in want["policy"].items():
        if k not in live_pol:
            problems.append(f"  billing_policy[{k}]: NO ROW on Neon")
        elif _norm(v) != _norm(live_pol[k]):
            problems.append(f"  billing_policy[{k}]: seed={v!r} neon={live_pol[k]!r}")
    if problems:
        print("✗ THE LIVE REFERENCE TABLES DO NOT EQUAL apps/web/db/plans.v3.json:\n")
        print("\n".join(problems))
        print(
            "\n  The gateway reads these TABLES, not the JSON — deploying now ships a binary\n"
            "  whose docs say one thing and whose rate card says another. Seed first, then\n"
            "  deploy again:\n"
            f"    {SEED_COMMAND}\n"
            "  (the URL is POSTGRES_DIRECT_URL in `docker inspect tracelane-gateway-1` on the node)."
        )
        return 1
    print(
        f"OK — Neon equals plans.v3.json: {len(want['plans'])} plan rows × "
        f"{len(next(iter(want['plans'].values())))} columns, {len(want['rates'])} current "
        f"rate bands, {len(want['policy'])} policy keys."
    )
    return 0


# ── selftest ───────────────────────────────────────────────────────────────────


def _live_from(want: dict) -> dict:
    """A live dump equal to the seed, in the shape the catalog query returns."""
    plans = []
    for key, cols in want["plans"].items():
        row = {"plan_lookup_key": key, "created_at": "2026-01-01T00:00:00Z"}
        for c, v in cols.items():
            # Neon returns numeric columns as strings — the shape row_to_json produces.
            row[c] = str(v) if isinstance(v, float) and not isinstance(v, bool) else v
        plans.append(row)
    rates = []
    for k, v in want["rates"].items():
        meter, lo = k.split("@")
        rates.append(
            {
                "price_version": "v3",
                "meter": meter,
                "band_lo": f"{float(lo):.3f}",
                "usd_per_unit": f"{v:.4f}",
                "is_current": True,
            }
        )
    pol = [{"key": k, "value": v} for k, v in want["policy"].items()]
    return {"plan_entitlements": plans, "pricing_rates": rates, "billing_policy": pol}


def selftest() -> int:
    import contextlib
    import copy
    import io

    fails = 0

    def case(label: str, want: dict, have: dict, rc_expected: int) -> None:
        nonlocal fails
        with contextlib.redirect_stdout(io.StringIO()):
            rc = compare(want, have)
        print(
            ("  ✓ " if rc == rc_expected else "  ✗ ")
            + label
            + ("" if rc == rc_expected else f" — expected rc={rc_expected}, got {rc}")
        )
        fails += rc != rc_expected

    want = expected()
    src = SEED_MJS.read_text(encoding="utf-8")
    # The expectation must cover EVERYTHING the seed writes, or a drift there is invisible.
    seed_pol = set(_seed_policy_keys(src))
    if seed_pol and seed_pol == set(want["policy"]):
        print(
            f"  ✓ every policyRows key in seed.mjs is compared ({len(seed_pol)} keys)"
        )
    else:
        print(
            f"  ✗ policy keys differ: seed.mjs={sorted(seed_pol)} guard={sorted(want['policy'])}"
        )
        fails += 1
    n_flags = len(_seed_flag_columns(src)) - 1
    if n_flags >= 13 and all(
        len(c) == len(V3_PLAN_COLUMNS) + n_flags for c in want["plans"].values()
    ):
        print(
            f"  ✓ every plan row compares {len(V3_PLAN_COLUMNS)} v3 columns + {n_flags} f_* flags from the PLANS array"
        )
    else:
        print(
            f"  ✗ plan column coverage wrong: flags={n_flags} rows={[len(c) for c in want['plans'].values()]}"
        )
        fails += 1
    if (
        "annual_pairing_deadline_ms" in want["policy"]
        or "annual_pairing_deadline_ms" not in src
    ):
        print(
            "  ✓ a policy key added to seed.mjs after this guard was written is picked up (derived, not retyped)"
        )
    else:
        print("  ✗ a policyRows key present in seed.mjs is not compared")
        fails += 1

    ok = _live_from(want)
    print("  " + "-" * 60)
    case("Neon equal to the seed PASSES (rc=0)", want, ok, 0)

    stale = copy.deepcopy(ok)
    for r in stale["plan_entitlements"]:
        if r["plan_lookup_key"] == "builder_v1":
            r["price_monthly_usd"] = (
                59  # the retired ADR-020 price — the exact drift shape
            )
    case(
        "a STALE plan price on Neon REFUSES, naming both values (rc=1)", want, stale, 1
    )

    flag = copy.deepcopy(ok)
    for r in flag["plan_entitlements"]:
        if r["plan_lookup_key"] == "team_v1":
            r["f_experiments"] = False
    case("a drifted f_* PLAN FLAG (seed.mjs PLANS array) REFUSES", want, flag, 1)

    rate = copy.deepcopy(ok)
    for r in rate["pricing_rates"]:
        if r["meter"] == "hot_gb_month" and float(r["band_lo"]) == 500:
            r["usd_per_unit"] = "9.0000"
    case("a drifted pricing_rates band REFUSES", want, rate, 1)

    extra = copy.deepcopy(ok)
    extra["pricing_rates"].append(
        {
            "price_version": "v3",
            "meter": "trace_overage",
            "band_lo": "0.000",
            "usd_per_unit": "1.2000",
            "is_current": True,
        }
    )
    case("a retired band still is_current on Neon REFUSES", want, extra, 1)

    pol = copy.deepcopy(ok)
    for r in pol["billing_policy"]:
        if r["key"] == "warn_pct":
            r["value"] = [80, 95]
    case("a drifted billing_policy value (array) REFUSES", want, pol, 1)

    missing = copy.deepcopy(ok)
    missing["billing_policy"] = [
        r for r in missing["billing_policy"] if r["key"] != "dunning_retry_days"
    ]
    case(
        "a policy key the seed writes but Neon lacks REFUSES (never seeded)",
        want,
        missing,
        1,
    )

    norow = copy.deepcopy(ok)
    norow["plan_entitlements"] = [
        r for r in norow["plan_entitlements"] if r["plan_lookup_key"] != "free_v1"
    ]
    case("a missing plan row REFUSES", want, norow, 1)

    nocol = copy.deepcopy(ok)
    for r in nocol["plan_entitlements"]:
        r.pop("cold_gb_included", None)
    case("a plan COLUMN absent on Neon (migration unapplied) REFUSES", want, nocol, 1)

    case(
        "a dump with no billing_policy array is rc=2, never a pass",
        want,
        {
            "plan_entitlements": ok["plan_entitlements"],
            "pricing_rates": ok["pricing_rates"],
        },
        2,
    )
    case("an empty dump is rc=2", want, {}, 2)

    numeric = copy.deepcopy(ok)
    for r in numeric["plan_entitlements"]:
        if r["plan_lookup_key"] == "free_v1":
            r["hot_gb_included"] = "0.250"  # numeric(12,3) as Neon renders it
    case(
        "Neon's numeric-as-text rendering (0.250 vs 0.25) is NOT a delta",
        want,
        numeric,
        0,
    )

    if fails:
        print(f"\nSELFTEST FAILED — {fails} case(s).")
        return 1
    print(
        "\nSELFTEST PASSED — a stale price, flag, rate band and policy value each REFUSE; an unread table is CANNOT DETERMINE."
    )
    return 0


def main() -> int:
    argv = sys.argv[1:]
    if argv == ["--selftest"]:
        return selftest()
    if argv == ["--expected"]:
        print(json.dumps(expected(), indent=2))
        return 0
    if argv == ["--catalog-sql"]:
        print(CATALOG_SQL)
        return 0
    if argv == ["--compare"]:
        raw = sys.stdin.read().strip()
        if not raw:
            print(
                "✗ CANNOT DETERMINE — the live dump is EMPTY (the Neon read returned nothing)."
            )
            return 2
        try:
            have = json.loads(raw)
        except json.JSONDecodeError as e:
            print(f"✗ CANNOT DETERMINE — the live dump is not JSON: {e}")
            return 2
        if not isinstance(have, dict):
            print("✗ CANNOT DETERMINE — the live dump is not a JSON object.")
            return 2
        return compare(expected(), have)
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
