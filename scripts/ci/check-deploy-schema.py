#!/usr/bin/env python3
"""A deploy REFUSES when the binary reads a schema the target database does not have.

WHY THIS EXISTS — 2026-08-22 produced BOTH halves of this in one night, which is why it
is one refusal with two sources rather than two guards.

  * POSTGRES. The gateway deployed with an entitlement SELECT naming four columns
    (`f_datasets`, `f_experiments`, `f_online_evals`, `f_annotation_queues`) that did not
    exist in prod Neon. Every chat request logged "entitlement resolve failed with no
    last-known grant" and paid a failed round trip: overhead 1.40 -> 17.19 ms, ~12x, for
    4m52s. RCA: `runbooks/RCA-evl04-entitlement-outage-schema-before-binary.md`.
  * CLICKHOUSE. The same sprint deployed `/v1/datasets*` against SIX tables that had never
    been created, because ClickHouse migrations here are applied BY HAND, per file. Every
    dataset call would have failed at the query rather than at a typed refusal.

`CLAUDE.md` §4.0 already states the rule — *"Ordered, not parallel — the column lands in
Neon BEFORE the gateway that reads it deploys"* — and the commit that broke production
QUOTED THAT SENTENCE IN A COMMENT THREE LINES ABOVE THE CHANGE. A rule that can be cited
and violated in one edit has no consumer. This is the consumer.
(`docs/reference/TRAPS.md` §44.)

IT DOES NOT AUTO-APPLY, DELIBERATELY. Hand-application is the repo's chosen posture for
un-journaled migrations (`CLAUDE.md` §5): a human decides when a column lands, because the
ordering constraint is the point. This refuses, names the file, and prints the command.

── THE SPLIT, and it is what makes the logic testable ──────────────────────────
`--expected` answers "what does the CODE require?" — pure, offline, no database.
`--compare` answers "does the TARGET have it?" — takes the target's actual schema as JSON
on stdin, so the half that needs credentials is the deploy script's job and the half that
needs judgement is covered by `--selftest`.

USAGE
  check-deploy-schema.py --expected                 # JSON: what the code requires
  check-deploy-schema.py --compare < actual.json    # refuse on any gap
  check-deploy-schema.py --selftest                 # prove it BLOCKS
EXIT 0 satisfied · 1 the target is missing something the code reads · 2 could not determine
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
ENTITLEMENTS = ROOT / "crates/gateway/src/entitlement_cache.rs"
CH_MIGRATIONS = ROOT / "infra/dev/clickhouse/migrations"

# `Self::Datasets => "f_datasets",` — the `column()` mapping IS the authoritative list of
# what the resolver selects. Deriving the requirement from the enum rather than from the
# SQL string is deliberate: the SQL is built by concatenation across two queries, and a
# regex over it would miss exactly the case that broke us (a column added to one and not
# the other).
_COLUMN_ARM = re.compile(r'Self::\w+\s*=>\s*"(f_\w+)"')
# What the gateway actually queries: `FROM tbl`, `INSERT INTO tbl`, `insert("tbl")`.
# The optional `tracelane.` prefix is stripped for the same reason as above.
# Columns the resolver SELECT actually names: `COALESCE(we.f_x, pe.f_x) AS f_x` and the
# bare `f_x,` list in the plan-only query.
_SELECTED_COL = re.compile(
    r"\bAS\s+(f_\w+)|^\s*(?:COALESCE\()?(?:pe\.|we\.)?(f_\w+)\s*,", re.MULTILINE
)
_CH_FROM = re.compile(r"\bFROM\s+(?:tracelane\.)?(\w+)", re.IGNORECASE)
_CH_INSERT = re.compile(
    r'(?:INSERT\s+INTO\s+|\.insert\(")(?:tracelane\.)?(\w+)', re.IGNORECASE
)
# `CREATE TABLE [IF NOT EXISTS] [db.]table` — the OPTIONAL DATABASE PREFIX is the whole
# reason this is not a two-token regex. The first version captured `tracelane` out of
# `CREATE TABLE tracelane.slo_alerts` and then reported a table called "tracelane" as
# missing from prod — a FALSE REFUSAL that would have blocked every deploy. Caught by
# running the guard against the real prod schema rather than only its own selftest, which
# is exactly what the founder's ruling asked for.
_CREATE_TABLE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:`?\w+`?\.)?`?(\w+)`?", re.IGNORECASE
)


# `infra/dev/clickhouse/schema.sql` is the BASE CONTRACT — the DDL a fresh install gets
# through `/docker-entrypoint-initdb.d`. Its columns are the ones every environment is
# supposed to have, which makes them the honest thing to require of a target.
CH_SCHEMA = ROOT / "infra/dev/clickhouse/schema.sql"


def _columns_of(sql: str) -> dict[str, list[str]]:
    """`{table: [column, ...]}` from CREATE TABLE blocks, by paren depth.

    Depth, not a line regex, because a column's TYPE carries its own parens —
    `DateTime64(6, 'UTC')`, `Nullable(String)`, `Array(String)`. A regex that ignored
    them would either stop at the first `)` (truncating the table) or run past the last
    one (swallowing the ENGINE clause and reporting `ORDER` as a column).
    """
    out: dict[str, list[str]] = {}
    for m in _CREATE_TABLE.finditer(sql):
        table = m.group(1)
        i = sql.find("(", m.end())
        if i == -1:
            continue
        depth, j = 0, i
        while j < len(sql):
            if sql[j] == "(":
                depth += 1
            elif sql[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        body, cols, d = sql[i + 1 : j], [], 0
        for raw in body.split("\n"):
            line = raw.split("--", 1)[0].strip()
            if d == 0 and line:
                c = re.match(r"^`?(\w+)`?\s+\S", line)
                # Skip table-level clauses that share the column position.
                if c and c.group(1).upper() not in {
                    "INDEX",
                    "PRIMARY",
                    "ORDER",
                    "PARTITION",
                    "TTL",
                    "SETTINGS",
                    "ENGINE",
                    "CONSTRAINT",
                    "PROJECTION",
                }:
                    cols.append(c.group(1))
            d += raw.count("(") - raw.count(")")
        if cols:
            out.setdefault(table, cols)
    return out


def expected() -> dict:
    """What the code requires of its databases. Pure — reads the tree, nothing else."""
    if not ENTITLEMENTS.is_file():
        print(f"✗ CANNOT DETERMINE — {ENTITLEMENTS} not found", file=sys.stderr)
        raise SystemExit(2)
    # THE FeatureKey MAPPING IS NOT THE WHOLE READ, and assuming it was left a blind
    # spot: `f_full_capture` is SELECTed by the resolver and has NO `FeatureKey` variant,
    # so deriving the requirement from the enum alone would have missed exactly the class
    # of outage this guard exists for. Union the enum with the columns the SELECT actually
    # names — the SELECT is the read, the enum is only one caller of it.
    src = ENTITLEMENTS.read_text(encoding="utf-8")
    cols = set(_COLUMN_ARM.findall(src)) | {
        g for t in _SELECTED_COL.findall(src) for g in t if g
    }
    cols = sorted(cols)
    if not cols:
        # A vocabulary that reads as empty would make this guard certify everything.
        # An empty result here is a parse failure, not a clean bill of health.
        print(
            "✗ CANNOT DETERMINE — no f_* columns parsed from the FeatureKey mapping",
            file=sys.stderr,
        )
        raise SystemExit(2)

    # WHICH TABLES DOES THE BINARY ACTUALLY READ? Not "every table any migration ever
    # defined" — that was this guard's first shape and it REFUSED A HEALTHY PROD, naming
    # `slo_alerts`, `slo_minute_stats`, `token_economics` and `ttft_stats`. Those are real
    # repo-vs-prod drift (seven such tables exist) but NOTHING IN THE GATEWAY READS THEM,
    # so blocking a deploy on them is a guard that fires on a condition the deployer
    # cannot act on — and a guard that always fires is one that gets switched off.
    #
    # So the requirement is the INTERSECTION: a table must be defined by a migration AND
    # referenced by gateway code. That ties the check to its own sentence — "the schema
    # this binary reads" — and it self-maintains: a new `FROM foo` starts requiring `foo`
    # the moment it is written.
    defined: dict[str, str] = {}
    for f in sorted(CH_MIGRATIONS.glob("*.sql")):
        for t in _CREATE_TABLE.findall(f.read_text(encoding="utf-8")):
            defined.setdefault(t, f.name)

    referenced: set[str] = set()
    for rs in (ROOT / "crates").rglob("*.rs"):
        if "/target/" in str(rs):
            continue
        txt = rs.read_text(encoding="utf-8", errors="replace")
        referenced |= set(_CH_FROM.findall(txt))
        referenced |= set(_CH_INSERT.findall(txt))
    tables = {t: f for t, f in defined.items() if t in referenced}
    if not tables:
        print(
            "✗ CANNOT DETERMINE — no migration-defined table is referenced by any Rust "
            "source; the reference scan is broken, and an empty requirement would "
            "certify anything.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    if not tables:
        print(
            f"✗ CANNOT DETERMINE — no CREATE TABLE found under {CH_MIGRATIONS}",
            file=sys.stderr,
        )
        raise SystemExit(2)

    # COLUMNS, not just tables (B-369). The table check cannot see a column that never
    # landed, and one did not: migration 04 adds eight MATERIALIZED columns to `spans`
    # and PROD HAS NONE OF THEM, while migrations 13 and 16 — both later — were applied.
    # Read from prod `system.columns` on 2026-09-10, not inferred.
    #
    # The requirement is `schema.sql`'s columns, NOT every column every migration ever
    # added, and that boundary is deliberate for the same reason the table check uses an
    # intersection: migration-only columns are known drift with zero readers, and a guard
    # that fires on a condition the deployer will not act on is a guard that gets switched
    # off. schema.sql is what a FRESH install gets, so every environment owes it.
    ch_cols: dict[str, list[str]] = {}
    if CH_SCHEMA.is_file():
        for t, c in _columns_of(CH_SCHEMA.read_text(encoding="utf-8")).items():
            if t in referenced:
                ch_cols[t] = c
    if not ch_cols:
        print(
            "✗ CANNOT DETERMINE — no columns parsed from "
            f"{CH_SCHEMA}; an empty column requirement would certify anything.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    return {
        "postgres_columns": cols,
        "postgres_tables": ["plan_entitlements", "workspace_entitlements"],
        "clickhouse_tables": dict(sorted(tables.items())),
        "clickhouse_columns": {k: sorted(v) for k, v in sorted(ch_cols.items())},
    }


def compare(want: dict, have: dict) -> int:
    """Refuse on any gap. `have` is the TARGET's actual schema."""
    problems: list[str] = []

    have_pg = have.get("postgres_columns")
    if have_pg is None:
        print("✗ CANNOT DETERMINE — target reported no postgres_columns at all.")
        print("  An unread database is not a clean database (CLAUDE.md §1).")
        return 2
    for tbl in want["postgres_tables"]:
        present = set(have_pg.get(tbl, []))
        missing = [c for c in want["postgres_columns"] if c not in present]
        if missing:
            problems.append(
                f"  POSTGRES {tbl}: missing {', '.join(missing)}\n"
                f"    the gateway's entitlement resolver SELECTs these. Deploying without\n"
                f"    them fails the resolve on EVERY request and denies all features.\n"
                f'    apply:  psql "$POSTGRES_DIRECT_URL" -v ON_ERROR_STOP=1 \\\n'
                f"              -f apps/web/db/migrations/<the migration that adds them>.sql"
            )

    have_ch = have.get("clickhouse_tables")
    if have_ch is None:
        print("✗ CANNOT DETERMINE — target reported no clickhouse_tables at all.")
        return 2
    have_ch_set = set(have_ch)
    missing_ch = {
        t: f for t, f in want["clickhouse_tables"].items() if t not in have_ch_set
    }
    if missing_ch:
        by_file: dict[str, list[str]] = {}
        for t, f in missing_ch.items():
            by_file.setdefault(f, []).append(t)
        for f, ts in sorted(by_file.items()):
            problems.append(
                f"  CLICKHOUSE: {len(ts)} table(s) from {f} are absent — {', '.join(sorted(ts))}\n"
                f"    routes are mounted against them and would fail at the QUERY rather\n"
                f"    than at a typed refusal.\n"
                f"    apply BY HAND (deliberate — see the header):\n"
                f"      infra/dev/clickhouse/migrations/{f}"
            )

    # B-369 — COLUMNS. `have_ch_cols` absent means the target was asked for tables only
    # (an older deploy script). That is CANNOT DETERMINE, not a pass: an unread column
    # set is not a clean one, and silently skipping it is how migration 04 went unapplied
    # for months without any control noticing.
    want_ch_cols = want.get("clickhouse_columns") or {}
    if want_ch_cols:
        have_ch_cols = have.get("clickhouse_columns")
        if have_ch_cols is None:
            print(
                "✗ CANNOT DETERMINE — the target reported TABLES but no clickhouse_columns.\n"
                "  The deploy script must send `system.columns` too; see scripts/deploy/gateway.sh.\n"
                "  An unread column set is not a clean one (CLAUDE.md §1)."
            )
            return 2
        for tbl, cols in want_ch_cols.items():
            # A table already reported missing above is not also a column complaint —
            # that would print the same defect twice and bury the actionable line.
            if tbl not in have_ch_set:
                continue
            present = set(have_ch_cols.get(tbl, []))
            missing = [c for c in cols if c not in present]
            if missing:
                problems.append(
                    f"  CLICKHOUSE {tbl}: missing column(s) {', '.join(missing)}\n"
                    f"    `infra/dev/clickhouse/schema.sql` declares them, so a FRESH install\n"
                    f"    has them and this target does not. That is un-journaled migration\n"
                    f"    drift — the B-369 class, where migration 04's eight columns were\n"
                    f"    never applied to prod while 13 and 16 were.\n"
                    f"    apply BY HAND:  ALTER TABLE tracelane.{tbl} ADD COLUMN ..."
                )

    if problems:
        print("✗ THE TARGET DOES NOT HAVE THE SCHEMA THIS BINARY READS:\n")
        print("\n\n".join(problems))
        print(
            "\n  This is the ordering CLAUDE.md §4.0 requires: the schema lands FIRST,\n"
            "  then the binary that reads it. Apply the above, then deploy again."
        )
        return 1

    print(
        f"OK — target has all {len(want['postgres_columns'])} entitlement column(s), "
        f"all {len(want['clickhouse_tables'])} ClickHouse table(s) the code reads, and "
        f"every column `schema.sql` declares for "
        f"{len(want.get('clickhouse_columns') or {})} of them."
    )
    print(
        "  NOTE: the column check covers what `schema.sql` declares — the base contract a\n"
        "  fresh install gets. Columns added ONLY by a migration file are deliberately out\n"
        "  of scope; they are known drift with no readers, and requiring them would refuse\n"
        "  a healthy prod."
    )
    return 0


def selftest() -> int:
    fails = 0

    def case(label: str, want: dict, have: dict, expect_rc: int) -> None:
        nonlocal fails
        rc = compare(want, have)
        if rc == expect_rc:
            print(f"  ✓ {label}")
        else:
            print(f"  ✗ {label} — expected rc={expect_rc}, got {rc}")
            fails += 1

    want = {
        "postgres_columns": ["f_alerts", "f_datasets"],
        "postgres_tables": ["plan_entitlements", "workspace_entitlements"],
        "clickhouse_tables": {"datasets": "18_datasets.sql", "spans": "01_core.sql"},
    }
    full = {
        "postgres_columns": {
            "plan_entitlements": ["f_alerts", "f_datasets"],
            "workspace_entitlements": ["f_alerts", "f_datasets"],
        },
        "clickhouse_tables": ["datasets", "spans"],
    }
    case("a fully-migrated target passes", want, full, 0)

    # TONIGHT'S EXACT CASE: revert 0030 — the column is gone from BOTH tables.
    no_col = json.loads(json.dumps(full))
    for t in no_col["postgres_columns"]:
        no_col["postgres_columns"][t] = ["f_alerts"]
    case("a MISSING postgres column REFUSES (the 2026-08-22 outage)", want, no_col, 1)

    # Missing on ONE table only — the asymmetry that a single-table check would miss.
    one_side = json.loads(json.dumps(full))
    one_side["postgres_columns"]["workspace_entitlements"] = ["f_alerts"]
    case("missing on ONE table only still REFUSES", want, one_side, 1)

    # TONIGHT'S OTHER CASE: migration 18 never applied.
    no_tbl = json.loads(json.dumps(full))
    no_tbl["clickhouse_tables"] = ["spans"]
    case(
        "a MISSING clickhouse table REFUSES (item 8's six absent tables)",
        want,
        no_tbl,
        1,
    )

    # CANNOT DETERMINE is not a pass — the failure mode that would make this decorative.
    case(
        "a target that reported NO postgres schema is rc=2, not 0",
        want,
        {"clickhouse_tables": []},
        2,
    )
    case(
        "a target that reported NO clickhouse schema is rc=2, not 0",
        want,
        {"postgres_columns": full["postgres_columns"]},
        2,
    )

    # The db-qualified form. This is the false-REFUSAL that a synthetic selftest missed
    # and a real-schema run caught: `CREATE TABLE tracelane.slo_alerts` must yield
    # `slo_alerts`, never `tracelane`.
    got = _CREATE_TABLE.findall(
        "CREATE TABLE tracelane.slo_alerts (a UInt8);\n"
        "CREATE TABLE IF NOT EXISTS `tracelane`.`spans` (b UInt8);\n"
        "CREATE TABLE plain_one (c UInt8);"
    )
    if got == ["slo_alerts", "spans", "plain_one"]:
        print("  ✓ a db-qualified CREATE TABLE yields the TABLE, not the database")
    else:
        print(f"  ✗ db-qualified parse wrong: {got}")
        fails += 1

    # ── B-369: the COLUMN check, proven to BLOCK ───────────────────────────────
    _base_want = {
        "postgres_columns": ["f_x"],
        "postgres_tables": ["plan_entitlements"],
        "clickhouse_tables": {"spans": "schema.sql"},
        "clickhouse_columns": {"spans": ["tenant_id", "api_key_id", "cost_usd"]},
    }
    case(
        "a MISSING clickhouse COLUMN refuses (the migration-04 class)",
        _base_want,
        {
            "postgres_columns": {"plan_entitlements": ["f_x"]},
            "clickhouse_tables": ["spans"],
            # `cost_usd` absent — exactly the shape of migration 04's unapplied columns.
            "clickhouse_columns": {"spans": ["tenant_id", "api_key_id"]},
        },
        1,
    )
    case(
        "all columns present PASSES",
        _base_want,
        {
            "postgres_columns": {"plan_entitlements": ["f_x"]},
            "clickhouse_tables": ["spans"],
            "clickhouse_columns": {
                "spans": ["tenant_id", "api_key_id", "cost_usd", "extra_ok"]
            },
        },
        0,
    )
    case(
        "a target reporting TABLES but NO columns is rc=2, never a pass",
        _base_want,
        {
            "postgres_columns": {"plan_entitlements": ["f_x"]},
            "clickhouse_tables": ["spans"],
        },
        2,
    )
    case(
        "a missing TABLE is reported once, not also as N missing columns",
        _base_want,
        {
            "postgres_columns": {"plan_entitlements": ["f_x"]},
            "clickhouse_tables": [],
            "clickhouse_columns": {},
        },
        1,
    )

    # And the pure half must actually parse the real tree, or the guard certifies nothing.
    try:
        real = expected()
    except SystemExit:
        print("  ✗ --expected raised on the real tree")
        fails += 1
        real = {"postgres_columns": [], "clickhouse_tables": {}}
    if len(real["postgres_columns"]) >= 4 and "f_datasets" in real["postgres_columns"]:
        print(
            f"  ✓ parses the real tree ({len(real['postgres_columns'])} columns, "
            f"{len(real['clickhouse_tables'])} tables)"
        )
    else:
        print(f"  ✗ real-tree parse looks wrong: {real['postgres_columns'][:6]}")
        fails += 1

    if fails == 0:
        print(
            "\nSELFTEST PASSED — both of 2026-08-22's failures REFUSE, a one-sided gap\n"
            "  refuses, and an unread target is CANNOT DETERMINE rather than a pass."
        )
        return 0
    print(f"\nSELFTEST FAILED — {fails} case(s).")
    return 1


def main() -> int:
    argv = sys.argv[1:]
    if argv == ["--selftest"]:
        return selftest()
    if argv == ["--expected"]:
        print(json.dumps(expected(), indent=2))
        return 0
    if argv == ["--compare"]:
        try:
            have = json.load(sys.stdin)
        except json.JSONDecodeError as e:
            print(f"✗ CANNOT DETERMINE — target schema is not JSON: {e}")
            return 2
        return compare(expected(), have)
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
