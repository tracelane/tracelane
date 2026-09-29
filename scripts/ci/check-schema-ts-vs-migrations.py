#!/usr/bin/env python3
"""check-schema-ts-vs-migrations.py — the Drizzle schema must agree with the migrations.

B-446 (2026-09-19, found by the ADR-077 design wave). CLAUDE.md §5 names
`apps/web/db/schema.ts` canonical for control-plane Postgres, and the hand-written
migrations under `apps/web/db/migrations/` are what actually reaches Neon (0009+ are
un-journaled and applied by file glob). The two had drifted in BOTH directions:

  * `audit_chain_state.tenant_id` in schema.ts still carried
    `.references(() => tenants.id, { onDelete: "cascade" })` — migration
    `0018_audit_chain_state_retain_beyond_tenant.sql` DROPPED that FK so the ledger head
    survives a tenant purge (ADR-068). A `drizzle-kit generate` from schema.ts would have
    re-added the cascade and silently defeated retention.
  * `audit_appended` (0020) and `tool_capabilities` (0016) exist in Neon and are read by
    the gateway, and schema.ts did not declare either.

`scripts/ops/check-db-drift.py` compares the MIGRATIONS to LIVE Neon and was green — it
cannot see this class, because schema.ts is on neither side of that comparison. This guard
is the third leg: schema.ts vs the migration-derived tree, reusing the drift tool's own
migration replay so there is ONE parser of the SQL.

WHAT THIS PROVES
  1. every table the migrations leave standing is declared in schema.ts, and vice versa;
  2. no `.references(...)` in schema.ts names a foreign key a migration has DROPPED
     (`ALTER TABLE <t> DROP CONSTRAINT IF EXISTS <t>_<col>_fkey`).

HONEST LIMIT: column-level parity and check constraints are the drift tool's job against
live Neon; this guard reads table names and FK references only. Drizzle's own FK naming
(`<t>_<col>_<ref>_fk`) differs from Postgres's auto-name (`<t>_<col>_fkey`) — the check
keys on the Postgres name the migrations use, because that is the string a DROP names.

Usage:
  check-schema-ts-vs-migrations.py            # gate: exit 1 on any drift
  check-schema-ts-vs-migrations.py --selftest # plant each drift, prove it blocks; clean passes
"""

from __future__ import annotations

import importlib.util
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_TS = ROOT / "apps/web/db/schema.ts"
MIGRATIONS = ROOT / "apps/web/db/migrations"
DRIFT_TOOL = ROOT / "scripts/ops/check-db-drift.py"

RE_TABLE = re.compile(r'pgTable\(\s*"([a-z_]+)"')
RE_DROP_FK = re.compile(
    r"ALTER\s+TABLE\s+\"?([a-z_]+)\"?\s+DROP\s+CONSTRAINT\s+(?:IF\s+EXISTS\s+)?\"?([a-z_]+)\"?",
    re.IGNORECASE,
)
RE_ADD_FK = re.compile(
    r"ALTER\s+TABLE\s+\"?([a-z_]+)\"?\s+ADD\s+CONSTRAINT\s+\"?([a-z_]+)\"?\s+FOREIGN\s+KEY",
    re.IGNORECASE,
)


def _drift_module():
    spec = importlib.util.spec_from_file_location("check_db_drift", DRIFT_TOOL)
    assert spec is not None and spec.loader is not None, f"cannot load {DRIFT_TOOL}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def migration_tables(migrations: Path) -> set[str]:
    """Tables the migrations leave standing, via the drift tool's replay."""
    mod = _drift_module()
    declared = mod.replay(sorted(migrations.glob("*.sql")))
    return {
        name for name, rel in declared.relations.items() if rel.get("kind") == "table"
    }


def dropped_fks(migrations: Path) -> set[str]:
    """Constraint names DROPped by a migration and not re-ADDed by a later one."""
    dropped: set[str] = set()
    for f in sorted(migrations.glob("*.sql")):
        sql = f.read_text()
        for _, name in RE_DROP_FK.findall(sql):
            dropped.add(name.lower())
        for _, name in RE_ADD_FK.findall(sql):
            dropped.discard(name.lower())
    return dropped


def schema_tables(ts: str) -> set[str]:
    return set(RE_TABLE.findall(ts))


def schema_fk_names(ts: str) -> list[tuple[str, str, str]]:
    """(table, column, postgres_fkey_name) for every `.references(` in schema.ts.

    The column is the nearest preceding `<builder>("<col>")` call; the table is the
    nearest preceding `pgTable("<t>"`. Both are how Drizzle spells them today.
    """
    out = []
    for m in re.finditer(r"\.references\(", ts):
        before = ts[: m.start()]
        t = RE_TABLE.findall(before)
        c = re.findall(r'\b[a-zA-Z]+\(\s*"([a-z_]+)"', before)
        if not t or not c:
            continue
        table, col = t[-1], c[-1]
        out.append((table, col, f"{table}_{col}_fkey"))
    return out


def check(ts_text: str, migrations: Path) -> list[str]:
    problems: list[str] = []
    mig = migration_tables(migrations)
    sch = schema_tables(ts_text)
    for t in sorted(mig - sch):
        problems.append(
            f"table `{t}` exists in the migrations (and Neon) but schema.ts does not declare it"
        )
    for t in sorted(sch - mig):
        problems.append(
            f"table `{t}` is declared in schema.ts but no migration creates it"
        )
    dropped = dropped_fks(migrations)
    for table, col, fkey in schema_fk_names(ts_text):
        if fkey in dropped:
            problems.append(
                f"schema.ts `{table}.{col}` still carries `.references(...)` but a migration DROPPED `{fkey}` — "
                f"a drizzle-kit regeneration would re-add it"
            )
    return problems


def selftest() -> int:
    fails = 0
    real = SCHEMA_TS.read_text()
    clean = check(real, MIGRATIONS)
    if clean:
        print("  ✗ the real tree has drift — fix it before trusting this guard:")
        for p in clean:
            print(f"      {p}")
        fails += 1
    else:
        print("  ✓ the real schema.ts agrees with the migrations")
    # 1. a table the migrations create but schema.ts drops → blocks
    # Drizzle spells multi-column tables `pgTable(\n\t"name",` — plant through the same regex
    # the check reads with, and REFUSE a plant that did not land (a mutation that silently
    # fails to apply is a selftest that passes by doing nothing — run-clickhouse-integration.sh
    # learned that one the expensive way).
    mutated = re.sub(
        r'pgTable\(\s*"webhook_events"',
        lambda m: m.group(0).replace("webhook_events", "webhook_events_renamed"),
        real,
        count=1,
    )
    if mutated == real:
        print(
            "  ✗ CANNOT DETERMINE: the webhook_events plant did not land in schema.ts"
        )
        return 1
    probs = check(mutated, MIGRATIONS)
    if any("webhook_events" in p and "does not declare" in p for p in probs) and any(
        "webhook_events_renamed" in p for p in probs
    ):
        print("  ✓ a table missing from schema.ts (and one it invents) BLOCKS")
    else:
        print(f"  ✗ table drift not caught: {probs}")
        fails += 1
    # 2. a reference to a dropped FK → blocks
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        for f in MIGRATIONS.glob("*.sql"):
            (d / f.name).write_text(f.read_text())
        (d / "9999_plant.sql").write_text(
            'ALTER TABLE "api_keys" DROP CONSTRAINT IF EXISTS api_keys_tenant_id_fkey;\n'
        )
        probs = check(real, d)
        if any("api_keys.tenant_id" in p and "DROPPED" in p for p in probs):
            print("  ✓ a `.references()` whose FK a migration dropped BLOCKS")
        else:
            print(f"  ✗ dropped-FK drift not caught: {probs}")
            fails += 1
    if fails == 0:
        print("schema-ts-vs-migrations selftest PASSED.")
        return 0
    print(f"schema-ts-vs-migrations selftest FAILED — {fails} case(s).")
    return 1


def main() -> int:
    args = sys.argv[1:]
    if args == ["--selftest"]:
        return selftest()
    if args:
        # The meta-gate (check-guard-selftests.py) requires a nonsense flag to be REFUSED —
        # a script that exits 0 for anything cannot prove `--selftest` meant anything.
        print(
            f"usage: {Path(__file__).name} [--selftest]  (unknown argument: {' '.join(args)})",
            file=sys.stderr,
        )
        return 2
    problems = check(SCHEMA_TS.read_text(), MIGRATIONS)
    if problems:
        print(f"FAIL — schema.ts vs migrations: {len(problems)} problem(s)")
        for p in problems:
            print(f"  ✗ {p}")
        print(
            "  Fix schema.ts (CLAUDE.md §5: it is canonical) or write the migration — never route around it."
        )
        return 1
    print(
        f"OK — schema.ts declares exactly the {len(schema_tables(SCHEMA_TS.read_text()))} tables the migrations leave standing; no reference to a dropped FK."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
