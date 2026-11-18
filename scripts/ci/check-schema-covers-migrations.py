#!/usr/bin/env python3
"""Every table and column the ClickHouse migrations leave behind must be in schema.sql.

WHY THIS EXISTS — B-555, 2026-10-25. A fresh install (dev compose, self-host) mounts
`infra/dev/clickhouse/schema.sql` (and its byte-identical self-host copy) into the init
directory and NEVER replays `migrations/`. Sixteen product tables — prompts, datasets,
eval runs, experiments, semantic_cache, online_eval_scores, … — and `spans.gateway_overhead_us`
existed only in migrations, so a fresh self-host had none of them. B-482 was the same
shape for one column. `check-self-host-schema-parity.py` only proves the two COPIES of
schema.sql match each other; whether either reflects the migrations was outside every
guard. This replays the migrations at the NAME level (CREATE / DROP / RENAME / EXCHANGE,
ADD / DROP COLUMN) and fails when a surviving table or added column is absent from schema.sql.

    check-schema-covers-migrations.py             # exit 0 iff schema.sql covers the migrations
    check-schema-covers-migrations.py --selftest  # plants a migration-only table and column, proves red

Static by design (runs in well under a second). The behavioural proof — load schema.sql
into a scratch ClickHouse and diff system.columns against prod — was done once by hand
on 2026-10-25 (0 missing, 0 extra).
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "infra/dev/clickhouse/schema.sql"
MIGRATIONS = ROOT / "infra/dev/clickhouse/migrations"

# Prod-only retained backups a fresh install must NOT create, each with its reason.
NOT_FOR_FRESH_INSTALL = {
    "audit_log_pre_rmt": "migration 11 keeps the pre-ReplacingMergeTree audit_log as a rollback copy",
}

NAME = r"(?:`?tracelane`?\.)?`?([A-Za-z0-9_]+)`?"


def strip_comments(sql: str) -> str:
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    return re.sub(r"--[^\n]*", " ", sql)


def statements(sql: str) -> list[str]:
    return [s.strip() for s in strip_comments(sql).split(";") if s.strip()]


def inline_columns(create: str) -> set[str]:
    """Column names declared inside a CREATE TABLE's first parenthesised list."""
    start = create.find("(")
    if start < 0 or re.match(r"[^(]*\bAS\b", create[:start], re.IGNORECASE):
        return set()
    depth, items, cur = 0, [], []
    for ch in create[start + 1 :]:
        if ch == "(":
            depth += 1
        elif ch == ")":
            if depth == 0:
                break
            depth -= 1
        if ch == "," and depth == 0:
            items.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    items.append("".join(cur))
    cols = set()
    for item in items:
        m = re.match(r"\s*`?([A-Za-z_][A-Za-z0-9_]*)`?\s+\S", item)
        if m and m.group(1).upper() not in {"INDEX", "PROJECTION", "CONSTRAINT"}:
            cols.add(m.group(1))
    return cols


def replay(migration_texts: list[str]) -> tuple[set[str], dict[str, set[str]]]:
    """Return (surviving object names, {table: columns added by ALTER and not dropped})."""
    objects: set[str] = set()
    added: dict[str, set[str]] = {}
    for text in migration_texts:
        for st in statements(text):
            up = st.upper()
            if m := re.match(
                rf"CREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|(?:MATERIALIZED\s+)?VIEW|DICTIONARY)\s+(?:IF\s+NOT\s+EXISTS\s+)?{NAME}",
                st,
                re.IGNORECASE,
            ):
                objects.add(m.group(1))
                if re.match(r"CREATE\s+(?:OR\s+REPLACE\s+)?TABLE", st, re.IGNORECASE):
                    # A migration-created table: its inline columns count too.
                    added[m.group(1)] = inline_columns(st)
            elif m := re.match(
                rf"DROP\s+(?:TABLE|VIEW|DICTIONARY)\s+(?:IF\s+EXISTS\s+)?{NAME}",
                st,
                re.IGNORECASE,
            ):
                objects.discard(m.group(1))
                added.pop(m.group(1), None)
            elif up.startswith("RENAME TABLE"):
                for a, b in re.findall(
                    rf"{NAME}\s+TO\s+{NAME}", st[len("RENAME TABLE") :], re.IGNORECASE
                ):
                    if a in objects:
                        objects.discard(a)
                    objects.add(b)
                    if a in added:
                        added[b] = added.pop(a)
            elif m := re.match(
                rf"EXCHANGE\s+TABLES\s+{NAME}\s+AND\s+{NAME}", st, re.IGNORECASE
            ):
                # Both names survive but swap definitions: spans became the rebuilt
                # spans_v2 (migration 22), so columns ALTERed onto the old one went with it.
                a, b = m.group(1), m.group(2)
                added[a], added[b] = added.pop(b, set()), added.pop(a, set())
            elif m := re.match(rf"ALTER\s+TABLE\s+{NAME}", st, re.IGNORECASE):
                table = m.group(1)
                for col in re.findall(
                    r"ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([A-Za-z0-9_]+)`?",
                    st,
                    re.IGNORECASE,
                ):
                    added.setdefault(table, set()).add(col)
                for col in re.findall(
                    r"DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?`?([A-Za-z0-9_]+)`?",
                    st,
                    re.IGNORECASE,
                ):
                    added.get(table, set()).discard(col)
    return objects, added


def schema_blocks(schema_sql: str) -> dict[str, str]:
    """{object name: its CREATE statement text} from schema.sql."""
    out: dict[str, str] = {}
    for st in statements(schema_sql):
        if m := re.match(
            rf"CREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|(?:MATERIALIZED\s+)?VIEW|DICTIONARY)\s+(?:IF\s+NOT\s+EXISTS\s+)?{NAME}",
            st,
            re.IGNORECASE,
        ):
            out[m.group(1)] = st
    return out


def check(schema_sql: str, migration_texts: list[str]) -> list[str]:
    objects, added = replay(migration_texts)
    blocks = schema_blocks(schema_sql)
    problems = []
    for name in sorted(objects - set(blocks) - set(NOT_FOR_FRESH_INSTALL)):
        problems.append(
            f"table/view `{name}` is created by a migration but absent from schema.sql"
        )
    for table, cols in sorted(added.items()):
        if table in NOT_FOR_FRESH_INSTALL or (
            table not in objects and table not in blocks
        ):
            continue
        body = blocks.get(table, "")
        for col in sorted(cols):
            if (
                not re.search(rf"(?m)^\s*`?{re.escape(col)}`?\s", body)
                and f"`{col}`" not in body
            ):
                problems.append(
                    f"column `{table}.{col}` is added by a migration but absent from schema.sql"
                )
    return problems


def load() -> tuple[str, list[str]]:
    return SCHEMA.read_text(), [p.read_text() for p in sorted(MIGRATIONS.glob("*.sql"))]


def selftest() -> int:
    for args in (["--tracelane-unknown"], ["--selftest", "--tracelane-unknown"]):
        # Run the parser only: even --selftest must reject an unknown flag.
        result = subprocess.run(
            [sys.executable, __file__, *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if result.returncode != 2 or "unrecognized arguments" not in result.stderr:
            print(f"SELFTEST FAILED — unknown arguments accepted: {args}")
            return 1
    schema_sql, migs = load()
    if check(schema_sql, migs):
        print("SELFTEST FAILED — the real tree must be clean before planting")
        return 1
    plants = {
        "migration-only table": migs
        + [
            "CREATE TABLE IF NOT EXISTS tracelane.zz_selftest (a UInt8) ENGINE = Memory;"
        ],
        "migration-only column": migs
        + [
            "ALTER TABLE tracelane.spans ADD COLUMN IF NOT EXISTS zz_selftest_col UInt8;"
        ],
    }
    for label, planted in plants.items():
        if not check(schema_sql, planted):
            print(f"SELFTEST FAILED — a planted {label} was not reported")
            return 1
    # A table created then dropped, and a renamed-away name, must NOT be reported.
    benign = migs + [
        "CREATE TABLE tracelane.zz_tmp (a UInt8) ENGINE = Memory;",
        "DROP TABLE IF EXISTS tracelane.zz_tmp;",
    ]
    if check(schema_sql, benign):
        print("SELFTEST FAILED — a created-then-dropped table was reported")
        return 1
    print(
        "SELFTEST OK — planted table and column are RED; created-then-dropped is green"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        return selftest()
    problems = check(*load())
    if problems:
        print("schema.sql does not cover the migrations — a FRESH install would lack:")
        for p in problems:
            print(f"  ✗ {p}")
        print(
            "Fix: add the final DDL to infra/dev/clickhouse/schema.sql, then\n"
            "     cp infra/dev/clickhouse/schema.sql infra/self-host/clickhouse/schema.sql"
        )
        return 1
    print("schema.sql covers every table and column the migrations leave behind ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main())
