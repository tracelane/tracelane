#!/usr/bin/env python3
"""Report objects a migration DECLARES that the live database does not HAVE.

WHY (B-188, 2026-08-08). `infra/dev/postgres/migrations/14_full_capture_sampling.sql`
landed in production Frankfurt HALF-APPLIED: its columns (`tenants.sampling_policy`,
`force_tail`) exist, its `notify_tenant_config_changed()` function and
`trg_tenants_config_notify` trigger do not. Nothing recorded that. Migrations 0009+ are
un-journaled and hand-applied (CLAUDE.md rule 5), so there is no table saying which ran —
the only ground truth is the catalog itself.

If one migration half-landed silently, others may have. This enumerates every object the
migration files declare and asks the live catalog whether it is there.

USAGE
  # 1. on a host with DB access, dump the live catalog:
  #      audit-migration-drift.py --catalog-sql   > /tmp/cat.sql
  #      psql "$PG_URL" -tAF'|' -f /tmp/cat.sql   > /tmp/live.tsv
  # 2. anywhere:
  #      audit-migration-drift.py --live /tmp/live.tsv

HONEST LIMITS — read before trusting a clean result.
  * Regex parsing, not a SQL grammar. `CREATE TABLE`/`ADD COLUMN`/`CREATE INDEX`/
    `CREATE TRIGGER`/`CREATE FUNCTION`/`ADD CONSTRAINT` are recognised; anything
    expressed another way (DO blocks, dynamic SQL, `EXECUTE format(...)`) is INVISIBLE
    to this tool and will not be reported as missing.
  * It reports MISSING objects only. It does not detect a column whose TYPE drifted, a
    trigger rebound to a different function, or an object the DB has that no migration
    declares.
  * A DROP in a later migration is honoured, so an object created then dropped is not
    reported. An object RENAMED is reported missing under its old name.
  So: findings here are real, but "0 findings" is not proof of a fully-applied schema.

GATE (2026-08-09). This was reporting-only — it always returned 0, so nothing it found
could ever stop anything. It now EXITS 1 on any unacknowledged missing object.

Two mechanical false-positive classes were removed first, because a gate that cries wolf
is not a gate:
  1. **63-char identifier truncation.** Postgres truncates every identifier to
     `NAMEDATALEN-1` = 63 bytes. `workspace_entitlements_plan_lookup_key_plan_entitlements_plan_lookup_key_fk`
     (75 chars) is declared in full and lives as its 63-char prefix. Comparison now
     happens on the truncated form, so this whole class disappears.
  2. **Renames.** `infra/dev/postgres/migrations/` names indexes `idx_<table>_<col>`;
     Drizzle names them `<table>_<col>_idx`. Prod was built by Drizzle, so every
     dev-named index reads as "missing". A rename is INVISIBLE to this tool by
     construction — it cannot tell a rename from a deletion — so each one is recorded
     by hand in the acknowledgements file with the live name it maps to.

ACKNOWLEDGEMENTS — `scripts/ci/migration-drift-acknowledged.txt`. One line per accepted
absence, `kind|name|column|REASON`. An entry with no reason is refused: an override
without a record is not a control (B-167). `PENDING <YYYY-MM-DD>` entries EXPIRE — after
that date the gate fires again, so "founder-gated, not blocking" cannot quietly become
"forgotten forever".

USAGE (gate)
  audit-migration-drift.py --selftest              # prove it blocks — no DB needed
  audit-migration-drift.py --live /tmp/live.tsv    # exit 1 on unacknowledged drift
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MIGRATION_DIRS = ("apps/web/db/migrations", "infra/dev/postgres/migrations")
ACK_FILE = Path(__file__).resolve().parent / "migration-drift-acknowledged.txt"

# Postgres NAMEDATALEN-1. Every identifier longer than this is silently truncated on
# creation, so a declared 75-char constraint name can only ever exist as its 63-char
# prefix. Compare on the truncated form or that difference reads as a missing object.
PG_NAME_MAX = 63


def trunc(name: str) -> str:
    """Identifier as Postgres will actually have stored it."""
    return name[:PG_NAME_MAX]


def load_ack(path: Path) -> tuple[dict[tuple[str, str, str], str], list[str]]:
    """Accepted absences → reason. Returns (acks, errors).

    Format: `kind|name|column|REASON`. A missing or empty REASON is an error, not a
    silent pass — the whole point is that every suppression carries its justification.
    A `PENDING <YYYY-MM-DD>` reason expires on that date.
    """
    acks: dict[tuple[str, str, str], str] = {}
    errors: list[str] = []
    if not path.exists():
        return acks, errors
    today = _today()
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 4 or not parts[3]:
            errors.append(
                f"{path.name}:{lineno}: expected `kind|name|column|REASON`, got {raw!r}"
            )
            continue
        kind, name, col, reason = parts
        m = re.match(r"PENDING\s+(\d{4}-\d{2}-\d{2})\b", reason, re.IGNORECASE)
        if m and m.group(1) < today:
            errors.append(
                f"{path.name}:{lineno}: PENDING expired {m.group(1)} — apply the migration "
                f"or re-date the entry: {kind} {name}{'.' + col if col else ''}"
            )
            continue
        acks[(kind.lower(), trunc(name.lower()), col.lower())] = reason
    return acks, errors


def _today() -> str:
    # UTC, not local: a PENDING acknowledgement expires on a calendar date, and a
    # naive `date.today()` would expire it up to a day early or late depending on
    # which timezone the runner happens to be in. Also ruff DTZ011.
    import datetime

    return datetime.datetime.now(datetime.UTC).date().isoformat()


CATALOG_SQL = r"""
SELECT 'table', c.relname, '' FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='public' AND c.relkind IN ('r','p')
UNION ALL
SELECT 'column', table_name, column_name FROM information_schema.columns
  WHERE table_schema='public'
UNION ALL
SELECT 'index', indexname, '' FROM pg_indexes WHERE schemaname='public'
UNION ALL
SELECT 'trigger', tgname, '' FROM pg_trigger WHERE NOT tgisinternal
UNION ALL
SELECT 'function', proname, '' FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
  WHERE n.nspname='public'
UNION ALL
SELECT 'constraint', conname, '' FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace
  WHERE n.nspname='public';
"""

IDENT = r'"?([a-zA-Z_][a-zA-Z0-9_]*)"?'
RE_CREATE_TABLE = re.compile(
    rf"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?{IDENT}", re.IGNORECASE
)
RE_ADD_COLUMN = re.compile(
    rf"ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?(?:public\.)?{IDENT}"
    rf"[\s\S]{{0,200}}?ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?{IDENT}",
    re.IGNORECASE,
)
RE_CREATE_INDEX = re.compile(
    rf"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?{IDENT}",
    re.IGNORECASE,
)
RE_CREATE_TRIGGER = re.compile(
    rf"CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER\s+{IDENT}", re.IGNORECASE
)
RE_CREATE_FUNCTION = re.compile(
    rf"CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:public\.)?{IDENT}", re.IGNORECASE
)
RE_ADD_CONSTRAINT = re.compile(rf"ADD\s+CONSTRAINT\s+{IDENT}", re.IGNORECASE)
RE_DROP = re.compile(
    rf"DROP\s+(TABLE|INDEX|TRIGGER|FUNCTION|CONSTRAINT)\s+(?:IF\s+EXISTS\s+)?{IDENT}",
    re.IGNORECASE,
)


def strip_sql_comments(sql: str) -> str:
    sql = re.sub(r"/\*[\s\S]*?\*/", " ", sql)
    return re.sub(r"--[^\n]*", " ", sql)


def parse_migrations() -> list[tuple]:
    """Replay every statement IN ORDER and return what the schema should end up with.

    Order matters and getting it wrong hid the real finding. Migration 14 uses the
    idempotent `DROP TRIGGER IF EXISTS x; CREATE TRIGGER x;` pattern. A set-based
    "was it ever dropped?" test cancelled the CREATE and made
    `trg_tenants_config_notify` — the object B-188 is ABOUT — invisible to this
    audit. A drop only cancels declarations that came BEFORE it.
    """
    state: dict[tuple[str, str, str], str] = {}
    events: list[tuple] = []
    for d in MIGRATION_DIRS:
        for path in sorted((ROOT / d).glob("*.sql")):
            raw = strip_sql_comments(path.read_text(encoding="utf-8", errors="ignore"))
            rel = f"{d}/{path.name}"
            for m in RE_CREATE_TABLE.finditer(raw):
                events.append(
                    (m.start(), rel, "create", "table", m.group(1).lower(), "")
                )
            for m in RE_ADD_COLUMN.finditer(raw):
                events.append(
                    (
                        m.start(),
                        rel,
                        "create",
                        "column",
                        m.group(1).lower(),
                        m.group(2).lower(),
                    )
                )
            for m in RE_CREATE_INDEX.finditer(raw):
                events.append(
                    (m.start(), rel, "create", "index", m.group(1).lower(), "")
                )
            for m in RE_CREATE_TRIGGER.finditer(raw):
                events.append(
                    (m.start(), rel, "create", "trigger", m.group(1).lower(), "")
                )
            for m in RE_CREATE_FUNCTION.finditer(raw):
                events.append(
                    (m.start(), rel, "create", "function", m.group(1).lower(), "")
                )
            for m in RE_ADD_CONSTRAINT.finditer(raw):
                events.append(
                    (m.start(), rel, "create", "constraint", m.group(1).lower(), "")
                )
            for m in RE_DROP.finditer(raw):
                events.append(
                    (m.start(), rel, "drop", m.group(1).lower(), m.group(2).lower(), "")
                )

    # Sort by (file, offset) so statements replay in the order they would execute.
    for _pos, rel, action, kind, name, col in sorted(
        events, key=lambda e: (e[1], e[0])
    ):
        key = (kind, name, col)
        if action == "create":
            state[key] = rel
        else:
            state.pop(key, None)
            if kind == "table":  # dropping a table takes its columns with it
                for k in [k for k in state if k[0] == "column" and k[1] == name]:
                    state.pop(k, None)
    return [(k[0], k[1], k[2], src) for k, src in state.items()]


def load_live(path: Path) -> set[tuple[str, str, str]]:
    live: set[tuple[str, str, str]] = set()
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|")
        if len(parts) < 2:
            continue
        kind, name = parts[0].strip().lower(), parts[1].strip().lower()
        col = parts[2].strip().lower() if len(parts) > 2 else ""
        # Live names are already truncated by Postgres; trunc() here is a no-op that
        # keeps both sides of the comparison provably on the same normalisation.
        live.add((kind, trunc(name), col))
    return live


BLIND_SPOTS = """
WHAT A PASS DOES *NOT* PROVE — read before treating a clean run as a clean schema:
  * RENAMES are invisible. This tool cannot distinguish a renamed object from a deleted
    one; it only ever asks "is an object with this exact name present?". An object
    renamed in the database still reads as MISSING, and an object renamed in a migration
    reads as present under the old name. Every rename here is hand-recorded in
    scripts/ci/migration-drift-acknowledged.txt.
  * DO-blocks and dynamic SQL (`EXECUTE format(...)`) are not parsed at all, so objects
    created that way are never checked in either direction.
  * TYPE DRIFT is not checked — a column present with the wrong type passes.
  * A trigger REBOUND to a different function passes.
  * EXTRA objects the database has and no migration declares are not reported.
"""


def audit(
    live_path: Path, ack_path: Path = ACK_FILE
) -> tuple[int, list[tuple], list[str]]:
    """Returns (declared_count, unacknowledged_missing, ack_errors)."""
    declared = parse_migrations()
    live = load_live(live_path)
    acks, ack_errors = load_ack(ack_path)
    live_tables = {n for k, n, _ in live if k == "table"}

    missing: list[tuple] = []
    seen: set[tuple] = set()
    for kind, name, col, src in declared:
        key = (kind, trunc(name), col)
        seen.add(key)
        if kind == "column" and trunc(name) not in live_tables:
            continue  # the table itself is missing; reported once as a table finding
        if key not in live and key not in acks:
            missing.append((kind, name, col, src))
    return len(seen), missing, ack_errors


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--catalog-sql", action="store_true", help="print the catalog query and exit"
    )
    ap.add_argument(
        "--live", type=Path, help="TSV/pipe dump produced by the catalog query"
    )
    ap.add_argument(
        "--selftest", action="store_true", help="prove the gate blocks a planted drift"
    )
    args = ap.parse_args()

    if args.selftest:
        return selftest()
    if args.catalog_sql:
        print(CATALOG_SQL)
        return 0
    if not args.live:
        ap.error("--live is required (or --catalog-sql / --selftest)")

    declared_n, missing, ack_errors = audit(args.live)
    acks, _ = load_ack(ACK_FILE)

    print(f"declared objects parsed : {declared_n}")
    print(f"acknowledged absences   : {len(acks)}")
    print(f"UNACKNOWLEDGED missing  : {len(missing)}")

    for e in ack_errors:
        print(f"  ACK ERROR: {e}")
    if missing:
        by_kind: dict[str, int] = {}
        for kind, _, _, _ in missing:
            by_kind[kind] = by_kind.get(kind, 0) + 1
        print("  by kind: " + ", ".join(f"{k}={v}" for k, v in sorted(by_kind.items())))
        print("\nkind        object                              declared by")
        print("-" * 96)
        for kind, name, col, src in sorted(missing, key=lambda r: (r[3], r[0], r[1])):
            label = f"{name}.{col}" if col else name
            print(f"{kind:<11} {label:<35} {src}")
        print(
            "\nFAIL: the migration declares these objects and the live database does not "
            "have them.\nEither apply the migration, or — if the absence is correct — add a "
            "line with its\nreason to scripts/ci/migration-drift-acknowledged.txt."
        )
    print(BLIND_SPOTS)
    return 1 if (missing or ack_errors) else 0


def selftest() -> int:
    """Plant a drifted object and prove the gate blocks; prove a clean catalog passes."""
    import tempfile

    declared = parse_migrations()
    assert declared, "selftest cannot run: no migrations parsed"

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        empty_ack = td / "ack.txt"
        empty_ack.write_text("# none\n")

        # A catalog holding EVERY declared object → nothing missing → must PASS.
        full = td / "full.tsv"
        full.write_text(
            "".join(f"{k}|{trunc(n)}|{c}\n" for k, n, c, _ in declared),
            encoding="utf-8",
        )
        n, missing, errs = audit(full, empty_ack)
        assert not missing, f"selftest: complete catalog must pass, got {missing[:3]}"
        assert not errs, errs
        print(f"✓ selftest: complete catalog passes ({n} declared objects)")

        # Drop ONE declared object → must be reported → gate must FAIL.
        victim = declared[0]
        drifted = td / "drifted.tsv"
        drifted.write_text(
            "".join(
                f"{k}|{trunc(n)}|{c}\n"
                for k, n, c, _ in declared
                if (k, n, c) != (victim[0], victim[1], victim[2])
            ),
            encoding="utf-8",
        )
        _, missing, _ = audit(drifted, empty_ack)
        label = f"{victim[1]}.{victim[2]}" if victim[2] else victim[1]
        assert len(missing) == 1, (
            f"selftest: expected exactly 1 finding, got {len(missing)}"
        )
        assert missing[0][1] == victim[1], (
            f"selftest: wrong object reported: {missing[0]}"
        )
        print(f"✓ selftest: planted drift DETECTED and blocks ({victim[0]} {label})")

        # The same drift, acknowledged, must be suppressed — and ONLY that one.
        ack = td / "ack2.txt"
        ack.write_text(
            f"{victim[0]}|{victim[1]}|{victim[2]}|RENAME live as something_else\n"
        )
        _, missing, errs = audit(drifted, ack)
        assert not missing, f"selftest: acknowledged absence must pass, got {missing}"
        assert not errs, errs
        print("✓ selftest: an acknowledged absence is suppressed")

        # An acknowledgement with NO reason must be REFUSED, not silently honoured.
        bad = td / "bad.txt"
        bad.write_text(f"{victim[0]}|{victim[1]}|{victim[2]}|\n")
        _, missing, errs = audit(drifted, bad)
        assert errs, "selftest: a reasonless acknowledgement must be refused"
        assert missing, "selftest: a reasonless acknowledgement must not suppress"
        print("✓ selftest: a reasonless acknowledgement is refused (B-167)")

        # An EXPIRED pending acknowledgement must stop suppressing.
        expired = td / "expired.txt"
        expired.write_text(f"{victim[0]}|{victim[1]}|{victim[2]}|PENDING 2000-01-01\n")
        _, missing, errs = audit(drifted, expired)
        assert errs, "selftest: an expired PENDING must be reported"
        assert missing, "selftest: an expired PENDING must stop suppressing"
        print("✓ selftest: an EXPIRED PENDING acknowledgement stops suppressing")

        # The 63-char truncation class must NOT be reported. Build a catalog whose
        # long names are stored truncated, exactly as Postgres would.
        longs = [d for d in declared if len(d[1]) > PG_NAME_MAX]
        if longs:
            _, missing, _ = audit(full, empty_ack)
            assert not any(len(m[1]) > PG_NAME_MAX for m in missing), (
                "selftest: a >63-char identifier must compare on its truncated form"
            )
            print(
                f"✓ selftest: {len(longs)} over-length identifier(s) compare truncated"
            )
        else:
            print(
                "✓ selftest: no over-length identifiers declared (truncation path idle)"
            )

    print("\nselftest PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
