#!/usr/bin/env python3
"""Every tenant-keyed ClickHouse store the repo DEFINES is classified by the tenant purge.

WHY (2026-09-30). `scripts/ops/tenant-purge.sh` refuses to run when the LIVE schema holds
a tenant-keyed table it has not classified (CH_PURGE / CH_RETAIN / CH_EXEMPT). That is the
right refusal, but it fires at purge time, against prod, after the table shipped — a GDPR
erasure blocked until someone edits the script. Two Codex runs in one day (EVL-40
`outcomes`, OBS-47 `spend_hourly`) added tenant-keyed tables without classifying them; both
were caught only by a human-triggered security review. `check-orphan-sweep-covers-purge.py`
holds the purge list and the sweep list EQUAL, and says in its own docstring that it cannot
see a table missing from both. This is that missing half, statically, at commit time.

WHAT: every `CREATE TABLE` / `CREATE [MATERIALIZED] VIEW` in `infra/dev/clickhouse/schema.sql`
and `infra/dev/clickhouse/migrations/*.sql` whose definition names `tenant_id` or
`tenant_id_hash`, and is not dropped by a later migration, must appear in one of the three
arrays of `tenant-purge.sh`. The arrays are read by BASH itself (the region is evaluated,
not re-parsed), so the guard sees exactly what the purge sees.

HONEST LIMIT: this proves a store is CLASSIFIED, not that the classification is right
(PURGE vs RETAIN is a judgement, and the reason text is review). A table created outside
these files (by hand on prod) is the live gate's job, not this one's.

USAGE
  check-ch-purge-classification.py             # check the repo
  check-ch-purge-classification.py --selftest  # prove it BLOCKS
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PURGE = "scripts/ops/tenant-purge.sh"
SCHEMA = "infra/dev/clickhouse/schema.sql"
MIGRATIONS = "infra/dev/clickhouse/migrations"

_CREATE = re.compile(
    r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|MATERIALIZED\s+VIEW|VIEW)\s+"
    r"(?:IF\s+NOT\s+EXISTS\s+)?(?:`?tracelane`?\.)?`?(\w+)`?",
    re.IGNORECASE,
)
_DROP = re.compile(
    r"DROP\s+(?:TABLE|VIEW)\s+(?:IF\s+EXISTS\s+)?(?:`?tracelane`?\.)?`?(\w+)`?",
    re.IGNORECASE,
)
_RENAME = re.compile(
    r"(?:`?tracelane`?\.)?`?(\w+)`?\s+TO\s+(?:`?tracelane`?\.)?`?(\w+)`?", re.IGNORECASE
)
_TENANT = re.compile(r"\btenant_id(?:_hash)?\b")


def _strip_comments(sql: str) -> str:
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    return re.sub(r"--[^\n]*", " ", sql)


def defined_tenant_stores(root: Path) -> dict[str, str]:
    """{store: file} for every tenant-keyed store still standing after all migrations."""
    files = [root / SCHEMA, *sorted((root / MIGRATIONS).glob("*.sql"))]
    stores: dict[str, str] = {}
    for f in files:
        if not f.is_file():
            continue
        sql = _strip_comments(f.read_text(encoding="utf-8"))
        # Statement by statement, in file order, so a DROP after a CREATE retires it.
        for stmt in sql.split(";"):
            m = _CREATE.search(stmt)
            if m and _TENANT.search(stmt[m.end() :]):
                stores.setdefault(m.group(1), f.relative_to(root).as_posix())
                continue
            if f.parent.name != "migrations":
                continue
            d = _DROP.search(stmt)
            if d:
                stores.pop(d.group(1), None)
            # `RENAME TABLE a TO b, c TO d` — the atomic swaps of migrations 11 and 15.
            # Applied pair by pair in order, as ClickHouse does.
            r = re.search(r"\bRENAME\s+TABLE\b(.*)", stmt, re.IGNORECASE | re.DOTALL)
            if r:
                for src, dst in _RENAME.findall(r.group(1)):
                    if src in stores:
                        stores[dst] = stores.pop(src)
    return stores


def classified(root: Path) -> set[str]:
    """The names in CH_PURGE / CH_RETAIN / CH_EXEMPT, as BASH evaluates the arrays."""
    src = (root / PURGE).read_text(encoding="utf-8")
    m = re.search(r"^CH_PURGE=\(.*?(?=^in_list\(\))", src, re.MULTILINE | re.DOTALL)
    if not m:
        return set()
    region = m.group(0)
    script = (
        region
        + '\nfor e in "${CH_PURGE[@]}" "${CH_RETAIN[@]}" "${CH_EXEMPT[@]}"; do'
        + ' e="${e%%|*}"; printf "%s\\n" "${e%%:*}"; done\n'
    )
    out = subprocess.run(
        ["bash", "-c", script], capture_output=True, text=True, check=True
    ).stdout
    return {line.strip() for line in out.splitlines() if line.strip()}


def check(root: Path = ROOT) -> list[str]:
    stores = defined_tenant_stores(root)
    if not stores:
        return [
            "found ZERO tenant-keyed stores — the SQL parse is broken, not the repo clean"
        ]
    known = classified(root)
    if not known:
        return [f"read ZERO classified names from {PURGE} — the array read is broken"]
    return [
        f"{name} (defined in {where}) is tenant-keyed but NOT classified in {PURGE} "
        "(CH_PURGE, or CH_RETAIN/CH_EXEMPT with a reason) — a live purge will refuse "
        "on it, blocking every erasure until it is"
        for name, where in sorted(stores.items())
        if name not in known
    ]


def selftest() -> int:
    with tempfile.TemporaryDirectory() as td:
        t = Path(td)
        (t / MIGRATIONS).mkdir(parents=True)
        (t / "scripts/ops").mkdir(parents=True)
        (t / SCHEMA).write_text(
            "CREATE TABLE IF NOT EXISTS tracelane.spans (tenant_id UUID, x String);\n"
            "-- CREATE TABLE commented_out (tenant_id UUID);\n"
            "CREATE TABLE tracelane.no_tenant (x String);\n"
        )
        (t / PURGE).write_text(
            "CH_PURGE=(spans\n  # a comment\n  dropped_later)\n"
            'CH_RETAIN=(\n  "audit_log|ADR (c): kept) with a paren"\n  "audit_log_old|rollback copy"\n)\n'
            "CH_EXEMPT=()\nin_list() { :; }\n"
        )
        (t / MIGRATIONS / "01_a.sql").write_text(
            "CREATE TABLE tracelane.audit_log (tenant_id UUID);\n"
            "CREATE TABLE tracelane.dropped_later (tenant_id UUID);\n"
        )
        (t / MIGRATIONS / "02_b.sql").write_text(
            "DROP TABLE IF EXISTS tracelane.dropped_later;\n"
            "CREATE TABLE tracelane.audit_log_v2 (tenant_id UUID);\n"
            "RENAME TABLE tracelane.audit_log TO tracelane.audit_log_old,\n"
            "             tracelane.audit_log_v2 TO tracelane.audit_log;\n"
        )
        f = check(t)
        assert not f, f"a fully classified tree must pass: {f}"
        print(
            "  ✓ classified stores pass; comments, tenant-less tables, DROPs and RENAME swaps are followed"
        )

        (t / MIGRATIONS / "03_new.sql").write_text(
            "CREATE TABLE tracelane.outcomes (tenant_id UUID, reason String);\n"
            "CREATE MATERIALIZED VIEW tracelane.mv_new TO tracelane.spans AS "
            "SELECT tenant_id FROM tracelane.spans;\n"
        )
        f = check(t)
        assert len(f) == 2 and "outcomes" in f[1] and "mv_new" in f[0], f
        print(
            "  ✓ an unclassified tenant-keyed TABLE and MATERIALIZED VIEW both REFUSE"
        )

        for mig in (t / MIGRATIONS).glob("*.sql"):
            mig.unlink()
        (t / SCHEMA).write_text("CREATE TABLE tracelane.x (y String);\n")
        f = check(t)
        assert f and "ZERO tenant-keyed" in f[0], f
        print("  ✓ a parse that finds nothing is a FAILURE, not a pass")
    print("selftest PASSED.")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if args == ["--selftest"]:
        return selftest()
    if args:
        print(f"usage: {Path(__file__).name} [--selftest]", file=sys.stderr)
        return 2
    failures = check()
    for f in failures:
        print(f"✗ {f}")
    if failures:
        return 1
    print(
        f"OK — {len(defined_tenant_stores(ROOT))} tenant-keyed ClickHouse store(s) defined, "
        f"every one classified in {PURGE}."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
