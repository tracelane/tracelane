#!/usr/bin/env python3
"""Every ClickHouse READ in the gateway carries ADR-031 caps — per CALL SITE, not per file.

SRE register #20 follow-up (2026-09-06). `no-raw-ch-query.sh` lists FILES as COMPLIANT
and documents their `.query(` / `capped(` counts in comments — comments, not assertions.
So six reads sat uncapped inside "compliant" files for weeks (two dataset reads, four
eval-run reads), and the first thing that saw them was `system.query_log` on prod: a
Team tenant's dataset LIST ran with EMPTY settings while every neighbouring read carried
Team caps. A file-level listing cannot see a call-level gap; this guard reads the call.

RULE. In the NON-TEST half of every `crates/gateway/src/**/*.rs` that talks to
ClickHouse, each `.query(` must have a cap marker in the surrounding window
(25 lines before, 4 after): `capped(`, `capped_sql(`, `candidate_sql(`,
`ceiling(`, `TenantQuery::new(`, or `sql_with_settings()`. Exempt by evidence, never by list:
  * a Postgres call — a `&[` parameter slice within 10 lines, or `pool`/`pg` on the line;
  * a MUTATION — the window's SQL starts with INSERT / ALTER / DELETE / OPTIMIZE /
    SYSTEM / CREATE / DROP / TRUNCATE (caps are read protection; the writers are the
    persister's business);
  * `system.query_log` itself (the proof reads).

HONEST LIMIT. The window is a heuristic: a `let sql = capped(...)` more than 25 lines
above its `.query(` reads as uncapped (FAIL, loud, fix by moving it), and a cap on the
WRONG variable within the window reads as capped (a false pass). The prod query_log is
the proof of record; this guard is the thing that runs on every push.

Usage:
  check-ch-reads-capped.py             scan the tree under $PWD
  check-ch-reads-capped.py --selftest  plant an uncapped read and prove it BLOCKS
Any other argument is refused (exit 2) — a guard that exits 0 on `--bogus` cannot be
told apart from one whose selftest passed (`check-guard-selftests.py`).
"""

from __future__ import annotations

import pathlib
import re
import sys
import tempfile

CAP_MARKERS = re.compile(
    r"capped\(|capped_sql\(|candidate_sql\(|ceiling\(|TenantQuery::new\(|sql_with_settings\(\)"
)
MUTATION = re.compile(r"\b(INSERT|ALTER|DELETE|OPTIMIZE|SYSTEM|CREATE|DROP|TRUNCATE)\b")
CH_FILE = re.compile(
    r"clickhouse::Client|ClickhouseClient|ch_client\(|\.fetch_all::<|\.fetch_one::<"
)
BEFORE, AFTER, PG_AFTER = 25, 4, 10


def scan_file(path: pathlib.Path) -> list[tuple[int, str]]:
    src = path.read_text(encoding="utf-8", errors="replace")
    non_test = src.split("#[cfg(test)]")[0]
    if not CH_FILE.search(non_test):
        return []
    lines = non_test.split("\n")
    out: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        if ".query(" not in line or "system.query_log" in line:
            continue
        after = "\n".join(lines[i : i + 1 + AFTER])
        pg_after = "\n".join(lines[i : i + 1 + PG_AFTER])
        if "&[" in pg_after or re.search(r"\b(pool|pg)\b", line):
            continue  # Postgres — a `&[..]` parameter slice is tokio-postgres, never ClickHouse
        window = "\n".join(lines[max(0, i - BEFORE) : i + 1 + AFTER])
        if CAP_MARKERS.search(window):
            continue
        sql_evidence = re.search(
            r'"\s*(SELECT|INSERT|ALTER|DELETE|OPTIMIZE|SYSTEM|CREATE|DROP|TRUNCATE|WITH)\b',
            after,
        )
        if sql_evidence and MUTATION.match(sql_evidence.group(1)):
            continue  # a mutation, not a read
        out.append((i + 1, line.strip()))
    return out


def scan_tree(root: pathlib.Path) -> list[str]:
    findings: list[str] = []
    for f in sorted((root / "crates" / "gateway" / "src").rglob("*.rs")):
        for ln, text in scan_file(f):
            findings.append(
                f"{f.relative_to(root)}:{ln}: uncapped ClickHouse read — {text[:90]}"
            )
    return findings


FIXTURE_OK = """
use crate::clickhouse_query::{PlanTier, TenantQuery};
pub struct R { ch: clickhouse::Client }
impl R {
    async fn capped(&self, sql: &str) -> String { TenantQuery::new(sql, PlanTier::Free).sql_with_settings() }
    async fn good(&self) -> anyhow::Result<()> {
        let sql = self.capped("SELECT count() FROM spans WHERE tenant_id = ?").await;
        self.ch.query(&sql).fetch_all::<u64>().await?;
        Ok(())
    }
    async fn writer(&self) -> anyhow::Result<()> {
        self.ch.query(
            "INSERT INTO spans (a) VALUES (?)",
        ).bind(1).execute().await?;
        Ok(())
    }
    async fn pg(&self, c: &tokio_postgres::Client) -> anyhow::Result<()> {
        c.query(
            "SELECT 1 FROM tenants WHERE id = $1",
            &[&1i64],
        ).await?;
        Ok(())
    }
}
"""
# Planted in its OWN file: the marker window is 25 lines, and a bad read that sits
# next to a good one would read as capped (the guard's stated limit, not a bug).
FIXTURE_BAD = """
pub struct B { ch: clickhouse::Client }
impl B {
    async fn bad(&self) -> anyhow::Result<()> {
        let mut sql = String::from("SELECT x FROM datasets FINAL WHERE tenant_id = ?");
        sql.push_str(" LIMIT ?");
        self.ch.query(&sql).bind(1).fetch_all::<u64>().await?;
        Ok(())
    }
}
"""


def selftest() -> int:
    fails = 0
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        src = root / "crates" / "gateway" / "src"
        src.mkdir(parents=True)
        (src / "reader.rs").write_text(FIXTURE_OK)
        got = scan_tree(root)
        if got:
            print(
                f"  ✗ clean fixture (capped read, an INSERT, a Postgres call) was flagged: {got}"
            )
            fails += 1
        else:
            print("  ✓ a capped read, an uncapped INSERT and a Postgres call all PASS")
        (src / "bad.rs").write_text(FIXTURE_BAD)
        got = scan_tree(root)
        if any("uncapped ClickHouse read" in g and "bad.rs" in g for g in got):
            print(f"  ✓ a dynamically built SELECT with no cap is REFUSED: {got[0]}")
        else:
            print(f"  ✗ the planted uncapped SELECT was NOT refused (got {got})")
            fails += 1
        # the real tree must be clean — a red baseline makes the plants vacuous
        real = scan_tree(pathlib.Path.cwd())
        if real:
            print("  ✗ the real tree is RED, so the planted cases prove nothing:")
            print("\n".join("      " + r for r in real))
            fails += 1
        else:
            print("  ✓ the real tree passes (baseline)")
    if fails:
        print(f"selftest FAILED — {fails} case(s)")
        return 1
    print("selftest PASSED.")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv:
        print(
            f"{pathlib.Path(sys.argv[0]).name}: unknown argument {argv!r} — expected nothing or --selftest",
            file=sys.stderr,
        )
        return 2
    findings = scan_tree(pathlib.Path.cwd())
    if findings:
        print(
            "check-ch-reads-capped: FAIL — ClickHouse reads without ADR-031 caps at the call site:"
        )
        print("\n".join("  " + f for f in findings))
        print(
            "  fix: route the SQL through the reader's `capped(sql, tenant)` / `TenantQuery::new(sql, tier_for_tenant(..))`."
        )
        return 1
    print(
        "check-ch-reads-capped: OK — every ClickHouse read in crates/gateway carries caps at its call site."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
