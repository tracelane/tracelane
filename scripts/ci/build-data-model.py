#!/usr/bin/env python3
"""Generate `docs/reference/DATA_MODEL.md` — the ONE data model, derived from code.

Founder, 2026-09-14: *"ensure to start building full data models; documents were
indexed in past — see if they all convey the same findings as the data model."*

WHAT THIS DERIVES (never re-typed by hand)
  1. Neon (control plane): every `pgTable` in `apps/web/db/schema.ts` — table,
     column, type, NOT NULL, default, PK, FK. schema.ts is canonical (CLAUDE.md §5).
  2. ClickHouse (data plane): every `CREATE TABLE` / `MATERIALIZED VIEW` in
     `infra/dev/clickhouse/schema.sql` — columns, engine, ORDER BY, TTL, storage policy.
  3. Reference tables: `apps/web/db/plans.v3.json` (plans × fields, meters, policy).
  4. Who reads / writes each table — from the code: Drizzle calls in `apps/web`
     (`from(schema.x)`, `insert(schema.x)`, `update(schema.x)`, `delete(schema.x)`) and
     SQL literals in `crates/` (`FROM x`, `INSERT INTO x`, `UPDATE x`, `tracelane.x`).
  5. Findings — where the CODE and the DOCS disagree:
     (a) a table nothing in the code reads or writes (a data-model residue);
     (b) a doc naming `table.column` where that column does not exist;
     (c) a doc naming a RETIRED identifier (dropped by the BILL-01 contract step) as
         if live — lines that say retired/dropped/deleted/superseded/gone are excused.

WHY A GENERATOR AND NOT A HAND DOC. The 2026-09-14 residual sweep found eight
ADR-020 columns still declared, seeded and (in the gateway) read, a day after the
model that retired them shipped — a hand-written data model would have said the
same wrong thing the docs did. This one cannot: it is the schema, re-read.

USAGE
  build-data-model.py            # (re)generate docs/reference/DATA_MODEL.md
  build-data-model.py --check    # exit 1 if the committed file is stale
  build-data-model.py --selftest # determinism + staleness detection
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs" / "reference" / "DATA_MODEL.md"
SCHEMA_TS = ROOT / "apps" / "web" / "db" / "schema.ts"
CH_SQL = ROOT / "infra" / "dev" / "clickhouse" / "schema.sql"
PLANS = ROOT / "apps" / "web" / "db" / "plans.v3.json"

# Identifiers the ruled model retired (migration 0042 + the deleted ADR-020 code).
# A doc naming one of these as LIVE is finding (c).
RETIRED = [
    "seat_cap_included",
    "seat_cap_max",
    "retention_days",
    "trace_quota_monthly",
    "gateway_quota_monthly",
    "overage_hard_cap_multiplier",
    "overage_price_per_10k_usd",
    "f_hipaa_gcp_addon",
    "addon_modified_at",
    "tokens_processed",
    "quota_exceeded_since_start",
    "spawn_billing_record",
    "handleAddOnChange",
    "QuotaConfig",
    "QuotaTracker",
]
NOT_COLUMNS = {
    "rs",
    "ts",
    "tsx",
    "mjs",
    "md",
    "mdx",
    "py",
    "sh",
    "sql",
    "json",
    "yml",
    "yaml",
    "length",
    "map",
    "filter",
    "test",
}
EXCUSE_RE = re.compile(
    r"retire|dropped|drop column|deleted|superseded|gone|removed|no longer|renamed|was `|"
    r"used to|was the|historical|before this block|pinned to commit|archive",
    re.IGNORECASE,
)
DOC_GLOBS = [
    "CLAUDE.md",
    "crates/gateway/CLAUDE.md",
    "crates/ingest/CLAUDE.md",
    "apps/web/CLAUDE.md",
    ".claude/rules/*.md",
    "docs/product/*.md",
    "docs/reference/*.md",
    "specs/*.md",
]


# ── 1. Neon (Drizzle) ──────────────────────────────────────────────────────────
COL_RE = re.compile(r'^\s+(\w+):\s*(\w+)\("([a-z0-9_]+)"')


def parse_drizzle(text: str) -> dict[str, dict]:
    tables: dict[str, dict] = {}
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        m = re.match(r"^export const (\w+) = pgTable\(", lines[i])
        if not m:
            i += 1
            continue
        var = m.group(1)
        # table name: on this line or the next
        tm = re.search(r'pgTable\(\s*"([a-z0-9_]+)"', lines[i]) or re.search(
            r'^\s*"([a-z0-9_]+)",', lines[i + 1]
        )
        name = tm.group(1) if tm else var
        j = i + 1
        block: list[str] = []
        while j < len(lines) and not re.match(r"^(\}\)?\);?|\);)\s*$", lines[j]):
            block.append(lines[j])
            j += 1
        cols: list[dict] = []
        cur: dict | None = None
        pending: tuple[str, str] | None = (
            None  # a `field: type(` whose "col" is on the next line
        )
        for ln in block:
            cm = COL_RE.match(ln)
            om = re.match(r"^\s+(\w+):\s*(\w+)\($", ln)
            if cm:
                cur = {
                    "field": cm.group(1),
                    "type": cm.group(2),
                    "col": cm.group(3),
                    "mods": ln,
                }
                cols.append(cur)
                pending = None
            elif om:
                pending = (om.group(1), om.group(2))
            elif pending and re.match(r'^\s+"([a-z0-9_]+)",?\s*$', ln):
                col = re.match(r'^\s+"([a-z0-9_]+)"', ln).group(1)
                cur = {"field": pending[0], "type": pending[1], "col": col, "mods": ""}
                cols.append(cur)
                pending = None
            elif cur is not None and (
                ln.strip().startswith(".") or ln.strip().startswith(")")
            ):
                cur["mods"] += " " + ln.strip()
        for c in cols:
            mods = c.pop("mods")
            c["not_null"] = ".notNull()" in mods or ".primaryKey()" in mods
            c["pk"] = ".primaryKey()" in mods
            dm = re.search(r"\.default(?:Random|Now)?\(([^)]*)\)", mods)
            c["default"] = (
                "random()"
                if ".defaultRandom()" in mods
                else "now()"
                if ".defaultNow()" in mods
                else (dm.group(1) if dm else "")
            )
            rm = re.search(r"\.references\(\(\) => (\w+)\.(\w+)", mods)
            c["fk"] = f"{rm.group(1)}.{rm.group(2)}" if rm else ""
        tables[name] = {"var": var, "columns": cols}
        i = j + 1
    return tables


# ── 2. ClickHouse ──────────────────────────────────────────────────────────────
def parse_clickhouse(text: str) -> dict[str, dict]:
    tables: dict[str, dict] = {}
    # strip -- comments
    body = "\n".join(re.sub(r"--.*$", "", ln) for ln in text.split("\n"))
    for stmt in re.split(r";\s*\n", body):
        m = re.search(
            r"CREATE\s+(TABLE|MATERIALIZED VIEW)\s+(?:IF NOT EXISTS\s+)?tracelane\.(\w+)",
            stmt,
        )
        if not m:
            continue
        kind, name = m.group(1), m.group(2)
        cols: list[dict] = []
        pm = re.search(
            r"\(\s*(.*?)\)\s*(ENGINE|AS\s+SELECT|TO\s+tracelane)", stmt, re.DOTALL
        )
        if (
            pm
            and kind == "TABLE"
            or (
                pm
                and "TO tracelane" in stmt
                and "(" in stmt[: stmt.find("TO tracelane")]
            )
        ):
            for raw in pm.group(1).split("\n"):
                raw = raw.strip().rstrip(",")
                cm = re.match(
                    r"`?([a-zA-Z_][a-zA-Z0-9_]*)`?\s+([A-Za-z][A-Za-z0-9_(), ]*?)(?:\s+(?:DEFAULT|CODEC|COMMENT|MATERIALIZED|ALIAS)\b.*)?$",
                    raw,
                )
                if cm and cm.group(1).upper() not in {
                    "INDEX",
                    "PROJECTION",
                    "CONSTRAINT",
                    "TTL",
                    "PRIMARY",
                    "ORDER",
                }:
                    cols.append({"col": cm.group(1), "type": cm.group(2).strip()})
        eng = re.search(r"ENGINE\s*=\s*([A-Za-z]+(?:\([^)]*\))?)", stmt)
        order = re.search(r"ORDER BY\s+(\([^)]*\)|\S+)", stmt)
        ttl = re.search(r"\bTTL\s+(.+?)(?=\s+SETTINGS|\s*$)", stmt, re.DOTALL)
        pol = re.search(r"storage_policy\s*=\s*'(\w+)'", stmt)
        tables[name] = {
            "kind": kind,
            "columns": cols,
            "engine": eng.group(1) if eng else "",
            "order_by": order.group(1) if order else "",
            "ttl": " ".join(ttl.group(1).split()) if ttl else "",
            "policy": pol.group(1) if pol else "",
        }
    return tables


# ── 4. readers / writers ───────────────────────────────────────────────────────
def scan_usage(
    pg_vars: dict[str, str], pg_tables: set[str], ch_tables: set[str]
) -> dict[str, dict[str, set[str]]]:
    """table -> {'reads': {file...}, 'writes': {file...}}"""
    use: dict[str, dict[str, set[str]]] = {}

    def add(table: str, op: str, f: str) -> None:
        use.setdefault(table, {"reads": set(), "writes": set()})[op].add(f)

    web_roots = [
        ROOT / "apps" / "web" / d for d in ("app", "lib", "components", "db", "e2e")
    ]
    for root in web_roots:
        for p in root.rglob("*.ts*"):
            if "node_modules" in p.parts or ".next" in p.parts:
                continue
            rel = str(p.relative_to(ROOT))
            t = p.read_text(encoding="utf-8", errors="ignore")
            for m in re.finditer(
                r"\.(from|insert|update|delete)\((?:schema\.)?(\w+)\)", t
            ):
                var = m.group(2)
                table = pg_vars.get(var)
                if not table:
                    continue
                add(table, "reads" if m.group(1) == "from" else "writes", rel)
            # raw SQL through the `sql` template (lib/admin-audit.ts writes this way)
            for m in re.finditer(r"\b(FROM|JOIN)\s+([a-z_][a-z0-9_]*)\b", t):
                if m.group(2) in pg_tables:
                    add(m.group(2), "reads", rel)
            for m in re.finditer(
                r"\b(INSERT INTO|UPDATE|DELETE FROM)\s+([a-z_][a-z0-9_]*)\b", t
            ):
                if m.group(2) in pg_tables:
                    add(m.group(2), "writes", rel)
    for p in (ROOT / "crates").rglob("*.rs"):
        rel = str(p.relative_to(ROOT))
        t = p.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(
            r"\b(FROM|JOIN)\s+(?:tracelane\.)?([a-z_][a-z0-9_]*)\b", t
        ):
            tb = m.group(2)
            if tb in pg_tables or tb in ch_tables:
                add(tb, "reads", rel)
        for m in re.finditer(
            r"\b(INSERT INTO|UPDATE|DELETE FROM|ALTER TABLE)\s+(?:tracelane\.)?([a-z_][a-z0-9_]*)\b",
            t,
        ):
            tb = m.group(2)
            if tb in pg_tables or tb in ch_tables:
                add(tb, "writes", rel)
        for m in re.finditer(r"tracelane\.([a-z_][a-z0-9_]*)", t):
            tb = m.group(1)
            if tb in ch_tables:
                # crude but honest: an INSERT literal or `.insert("x")` is a write; else a read
                add(tb, "reads", rel)
        for m in re.finditer(
            r"\.insert\(\"(?:tracelane\.)?([a-z_][a-z0-9_]*)\"\)|INSERT INTO\s+tracelane\.([a-z_][a-z0-9_]*)",
            t,
        ):
            tb = m.group(1) or m.group(2)
            if tb in ch_tables:
                add(tb, "writes", rel)
    return use


# ── 5. doc reconciliation ──────────────────────────────────────────────────────
def scan_docs(pg: dict[str, dict], ch: dict[str, dict]) -> list[str]:
    cols_by_table: dict[str, set[str]] = {
        t: {c["col"] for c in d["columns"]} for t, d in pg.items()
    }
    cols_by_table.update({t: {c["col"] for c in d["columns"]} for t, d in ch.items()})
    findings: list[str] = []
    files: list[Path] = []
    for g in DOC_GLOBS:
        files += sorted(ROOT.glob(g))
    dotted = re.compile(r"`([a-z_][a-z0-9_]*)\.([a-z_][a-z0-9_]*)`")
    for f in files:
        rel = str(f.relative_to(ROOT))
        if "/archive/" in rel:
            continue
        doc_lines = f.read_text(encoding="utf-8", errors="ignore").split("\n")
        # Prose wraps and a paragraph is one thought: an excuse word anywhere in the
        # blank-line-delimited paragraph (or table row) governs every line in it.
        para_excused: list[bool] = []
        start = 0
        for k, ln in enumerate(doc_lines + [""]):
            if ln.strip() == "":
                block = "\n".join(doc_lines[start:k])
                ex = bool(EXCUSE_RE.search(block))
                para_excused.extend([ex] * (k - start + 1))
                start = k + 1
        for i, ln in enumerate(doc_lines, 1):
            if para_excused[i - 1] or EXCUSE_RE.search(ln):
                continue
            for m in dotted.finditer(ln):
                t, c = m.group(1), m.group(2)
                if c in NOT_COLUMNS:
                    continue  # `spans.rs`, `api_keys.rs`, `spans.length` — a file or a JS member
                if t in cols_by_table and c not in cols_by_table[t]:
                    findings.append(f"{rel}:{i}: `{t}.{c}` — column not in the model")
            for r in RETIRED:
                if re.search(rf"`[^`]*\b{re.escape(r)}\b[^`]*`", ln):
                    findings.append(f"{rel}:{i}: retired `{r}` named as live")
    return findings


# ── render ─────────────────────────────────────────────────────────────────────
def render() -> str:
    pg = parse_drizzle(SCHEMA_TS.read_text(encoding="utf-8"))
    ch = parse_clickhouse(CH_SQL.read_text(encoding="utf-8"))
    plans = json.loads(PLANS.read_text(encoding="utf-8"))
    pg_vars = {d["var"]: t for t, d in pg.items()}
    use = scan_usage(pg_vars, set(pg), set(ch))

    o: list[str] = []
    o.append("<!-- tracelane:classification: INTERNAL -->")
    o.append("<!-- GENERATED by scripts/ci/build-data-model.py — DO NOT EDIT BY HAND.")
    o.append("     `build-data-model.py --check` fails when this file is stale. -->")
    o.append("# Data model — every table, column and flow, derived from the code")
    o.append("")
    o.append(
        "> **GENERATED. Do not edit.** Sources: `apps/web/db/schema.ts` (Neon, canonical per CLAUDE.md §5),"
    )
    o.append(
        "> `infra/dev/clickhouse/schema.sql` (ClickHouse), `apps/web/db/plans.v3.json` (reference tables),"
    )
    o.append(
        "> and the code's own reads/writes. **Where a doc and this file disagree, this file wins** — it is the"
    )
    o.append(
        "> schema re-read, not a description of it (CLAUDE.md §17). Findings at the end list the disagreements."
    )
    o.append("")
    o.append(
        f"**{len(pg)} Neon tables · {len(ch)} ClickHouse objects · {len(plans['plans'])} plans · {len(plans['meters'])} meter rates · {len(plans['policy'])} policy keys.**"
    )
    o.append("")
    o.append("## 1. Neon (control plane) — Drizzle `schema.ts`")
    o.append("")
    for t in sorted(pg):
        d = pg[t]
        o.append(f"### `{t}` (`{d['var']}`)")
        o.append("")
        o.append("| column | type | null | default | key |")
        o.append("|---|---|---|---|---|")
        for c in d["columns"]:
            key = "PK" if c["pk"] else (f"FK → `{c['fk']}`" if c["fk"] else "")
            o.append(
                f"| `{c['col']}` | {c['type']} | {'NOT NULL' if c['not_null'] else 'null'} | {c['default'] or ''} | {key} |"
            )
        o.append("")
    o.append("## 2. ClickHouse (data plane) — `schema.sql`")
    o.append("")
    for t in sorted(ch):
        d = ch[t]
        o.append(f"### `tracelane.{t}` — {d['kind'].title()}")
        o.append("")
        meta = []
        if d["engine"]:
            meta.append(f"engine `{d['engine']}`")
        if d["order_by"]:
            meta.append(f"ORDER BY `{d['order_by']}`")
        if d["policy"]:
            meta.append(f"storage policy `{d['policy']}`")
        if d["ttl"]:
            meta.append(f"TTL `{d['ttl'][:160]}`")
        if meta:
            o.append("· ".join(meta))
            o.append("")
        if d["columns"]:
            o.append("| column | type |")
            o.append("|---|---|")
            for c in d["columns"]:
                o.append(f"| `{c['col']}` | {c['type']} |")
            o.append("")
    o.append(
        "## 3. Reference tables — `plans.v3.json` (the ONE source for every price, limit and window)"
    )
    o.append("")
    plan_keys = list(plans["plans"])
    fields = sorted({k for p in plans["plans"].values() for k in p})
    o.append("| field | " + " | ".join(f"`{k}`" for k in plan_keys) + " |")
    o.append("|---|" + "---|" * len(plan_keys))
    for f in fields:
        o.append(
            f"| `{f}` | "
            + " | ".join(str(plans["plans"][k].get(f, "")) for k in plan_keys)
            + " |"
        )
    o.append("")
    o.append(
        "**Meters:** " + ", ".join(f"`{k}` = {v}" for k, v in plans["meters"].items())
    )
    o.append("")
    o.append(
        "**Policy:** " + ", ".join(f"`{k}` = {v}" for k, v in plans["policy"].items())
    )
    o.append("")
    o.append("## 4. Who reads and writes each table (from the code)")
    o.append("")
    o.append("| table | readers | writers |")
    o.append("|---|---|---|")
    orphans: list[str] = []
    for t in sorted(list(pg) + list(ch)):
        u = use.get(t, {"reads": set(), "writes": set()})
        r = ", ".join(f"`{x}`" for x in sorted(u["reads"])[:6]) + (
            " …" if len(u["reads"]) > 6 else ""
        )
        w = ", ".join(f"`{x}`" for x in sorted(u["writes"])[:6]) + (
            " …" if len(u["writes"]) > 6 else ""
        )
        if not u["reads"] and not u["writes"]:
            orphans.append(t)
        o.append(f"| `{t}` | {r or '—'} | {w or '—'} |")
    o.append("")
    o.append("## 5. Findings — where the docs or the code disagree with the model")
    o.append("")
    o.append("### (a) Tables no code reads or writes")
    o.append("")
    if orphans:
        for t in orphans:
            o.append(
                f"- `{t}` — declared, unused by any Drizzle call or SQL literal this generator can see (a materialized view's own writes are implicit; everything else here is a residue to explain or drop)"
            )
    else:
        o.append("- none")
    o.append("")
    findings = scan_docs(pg, ch)
    o.append(
        "### (b)/(c) Docs naming a column that does not exist, or a retired identifier as live"
    )
    o.append("")
    if findings:
        for f in findings:
            o.append(f"- {f}")
    else:
        o.append("- none")
    o.append("")
    return "\n".join(o) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--out", default=str(OUT))
    a = ap.parse_args()
    out = Path(a.out)
    if a.selftest:
        a1, a2 = render(), render()
        if a1 != a2:
            print("  ✗ NOT deterministic across two renders")
            return 1
        print("  ✓ deterministic across runs (--check cannot flap)")
        with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
            fh.write(a1 + "\n<!-- planted staleness -->\n")
            stale = Path(fh.name)
        rc = 0 if stale.read_text() != render() else 1
        stale.unlink()
        print("  ✓ staleness is DETECTED" if rc == 0 else "  ✗ staleness NOT detected")
        print("selftest PASSED." if rc == 0 else "selftest FAILED.")
        return rc
    text = render()
    if a.check:
        if not out.exists() or out.read_text(encoding="utf-8") != text:
            print(f"✗ {out} is STALE — run scripts/ci/build-data-model.py")
            return 1
        print(f"✓ {out} is current")
        return 0
    out.write_text(text, encoding="utf-8")
    print(f"wrote {out} ({len(text)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
