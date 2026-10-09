#!/usr/bin/env python3
"""B-459: the retention sweep's ORPHAN list equals the tenant purge's ClickHouse list.

WHY (2026-09-20, `runbooks/RCA-stream-replay-resurrected-a-purged-tenant.md`). A stream replay
brought a purged tenant's rows back. The boot-time orphan sweep in
`crates/gateway/src/retention_sweep.rs` (rows whose `tenant_id` has no `tenants` row) is the net that
catches a resurrection — but it covered SIX tables, while `scripts/ops/tenant-purge.sh` deletes a
tenant from ~25. Every table in the purge list and not in the sweep list is a table where a purged
tenant's resurrected rows stay forever. The two lists were written by different people on different
days and nothing held them equal.

THE RULE, both directions:
  1. every `CH_PURGE` table is orphan-swept (named in an `orphan_*_sql` of `retention_sweep.rs`);
  2. every orphan-swept table is in `CH_PURGE` (a sweep of a table the purge does not know is a
     table whose classification is missing — the purge would refuse on it as UNCLASSIFIED).
Tables in `CH_RETAIN` (the ledger, ADR-068) are never swept and never purged — they must be in
NEITHER list, and the guard refuses a retained table that appears in the sweep.

The grant and SQL check also pins every extracted statement to the explicit sweeper grants.
HONEST LIMIT: this proves the lists, SQL shapes, and grants agree. It does not prove the SQL deletes the right rows
(the sweep's real-ClickHouse test does that), nor that a new table was classified at all — that is
`tenant-purge.sh`'s own discovery refusal on the live database.

Usage: check-orphan-sweep-covers-purge.py [--selftest | --print-purge | --print-deletes]
"""

from __future__ import annotations

import re
import runpy
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PURGE = "scripts/ops/tenant-purge.sh"
SWEEP = "crates/gateway/src/retention_sweep.rs"
USERS = "infra/prod/clickhouse/users.d/services.xml"
COMPOSE = "infra/prod/docker-compose.yml"


def bash_array(text: str, name: str) -> list[str]:
    """Items of `NAME=( … )`: a quote-aware scan (reasons contain parentheses), `#` comments
    dropped, each item cut at its first `|` or `:` (the `table|reason` convention)."""
    m = re.search(rf"^{name}=\(", text, re.MULTILINE)
    if not m:
        return []
    items: list[str] = []
    cur, quote, i = "", "", m.end()
    while i < len(text):
        c = text[i]
        if quote:
            if c == quote:
                quote = ""
            else:
                cur += c
        elif c in "\"'":
            quote = c
        elif c == "#":
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        elif c == ")":
            break
        elif c.isspace():
            if cur:
                items.append(cur)
                cur = ""
        else:
            cur += c
        i += 1
    if cur:
        items.append(cur)
    return [re.split(r"[|:]", t, maxsplit=1)[0] for t in items if t]


def swept_tables(text: str) -> set[str]:
    text = text.split("#[cfg(test)]", 1)[0]
    out: set[str] = set()
    for m in re.finditer(
        r'orphan_(?:count|delete)_sql:\s*"([^"]*(?:\\\n[^"]*)*)"', text
    ):
        for t in re.findall(r"(?:FROM|TABLE)\s+tracelane\.(\w+)", m.group(1)):
            out.add(t)
    return out


def check(root: Path) -> list[str]:
    purge_text = (root / PURGE).read_text()
    sweep_text = (root / SWEEP).read_text()
    purge = set(bash_array(purge_text, "CH_PURGE"))
    retain = set(bash_array(purge_text, "CH_RETAIN"))
    swept = swept_tables(sweep_text)
    if not purge:
        return [
            f"{PURGE}: could not parse CH_PURGE — refusing to call an empty list covered"
        ]
    if not swept:
        return [
            f"{SWEEP}: found no orphan_*_sql — refusing to call an empty sweep covered"
        ]
    f = []
    for t in sorted(purge - swept):
        f.append(
            f"`{t}` is purged by {PURGE} but NOT orphan-swept by {SWEEP} — a purged tenant's resurrected rows would stay"
        )
    for t in sorted(swept - purge - retain):
        f.append(f"`{t}` is orphan-swept but not in CH_PURGE — classify it in {PURGE}")
    for t in sorted(swept & retain):
        f.append(
            f"`{t}` is RETAINED (ADR-068) but orphan-swept — the ledger must never be swept"
        )
    return f


def _plant(root: Path, purge: list[str], swept: list[str], retain: list[str]) -> None:
    (root / "scripts/ops").mkdir(parents=True)
    (root / "crates/gateway/src").mkdir(parents=True)
    (root / PURGE).write_text(
        "CH_PURGE=("
        + " ".join(purge[:1])
        + "\n  # a comment with words\n  "
        + " ".join(purge[1:])
        + ")\n"
        + "CH_RETAIN=(\n"
        + "".join(f'  "{t}|reason: kept"\n' for t in retain)
        + ")\n"
    )
    rs = "".join(
        f'    SweepTable {{ orphan_count_sql: "SELECT count() AS n FROM tracelane.{t} WHERE tenant_id NOT IN ?",\n'
        f'        orphan_delete_sql: "ALTER TABLE tracelane.{t} DELETE \\\n WHERE tenant_id NOT IN ?" }},\n'
        for t in swept
    )
    (root / SWEEP).write_text(rs)


def selftest() -> int:
    cases = [
        (
            "equal lists -> PASS",
            ["spans", "datasets"],
            ["spans", "datasets"],
            ["audit_log"],
            None,
        ),
        (
            "purged but not swept -> BLOCK",
            ["spans", "datasets"],
            ["spans"],
            [],
            "`datasets` is purged",
        ),
        (
            "swept but not purged -> BLOCK",
            ["spans"],
            ["spans", "blob_refs"],
            [],
            "`blob_refs` is orphan-swept",
        ),
        (
            "retained ledger swept -> BLOCK",
            ["spans"],
            ["spans", "audit_log"],
            ["audit_log"],
            "RETAINED",
        ),
    ]
    bad = 0
    for name, purge, swept, retain, needle in cases:
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            _plant(root, purge, swept, retain)
            f = check(root)
            ok = (not f) if needle is None else any(needle in x for x in f)
            print(
                f"selftest: {'✓' if ok else '✗'} {name}"
                + ("" if ok else f"  (got {f})")
            )
            bad += 0 if ok else 1
    return 1 if bad else 0


def sweep_statements(text: str) -> list[tuple[str, str, str]]:
    """Read every statement in the two typed Rust lists, refusing any parse gap."""
    text = text.split("#[cfg(test)]", 1)[0]
    out = []
    for name, kind, fields in [
        (
            "SWEEP_TABLES",
            "SweepTable",
            {"count_sql", "delete_sql", "orphan_count_sql", "orphan_delete_sql"},
        ),
        (
            "ORPHAN_ONLY_TABLES",
            "OrphanOnlyTable",
            {"orphan_count_sql", "orphan_delete_sql"},
        ),
    ]:
        m = re.search(rf"const {name}:.*?=\s*&\[(.*?)\n\];", text, re.DOTALL)
        if not m:
            raise ValueError(f"cannot extract {name}")
        region = re.sub(r"//[^\n]*", "", m[1])
        blocks = re.findall(rf"{kind}\s*\{{(.*?)\}}", region, re.DOTALL)
        if not blocks or len(blocks) != len(re.findall(rf"\b{kind}\s*\{{", region)):
            raise ValueError(f"empty or missed entries in {name}")
        for block in blocks:
            values = dict(
                re.findall(r'(\w+):\s*"([^"\\]*(?:\\.[^"\\]*)*)"', block, re.DOTALL)
            )
            if set(values) != fields | {"label"}:
                raise ValueError(f"missed SQL fields in {name}: {values.keys()}")
            for field in sorted(fields):
                sql = re.sub(r"\\\s*\n\s*", "", values[field])
                out.append((values["label"], field, sql))
    return out


def grants_and_statements(root: Path) -> list[str]:
    import xml.etree.ElementTree as ET

    failures = []
    text = (root / SWEEP).read_text().split("#[cfg(test)]", 1)[0]
    try:
        statements = sweep_statements(text)
        users = ET.parse(root / USERS).getroot()
    except (ValueError, ET.ParseError, OSError) as exc:
        return [f"cannot prove sweep/grant coverage: {exc}"]
    compose = (root / COMPOSE).read_text()
    consumers = set()
    for service, body in re.findall(
        r"^  (\w+):\n(.*?)(?=^  \w+:|\Z)", compose, re.MULTILINE | re.DOTALL
    ):
        if "./.env.sweeper" in body:
            consumers.add(service)
            required = (
                "env_file: [./.env.sweeper]"
                if service == "clickhouse"
                else "env_file: [./.env, ./.env.sweeper]"
            )
            if required not in body:
                failures.append(f"sweeper secret file must be required: {service}")
    if consumers != {"clickhouse", "gateway"} or re.search(
        r"(?<!\$)\$\{CLICKHOUSE_SWEEPER_PASSWORD", compose
    ):
        failures.append(
            "sweeper secret must reach ONLY clickhouse/gateway through env_file"
        )
    purge = set(bash_array((root / PURGE).read_text(), "CH_PURGE"))
    grants = {
        u: [q.text or "" for q in users.findall(f"./users/{u}/grants/query")]
        for u in ("tl_gateway", "tl_sweeper")
    }
    deletable = set()
    for grant in grants["tl_sweeper"]:
        match = re.fullmatch(r"GRANT SELECT, ALTER DELETE ON tracelane\.(\w+)", grant)
        if match:
            deletable.add(match[1])
        elif grant != "GRANT SELECT ON system.mutations":
            failures.append(f"unexpected sweeper grant: {grant}")
    if deletable != purge:
        failures.append(
            f"sweeper ALTER DELETE != CH_PURGE: missing={sorted(purge - deletable)}, extra={sorted(deletable - purge)}"
        )
    if any(
        "ALTER DELETE" in g.upper()
        or "_ROW_EXISTS" in g.upper()
        or re.search(
            r"(?:^GRANT\s+|,\s*)(?:ALTER(?: TABLE)?|ALL(?: PRIVILEGES)?)(?=\s*(?:,|ON\b))",
            g.upper(),
        )
        for g in grants["tl_gateway"]
    ):
        failures.append("gateway still has delete/hidden-row grants")
    if re.search(r"DELETE\s+FROM\s+tracelane\.", re.sub(r"//[^\n]*", "", text)):
        failures.append("lightweight DELETE remains in sweep")
    for label, field, sql in statements:
        if "delete" in field:
            if not sql.startswith(
                f"ALTER TABLE tracelane.{label} DELETE WHERE tenant_id"
            ):
                failures.append(f"unexpected delete shape: {label}: {sql}")
            if label not in deletable:
                failures.append(f"ungranted sweep delete: {label}")
        elif not sql.startswith(
            f"SELECT count() AS n FROM tracelane.{label} WHERE tenant_id"
        ):
            failures.append(f"unexpected count shape: {label}: {sql}")
    return failures


def grants_selftest() -> None:
    import shutil

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        for file in (PURGE, SWEEP, USERS, COMPOSE):
            (root / file).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / file, root / file)
        assert not grants_and_statements(root), grants_and_statements(root)
        sweep = (root / SWEEP).read_text()
        users = (root / USERS).read_text()
        plants = [
            (
                SWEEP,
                sweep.replace(
                    "ALTER TABLE tracelane.spans DELETE",
                    "DELETE FROM tracelane.spans",
                    1,
                ),
                "lightweight",
            ),
            (
                USERS,
                users.replace(
                    "<query>GRANT SELECT, ALTER DELETE ON tracelane.spans</query>", ""
                ),
                "missing=['spans']",
            ),
            (
                SWEEP,
                sweep.replace('label: "spans"', 'label: "ungranted"', 1),
                "ungranted",
            ),
            (
                SWEEP,
                sweep.replace('orphan_delete_sql: "', 'missed_field: "', 1),
                "missed SQL fields",
            ),
            (
                SWEEP,
                sweep.replace(
                    "ALTER TABLE tracelane.spans DELETE",
                    "ALTER TABLE tracelane.spans UPDATE",
                    1,
                ),
                "unexpected delete shape",
            ),
        ]
        for privilege in (
            "ALTER",
            "ALTER TABLE",
            "ALL",
            "ALL PRIVILEGES",
            "SELECT, ALTER",
            "SELECT, ALL",
        ):
            plants.append(
                (
                    USERS,
                    users.replace(
                        "<query>GRANT SELECT ON tracelane.*</query>",
                        f"<query>GRANT {privilege} ON tracelane.datasets</query>",
                        1,
                    ),
                    "gateway still has delete/hidden-row grants",
                )
            )
        for file, content, needle in plants:
            (root / file).write_text(content)
            found = grants_and_statements(root)
            assert any(needle in f for f in found), (needle, found)
            print(f"selftest: plant BLOCKED: {needle}")
            (root / SWEEP).write_text(sweep)
            (root / USERS).write_text(users)


def sweeper_call_sites(root: Path) -> list[str]:
    """Only the two deletion jobs may reference the privileged constructor.

    Check references as well as calls so a handler cannot import it under an alias.
    This is a source guard, not containment against code execution in the process.
    """
    parser = runpy.run_path(str(ROOT / "scripts/ci/check-banned-patterns.py"))
    allowed = {
        SWEEP: "run_sweep_inner",
        "crates/gateway/src/billing/metering_job.rs": "run_gc",
    }
    findings = []
    for file in sorted((root / "crates").rglob("*.rs")):
        path = file.relative_to(root).as_posix()
        src = parser["production_part"](
            parser["strip_comments_and_strings"](file.read_text())
        )
        ranges = []
        name = allowed.get(path)
        if name:
            for fn in re.finditer(rf"\bfn\s+{name}\s*\([^{{]+\{{", src):
                start = fn.end()
                depth, end = 1, start
                while end < len(src) and depth:
                    depth += (src[end] == "{") - (src[end] == "}")
                    end += 1
                if depth == 0:
                    ranges.append((start, end))
        for match in re.finditer(r"\bsweeper_client\b", src):
            if path == "crates/gateway/src/clickhouse_query.rs" and re.search(
                r"\bfn\s+$", src[: match.start()]
            ):
                continue
            if not any(start <= match.start() < end for start, end in ranges):
                line = src.count("\n", 0, match.start()) + 1
                findings.append(
                    f"{path}:{line}: sweeper_client outside retention/blob GC allowlist"
                )
    return findings


def call_sites_selftest() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        handler = root / "crates/gateway/src/trace_reads.rs"
        handler.parent.mkdir(parents=True)
        handler.write_text(
            "async fn request_handler() { let ch = crate::clickhouse_query::sweeper_client(url); }"
        )
        found = sweeper_call_sites(root)
        assert any("trace_reads.rs:1" in f for f in found), (
            "request handler must be refused",
            found,
        )
        print("selftest: request-handler sweeper client BLOCKED")
        handler.unlink()
        for path, function in [
            (SWEEP, "run_sweep_inner"),
            ("crates/gateway/src/billing/metering_job.rs", "run_gc"),
        ]:
            file = root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            good = f"async fn {function}() {{ let ch = crate::clickhouse_query::sweeper_client(url); }}"
            file.write_text(good)
            assert not sweeper_call_sites(root)
            file.write_text(
                good
                + "\nasync fn handler() { let ch = crate::clickhouse_query::sweeper_client(url); }"
            )
            assert any(path + ":2" in f for f in sweeper_call_sites(root))
            file.write_text(
                good
                + "\nuse crate::clickhouse_query::sweeper_client as ordinary_client;"
            )
            assert any(path + ":2" in f for f in sweeper_call_sites(root))
            file.write_text(
                good
                + "\n#[cfg(test)] mod tests { fn proof() { sweeper_client(url); } }\nasync fn handler() { sweeper_client(url); }"
            )
            assert any(path + ":3" in f for f in sweeper_call_sites(root))
            file.unlink()
        print(
            "selftest: allowed jobs PASS; same-file handlers, aliases and post-test handlers BLOCKED"
        )


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        result = selftest()
        grants_selftest()
        call_sites_selftest()
        return result
    if argv == ["--print-deletes"]:
        statements = sweep_statements((ROOT / SWEEP).read_text())
        for _, field, sql in statements:
            if "delete" in field:
                tenant = "'00000000-0000-0000-0000-00000000dead'"
                if field.startswith("orphan"):
                    print(sql.replace("?", "(" + tenant + ")"))
                else:
                    print(sql.replace("?", tenant, 1).replace("?", "99999", 1))
        return 0
    if argv == ["--print-purge"]:
        # One table per line: the restore drill (`scripts/ops/tlane-ch-backup.sh`) counts
        # unknown-tenant rows over exactly this list, so it can never drift from the purge.
        purge = bash_array((ROOT / PURGE).read_text(), "CH_PURGE")
        if not purge:
            print("could not parse CH_PURGE", file=sys.stderr)
            return 2
        print("\n".join(purge))
        return 0
    if argv:
        print(
            f"usage: {Path(__file__).name} [--selftest | --print-purge]",
            file=sys.stderr,
        )
        return 2
    f = check(ROOT) + grants_and_statements(ROOT) + sweeper_call_sites(ROOT)
    for x in f:
        print(f"✗ {x}")
    if f:
        print(f"orphan sweep vs purge: {len(f)} table(s) out of step (B-459).")
        return 1
    print("orphan sweep vs purge: the orphan-swept tables equal CH_PURGE ✓")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
