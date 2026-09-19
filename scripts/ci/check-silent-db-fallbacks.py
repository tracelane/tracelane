#!/usr/bin/env python3
"""A fallback on a ClickHouse / Postgres result in the billing, audit and eval paths must log at the site.

WHY THIS EXISTS (B-424, B-425, B-426 — 2026-09-16). Three defects sat in the BILL-01
metering job for two days behind a green gate and a healthy-looking deploy, and none
was found by a test. They were found by reading `/health` at session start. Each one
hid inside a SILENT fallback on a database result:

    query_period_daily_ingest(..).await.unwrap_or_default()      // no line — B-424
    ch.query(..).fetch_one().await.map(|n| n > 0).unwrap_or(true) // no line — B-426

A fail-OPEN fallback is the correct posture on a display or probe path (CLAUDE.md §10).
A fail-open fallback that says NOTHING is how a read that failed on every single call
looks exactly like a read that returned nothing — TRAPS §46, the class that hid the
semantic cache's 100% write failure and now three more.

WIDENED 2026-09-19 (B-427, B-428, B-429 — founder ruling). The scanner already SAW
the three sites below on 2026-09-16 and declined to block them, because they sat
outside SITES — a guard that sees a defect and does not block it is the expected-red
shape. `audit_export.rs`, `audit.rs` and `prompt_eval.rs` are now enforced, and a
second shape is flagged: `.ok()?` on a database result, the one that ended the
evidence-pack stream CLEANLY on a failed page read —

    read_anchor_records(..).await.unwrap_or_default()       // no line — B-427
    reader.read_range_page(..).await.ok()?                  // clean end — B-427
    query_one("SELECT pg_try_advisory_xact_lock").unwrap_or(false)  // B-428
    fetch_one().await.unwrap_or(0)                          // "no content" — B-429

THE RULE. In the files listed in SITES, a statement that ends in `unwrap_or(…)`,
`unwrap_or_default()`, `unwrap_or_else(…)` or `.ok()?` and whose receiver is a
database result — a direct `.fetch_one/.fetch_all/.fetch_optional/.execute/.query/
.query_one/.query_opt` chain, or a call to a function IN THE SAME FILE whose body
makes such a call — must carry, inside that same statement, one of:

    tracing::warn!(..)  tracing::error!(..)  warn!(..)  error!(..)  degradation::note(..)

— in the `unwrap_or_else` closure, or in an `inspect_err` / `map_err` earlier in the
chain. A counter counts as a signal because the logging policy prefers one
(`.claude/rules/logging.md`); silence does not. A site that must stay silent writes why:

    // silent-fallback-ok: <why nobody needs to know this read failed>

HONEST LIMIT. This reads statement TEXT: the statement is the span from the previous
`;` / `{` / `}` to the end of the `unwrap_or*` call, so a fallback reached through a
helper defined in ANOTHER file, or a result stored in a variable and unwrapped later,
is invisible to it. It scans only SITES — a new billing module is unseen until added
here. It proves a log line EXISTS in the statement, not that it says anything useful.
`--selftest` plants both real shapes above and proves each BLOCKS.

USAGE
  check-silent-db-fallbacks.py             # scan SITES
  check-silent-db-fallbacks.py --selftest  # plant violations, prove they block
  check-silent-db-fallbacks.py --file F    # scan one file (the selftest's path)
"""

from __future__ import annotations

import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SITES = [
    "crates/gateway/src/billing",  # every module: metering, rating, usage, meters, …
    "crates/gateway/src/entitlement_cache.rs",
    "crates/gateway/src/audit_export.rs",  # B-427 — the evidence pack
    "crates/gateway/src/audit.rs",  # B-428 — the anchor sweep's claim
    "crates/gateway/src/prompt_eval.rs",  # B-429 — a count that decides a message
]
EXEMPT_MARKER = "silent-fallback-ok:"
EXEMPT_WINDOW = 6
MIN_REASON = 20

# `.ok()?` is a fallback too: it turns `Err` into "stop here" with no line, which on
# a paging stream reads as "the ledger ended" (B-427). Matched as its own group so the
# finding can name the shape.
FALLBACK = re.compile(r"\.unwrap_or(?:_default|_else)?\s*\(|\.ok\s*\(\s*\)\s*\?")
DB_CALL = re.compile(
    r"\.(?:fetch_one|fetch_all|fetch_optional|execute|query|query_one|query_opt)\s*(?:::<[^>]*>)?\s*\("
)
LOG = re.compile(r"(?:tracing::)?(?:warn|error)!\s*\(|degradation::note\s*\(")
FN_DEF = re.compile(r"\b(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*[<(]")


def strip_test_modules(t: str) -> str:
    """Remove every `#[cfg(test)] mod name { … }` (balanced braces; strings/comments
    skipped) — NOT a cut at the first marker, which would blind this to
    `entitlement_cache.rs` (a cfg(test) item near its top)."""
    out: list[str] = []
    i = 0
    marker = "#[cfg(test)]"
    while True:
        j = t.find(marker, i)
        if j < 0:
            out.append(t[i:])
            return "".join(out)
        k = j + len(marker)
        m = re.match(
            r"(?:\s*#\[[^\]]*\])*\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{", t[k:]
        )
        if not m:
            out.append(t[i:k])
            i = k
            continue
        pos = k + m.end()
        pos = skip_block(t, pos, depth=1)
        out.append(t[i:j])
        i = pos


def skip_block(t: str, pos: int, depth: int) -> int:
    """Advance past the `}` that closes `depth` open braces, skipping strings/comments."""
    n = len(t)
    while pos < n and depth > 0:
        c = t[pos]
        if t.startswith("//", pos):
            nl = t.find("\n", pos)
            pos = n if nl < 0 else nl
            continue
        if c == "r" and re.match(r'r#*"', t[pos:]):
            hashes = len(t[pos + 1 :].split('"', 1)[0])
            end = t.find('"' + "#" * hashes, pos + 2 + hashes)
            pos = n if end < 0 else end + 1 + hashes
            continue
        if c == '"':
            pos += 1
            while pos < n and t[pos] != '"':
                pos += 2 if t[pos] == "\\" else 1
            pos += 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        pos += 1
    return pos


def call_end(t: str, open_paren: int) -> int:
    """Index just past the `)` matching `open_paren` (strings skipped)."""
    depth = 0
    i = open_paren
    n = len(t)
    while i < n:
        c = t[i]
        if c == '"':
            i += 1
            while i < n and t[i] != '"':
                i += 2 if t[i] == "\\" else 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def statement_start(t: str, pos: int) -> int:
    """Back to the previous `;`, `{` or `}` — the statement this fallback ends."""
    k = pos
    while k > 0 and t[k - 1] not in ";{}":
        k -= 1
    return k


def db_reading_fns(t: str) -> set[str]:
    """Names of functions in this file whose body makes a database call."""
    names: set[str] = set()
    for m in FN_DEF.finditer(t):
        brace = t.find("{", m.end())
        if brace < 0:
            continue
        body = t[brace + 1 : skip_block(t, brace + 1, depth=1)]
        if DB_CALL.search(body):
            names.add(m.group(1))
    return names


def exempt_reason(lines: list[str], line_no: int) -> str | None:
    lo = max(0, line_no - EXEMPT_WINDOW)
    for k in range(line_no - 1, lo - 1, -1):
        s = lines[k].strip()
        if EXEMPT_MARKER in s:
            return s.split(EXEMPT_MARKER, 1)[1].strip()
        if not s.startswith("//"):
            break
    return None


def scan_file(path: pathlib.Path) -> list[str]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    t = strip_test_modules(raw)
    lines = t.split("\n")
    fns = db_reading_fns(t)
    helper = (
        re.compile(r"\b(?:" + "|".join(map(re.escape, sorted(fns))) + r")\s*\(")
        if fns
        else None
    )
    findings: list[str] = []
    for m in FALLBACK.finditer(t):
        start = statement_start(t, m.start())
        # Only a fallback that ENDS the statement's chain is a fallback on the
        # result: `.bind(u32::try_from(n).unwrap_or(4))` inside a DB chain falls
        # back on `try_from`, not on the database (paren depth > 0 at the site).
        if t[start : m.start()].count("(") - t[start : m.start()].count(")") > 0:
            continue
        is_ok_q = m.group(0).rstrip().endswith("?")
        end = m.end() if is_ok_q else call_end(t, m.end() - 1)
        stmt = t[start:end]
        direct = bool(DB_CALL.search(stmt))
        via_helper = bool(helper and helper.search(stmt))
        if not (direct or via_helper):
            continue
        if LOG.search(stmt):
            continue
        line_no = t.count("\n", 0, m.start())
        reason = exempt_reason(lines, line_no)
        if reason is not None and len(reason) >= MIN_REASON:
            continue
        how = (
            "no exemption"
            if reason is None
            else f"exemption reason too short ({reason!r})"
        )
        rel = path.relative_to(ROOT) if path.is_relative_to(ROOT) else path
        what = (
            "a database call"
            if direct
            else "a function in this file that reads the database"
        )
        shape = ".ok()?" if is_ok_q else m.group(0).strip("(").strip()
        findings.append(
            f"{rel}:{line_no + 1}: {shape} on {what} with no "
            f"warn!/error!/degradation::note in the statement ({how}) — log the error at "
            f"the site, or write `// {EXEMPT_MARKER} <why silence is right here>`"
        )
    return findings


def scan(paths: list[pathlib.Path]) -> list[str]:
    out: list[str] = []
    for p in paths:
        if p.is_dir():
            for f in sorted(p.glob("*.rs")):
                out.extend(scan_file(f))
        elif p.exists():
            out.extend(scan_file(p))
        else:
            out.append(f"{p}: listed in SITES but does not exist — fix the list")
    return out


def selftest() -> int:
    cases: list[tuple[str, str, bool]] = [
        (
            "direct_chain_unwrap_or_default_is_silent",
            (
                "async fn f(ch: &clickhouse::Client) -> Vec<Row> {\n"
                "    ch.query(&sql).bind(1).fetch_all().await.unwrap_or_default()\n}\n"
            ),
            True,
        ),
        (
            "b426_shape_map_then_unwrap_or_true",
            (
                "async fn f(ch: &clickhouse::Client) -> bool {\n"
                '    ch.query(&capped("SELECT count() FROM t WHERE day = ?"))\n'
                "        .bind(d)\n        .fetch_one::<u64>()\n        .await\n"
                "        .map(|n| n > 0)\n        .unwrap_or(true)\n}\n"
            ),
            True,
        ),
        (
            "direct_chain_with_warn_in_closure",
            (
                "async fn f(ch: &clickhouse::Client) -> Vec<Row> {\n"
                "    ch.query(&sql).fetch_all().await.unwrap_or_else(|e| {\n"
                '        tracing::warn!(error = %e, "read failed");\n        Vec::new()\n    })\n}\n'
            ),
            False,
        ),
        (
            "b424_shape_helper_unwrap_or_default",
            (
                "async fn read_daily(ch: &clickhouse::Client) -> Result<Vec<Row>, E> {\n"
                "    ch.query(&sql).fetch_all().await\n}\n"
                "async fn handler(ch: &clickhouse::Client) {\n"
                "    let rows = read_daily(&ch).await.unwrap_or_default();\n    let _ = rows;\n}\n"
            ),
            True,
        ),
        (
            "helper_with_inspect_err_warn",
            (
                "async fn read_daily(ch: &clickhouse::Client) -> Result<Vec<Row>, E> {\n"
                "    ch.query(&sql).fetch_all().await\n}\n"
                "async fn handler(ch: &clickhouse::Client) {\n"
                "    let rows = read_daily(&ch)\n        .await\n"
                '        .inspect_err(|e| tracing::warn!(error = %e, "daily read failed"))\n'
                "        .unwrap_or_default();\n    let _ = rows;\n}\n"
            ),
            False,
        ),
        (
            "counter_note_counts_as_a_signal",
            (
                "async fn f(ch: &clickhouse::Client) -> u64 {\n"
                "    ch.query(&sql).fetch_one().await.unwrap_or_else(|_| {\n"
                "        tracelane_shared::degradation::note(Degradation::MeteringJobFailed);\n        0\n    })\n}\n"
            ),
            False,
        ),
        (
            "non_db_option_fallback_is_fine",
            "fn f(x: Option<u32>) -> u32 {\n    x.unwrap_or(3)\n}\n",
            False,
        ),
        (
            "fallback_inside_a_bind_argument_is_not_on_the_result",
            (
                "async fn f(ch: &clickhouse::Client) -> Vec<Row> {\n"
                "    ch.query(&sql).bind(u32::try_from(n).unwrap_or(4)).fetch_all().await?\n}\n"
            ),
            False,
        ),
        (
            "exempt_with_reason",
            (
                "async fn f(ch: &clickhouse::Client) -> Vec<Row> {\n"
                "    // silent-fallback-ok: the caller logs the aggregate miss count once per tick\n"
                "    ch.query(&sql).fetch_all().await.unwrap_or_default()\n}\n"
            ),
            False,
        ),
        (
            "exempt_reason_too_short",
            (
                "async fn f(ch: &clickhouse::Client) -> Vec<Row> {\n"
                "    // silent-fallback-ok: fine\n"
                "    ch.query(&sql).fetch_all().await.unwrap_or_default()\n}\n"
            ),
            True,
        ),
        (
            "b427_shape_ok_question_on_a_db_helper_ends_a_stream_silently",
            (
                "async fn read_range_page(ch: &clickhouse::Client) -> Result<Vec<Row>, E> {\n"
                "    ch.query(&sql).fetch_all().await\n}\n"
                "async fn page(ch: &clickhouse::Client) -> Option<Vec<Row>> {\n"
                "    let page = read_range_page(&ch).await.ok()?;\n    Some(page)\n}\n"
            ),
            True,
        ),
        (
            "ok_question_on_a_direct_db_call_is_silent",
            (
                "async fn f(ch: &clickhouse::Client) -> Option<u64> {\n"
                "    let n = ch.query(&sql).fetch_one::<u64>().await.ok()?;\n    Some(n)\n}\n"
            ),
            True,
        ),
        (
            "ok_question_with_inspect_err_warn_passes",
            (
                "async fn f(ch: &clickhouse::Client) -> Option<u64> {\n"
                "    let n = ch.query(&sql).fetch_one::<u64>().await\n"
                '        .inspect_err(|e| tracing::warn!(error = %e, "count read failed"))\n'
                "        .ok()?;\n    Some(n)\n}\n"
            ),
            False,
        ),
        (
            "ok_question_on_a_non_db_result_is_fine",
            (
                "fn f(s: &str) -> Option<u64> {\n"
                "    let n = s.parse::<u64>().ok()?;\n    Some(n)\n}\n"
            ),
            False,
        ),
        (
            "test_module_is_not_scanned",
            (
                "fn prod() -> u32 { 1 }\n#[cfg(test)]\nmod tests {\n"
                "    async fn t(ch: &clickhouse::Client) -> Vec<Row> {\n"
                "        ch.query(&sql).fetch_all().await.unwrap_or_default()\n    }\n}\n"
            ),
            False,
        ),
    ]
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, src, expect_block in cases:
            f = pathlib.Path(tmp) / f"{name}.rs"
            f.write_text(src)
            got = scan_file(f)
            blocked = bool(got)
            ok = blocked == expect_block
            bad += 0 if ok else 1
            print(
                f"  {'✓' if ok else '✗'} {name}: {'BLOCKED' if blocked else 'passed'} "
                f"(expected {'BLOCK' if expect_block else 'pass'})"
            )
            for g in got:
                print(f"      {g}")
    if bad:
        print(f"✗ selftest: {bad} case(s) did not behave as expected")
        return 1
    print(
        f"✓ selftest: {len(cases)} cases — the unwrap_or* and .ok()? prod shapes block; a "
        "warn!, error! or degradation::note in the statement passes; exemptions need a reason"
    )
    return 0


def main(argv: list[str]) -> int:
    args = list(argv)
    if "--selftest" in args:
        if len(args) != 1:
            print("✗ --selftest takes no other arguments")
            return 2
        return selftest()
    paths = [ROOT / s for s in SITES]
    if "--file" in args:
        i = args.index("--file")
        if i + 1 >= len(args):
            print("✗ --file needs a path")
            return 2
        paths = [pathlib.Path(args[i + 1])]
        del args[i : i + 2]
    if args:
        print(f"✗ unknown argument(s): {' '.join(args)}")
        print((__doc__ or "").split("USAGE", 1)[1])
        return 2
    findings = scan(paths)
    if findings:
        print(
            "✗ silent fallbacks on database results in the billing / entitlement / audit / eval paths:"
        )
        for f in findings:
            print(f"  {f}")
        return 1
    print(
        f"✓ silent-db-fallbacks: every fallback on a database result in {len(SITES)} site(s) logs at the site"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
