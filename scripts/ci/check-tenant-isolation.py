#!/usr/bin/env python3
"""
Tenant isolation guard — every ClickHouse query against tracelane.* MUST carry
a tenant_id filter sourced from server-side auth, never from user input.

PER-QUERY (2026-08-03). The previous implementation was WHOLE-FILE: it flagged
a file only if it contained `FROM tracelane.` and never mentioned `tenant_id`
*anywhere* in the file. Its docstring called that "a strict superset that
catches every real violation" — that claim was false. It is a superset of
FILES, not of QUERIES: nine tenant-scoped queries sitting beside one unscoped
query in the same file passed clean, and every real file here has at least one
scoped query. The guard covered CLAUDE.md's #1 non-negotiable and the repo's
self-declared #1 recurring bug class, and it could not fail. It never had.

    Proof it was vacuous: planting `SELECT * FROM tracelane.spans` (no tenant
    filter) into any already-scoped file left the old guard GREEN. See
    `--selftest`, case `unscoped_beside_scoped`.

How the per-query check works
-----------------------------
1. Walk .rs/.ts/.tsx, skipping vendor/build dirs only.
2. Identify TEST REGIONS — a `#[cfg(test)] mod|fn … { … }` block (brace-matched),
   or the whole file when its name says test/spec/fixture/mock. Inside a region
   the rule is stricter, not absent (see below); outside it is unchanged.

   B-180 (2026-08-12) — THIS USED TO BE A BLIND SPOT, and it was the wrong one
   to have. Test-named files were dropped from the walk entirely and
   `#[cfg(test)]` bodies were blanked out, because
   `trace_reads.rs` asserts `TRACE_CHAIN_SQL.contains("FROM tracelane.audit_log")`
   inside its test module — a string ABOUT a query, not a query. Correct problem,
   too blunt a fix: integration tests here are NOT hermetic.
   `crates/gateway/src/guardrail/engine.rs:1168,1233` poll a LIVE ClickHouse from
   inside `#[cfg(test)]`, so an unscoped query there would execute against real
   multi-tenant data — and the guard covering the repo's #1 recurring bug class
   was, by construction, silent exactly there.

   Falsified rather than assumed: a planted `db.query({query: "… FROM
   tracelane.spans …"})` in `x.test.ts` and the BYTE-IDENTICAL body in `x.ts`
   returned opposite verdicts, decided purely by the filename.

   The fix is two-mode. In a test region a literal counts as a query only if it
   is EXECUTOR-REACHABLE (passed to `.query(`/`.execute(`/`query:`/
   `TenantQuery::new(`, directly or one hop through a named constant). So
   `assert!(SQL.contains(…))` and `expect(q.query).toContain(…)` stay clean while
   an executed query does not. Applying that adjacency rule to PRODUCTION code
   would be a regression — production SQL is a `const` declared far from its
   executor — so production keeps the original rule verbatim, and all eight
   original selftest cases still pass unchanged.

   Honest limit: the executor list is deliberately narrow and closed. A test-region
   query reaching ClickHouse through a shape not listed in `EXECUTOR_CALL_BEFORE`
   is still missed. Widening it to "anything that looks like a call" would re-flag
   every assertion and put the guard back where it started.
3. Tokenise the file's string literals (Rust `"…"` / `r"…"` / `r#"…"#`,
   TS `"…"` / `'…'` / `` `…` ``), skipping comments. The QUERY UNIT for each
   `FROM tracelane.` match is the literal that contains it — not the file.
4. A unit passes if it references tenant_id / tenantId.
5. Otherwise, resolve ONE level of interpolation. `apps/mcp/src/tools/traces.ts`
   builds `${where}` from `let where = "WHERE tenant_id = {tenantId: String}"`,
   so the tenant filter is genuinely present but one hop away. For each
   `${ident}` (TS) or `{ident}` (Rust format!) in the unit, look for an
   assignment to that identifier in the same file and check IT for tenant_id.
   One hop only — deeper indirection must be made obvious at the query site.
6. Anything still unscoped is a violation, reported as file:line of the FROM.

This is deliberately stricter than the old check and CAN false-positive on a
query whose tenant filter is more than one hop away. That is the correct
trade: a false positive is a five-minute conversation, a false negative is a
cross-tenant data leak.

Exit codes:
    0 — no violations
    1 — at least one query against tracelane.* lacks a tenant_id filter
    2 — --selftest failed (the guard itself is broken), OR an unrecognised
        command-line flag was passed

An unknown flag is REJECTED, never ignored. `--selftesst` (typo) used to run the
ordinary guard and exit 0, so an operator believed a selftest had run when none
had — the guard's falsification claim rested on a flag it never parsed.

Run locally:  python3 scripts/ci/check-tenant-isolation.py
Falsify it:   python3 scripts/ci/check-tenant-isolation.py --selftest
CI:           .github/workflows/ci.yml job `guards`, step
              "Tenant Isolation (ClickHouse SQL guard)".
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "target",
    ".next",
    ".turbo",
    "coverage",
}
SKIP_FILENAME_WORDS = {"test", "spec", "fixture", "mock", ".d.ts"}
SCAN_EXTENSIONS = (".rs", ".ts", ".tsx")


def _clickhouse_tables() -> list[str]:
    """Table names DERIVED from the ClickHouse schema, never restated here.

    PATTERN A (2026-08-13). A hardcoded copy of a list that already exists drifts
    silently, always toward less coverage — it is the single commonest defect
    across this repo's guards (~14 of 49). The schema is the authoritative source,
    so read it.

    FAILS CLOSED. If the schema cannot be read, this raises rather than returning
    a short list: a guard that quietly narrows its own scope is exactly the
    "I could not look, so nothing is there" shape (PATTERN B, CLAUDE.md §1.14).
    """
    # The repo root is derived here rather than reused: this runs at IMPORT time,
    # before main() computes its own `repo_root`.
    root = Path(__file__).resolve().parent.parent.parent
    schema = root / "infra" / "dev" / "clickhouse" / "schema.sql"
    if not schema.is_file():
        raise SystemExit(
            f"check-tenant-isolation: CANNOT DETERMINE — {schema} is missing, so the\n"
            "table list cannot be derived. Refusing to scan with a partial list."
        )
    names = re.findall(
        r"CREATE\s+(?:TABLE|MATERIALIZED\s+VIEW)(?:\s+IF\s+NOT\s+EXISTS)?\s+"
        r"(?:[A-Za-z_][A-Za-z0-9_]*\.)?([A-Za-z_][A-Za-z0-9_]*)",
        schema.read_text(encoding="utf-8"),
        re.IGNORECASE,
    )
    uniq = sorted(set(names))
    if not uniq:
        raise SystemExit(
            "check-tenant-isolation: CANNOT DETERMINE — parsed ZERO tables from the\n"
            "schema. A zero-length scope is never a pass."
        )
    return uniq


CH_TABLES = _clickhouse_tables()

# BOTH SPELLINGS. Until 2026-08-13 this was `FROM\s+tracelane\.` alone, and the
# codebase overwhelmingly writes the UNQUALIFIED form: 19 sites carried the
# qualified spelling and **46 carried the bare one**, so the guard on CLAUDE.md's
# #1 non-negotiable could not see 70% of the surface it exists to police.
# `CLICKHOUSE_DB=tracelane`, so `FROM spans` and `FROM tracelane.spans` read the
# same table — the distinction was never semantic, only stylistic.
#
# There was no leak, and that is the finding rather than the reassurance: all 39
# production sites HAPPEN to carry a tenant filter (the other 7 are
# `assert!(sql.contains(...))` strings in test modules). The invariant was held by
# coincidence, not by a control — TRAPS §25.
QUERY_PATTERN = re.compile(
    r"FROM\s+(?:tracelane\.\w+|(?:" + "|".join(CH_TABLES) + r")\b)",
    re.IGNORECASE,
)
TENANT_ID_PATTERN = re.compile(r"\btenant_id\b|\btenantId\b", re.IGNORECASE)

# `${ident}` (TS template) or `{ident}` (Rust format!/ClickHouse named param).
# ClickHouse's own `{name: Type}` params are matched too; harmless — they just
# fail to resolve to an assignment and are ignored.
INTERPOLATION_PATTERN = re.compile(
    r"\$\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*[}:]|\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*[}:]"
)


def should_skip_path(path: Path) -> bool:
    """Hard skip: vendor / build output only. Test-NAMED files are no longer
    dropped here — they are scanned as a test region (B-180). See
    `path_is_all_test_region`."""
    return bool({p.lower() for p in path.parts} & SKIP_DIRS)


def path_is_all_test_region(path: Path) -> bool:
    """Is the WHOLE file test code, by filename convention?

    B-180: this used to mean "do not scan at all". A test file is not hermetic
    here — `crates/gateway/src/guardrail/engine.rs` polls a LIVE ClickHouse from
    inside `#[cfg(test)]`, and an unscoped query there executes against real
    multi-tenant data. Dropping the file put the guard's blind spot exactly where
    its blast radius was. The file is now scanned under the stricter
    executor-reachability rule instead.
    """
    return any(word in path.name.lower() for word in SKIP_FILENAME_WORDS)


def rust_test_mod_spans(src: str) -> list[tuple[int, int]]:
    """Offset spans of `#[cfg(test)] mod|fn … { … }` blocks.

    B-180: this used to BLANK these regions (`blank_rust_test_mods`), which is
    why `assert!(SQL.contains("FROM tracelane.audit_log"))` did not read as a
    query — and also why a genuinely executed unscoped query in a test module
    did not either. Returning the spans instead lets the scanner keep the first
    behaviour and drop the second: inside a span a query must be shown to reach
    an executor before it counts.
    """
    spans: list[tuple[int, int]] = []
    for m in re.finditer(r"#\[cfg\(test\)\]", src):
        brace = src.find("{", m.end())
        if brace == -1:
            continue
        # Only treat it as a module/block if `mod` or `fn` precedes the brace.
        head = src[m.end() : brace]
        if not re.search(r"\b(mod|fn)\b", head):
            continue
        depth, i, n = 0, brace, len(src)
        while i < n:
            c = src[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        spans.append((m.start(), min(i + 1, n)))
    return spans


# ---------------------------------------------------------------------------
# Executor reachability (, test regions only)
# ---------------------------------------------------------------------------
#
# The filed fix shape — "only flag a literal actually PASSED to a query
# executor" — is CORRECT for test code and a REGRESSION if applied everywhere:
# production SQL is overwhelmingly a `const`/`static` declared far from its
# executor, so requiring syntactic adjacency would silently disarm the guard on
# exactly the code it exists to protect. Hence two modes:
#
#   production region -> today's rule, unchanged (a literal is a query)
#   test region       -> a literal is a query only if it reaches an executor
#
# The shapes below are the ones that exist in this repo. Deliberately narrow: a
# new executor shape must be added here, and until it is, a test-region query
# using it is missed. That is stated rather than hidden — the alternative
# (matching anything that looks like a call) would re-flag every
# `assert!(SQL.contains(…))` and put us back where we started.

# The literal is the argument: `ch.query("…")`, `db.query({ query: "…" })`,
# `client.execute("…")`, `TenantQuery::new("…", …)`.
EXECUTOR_CALL_BEFORE = re.compile(
    r"(?:\.\s*(?:query|execute)\s*\(|(?<![A-Za-z0-9_])query\s*:\s*|"
    r"TenantQuery::new\s*\(\s*)(?:&\s*)?$"
)

# The literal is bound to a name that is later handed to an executor.
ASSIGNED_NAME_BEFORE = re.compile(
    r"(?:const|let|var|static)\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*:\s*[^=\n]*)?\s*=\s*(?:&\s*)?$"
)


def name_reaches_executor(ident: str, src: str) -> bool:
    """Is `ident` passed to a query executor anywhere in this file? One hop."""
    return bool(
        re.search(
            rf"(?:\.\s*(?:query|execute)\s*\(\s*(?:&\s*)?{re.escape(ident)}\b"
            rf"|(?<![A-Za-z0-9_])query\s*:\s*{re.escape(ident)}\b"
            rf"|TenantQuery::new\s*\(\s*{re.escape(ident)}\b)",
            src,
        )
    )


def reaches_executor(src: str, literal_start: int) -> bool:
    """Does the literal beginning at `literal_start` reach a query executor?"""
    # Look back a bounded distance, collapsing whitespace/newlines so a call
    # broken across lines still matches.
    lead = src[max(0, literal_start - 200) : literal_start]
    lead = re.sub(r"\s+", " ", lead)
    if EXECUTOR_CALL_BEFORE.search(lead):
        return True
    m = ASSIGNED_NAME_BEFORE.search(lead)
    return bool(m and name_reaches_executor(m.group(1), src))


def string_literal_spans(
    src: str, is_rust: bool
) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Return (literal_spans, comment_spans) as (start, end) offset pairs.

    Comment spans are returned so the caller can DISCARD query matches that
    live in commented-out code. Without that, a commented query has no
    containing literal, falls through to the bounded-window fallback, and is
    reported as a violation — caught by the `commented_out_query_is_ignored`
    selftest case before this guard ever ran on the repo.

    Handles Rust raw strings (r"…", r#"…"#) and TS template literals.
    """
    spans: list[tuple[int, int]] = []
    comments: list[tuple[int, int]] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        # comments
        if c == "/" and i + 1 < n:
            if src[i + 1] == "/":
                end = src.find("\n", i)
                end = n if end == -1 else end
                comments.append((i, end))
                i = end
                if i >= n:
                    break
                continue
            if src[i + 1] == "*":
                end = src.find("*/", i + 2)
                end = n if end == -1 else end + 2
                comments.append((i, end))
                i = end
                continue
        # Rust raw string: r"…" or r#"…"#  (any number of #)
        if is_rust and c == "r":
            j = i + 1
            hashes = 0
            while j < n and src[j] == "#":
                hashes += 1
                j += 1
            if j < n and src[j] == '"':
                terminator = '"' + "#" * hashes
                end = src.find(terminator, j + 1)
                end = n if end == -1 else end + len(terminator)
                spans.append((j, end))
                i = end
                continue
        if c in ('"', "'") or (not is_rust and c == "`"):
            quote = c
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == quote:
                    break
                j += 1
            spans.append((i, min(j + 1, n)))
            i = j + 1
            continue
        i += 1
    return spans, comments


def containing_span(
    spans: list[tuple[int, int]], offset: int
) -> tuple[int, int] | None:
    for s, e in spans:
        if s <= offset < e:
            return (s, e)
    return None


def resolves_to_tenant_scope(ident: str, src: str) -> bool:
    """Does `ident` get assigned something containing tenant_id in this file?

    One hop only. Covers `let where = "WHERE tenant_id = {tenantId: String}"`
    (traces.ts:38, :272) and `const X: &str = "… tenant_id …"` in Rust.
    """
    for m in re.finditer(
        rf"(?:const|let|var|static)\s+(?:mut\s+)?{re.escape(ident)}\b[^=\n]*=\s*(.{{0,400}})",
        src,
        re.DOTALL,
    ):
        if TENANT_ID_PATTERN.search(m.group(1)):
            return True
    return False


def scan_source(src: str, is_rust: bool, all_test_region: bool = False) -> list[int]:
    """Return line numbers of unscoped `FROM tracelane.` queries in `src`.

    `all_test_region` marks a file that is test code by filename convention, so
    every match is judged under the test-region rule (B-180).
    """
    if all_test_region:
        test_spans = [(0, len(src))]
    else:
        test_spans = rust_test_mod_spans(src) if is_rust else []
    spans, comments = string_literal_spans(src, is_rust)
    bad: list[int] = []

    for qm in QUERY_PATTERN.finditer(src):
        # A query inside a comment is documentation, not a query.
        if containing_span(comments, qm.start()) is not None:
            continue
        span = containing_span(spans, qm.start())
        # A FROM outside any string literal is not a query we can reason about
        # (it is prose in a doc-comment that survived comment-stripping, or a
        # construction we cannot see). Fall back to a bounded window rather
        # than the whole file.
        if span is None:
            unit = src[max(0, qm.start() - 200) : qm.start() + 400]
        else:
            unit = src[span[0] : span[1]]

        # Inside a test region a string containing `FROM tracelane.` is
        # usually an ASSERTION ABOUT a query (`assert!(SQL.contains(…))`,
        # `expect(q.query).toContain(…)`), not a query. It only counts if it can
        # be shown to reach an executor — which is what makes the live-ClickHouse
        # queries in `guardrail/engine.rs`'s test module visible to this guard for
        # the first time.
        if containing_span(test_spans, qm.start()) is not None and not reaches_executor(
            src, span[0] if span else qm.start()
        ):
            continue

        # THE BARE SPELLING NEEDS SQL CONTEXT, THE QUALIFIED ONE DOES NOT.
        # `FROM tracelane.spans` can only be a query. `FROM spans` is also an
        # ENGLISH PHRASE, and the first run of the widened pattern proved it:
        # `packages/cli/src/commands/export.ts:375` matched
        # "PII regex layer removes SSN, CC, email, phone, AWS keys FROM SPANS"
        # — prose inside a generated compliance document. A guard that cries wolf
        # on prose is one people learn to skip, which is how the widening would
        # have undone itself. So a bare table name only counts as a query when a
        # SELECT is in the same unit; a real ClickHouse read always has one.
        if "tracelane." not in qm.group(0).lower() and not re.search(
            r"\bSELECT\b", unit, re.IGNORECASE
        ):
            continue

        if TENANT_ID_PATTERN.search(unit):
            continue

        # One hop of interpolation.
        resolved = False
        for im in INTERPOLATION_PATTERN.finditer(unit):
            ident = im.group(1) or im.group(2)
            if ident and resolves_to_tenant_scope(ident, src):
                resolved = True
                break
        if resolved:
            continue

        bad.append(src[: qm.start()].count("\n") + 1)
    return bad


def find_violations(repo_root: Path) -> list[tuple[Path, int]]:
    violations: list[tuple[Path, int]] = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if not fname.endswith(SCAN_EXTENSIONS):
                continue
            fpath = Path(dirpath) / fname
            rel = fpath.relative_to(repo_root)
            if should_skip_path(rel):
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if not QUERY_PATTERN.search(content):
                continue
            for lineno in scan_source(
                content, fpath.suffix == ".rs", path_is_all_test_region(rel)
            ):
                violations.append((rel, lineno))
    return violations


# ---------------------------------------------------------------------------
# Self-test: the guard must be observed FAILING on planted violations, or it is
# assumed decorative. Each case is a minimal source snippet, not a repo write.
# ---------------------------------------------------------------------------

SELFTEST_CASES: list[tuple[str, str, bool, bool]] = [
    # (name, source, is_rust, expect_violation)
    (
        "scoped_rust_const",
        'const S: &str = "SELECT a FROM tracelane.spans WHERE tenant_id = ?";',
        True,
        False,
    ),
    (
        "unscoped_rust_const",
        'const S: &str = "SELECT a FROM tracelane.spans WHERE ts > now()";',
        True,
        True,
    ),
    (
        # THE case the old whole-file guard could not catch.
        "unscoped_beside_scoped",
        (
            'const OK: &str = "SELECT a FROM tracelane.spans WHERE tenant_id = ?";\n'
            'const BAD: &str = "SELECT b FROM tracelane.trace_summaries WHERE ts > now()";'
        ),
        True,
        True,
    ),
    (
        "rust_test_mod_assertion_is_not_a_query",
        (
            "#[cfg(test)]\nmod tests {\n  #[test]\n  fn t() {\n"
            '    assert!(SQL.contains("FROM tracelane.audit_log"));\n  }\n}'
        ),
        True,
        False,
    ),
    (
        "ts_template_inline_scope",
        "const q = `SELECT a FROM tracelane.spans WHERE tenant_id = {tenantId: String}`;",
        False,
        False,
    ),
    (
        "ts_template_interpolated_scope_one_hop",
        (
            'let where = "WHERE tenant_id = {tenantId: String}";\n'
            "const q = `SELECT a FROM tracelane.spans ${where} LIMIT 1`;"
        ),
        False,
        False,
    ),
    (
        "ts_template_interpolated_UNSCOPED_one_hop",
        (
            'let where = "WHERE start_time > now()";\n'
            "const q = `SELECT a FROM tracelane.spans ${where} LIMIT 1`;"
        ),
        False,
        True,
    ),
    (
        "commented_out_query_is_ignored",
        '// const S: &str = "SELECT a FROM tracelane.spans";\nfn f() {}',
        True,
        False,
    ),
    # ──: the test-region surface. Previously these regions were BLANKED,
    # so every case below returned "clean" — including the executed ones.
    (
        "test_mod_executed_unscoped_query_BLOCKS",
        (
            "#[cfg(test)]\nmod tests {\n"
            '    let r = ch.query("SELECT decision FROM tracelane.guardrail_verdicts LIMIT 1")\n'
            "        .fetch_optional::<Row>();\n}"
        ),
        True,
        True,
    ),
    (
        "test_mod_executed_SCOPED_query_passes",
        # guardrail/engine.rs:1168 verbatim in shape — a real live-CH query that
        # IS correctly scoped. It must stay clean, or the fix costs a false alarm
        # on the very code that motivated it.
        (
            "#[cfg(test)]\nmod tests {\n"
            '    let r = ch.query("SELECT decision FROM tracelane.guardrail_verdicts \\\n'
            '         WHERE tenant_id = ? AND correlation_id = ? LIMIT 1")\n'
            "        .bind(&tenant_key).fetch_optional::<Row>();\n}"
        ),
        True,
        False,
    ),
    (
        "test_mod_contains_assertion_is_not_a_query",
        # The case the blanking existed to handle. It must STILL be clean now
        # that the region is scanned — this is what "two-mode" buys.
        (
            "#[cfg(test)]\nmod tests {\n"
            '    assert!(TRACE_CHAIN_SQL.contains("FROM tracelane.audit_log"));\n}'
        ),
        True,
        False,
    ),
    # NOTE: the TypeScript `toContain` equivalent is a PATH case, not one of
    # these — a TS file is test code by FILENAME, so asserting it here would test
    # a code path that cannot exist. It lives in SELFTEST_PATH_CASES below.
    (
        "test_mod_const_handed_to_executor_BLOCKS",
        # One hop: the literal is bound to a name, and the NAME reaches the
        # executor. Adjacency alone would miss this.
        (
            "#[cfg(test)]\nmod tests {\n"
            '    const SQL: &str = "SELECT a FROM tracelane.spans LIMIT 100";\n'
            "    let r = ch.query(SQL).fetch_all::<Row>();\n}"
        ),
        True,
        True,
    ),
    # ── THE BARE SPELLING (2026-08-13). The guard matched only
    # `FROM tracelane.` while the codebase overwhelmingly writes the
    # unqualified form — 19 qualified sites against 46 bare ones, i.e. 70% of
    # the surface of CLAUDE.md's #1 non-negotiable was invisible. There was no
    # leak because all 39 production sites HAPPEN to carry a filter, which is
    # coincidence, not a control (TRAPS §25).
    (
        "bare-spelling unscoped query (the 46-site blind spot)",
        'let sql = "SELECT trace_id, name FROM spans WHERE start_time > now() - 3600";',
        True,
        True,
    ),
    (
        "bare-spelling SCOPED query must PASS (not a wall)",
        'let sql = "SELECT trace_id FROM spans WHERE tenant_id = ? AND start_time > now()";',
        True,
        False,
    ),
    # A bare table name is also an ENGLISH PHRASE. The first run of the widened
    # pattern fired on `packages/cli/src/commands/export.ts:375` — "the PII regex
    # layer removes SSN, CC, email, phone, AWS keys FROM SPANS" — prose inside a
    # generated compliance document. A guard that cries wolf on prose is one
    # people learn to skip, which would have undone the widening. Hence: a bare
    # table only counts as a query when a SELECT shares the unit.
    (
        "prose containing 'from spans' must NOT fire",
        'pub const NOTE: &str = "we strip AWS keys from spans at ingest";',
        True,
        False,
    ),
    (
        "bare-spelling unscoped query in TypeScript",
        "const q = `SELECT trace_id FROM guardrail_verdicts WHERE created_at > now()`;",
        False,
        True,
    ),
    (
        # PL-20 #2, PINNED 2026-08-20. The falsification-backlog audit recorded
        # this guard as "weak BY CONSTRUCTION — `:100` searches the whole file, so
        # nine scoped queries beside one unscoped in the same file passes clean",
        # and ranked fixing it #2 of three.
        #
        # Re-measured on the day that review came due: the guard ALREADY catches
        # it. B-226 rewrote the scan to judge each query against its own string
        # literal rather than the file, so the audit's premise had gone stale.
        #
        # Nothing PINNED it, though. The property held by construction of the
        # current implementation, and a refactor that widened the unit back toward
        # file scope would restore the blind spot with every existing test still
        # green — precisely the class PL-20 exists to close. The audit's own
        # fixture is therefore a permanent case now, not a one-off check someone
        # ran once and wrote a sentence about.
        "nine scoped queries beside one unscoped, same file (PL-20 #2)",
        "\n".join(
            f'const OK{i}: &str = "SELECT a FROM tracelane.spans WHERE tenant_id = ?";'
            for i in range(9)
        )
        + '\nconst BAD: &str = "SELECT a FROM tracelane.spans WHERE trace_id = ?";',
        True,
        True,
    ),
    (
        # The other direction, because a guard that always fires is a wall rather
        # than a gate: ten scoped queries in one file must stay clean.
        "ten scoped queries, same file, no false positive (PL-20 #2)",
        "\n".join(
            f'const OK{i}: &str = "SELECT a FROM tracelane.spans WHERE tenant_id = ?";'
            for i in range(10)
        ),
        True,
        False,
    ),
]

# find_violations-level cases: (relative path, source, expect_violation).
# The filename-skip surface had ZERO selftest coverage — every case above calls
# `scan_source` directly, which cannot exercise `path_is_all_test_region`. A skip
# rule with no test is how a whole class of files goes unscanned unnoticed.
SELFTEST_PATH_CASES: list[tuple[str, str, bool]] = [
    (
        "apps/x/leak.test.ts",
        "const rows = await db.query({ query: `SELECT prompt FROM tracelane.spans LIMIT 100` });",
        True,
    ),
    (
        "apps/x/leak.ts",
        # The BYTE-IDENTICAL body outside a test filename. Same verdict — the
        # point of is that the filename stopped deciding the answer.
        "const rows = await db.query({ query: `SELECT prompt FROM tracelane.spans LIMIT 100` });",
        True,
    ),
    (
        "apps/x/assert.test.ts",
        'expect(built.query).toContain("FROM tracelane.spans");',
        False,
    ),
    (
        "node_modules/pkg/leak.ts",
        # Vendor is still a hard skip — scanning it would flag other people's code.
        "const rows = await db.query({ query: `SELECT prompt FROM tracelane.spans` });",
        False,
    ),
]


def selftest() -> int:
    failures = 0
    for name, src, is_rust, expect in SELFTEST_CASES:
        # all_test_region=False for every case here: a Rust test region is found
        # from `#[cfg(test)]` in the source itself, and the FILENAME surface is
        # only reachable through find_violations (SELFTEST_PATH_CASES). Inferring
        # the flag from the case NAME — which an earlier draft of this did — makes
        # the harness assert something other than what it claims to.
        got = bool(scan_source(src, is_rust))
        ok = got == expect
        print(
            f"  [{'PASS' if ok else 'FAIL'}] {name}: expected_violation={expect} got={got}"
        )
        if not ok:
            failures += 1

    # Whole-walk cases: these are the only ones that exercise the FILENAME
    # surface, so they are planted in a real (temporary) tree and run through
    # find_violations, not scan_source.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, src, _ in SELFTEST_PATH_CASES:
            fp = root / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(src, encoding="utf-8")
        found = {str(p) for p, _ in find_violations(root)}
        for rel, _, expect in SELFTEST_PATH_CASES:
            got = rel in found
            ok = got == expect
            print(
                f"  [{'PASS' if ok else 'FAIL'}] path:{rel}: "
                f"expected_violation={expect} got={got}"
            )
            if not ok:
                failures += 1

    total = len(SELFTEST_CASES) + len(SELFTEST_PATH_CASES)
    if failures:
        print(f"\nSELFTEST FAILED — {failures} case(s). The guard is not trustworthy.")
        return 2
    print(
        f"\nSelftest passed — {total} cases. Covers a planted unscoped query beside a "
        "scoped one (the case the whole-file guard missed), an EXECUTED unscoped query "
        "inside #[cfg(test)] and inside a *.test.ts file (both invisible before B-180), "
        "and the assertions-about-queries that must stay clean in the same regions."
    )
    return 0


# Every flag this script understands. An argv token starting with `-` that is not
# here is a typo or a wrong assumption, and must not run the guard silently.
KNOWN_FLAGS = {"--selftest"}


def reject_unknown_flags(argv: list[str]) -> int | None:
    """Return 2 on any option-looking token that is not a real flag, else None."""
    unknown = [a for a in argv if a.startswith("-") and a not in KNOWN_FLAGS]
    if unknown:
        print(
            f"{Path(__file__).name}: unrecognised option {unknown[0]!r}\n"
            f"usage: {Path(__file__).name} [--selftest]",
            file=sys.stderr,
        )
        return 2
    return None


def main() -> int:
    bad_flag = reject_unknown_flags(sys.argv[1:])
    if bad_flag is not None:
        return bad_flag
    if "--selftest" in sys.argv:
        return selftest()

    repo_root = Path(__file__).resolve().parent.parent.parent
    violations = find_violations(repo_root)

    if violations:
        print("ERROR: ClickHouse query against tracelane.* without a tenant_id filter:")
        for fpath, lineno in violations:
            print(f"  {fpath}:{lineno}")
        print()
        print("Every QUERY against tracelane.* must filter on tenant_id, sourced from")
        print("server-side auth (session.tenantId, getTenantId(), or a JWT claim) —")
        print("never from a request body. See CLAUDE.md §SQL.")
        return 1

    print("Tenant isolation check passed (per-query).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
