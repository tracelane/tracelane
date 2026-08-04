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
1. Walk .rs/.ts/.tsx (skipping vendor/build dirs and *.test.* / *.spec.* /
   fixture / mock files, as before).
2. Rust only: blank out `#[cfg(test)] mod … { … }` bodies by brace matching,
   replacing them with newlines so line numbers are preserved. Required — e.g.
   `trace_reads.rs` asserts `TRACE_CHAIN_SQL.contains("FROM tracelane.audit_log")`
   inside its test module, which is a string ABOUT a query, not a query.
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
    2 — --selftest failed (the guard itself is broken)

Run locally:  python3 scripts/ci/check-tenant-isolation.py
Falsify it:   python3 scripts/ci/check-tenant-isolation.py --selftest
CI:           .github/workflows/ci.yml job `guards`, step
              "Tenant Isolation (ClickHouse SQL guard)".
"""

from __future__ import annotations

import os
import re
import sys
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

QUERY_PATTERN = re.compile(r"FROM\s+tracelane\.", re.IGNORECASE)
TENANT_ID_PATTERN = re.compile(r"\btenant_id\b|\btenantId\b", re.IGNORECASE)

# `${ident}` (TS template) or `{ident}` (Rust format!/ClickHouse named param).
# ClickHouse's own `{name: Type}` params are matched too; harmless — they just
# fail to resolve to an assignment and are ignored.
INTERPOLATION_PATTERN = re.compile(
    r"\$\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*[}:]|\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*[}:]"
)


def should_skip_path(path: Path) -> bool:
    name_lower = path.name.lower()
    if any(word in name_lower for word in SKIP_FILENAME_WORDS):
        return True
    return bool({p.lower() for p in path.parts} & SKIP_DIRS)


def blank_rust_test_mods(src: str) -> str:
    """Replace `#[cfg(test)] mod … { … }` bodies with newlines.

    Line numbers are preserved so violation reports stay accurate. Without
    this, assertions ABOUT query strings inside test modules read as queries.
    """
    out = list(src)
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
        for j in range(m.start(), min(i + 1, n)):
            if out[j] != "\n":
                out[j] = " "
    return "".join(out)


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


def scan_source(src: str, is_rust: bool) -> list[int]:
    """Return line numbers of unscoped `FROM tracelane.` queries in `src`."""
    if is_rust:
        src = blank_rust_test_mods(src)
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
            for lineno in scan_source(content, fpath.suffix == ".rs"):
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
]


def selftest() -> int:
    failures = 0
    for name, src, is_rust, expect in SELFTEST_CASES:
        got = bool(scan_source(src, is_rust))
        ok = got == expect
        print(
            f"  [{'PASS' if ok else 'FAIL'}] {name}: expected_violation={expect} got={got}"
        )
        if not ok:
            failures += 1
    if failures:
        print(f"\nSELFTEST FAILED — {failures} case(s). The guard is not trustworthy.")
        return 2
    print(
        f"\nSelftest passed — {len(SELFTEST_CASES)} cases, including a planted "
        "unscoped query beside a scoped one (the case the whole-file guard missed)."
    )
    return 0


def main() -> int:
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
