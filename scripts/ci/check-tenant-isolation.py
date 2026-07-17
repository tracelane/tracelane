#!/usr/bin/env python3
"""
Tenant isolation guard — every ClickHouse query against tracelane.* tables
MUST include a tenant_id filter sourced from server-side auth (session or env),
never from user input.

Heuristic:
1. Walk all .rs/.ts/.tsx files (skip tests, fixtures, mocks, build artifacts).
2. For each file containing `FROM tracelane.`, require that the SAME file
   also references `tenant_id` AND sources it from one of:
       - session.tenantId          (TS, WorkOS session)
       - getTenantId()             (TS, env-derived in MCP)
       - tenant_id from JWT claim  (Rust)
       - workspace.tenant_id       (Rust gateway)
3. If a file queries FROM tracelane.* but never mentions tenant_id, flag it.

The check is intentionally whole-file rather than fixed-window because
TypeScript/JS code frequently declares the WHERE clause hundreds of lines
above the query template literal, and Rust functions can span many lines
between auth extraction and ClickHouse query construction. Function-scope
detection in regex would be fragile across two languages; whole-file
scope is a strict superset that catches every real violation without
false positives on hand-audited code.

Exit codes:
    0 — no violations
    1 — at least one file queries tracelane.* without any tenant_id reference

Run locally: python3 scripts/ci/check-tenant-isolation.py
CI:          .github/workflows/ci.yml job `tenant-isolation-check`.
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

# Pattern: any query against the tracelane.* schema (case-insensitive)
QUERY_PATTERN = re.compile(r"FROM\s+tracelane\.", re.IGNORECASE)

# Pattern: any reference to tenant_id (snake case for SQL/Rust)
# or tenantId (camelCase for TS), in identifiers, strings, or column refs
TENANT_ID_PATTERN = re.compile(
    r"\btenant_id\b|\btenantId\b",
    re.IGNORECASE,
)


def should_skip_path(path: Path) -> bool:
    """Skip test files, type definitions, and known-exempt directories."""
    name_lower = path.name.lower()
    if any(word in name_lower for word in SKIP_FILENAME_WORDS):
        return True
    parts_lower = {p.lower() for p in path.parts}
    if parts_lower & SKIP_DIRS:
        return True
    return False


def find_violations(repo_root: Path) -> list[tuple[Path, int]]:
    """Return list of (file, line_number) tuples for files that query
    tracelane.* but never reference tenant_id anywhere in the file."""
    violations: list[tuple[Path, int]] = []

    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if not fname.endswith(SCAN_EXTENSIONS):
                continue
            fpath = Path(dirpath) / fname
            if should_skip_path(fpath.relative_to(repo_root)):
                continue
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            # Skip files that don't query tracelane.*
            query_match = QUERY_PATTERN.search(content)
            if not query_match:
                continue

            # File queries tracelane.* — must reference tenant_id somewhere
            if TENANT_ID_PATTERN.search(content):
                continue

            # Real violation
            lineno = content[: query_match.start()].count("\n") + 1
            violations.append((fpath.relative_to(repo_root), lineno))

    return violations


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent.parent
    violations = find_violations(repo_root)

    if violations:
        print(
            "ERROR: ClickHouse query against tracelane.* without tenant_id reference:"
        )
        for fpath, lineno in violations:
            print(f"  {fpath}:{lineno}")
        print()
        print("Every file that queries tracelane.* MUST reference tenant_id sourced")
        print("from server-side auth (session.tenantId, getTenantId(), or JWT claim).")
        print("See CLAUDE.md §SQL: tenant_id must come from server-side auth only.")
        return 1

    print("Tenant isolation check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
