#!/usr/bin/env python3
"""Ban reads of dead/legacy entitlement columns in apps/web.

The audit add-on's source of truth moved to `workspace_entitlements.f_audit_addon`
(resolved via `lib/entitlements.ts` `resolveEntitlements().audit_ledger`). The
legacy `tenants.auditEnabled` column is no longer written by anything, so any UI
or API that *reads* it silently shows the wrong state to paying customers — the
"invisible entitlement-gated UI" bug class
(an internal incident review).

This guard fails CI if `tenants.auditEnabled` is read in application code. The
column may still be DEFINED in the schema and referenced in migrations/tests
(historical), so those paths are allowlisted. Extend `BANNED` as more columns
are retired.

Usage: python3 scripts/ci/no-legacy-entitlement-columns.py
Exit 0 = clean, 1 = a banned read was found.
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
WEB = REPO / "apps" / "web"

# column-read patterns that must not appear in application code
BANNED: dict[str, str] = {
    r"tenants\.auditEnabled": (
        "reads the dead `tenants.auditEnabled` column — use "
        "resolveEntitlements(tenantId, plan).audit_ledger "
        "(workspace_entitlements.f_audit_addon). "
        "This guard prevents the invisible entitlement-gated UI bug class."
    ),
}

# paths where the historical column name may legitimately appear
ALLOW_SUBSTRINGS = (
    "/db/schema",  # the column definition itself
    "/db/migrations/",  # historical migrations
    ".test.",  # tests that assert legacy behavior
    "/scripts/ci/",  # this guard
)


def main() -> int:
    if not WEB.is_dir():
        print(f"skip: {WEB} not found")
        return 0
    violations: list[str] = []
    patterns = {re.compile(p): msg for p, msg in BANNED.items()}
    for path in WEB.rglob("*.ts*"):
        sp = str(path)
        if "/node_modules/" in sp or "/.next/" in sp:
            continue
        if any(a in sp for a in ALLOW_SUBSTRINGS):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for rx, msg in patterns.items():
            for i, line in enumerate(text.splitlines(), 1):
                m = rx.search(line)
                if not m:
                    continue
                stripped = line.lstrip()
                # Skip comment lines (doc/inline) — we ban real property READS, not
                # prose that names the column.
                if stripped.startswith(("*", "//", "/*")):
                    continue
                # Skip mentions inside a backtick span on this line (e.g. `tenants.auditEnabled`).
                before = line[: m.start()]
                if before.count("`") % 2 == 1:
                    continue
                rel = path.relative_to(REPO)
                violations.append(f"{rel}:{i}: {msg}\n    {line.strip()}")
    if violations:
        print("FAIL: legacy/dead entitlement-column read(s) found:\n")
        for v in violations:
            print(f"  {v}")
        print(
            "\nGate UI/API on the real entitlement "
            "(resolveEntitlements), not a column that is no longer written."
        )
        return 1
    print("ok: no dead entitlement-column reads in apps/web")
    return 0


if __name__ == "__main__":
    sys.exit(main())
