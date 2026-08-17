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

Exit codes:
    0 — clean
    1 — a banned read was found (or --selftest failed)
    2 — bad usage (unrecognised argument)

Usage:        python3 scripts/ci/no-legacy-entitlement-columns.py
Falsify it:   python3 scripts/ci/no-legacy-entitlement-columns.py --selftest

`--selftest` plants a real read of the dead column in a throwaway tree and
asserts the guard REPORTS it, then asserts every deliberate exemption (comments,
backticked prose, the schema definition, migrations, tests) still passes. A
guard whose blocking has never been observed is not a guard.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys
import tempfile

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


def find_violations(web_root: pathlib.Path, label_root: pathlib.Path) -> list[str]:
    """Return `file:line: reason` for every banned column read under web_root."""
    violations: list[str] = []
    patterns = {re.compile(p): msg for p, msg in BANNED.items()}
    for path in sorted(web_root.rglob("*.ts*")):
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
                try:
                    rel = path.relative_to(label_root)
                except ValueError:  # pragma: no cover
                    rel = path
                violations.append(f"{rel}:{i}: {msg}\n    {line.strip()}")
    return violations


# ---------------------------------------------------------------------------
# Selftest
# ---------------------------------------------------------------------------

# (relative path under a fake apps/web root, file contents, must_be_flagged)
SELFTEST_FILES: list[tuple[str, str, bool]] = [
    # --- must BLOCK: a real read of the dead column -------------------------
    (
        "app/audit/page.tsx",
        (
            "export default function P({ tenants }) {\n"
            "  if (tenants.auditEnabled) return <Ledger />;\n"
            "  return null;\n"
            "}\n"
        ),
        True,
    ),
    (
        "app/api/audit/route.ts",
        "const enabled = row.tenants.auditEnabled ?? false;\n",
        True,
    ),
    # --- must PASS: deliberate exemptions -----------------------------------
    (
        # The correct replacement must never trip the guard, or the guard
        # punishes the fix it is asking for.
        "app/audit/ok-page.tsx",
        "const { audit_ledger } = await resolveEntitlements(tenantId, plan);\n",
        False,
    ),
    (
        "components/gate.tsx",
        (
            "// tenants.auditEnabled is dead; gate on resolveEntitlements instead\n"
            " * tenants.auditEnabled was the old source of truth\n"
            "export const G = 1;\n"
        ),
        False,
    ),
    (
        "components/doc.tsx",
        "const note = `tenants.auditEnabled`;\n",
        False,
    ),
    (
        "db/schema.ts",
        "export type Legacy = typeof tenants.auditEnabled;\n",
        False,
    ),
    (
        "db/migrations/0009_audit.ts",
        "await db.update(tenants).set({ x: tenants.auditEnabled });\n",
        False,
    ),
    (
        "lib/entitlements.test.ts",
        "expect(tenants.auditEnabled).toBe(false);\n",
        False,
    ),
    (
        "node_modules/legacy/index.ts",
        "const v = tenants.auditEnabled;\n",
        False,
    ),
    (
        ".next/server/page.ts",
        "const v = tenants.auditEnabled;\n",
        False,
    ),
]


def _tree_state() -> str | None:
    """`git status --porcelain` for the real repo, or None if git is unusable."""
    try:
        r = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def selftest() -> int:
    failures = 0
    before = _tree_state()

    with tempfile.TemporaryDirectory() as td:
        web = pathlib.Path(td) / "apps" / "web"
        for rel, body, _ in SELFTEST_FILES:
            p = web / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")

        flagged = {
            v.split(":", 1)[0].removeprefix("apps/web/")
            for v in find_violations(web, pathlib.Path(td))
        }

        for rel, _, must_flag in SELFTEST_FILES:
            got = rel in flagged
            ok = got == must_flag
            verb = "BLOCKS" if must_flag else "allows"
            print(
                f"  {'✓' if ok else '✗'} {verb} {rel}"
                f"{'' if ok else f'  (expected flagged={must_flag}, got {got})'}"
            )
            if not ok:
                failures += 1

        # Assert the negative at TREE level: a tree that never names the dead
        # column yields zero violations. Without this, a guard that fires on
        # everything would still satisfy the per-file cases above.
        clean = pathlib.Path(td) / "clean" / "apps" / "web"
        (clean / "app").mkdir(parents=True)
        (clean / "app" / "page.tsx").write_text(
            "const { audit_ledger } = await resolveEntitlements(t, p);\n",
            encoding="utf-8",
        )
        clean_hits = find_violations(clean, pathlib.Path(td) / "clean")
        if clean_hits:
            print(f"  ✗ clean tree PASSES — got {len(clean_hits)} false hit(s)")
            failures += 1
        else:
            print("  ✓ clean tree PASSES (guard does not fire on everything)")

    after = _tree_state()
    if before is None or after is None:
        print("  ! tree-unchanged check SKIPPED (git unavailable)")
    elif before != after:
        print("  ✗ selftest mutated the working tree")
        failures += 1
    else:
        print("  ✓ working tree unchanged (git status --porcelain identical)")

    if failures:
        print(f"\nselftest FAILED — {failures} case(s). The guard is not trustworthy.")
        return 1
    print("\nselftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Ban reads of dead/legacy entitlement columns in apps/web."
    )
    ap.add_argument(
        "--selftest",
        action="store_true",
        help="plant a dead-column read in a temp tree and prove the guard blocks it",
    )
    args = ap.parse_args()  # exits 2 on an unrecognised argument

    if args.selftest:
        return selftest()

    if not WEB.is_dir():
        print(f"skip: {WEB} not found")
        return 0
    violations = find_violations(WEB, REPO)
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
