#!/usr/bin/env python3
"""`tenants.plan` may be written from ONE place: the Polar webhook.

WHY THIS EXISTS
---------------
`.claude/rules/billing.md` has said "billing changes ONLY through the Polar
webhook — never `UPDATE tenants SET plan`" since B-133. It was a rule with no
consumer: the tree carried 6+ `tenants` writers and nothing checked which of
them touched `plan`.

B-241 is what that costs. A tenant whose `tenants.plan` says `builder` resolves
to FREE entitlements at the gateway, because the two writes the webhook makes —
`tenants` and `workspace_entitlements` — are not atomic. Every additional plan
writer multiplies the ways those two can disagree, and a plan write that does
NOT go through the webhook cannot write the entitlement row at all.

SCOPE, deliberately narrow (founder-enumerated 2026-08-14 BEFORE this was built,
so it blocks nothing real): only writes to the `plan` COLUMN are gated. The four
legitimate web writers touch `archivedAt` and `name`; the gateway's other writer
touches the Polar ids. None is affected.

Exit 0 clean · 1 violation · 2 usage.
Falsify:  python3 scripts/ci/check-plan-write-single-source.py --selftest
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# The ONE sanctioned writer. Polar is the source of truth for plan state; this
# handler is the only place that learns of a change.
ALLOWED = {"apps/web/app/api/webhooks/polar/route.ts"}

# Rust: any SQL that sets the plan column on tenants. There is no Rust webhook —
# violation by construction, not by allowlist.
RUST_SQL = re.compile(r"UPDATE\s+tenants\s+SET\s+plan\b", re.IGNORECASE)

# TypeScript: `.update(tenants)` whose `.set({...})` names `plan`. Matched over a
# window rather than one line because Drizzle chains across lines.
TS_UPDATE = re.compile(r"\.update\(\s*tenants\s*\)")
TS_PLAN = re.compile(r"\bplan\s*:")
WINDOW = 8


def strip_comments(src: str) -> str:
    """Blank comments, preserving line count. A rule about CODE must not fire on
    prose describing the rule — the failure mode `TRAPS.md` §19 names."""
    src = re.sub(
        r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.DOTALL
    )
    return "\n".join(re.sub(r"//.*$", "", ln) for ln in src.split("\n"))


def scan(root: Path) -> list[str]:
    hits: list[str] = []
    for f in sorted((root / "crates").rglob("*.rs")):
        rel = f.relative_to(root).as_posix()
        try:
            src = strip_comments(f.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
        for i, line in enumerate(src.splitlines(), 1):
            if RUST_SQL.search(line):
                hits.append(
                    f"{rel}:{i}: UPDATE tenants SET plan — gateway-side plan write"
                )
    for f in sorted((root / "apps" / "web").rglob("*.ts")):
        rel = f.relative_to(root).as_posix()
        if rel in ALLOWED or "/node_modules/" in rel or ".test." in rel:
            continue
        try:
            lines = strip_comments(f.read_text(encoding="utf-8")).splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for i, line in enumerate(lines):
            if not TS_UPDATE.search(line):
                continue
            for j in range(i, min(i + WINDOW, len(lines))):
                if TS_PLAN.search(lines[j]):
                    hits.append(f"{rel}:{j + 1}: .update(tenants).set({{ plan: … }})")
                    break
    return hits


def report(hits: list[str]) -> int:
    if not hits:
        print("✓ tenants.plan is written from exactly one place (the Polar webhook)")
        return 0
    print("❌ a NON-WEBHOOK write to tenants.plan:")
    for h in hits:
        print(f"   {h}")
    print(
        "\n→ Plan state moves through the Polar webhook ONLY "
        "(.claude/rules/billing.md). A direct write cannot also write "
        "workspace_entitlements, which is what the gateway actually reads — "
        "so the tenant silently keeps free-tier entitlements."
    )
    return 1


SELFTEST = [
    # (relpath, body, must_block)
    (
        "crates/gateway/src/db/bad.rs",
        'let sql = "UPDATE tenants SET plan = $2 WHERE id = $1";\n',
        True,
    ),
    (
        "apps/web/app/api/admin/route.ts",
        "await db\n  .update(tenants)\n  .set({ plan: 'team' })\n  .where(eq(tenants.id, id));\n",
        True,
    ),
    # The sanctioned writer must NOT be flagged, or the guard blocks billing.
    (
        "apps/web/app/api/webhooks/polar/route.ts",
        "await db\n  .update(tenants)\n  .set({ plan: planValue })\n  .where(eq(tenants.id, t.id));\n",
        False,
    ),
    # A legitimate non-plan write must NOT be flagged — this is the half that
    # proves the guard is scoped rather than blanket.
    (
        "apps/web/app/api/settings/workspace/route.ts",
        "await db\n  .update(tenants)\n  .set({ name })\n  .where(eq(tenants.id, t.id));\n",
        False,
    ),
    (
        "apps/web/app/api/settings/account/route.ts",
        "await db\n  .update(tenants)\n  .set({ archivedAt: new Date() })\n  .where(eq(tenants.id, t.id));\n",
        False,
    ),
    # A COMMENT describing the rule must not trip it (TRAPS §19).
    (
        "crates/gateway/src/db/ok_comment.rs",
        "// never write `UPDATE tenants SET plan` outside the webhook\nfn f() {}\n",
        False,
    ),
]


def selftest() -> int:
    failures = 0
    with tempfile.TemporaryDirectory() as td:
        fake = Path(td) / "repo"
        for rel, body, _ in SELFTEST:
            p = fake / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body, encoding="utf-8")
        hits = scan(fake)
        for rel, _, must_block in SELFTEST:
            flagged = any(h.startswith(rel + ":") for h in hits)
            if flagged != must_block:
                verb = "BLOCK" if must_block else "allow"
                print(f"  ✗ expected to {verb} {rel} — got flagged={flagged}")
                failures += 1
            else:
                print(f"  {'✓ BLOCKS' if must_block else '✓ allows'} {rel}")
    if failures:
        print(f"\nselftest FAILED — {failures} case(s). The guard is not trustworthy.")
        return 1
    print("\nselftest PASSED.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    return report(scan(ROOT))


if __name__ == "__main__":
    sys.exit(main())
