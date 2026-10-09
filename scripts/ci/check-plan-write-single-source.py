#!/usr/bin/env python3
"""`tenants.plan` — and its price-protection PINS `tenants.plan_version` /
`tenants.price_version` (B-409) — may be written from ONE place: the Polar webhook.

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

B-409 (2026-10-03): the pins are plan state too. `plan_version` decides which
`plan_allowances` row (what the price buys) a tenant reads for 12 months; a second
writer could re-pin a protected customer onto a worse ruling, or a free tenant
onto a paid version. Same two shapes, same one sanctioned writer.

rev4 L5 (2026-10-03, security review): the first cut read ONE line per Rust match
and only `.set({ literal })` in TypeScript, so a SET list wrapped across lines, a
`.set(patch)` built elsewhere, a `{ ...extra }` spread, any INSERT (Drizzle
`.insert(tenants)` / its `onConflictDoUpdate`, raw SQL), and the third pin
`price_protected_until` all passed. Now: SQL is matched over the whole file; an
INSERT naming a pin is a write anywhere, an INSERT naming `plan` is allowed only in
the provisioning module (a new tenant's STARTING plan); an identifier passed to
`.set`/`.values` or spread into one is resolved in the same file and FAILS CLOSED
when it cannot be seen; `#[cfg(test)]` items and `crates/*/tests/` are fixtures,
not writers.

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

# The plan state: the plan itself and its three price-protection pins —
# `plan_version` / `price_version` (WHAT is pinned) and `price_protected_until`
# (for how LONG; rev4 L5 — a second writer of the expiry un-pins or eternally pins).
SQL_COLS = r"(?:plan|plan_version|price_version|price_protected_until)"
TS_KEYS = r"(?:plan|planVersion|priceVersion|priceProtectedUntil)"

# The one sanctioned INSERT naming `plan`: provisioning a NEW tenant with its
# STARTING plan (`db::tenants::create*`). An insert is not a plan CHANGE; the pins
# are never inserted anywhere (the webhook sets them on the first paid activation).
ALLOWED_PLAN_INSERT = {"crates/gateway/src/db/tenants.rs"}

# SQL (Rust strings and TS raw `sql` templates). Searched over the WHOLE file, not
# line by line, so a SET list or column list wrapped across lines is still seen.
SQL_UPDATE = re.compile(
    r"UPDATE\s+tenants\s+SET\s+(?:[^;\"`]*?,\s*)?" + SQL_COLS + r"\s*=",
    re.IGNORECASE,
)
SQL_INSERT = re.compile(r"INSERT\s+INTO\s+tenants\s*\(([^)]*)\)", re.IGNORECASE)
SQL_UPSERT_SET = re.compile(
    r"DO\s+UPDATE\s+SET\s+(?:[^;\"`]*?,\s*)?" + SQL_COLS + r"\s*=", re.IGNORECASE
)
SQL_PIN_COL = re.compile(
    r"\b(plan_version|price_version|price_protected_until)\b", re.IGNORECASE
)
SQL_PLAN_COL = re.compile(r"\bplan\b", re.IGNORECASE)

# TypeScript: a Drizzle chain on `tenants` — `.update(tenants).set(…)` or
# `.insert(tenants).values(…)[.onConflictDoUpdate({ set: … })]`. Matched over a
# window because Drizzle chains across lines.
TS_CHAIN = re.compile(r"\.(update|insert)\(\s*tenants\s*\)")
TS_PLAN = re.compile(r"\b" + TS_KEYS + r"\s*:")
# `.set(patch)` / `.values(row)` — a bare identifier whose keys are elsewhere.
TS_ARG_IDENT = re.compile(r"\.(?:set|values)\(\s*([A-Za-z_$][\w$]*)\s*\)")
# `{ ...extra }` — a spread of a bare identifier; `...(cond ? {…} : {})` spreads
# an inline literal whose keys the window already sees.
TS_SPREAD_IDENT = re.compile(r"\.\.\.\s*([A-Za-z_$][\w$]*)\b(?!\s*[.(\[])")
TS_SPREAD_OTHER = re.compile(r"\.\.\.\s*[A-Za-z_$][\w$]*\s*[.(\[]")
WINDOW = 8


def strip_comments(src: str) -> str:
    """Blank comments, preserving line count. A rule about CODE must not fire on
    prose describing the rule — the failure mode `TRAPS.md` §19 names."""
    src = re.sub(
        r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), src, flags=re.DOTALL
    )
    return "\n".join(re.sub(r"//.*$", "", ln) for ln in src.split("\n"))


# `#[cfg(test)]` and `#[cfg(all(test, …))]` — a test-only item. `not(test)` is not.
TEST_CFG = re.compile(
    r"#\[cfg\((?:test|all\((?:[^()\]]|\([^()]*\))*?\btest\b(?:[^()\]]|\([^()]*\))*\))\)\]"
)


def production_part(src: str) -> str:
    """Blank every `#[cfg(test)]`-gated item (brace-matched), keeping newlines —
    the same rule `check-banned-patterns.py` applies: a test fixture that inserts a
    tenant on a plan is not a plan writer, and a column-0 cut would miss a test
    module mid-file."""
    out: list[str] = []
    i, n = 0, len(src)
    while i < n:
        m = TEST_CFG.search(src, i)
        if not m:
            out.append(src[i:])
            break
        j = m.start()
        if "not(test" in m.group(0).replace(" ", ""):
            out.append(src[i : m.end()])
            i = m.end()
            continue
        out.append(src[i:j])
        k, depth, seen, end = m.end(), 0, False, n
        while k < n:
            ch = src[k]
            if ch == "{":
                depth, seen = depth + 1, True
            elif ch == "}":
                depth -= 1
                if seen and depth == 0:
                    end = k + 1
                    break
            elif ch == ";" and not seen:
                end = k + 1
                break
            k += 1
        out.append("".join("\n" if c == "\n" else " " for c in src[j:end]))
        i = end
    return "".join(out)


def _line(src: str, pos: int) -> int:
    return src.count("\n", 0, pos) + 1


def sql_hits(rel: str, src: str, allow_plan_insert: bool) -> list[str]:
    """Every plan-state write in SQL text: UPDATE … SET <col>, an INSERT whose column
    list names a pin (or `plan`, outside the provisioning site), and an upsert arm
    `DO UPDATE SET <col>` on a tenants insert."""
    hits = [
        f"{rel}:{_line(src, m.start())}: UPDATE tenants SET <plan state> — non-webhook plan write"
        for m in SQL_UPDATE.finditer(src)
    ]
    for m in SQL_INSERT.finditer(src):
        cols = m.group(1)
        pin = SQL_PIN_COL.search(cols)
        if pin or (SQL_PLAN_COL.search(cols) and not allow_plan_insert):
            col = pin.group(1) if pin else "plan"
            hits.append(
                f"{rel}:{_line(src, m.start())}: INSERT INTO tenants (… {col} …)"
            )
        stmt = src[m.end() : m.end() + 600].split(";", 1)[0]
        if SQL_UPSERT_SET.search(stmt):
            hits.append(
                f"{rel}:{_line(src, m.start())}: INSERT INTO tenants … DO UPDATE SET <plan state>"
            )
    return hits


def _object_literal_after(src: str, start: int) -> str:
    """The `{ … }` text starting at the first `{` at/after `start` (brace-matched)."""
    i = src.find("{", start)
    if i == -1:
        return ""
    depth = 0
    for k in range(i, len(src)):
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                return src[i : k + 1]
    return src[i:]


def ident_carries_pin(src: str, ident: str) -> bool | None:
    """Whether the object bound to `ident` in this file carries a plan-state key:
    True / False, or None when the binding cannot be seen (a parameter, an import,
    a non-literal initialiser) — which the caller treats as a write (fail CLOSED)."""
    esc = re.escape(ident)
    # Property assignment anywhere in the file: `x.plan = …`, `x["planVersion"] = …`.
    if re.search(
        rf"\b{esc}\s*(?:\.\s*{TS_KEYS}|\[\s*[\"']{TS_KEYS}[\"']\s*\])\s*=(?!=)", src
    ):
        return True
    decl = re.search(rf"\b(?:const|let|var)\s+{esc}\b[^=;]*=\s*", src)
    if not decl:
        return None
    rest = src[decl.end() :]
    if not rest.lstrip().startswith("{"):
        return None
    body = _object_literal_after(src, decl.end())
    if TS_PLAN.search(body):
        return True
    # A spread inside the literal: resolve one level further, the same way.
    for s in TS_SPREAD_IDENT.findall(body):
        if s != ident and ident_carries_pin(src, s) is not False:
            return True
    return bool(TS_SPREAD_OTHER.search(body)) or False


def ts_hits(rel: str, src: str) -> list[str]:
    hits: list[str] = []
    lines = src.splitlines()
    for i, line in enumerate(lines):
        m = TS_CHAIN.search(line)
        if not m:
            continue
        verb = m.group(1)
        window = "\n".join(lines[i : i + WINDOW])
        why = None
        if TS_PLAN.search(window):
            why = "names a plan-state key"
        else:
            for ident in TS_ARG_IDENT.findall(window) + TS_SPREAD_IDENT.findall(window):
                if ident == "tenants":
                    continue
                carried = ident_carries_pin(src, ident)
                if carried is None:
                    why = f"writes `{ident}`, whose keys this guard cannot see (fail closed)"
                    break
                if carried:
                    why = f"writes `{ident}`, which carries a plan-state key"
                    break
            if why is None and TS_SPREAD_OTHER.search(window):
                why = "spreads a value whose keys this guard cannot see (fail closed)"
        if why:
            hits.append(f"{rel}:{i + 1}: .{verb}(tenants) {why}")
    hits.extend(sql_hits(rel, src, allow_plan_insert=False))
    return hits


def scan(root: Path) -> list[str]:
    hits: list[str] = []
    for f in sorted((root / "crates").rglob("*.rs")):
        rel = f.relative_to(root).as_posix()
        # Integration-test crates (`crates/*/tests/`) build fixtures; they are not
        # writers. `#[cfg(test)]` items inside src/ are blanked the same way.
        if "/tests/" in f"/{rel}":
            continue
        try:
            src = production_part(strip_comments(f.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError):
            continue
        hits += sql_hits(rel, src, allow_plan_insert=rel in ALLOWED_PLAN_INSERT)
    for f in sorted((root / "apps" / "web").rglob("*.ts")):
        rel = f.relative_to(root).as_posix()
        if rel in ALLOWED or "/node_modules/" in rel or ".test." in rel:
            continue
        try:
            src = strip_comments(f.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
        hits += ts_hits(rel, src)
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
    # B-409: the price-protection PINS are plan state — a second writer of either
    # re-pins a protected customer. Both shapes, both columns, must BLOCK.
    (
        "crates/gateway/src/db/bad_pin.rs",
        'let sql = "UPDATE tenants SET updated_at = now(), plan_version = $2 WHERE id = $1";\n',
        True,
    ),
    (
        "apps/web/app/api/admin/repin.ts",
        "await db\n  .update(tenants)\n  .set({ planVersion: 'v4' })\n  .where(eq(tenants.id, id));\n",
        True,
    ),
    (
        "apps/web/app/api/admin/reprice.ts",
        "await db\n  .update(tenants)\n  .set({ priceVersion: 'v4' })\n  .where(eq(tenants.id, id));\n",
        True,
    ),
    # A legitimate gateway write to OTHER tenants columns must still pass.
    (
        "crates/gateway/src/db/ok_other.rs",
        'let sql = "UPDATE tenants SET auto_age_window_days = $2 WHERE id = $1";\n',
        False,
    ),
    # A COMMENT describing the rule must not trip it (TRAPS §19).
    (
        "crates/gateway/src/db/ok_comment.rs",
        "// never write `UPDATE tenants SET plan` outside the webhook\nfn f() {}\n",
        False,
    ),
]

# rev4 L5 (2026-10-03): the shapes the first cut could not see. Written with a
# `‹plan›` placeholder, substituted below — the PreToolUse hook
# (`protect-billing-webhook-single-source.sh`) refuses an edit that ADDS the literal
# shape, which is right for code and wrong for a fixture that must contain it.
_L5_CASES = [
    # `price_protected_until` is the third pin — it decides how LONG the others hold.
    (
        "crates/gateway/src/db/bad_protect.rs",
        'let sql = "UPDATE tenants SET price_protected_until = now() WHERE id = $1";\n',
        True,
    ),
    (
        "apps/web/app/api/admin/protect.ts",
        "await db\n  .update(tenants)\n  .set({ priceProtectedUntil: new Date() })\n  .where(eq(tenants.id, id));\n",
        True,
    ),
    # A multi-line Rust UPDATE: the pin on the SECOND line of the SET list.
    (
        "crates/gateway/src/db/bad_multiline.rs",
        'let sql = "UPDATE tenants SET updated_at = now(),\n    ‹plan› = $2 WHERE id = $1";\n',
        True,
    ),
    # `.set(variable)` — the object is built elsewhere in the file.
    (
        "apps/web/app/api/admin/set_var.ts",
        "const patch = { ‹plan›: 'team' };\n\n\n\n\n\n\n\n\nawait db\n  .update(tenants)\n  .set(patch)\n  .where(eq(tenants.id, id));\n",
        True,
    ),
    # `.set(variable)` whose content cannot be seen (a parameter) — fail CLOSED.
    (
        "apps/web/app/api/admin/set_param.ts",
        "export async function f(patch: Record<string, unknown>) {\n  await db\n    .update(tenants)\n    .set(patch)\n    .where(eq(tenants.id, id));\n}\n",
        True,
    ),
    # A spread whose source gains the pin by property assignment, far above.
    (
        "apps/web/app/api/admin/spread.ts",
        "const extra: Record<string, unknown> = {};\nextra.priceVersion = 'v4';\n\n\n\n\n\n\n\n\nawait db\n  .update(tenants)\n  .set({ name, ...extra })\n  .where(eq(tenants.id, id));\n",
        True,
    ),
    # INSERT shapes: Drizzle `.insert(tenants).values({...})`, its upsert arm, raw SQL.
    (
        "apps/web/app/api/admin/insert.ts",
        "await db\n  .insert(tenants)\n  .values({ workosOrgId, ‹plan›: 'business' });\n",
        True,
    ),
    (
        "apps/web/app/api/admin/upsert.ts",
        "await db\n  .insert(tenants)\n  .values({ workosOrgId })\n  .onConflictDoUpdate({ target: tenants.workosOrgId, set: { planVersion: 'v4' } });\n",
        True,
    ),
    (
        "apps/web/lib/raw_sql.ts",
        "await db.execute(sql`update tenants set price_version = ${v} where id = ${id}`);\n",
        True,
    ),
    (
        "crates/gateway/src/db/bad_insert.rs",
        'let sql = "INSERT INTO tenants (id, workos_org_id, plan_version) VALUES ($1, $2, $3)";\n',
        True,
    ),
    (
        "crates/gateway/src/billing/bad_insert_plan.rs",
        'let sql = "INSERT INTO tenants (id, workos_org_id, \\\n    ‹plan›) VALUES ($1, $2, $3)";\n',
        True,
    ),
    (
        "crates/gateway/src/db/bad_upsert.rs",
        'let sql = "INSERT INTO tenants (id, workos_org_id) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET ‹plan› = $3";\n',
        True,
    ),
    # MUST pass: the provisioning insert names the STARTING plan (the one sanctioned
    # insert site), a test-module fixture, an integration-test fixture, and resolvable
    # writes that carry no pin.
    (
        "crates/gateway/src/db/tenants.rs",
        'let sql = "INSERT INTO tenants (id, workos_org_id, ‹plan›) VALUES ($1, $2, $3)";\n',
        False,
    ),
    (
        "crates/gateway/src/billing/ok_test_fixture.rs",
        'fn f() {}\n#[cfg(test)]\nmod tests {\n    const S: &str = "INSERT INTO tenants (id, ‹plan›, plan_version) VALUES ($1, $2, $3)";\n}\n',
        False,
    ),
    (
        "crates/gateway/src/ok_all_test_fixture.rs",
        'fn f() {}\n#[cfg(all(test, debug_assertions))]\nmod tests {\n    const S: &str = "INSERT INTO tenants (id, ‹plan›) VALUES ($1, $2)";\n}\n',
        False,
    ),
    # …but `not(test)` is PRODUCTION code and must still be scanned.
    (
        "crates/gateway/src/bad_not_test.rs",
        '#[cfg(all(not(test), feature = "x"))]\nfn f() { let s = "INSERT INTO tenants (id, plan_version) VALUES ($1, $2)"; }\n',
        True,
    ),
    (
        "crates/gateway/tests/ok_integration.rs",
        'const S: &str = "INSERT INTO tenants (id, ‹plan›) VALUES ($1, $2)";\n',
        False,
    ),
    (
        "apps/web/lib/ok_insert.ts",
        "await db\n  .insert(tenants)\n  .values({ workosOrgId, name: name?.trim() || null })\n  .onConflictDoNothing({ target: tenants.workosOrgId });\n",
        False,
    ),
    (
        "apps/web/app/api/settings/ok_set_var.ts",
        "const patch = { name: body.name };\nawait db\n  .update(tenants)\n  .set(patch)\n  .where(eq(tenants.id, t.id));\n",
        False,
    ),
    (
        "apps/web/app/api/settings/ok_spread.ts",
        "const rest = { archivedAt: new Date() };\nawait db\n  .update(tenants)\n  .set({ ...rest })\n  .where(eq(tenants.id, t.id));\n",
        False,
    ),
]
SELFTEST += [(p, b.replace("‹plan›", "plan"), m) for p, b, m in _L5_CASES]


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
