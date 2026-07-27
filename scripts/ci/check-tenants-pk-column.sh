#!/usr/bin/env bash
#
# The old pre-ADR-040 shape used `tenant_id` as the tenants PK. Prod is `id`.
# Any raw SQL that references the tenants PK as `tenant_id` (a FK target, an
# INSERT column list, a qualified `tenants.tenant_id`, or a `FROM tenants t ...
# t.tenant_id` query) fails against prod with "column ... does not exist". This
# is now CI-enforced.
#
# NOTE: `<table>.tenant_id` on OTHER tables (workspace_entitlements, api_keys,
# audit_chain_state, …) is a legitimate FK column -> tenants.id, and Rust struct
# field access `t.tenant_id` (where `t` is a `Tenant`) is fine. This guard
# targets only SQL that treats the *tenants* PK as `tenant_id`.
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)
ROOT=$(cd -- "$HERE/../.." >/dev/null 2>&1 && pwd)
cd "$ROOT"

fail=0
report() {
  echo "❌ TENANTS-PK GUARD: $1"
  fail=1
}

# ci/run-cogs.sh embeds a resolver SQL query that had the old shape and slipped
# the .rs/.sql-only scan). Excludes: docs (may cite the bug), THIS guard script
# (it contains the anti-patterns as its own regex/comments), and
# infra/dev/postgres/migrations/ — the RETIRED pre-ADR-040 shape kept only until
# tool_capabilities) into Drizzle; it is not live schema (nothing builds/applies
# it — the gateway include_str!s the Drizzle set; COGS uses Drizzle too).
mapfile -t FILES < <(git ls-files '*.rs' '*.sql' '*.sh' \
  | grep -vE '^(docs/|infra/dev/postgres/migrations/|scripts/ci/check-tenants-pk-column\.sh$)')

# 1. FK / INSERT column-list referencing tenants(tenant_id) — SQL-exclusive.
hits=$(printf '%s\n' "${FILES[@]}" | xargs -r grep -nE 'tenants[[:space:]]*\([[:space:]]*tenant_id' 2>/dev/null || true)
[ -n "$hits" ] && report $'tenants(tenant_id) — FK/insert must target tenants(id):\n'"$hits"

# 2. Qualified column `tenants.tenant_id` — SQL-exclusive (tenants has no such col).
hits=$(printf '%s\n' "${FILES[@]}" | xargs -r grep -nE '\btenants\.tenant_id\b' 2>/dev/null || true)
[ -n "$hits" ] && report $'tenants.tenant_id — the tenants PK is id:\n'"$hits"

# 3. A SQL query over tenants that uses the tenants alias's `.tenant_id` in an
#    actual SQL construct — `WHERE t.tenant_id`, `t.tenant_id =`, or `= t.tenant_id`
#    (a join). Targeting SQL operators (not a bare `t.tenant_id`) avoids both
#    Rust struct-field access (`let x = t.tenant_id`) and negative test
#    assertions (`!sql.contains("t.tenant_id")`). The `FROM tenants` file gate is
#    a second belt.
SQL_TID='WHERE[[:space:]]+t\.tenant_id|[[:space:]]t\.tenant_id[[:space:]]*=|=[[:space:]]+t\.tenant_id\b'
for f in "${FILES[@]}"; do
  grep -qE 'FROM tenants\b' "$f" || continue
  hit=$(grep -nE "$SQL_TID" "$f" || true)
  [ -n "$hit" ] && report "$f: SQL over tenants references t.tenant_id (use t.id, the PK):
$hit"
done

if [ "$fail" -ne 0 ]; then
  echo
  echo "The tenants PK is 'id' (ADR-040)."
  exit 1
fi
echo "✅ tenants-pk guard: no tenant_id-as-tenants-PK anti-patterns"
