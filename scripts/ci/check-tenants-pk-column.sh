#!/usr/bin/env bash
#  static guard: the `tenants` table PK is `id`, NEVER `tenant_id`.
#
# The old pre-ADR-040 shape used `tenant_id` as the tenants PK. Prod is `id`.
# Any raw SQL that references the tenants PK as `tenant_id` (a FK target, an
# INSERT column list, a qualified `tenants.tenant_id`, or a `FROM tenants t ...
# t.tenant_id` query) fails against prod with "column ... does not exist". This
# exact seam class has bitten FOUR times, so it
# is now CI-enforced.
#
# NOTE: `<table>.tenant_id` on OTHER tables (workspace_entitlements, api_keys,
# audit_chain_state, …) is a legitimate FK column -> tenants.id, and Rust struct
# field access `t.tenant_id` (where `t` is a `Tenant`) is fine. This guard
# targets only SQL that treats the *tenants* PK as `tenant_id`.
#
# Falsify it: ./scripts/ci/check-tenants-pk-column.sh --selftest
# Exit codes: 0 = clean · 1 = violation(s) found · 2 = bad usage / selftest failed.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: check-tenants-pk-column.sh [--selftest] [-h|--help]

  (no args)   Scan the tracked .rs/.sql/.sh files under $PWD for SQL that treats
              the `tenants` PK as `tenant_id` instead of `id`. Exit 1 on any hit.
  --selftest  Prove the guard BLOCKS: plant each of the three anti-pattern shapes
              in a throwaway git repo and assert each is caught, and assert the
              clean shape plus the documented exclusions still pass. Exit 0 only
              if every case holds.
EOF
}

mode=scan
while [ $# -gt 0 ]; do
  case "$1" in
    --selftest) mode=selftest ;;
    -h|--help)  usage; exit 0 ;;
    *)
      echo "check-tenants-pk-column.sh: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)
ROOT=$(cd -- "$HERE/../.." >/dev/null 2>&1 && pwd)

report() {
  echo "❌ TENANTS-PK GUARD: $1"
  fail=1
}

# Scans the git-tracked files of the repo at $PWD. 0 = clean, 1 = violation.
run_guard() {
local fail=0
local -a FILES

# Source files to scan (tracked.rs.sql.sh —.sh added because
# ci/run-cogs.sh embeds a resolver SQL query that had the old shape and slipped
# the .rs/.sql-only scan). Excludes: docs (may cite the bug), THIS guard script
# (it contains the anti-patterns as its own regex/comments), and
# infra/dev/postgres/migrations/ — the RETIRED pre-ADR-040 shape kept only until
#  D2 migrates its non-Drizzle SQL (NOTIFY triggers, cardinality,
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
  return 1
fi
echo "✅ tenants-pk guard: no tenant_id-as-tenants-PK anti-patterns"
return 0
}

# ── Selftest ───────────────────────────────────────────────────────────────
#
# The guard's file list comes from `git ls-files`, so each case is a throwaway
# git repo under $TMPDIR. Nothing under this repo is written, so
# `git status --porcelain` is unchanged afterwards.

selftest_failures=0
selftest_tmp=""

# _case <name> <expected_exit> <dir> [expected_substring]
_case() {
  local name="$1" want="$2" dir="$3" needle="${4:-}" rc=0 out
  out="$( cd "$dir" && run_guard 2>&1 )" || rc=$?
  if [ "$rc" -ne "$want" ]; then
    echo "✗ $name: expected exit $want, got $rc"
    printf '%s\n' "$out" | sed 's/^/      /'
    selftest_failures=$((selftest_failures + 1))
    return 0
  fi
  if [ -n "$needle" ] && ! printf '%s' "$out" | grep -qF "$needle"; then
    echo "✗ $name: exit $rc as expected, but output did not mention '$needle'"
    printf '%s\n' "$out" | sed 's/^/      /'
    selftest_failures=$((selftest_failures + 1))
    return 0
  fi
  echo "✓ $name (exit $rc)"
}

# A throwaway repo whose tracked files are all the CORRECT `id`-PK shape.
_fixture() {
  local d="$1"
  mkdir -p "$d/crates/ingest/src" "$d/apps/web/db/migrations"

  # Correct resolver SQL: joins on the FK column, filters on the `id` PK. Also
  # exercises the `FROM tenants` file gate of check 3 without tripping it.
  cat > "$d/crates/ingest/src/tenant_config.rs" <<'RS'
const RESOLVE_SQL: &str = "SELECT t.id, we.plan FROM tenants t \
  LEFT JOIN workspace_entitlements we ON we.tenant_id = t.id WHERE t.id = $1";

#[test]
fn resolve_sql_uses_tenants_id_pk_not_tenant_id() {
    assert!(!RESOLVE_SQL.contains("t.tenant_id"));
}
RS
  cat > "$d/apps/web/db/migrations/0001_init.sql" <<'SQL'
CREATE TABLE api_keys (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id)
);
SQL

  git -C "$d" init -q
  git -C "$d" add -A
}

selftest() {
  local d
  selftest_tmp="$(mktemp -d)"   # global: the EXIT trap fires after locals die
  trap 'rm -rf "$selftest_tmp"' EXIT
  echo "check-tenants-pk-column.sh --selftest"
  echo

  # 1. NEGATIVE CONTROL — the correct shape must pass, or the guard is a wall.
  #    Includes the two forms the guard documents as deliberately NOT flagged:
  #    an FK column `we.tenant_id` on another table, and the negative test
  #    assertion `!RESOLVE_SQL.contains("t.tenant_id")`.
  d="$selftest_tmp/clean"; _fixture "$d"
  _case "correct id-PK shape passes" 0 "$d" "✅ tenants-pk guard"

  # 2. Check 1 — FK / INSERT column list targeting tenants(tenant_id).
  d="$selftest_tmp/fk"; mkdir -p "$d/apps/web/db/migrations"
  echo 'CREATE TABLE tool_capabilities (tenant_id uuid REFERENCES tenants(tenant_id));' \
    > "$d/apps/web/db/migrations/0016_tool_capabilities.sql"
  _fixture "$d"
  _case "planted FK tenants(tenant_id) BLOCKS" 1 "$d" \
    "tenants(tenant_id) — FK/insert must target tenants(id)"

  # 3. Check 2 — qualified column `tenants.tenant_id`.
  d="$selftest_tmp/qualified"; mkdir -p "$d/apps/web/db/migrations"
  echo 'SELECT tenants.tenant_id, plan FROM billing_view;' \
    > "$d/apps/web/db/migrations/0017_view.sql"
  _fixture "$d"
  _case "planted tenants.tenant_id BLOCKS" 1 "$d" \
    "tenants.tenant_id — the tenants PK is id"

  # 4. Check 3 — SQL over `FROM tenants` using the alias's .tenant_id. This is
  #    the exact shape that slipped the.rs.sql-only scan in, so plant it
  #    in a .sh file, the extension added to close that hole.
  d="$selftest_tmp/alias"; mkdir -p "$d/ci"
  cat > "$d/ci/run-cogs.sh" <<'SH'
psql -c "SELECT t.plan FROM tenants t WHERE t.tenant_id = '$TENANT'"
SH
  _fixture "$d"
  _case "planted 'FROM tenants t … WHERE t.tenant_id' in a .sh BLOCKS" 1 "$d" \
    "SQL over tenants references t.tenant_id (use t.id, the PK)"

  # 5. docs/ is excluded — docs may cite the bug verbatim.
  d="$selftest_tmp/docs"; mkdir -p "$d/docs/reference"
  echo 'The old shape was: REFERENCES tenants(tenant_id) -- do not copy' \
    > "$d/docs/reference/old-shape.sql"
  _fixture "$d"
  _case "same anti-pattern under docs/ is excluded" 0 "$d" "✅ tenants-pk guard"

  # 6. The retired pre-ADR-040 infra tree is excluded (it is not live schema).
  d="$selftest_tmp/infra"; mkdir -p "$d/infra/dev/postgres/migrations"
  echo 'CREATE TABLE tenants (tenant_id uuid PRIMARY KEY);' \
    > "$d/infra/dev/postgres/migrations/01_tenants.sql"
  echo 'ALTER TABLE x ADD FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id);' \
    > "$d/infra/dev/postgres/migrations/13_tool_capabilities.sql"
  _fixture "$d"
  _case "retired infra/dev/postgres/migrations/ is excluded" 0 "$d" "✅ tenants-pk guard"

  # 7. An untracked file is invisible to `git ls-files` — the guard's real blind
  #    spot, asserted so a future switch to a filesystem walk shows up here.
  d="$selftest_tmp/untracked"; _fixture "$d"
  echo 'SELECT tenants.tenant_id FROM tenants;' > "$d/never_added.sql"
  _case "untracked file is NOT scanned (git ls-files scope)" 0 "$d" "✅ tenants-pk guard"

  if [ "$selftest_failures" -gt 0 ]; then
    echo
    echo "selftest FAILED — $selftest_failures case(s). The guard is not trustworthy."
    return 2
  fi
  echo
  echo "selftest PASSED."
  return 0
}

if [ "$mode" = selftest ]; then
  selftest
  exit $?
fi

cd "$ROOT"
run_guard
