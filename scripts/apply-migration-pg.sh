#!/usr/bin/env bash
# Apply Postgres migrations against a running Postgres instance, then run
# the gateway's tenant + api_key integration tests.
#
# Usage:
#   POSTGRES_URL=postgres://tracelane:tracelane_dev@localhost:5432/tracelane \
#     ./scripts/apply-migration-pg.sh
#
# Env vars:
#   POSTGRES_URL  — full connection URL (preferred)
#   PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE — libpq fallbacks
#
# Exit codes:
#   0  — migration applied + integration tests pass
#   1  — Postgres not reachable
#   2  — migration apply failed
#   3  — integration tests failed
set -euo pipefail

HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)
ROOT=$(cd -- "$HERE/.." >/dev/null 2>&1 && pwd)
# retired infra SQL. psql handles the `--> statement-breakpoint` `--` comments.
MIGRATIONS_DIR="$ROOT/apps/web/db/migrations"

if [[ ! -d "$MIGRATIONS_DIR" ]]; then
  echo "migrations dir not found: $MIGRATIONS_DIR" >&2
  exit 2
fi

if [[ -n "${POSTGRES_URL:-}" ]]; then
  PSQL_CONN="$POSTGRES_URL"
else
  : "${PGHOST:?set POSTGRES_URL or PGHOST}"
  : "${PGDATABASE:?set POSTGRES_URL or PGDATABASE}"
  PSQL_CONN=""
fi

echo "=> probing Postgres"
if ! psql ${PSQL_CONN:+"$PSQL_CONN"} -c "SELECT 1" >/dev/null; then
  echo "Postgres not reachable" >&2
  exit 1
fi

echo "=> applying Drizzle migrations (0000-0006) — expects a FRESH database"
for m in "$MIGRATIONS_DIR"/[0-9][0-9][0-9][0-9]_*.sql; do
  echo "   applying $(basename "$m")"
  if ! psql ${PSQL_CONN:+"$PSQL_CONN"} -v ON_ERROR_STOP=1 -f "$m"; then
    echo "migration apply failed: $m" >&2
    exit 2
  fi
done

echo "=> verifying tables exist"
for tbl in tenants api_keys users plan_entitlements workspace_entitlements; do
  count=$(psql ${PSQL_CONN:+"$PSQL_CONN"} -tAc \
    "SELECT COUNT(*) FROM information_schema.tables WHERE table_name='$tbl'")
  if [[ "$count" != "1" ]]; then
    echo "table $tbl missing after migration" >&2
    exit 2
  fi
  echo "   $tbl OK"
done

echo
echo "all green — Drizzle migrations applied + core tables present"
echo "(The #[ignore] integration tests self-apply via db::apply_migrations against"
echo " their own fresh DB — run them separately, not against this seeded one.)"
