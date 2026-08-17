#!/usr/bin/env bash
# Apply migration 03 (B1 prompt-promotion schema) to a running ClickHouse,
# then run the gateway's schema-parity integration tests against it.
#
# Usage:
#   CLICKHOUSE_URL=http://localhost:8123 ./scripts/apply-migration-03.sh
#
# Env vars:
#   CLICKHOUSE_URL  — defaults to http://localhost:8123
#   CLICKHOUSE_DB   — defaults to tracelane
#
# Exit codes:
#   0  — migration applied + integration tests pass
#   1  — clickhouse not reachable
#   2  — migration apply failed
#   3  — integration tests failed
set -euo pipefail

CLICKHOUSE_URL=${CLICKHOUSE_URL:-http://localhost:8123}
CLICKHOUSE_DB=${CLICKHOUSE_DB:-tracelane}
HERE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)
ROOT=$(cd -- "$HERE/.." >/dev/null 2>&1 && pwd)
MIGRATION="$ROOT/infra/dev/clickhouse/migrations/03_prompt_promotion.sql"

if [[ ! -f "$MIGRATION" ]]; then
  echo "migration file not found: $MIGRATION" >&2
  exit 2
fi

echo "=> probing ClickHouse at $CLICKHOUSE_URL"
if ! curl -fsS "$CLICKHOUSE_URL/ping" >/dev/null; then
  echo "ClickHouse not reachable at $CLICKHOUSE_URL" >&2
  exit 1
fi

echo "=> ensuring database $CLICKHOUSE_DB exists"
curl -fsS --data-urlencode "query=CREATE DATABASE IF NOT EXISTS $CLICKHOUSE_DB" "$CLICKHOUSE_URL/" >/dev/null

echo "=> applying migration 03 (skipping row-policy statements)"
# Strip row-policy statements (they need a tenant_role we don't provision
# in dev). Send each remaining statement individually.
python3 - "$MIGRATION" "$CLICKHOUSE_URL" "$CLICKHOUSE_DB" <<'PY'
import sys, urllib.parse, urllib.request

migration_path, ch_url, db = sys.argv[1], sys.argv[2], sys.argv[3]
sql = open(migration_path).read()

statements = []
for raw in sql.split(';'):
    stripped = raw.strip()
    if not stripped:
        continue
    lower = stripped.lower()
    if lower.startswith('create row policy'):
        continue
    if stripped.startswith('--'):
        # Filter inner comment-only lines but keep statements with leading
        # comments by stripping pure-comment lines.
        non_comment = '\n'.join(
            line for line in stripped.splitlines() if not line.lstrip().startswith('--')
        ).strip()
        if not non_comment:
            continue
        stripped = non_comment
    statements.append(stripped)

print(f"   applying {len(statements)} statements to database={db}")

for i, stmt in enumerate(statements, 1):
    url = f"{ch_url}/?database={urllib.parse.quote(db)}"
    req = urllib.request.Request(url, data=stmt.encode("utf-8"), method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        sys.stderr.write(f"statement #{i} failed:\n{stmt}\n---\n{body}\n")
        sys.exit(2)
    print(f"   [{i:02d}/{len(statements):02d}] OK")
PY

echo "=> verifying tables exist"
for tbl in prompts prompt_versions eval_runs promotion_decisions rollback_events; do
  count=$(curl -fsS --data-urlencode "query=EXISTS TABLE $CLICKHOUSE_DB.$tbl" "$CLICKHOUSE_URL/")
  if [[ "$count" != "1" ]]; then
    echo "table $tbl missing after migration" >&2
    exit 2
  fi
  echo "   $tbl OK"
done

echo "=> running schema-parity integration tests"
cd "$ROOT"
if ! CLICKHOUSE_TEST_URL="$CLICKHOUSE_URL" \
     cargo test \
       --features prompt-promotion-preview \
       --test clickhouse_persister_integration \
       -- --ignored --nocapture; then
  echo "integration tests failed" >&2
  exit 3
fi

echo
echo "all green — migration 03 applied + persister schema-parity tests pass"
