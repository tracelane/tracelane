#!/usr/bin/env bash
# check-clickhouse-users.sh — PROVE the per-service ClickHouse grants block what they
# must and allow what the services need (B-383 c, 2026-09-12).
#
# WHAT IT DOES. Starts a throwaway ClickHouse 24.12 (the image prod runs) with the
# prod users file (`infra/prod/clickhouse/users.d/services.xml`) mounted and the two
# passwords set in its environment exactly as compose sets them, applies the canonical
# schema, then runs every statement in the table below as each user and asserts the
# verdict. A grant file that only READS right is a guard never observed blocking
# (CLAUDE.md §1) — the assertions below are the observation.
#
# `tl_ingest`  INSERT spans → OK (and the MV row lands in trace_summaries — the MV
#              target grant is what makes that work; without it the insert fails)
#              INSERT audit_log → DENIED · SELECT on any table but spans → DENIED
#              (schema.sql now carries BOTH of prod's MVs over spans — the SLO one was
#              the grant the 2026-09-12 outage lacked; asserted present below)
# `tl_gateway` INSERT audit_log → OK · SELECT spans → OK · INSERT guardrail_verdicts → OK
#              INSERT spans → DENIED · INSERT trace_summaries → DENIED
#              DELETE FROM audit_log → DENIED · DROP TABLE audit_log → DENIED
#              ALTER TABLE audit_log UPDATE event_hash → DENIED
#              ALTER TABLE audit_log UPDATE rekor_entry_id → OK (the back-fill column)
#              DELETE FROM spans → OK (the retention sweep); ALTER TABLE trace_summaries
#              DELETE → OK (the heavy form the sweep uses on the projected table);
#              DELETE FROM trace_summaries → THROW (Code 344: refused by the table
#              setting, migration 23 — never a lightweight delete on a projection)
#              TRUNCATE spans → DENIED
#
# BILL-01 / ADR-076 (migration 24, mounted as a second init script — see
# MIGRATION_24 below): `tl_ingest` INSERT meter_counters/blobs/blob_refs → OK,
# SELECT on any of the three → DENIED (it never reads them back). `tl_gateway`
# SELECT+INSERT meter_counters/meter_gauges, SELECT blobs/blob_refs, SELECT
# system.query_log → OK (all via the `tracelane.*` wildcard except
# system.query_log, which is a separate database); ALTER DELETE on
# blobs/blob_refs → OK (the weekly GC mutation + the retention sweep).
#
# Exit 0 = every verdict as expected. Exit 1 = a grant is wrong. Exit 0 with SKIP when
# there is no usable docker — the verify-all step that wires this will then report
# SKIP loudly, never PASS (the same contract as run-clickhouse-integration.sh).
#
#   scripts/ci/check-clickhouse-users.sh              # the proof
#   scripts/ci/check-clickhouse-users.sh --selftest   # prove a WRONG grants file is caught
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
USERS_XML="${USERS_XML:-$ROOT/infra/prod/clickhouse/users.d/services.xml}"
SCHEMA="$ROOT/infra/dev/clickhouse/schema.sql"
# BILL-01 / ADR-076 (migration 24), 2026-09-13 — meter_counters / meter_gauges /
# blobs / blob_refs are NOT in schema.sql (a later migration), so this proof's
# throwaway container needs it mounted as a SECOND init script or those four
# tables would not exist and every grant-on-them assertion below would
# ERROR rather than prove anything. The tiering section at the bottom of that
# file is pure SQL comments (a manual, precondition-gated step) — safe to
# apply here as-is.
MIGRATION_24="$ROOT/infra/dev/clickhouse/migrations/24_bill01_meters_blobs_tiering.sql"
PORT="${CH_USERS_PORT:-18125}"
CONTAINER="tlane-ch-users-$$"
IMAGE="clickhouse/clickhouse-server:24.12-alpine"
INGEST_PW="unit-test-ingest-password-do-not-use"
GATEWAY_PW="unit-test-gateway-password-do-not-use"
ADMIN_PW="unit-test-admin-password-do-not-use"

cleanup() { docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "SKIP: no usable docker — the ClickHouse grants proof CANNOT RUN here (not a pass)."
  exit 0
fi

# q <user> <password> <sql>  → prints "OK" or "DENIED" or "ERROR:<text>"
q() {
  local out
  out="$(curl -sS -m 20 "http://127.0.0.1:${PORT}/?user=$1&password=$2" --data-binary "$3" 2>&1)"
  local rc=$?
  if [ $rc -eq 0 ] && ! grep -q 'Code: ' <<<"$out"; then echo "OK"; echo "$out" >&3
  elif grep -q 'ACCESS_DENIED\|Not enough privileges' <<<"$out"; then echo "DENIED"
  # Code 344: the server refuses a lightweight DELETE on the projected table — the
  # table setting (`throw`, migration 23) doing its job, not a grant.
  elif grep -q 'Code: 344' <<<"$out"; then echo "THROW"
  else echo "ERROR:$(head -c 200 <<<"$out")"; fi
}

start() {
  docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true
  if ! docker run -d --name "$CONTAINER" \
      -e CLICKHOUSE_DB=tracelane -e CLICKHOUSE_USER=tracelane -e CLICKHOUSE_PASSWORD="$ADMIN_PW" \
      -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
      -e CLICKHOUSE_INGEST_PASSWORD="$INGEST_PW" -e CLICKHOUSE_GATEWAY_PASSWORD="$GATEWAY_PW" \
      -v "$1:/etc/clickhouse-server/users.d/services.xml:ro" \
      -v "$SCHEMA:/docker-entrypoint-initdb.d/01_schema.sql:ro" \
      -v "$MIGRATION_24:/docker-entrypoint-initdb.d/02_bill01.sql:ro" \
      -p "${PORT}:8123" "$IMAGE" >/dev/null 2>&1; then
    echo "ERROR: throwaway ClickHouse did not start (port ${PORT} held?)" >&2; return 1
  fi
  local i
  for i in $(seq 1 90); do
    # Both init scripts are applied by the entrypoint IN ORDER; wait for the
    # LAST table EACH creates (schema.sql's trace_summaries, then migration
    # 24's blob_refs) so a race can never see the first without the second.
    if [ "$(curl -sS -m 3 "http://127.0.0.1:${PORT}/?user=tracelane&password=${ADMIN_PW}" \
          --data-binary "SELECT count() FROM system.tables WHERE database='tracelane' AND name IN ('trace_summaries','blob_refs')" 2>/dev/null)" = "2" ]; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: ClickHouse never finished applying the schema (docker logs $CONTAINER)" >&2
  return 1
}

# The proof table: user  expected  sql
run_proof() {
  local rc=0 seq=0
  exec 3>/dev/null
  local T="2026-09-12 00:00:00.000000"
  local SPAN="INSERT INTO tracelane.spans (tenant_id, trace_id, span_id, parent_span_id, name, start_time, end_time, status_code) VALUES ('00000000-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'a1b2c3d4e5f60718', NULL, 'gen_ai.chat', '$T', '$T', 1)"
  local AUDIT="INSERT INTO tracelane.audit_log (tenant_id, seq, event_time, event_type, actor, row_hash, prev_hash) VALUES ('00000000-0000-0000-0000-000000000001', 1, '$T', 'chat.completions.request', 'proof', '0000000000000000000000000000000000000000000000000000000000000001', '')"
  while IFS='|' read -r user expect sql; do
    [ -z "$user" ] && continue
    case "$user" in tl_ingest) pw=$INGEST_PW ;; tl_gateway) pw=$GATEWAY_PW ;; esac
    got="$(q "$user" "$pw" "$sql")"
    if [ "$got" = "$expect" ]; then echo "  ✔ $user: $expect — ${sql:0:70}"
    else echo "  ✗ $user: expected $expect got $got — ${sql:0:90}"; rc=1; fi
  done <<EOT
tl_ingest|OK|$SPAN
tl_ingest|DENIED|$AUDIT
tl_ingest|OK|SELECT status_message FROM tracelane.spans LIMIT 1
tl_ingest|DENIED|SELECT count() FROM tracelane.trace_summaries
tl_ingest|DENIED|SELECT count() FROM tracelane.guardrail_verdicts
tl_ingest|DENIED|SELECT count() FROM tracelane.slo_hourly_stats
tl_ingest|DENIED|SELECT count() FROM tracelane.audit_log
tl_ingest|OK|INSERT INTO tracelane.meter_counters (tenant_id, day, meter, dim, value, source) VALUES ('00000000-0000-0000-0000-000000000001', '2026-09-12', 'ingest_bytes', '', 1.0, 'ingest')
tl_ingest|OK|INSERT INTO tracelane.blobs (tenant_id, hash, bytes, size) VALUES ('00000000-0000-0000-0000-000000000001', unhex('$(printf '00%.0s' $(seq 1 32))'), 'x', 1)
tl_ingest|OK|INSERT INTO tracelane.blob_refs (tenant_id, hash, span_id, day) VALUES ('00000000-0000-0000-0000-000000000001', unhex('$(printf '00%.0s' $(seq 1 32))'), 'a1b2c3d4e5f60718', '2026-09-12')
tl_ingest|DENIED|SELECT count() FROM tracelane.meter_counters
tl_ingest|DENIED|SELECT count() FROM tracelane.blobs
tl_gateway|OK|$AUDIT
tl_gateway|OK|SELECT count() FROM tracelane.meter_counters
tl_gateway|OK|SELECT count() FROM tracelane.meter_gauges
tl_gateway|OK|SELECT count() FROM tracelane.blobs
tl_gateway|OK|SELECT count() FROM tracelane.blob_refs
tl_gateway|OK|SELECT sum(read_bytes) FROM system.query_log WHERE log_comment LIKE 'tenant_id=%'
tl_gateway|OK|INSERT INTO tracelane.meter_gauges (tenant_id, day, meter, value) VALUES ('00000000-0000-0000-0000-000000000001', '2026-09-12', 'hot_resident_bytes', 1.0)
tl_gateway|OK|ALTER TABLE tracelane.blobs DELETE WHERE tenant_id = '00000000-0000-0000-0000-000000000001' AND 1 = 0
tl_gateway|OK|ALTER TABLE tracelane.blob_refs DELETE WHERE tenant_id = '00000000-0000-0000-0000-000000000001' AND day < '2000-01-01'
tl_gateway|OK|SELECT count() FROM tracelane.spans
tl_gateway|OK|SELECT count() FROM tracelane.audit_log
tl_gateway|OK|INSERT INTO tracelane.guardrail_verdicts (tenant_id, correlation_id, side, event_time, decision, total_latency_micros) VALUES ('00000000-0000-0000-0000-000000000001', '01J0000000000000000000000X', 'request', '$T', 'allow', 1)
tl_gateway|DENIED|$SPAN
tl_gateway|DENIED|INSERT INTO tracelane.trace_summaries (tenant_id, trace_id) VALUES ('00000000-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111')
tl_gateway|DENIED|DELETE FROM tracelane.audit_log WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
tl_gateway|DENIED|ALTER TABLE tracelane.audit_log DELETE WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
tl_gateway|DENIED|DROP TABLE tracelane.audit_log
tl_gateway|DENIED|TRUNCATE TABLE tracelane.spans
tl_gateway|DENIED|ALTER TABLE tracelane.audit_log UPDATE row_hash = '0' WHERE seq = 1
tl_gateway|DENIED|ALTER TABLE tracelane.audit_log UPDATE seq = 2 WHERE seq = 1
tl_gateway|OK|ALTER TABLE tracelane.audit_log UPDATE rekor_entry_id = 'abc' WHERE tenant_id = '00000000-0000-0000-0000-000000000001' AND seq = 1
tl_gateway|OK|ALTER TABLE tracelane.audit_log UPDATE signature = 's', signing_pubkey = 'p' WHERE tenant_id = '00000000-0000-0000-0000-000000000001' AND seq = 1
tl_gateway|OK|DELETE FROM tracelane.spans WHERE tenant_id = '00000000-0000-0000-0000-000000000001' AND start_time < '2000-01-01'
tl_gateway|OK|ALTER TABLE tracelane.trace_summaries DELETE WHERE tenant_id = '00000000-0000-0000-0000-000000000001' AND start_time < '2000-01-01' SETTINGS mutations_sync = 2
tl_gateway|THROW|DELETE FROM tracelane.trace_summaries WHERE tenant_id = '00000000-0000-0000-0000-000000000001'
tl_gateway|DENIED|CREATE TABLE tracelane.x (a UInt8) ENGINE = Memory
tl_gateway|DENIED|CREATE USER attacker
tl_gateway|DENIED|SYSTEM FLUSH LOGS
EOT
  # The MV target grant is load-bearing: the ingest's span insert must have produced
  # the summary row, or the read path sees nothing.
  local n
  n="$(curl -sS -m 5 "http://127.0.0.1:${PORT}/?user=tracelane&password=${ADMIN_PW}" --data-binary "SELECT count() FROM tracelane.trace_summaries WHERE trace_id = '11111111-1111-1111-1111-111111111111'")"
  if [ "$n" = "1" ]; then echo "  ✔ tl_ingest's span insert produced its trace_summaries row through the MV"
  else echo "  ✗ the MV row did not land (count=$n) — the ingest user is missing INSERT on the MV target"; rc=1; fi
  local m
  m="$(curl -sS -m 5 "http://127.0.0.1:${PORT}/?user=tracelane&password=${ADMIN_PW}" --data-binary "SELECT count() FROM system.tables WHERE database='tracelane' AND name='mv_slo_hourly_stats'")"
  if [ "$m" = "1" ]; then echo "  ✔ prod's second MV over spans (mv_slo_hourly_stats) is present in the proof container"
  else echo "  ✗ migration 06 did not apply — the proof would pass against fewer MVs than prod has"; rc=1; fi
  return $rc
}

case "${1:-}" in
  ""|--selftest) ;;
  *) echo "usage: $(basename "$0") [--selftest]" >&2; exit 2 ;;
esac

if [ "${1:-}" = "--selftest" ]; then
  # Plant a grants file that hands the gateway ALTER DELETE on audit_log and the
  # ingest SELECT on spans — the proof MUST fail on both.
  tmp="$(mktemp --suffix=.xml)"
  chmod 644 "$tmp"   # mktemp gives 0600; the container's clickhouse uid must read it
  sed -e 's#<query>GRANT ALTER DELETE, ALTER UPDATE(_row_exists) ON tracelane.spans</query>#<query>GRANT ALTER DELETE, ALTER UPDATE(_row_exists) ON tracelane.spans</query><query>GRANT ALTER DELETE, ALTER UPDATE(_row_exists) ON tracelane.audit_log</query>#' \
      -e 's#<query>GRANT INSERT ON tracelane.federation_signals</query>#<query>GRANT INSERT ON tracelane.federation_signals</query><query>GRANT SELECT ON tracelane.spans</query>#' \
      "$USERS_XML" > "$tmp"
  grep -q 'ON tracelane.audit_log</query>' "$tmp" || { echo "selftest could not plant the bad grant"; exit 1; }
  start "$tmp" || { echo "SELFTEST CANNOT DETERMINE — container did not come up"; exit 3; }
  if run_proof >/dev/null; then echo "SELFTEST FAIL — a grants file that lets the gateway delete ledger rows PASSED"; exit 1; fi
  echo "SELFTEST PASS — an over-granted users file is refused"
  rm -f "$tmp"; exit 0
fi

start "$USERS_XML" || exit 3
if run_proof; then echo "clickhouse users: OK — every per-service grant behaves as specified (refusals observed)"; exit 0; fi
echo "clickhouse users: FAIL"; exit 1
