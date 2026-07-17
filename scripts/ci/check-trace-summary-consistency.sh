#!/usr/bin/env bash
# check-trace-summary-consistency.sh — the span↔trace_summaries integrity probe.
#
# The invariant behind the Signatures/Gateway TRACES click-throughs (see
# runbooks/RCA-signatures-traces-count-mismatch.md): counts are computed over
# `spans`, but the /traces list is backed by `trace_summaries`. They only agree
# if EVERY trace with spans has a summary row (and there are no orphan summaries).
# For real gateway traffic the mv_trace_summaries MV keeps this true atomically;
# it broke once on the seeded DEMO tenant (legacy/partial seed). This probe catches
# that drift at its root — run it after seeding, or as a prod data-quality check.
#
# CH client is configurable (default = the prod node's docker exec, matching how
# the demo is seeded/fixed). Override with CLICKHOUSE_CMD for a local/other CH:
#   CLICKHOUSE_CMD='clickhouse-client -q' scripts/ci/check-trace-summary-consistency.sh
#   NODE=tl-node-1 scripts/ci/check-trace-summary-consistency.sh   # via ssh+docker
#
# Exit 0 iff spans↔summaries are fully consistent (0 missing, 0 orphan).
set -uo pipefail

DB="${TRACELANE_DB:-tracelane}"

run() { # <sql> -> the query result (one line)
  local sql="$1"
  if [ -n "${CLICKHOUSE_CMD:-}" ]; then
    eval "$CLICKHOUSE_CMD \"\$sql\""
  else
    local node="${NODE:-tl-node-1}"
    ssh -o ConnectTimeout=15 -i "${SSH_KEY:-$HOME/.ssh/hetzner}" "$node" \
      "docker exec tracelane-clickhouse-1 clickhouse-client -q \"$sql\"" 2>/dev/null
  fi
}

SQL="SELECT
  (SELECT uniqExact(trace_id) FROM ${DB}.spans WHERE trace_id NOT IN (SELECT trace_id FROM ${DB}.trace_summaries FINAL)) AS spans_missing_summary,
  (SELECT uniqExact(trace_id) FROM ${DB}.trace_summaries FINAL WHERE trace_id NOT IN (SELECT trace_id FROM ${DB}.spans)) AS orphan_summaries
FORMAT TSV"

out="$(run "$SQL")"
if [ -z "$out" ]; then
  echo "❌ trace-summary consistency: could not reach ClickHouse (set CLICKHOUSE_CMD or NODE)"; exit 2
fi
missing="$(echo "$out" | awk '{print $1}')"
orphan="$(echo "$out" | awk '{print $2}')"

echo "== trace_summaries consistency =="
echo "  spans traces missing a summary : ${missing}"
echo "  orphan summaries (no spans)    : ${orphan}"

if [ "$missing" = "0" ] && [ "$orphan" = "0" ]; then
  echo "✓ spans ↔ trace_summaries fully consistent — every count agrees with its /traces click-through"
  exit 0
fi
echo "✗ INCONSISTENT — a spans-derived count (Signatures TRACES, Gateway Requests) can exceed what /traces shows."
echo "  Fix: backfill trace_summaries from spans (the mv_trace_summaries SELECT) for missing traces;"
echo "  delete orphan summaries (ALTER TABLE ${DB}.trace_summaries DELETE WHERE trace_id NOT IN (SELECT trace_id FROM ${DB}.spans))."
echo "  See runbooks/RCA-signatures-traces-count-mismatch.md."
exit 1
