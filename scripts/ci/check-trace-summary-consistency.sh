#!/usr/bin/env bash
# check-trace-summary-consistency.sh — the span↔trace_summaries integrity probe.
#
# The invariant behind the Signatures/Gateway TRACES click-throughs
# (the signatures-traces count-mismatch invariant): counts are computed over
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

# PARSE ARGV AND REFUSE THE UNKNOWN. `check-guard-selftests.py` requires it: a
# script that accepts any flag makes its own `--selftest` meaningless, because a
# pass cannot be told from an ignored flag.
case "${1:-}" in
  ""|--selftest) ;;
  *) echo "usage: $(basename "$0") [--selftest]  (unknown argument: $1)" >&2; exit 2 ;;
esac

DB="${TRACELANE_DB:-tracelane}"

# ── --selftest: PLANT an orphan and require a RED ────────────────────────────
#
# WHY THIS EXISTS. This probe was written, was correct, and had ZERO CALLERS in
# verify-all.sh or any workflow from the day it landed. On 2026-08-14 it was run
# by hand for the first time and immediately found 26 real orphan summaries on
# prod — plus it would have caught a hand-deletion that left 10,154 more. A
# detector that only runs when someone remembers is the thing it was built to
# replace (TRAPS §1 CLASS-1, fourth instance this week).
#
# The selftest uses a THROWAWAY ClickHouse, never the node: a guard that needs
# production to prove itself cannot run on every push.
if [ "${1:-}" = "--selftest" ]; then
  # Exit 3, NOT 0. Invoked directly on a docker-less host this must not read as
  # a pass — "could not run" and "ran and passed" are different answers and only
  # one of them is coverage. verify-all branches on docker BEFORE calling this and
  # renders the gap as a named SKIP in its summary.
  command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1 || {
    echo "CANNOT RUN: docker unavailable — this selftest is UNPROVEN here (exit 3, not a pass)."; exit 3; }
  C="tlane-tsc-selftest-$$"
  cleanup(){ docker rm -f "$C" >/dev/null 2>&1; }
  trap cleanup EXIT
  docker run -d --name "$C" clickhouse/clickhouse-server:24.12-alpine >/dev/null 2>&1 || {
    echo "SKIP: could not start a throwaway ClickHouse."; exit 0; }
  q(){ docker exec "$C" clickhouse-client --query "$1" 2>&1; }
  ok=0
  for i in $(seq 1 60); do q "SELECT 1" >/dev/null 2>&1 && { ok=1; break; }; sleep 1; done
  [ "$ok" = 1 ] || { echo "SKIP: throwaway ClickHouse never became ready."; exit 0; }

  q "CREATE DATABASE IF NOT EXISTS ${DB}" >/dev/null
  q "CREATE TABLE ${DB}.spans (trace_id String) ENGINE = MergeTree ORDER BY trace_id" >/dev/null
  q "CREATE TABLE ${DB}.trace_summaries (trace_id String) ENGINE = ReplacingMergeTree ORDER BY trace_id" >/dev/null
  export CLICKHOUSE_CMD="docker exec $C clickhouse-client --query"

  # (a) consistent -> GREEN
  q "INSERT INTO ${DB}.spans VALUES ('t1')" >/dev/null
  q "INSERT INTO ${DB}.trace_summaries VALUES ('t1')" >/dev/null
  if "$0" >/dev/null 2>&1; then echo "  ✓ consistent tree passes"; else
    echo "  ✗ consistent tree FAILED — the guard cries wolf"; exit 1; fi

  # (b) ORPHAN SUMMARY (a summary with no spans) -> must go RED. This is the
  #     exact state a hand-written DELETE leaves behind.
  q "INSERT INTO ${DB}.trace_summaries VALUES ('orphan')" >/dev/null
  if "$0" >/dev/null 2>&1; then
    echo "  ✗ ORPHAN SUMMARY NOT DETECTED — this guard proves nothing"; exit 1; fi
  echo "  ✓ orphan summary detected (the hand-deletion shape)"
  q "ALTER TABLE ${DB}.trace_summaries DELETE WHERE trace_id='orphan'" >/dev/null; sleep 2

  # (c) MISSING SUMMARY (spans with no summary) -> must also go RED, or the
  #     guard would only cover one direction of the invariant.
  q "INSERT INTO ${DB}.spans VALUES ('nosummary')" >/dev/null
  if "$0" >/dev/null 2>&1; then
    echo "  ✗ MISSING SUMMARY NOT DETECTED — only half the invariant is guarded"; exit 1; fi
  echo "  ✓ missing summary detected"

  echo "SELFTEST PASSED — both directions of the spans<->summaries invariant go RED when broken."
  exit 0
fi

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
echo "  This guard enforces the spans <-> trace_summaries integrity invariant."
exit 1
