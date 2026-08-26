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
  # `start_time` IS IN THE SORTING KEY, exactly as in the real schema — and that is the
  # whole point of the B-243 case below. A throwaway table keyed only on trace_id would
  # collapse the two planted rows under FINAL and the probe would pass, proving nothing.
  # The selftest has to reproduce the KEY, not just the row count.
  q "CREATE TABLE ${DB}.trace_summaries (trace_id String, start_time DateTime64(6,'UTC') DEFAULT toDateTime64(0,6)) ENGINE = ReplacingMergeTree ORDER BY (start_time, trace_id)" >/dev/null
  export CLICKHOUSE_CMD="docker exec $C clickhouse-client --query"

  # (a) consistent -> GREEN
  q "INSERT INTO ${DB}.spans VALUES ('t1')" >/dev/null
  q "INSERT INTO ${DB}.trace_summaries (trace_id) VALUES ('t1')" >/dev/null
  if "$0" >/dev/null 2>&1; then echo "  ✓ consistent tree passes"; else
    echo "  ✗ consistent tree FAILED — the guard cries wolf"; exit 1; fi

  # (b) ORPHAN SUMMARY (a summary with no spans) -> must go RED. This is the
  #     exact state a hand-written DELETE leaves behind.
  q "INSERT INTO ${DB}.trace_summaries (trace_id) VALUES ('orphan')" >/dev/null
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
  q "INSERT INTO ${DB}.spans VALUES ('t1')" >/dev/null  # restore: 'nosummary' stays, removed next
  q "ALTER TABLE ${DB}.spans DELETE WHERE trace_id='nosummary'" >/dev/null; sleep 2

  # (d) B-243 — TWO SUMMARY ROWS FOR ONE TRACE, planted in the exact shape the MV
  #     produces: same trace_id, DIFFERENT start_time, so the two rows have different
  #     sorting keys and FINAL cannot collapse them. Both presence invariants above are
  #     SATISFIED here — the trace has a summary and the summary has spans — which is
  #     precisely why this went undetected while /traces rendered one trace twice.
  q "INSERT INTO ${DB}.trace_summaries (trace_id, start_time) VALUES ('t1', toDateTime64('2026-08-14 10:14:21.236191',6))" >/dev/null
  q "INSERT INTO ${DB}.trace_summaries (trace_id, start_time) VALUES ('t1', toDateTime64('2026-08-14 10:14:21.236248',6))" >/dev/null
  # Falsify the harness before trusting the verdict: if FINAL DID collapse these, the
  # case would be untestable here and a pass would be meaningless.
  n_final="$(q "SELECT count() FROM ${DB}.trace_summaries FINAL WHERE trace_id='t1'" | tr -d '[:space:]')"
  if [ "$n_final" = "1" ]; then
    echo "  ✗ HARNESS BROKEN — FINAL collapsed the planted rows, so this case cannot fail. Fix the key."; exit 1; fi
  if "$0" >/dev/null 2>&1; then
    echo "  ✗ B-243 DUPLICATE SUMMARY NOT DETECTED — a trace can render twice and this guard is silent"; exit 1; fi
  echo "  ✓ B-243 duplicate summary detected (${n_final} rows survive FINAL, as in prod)"

  echo "SELFTEST PASSED — all three invariants go RED when broken: missing, orphan, and duplicate."
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

# THE THIRD INVARIANT (B-243, added 2026-08-17): EXACTLY ONE summary row per trace.
#
# The two invariants above are about PRESENCE — every trace has a summary, every
# summary has a trace. Both were satisfied on 2026-08-14 while the /traces list was
# rendering one trace as TWO rows, because neither asks about CARDINALITY.
#
# WHY IT HAPPENS. `mv_trace_summaries` does `GROUP BY tenant_id, trace_id`, and a
# materialized view aggregates PER INSERT BLOCK, never across the table. So a trace
# whose spans arrive in two ingest flushes emits TWO summary rows, each holding that
# batch's own `min(start_time)`. `start_time` is IN THE SORTING KEY, so the two rows
# have DIFFERENT keys and ReplacingMergeTree cannot collapse them — which is why this
# query says FINAL and still expects to find them.
#
# WHY IT LOOKED CLEAN FOR MONTHS. Every prior proof used simulated ~40ms "LLM" calls,
# so all spans left in a single BatchSpanProcessor flush. REAL latency is the trigger,
# so this fires for genuine agents and for no synthetic test. Measured on prod
# 2026-08-17: 8,893 rows / 8,892 distinct traces — exactly ONE duplicated trace, and it
# is the B-227 SDK proof run, the only real multi-span trace with real latency the
# system has ever recorded. The defect is not rare; the traffic is.
#
# WHAT THE USER SEES when it fires (the real row, prod):
#     research.run   5 spans   6.55s
#     (empty name)   3 spans   3.72s
# against a truth in `spans` of ONE trace, EIGHT spans, 6.551008s. A nameless trace
# that never existed, next to an under-counted real one.
#
# uniqExact vs count() is the whole tell, and it is why the metering paths were already
# safe (alerts/checker.rs:67, server.rs:3566, trace_reads.rs:1449 all count DISTINCT
# trace_id and name B-243). This probe deliberately measures the gap BETWEEN them.
SQL="SELECT
  (SELECT uniqExact(trace_id) FROM ${DB}.spans WHERE trace_id NOT IN (SELECT trace_id FROM ${DB}.trace_summaries FINAL)) AS spans_missing_summary,
  (SELECT uniqExact(trace_id) FROM ${DB}.trace_summaries FINAL WHERE trace_id NOT IN (SELECT trace_id FROM ${DB}.spans)) AS orphan_summaries,
  (SELECT count() - uniqExact(trace_id) FROM ${DB}.trace_summaries FINAL) AS surplus_summary_rows
FORMAT TSV"

out="$(run "$SQL")"
if [ -z "$out" ]; then
  echo "❌ trace-summary consistency: could not reach ClickHouse (set CLICKHOUSE_CMD or NODE)"; exit 2
fi
missing="$(echo "$out" | awk '{print $1}')"
orphan="$(echo "$out" | awk '{print $2}')"
surplus="$(echo "$out" | awk '{print $3}')"

echo "== trace_summaries consistency =="
echo "  spans traces missing a summary : ${missing}"
echo "  orphan summaries (no spans)    : ${orphan}"
echo "  SURPLUS rows (dupes, B-243)    : ${surplus}"

if [ "$missing" = "0" ] && [ "$orphan" = "0" ] && [ "$surplus" = "0" ]; then
  echo "✓ spans ↔ trace_summaries fully consistent — every count agrees with its /traces click-through,"
  echo "  and every trace occupies EXACTLY ONE summary row."
  exit 0
fi
if [ "$missing" != "0" ] || [ "$orphan" != "0" ]; then
  echo "✗ INCONSISTENT — a spans-derived count (Signatures TRACES, Gateway Requests) can exceed what /traces shows."
  echo "  Fix: backfill trace_summaries from spans (the mv_trace_summaries SELECT) for missing traces;"
  echo "  delete orphan summaries (ALTER TABLE ${DB}.trace_summaries DELETE WHERE trace_id NOT IN (SELECT trace_id FROM ${DB}.spans))."
fi
if [ "$surplus" != "0" ]; then
  echo "✗ B-243 — ${surplus} SURPLUS summary row(s): a trace is rendered MORE THAN ONCE on /traces,"
  echo "  each row carrying only its own ingest batch's span_count and duration. FINAL cannot collapse"
  echo "  them: start_time is in the sorting key and each batch computed its own min(start_time)."
  echo "  Locate:  SELECT trace_id, count() n FROM ${DB}.trace_summaries FINAL GROUP BY trace_id HAVING n>1"
  echo "  REPAIR (per trace, and it must be a DELETE + re-INSERT from spans — there is no in-place"
  echo "  merge, because the two rows are partial and neither is correct):"
  echo "    ALTER TABLE ${DB}.trace_summaries DELETE WHERE trace_id = '<id>';"
  echo "    -- then re-run the mv_trace_summaries SELECT for that trace as a single INSERT, so the"
  echo "    -- whole trace aggregates in ONE block and lands as ONE row."
  echo "  DURABLE FIX is a schema change, not a repair: the target table's ORDER BY must not contain"
  echo "  a column the MV derives per batch, and the engine must MERGE partial rows rather than"
  echo "  REPLACE them. Repairing without that lets the next real agent recreate it."
fi
echo "  This guard enforces the spans <-> trace_summaries integrity invariant."
exit 1
