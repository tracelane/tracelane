#!/usr/bin/env bash
#
# L2 live eval gate — stand up an EPHEMERAL REAL stack and run the behavioral
# evals against it, with ONLY the upstream provider faked.
#
# Why: the CI "Eval Suite (Merge Gate)" runs mock-only, so every behavioral
# assertion skips — that hole let the  100%-span-drop ship unnoticed.
# This boots gateway → NATS → ingest → ClickHouse for real (version-pinned to
# prod: ClickHouse 24.12-alpine, NATS 2.10-alpine via infra/dev/docker-compose)
# and points the gateway's upstream at a local mock provider. The canonical
# GC-TRACE-LOOP eval then proves the WHOLE loop: real chat request → span in
# ClickHouse (write) → queryable via the gateway /v1/traces read.
#
# No prod secrets / no gateway code change: a DEBUG gateway with WORKOS_CLIENT_ID
# unset resolves the fixed dev-stub tenant (auth/mod.rs::DEV_TENANT_UUID); the
# provider key falls back to OPENAI_API_KEY (env) and the upstream is the mock;
# TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS=1 lets it reach the loopback mock.
#
# Authored without Docker locally (like scripts/smoke/e2e-smoke.sh) — CI is its
# first real execution; treat a first red run as expected iteration.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

COMPOSE=(docker compose -f infra/dev/docker-compose.yml)
MOCK_PORT="${MOCK_PROVIDER_PORT:-7070}"
GATEWAY_PORT="${TRACELANE_EVAL_GATEWAY_PORT:-8080}"
CH_URL="http://localhost:8123"
NATS_URL_LOCAL="nats://localhost:4222"

MOCK_PID="" ; INGEST_PID="" ; GATEWAY_PID=""

cleanup() {
	echo "==> Teardown"
	for pid in "$GATEWAY_PID" "$INGEST_PID" "$MOCK_PID"; do
		[ -n "$pid" ] && kill "$pid" 2>/dev/null || true
	done
	"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

wait_http() { # url, tries, sleep
	local url="$1" tries="${2:-60}" nap="${3:-2}"
	for _ in $(seq 1 "$tries"); do
		if curl -fsS "$url" >/dev/null 2>&1; then return 0; fi
		sleep "$nap"
	done
	return 1
}

echo "==> 1/6 Bring up ClickHouse + NATS (+ stream) — prod-pinned 24.12 / 2.10"
"${COMPOSE[@]}" up -d clickhouse nats nats-init

echo "==> 2/6 Wait for ClickHouse + base schema (prod-parity)"
wait_http "$CH_URL/ping" 60 2 || { echo "FAIL: ClickHouse not ready"; exit 1; }
# The dev schema.sql is auto-applied via the compose init mount and is the
# CURRENT canonical schema (it already bakes in the  gen_ai_* → model
# coalesce + trace_summaries + slo + audit_log for fresh inits). So a fresh
# init equals prod's post-migration state — re-applying the INCREMENTAL
# migrations on top is wrong (they are deltas for existing deployments and
# double-apply). Just wait for the init mount to finish (it races /ping).
for _ in $(seq 1 30); do
	exists="$("${COMPOSE[@]}" exec -T clickhouse clickhouse-client --query "EXISTS tracelane.spans" 2>/dev/null | tr -d '[:space:]')"
	[ "$exists" = "1" ] && break
	sleep 2
done
if [ "${exists:-0}" != "1" ]; then
	echo "FAIL: base schema (tracelane.spans) not initialized from schema.sql"
	"${COMPOSE[@]}" logs clickhouse 2>&1 | tail -40
	exit 1
fi
echo "    base schema ready (tracelane.spans exists)"

echo "==> 3/6 Start mock provider (upstream LLM stand-in) on :$MOCK_PORT"
MOCK_PROVIDER_PORT="$MOCK_PORT" node evals/ci/mock-provider.mjs >/tmp/mock-provider.log 2>&1 &
MOCK_PID=$!
wait_http "http://127.0.0.1:$MOCK_PORT/__health" 20 1 || { echo "FAIL: mock provider"; cat /tmp/mock-provider.log; exit 1; }

# Pre-build BOTH binaries before starting them. `cargo run` would otherwise
# compile inline, and on a PR that changes gateway code that cold compile (a
# few minutes) overruns the per-service health waits below — the gateway never
# answered /health in time and the job failed even though nothing was wrong.
# Building up-front makes the `cargo run` steps start the cached binary in
# seconds, so the waits only cover real startup.
echo "==> Pre-build gateway + ingest (debug)"
cargo build -p gateway -p ingest >/tmp/cargo-build.log 2>&1 \
	|| { echo "FAIL: cargo build (debug)"; tail -40 /tmp/cargo-build.log; exit 1; }
echo "    binaries built"

echo "==> 4/6 Start ingest (debug — NATS consumer → ClickHouse)"
# Full-fidelity for the eval: the prod default is 10% (clean traces tail-sampled),
# which silently drops the benign GC-TRACE-LOOP span ~90% of the time (#81).
CLICKHOUSE_URL="$CH_URL" NATS_URL="$NATS_URL_LOCAL" TRACELANE_TAIL_SAMPLE_RATE_PCT=100 \
	cargo run -p ingest >/tmp/ingest-live.log 2>&1 &
INGEST_PID=$!
wait_http "http://localhost:4318/v1/traces" 120 1 || true  # OTLP port live = process up

echo "==> 5/6 Start gateway (debug — dev-stub auth, mock upstream, real NATS/CH)"
# WORKOS_CLIENT_ID intentionally UNSET → dev-stub tenant. OPENAI_* → mock.
env -u WORKOS_CLIENT_ID \
	TRACELANE_PORT="$GATEWAY_PORT" \
	TRACELANE_LOG_FORMAT=json \
	NATS_URL="$NATS_URL_LOCAL" \
	CLICKHOUSE_URL="$CH_URL" \
	OPENAI_BASE_URL="http://127.0.0.1:$MOCK_PORT" \
	OPENAI_API_KEY="sk-fake-eval-key" \
	ANTHROPIC_BASE_URL="http://127.0.0.1:$MOCK_PORT" \
	ANTHROPIC_API_KEY="sk-ant-fake-eval-key" \
	TRACELANE_SSRF_ALLOW_LOOPBACK_FOR_TESTS=1 \
	TRACELANE_PREDICTIVE_TEST_HOOKS=1 \
	OTEL_SEMCONV_STABILITY_OPT_IN=gen_ai_latest_experimental \
	cargo run -p gateway >/tmp/gateway-live.log 2>&1 &
GATEWAY_PID=$!
wait_http "http://localhost:$GATEWAY_PORT/health" 120 1 || { echo "FAIL: gateway health"; tail -50 /tmp/gateway-live.log; exit 1; }

echo "==> 6/6 Run live eval gate (canonical trace-loop + gateway-correctness)"
# TRACELANE_EVAL_LIVE_GATEWAY_URL flips isLiveGatewayConfigured()=true so the
# behavioral evals run instead of skipping. CLICKHOUSE_URL lets the canonical
# eval assert the write half directly.
set +e
TRACELANE_EVAL_LIVE_GATEWAY_URL="http://localhost:$GATEWAY_PORT" \
CLICKHOUSE_URL="$CH_URL" \
	pnpm eval:run --suite="${LIVE_EVAL_SUITE:-gc}" 2>&1 | tee /tmp/live-eval-out.log
EVAL_RC=${PIPESTATUS[0]}
set -e

# Anti-vacuous-gate guard. The whole point of L2 is that the core assertion must
# actually RUN; a green suite where GC-TRACE-LOOP shows "skipped" is the exact
#  failure mode (gate passes while its assertion never executes). Fail
# hard if the canonical loop is absent or skipped.
if ! grep -aqE "GC-TRACE-LOOP" /tmp/live-eval-out.log; then
	echo "❌ GC-TRACE-LOOP did not appear in the eval output — the live gate is not exercising it."
	EVAL_RC=1
elif grep -aE "GC-TRACE-LOOP" /tmp/live-eval-out.log | grep -qi "skip"; then
	echo "❌ GC-TRACE-LOOP was SKIPPED under the live gate — the core trace-loop assertion did not run (vacuous green)."
	EVAL_RC=1
fi

if [ "$EVAL_RC" -ne 0 ]; then
	echo "❌ live eval gate FAILED (rc=$EVAL_RC)"
	echo "----- span-path warnings (gateway + ingest) -----"
	grep -aE 'span publish DISABLED|span NATS publish failed|rejecting NATS span|failed to deserialize span|ClickHouse insert failed' \
		/tmp/gateway-live.log /tmp/ingest-live.log || echo "(no span-path warnings)"
	echo "----- gateway log (tail) -----"; tail -60 /tmp/gateway-live.log || true
	echo "----- ingest log (tail) -----"; tail -40 /tmp/ingest-live.log || true
	echo "----- mock provider log -----"; tail -20 /tmp/mock-provider.log || true
	exit "$EVAL_RC"
fi
echo "✅ live eval gate PASSED"
