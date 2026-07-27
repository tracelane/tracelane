#!/usr/bin/env bash
#
# End-to-end integration smoke (punchlist #4): ingest -> ClickHouse path.
#
# Proves the data-loss-critical half of proxy -> ingest -> ClickHouse ->
# dashboard: a real OTLP span shipped to the ingest receiver lands in the
# ClickHouse spans table, tenant-scoped. (The gateway-proxy front half and the
# dashboard query are covered by their own crate/web tests; this script proves
# the wire path between them with live infra.)
#
# Requires Docker + a Rust toolchain + Python with the OTel SDK. It runs in the
# `smoke` CI job (.github/workflows/smoke.yml). It was authored in an
# environment WITHOUT Docker, so CI is its first real execution — treat a first
# red run as expected iteration, not a product regression.
#
# Run locally (on a Docker host):
#   pip install opentelemetry-sdk opentelemetry-exporter-otlp-proto-http
#   bash scripts/smoke/e2e-smoke.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

COMPOSE=(docker compose -f infra/dev/docker-compose.yml)
TENANT="00000000-0000-0000-0000-0000000000ab"
INGEST_PID=""

cleanup() {
	[ -n "$INGEST_PID" ] && kill "$INGEST_PID" 2>/dev/null || true
	"${COMPOSE[@]}" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Bringing up ClickHouse + NATS"
"${COMPOSE[@]}" up -d clickhouse nats

echo "==> Waiting for ClickHouse HTTP"
for _ in $(seq 1 60); do
	if curl -fsS "http://localhost:8123/ping" >/dev/null 2>&1; then break; fi
	sleep 2
done
curl -fsS "http://localhost:8123/ping" >/dev/null

echo "==> Starting ingest (debug = plaintext + resource-attr tenant)"
CLICKHOUSE_URL="http://localhost:8123" NATS_URL="nats://localhost:4222" \
	cargo run -p ingest >/tmp/ingest-smoke.log 2>&1 &
INGEST_PID=$!

echo "==> Waiting for the OTLP receiver on :4318"
for _ in $(seq 1 120); do
	# Any HTTP response (even 400 on an empty POST) means the port is live.
	if curl -s -o /dev/null -X POST "http://localhost:4318/v1/traces"; then break; fi
	sleep 1
done

echo "==> Emitting a smoke span via OTLP"
python3 scripts/smoke/send_span.py "http://localhost:4318" "$TENANT"

echo "==> Polling ClickHouse for the span"
QUERY="SELECT count() FROM tracelane.spans WHERE tenant_id = '${TENANT}'"
ENCODED="$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$QUERY")"
for _ in $(seq 1 30); do
	COUNT="$(curl -fsS "http://localhost:8123/?query=${ENCODED}" 2>/dev/null || echo 0)"
	COUNT="${COUNT//[$'\t\r\n ']/}"
	if [ "${COUNT:-0}" -ge 1 ] 2>/dev/null; then
		echo "✅ smoke PASS: span reached ClickHouse (count=${COUNT})"
		exit 0
	fi
	sleep 2
done

echo "❌ smoke FAIL: span did not reach ClickHouse within budget"
echo "----- ingest log -----"
cat /tmp/ingest-smoke.log || true
exit 1
