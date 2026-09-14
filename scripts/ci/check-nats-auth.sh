#!/usr/bin/env bash
# check-nats-auth.sh — PROVE the prod NATS authorization block lets each service do
# exactly its job and nothing else (B-383 b, 2026-09-12).
#
# Starts a throwaway nats-server on the image prod runs, with the prod
# `infra/prod/nats/nats.conf` mounted and the three passwords in its environment
# exactly as compose sets them, then runs the two clients' LIVE tests:
#   crates/gateway  b383_gateway_nats_user_can_do_exactly_its_job
#   crates/ingest   b383_ingest_nats_user_can_do_exactly_its_job
# Those drive the real `ensure_stream` / `ensure_pull_consumer` / `publish` code —
# the permission list is a list of the JetStream API subjects those calls emit, and
# a hand-written `nats pub` would prove a different thing. The refusals are asserted
# there too: anonymous connect, ingest → `tracelane.audit.>`, gateway → the spans
# stream, either → deleting a stream.
#
# Exit 0 = both tests green. Exit 1 = a permission is wrong. Exit 0 with SKIP when
# there is no usable docker (verify-all reports SKIP loudly, never PASS).
#
#   scripts/ci/check-nats-auth.sh              # the proof
#   scripts/ci/check-nats-auth.sh --selftest   # prove an OVER-permitted conf is caught
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONF="${NATS_CONF:-$ROOT/infra/prod/nats/nats.conf}"
PORT="${NATS_AUTH_PORT:-14223}"
CONTAINER="tlane-nats-auth-$$"
IMAGE="nats:2.12-alpine"
GW_PW="unit-test-gateway-nats-password"; IN_PW="unit-test-ingest-nats-password"; OPS_PW="unit-test-ops-nats-password"

cleanup() { docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "SKIP: no usable docker — the NATS auth proof CANNOT RUN here (not a pass)."
  exit 0
fi

start() {
  docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true
  if ! docker run -d --name "$CONTAINER" \
      -e NATS_GATEWAY_PASSWORD="$GW_PW" -e NATS_INGEST_PASSWORD="$IN_PW" -e NATS_OPS_PASSWORD="$OPS_PW" \
      -v "$1:/etc/nats/nats.conf:ro" -p "${PORT}:4222" "$IMAGE" -c /etc/nats/nats.conf >/dev/null 2>&1; then
    echo "ERROR: throwaway nats-server did not start (port ${PORT} held?)" >&2; return 1
  fi
  local i
  for i in $(seq 1 30); do
    if docker logs "$CONTAINER" 2>&1 | grep -q 'Server is ready'; then return 0; fi
    if docker logs "$CONTAINER" 2>&1 | grep -qi 'error'; then
      echo "ERROR: nats-server refused the config:"; docker logs "$CONTAINER" 2>&1 | tail -5; return 1
    fi
    sleep 1
  done
  echo "ERROR: nats-server never reported ready (docker logs $CONTAINER)" >&2; return 1
}

run_tests() {
  local rc=0
  export NATS_TEST_URL_GATEWAY="nats://gateway:${GW_PW}@127.0.0.1:${PORT}"
  export NATS_TEST_URL_INGEST="nats://ingest:${IN_PW}@127.0.0.1:${PORT}"
  export NATS_TEST_URL_OPS="nats://ops:${OPS_PW}@127.0.0.1:${PORT}"
  export NATS_TEST_URL_ANON="nats://127.0.0.1:${PORT}"
  cargo test -p ingest --bin ingest b383_ingest_nats_user -- --ignored 2>&1 | grep -E '^test |panicked|test result' || rc=1
  [ "${PIPESTATUS[0]}" -eq 0 ] || rc=1
  cargo test -p gateway --bin gateway b383_gateway_nats_user -- --ignored 2>&1 | grep -E '^test |panicked|test result' || rc=1
  [ "${PIPESTATUS[0]}" -eq 0 ] || rc=1
  return $rc
}

case "${1:-}" in
  ""|--selftest) ;;
  *) echo "usage: $(basename "$0") [--selftest]" >&2; exit 2 ;;
esac

if [ "${1:-}" = "--selftest" ]; then
  # Plant a conf where the INGEST user may publish into the ledger's subject; the
  # ingest test's "forged audit event" assertion must fail.
  tmp="$(mktemp --suffix=.conf)"; chmod 644 "$tmp"
  python3 - "$CONF" "$tmp" <<'PY'
import sys
s = open(sys.argv[1]).read()
i = s.index('user: ingest')
j = s.index('"$JS.API.INFO",', i)
s = s[:j] + '"tracelane.audit.>",\n            ' + s[j:]
open(sys.argv[2], 'w').write(s)
PY
  grep -A8 'user: ingest' "$tmp" | grep -q 'tracelane.audit' || { echo "selftest could not plant the over-permission"; exit 1; }
  start "$tmp" || { echo "SELFTEST CANNOT DETERMINE — server did not come up"; exit 3; }
  if run_tests >/dev/null 2>&1; then echo "SELFTEST FAIL — a conf that lets ingest write the ledger's subject PASSED"; rm -f "$tmp"; exit 1; fi
  echo "SELFTEST PASS — an over-permitted nats.conf is refused"; rm -f "$tmp"; exit 0
fi

start "$CONF" || exit 3
if run_tests; then echo "nats auth: OK — each service user does exactly its job; anonymous, cross-service and delete are refused"; exit 0; fi
echo "nats auth: FAIL"; exit 1
