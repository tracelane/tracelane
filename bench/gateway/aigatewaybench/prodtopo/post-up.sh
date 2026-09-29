#!/usr/bin/env bash
# prodtopo/post-up.sh — run by run.sh after the prod-topology gateway answers /health and
# BEFORE the scenario: prove ONE chat completion reaches the mock through the SEEDED BYOK
# row (decrypted by the gateway's real AAD-bound path — with a control plane + master key
# the env fallback is closed, `server/dispatch.rs::env_fallback_allowed`) and lands ONE
# ledger row, so the acked publish + head-writer are demonstrably on
# the path the scenario is about to measure. Prints `HEAD_BEFORE=<seq>` for run.sh.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GW="${1:?gateway base url}"
BEARER="$(cat "$HERE/generated/bearer")"
PG="psql postgres://tracelane:tracelane_bench@127.0.0.1:5432/tracelane -Atc"
pg() { docker run --rm --network host postgres:17-alpine $PG "$1" </dev/null; }

# The BYOK row was seeded (prepare.sh) — the route refuses API keys by design, so the
# proof that the credential path works is the chat probe below decrypting it.
head0="$(pg "SELECT coalesce(max(last_seq),-1) FROM audit_chain_state")"
code="$(curl -s -o /tmp/chat.out -w '%{http_code}' -X POST "$GW/v1/chat/completions" \
  -H "Authorization: Bearer $BEARER" -H 'content-type: application/json' \
  -d '{"model":"claude-mock-gwbench","messages":[{"role":"user","content":"post-up probe"}],"max_tokens":8}')"
[ "$code" = "200" ] || { echo "post-up: probe chat failed http=$code $(head -c 300 /tmp/chat.out)" >&2; exit 1; }
# The head-writer appends off the request path — give it a moment, then read the head.
head1=-1; for i in $(seq 1 20); do head1="$(pg "SELECT coalesce(max(last_seq),-1) FROM audit_chain_state")"; [ "$head1" -gt "$head0" ] && break; sleep 0.5; done
[ "$head1" -gt "$head0" ] || { echo "post-up: ONE chat request did not advance the ledger head ($head0 -> $head1) — the acked audit path is NOT live; refusing to measure" >&2; exit 1; }
rows="$(pg "SELECT count(*) FROM audit_log_rows")"
echo "post-up: probe 200, ledger head $head0 -> $head1, audit_log_rows=$rows — acked JetStream publish + head-writer are on the path" >&2
echo "HEAD_BEFORE=$head1"
