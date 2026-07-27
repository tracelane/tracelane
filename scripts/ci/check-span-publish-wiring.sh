#!/usr/bin/env bash
# scripts/ci/check-span-publish-wiring.sh
#
# CI guard for  / (silent 100% span-drop in prod).
#
# The gateway publishes every span to NATS. When `NATS_URL` is absent from the
# gateway *container env*, `AppState::nats` is `None` and the per-request publish
# is skipped — historically with no error and no log, so `/v1/chat/completions`
# returned 200 while ClickHouse `tracelane.spans` stayed at 0 rows. The code path
# is now loud (crates/gateway/src/otlp_emit.rs::note_span_dropped_no_nats), but
# the durable fix is to keep the prod gateway *wired* to NATS. This guard pins
# that wiring so a future compose edit can't silently reintroduce the regression.
#
# Asserts: the `gateway` service in infra/prod/docker-compose.yml carries NATS_URL
# literally in the COMMITTED compose (its `environment:` block). We deliberately do
# NOT accept "it's in the env_file" as sufficient: env_file targets (.env) are
# gitignored and uncommitted, so this guard cannot see them — a future edit moving
# NATS_URL into .env would let the guard pass while a later .env edit silently drops
# it and reintroduces the 100% span-loss regression. Keeping the value in the
# committed, reviewable compose is the durable guarantee this guard enforces.
set -euo pipefail

COMPOSE="infra/prod/docker-compose.yml"

if [ ! -f "$COMPOSE" ]; then
  echo "FAIL: $COMPOSE not found ( wiring guard cannot verify)"
  exit 1
fi

# Slice the gateway service block: from the `  gateway:` key to the next
# top-level (2-space-indented) service key. Then assert NATS_URL appears in it.
gateway_block="$(awk '
  /^  gateway:/        { in_gw = 1; next }
  in_gw && /^  [A-Za-z0-9_-]+:/ { in_gw = 0 }
  in_gw                { print }
' "$COMPOSE")"

if [ -z "$gateway_block" ]; then
  echo "FAIL: could not locate the 'gateway:' service block in $COMPOSE"
  exit 1
fi

if ! grep -q 'NATS_URL' <<<"$gateway_block"; then
  echo "FAIL: $COMPOSE 'gateway' service is missing NATS_URL."
  echo "      Without it, span publish silently disables in prod and 100% of"
  echo "      spans are dropped ( / ). Add to the gateway service"
  echo "      'environment:' block, e.g.:  NATS_URL: nats://nats:4222"
  exit 1
fi

echo "OK: prod 'gateway' service wires NATS_URL ($COMPOSE) —  guard passed"
