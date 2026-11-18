#!/usr/bin/env bash
# Run the real wire suites at nightly and immediately before gateway deploy.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
    echo 'CANNOT DETERMINE services: docker unavailable' >&2
    exit 1
fi
failed=0
attempt() {
    # TERM reaches the suite shell so its EXIT trap can remove its containers.
    timeout --signal=TERM --kill-after=30s 600s bash "$1"
}
while IFS='|' read -r name command; do
    [[ -n "$name" ]] || continue
    if attempt "$command"; then
        echo "PASS service: $name (attempt 1)"
        continue
    fi
    echo "RETRY service: $name after suite container teardown" >&2
    # Each suite has an EXIT trap that removes its uniquely named containers.
    if attempt "$command"; then
        echo "FLAKY service: $name (attempt 1 failed; attempt 2 passed)"
    else
        echo "FAIL service: $name (both attempts failed)" >&2
        failed=$((failed + 1))
    fi
done <<'SUITES'
postgres api key mint|scripts/ci/run-postgres-integration.sh
clickhouse dataset round trip|scripts/ci/run-clickhouse-integration.sh
ledger canonical store|scripts/ci/run-ledger-integration.sh
clickhouse grants|scripts/ci/check-clickhouse-users.sh
nats users|scripts/ci/check-nats-auth.sh
SUITES
exit "$((failed > 0))"
