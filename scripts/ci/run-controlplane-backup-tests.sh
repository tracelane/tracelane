#!/usr/bin/env bash
# run-controlplane-backup-tests.sh — SRE-33: run scripts/ops/tests/test_controlplane_backup.py
# against a REAL throwaway Postgres on the CI VM, with REQUIRE set so nothing can skip.
#
# WHY A SCRIPT (PR #275 review M4): the CI VM has docker and a Postgres 16 CLIENT
# (infra/ci/tl-ci-1-bootstrap.sh:11) but no server and no `age`. Nothing here depends on what
# the VM has installed:
#   * server: postgres:16-alpine, no published port, data on tmpfs, removed on exit (default
#             bridge, not `--network none`: the test container shares its namespace and needs
#             the Debian archive; a throwaway test DB with a dummy password, on the CI VM only);
#   * tests:  postgres:16-bookworm (pg_dump/pg_restore 16 = the server major) + age and python3
#             from the Debian archive, joined to the server's network namespace.
# Exit: the tests' exit code; 1 if the server never became ready.
set -euo pipefail

ROOT=$(git rev-parse --show-toplevel)
NAME="tl-cp-tests-$$-${RANDOM}"
cleanup() { docker rm -fv "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$NAME" --tmpfs /var/lib/postgresql/data \
  -e POSTGRES_USER=tracelane -e POSTGRES_PASSWORD=tracelane_dev -e POSTGRES_DB=tracelane \
  postgres:16-alpine >/dev/null

docker run --rm --network "container:$NAME" -v "$ROOT:/src:ro" -w /src \
  -e POSTGRES_TEST_URL=postgres://tracelane:tracelane_dev@127.0.0.1:5432/tracelane \
  -e TLANE_REQUIRE_PG_TESTS=1 \
  postgres:16-bookworm bash -c '
    set -euo pipefail
    apt-get update -qq >/dev/null && apt-get install -y -qq age python3 >/dev/null
    for _ in $(seq 1 60); do pg_isready -q -h 127.0.0.1 -U tracelane && break; sleep 1; done
    pg_isready -q -h 127.0.0.1 -U tracelane || { echo "throwaway Postgres never became ready" >&2; exit 1; }
    python3 scripts/ops/tests/test_controlplane_backup.py -v
  '
