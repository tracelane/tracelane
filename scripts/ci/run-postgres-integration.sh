#!/usr/bin/env bash
# Run the gateway's REAL-POSTGRES integration tests.
#
# WHY THIS EXISTS. `crates/gateway/tests/postgres_tenant_integration.rs` is the
# only test that exercises `db::api_keys::create()` against a real Postgres. It
# was `#[ignore]`d, gated on `POSTGRES_TEST_URL`, and referenced by NEITHER
# `.github/workflows/ci.yml` NOR `verify-all.sh` — zero callers. That is
# `docs/reference/TRAPS.md` §1 CLASS-1: a control that never ran.
#
# It would have gone red on the first execution. A13 (`5ab66bd0`, 2026-08-12)
# bound `budget_usd_monthly` as `$9::numeric` while passing an `Option<String>`;
# tokio-postgres refuses that conversion on EVERY call, including when the value
# is None, so `POST /v1/keys` returned 500 for two days and no customer could
# create an API key. Four independent probes were needed to recover a cause this
# test prints in one line.
#
# Running it for the first time also surfaced two further reasons it could never
# have passed, both now fixed:
#   * `db::apply_migrations` applied 0000-0006 then jumped to 0011, skipping the
#     migration that adds `tenants.archived_at`;
#   * every test called `test_pool()`, and the helper's own doc says re-migrating
#     a populated database fails — so the second test always died on
#     `type "cmk_algorithm" already exists`. Each test now gets a fresh database.
#
# USAGE
#   scripts/ci/run-postgres-integration.sh
#     - honours an existing $POSTGRES_TEST_URL (CI service container), or
#     - starts a throwaway docker postgres and removes it on exit.
#   --selftest   prove this runner FAILS when the defect is reintroduced.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# PARSE ARGV, and REFUSE anything unrecognised. Caught by
# `scripts/ci/check-guard-selftests.py` on this very script's first run: it
# exited 0 for `--tracelane-meta-gate-nonsense-flag`, because the original code
# only tested `$1 = --selftest` and let everything else fall through to a normal
# run. A script that accepts ANY flag makes its own `--selftest` pass
# meaningless — you cannot tell "the selftest ran and passed" from "the flag was
# ignored and a normal run passed". The meta-gate exists for exactly this and it
# bit the guard being added to it.
case "${1:-}" in
  ""|--selftest) ;;
  *) echo "usage: $(basename "$0") [--selftest]  (unknown argument: $1)" >&2; exit 2 ;;
esac

CONTAINER=tlane-pg-integration-$$
STARTED_CONTAINER=0
cleanup() { [ "$STARTED_CONTAINER" = 1 ] && docker rm -f "$CONTAINER" >/dev/null 2>&1; return 0; }
trap cleanup EXIT

start_throwaway_postgres() {
  command -v docker >/dev/null 2>&1 || return 1
  docker info >/dev/null 2>&1 || return 1
  local port=15466
  docker run -d --name "$CONTAINER" \
    -e POSTGRES_PASSWORD=tracelane_dev -e POSTGRES_USER=tracelane -e POSTGRES_DB=tracelane \
    -p "${port}:5432" postgres:16-alpine >/dev/null 2>&1 || return 1
  STARTED_CONTAINER=1
  # Poll a REAL connection, not `pg_isready` — the entrypoint reports ready
  # mid-initialisation and then restarts the server, so pg_isready alone
  # produced a run where all four tests failed in 0.00s against a live-looking
  # container. Observed 2026-08-14; the false-ready is the trap.
  local i
  for i in $(seq 1 90); do
    if docker exec "$CONTAINER" psql -U tracelane -d tracelane -tAc "SELECT 1" >/dev/null 2>&1; then
      POSTGRES_TEST_URL="postgres://tracelane:tracelane_dev@127.0.0.1:${port}/tracelane"
      export POSTGRES_TEST_URL
      return 0
    fi
    sleep 1
  done
  return 1
}

if [ "${1:-}" = "--selftest" ]; then
  # Prove the runner BITES: reintroduce the exact shipped defect and require a
  # RED. A guard that has never been observed failing is not a guard (§1).
  TARGET=crates/gateway/src/db/api_keys.rs
  BACKUP="$(mktemp)"; cp "$TARGET" "$BACKUP"
  restore() { cp "$BACKUP" "$TARGET"; rm -f "$BACKUP"; cleanup; }
  # SIGNALS, not just EXIT. This selftest rewrites a TRACKED gateway source in place —
  # reintroducing the `$9::numeric` defect that returned 500 from POST /v1/keys for two
  # days — and it is invoked by the meta-gate on every pre-push, wrapped in a 300s
  # timeout. `subprocess.run(timeout=)` kills a slow probe, and a bare `trap … EXIT`
  # does not survive that, nor an OOM (which has killed a session on this machine).
  # The worktree would be left carrying the known-broken constant with the backup
  # orphaned under a random /tmp name nobody knows to look for.
  #
  # So: trap the catchable signals, and PRINT the backup path up front so a SIGKILL —
  # the one case no trap can cover — still leaves a recoverable, discoverable state
  # rather than a silent one. That residual is the honest ceiling here; running the
  # whole selftest in a throwaway git worktree would close it, at the price of a cold
  # cargo build every pre-push.
  # ponytail: SIGKILL/OOM during the ~90s mutated window still leaves TARGET modified.
  # Recovery is `cp` from the printed BACKUP path, and `git diff` shows it immediately.
  trap restore EXIT INT TERM HUP
  echo "SELFTEST: $TARGET is mutated for the next step; pristine copy at $BACKUP"
  OLD='const BUDGET_NUMERIC_CAST: &str = "::text::numeric";'
  NEW='const BUDGET_NUMERIC_CAST: &str = "::numeric";'
  grep -qF "$OLD" "$TARGET" || { echo "SELFTEST BROKEN: cast const not found verbatim — the mutation would be a no-op"; exit 1; }
  # `assert old in s` before editing: a falsification that silently changes
  # nothing passes, and the pass is then read as proof (§19).
  python3 - "$TARGET" "$OLD" "$NEW" <<'PY'
import sys
p,old,new=sys.argv[1],sys.argv[2],sys.argv[3]
s=open(p).read(); assert old in s, "mutation target absent"
open(p,"w").write(s.replace(old,new,1))
PY
  echo "SELFTEST: reverted the cast to the shipped defect (\$9::numeric). Expecting RED."
  if bash "$0" >/dev/null 2>&1; then
    echo "SELFTEST FAILED — the suite passed with the defect reintroduced. This runner proves nothing."
    exit 1
  fi
  echo "SELFTEST PASSED — the suite goes RED on the reintroduced defect."
  exit 0
fi

if [ -z "${POSTGRES_TEST_URL:-}" ]; then
  if ! start_throwaway_postgres; then
    echo "SKIP: no POSTGRES_TEST_URL and no usable docker — this guard CANNOT RUN here."
    echo "      That is a real gap, not a pass. CI runs it with a postgres service."
    exit 0
  fi
fi

# `enum_param_serialization_contract` reaches Postgres through `build_pool()`,
# i.e. POSTGRES_URL, and needs a MIGRATED database (it asserts on the `plan`
# enum). The other tests create their own fresh databases. Migrate the base DB
# so all four run — without this the enum test passes only on leftover state
# from an earlier run, which is how it looked green locally and would have
# failed on a clean CI service.
# NEVER INHERIT POSTGRES_URL. This used to be `${POSTGRES_URL:-$POSTGRES_TEST_URL}`,
# which KEEPS an already-exported value — and `POSTGRES_URL` is the gateway's own
# control-plane variable, exactly what a deploy or a hand-applied Neon migration session
# has in its shell. The loop below then applies EVERY file in apps/web/db/migrations to
# it, output discarded, failures swallowed by `|| true`, and it tries this URL FIRST,
# falling back to the throwaway container only when it fails.
#
# `verify-all.sh` invokes this script whenever docker is available, and the pre-push
# hook invokes verify-all — so the inherited-variable path made a git push able to apply
# un-journaled DDL to the production control plane (CLAUDE.md §5). Nobody would have
# seen it: no output, no error, no row in any log.
#
# The throwaway container this script started is the ONLY correct target, so it is the
# only one used. Found 2026-08-16 while scoping the gate; never observed firing.
export POSTGRES_URL="$POSTGRES_TEST_URL"
for f in apps/web/db/migrations/*.sql; do
  psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 -q -f "$f" >/dev/null 2>&1 \
    || docker exec -i "$CONTAINER" psql -U tracelane -d tracelane -v ON_ERROR_STOP=1 -q < "$f" >/dev/null 2>&1 \
    || true   # base-DB migration is best-effort; the fresh-DB tests do their own
done

cargo test -p gateway --test postgres_tenant_integration -- --ignored
exit $?
