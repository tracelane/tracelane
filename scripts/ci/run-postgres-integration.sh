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
# B-494: the floors on tests this runner must DISCOVER (selftest, `--list`) and EXECUTE
# (real run, summed `N passed`). Counted 2026-09-21 with `cargo test … -- --list
# --ignored`: postgres_tenant_integration lists 14 `#[ignore]` tests; the three --bin
# filters list 1 + 1 + 1. A lower reading is a suite that shrank, never a pass.
# SET-38 / B-586 (2026-09-27): +7 in postgres_tenant_integration (set38_* ×5,
# b586_* ×2 — edit in place, revoke through the gateway). Re-measured the same day
# with the real run rather than added to the old floors: that crate now lists 31
# (the db::* module tests compile into it too, which is why 14 was already below
# reality) and the whole runner executed 38.
# GWY-53 (2026-09-28): +1 discovered (db::workspace_capture's round trip compiles into
# that crate too) and +3 --bin filters below. Re-measured with the real run: that crate
# lists 32 and the whole runner executed 42.
# B-409 (2026-10-03): +7 executed — entitlement_cache::b409_tests (5), the metering
# job's and the retention sweep's b409_tests (1 each), each on its own fresh migrated
# database. 43 + 7.
# B-594/B-409 rev4 (2026-10-03): re-measured 34 discovered / 54 executed (see git log).
# OG-20 / OG-23 (2026-10-03): +4 in postgres_tenant_integration (og23_* x3, og20_* x1 —
# the auth JOIN, cross-tenant projects, assignment/archive/rotation, an unparseable
# stored policy). 34 + 4 discovered; executed floor raised by the same 4 below.
# OG-24 / OG-25 (2026-10-04): +3 in postgres_tenant_integration (og25_* x2 — revoke-all,
# the controls round trip; og24_* x1 — the outbox dedup). Measured with the real run:
# 41 discovered in that crate, 61 executed by the whole runner.
# OG-35 / OG-36 (2026-10-04): +5 executed — the `control_plane::pg_tests` filter (audited
# admin-access put + refusal, append-only trigger, tenant-scoped paging, CIDR CHECK, the
# route end to end), run and passed 5/5 on a fresh database. Discovered floor unchanged
# (they live in the --bin, not the integration crate).
# OG-51 / OG-50 (2026-10-05): +2 in postgres_tenant_integration (og51_* — cache settings,
# epochs, a key's narrowing; og50_* — exports sealed, isolated, audited). Both ran green
# on a fresh database (2 passed); 41 + 2 discovered, 66 + 2 executed.
EXPECTED_PG_TESTS=43
EXPECTED_PG_EXECUTED=68
case "${1:-}" in
  ""|--selftest) ;;
esac

CONTAINER=tlane-pg-integration-$$
STARTED_CONTAINER=0
cleanup() { [ "$STARTED_CONTAINER" = 1 ] && docker rm -fv "$CONTAINER" >/dev/null 2>&1; return 0; }
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
  #
  # ══ R121 (2026-08-24) — THE FALSIFICATION NO LONGER TOUCHES A TRACKED FILE. ══
  #
  # This used to `cp` the real `crates/gateway/src/db/api_keys.rs` to a temp path,
  # REWRITE IT IN PLACE, run the suite, and restore on a trap. The mutation is the
  # `$9::numeric` defect that returned 500 from `POST /v1/keys` for two days. The
  # old comment here called the residual "the honest ceiling" and rejected the
  # worktree fix on an ASSUMED cold-build cost.
  #
  # It bit on 2026-08-24. A `git commit` was killed at a 10-minute tool ceiling
  # while this ran, and `git status` showed `crates/gateway/src/db/api_keys.rs`
  # carrying `::numeric` — the live defect, sitting unstaged in the working tree.
  # Only staging-by-name kept it out of the commit; `git add -A` would have shipped
  # it. **A hazard whose mitigation is "remember not to use git add -A" is not
  # mitigated** (founder ruling R121).
  #
  # THE ASSUMED COST WAS WRONG, and it was measured rather than argued:
  #   · worktree, first build (cold, its OWN CARGO_TARGET_DIR) ... ~140 s, ONCE
  #   · worktree, every subsequent build (warm) ................... 0 s
  #   · the OLD in-place mutation's rebuild ....................... 78 s, EVERY RUN
  #   · the OLD restore's rebuild ................................. 10 s, EVERY RUN
  # So the worktree is a one-time 136 s and is then CHEAPER than what it replaces.
  # The path is stable precisely so it stays warm; deleting it costs 136 s once.
  #
  # SEMANTIC CHANGE, stated rather than buried: the falsification now runs against
  # **HEAD**, not the working tree. That is deliberate and it is an improvement —
  # this step's job is to prove THE RUNNER BITES, and that proof should not depend
  # on whatever the developer happens to have open. The real suite (below, no
  # --selftest) still runs against the working tree and is what tests their code.
  # ── STRIP THE HOOK ENVIRONMENT BEFORE ANY git CALL. ────────────────────────
  # `.githooks/pre-commit` runs verify-all.sh -> the meta-gate -> this `--selftest`.
  # Git exports GIT_DIR / GIT_INDEX_FILE to hooks, and GIT_INDEX_FILE is a RELATIVE
  # path (`.git/index`). A nested `git worktree add` inherits it, resolves it against
  # the NEW worktree, and dies:
  #     fatal: .git/index: index file open failed: Not a directory
  # leaving an EMPTY worktree. Run bare this selftest passed; run under the hook it
  # did not — the same unit-vs-environment gap that let the CARGO_TARGET_DIR
  # contamination through one revision earlier. It failed CLOSED (the `[ -f $TARGET ]`
  # check refused rather than passing hollow), which is the only reason it was cheap.
  git_clean() {
      env -u GIT_DIR -u GIT_INDEX_FILE -u GIT_WORK_TREE -u GIT_PREFIX \
          -u GIT_OBJECT_DIRECTORY -u GIT_ALTERNATE_OBJECT_DIRECTORIES \
          -u GIT_COMMON_DIR -u GIT_NAMESPACE git "$@"
  }
  REPO_ROOT="$(git_clean rev-parse --show-toplevel)"
  HEAD_SHA="$(git_clean -C "$REPO_ROOT" rev-parse HEAD)"
  WT="${TRACELANE_FALSIFY_WORKTREE:-$HOME/.cache/tracelane/falsify-postgres-integration}"
  # ── THE WORKTREE MUST NOT SHARE THE REPO'S CARGO_TARGET_DIR. ────────────────
  # The first cut of R121 pointed the worktree at `$REPO_ROOT/target` to keep the
  # build warm. That is WRONG and the gate caught it within one run: cargo derives
  # the same unit hash for the same package regardless of source path, so the
  # worktree's MUTATED gateway OVERWROTE the shared test binary
  # (`target/debug/deps/postgres_tenant_integration-<hash>`) — and the real suite,
  # whose own fingerprint still read "current", then RAN THE MUTATED BINARY and
  # failed with the exact defect being falsified:
  #     cannot convert between `Option<String>` and the Postgres type `numeric`
  # A falsification that contaminates the thing it is falsifying proves nothing and
  # breaks the real run. Its own target dir, persistent so it stays warm.
  WT_TARGET="${TRACELANE_FALSIFY_TARGET:-$HOME/.cache/tracelane/falsify-target}"
  case "$WT_TARGET" in
    "$REPO_ROOT"/target|"$REPO_ROOT"/target/*)
      echo "SELFTEST BROKEN: the falsify target dir must NOT be the repo's — that is the contamination this exists to prevent"
      exit 1 ;;
  esac
  mkdir -p "$WT_TARGET"
  mkdir -p "$(dirname "$WT")"
  if [ -e "$WT/.git" ]; then
    git_clean -C "$WT" reset --hard "$HEAD_SHA" >/dev/null 2>&1       && git_clean -C "$WT" clean -fdq >/dev/null 2>&1       || { git_clean -C "$REPO_ROOT" worktree remove --force "$WT" >/dev/null 2>&1
           rm -rf "$WT"
           git_clean -C "$REPO_ROOT" worktree prune >/dev/null 2>&1 || true
           git_clean -C "$REPO_ROOT" worktree add --detach "$WT" "$HEAD_SHA" >/dev/null; }
  else
    rm -rf "$WT"
    # PRUNE BEFORE ADD — a worktree whose DIRECTORY is gone stays REGISTERED, and the
    # add then dies with "missing but already registered worktree", leaving the next
    # line to report the far more alarming "SELFTEST BROKEN: … absent in the worktree".
    # That is a stale-registration problem wearing the costume of a broken guard, and it
    # cost two full gate cycles on 2026-08-25 before anyone read git's own suggestion.
    # `rm -rf "$WT"` above is exactly what CREATES that state, so the prune belongs here.
    git_clean -C "$REPO_ROOT" worktree prune >/dev/null 2>&1 || true
    git_clean -C "$REPO_ROOT" worktree add --detach "$WT" "$HEAD_SHA" >/dev/null
  fi
  TARGET="$WT/crates/gateway/src/db/api_keys.rs"
  [ -f "$TARGET" ] || { echo "SELFTEST BROKEN: $TARGET absent in the worktree"; exit 1; }
  # The real tree's file, fingerprinted BEFORE the mutation. The property asserted
  # below is "the falsification did not touch the developer's file", which is a
  # before/after comparison — NOT "the developer's file matches HEAD": that older
  # form refused whenever api_keys.rs carried an honest uncommitted edit (B-383 f,
  # 2026-09-12) and called the guard BROKEN when it was the tree that was busy.
  REAL_BEFORE="$(sha256sum "$REPO_ROOT/crates/gateway/src/db/api_keys.rs" | cut -d' ' -f1)"

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
  # THE PROPERTY THAT MAKES R121 REAL, asserted rather than assumed: the developer's
  # own tree is untouched by everything above. If this ever stops holding, the fix
  # has silently reverted to the thing it replaced.
  REAL_AFTER="$(sha256sum "$REPO_ROOT/crates/gateway/src/db/api_keys.rs" | cut -d' ' -f1)"
  if [ "$REAL_BEFORE" != "$REAL_AFTER" ]; then
    echo "SELFTEST BROKEN: the REAL tree's api_keys.rs CHANGED during the falsification — it must never be touched"
    exit 1
  fi
  # ── B-494 (2026-09-21): THE FALSIFICATION RUNS ONLY THE TEST THE PLANT BREAKS. ──
  # It used to re-run the whole runner in the worktree — four cargo invocations, every
  # test against a fresh DB + 47 migrations — minutes after the gate had run the same
  # suite green: 936 s, 56 % of an unnarrowed meta-gate, to learn one fact. The plant
  # is `$9::numeric` on the key INSERT; `create_tenant_and_lookup_by_api_key` mints a
  # key and is the test that goes RED. Running only it proves the same thing.
  #
  # What narrowing must NOT hide: a suite that silently SHRANK. So before the plant,
  # the real tree's binary is asked to LIST the suite (no execution, warm compile) and
  # the count is held to the floor below — a `#[ignore]` attribute typo, a deleted
  # test, a module no longer compiled in, all read as fewer discovered tests and go
  # RED here, while the real run (below, `run_and_count`) holds the EXECUTED count to
  # the same floor. Falsified 2026-09-21 by setting the floor to 999: RED with the
  # exact message; restored.
  # A list that FAILS (a compile error in the tree) is not "zero tests" — it is CANNOT
  # DETERMINE, said as such, so a red here is never misread as a shrunken suite.
  LIST_LOG="$(mktemp)"
  if ! cargo test -p gateway --test postgres_tenant_integration -- --list --ignored >"$LIST_LOG" 2>&1; then
    echo "SELFTEST CANNOT DETERMINE — \`cargo test --list\` failed before any test was discovered (a compile error in the tree?):" >&2
    grep -E '^error' "$LIST_LOG" | head -5 >&2
    rm -f "$LIST_LOG"
    exit 1
  fi
  DISCOVERED="$(grep -c ': test$' "$LIST_LOG" || true)"
  rm -f "$LIST_LOG"
  if [ "${DISCOVERED:-0}" -lt "$EXPECTED_PG_TESTS" ]; then
    echo "SELFTEST FAILED — postgres_tenant_integration discovers $DISCOVERED test(s), floor is $EXPECTED_PG_TESTS: the suite SHRANK (a narrowed falsification would hide that). Fix the suite or the floor, with the reason."
    exit 1
  fi
  echo "SELFTEST: postgres_tenant_integration discovers $DISCOVERED tests (floor $EXPECTED_PG_TESTS)."
  echo "SELFTEST: falsifying in an isolated worktree ($WT). The real tree is NOT touched."
  echo "SELFTEST: reverted the cast to the shipped defect (\$9::numeric). Expecting RED from the ONE test that mints a key."
  if ( cd "$WT" && CARGO_TARGET_DIR="$WT_TARGET" TRACELANE_RUNNER_ONLY="create_tenant_and_lookup_by_api_key" bash "$WT/scripts/ci/run-postgres-integration.sh" ) >/dev/null 2>&1; then
    echo "SELFTEST FAILED — the key-mint test passed with the defect reintroduced. This runner proves nothing."
    git_clean -C "$WT" reset --hard "$HEAD_SHA" >/dev/null 2>&1
    exit 1
  fi
  git_clean -C "$WT" reset --hard "$HEAD_SHA" >/dev/null 2>&1
  echo "SELFTEST PASSED — the key-mint test goes RED on the reintroduced defect, with the real tree untouched."
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

RC=0
# B-494: every cargo invocation goes through `run_and_count`, which adds its `N passed`
# to EXECUTED so the floor below can refuse a run that executed fewer tests than the
# suite holds — a runner silently skipping half its suite must go RED, not green.
EXECUTED=0
run_and_count() {
  local out
  out="$(cargo test "$@" 2>&1)"; local rc=$?
  # 2026-09-30: a panic's PAYLOAD (the assertion, left/right) is printed too — b378 went
  # red on 2026-09-30 with only its `panicked at` line visible, and the cause had to be
  # inferred from a line number.
  printf '%s\n' "$out" | awk -v pat='^test |test result' 'n>0{print;n--;next} /panicked/{print;n=6;next} $0~pat{print}' || true
  local n
  for n in $(printf '%s\n' "$out" | sed -n 's/^test result: [a-z]*\. \([0-9]*\) passed.*/\1/p'); do
    EXECUTED=$((EXECUTED + n))
  done
  return $rc
}
if [ -n "${TRACELANE_RUNNER_ONLY:-}" ]; then
  # The narrowed falsification (the --selftest above): ONE named test, nothing else,
  # and no floor — the caller expects RED from that test alone.
  run_and_count -p gateway --test postgres_tenant_integration -- --ignored "$TRACELANE_RUNNER_ONLY" || RC=1
  exit $RC
fi
run_and_count -p gateway --test postgres_tenant_integration -- --ignored || RC=1
# B-394 (BILL-01): the ceiling write binds an `Option<f64>` into `numeric(12,2)`.
# Only a real server can refuse that bind (`error serializing parameter 1`) — it
# answered 503 on every prod call, `null` included, with the full gate green.
run_and_count -p gateway --bin gateway billing::usage::tests::set_ceiling_sql -- --ignored || RC=1
# B-418 / verifier R1 (2026-09-15): the boot schema check's REFUSAL had only ever been
# falsified by hand. Against a real information_schema: complete → Ok(n), one dropped
# column → Missing([that column]), no tables → Unavailable.
run_and_count -p gateway --bin gateway entitlement_cache::boot_schema_check_tests::verify_schema_refuses -- --ignored || RC=1
# RI-04 proof 4 (2026-09-19): the alerts ok→breach CAS admits exactly one of two
# concurrent claimants — a property only a real server's row lock can show. (Proofs 2
# and 3 — the job claim and `run_claimed` — ride the postgres_tenant_integration run above.)
run_and_count -p gateway --bin gateway alerts::ri04_cas_tests -- --ignored || RC=1
# GWY-27 (2026-09-26): per-workspace model aliases against a REAL Postgres — the
# migration's CHECKs, create/exists/update, the cap enforced INSIDE the insert, the
# entitlement resolver's second query actually loading the map, delete, and the cascade.
run_and_count -p gateway --bin gateway db::model_aliases::tests::gwy27_model_aliases_round_trip -- --ignored || RC=1
run_and_count -p gateway --bin gateway entitlement_cache::tests::gwy27_attach_model_aliases -- --ignored || RC=1
# GWY-52: workspace failover — the DB round trip and the refresh step both ways.
run_and_count -p gateway --bin gateway db::workspace_failover::tests::gwy52_workspace_failover_round_trip -- --ignored || RC=1
run_and_count -p gateway --bin gateway entitlement_cache::tests::gwy52_attach_workspace_failover -- --ignored || RC=1
# GWY-53: workspace content capture — the table round trip (a refused ledger rolls the
# change back), the refresh through the FULL resolver (missing table → OFF + counted),
# and the PUT handler appending exactly one ledger event per change.
run_and_count -p gateway --bin gateway db::workspace_capture::tests::gwy53_workspace_capture_round_trip -- --ignored || RC=1
run_and_count -p gateway --bin gateway entitlement_cache::tests::gwy53_attach_content_capture -- --ignored || RC=1
run_and_count -p gateway --bin gateway workspace_capture_routes::tests::gwy53_put_records_the_change_on_the_ledger -- --ignored || RC=1
run_and_count -p gateway --bin gateway retention_sweep::tests::postgres_retention_tombstone_and_policy_roundtrip -- --ignored --test-threads=1 || RC=1
run_and_count -p gateway --bin gateway entitlement_cache::b409_tests -- --ignored || RC=1
run_and_count -p gateway --bin gateway billing::metering_job::b409_tests -- --ignored || RC=1
run_and_count -p gateway --bin gateway retention_sweep::b409_tests -- --ignored || RC=1
# OG-35/OG-36: the audited admin-access write + its refusal, the append-only trigger,
# tenant-scoped paging of the trail, the CIDR CHECK, and the route end to end.
run_and_count -p gateway --bin gateway control_plane::pg_tests -- --ignored || RC=1
if [ "$EXECUTED" -lt "$EXPECTED_PG_EXECUTED" ]; then
  echo "postgres integration: FAIL — executed $EXECUTED test(s), floor is $EXPECTED_PG_EXECUTED: the suite shrank or a filter matched nothing (B-494)"
  exit 1
fi
echo "postgres integration: executed $EXECUTED tests (floor $EXPECTED_PG_EXECUTED)"
exit $RC
