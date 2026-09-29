#!/usr/bin/env bash
# Run the gateway's REAL-CLICKHOUSE integration tests.
#
# WHY THIS EXISTS — founder ruling R97, 2026-08-23.
#
# `crates/gateway/src/dataset_routes.rs` carries 49 tests. Every one of them
# drives a MOCK STORE. So a clean gate, 49 green tests and a successful deploy
# shipped TWO wire-level defects to production in a single night, and both were
# found by a prod probe rather than by anything in CI:
#
#   B-272  the item projection aliases `toString(item_id) AS item_id`, and an
#          UNQUALIFIED `WHERE dataset_id = toUUID(?)` then compares the aliased
#          String against a UUID. ClickHouse answers Code 386. EVERY read 502'd.
#   B-273  `input_hash` declared `String` against a `FixedString(64)` column.
#          RowBinary emits a varint length prefix for a String and none for a
#          FixedString, the stream desynchronises, and the server reports the
#          byte-count mismatch on a LATER row (Code 33). EVERY write failed.
#
# A mock stores a String and hands it back. The BYTES ON THE WIRE are the entire
# subject and no mock inspects them (`docs/reference/TRAPS.md` §33: an
# all-fixture test has never run the thing it names). Item 9's experiment writes
# use the same row shapes against the same tables, so this runs BEFORE item 9.
#
# THE SHAPE IS `run-postgres-integration.sh`'s, deliberately and on instruction —
# honour an existing URL, otherwise start a throwaway container, poll a REAL
# query rather than a readiness proxy, and carry a `--selftest` that proves the
# runner goes RED when the defect is put back. No second harness was invented.
#
# IT ALSO RUNS `clickhouse_persister_integration.rs`, WHICH HAD ZERO CALLERS.
# Nothing in `scripts/` or `.github/` referenced it — the same CLASS-1 shape
# (`docs/reference/TRAPS.md` §1) that `run-postgres-integration.sh` was written
# to close for its own test. Free to fix while a container is up. Note its own
# header says it uses "raw SQL that mirrors the column shape the Rust persisters
# use", so it could NOT have caught B-273: a mirror of a struct is the thing that
# was wrong. That is why the new tests live IN-CRATE and drive the real
# `ClickHouseDatasetStore`.
#
# USAGE
#   scripts/ci/run-clickhouse-integration.sh
#   --selftest   prove this runner FAILS when B-272 is reintroduced.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# ARGV IS AN ALLOWLIST — a script that accepts ANY flag makes its own
# `--selftest` meaningless, because "the selftest ran and passed" becomes
# indistinguishable from "the flag was ignored and a normal run passed". The
# meta-gate caught exactly this on the postgres runner's first day.
case "${1:-}" in
  ""|--selftest) ;;
  *) echo "usage: $(basename "$0") [--selftest]  (unknown argument: $1)" >&2; exit 2 ;;
esac

CONTAINER=tlane-ch-integration-$$
STARTED_CONTAINER=0
cleanup() { [ "$STARTED_CONTAINER" = 1 ] && docker rm -fv "$CONTAINER" >/dev/null 2>&1; return 0; }
trap cleanup EXIT

# Return codes: 1 = no usable docker on this box (a SKIP, exit 0 below, as before);
# 2 = docker is here but ClickHouse did NOT come up (a LOUD failure, exit 3 below).
# 2026-09-06 (block 6): five `tlane-ch-integration-*` containers sat in state
# `created` — host port 18123 was still held, `docker run` failed with "driver failed
# programming external connectivity", this function returned 1, the caller printed
# SKIP and exited 0, and the meta-gate's selftest read that 0 as "the suite PASSED
# with B-272 reintroduced". Two full gates went red for a cause the output never
# named. A start failure with docker PRESENT is not a skip.
start_throwaway_clickhouse() {
  command -v docker >/dev/null 2>&1 || return 1
  docker info >/dev/null 2>&1 || return 1
  local port=18123
  # Stale throwaways from a run that died mid-window hold the port; they are ours.
  docker ps -a --filter 'name=tlane-ch-integration-' --format '{{.Names}}' 2>/dev/null \
    | xargs -r docker rm -fv >/dev/null 2>&1 || true
  # 24.12 is the version the migration-18 type traps were verified against
  # (`Nullable(LowCardinality(String))` is illegal there, and the DateTime64
  # millis-vs-micros behaviour was MEASURED on 24.12.6.70). Pinning it means this
  # runner tests the server prod actually runs, not whatever `latest` became.
  if ! docker run -d --name "$CONTAINER" \
    -e CLICKHOUSE_SKIP_USER_SETUP=1 \
    -p "${port}:8123" clickhouse/clickhouse-server:24.12-alpine >/dev/null 2>&1; then
    docker rm -fv "$CONTAINER" >/dev/null 2>&1 || true   # `run` creates before it fails to start
    echo "ERROR: docker is present but the throwaway ClickHouse did not START — host port ${port} held? (ss -ltnp | grep ${port})" >&2
    return 2
  fi
  STARTED_CONTAINER=1
  # POLL A REAL QUERY, not `/ping`. The postgres runner learned the same lesson
  # the expensive way: an entrypoint that reports ready mid-initialisation
  # produced a run where every test failed in 0.00s against a live-looking
  # container. `/ping` answers before the HTTP query interface will serve DDL.
  local i
  for i in $(seq 1 90); do
    if curl -fsS -m 3 "http://127.0.0.1:${port}/" --data-binary "SELECT 1" >/dev/null 2>&1; then
      CLICKHOUSE_TEST_URL="http://127.0.0.1:${port}"
      export CLICKHOUSE_TEST_URL
      return 0
    fi
    sleep 1
  done
  echo "ERROR: the throwaway ClickHouse started but never answered SELECT 1 within 90 s (docker logs $CONTAINER)." >&2
  return 2
}

if [ "${1:-}" = "--selftest" ]; then
  # PROVE THE RUNNER BITES. Reintroduce B-272 — one line, still compiles — and
  # require a RED. A guard never observed failing is not a guard (§1).
  #
  # WHY B-272 AND NOT B-273 HERE. B-273's shape needs three coordinated edits
  # (the struct field type plus both write sites) to stay compiling, and a
  # three-point mutation that silently fails to apply is a selftest that passes
  # by doing nothing. B-273 was falsified BY HAND when these tests were written —
  # the three sites were reverted, the round-trip test went RED on the insert,
  # and the sites were restored — and it is the round-trip test's `expect()` on
  # `insert_items` that carries it from here. That split is stated rather than
  # implied: this selftest protects the READ half continuously and the WRITE half
  # was proven once.
  TARGET=crates/gateway/src/dataset_routes.rs
  BACKUP="$(mktemp)"; cp "$TARGET" "$BACKUP"
  restore() { cp "$BACKUP" "$TARGET"; rm -f "$BACKUP"; cleanup; }
  # SIGNALS, not just EXIT — this rewrites a TRACKED source in place. A bare
  # `trap … EXIT` does not survive a timeout kill or an OOM (which has killed a
  # session on this machine), and the worktree would be left carrying the
  # known-broken query with the backup orphaned under a random /tmp name.
  # ponytail: SIGKILL during the mutated window still leaves TARGET modified;
  # recovery is `cp` from the printed BACKUP path, and `git diff` shows it.
  trap restore EXIT INT TERM HUP
  echo "SELFTEST: $TARGET is mutated for the next step; pristine copy at $BACKUP"
  # Both strings run PAST the closing quote so the plant can carry the `SELFTEST PLANT`
  # marker as a trailing Rust comment (it cannot sit inside the SQL string literal) —
  # `check-no-stranded-selftest-plant.sh` refuses that marker at commit time, 2026-09-20.
  OLD='WHERE tenant_id = ? AND datasets.dataset_id = toUUID(?) AND deleted = 0",'
  NEW='WHERE tenant_id = ? AND dataset_id = toUUID(?) AND deleted = 0", // SELFTEST PLANT (B-272 shape)'
  # B-285 (2026-08-25): DISTINGUISH "not there yet" FROM "left mutated by a dead run".
  #
  # `trap … EXIT INT TERM HUP` does not survive SIGKILL, and the meta-gate probes this
  # selftest with a TIMEOUT — so a slow box kills it mid-window and the TRACKED source
  # keeps the broken query. Measured on 2026-08-25: the probe timed out at 300s, the
  # file stayed unqualified, and the NEXT step (`dataset round trip (real ClickHouse)`)
  # then failed for a reason that had nothing to do with it. One dead selftest, two red
  # steps, and a wrong-cause diagnosis — I read the mutated line as the EXPORT rewriting
  # shipped code and nearly filed that the export reintroduces B-272. It does not.
  #
  # So the already-mutated state now SELF-HEALS and says so, instead of reporting the
  # same "BROKEN" message as a genuinely missing anchor. Those are different facts and
  # collapsing them is what cost the diagnosis.
  if ! grep -qF "$OLD" "$TARGET"; then
    if grep -qF "$NEW" "$TARGET"; then
      echo "SELFTEST: $TARGET was left MUTATED by an earlier run that died mid-window" >&2
      echo "SELFTEST: restoring the qualified WHERE and continuing (B-285)." >&2
      python3 - "$TARGET" "$NEW" "$OLD" <<'PYFIX'
import sys
p, bad, good = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
open(p, "w").write(s.replace(bad, good, 1))
PYFIX
      cp "$TARGET" "$BACKUP"
    else
      echo "SELFTEST BROKEN: the qualified WHERE was not found verbatim — the mutation would be a no-op"
      exit 1
    fi
  fi
  python3 - "$TARGET" "$OLD" "$NEW" <<'PY'
import sys
p, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
assert old in s, "mutation target absent"
open(p, "w").write(s.replace(old, new, 1))
PY
  echo "SELFTEST: unqualified the dataset_id WHERE (B-272's exact shape). Expecting RED."
  # B-494 (2026-09-21): the falsification runs ONLY the test the plant breaks — the
  # dataset round-trip — not the whole 15-invocation suite the gate just ran green
  # (~200 s to learn one fact). The real run below holds its EXECUTED count to a floor,
  # so a suite that shrank cannot hide behind this narrowing; the selftest holds the
  # DISCOVERED count of the round-trip family to a floor the same way.
  # A list that FAILS (a compile error in the tree) is not "zero tests" — it is CANNOT
  # DETERMINE, said as such, so a red here is never misread as a shrunken suite.
  LIST_LOG="$(mktemp)"
  if ! cargo test -p gateway --bin gateway clickhouse_roundtrip -- --list --ignored >"$LIST_LOG" 2>&1; then
    echo "SELFTEST CANNOT DETERMINE — \`cargo test --list\` failed before any test was discovered (a compile error in the tree?):" >&2
    grep -E '^error' "$LIST_LOG" | head -5 >&2
    rm -f "$LIST_LOG"
    exit 1
  fi
  DISCOVERED="$(grep -c ': test$' "$LIST_LOG" || true)"
  rm -f "$LIST_LOG"
  # Re-measured 2026-09-27 (OBS-55): `cargo test -p gateway --bin gateway
  # clickhouse_roundtrip -- --list --ignored` discovers 21 tests, not the 16
  # this line held — it was already stale before this change (independently
  # of the one test OBS-55 adds), the same "these numbers rot" class
  # `.claude/rules/testing.md` documents for the Rust test counts. Set to the
  # measured value rather than merely +1, per CLAUDE.md §1 (a floor set below
  # reality is worse than none).
  EXPECTED_CH_ROUNDTRIP_TESTS=23  # 21 (OBS-55 re-measure) + B-568 C3 latency split + OBS-56 S4 batch resolution, 2026-09-28
  if [ "${DISCOVERED:-0}" -lt "$EXPECTED_CH_ROUNDTRIP_TESTS" ]; then
    echo "SELFTEST FAILED — discovered ${DISCOVERED:-0} clickhouse_roundtrip test(s), floor is $EXPECTED_CH_ROUNDTRIP_TESTS: the narrowed falsification would run fewer tests than the family holds (B-494)." >&2
    exit 1
  fi
  TRACELANE_RUNNER_ONLY=clickhouse_roundtrip bash "$0" >/dev/null 2>&1; _rc=$?
  if [ "$_rc" -eq 3 ]; then
    echo "SELFTEST CANNOT DETERMINE — ClickHouse did not come up, so the mutated suite never ran (runner exit 3). Fix docker / host port 18123 first; this is NOT a passing selftest." >&2
    exit 1
  fi
  if [ "$_rc" -eq 0 ]; then
    echo "SELFTEST FAILED — the suite passed with B-272 reintroduced. This runner proves nothing."
    exit 1
  fi
  echo "SELFTEST PASSED — the suite goes RED on the reintroduced alias shadowing."
  exit 0
fi

if [ -z "${CLICKHOUSE_TEST_URL:-}" ]; then
  start_throwaway_clickhouse; _st=$?
  if [ "$_st" -eq 1 ]; then
    echo "SKIP: no CLICKHOUSE_TEST_URL and no usable docker — this guard CANNOT RUN here."
    echo "      That is a real gap, not a pass."
    exit 0
  elif [ "$_st" -ne 0 ]; then
    echo "CANNOT DETERMINE: docker is present but ClickHouse did not come up — the round-trip suite did NOT run. Exit 3, never 0." >&2
    exit 3
  fi
fi

RC=0
# B-494: every cargo invocation goes through `run_and_count`, which adds its `N passed`
# to EXECUTED; the floor at the end refuses a run that executed fewer tests than the
# suite holds — a filter that matches nothing is a green that tested nothing.
# `TRACELANE_RUNNER_ONLY` is the --selftest's narrowed falsification (one filter, no floor).
EXECUTED=0
run_and_count() {
  local out rc n
  out="$(cargo test "$@" 2>&1)"; rc=$?
  printf '%s\n' "$out" | grep -E '^test |panicked|^test result|^error' || true
  for n in $(printf '%s\n' "$out" | sed -n 's/^test result: [a-z]*\. \([0-9]*\) passed.*/\1/p'); do
    EXECUTED=$((EXECUTED + n))
  done
  return $rc
}
if [ -n "${TRACELANE_RUNNER_ONLY:-}" ]; then
  run_and_count -p gateway --bin gateway "$TRACELANE_RUNNER_ONLY" -- --ignored || RC=1
  exit $RC
fi
# The in-crate round trip: the REAL ClickHouseDatasetStore, the REAL ItemWriteRow.
# The SAME filter reaches `trace_reads::clickhouse_roundtrip` — the reader-level
# tests (the DSH-11 SQL acceptance, the B-379 merge/window, the `until` binds) and,
# since 2026-09-21, B-500's `sub_hour_summary_counts_the_same_spans_as_the_sub_hour_rows`:
# three LLM spans across an hour boundary, one sub-hour window, and the headline
# (`/v1/slo/summary`), the table (`/v1/slo/models`) and the chart (`/v1/slo`) must
# answer the SAME count. Only a server can show it — the string test proves the SQL's
# shape, this proves what it COUNTS through the real reader and the real MV. Until
# the fix the summary/models read `slo_hourly_stats` by `bucket_hour` while the rows
# read `spans FINAL` by `start_time`, and answered 1 against 2 here.
# Confirm the reach after any module rename: `cargo test -p gateway --bin gateway
# clickhouse_roundtrip -- --ignored --list | grep sub_hour_summary`.
run_and_count -p gateway --bin gateway clickhouse_roundtrip -- --ignored --nocapture || RC=1
# B-383 (c) / B-387: the retention sweep's enforce DELETE against every content
# table on the checked-in schema — the projection-vs-lightweight-delete refusal
# (Code 344) is only visible to a server.
run_and_count -p gateway --bin gateway retention_sweep::tests::enforce_delete_is_accepted -- --ignored || RC=1
# RI-02 rule 5 (2026-09-20): the orphan-tenant step deletes a purged tenant's rows from every
# content table and spares a bystander; an EMPTY live list is refused. Behaviour, not SQL text.
run_and_count -p gateway --bin gateway retention_sweep::tests::ri02_orphan_step -- --ignored || RC=1
# B-393 (BILL-01): blob rehydration against a real server. The lookup compares
# `hex(hash)` (UPPERCASE on the server) to a bound string — a case mismatch
# matches zero rows and is invisible to every unit test, because the miss is
# the SQL's semantics, not the Rust's. This test existed and was `#[ignore]`d
# but nothing ran it; prod found the defect first.
run_and_count -p gateway --bin gateway billing::blobs::tests::rehydrate_against_a_real_clickhouse -- --ignored || RC=1
# B-424 / B-425 (BILL-01, found on prod 2026-09-16): every read the metering job
# makes, and the two period reads the usage page renders from, against a real
# server. A SELECT alias shadowing a same-named column (`toString(day) AS day
# … WHERE day >= …`) is NO_COMMON_TYPE on the server and nothing else; a
# UInt64 aggregate decoded into an f64 field is a denormal on the server and
# nothing else. Both failed on every run since BILL-01 deployed and no unit
# test could see either.
run_and_count -p gateway --bin gateway billing::metering_job::tests::meter_reads_run_against_a_real_clickhouse -- --ignored || RC=1
# B-445: the blob GC leaves referenced and young blobs; only old unreferenced ones go.
run_and_count -p gateway --bin gateway billing::metering_job::tests::gc_leaves_referenced_and_young_blobs_against_a_real_clickhouse -- --ignored || RC=1
run_and_count -p gateway --bin gateway billing::usage::tests::period_reads_run_against_a_real_clickhouse -- --ignored || RC=1
# REV-1 (the Codex independent review's billing trio, 2026-09-20) — three money
# defects the job's own log could never show, each proven on the real server:
#   B-468  idle days billed at the last active day's value (the trailing series
#          discarded its dates) — the backfill over a busy→idle→busy week must emit
#          for the two busy periods ONLY, read back from a recording Polar.
#   B-470  the completion marker landed BEFORE the Polar POST — a refused POST must
#          leave the day UNMARKED, the next run re-emits it under the same external
#          ids and only then marks it.
#   B-469  a batch retried after a lost response counted twice — the same immutable
#          batch + `insert_deduplication_token` sums ONCE on the real table (migration
#          28) and TWICE on a clone without the window: the setting is the control.
run_and_count -p gateway --bin gateway billing::metering_job::tests::rev1_idle_days_are_not_billed_against_a_real_clickhouse -- --ignored || RC=1
run_and_count -p gateway --bin gateway billing::metering_job::tests::rev1_a_failed_emission_withholds_the_marker_and_the_day_is_retried -- --ignored || RC=1
run_and_count -p gateway --bin gateway billing::metering_job::tests::rev1_a_kill_mid_emission_retries_the_day_under_the_same_external_ids -- --ignored || RC=1
run_and_count -p gateway --bin gateway billing::meters::tests::rev1_a_retried_batch_with_the_same_token_is_counted_once -- --ignored || RC=1
# The previously-uncalled migration-03 parity test. Mirrors column shapes rather
# than driving the persisters, so it is a weaker check — run for coverage, not
# for confidence.
run_and_count -p gateway --test clickhouse_persister_integration -- --ignored || RC=1
# RI-06 / B-449: the capture_gaps row (ingest) against the real schema — DateTime64(6)
# as i64 micros, three UInt64s. The B-292 class: green in cargo test, red on the server.
run_and_count -p ingest --bin ingest capture_gaps::tests::row_round_trips_against_a_real_clickhouse -- --ignored || RC=1
# B-445: a failed blobs insert PROPAGATES (the batch stays unacked) instead of warning past it.
run_and_count -p ingest --bin ingest clickhouse_writer::tests::flush_blobs_propagates_a_failed_insert_against_a_real_clickhouse -- --ignored || RC=1
# B-524 (CX-25, 2026-09-22): tool analytics `total_calls` is the window's TRUE total — a
# window function evaluated BEFORE the per-tool LIMIT — and `truncated` says when the list
# was cut; the plant (Σ over the capped Vec) read 59 for 60 on a real server.
run_and_count -p gateway --bin gateway tool_analytics::tests::the_total_survives_the_limit_and_says_when_it_did -- --ignored || RC=1
# B-493 (2026-09-21): a span batch retried under the same insert_deduplication_token — the
# "committed behind a client timeout, then retried" path — lands once and fires the mv_* views
# ONCE (migration 29's window on `spans`); a clone without the window takes it twice.
run_and_count -p ingest --bin ingest clickhouse_writer::tests::b493_a_retried_span_batch_fires_the_views_once_against_a_real_clickhouse -- --ignored || RC=1
# B-542 (2026-09-23): the promotion gate binds evidence to the CANDIDATE, not just
# (tenant, run) — a run that passed for version A must not promote version B. This is the
# ONLY test that proves it against a real ClickHouse and the real schema, and it shipped
# `#[ignore]`d with no runner entry, so it would have executed NEVER. That is the
# B-292/B-274 class precisely: the serde attr on `prompt_version_id` is what makes the
# projected column decode at all, and a regression there is invisible to `cargo test` and
# to every StaticEvalGate test in the suite.
run_and_count -p gateway --bin gateway prompt_router::tests::evidence_binding_real_clickhouse -- --ignored || RC=1
# B-494: the executed floor — the sum of `N passed` over every invocation above, counted
# on a green run 2026-09-21. A run that executes fewer is RED even if every test it ran passed.
# +1 (2026-09-27, OBS-55): `session_transcript_totals_and_turns_against_a_real_clickhouse`
# joined the `clickhouse_roundtrip -- --ignored --nocapture` line above and was run and
# proven green against a real ClickHouse (24.12-alpine) before this floor moved — every
# other line's contribution is unchanged by this session.
# 34 → 35 (2026-09-27, B-568 C3): `trace_reads::clickhouse_roundtrip::
# b568_latency_split_counts_the_right_populations_on_a_real_clickhouse` rides the
# `clickhouse_roundtrip` filter above — what the dispatched / hit / warm / cold split
# COUNTS on a real server, tenant isolation and the zero-sample decode included.
# +1 OBS-56 S4 `batch_span_resolution_and_dedupe_against_a_real_clickhouse`.
# All three merged 2026-09-28: 34 + OBS-55 + B-568 + OBS-56 S4 = 37.
EXPECTED_CH_EXECUTED=40  # measured 2026-09-28 full gate: "executed 40 tests"
if [ "$EXECUTED" -lt "$EXPECTED_CH_EXECUTED" ]; then
  echo "clickhouse integration: FAIL — executed $EXECUTED test(s), floor is $EXPECTED_CH_EXECUTED: the suite shrank or a filter matched nothing (B-494)"
  exit 1
fi
echo "clickhouse integration: executed $EXECUTED tests (floor $EXPECTED_CH_EXECUTED)"
exit $RC
