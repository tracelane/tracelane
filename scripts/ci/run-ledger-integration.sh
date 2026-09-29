#!/usr/bin/env bash
# run-ledger-integration.sh — ADR-078 (ruled B, 2026-09-20): the tamper-evident
# ledger's Tier-A proofs against BOTH real stores at once.
#
# WHY A THIRD RUNNER. The Postgres runner sets POSTGRES_TEST_URL; the ClickHouse runner
# sets CLICKHOUSE_TEST_URL; the ledger's dual-store tests (`adr078_*`, and the two
# `r21_*` age-sweep tests before them) self-skip unless BOTH are set — so until this
# file existed they had never executed in any gate (the founder's question B,
# 2026-09-20: a check whose pass path has never produced a non-empty result). This
# runner starts a throwaway Postgres AND a throwaway ClickHouse, applies every
# migration to the Postgres, and runs exactly those tests with both URLs exported.
#
# What it proves (the ADR's "Tier A proof as the ADR specifies"):
#   - a copy failure between the Postgres COMMIT and the ClickHouse copy leaves the
#     chain GREEN in the canonical store, counts `LedgerCopyFailed`, serves the export
#     from Postgres with ClickHouse dead, and the boot reconcile catches the copy up;
#   - the same copy failure leaves the per-trace chain-status READ (the dashboard's
#     "in tamper-evident ledger" chip) chained:true too, because it now reads the
#     canonical store instead of the copy the failure hit (B-513 / CX-14);
#   - the head-ahead-of-rows case is filled from a copy that chains, else left RED
#     (`LedgerHeadAheadOfRows`) with the head untouched and no gap row;
#   - a copy ahead of a restored head (open question 7) is adopted only while it chains.
#
# Exit codes: 0 pass · 1 a test failed · 3 docker present but a store did not come up
# (a LOUD failure, never a skip). Docker absent → SKIP (exit 0) with the gap stated.
#
# --selftest proves the runner BITES: it reintroduces the pre-B write (the copy written
# INSIDE the transaction instead of the canonical insert) by making the canonical insert
# a no-op, and requires `adr078_a_copy_failure…` to go RED.
set -euo pipefail
cd "$(dirname "$0")/../.."

case "${1:-}" in
  ""|--selftest) ;;
  *) echo "usage: $(basename "$0") [--selftest]  (unknown argument: $1)" >&2; exit 2 ;;
esac

# THE PLANT, defined once so heal and plant cannot drift. `--selftest` writes PLANT_TEXT
# over PLANT_ORIGINAL; a run that dies before its trap leaves the plant in tracked source,
# so EVERY run heals it first (B-285's class — earned again 2026-09-20 by a laptop reboot
# mid-selftest; `check-no-stranded-selftest-plant.sh` refuses the marker at commit time).
PLANT_TARGET=crates/gateway/src/db/audit_chain_state.rs
PLANT_ORIGINAL='    super::ledger::insert_rows_tx(&tx, &rows)
        .await
        .context("canonical audit_log_rows write")?;'
PLANT_TEXT='    // SELFTEST PLANT: the canonical write is skipped (pre-B shape: rows only in the copy).
    let _ = (&tx, &rows);'
swap_text() { # swap_text <file> <from> <to> — exactly one occurrence, or fail loudly
  python3 - "$1" "$2" "$3" <<'PYSWAP'
import sys
p, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
assert s.count(old) == 1, f"expected exactly one occurrence in {p}, found {s.count(old)}"
open(p, "w").write(s.replace(old, new, 1))
PYSWAP
}
if grep -qF 'SELFTEST PLANT' "$PLANT_TARGET"; then
  echo "SELFTEST: $PLANT_TARGET was left PLANTED by a run that died before its trap — healing (B-285)." >&2
  swap_text "$PLANT_TARGET" "$PLANT_TEXT" "$PLANT_ORIGINAL"
fi

PG_CONTAINER=tlane-ledger-pg-$$
CH_CONTAINER=tlane-ledger-ch-$$
STARTED_PG=0; STARTED_CH=0
cleanup() {
  [ "$STARTED_PG" = 1 ] && docker rm -fv "$PG_CONTAINER" >/dev/null 2>&1
  [ "$STARTED_CH" = 1 ] && docker rm -fv "$CH_CONTAINER" >/dev/null 2>&1
  return 0
}
trap cleanup EXIT

have_docker() { command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; }

start_throwaway_postgres() {
  local port=15467
  docker ps -a --filter 'name=tlane-ledger-pg-' --format '{{.Names}}' 2>/dev/null \
    | xargs -r docker rm -fv >/dev/null 2>&1 || true
  if ! docker run -d --name "$PG_CONTAINER" \
    -e POSTGRES_PASSWORD=tracelane_dev -e POSTGRES_USER=tracelane -e POSTGRES_DB=tracelane \
    -p "${port}:5432" postgres:16-alpine >/dev/null 2>&1; then
    docker rm -fv "$PG_CONTAINER" >/dev/null 2>&1 || true
    echo "ERROR: docker is present but the throwaway Postgres did not START — host port ${port} held?" >&2
    return 2
  fi
  STARTED_PG=1
  local i
  for i in $(seq 1 90); do
    # A REAL connection, not pg_isready (the entrypoint restarts mid-init).
    if docker exec "$PG_CONTAINER" psql -U tracelane -d tracelane -tAc "SELECT 1" >/dev/null 2>&1; then
      export POSTGRES_TEST_URL="postgres://tracelane:tracelane_dev@127.0.0.1:${port}/tracelane"
      return 0
    fi
    sleep 1
  done
  echo "ERROR: the throwaway Postgres never answered SELECT 1 within 90 s." >&2
  return 2
}

start_throwaway_clickhouse() {
  local port=18124
  docker ps -a --filter 'name=tlane-ledger-ch-' --format '{{.Names}}' 2>/dev/null \
    | xargs -r docker rm -fv >/dev/null 2>&1 || true
  # 24.12 — the server prod runs (see run-clickhouse-integration.sh for why the pin).
  if ! docker run -d --name "$CH_CONTAINER" \
    -e CLICKHOUSE_SKIP_USER_SETUP=1 \
    -p "${port}:8123" clickhouse/clickhouse-server:24.12-alpine >/dev/null 2>&1; then
    docker rm -fv "$CH_CONTAINER" >/dev/null 2>&1 || true
    echo "ERROR: docker is present but the throwaway ClickHouse did not START — host port ${port} held?" >&2
    return 2
  fi
  STARTED_CH=1
  local i
  for i in $(seq 1 90); do
    # A REAL query, not /ping (answers before DDL is served).
    if curl -fsS -m 3 "http://127.0.0.1:${port}/" --data-binary "SELECT 1" >/dev/null 2>&1; then
      export CLICKHOUSE_TEST_URL="http://127.0.0.1:${port}"
      return 0
    fi
    sleep 1
  done
  echo "ERROR: the throwaway ClickHouse never answered SELECT 1 within 90 s." >&2
  return 2
}

if ! have_docker; then
  echo "SKIP: no usable docker — the ledger's dual-store proofs CANNOT RUN here. That is a gap, not a pass."
  exit 0
fi
start_throwaway_postgres || exit 3
start_throwaway_clickhouse || exit 3

# Every migration, in order, into the THROWAWAY only (never an inherited POSTGRES_URL —
# the Postgres runner's own trap, 2026-08-16).
for f in apps/web/db/migrations/*.sql; do
  docker exec -i "$PG_CONTAINER" psql -U tracelane -d tracelane -v ON_ERROR_STOP=1 -q < "$f" >/dev/null 2>&1 \
    || { echo "ERROR: migration $(basename "$f") failed against the throwaway Postgres" >&2; exit 3; }
done

# `--test-threads=1`: every test here DROPs and recreates the shared ClickHouse ledger
# tables; two at once would race on the reset.
# B-494 (2026-09-21): every invocation goes through `run_and_count`, which sums `N passed`
# into EXECUTED; the floor after the run refuses a suite that shrank — a filter that
# matches nothing is a green that tested nothing. The --selftest holds the DISCOVERED
# count of the same filters to the same floor before it plants.
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
LEDGER_FILTERS="adr078_ r21_backlog_larger_than_anchor_every_anchors_from_genesis r21_flush_aged_batches_discriminates_on_age_and_writes_a_partial_batch b475_the_reconcile_refuses_a_copy_row_whose_content_was_altered b483_the_sweep_recovers_a_hole_below_the_watermark"
# B-513 (2026-09-21): adr078_b_trace_chain_status_reads_canonical_when_the_copy_write_failed
# joined the `adr078_` filter (already matched, no filter-list change needed) — the
# per-trace chain-status read now proven against the same kill as adr078_a. 7 -> 8.
EXPECTED_LEDGER_TESTS=8
run_suite() {
  run_and_count -p gateway --bin gateway -- --ignored --test-threads=1 adr078_ \
    && run_and_count -p gateway --bin gateway -- --ignored --test-threads=1 r21_backlog_larger_than_anchor_every_anchors_from_genesis r21_flush_aged_batches_discriminates_on_age_and_writes_a_partial_batch \
    && run_and_count -p gateway --bin gateway -- --ignored --test-threads=1 b475_the_reconcile_refuses_a_copy_row_whose_content_was_altered \
    && run_and_count -p gateway --bin gateway -- --ignored --test-threads=1 b483_the_sweep_recovers_a_hole_below_the_watermark
  # B-475 (REV-4, 2026-09-21): a copy row whose CONTENT was altered under intact hash
  # fields is refused by both reconcile rules — the row the old walk adopted.
  # B-483 (2026-09-21): a planted hole below the anchor watermark — the shape the 09-20
  # reboot left on prod — is found by the hole-aware probe (the old probe is the
  # control that cannot see it), anchored EXACTLY, stamped with the real time, and a
  # second sweep finds nothing left.
}

if [ "${1:-}" = "--selftest" ]; then
  # PROVE IT BITES. Neutralise the canonical insert — the one line that makes B "B" —
  # so rows never reach Postgres while the head still advances. The copy-failure test's
  # `ledger_range == (0,4,5)` assertion must go RED.
  # Restore by REVERSING the plant text — never by copying a backup or `git show HEAD:`,
  # both of which would also erase any other uncommitted edit to the file.
  # B-494: the suite is LISTED against the floor before the plant — a narrowed selftest
  # (one test) cannot see a suite that shrank; this can. A failed list is CANNOT
  # DETERMINE (a compile error), never "zero tests".
  LIST_LOG="$(mktemp)"
  # shellcheck disable=SC2086
  if ! cargo test -p gateway --bin gateway -- --list --ignored $LEDGER_FILTERS >"$LIST_LOG" 2>&1; then
    echo "SELFTEST CANNOT DETERMINE — \`cargo test --list\` failed before any test was discovered (a compile error in the tree?):" >&2
    grep -E '^error' "$LIST_LOG" | head -5 >&2
    rm -f "$LIST_LOG"
    exit 1
  fi
  DISCOVERED="$(grep -c ': test$' "$LIST_LOG" || true)"
  rm -f "$LIST_LOG"
  if [ "${DISCOVERED:-0}" -lt "$EXPECTED_LEDGER_TESTS" ]; then
    echo "SELFTEST FAILED — the ledger suite discovers ${DISCOVERED:-0} test(s), floor is $EXPECTED_LEDGER_TESTS: the suite SHRANK (a narrowed falsification would hide that). Fix the suite or the floor, with the reason." >&2
    exit 1
  fi
  echo "selftest: the ledger suite discovers $DISCOVERED tests (floor $EXPECTED_LEDGER_TESTS)."
  restore() { grep -qF 'SELFTEST PLANT' "$PLANT_TARGET" && swap_text "$PLANT_TARGET" "$PLANT_TEXT" "$PLANT_ORIGINAL"; cleanup; }
  trap restore EXIT INT TERM HUP
  swap_text "$PLANT_TARGET" "$PLANT_ORIGINAL" "$PLANT_TEXT" \
    || { echo "SELFTEST BROKEN: the canonical insert was not found verbatim — the plant would be a no-op" >&2; exit 1; }
  if cargo test -p gateway --bin gateway -- --ignored --test-threads=1 adr078_a_copy_failure_leaves_the_chain_green >/dev/null 2>&1; then
    echo "SELFTEST FAILED: with the canonical insert removed the ADR-078 copy-failure test still PASSED — the runner does not bite." >&2
    exit 1
  fi
  echo "selftest: ✓ removing the canonical insert turns adr078_a_copy_failure RED (the runner bites)"
  exit 0
fi

RC=0
run_suite || RC=1
if [ "$EXECUTED" -lt "$EXPECTED_LEDGER_TESTS" ]; then
  echo "ledger integration: FAIL — executed $EXECUTED test(s), floor is $EXPECTED_LEDGER_TESTS: the suite shrank or a filter matched nothing (B-494)" >&2
  exit 1
fi
if [ "$RC" -eq 0 ]; then
  echo "ledger integration (real Postgres + real ClickHouse): PASS — $EXECUTED tests (adr078_ ×4 + r21_ ×2 + b475_ ×1 + b483_ ×1) executed with both stores"
else
  echo "ledger integration: FAIL" >&2
fi
exit "$RC"
