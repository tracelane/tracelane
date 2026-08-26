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
cleanup() { [ "$STARTED_CONTAINER" = 1 ] && docker rm -f "$CONTAINER" >/dev/null 2>&1; return 0; }
trap cleanup EXIT

start_throwaway_clickhouse() {
  command -v docker >/dev/null 2>&1 || return 1
  docker info >/dev/null 2>&1 || return 1
  local port=18123
  # 24.12 is the version the migration-18 type traps were verified against
  # (`Nullable(LowCardinality(String))` is illegal there, and the DateTime64
  # millis-vs-micros behaviour was MEASURED on 24.12.6.70). Pinning it means this
  # runner tests the server prod actually runs, not whatever `latest` became.
  docker run -d --name "$CONTAINER" \
    -e CLICKHOUSE_SKIP_USER_SETUP=1 \
    -p "${port}:8123" clickhouse/clickhouse-server:24.12-alpine >/dev/null 2>&1 || return 1
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
  return 1
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
  OLD='WHERE tenant_id = ? AND datasets.dataset_id = toUUID(?) AND deleted = 0'
  NEW='WHERE tenant_id = ? AND dataset_id = toUUID(?) AND deleted = 0'
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
  if bash "$0" >/dev/null 2>&1; then
    echo "SELFTEST FAILED — the suite passed with B-272 reintroduced. This runner proves nothing."
    exit 1
  fi
  echo "SELFTEST PASSED — the suite goes RED on the reintroduced alias shadowing."
  exit 0
fi

if [ -z "${CLICKHOUSE_TEST_URL:-}" ]; then
  if ! start_throwaway_clickhouse; then
    echo "SKIP: no CLICKHOUSE_TEST_URL and no usable docker — this guard CANNOT RUN here."
    echo "      That is a real gap, not a pass."
    exit 0
  fi
fi

RC=0
# The in-crate round trip: the REAL ClickHouseDatasetStore, the REAL ItemWriteRow.
cargo test -p gateway --bin gateway clickhouse_roundtrip -- --ignored --nocapture || RC=1
# The previously-uncalled migration-03 parity test. Mirrors column shapes rather
# than driving the persisters, so it is a weaker check — run for coverage, not
# for confidence.
cargo test -p gateway --test clickhouse_persister_integration -- --ignored || RC=1
exit $RC
