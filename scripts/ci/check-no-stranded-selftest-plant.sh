#!/usr/bin/env bash
# check-no-stranded-selftest-plant.sh — refuse a tree that still carries a selftest's PLANT.
#
# Two runners prove they bite by MUTATING TRACKED SOURCE and restoring it on an EXIT trap:
# `run-ledger-integration.sh` (turns the canonical ledger insert into a no-op) and
# `run-clickhouse-integration.sh` (unqualifies a WHERE, B-272's shape). A trap does not
# survive SIGKILL — a laptop reboot, an OOM kill (seven on this box), the meta-gate's
# timeout (B-285, 2026-08-25). Earned again 2026-09-20: a reboot mid-selftest left
# `crates/gateway/src/db/audit_chain_state.rs` with `insert_rows_tx` REPLACED BY `let _ =`
# — the exact pre-ADR-078 shape in which the head advances and no row is written — and the
# next gate would have compiled, tested and committed the tree that way. `git status`
# showed a third modified file; only reading the diff told what it was.
#
# The control: every plant carries the marker below, and this refuses the marker anywhere
# under the source trees, in preflight (commit time) and in the gate, in ~50 ms. Each
# runner also heals its own stranded plant at start; this catches the window in between.
#
# Exit 0 clean · 1 a plant is stranded (paths printed) · --selftest proves both directions.
set -euo pipefail
case "${1:-}" in
  ""|--selftest) ;;
  *) echo "usage: $(basename "$0") [--selftest]  (unknown argument: $1)" >&2; exit 2 ;;
esac
MARKER='SELFTEST PLANT'
# The runners that WRITE the marker, and this file, are the only places it may appear.
WRITERS=(
  ':(exclude)scripts/ci/run-ledger-integration.sh'
  ':(exclude)scripts/ci/run-clickhouse-integration.sh'
  ':(exclude)scripts/ci/check-no-stranded-selftest-plant.sh'
)

scan() { # scan <repo-root> → prints offending paths, exit 1 if any
  local root="$1" hits
  hits=$(git -C "$root" grep -I -l -F --untracked -- "$MARKER" -- crates apps packages scripts "${WRITERS[@]}" 2>/dev/null || true)
  if [ -n "$hits" ]; then
    echo "STRANDED SELFTEST PLANT — a runner's --selftest died before its EXIT trap restored the source:" >&2
    printf '  %s\n' $hits >&2
    echo "Fix: re-run that runner's --selftest (it self-heals), or reverse the plant by hand; never commit it." >&2
    return 1
  fi
  return 0
}

if [ "${1:-}" = "--selftest" ]; then
  T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
  git -C "$T" init -q
  mkdir -p "$T/crates/x/src" "$T/scripts/ci"
  printf 'fn f() {}\n' > "$T/crates/x/src/lib.rs"
  # A writer may carry the marker (untracked, like a real runner): must PASS.
  printf '# %s lives here legitimately\n' "$MARKER" > "$T/scripts/ci/run-ledger-integration.sh"
  scan "$T" 2>/dev/null || { echo "SELFTEST FAILED: a clean tree (marker only in a writer) was refused" >&2; exit 1; }
  # A plant left in source: must REFUSE and name the file.
  printf '    // %s: the canonical write is skipped\n    let _ = ();\n' "$MARKER" >> "$T/crates/x/src/lib.rs"
  if out=$(scan "$T" 2>&1); then echo "SELFTEST FAILED: a planted source file PASSED" >&2; exit 1; fi
  grep -q 'crates/x/src/lib.rs' <<<"$out" || { echo "SELFTEST FAILED: refusal did not name the planted file" >&2; exit 1; }
  # Healed: must PASS again.
  printf 'fn f() {}\n' > "$T/crates/x/src/lib.rs"
  scan "$T" 2>/dev/null || { echo "SELFTEST FAILED: the healed tree was refused" >&2; exit 1; }
  echo "selftest: ✓ refuses a stranded plant and names it; passes a clean tree and a writer's own marker"
  exit 0
fi

cd "$(dirname "$0")/../.."
scan . && echo "no stranded selftest plant under crates/ apps/ packages/ scripts/"
