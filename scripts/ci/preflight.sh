#!/usr/bin/env bash
# preflight — the CHEAP checks, run BEFORE the expensive gate, so a doc-shaped
# defect refuses in ~30 seconds instead of after `cargo test --workspace
# --all-features`.
#
# WHY THIS EXISTS (founder ruling R89, 2026-08-22). `verify-all.sh` deliberately
# CONTINUES past a failing step and reports every failure at the end — that is the
# right design, because fixing one failure at a time is how you pay for N runs. But
# the expensive steps sit near the FRONT (`cargo clippy` and `cargo test` are steps
# 2 and 3), so a formatting slip or a stale doc anchor is not reported until the
# whole workspace has compiled and tested.
#
# Twice in one session that cost a full gate run each:
#   * `cargo fmt --check` + a CLAUDE.md line anchor  — ~12 min to learn
#   * `check-doc-freshness.py`, on an anchor MY OWN previous commit had moved — ~12 min
# Both were real defects and both were knowable in seconds.
#
# The founder's framing is the point: *"a lesson you carry is a rule with no
# consumer."* The consumer is `.githooks/pre-commit`, which runs this first and
# refuses before it starts the real gate.
#
# WHAT BELONGS HERE, and the rule is mechanical rather than a judgement call:
#   a check qualifies if it is (a) fast — under a couple of seconds, no compile,
#   no network — and (b) a check the author can FIX IMMEDIATELY from its output.
# Everything else stays in the full gate.
#
# WHAT THIS IS NOT. It is NOT a substitute for `verify-all.sh`, it does NOT stamp
# anything, and passing it means nothing about the gate. It only ever makes a
# refusal ARRIVE EARLIER. A green preflight followed by a red gate is the normal,
# expected shape — which is why it prints its own scope rather than a verdict that
# could be mistaken for the gate's.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

FAILED=0
run() { # run <label> <cmd...>
    local label="$1"; shift
    if out=$("$@" 2>&1); then
        printf '  ✔ %s\n' "$label"
    else
        printf '  ✗ %s\n' "$label"
        printf '%s\n' "$out" | sed 's/^/      /' | head -20
        FAILED=1
    fi
}

echo "── preflight (cheap checks, before the gate) ─────────────────────────"

# Formatting: the two that have actually refused a commit here.
command -v cargo >/dev/null 2>&1 && run "cargo fmt --check" cargo fmt --check
command -v ruff  >/dev/null 2>&1 && run "ruff format --check" ruff format --check scripts/
command -v ruff  >/dev/null 2>&1 && run "ruff check"          ruff check scripts/

# ── TYPESCRIPT FORMATTER — the third language, and it was MISSING. ──────────────
#
# `cargo fmt --check` (Rust) and `ruff format --check` (Python) are both above.
# biome (TypeScript) was NOT, so a TS formatting slip could only surface ~20 minutes
# into the FULL gate, at `pnpm lint (biome)`. Earned 2026-08-24: exactly that
# happened — a new `apps/web/lib` file was committed unformatted, the full gate went
# red on it after 20 minutes, and the whole cycle had to be paid again.
#
# CHANGED FILES ONLY, and via each workspace's LOCAL binary. Measured: a repo-wide
# `biome check` is 28 s and `npx biome` adds ~16 s of resolution — both far outside
# preflight's budget. The local binary on the changed files is **56 ms**.
#
# Silent when nothing TS changed, which is most Rust and docs commits.
_ts_format_check() {
    local files ws wsfiles bin rc=0
    files="$( { git diff --name-only HEAD; git diff --name-only --cached
                git ls-files --others --exclude-standard; } 2>/dev/null \
              | sort -u | grep -E '^(apps|packages)/[^/]+/.*\.(ts|tsx|js|jsx|mjs)$' || true )"
    [ -n "$files" ] || return 0
    # Group by workspace: each carries its own biome config and binary.
    for ws in $(printf '%s\n' "$files" | cut -d/ -f1,2 | sort -u); do
        bin="$ws/node_modules/.bin/biome"
        [ -x "$bin" ] || continue          # workspace has no biome — nothing to assert
        wsfiles="$(printf '%s\n' "$files" | grep "^$ws/" | sed "s|^$ws/||")"
        # shellcheck disable=SC2086
        ( cd "$ws" && ./node_modules/.bin/biome check --no-errors-on-unmatched $wsfiles ) || rc=1
    done
    return $rc
}
run "biome (changed TS)"          _ts_format_check

# Doc/anchor integrity — the class that cost the second run. These are the checks
# whose failure is caused by an edit made minutes earlier and fixed in one line.
run "doc freshness (cited code)"  python3 scripts/ci/check-doc-freshness.py
run "doc classification"          python3 scripts/ci/check-doc-classification.py
run "doc-index freshness"         python3 scripts/ci/build-doc-index.py --check
run "spec anchors"                python3 scripts/ci/check-spec-anchors.py
run "CLAUDE.md volatile anchors"  bash scripts/ci/check-claudemd-volatile-anchors.sh
run "script exec bits"            python3 scripts/ci/check-script-exec-bits.py

echo "──────────────────────────────────────────────────────────────────────"
if [ "$FAILED" -ne 0 ]; then
    echo "preflight: ✗ refusing BEFORE the expensive gate — fix the above and re-run."
    echo "preflight: this is a FAST subset. A green preflight says nothing about the"
    echo "           full gate; it only makes a refusal arrive in seconds, not minutes."
    exit 1
fi
echo "preflight: ✔ cheap checks clean — handing over to the full gate."
exit 0
