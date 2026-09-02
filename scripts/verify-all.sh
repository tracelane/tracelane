#!/usr/bin/env bash
# scripts/verify-all.sh
#
# One-click acceptance gate (closes audit finding P0-5): a SINGLE command
# that runs every merge-blocking check the way CI runs it, in dependency
# order, and reports a consolidated pass/fail. If this is green, `main` is
# green; if it is red, do not merge.
#
# Mirrors the jobs in .github/workflows/ci.yml. Run it locally before any
# hot-path PR and before claiming "tests pass" (per an internal ticket: cite a
# real run, never "verified locally" without evidence).
#
# Usage:
#   scripts/verify-all.sh            # full suite
#   scripts/verify-all.sh                 # the FULL gate (what pre-push runs)
#   scripts/verify-all.sh --commit-stage  # commit stage: selftests are diff-gated
#   SKIP_PY=1 scripts/verify-all.sh  # skip Python (e.g. pytest not installed)
#
# Exit code: 0 iff every selected step passed.

set -uo pipefail
cd "$(dirname "$0")/.."

# ── SINGLE-RUN LOCK ───────────────────────────────────────────────────────────
# TWO CONCURRENT RUNS CANNOT SHARE THIS WORKTREE, and the failure is silent and
# misleading. Many guards below are SELFTESTS that deliberately PLANT a violation in
# the repo — an untagged doc, a CONFIDENTIAL file in the export set, a broken anchor —
# assert it is caught, then remove it. A second run scanning at that moment sees the
# planted file and fails on it. The report then names a real-looking guard with a
# real-looking violation that has nothing to do with your code.
#
# Earned 2026-08-16: two overlapping runs produced two `gate=1` results with no
# honest cause and blocked a push. `CLAUDE.md` §14's whole point is that a gate must
# tell you WHAT it looked at; a gate that goes red for a reason unrelated to the code
# teaches people to re-run instead of read, which is the one behaviour it exists to
# prevent.
#
# So: refuse, immediately and loudly, with a DISTINCT exit code. 99 is not a gate
# failure and must never be read as one — `exit 1` here would recreate the very
# confusion this fixes.
# APPEND, never truncate. Opening with `>` truncates on open, so the second run erased
# the holder's own pid/start line BEFORE it could read it, and the message printed
# `holder: <unknown>`. A diagnostic that destroys its own evidence is worse than none —
# it turns "who is holding this?" into a shrug, which is the same unhelpfulness the
# lock was added to remove.
# --explain-scope takes NO LOCK: it executes nothing, so it cannot collide with a real
# run, and the lock is keyed on the user rather than the worktree — a probe from a
# throwaway worktree would otherwise wait on the main run for no reason.
_explain_early=0
for _a in "$@"; do [[ "$_a" == "--explain-scope" ]] && _explain_early=1; done

_lock="${TMPDIR:-/tmp}/tracelane-verify-all.$(id -u).lock"
exec {_lockfd}>>"$_lock" 2>/dev/null || true
if [[ "$_explain_early" -eq 0 ]] && [[ -n "${_lockfd:-}" ]] && command -v flock >/dev/null 2>&1; then
    if ! flock -n "$_lockfd"; then
        holder="$(cat "$_lock" 2>/dev/null || true)"
        echo "═══════════════════════════════════════════════════════════════════════"
        echo " ⛔ NOT A GATE FAILURE — another verify-all.sh is already running."
        echo "═══════════════════════════════════════════════════════════════════════"
        echo "   holder: ${holder:-<unknown>}"
        echo "   this run: pid $$ at $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo
        echo "   Two runs cannot share this worktree: the selftests below PLANT"
        echo "   violations in the repo and remove them again, so a concurrent scan"
        echo "   fails on the other run's plant. That red would be about timing, not"
        echo "   about your code."
        echo
        echo "   Wait for the other run, then re-run. Exit code 99 (not 1) so no"
        echo "   caller can mistake this for a failing check."
        exit 99
    fi
    # We hold it now — replace the file's contents with our identity, so the next
    # arrival can name us instead of guessing.
    printf 'pid %s started %s\n' "$$" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$_lock" 2>/dev/null || true
fi

# ── ARGUMENTS ─────────────────────────────────────────────────────────────────
# STRICT, and unknown argv REFUSES. This script used to read only `$1` and ignore
# everything else, which is the same shape as `scripts/deploy/site.sh`'s
# `MODE="${1:-deploy}"` — the default that produced SEVEN unauthorised production
# deploys on 2026-08-16. Ignoring argv was harmless here only by luck: it meant MORE
# coverage, not an action. Now that `--scoped` can remove coverage, a silently-ignored
# flag would mean the opposite, so it refuses.
# `--fast` WAS REMOVED 2026-08-22 and the reason is worth keeping: it skipped exactly
# ONE of 146 steps (`pnpm eval:run`), and BOTH callers passed it — `.githooks/pre-commit`
# and `.githooks/pre-push`. So "fast" was the only mode anyone ever ran, the flag
# described nothing, and the eval suite it named had no local caller at all. A flag whose
# every caller sets it is not a mode, it is a default with a misleading name.
#
# What replaces it is a flag that actually marks a STAGE, because the two stages have
# genuinely different jobs:
#   --commit-stage  cheap, advisory, runs on every commit. May diff-gate guard selftests.
#   (no flag)       the FULL gate. What `.githooks/pre-push` runs, and the only thing
#                   standing between this machine and the remote.
COMMIT_STAGE=0
WITH_EVAL_SUITE=0
SCOPED=0
EXPLAIN=0
for _arg in "$@"; do
    case "$_arg" in
        --commit-stage)    COMMIT_STAGE=1 ;;
        --with-eval-suite) WITH_EVAL_SUITE=1 ;;
        --scoped)          SCOPED=1 ;;
        --explain-scope)   EXPLAIN=1 ;;
        *)
            echo "verify-all.sh: unknown argument '$_arg'" >&2
            echo "usage: verify-all.sh [--commit-stage] [--scoped] [--with-eval-suite] [--explain-scope]" >&2
            echo "  --commit-stage     COMMIT stage: advisory, and guard selftests are" >&2
            echo "                     diff-gated. NEVER passed by the pre-push hook." >&2
            echo "  --scoped           run only the areas the working diff touches (LOCAL)." >&2
            echo "                     The pre-push hook deliberately does NOT pass this." >&2
            echo "  --with-eval-suite  also run pnpm eval:run (slow; no caller passes it)." >&2
            echo "  --explain-scope    print RUN/SKIP per step and exit. Runs NOTHING." >&2
            exit 2
            ;;
    esac
done

# ── PREFLIGHT (R140, founder-ruled 2026-08-25) ────────────────────────────────
#
# 26 SECONDS, AT THE TOP, BEFORE ANY EXPENSIVE STEP.
#
# THE FINDING THAT EARNED THIS: preflight already existed and already contained BOTH
# checks that would have caught the two wasted full gates of 2026-08-25 —
# `ruff format --check scripts/` (preflight.sh:51) and `check-doc-classification.py`
# (preflight.sh:88), the latter being the exact "consumer check" that refuses when a
# data structure other files parse is deleted. It was simply NEVER INVOKED from here:
# `grep -c preflight scripts/verify-all.sh` was 0, and so was the pre-push hook. It
# ran only from `.githooks/pre-commit`.
#
# That gap is not academic: the stamp-reuse workflow (run the FULL gate, then commit
# with TRACELANE_SKIP_SCOPED_GATE=1) means the expensive run is routinely started by
# hand, which bypassed preflight entirely. Two ~20-minute gates were spent on defects
# that refuse here in seconds.
#
# NOTHING NEW WAS BUILT. The mechanism existed; only the wire was missing.
#
# NOT OPTIMISED, DELIBERATELY (founder, R140): if preflight grows to 60s because it
# caught something real, that is a good trade, not a regression. It is the cheapest
# detection in the repo.
#
# `--explain-scope` prints and exits without running anything, so it skips this too.
# `TRACELANE_PREFLIGHT_DONE=1` is set by `.githooks/pre-commit`, which runs preflight
# itself a few lines earlier — without that marker the hook would pay the 26s twice.
if [[ "${EXPLAIN:-0}" -ne 1 ]] \
   && [ -x scripts/ci/preflight.sh ] \
   && [ "${TRACELANE_SKIP_PREFLIGHT:-0}" != "1" ] \
   && [ "${TRACELANE_PREFLIGHT_DONE:-0}" != "1" ]; then
    if ! bash scripts/ci/preflight.sh; then
        echo "" >&2
        echo "verify-all: ✗ REFUSING TO START — preflight failed above." >&2
        echo "verify-all:   Those checks are seconds and fixable from their own output." >&2
        echo "verify-all:   Fix them and re-run rather than spending ~20 minutes to be" >&2
        echo "verify-all:   told the same thing. (TRACELANE_SKIP_PREFLIGHT=1 overrides.)" >&2
        exit 1
    fi
fi

# ── SCOPE (founder-ruled 2026-08-16) ──────────────────────────────────────────
# THE PROBLEM. Measured over all 120 steps, warm caches: a full run is
# 411.6s. A docs-only commit — which is a large share of this repo's commits — pays
# every second of it: cargo test, clippy, the whole pnpm workspace, the 64-guard
# meta-gate (136.2s) and a docker Postgres integration (96.6s), for a change to a
# Markdown file. The gate is also single-flocked, so one session's run blocks another's.
#
# THE RULE, and it is the load-bearing sentence: SCOPING DECIDES WHICH GUARDS RUN,
# NEVER WHAT A GUARD LOOKS AT. Every guard that runs, runs over its full scope. That
# distinction is why `.githooks/pre-commit` scans the whole tree rather than the staged
# files — a deny-list edit pulls an ALREADY-COMMITTED doc into the export set, and that
# file is in no diff. Narrowing a guard's input would break that; skipping the guard
# entirely when nothing it reads has changed does not.
#
# FAIL OPEN, ALWAYS TOWARD MORE COVERAGE. A path we cannot classify, an unavailable
# upstream, an unreadable diff — every one of those runs EVERYTHING. The only way to
# skip a step is to positively establish that nothing in its buckets changed.
#
# WHAT IS NOT WEAKENED: `--scoped` is opt-in and local. `.githooks/pre-push` invokes
# `verify-all.sh` with no flags, so the full unscoped gate still stands
# between this repo and every push. This schedules work; it does not remove it.
declare -a CHANGED_BUCKETS=()
SCOPE_REASON=""

_classify_changed() {
    # The diff is everything not yet on the remote: unpushed commits + staged +
    # working tree + untracked. Anything we cannot compute means ALL.
    local files upstream

    # TEST SEAM, and it is deliberately inert outside an explain pass.
    # `check-verify-all-scoping.py --selftest` drives this classifier with a synthetic
    # file list, because the alternative — planting real files in a real worktree — is
    # what the run-lock exists to prevent, and planting them in a COPY makes
    # `scripts/verify-all.sh` itself part of the probe's diff, which trips the tripwire
    # and makes every assertion pass for the wrong reason. That was the first version.
    #
    # Honoured ONLY under --explain-scope, which executes nothing and writes no stamp,
    # so this variable can never shrink the coverage of a real run.
    #
    # WHAT IT COSTS, said plainly: the seam tests the CLASSIFIER (the case arms below),
    # not the six lines of git plumbing that build the list. Those fail open by
    # construction — every branch that cannot produce a list returns 1 — and the
    # end-to-end path is exercised every time anyone runs `--scoped` for real.
    if [[ "$EXPLAIN" -eq 1 && -n "${TRACELANE_SCOPE_FILES:-}" ]]; then
        files="$TRACELANE_SCOPE_FILES"
        upstream="synthetic"
    else
    if ! git rev-parse --git-dir >/dev/null 2>&1; then
        SCOPE_REASON="not a git worktree"; return 1
    fi
    upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
    files="$(
        { git diff --name-only HEAD 2>/dev/null
          git diff --name-only --cached 2>/dev/null
          git ls-files --others --exclude-standard 2>/dev/null
          [[ -n "$upstream" ]] && git diff --name-only "$upstream...HEAD" 2>/dev/null
        } | sort -u
    )"
    fi
    if [[ -z "$upstream" ]]; then
        SCOPE_REASON="no upstream branch — cannot bound the diff"; return 1
    fi
    if [[ -z "$files" ]]; then
        SCOPE_REASON="empty diff"; return 1
    fi

    local -A seen=()
    local f b
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        b=""
        case "$f" in
            # A TRIPWIRE forces a full run: these define the gate itself or the export
            # set, so a change to one invalidates every scoping decision below it.
            # `.claude/**` is a tripwire because it can change WHAT RUNS: settings.json
            # registers the PreToolUse hooks, and rules/ and skills/ change how the work
            # is done. It would fail open anyway as an unclassified path — this only makes
            # the reason legible instead of leaving it to the catch-all.
            scripts/verify-all.sh|.githooks/*|.claude/*|scripts/export/export-deny.txt|scripts/export/build-public-export.sh)
                SCOPE_REASON="tripwire touched: $f"; return 1 ;;
            crates/*|Cargo.toml|Cargo.lock|rust-toolchain*|.cargo/*)  b="RUST" ;;
            apps/*|packages/*|pnpm-*.yaml|package.json|biome.json|knip*) b="WEB" ;;
            .github/*)                                                b="CI" ;;
            infra/*|Dockerfile*|docker-compose*|*.Dockerfile)         b="INFRA" ;;
            scripts/*|bench/*)                                        b="SCRIPTS" ;;
            evals/*|ml/*|pyproject.toml|pytest.ini|*.py)              b="PY" ;;
            *.md|*.mdx|*.mdc|docs/*|decisions/*|specs/*|runbooks/*)   b="DOCS" ;;
            *)
                # Unclassifiable path -> run everything. Adding a bucket is a decision
                # someone must make deliberately; guessing is how a guard goes dark.
                SCOPE_REASON="unclassified path: $f"; return 1 ;;
        esac
        # A markdown file ANYWHERE is also a DOCS change: build-doc-index.py and
        # check-doc-classification.py key on the EXTENSION, not the directory, so a new
        # README.md under crates/ makes docs/INDEX.md stale.
        case "$f" in *.md|*.mdx|*.mdc) seen[DOCS]=1 ;; esac

        # ── MIGRATIONS (R127, 2026-08-24) — a NARROW bucket carved out of WEB. ──
        #
        # `api-key mint (real Postgres)` was declared `area RUST WEB`, and that was
        # CORRECT rather than a misfiling: the runner applies every
        # `apps/web/db/migrations/*.sql`, and `postgres_tenant_integration.rs`
        # `include_str!`s `0000_initial_baseline.sql` directly. A Drizzle migration
        # genuinely can break it.
        #
        # The defect is that WEB is TOO COARSE — it lumps the migrations the suite
        # needs with `apps/web/lib/**`, which cannot affect it. MEASURED on a WEB-only
        # diff (2026-08-24): that suite is **100.1 s of a 198.6 s commit stage —
        # 50.4%** — on a change that touched one `.ts` file.
        #
        # WHY THIS SPLIT IS SAFE WHERE THE `RUST` BEHAVIOUR/WIRE SPLIT WAS NOT
        # (founder ruling R124(b), refuted the same day): **A BUCKET SPLIT IS SAFE
        # WHEN THE SURFACE IS A DIRECTORY AND UNSAFE WHEN IT IS A DERIVE.** The RUST
        # wire surface is 31 of 118 `crates/gateway/src` files carrying a
        # `#[derive(Row)]`, NONE of them in `db/` — so any list narrow enough to save
        # time is one new derive away from going dark, silently. This surface is 30
        # `.sql` files in ONE directory plus `schema.ts`, verified by grepping every
        # `apps/web` reference in both the runner and the test. Nothing can drift out
        # of it without moving a file, and moving a file is visible in review.
        #
        # ADDITIVE, NEVER A REPLACEMENT: these paths keep WEB too, so a migration
        # change LOSES NO COVERAGE — it gains a precise extra trigger.
        case "$f" in
            apps/web/db/migrations/*|apps/web/db/schema.ts) seen[MIGRATIONS]=1 ;;
        esac
        seen[$b]=1
    done <<< "$files"

    CHANGED_BUCKETS=("${!seen[@]}")
    return 0
}

# ── R129 (2026-08-24): SAY UP FRONT WHEN THE META-GATE REFUSES TO NARROW. ──
#
# `check-guard-selftests.py --changed-only` correctly runs EVERY guard when a SHARED
# GUARD INPUT changes — `osv-scanner.toml`, `export-deny.txt`, a workflow the guards
# parse — because those change what other guards assert while leaving every guard file
# untouched. That is right, and it costs **441 s** (36% of a full gate, the single
# largest step).
#
# It used to be discoverable ONLY from one line inside that step's output, ~85 steps
# into a 102-step log. On 2026-08-24 two commits took >10 minutes each for exactly this
# reason — a two-line edit to an ignore ledger — and neither the founder nor I connected
# the cost to the cause until the measurement was re-read. A cost you cannot see is a
# cost you cannot decide about; announced here, it becomes a choice (commit the ledger
# edit separately and the other commits stay cheap).
if _why="$(python3 scripts/ci/check-guard-selftests.py --why-full 2>/dev/null)"; then
    echo "═══════════════════════════════════════════════════════════════════════"
    echo " GUARD META-GATE WILL NOT NARROW — every guard selftest runs (~441s)."
    echo "   reason: $_why"
    echo "   This is CORRECT: that input changes what other guards assert."
    echo "   To keep later commits cheap, land that file in its own commit."
    echo "═══════════════════════════════════════════════════════════════════════"
fi

if [[ "$SCOPED" -eq 1 ]]; then
    if _classify_changed; then
        echo "═══════════════════════════════════════════════════════════════════════"
        echo " SCOPED RUN — areas touched by the diff: ${CHANGED_BUCKETS[*]}"
        echo " Steps outside these areas report SCOPED-OUT, never PASS."
        echo " The pre-push hook runs the FULL gate; this does not replace it."
        echo "═══════════════════════════════════════════════════════════════════════"
    else
        SCOPED=0
        echo "── --scoped requested but running EVERYTHING: $SCOPE_REASON"
    fi
fi

# `area A [B ...]` declares which buckets the FOLLOWING `run` lines belong to. A step
# runs when ANY of its buckets is active. ALWAYS means it can never be scoped out —
# eleven guards scan the whole tree by construction and are marked so deliberately.
AREA="ALWAYS"
area() { AREA="$*"; }

_area_active() {
    [[ "$SCOPED" -eq 0 ]] && return 0
    local a b
    for a in $AREA; do
        [[ "$a" == "ALWAYS" ]] && return 0
        for b in "${CHANGED_BUCKETS[@]}"; do
            [[ "$a" == "$b" ]] && return 0
        done
    done
    return 1
}

# ── result accounting ──────────────────────────────────────────────────────
declare -a NAMES STATUSES
overall=0
declare -a SCOPED_OUT=()

run() {
    local name="$1"; shift
    # --explain-scope: answer "would this run?" and execute NOTHING. This exists so the
    # scoping falsification MEASURES the real classifier instead of re-implementing it —
    # a guard that restates the same table twice agrees with itself by construction and
    # proves nothing (`docs/reference/TRAPS.md` §38).
    if [[ "$EXPLAIN" -eq 1 ]]; then
        if _area_active; then printf 'RUN\t%s\n' "$name"; else printf 'SKIP\t%s\n' "$name"; fi
        return
    fi
    if ! _area_active; then
        NAMES+=("$name"); STATUSES+=("SCOPED-OUT")
        SCOPED_OUT+=("$name [$AREA]")
        return
    fi
    echo "──────────────────────────────────────────────────────────────"
    echo "▶ $name"
    echo "  \$ $*"
    if "$@"; then
        NAMES+=("$name"); STATUSES+=("PASS")
        echo "✔ $name"
    else
        local rc=$?
        NAMES+=("$name"); STATUSES+=("FAIL($rc)")
        echo "x $name FAILED (exit $rc)"
        overall=1
    fi
}

skip() {
    NAMES+=("$1"); STATUSES+=("SKIP")
    echo "- skipping $1 ($2)"
}

# ── Rust ────────────────────────────────────────────────────────────────────
area RUST
run "cargo fmt --check"            cargo fmt --check
# --all-targets so test/bench code is linted too (audit finding P2-1: the
# CI gate previously linted only lib+bin targets, hiding test-code lint rot).
run "cargo clippy (all targets)"   cargo clippy --workspace --all-targets -- -D warnings
run "cargo test --all-features"    cargo test --workspace --all-features

# B-263: no crate's BUILD SCRIPT may take a network client as a dependency.
# Offline (reads the resolved graph, no registry access), so unlike cargo-deny
# this is NOT advisory — it runs every time. Earned 2026-08-20 by `proc-macro1`
# shipping an RCE dropper through a yanked `arrayref`; `cargo tree -e build`
# could not see it because it sat at normal->normal->build, which is why the
# guard walks `cargo metadata` instead.
# GWY-45: content capture may only be enabled for the internal tenant until
# content-specific retention exists. A precondition, made executable — TRAPS §40.
run "trace-content allowlist"          python3 scripts/ci/check-trace-content-allowlist.py

run "build-script network deps"      python3 scripts/ci/check-build-script-network-deps.py
run "new-crate build deps"           python3 scripts/ci/check-new-crate-build-deps.py

# cargo-deny / cargo-audit are advisory locally (network); run if present.
if command -v cargo-deny >/dev/null 2>&1; then
    run "cargo deny check"         cargo deny check
else
    skip "cargo deny check" "cargo-deny not installed"
fi
if command -v cargo-audit >/dev/null 2>&1; then
    run "cargo audit"              cargo audit
else
    skip "cargo audit" "cargo-audit not installed"
fi
# cargo-machete: unused-dependency gate (2026-07-23 — the mcp-rs/policy dep rot
# was invisible until first run; CLAUDE.md promised this gate but it was wired
# nowhere). Full scanner sweep incl. osv/grype: scripts/security-scan.sh.
if command -v cargo-machete >/dev/null 2>&1; then
    run "cargo machete (unused deps)" cargo machete
else
    skip "cargo machete (unused deps)" "cargo install cargo-machete --locked"
fi

# ── CI guard scripts ─────────────────────────────────────────────────────────
run "no-auth-stub guard"           bash scripts/ci/no-auth-stub.sh
area RUST WEB
run "no-raw-ch-query guard"        bash scripts/ci/no-raw-ch-query.sh
run "no-llm-in-recovery guard"     bash scripts/ci/no-llm-in-recovery.sh
if [[ -f scripts/hooks/protect-uncommitted-from-git-restore.sh ]]; then
    area SCRIPTS
    skip "git-restore guard selftest" "guard not exported to the public repo"
fi
if [[ -f scripts/hooks/protect-ponytail-markers.sh ]]; then
    skip "ponytail guard selftest" "guard not exported to the public repo"
fi
# R60. TEN instances of the self-matching-probe class in one session, three of them AFTER
# the memory note documenting it, and four shells left spinning (two for 1h13m, found only
# because the founder asked what was running). A note did not work. Its selftest falsifies
# against the four commands that ACTUALLY hung, verbatim — a guard that cannot block the
# exact instances that produced it is not armed.
if [[ -f scripts/hooks/protect-self-matching-process-probe.sh ]]; then
    skip "self-matching-probe guard selftest" "guard not exported to the public repo"
fi
# W2 (2026-08-21) — four PreToolUse hooks for rules that were prose-only at the EDIT
# layer. Two of the four rules already have CI guards (check-plan-write-single-source.py,
# check-tracker-discipline.py) and these hooks deliberately MIRROR them rather than
# diverge — two controls for one rule that disagree is worse than one control.
# The other two (raw control-plane Postgres SQL, audit fail-open) had no gate anywhere.
#
# HONEST LIMIT, and it is the reason the CI guards beside them matter: a PreToolUse hook
# runs in Claude Code and NOWHERE ELSE. A cofounder using another agent, or plain git,
# gets none of them. An editor hook is an accelerator; it is never a rule's only copy.
if [[ -f scripts/hooks/protect-drizzle-only-postgres.sh ]]; then
    skip "drizzle-only guard selftest" "guard not exported to the public repo"
fi
if [[ -f scripts/hooks/protect-billing-webhook-single-source.sh ]]; then
    skip "billing-source guard selftest" "guard not exported to the public repo"
fi
if [[ -f scripts/hooks/protect-two-trackers.sh ]]; then
    skip "two-trackers guard selftest" "guard not exported to the public repo"
fi
if [[ -f scripts/hooks/protect-audit-fail-closed.sh ]]; then
    skip "audit-fail-closed guard selftest" "guard not exported to the public repo"
fi
# A deferred item must be able to come back. The `Review:` convention was referenced
# in and read by nothing, so five rows were deferred with no trigger
# one of them said so in its own text. Prints when a review comes due; blocks only once
# it is 30 days past, so a due date cannot wall off unrelated work on the day it lands.
# Non-blocking reminder: what is still waiting on the founder. Printed here as well
# as at session start because verify-all runs far more often than a session begins,
# and the founder asked to be reminded until the items are done. It NEVER gates —
# a reminder that can fail a build gets removed, and then it reminds nobody.
if [[ "$EXPLAIN" -eq 0 ]] && [[ -f scripts/ops/founder-open-items.sh ]]; then
    bash scripts/ops/founder-open-items.sh || true
fi

if [[ -f scripts/ci/check-review-dates.py ]] && command -v python3 >/dev/null 2>&1; then
    area DOCS
    skip "review-dates" "guard not exported to the public repo"
fi

if [[ -f scripts/ci/check-guard-parity.py ]] && command -v python3 >/dev/null 2>&1; then
    # Two pre-public-push guards, only one enforcing. Selftest first
    # it must PASS when they agree and BLOCK when either drifts.
    area SCRIPTS DOCS
    run "guard-parity"          python3 scripts/ci/check-guard-parity.py
fi
if [[ -f bench/gateway/summary-gate.selftest.mjs ]] && command -v node >/dev/null 2>&1; then
    # The benchmark 2xx gate. Its predecessor was only ever tested for BLOCKING,
    # and shipped unable to PASS any run at all — it read metrics[n].count where
    # k6 puts metrics[n].values.count, on every k6 version. This selftest runs
    # both halves against real captured k6 payloads.
    area SCRIPTS
    run "bench 2xx-gate selftest" node bench/gateway/summary-gate.selftest.mjs
fi
if [[ -f scripts/ci/check-tenant-isolation.py ]] && command -v python3 >/dev/null 2>&1; then
    # Selftest first — it plants violations and asserts the guard reports them.
    # A guard nobody has watched fail is assumed decorative.
    area ALWAYS
    run "tenant-isolation guard"   python3 scripts/ci/check-tenant-isolation.py
fi
# The provider-count doc-comments are a public-facing claim (they leaked
# to the marketing site as "35+ providers"). Hand-maintained, they rot silently —
# the count drifted again within a day of closing, when Vertex landed.
if [[ -f scripts/ci/check-provider-count.py ]] && command -v python3 >/dev/null 2>&1; then
    area RUST
    skip "provider-count guard" "guard not exported to the public repo"
fi
# Counting the providers is not the same as being able to USE them. Groq,
# Together, Fireworks and OpenRouter routed (and counted toward "35") while the
# BYOK allowlist rejected their key upload with 400, so no customer could store
# one. Three hand-maintained lists that must agree — registry, allowlist, dropdown.
if [[ -f scripts/ci/check-byok-provider-coverage.py ]] && command -v python3 >/dev/null 2>&1; then
    area RUST WEB
    run "byok-provider-coverage guard" python3 scripts/ci/check-byok-provider-coverage.py
fi
# `apply_migrations`'s hand-written list IS the definition of a fresh database —
# every Postgres integration test builds its schema from it. Its own comment has
# credited "scripts/ci/check-migration-list-complete.py" since the list drifted
# in 2026-08 (0007-0010 silently skipped). That file did not exist, so the list
# drifted again on 2026-08-18: migration 0029 landed on disk, never reached the
# list, and the api-key mint test died on `column "rate_limit_rpm" does not
# exist` — the identical failure from the identical cause, with a comment in
# between asserting it could not happen. A comment naming a control is not one.
if [[ -f scripts/ci/check-migration-list-complete.py ]] && command -v python3 >/dev/null 2>&1; then
    area RUST
    run "migration-list complete"  python3 scripts/ci/check-migration-list-complete.py
fi
# GWY-42: the provider catalog and everything generated FROM it — the dashboard
# dropdown module and the two published provider tables.
#
# LOCAL ONLY, and that is deliberate. `--check` originally re-fetched
# models.dev and diffed, so the gate went red whenever THEY published — a gate
# failing for a reason that has nothing to do with this repo. A gate that fails
# on someone else's release teaches people to ignore it, and an ignored gate is
# worse than none. What can actually rot locally is `providers.tsv` changing
# without its derived artifacts being regenerated; that is deterministic, and it
# is what this checks. Pulling new providers/prices from upstream is a REFRESH
# (run the script with no flags), not a gate.
if [[ -f scripts/ci/build-provider-catalog.py ]] && command -v python3 >/dev/null 2>&1; then
    area RUST WEB DOCS
    run "provider-catalog freshness"  python3 scripts/ci/build-provider-catalog.py --check
fi
# Concurrent gateway fan-out budget. /dashboard fired EIGHT gateway subrequests
# in one Promise.all, which resolves at the SLOWEST member — so it sampled the
# wide-area tail eight times and took 6s+ per load while the gateway itself
# answered in 0.9ms on-node. No existing gate could see it: the bench suite
# measures GATEWAY latency (green throughout) and nothing measures latency from
# where a customer stands. Selftest first — a guard nobody has watched fail is
# assumed decorative. (runbooks/RCA-dashboard-fanout-tail-latency.md)
if [[ -f scripts/ci/check-page-fanout.py ]] && command -v python3 >/dev/null 2>&1; then
    area WEB
    run "page-fanout guard"        python3 scripts/ci/check-page-fanout.py
fi
# R13 / B-245 §5.2. Past the audit publish the ledger asserts the request happened, so a
# return with no span is a row the tamper-evident record names and the product cannot
# show — ~500 existed fleet-wide, on every tenant, with no instrument reporting one.
# Selftest first, and it must be seen BLOCKING: this guard's own first draft passed the
# real file for the wrong reason.
if [[ -f scripts/ci/check-post-ledger-span-emit.py ]] && command -v python3 >/dev/null 2>&1; then
    area RUST
    run "post-ledger span-emit guard"    python3 scripts/ci/check-post-ledger-span-emit.py
fi
# R21 / 2026-08-15. `spawn_anchor_age_sweeper` was committed fully built, documented and
# unit-tested with NOTHING calling it, and reached the tip of main that way. Clippy cannot
# see it — crates/gateway/{main,lib}.rs carry crate-wide #![allow(dead_code)] — knip is
# apps/web only, and every other server.rs guard checks content INSIDE a named function
# rather than whether one is reached. So a background task with no caller passed every
# gate here and every job in ci.yml. Falsified against the REAL file: removing the wiring
# reproduces the 70ea128c state and this goes RED naming the function.
if [[ -f scripts/ci/check-background-task-wiring.py ]] && command -v python3 >/dev/null 2>&1; then
    run "background-task wiring guard"    python3 scripts/ci/check-background-task-wiring.py
fi
# Mirrored from ci.yml: these guards were CI-ONLY and therefore enforced
# NOWHERE while the CI workflow was disabled (dark 2026-06-20→). Local gate now
# carries the load-bearing ones so a disabled CI can't silently un-guard them.
area RUST WEB
run "tenant-id-provenance guard"   bash scripts/ci/check-tenant-id-provenance.sh
area INFRA
run "prod-nats-wiring guard"       bash scripts/ci/check-span-publish-wiring.sh
run "genai-attr-keys guard"        bash scripts/ci/check-genai-attr-keys.sh
area ALWAYS
run "no-e2e-auth-in-prod guard"    bash scripts/ci/no-e2e-auth-in-prod.sh
# A Playwright storage-state dump reached the PUBLIC mirror on 2026-08-17 because
# `apps/web` is an allowlisted export tree and gitleaks cannot see Iron-encoded
# cookie values. Filename rule, selftested.
run "no tracked session state"    python3 scripts/ci/check-no-session-state-files.py
if command -v python3 >/dev/null 2>&1; then
    area RUST
    run "span-publish-ordering guard" python3 scripts/ci/check-span-publish-ordering.py
    area RUST WEB
    skip "no-internal-refs-in-ui guard" "guard not exported to the public repo"
    area WEB
    run "gateway-fallback guard"       python3 scripts/ci/check-no-localhost-gateway-fallback.py
    area ALWAYS
    skip "npm-scope guard" "guard not exported to the public repo"
    # Sub-processor disclosure: if tracked CONFIG enables a third-party processor, the
    # legal tables must disclose it in the SAME commit. PostHog is wired in
    # kill_switch.rs but dormant (key unset) and undisclosed — exactly the state that
    # ships a silent disclosure gap the day someone sets the key. Selftest plants an
    # enabling line and proves it blocks, then proves it passes once disclosed.
    run "subprocessor guard"           python3 scripts/ci/check-subprocessor-disclosure.py
    # Doc classification: every .md/.mdx in the export set carries a tag, and no
    # CONFIDENTIAL/RESTRICTED doc sits inside it. MUST be here, not only in ci.yml:
    # private-repo CI skips the root jobs on a direct push, so this hook is the only
    # place the gate actually runs. Selftest first — it plants an untagged file, a
    # CONFIDENTIAL one and a bogus level, and proves each blocks.
    area DOCS SCRIPTS
    skip "doc-classification guard" "guard not exported to the public repo"
    # CLAUDE.md is always-resident, so a `file.rs:882` anchor in it is read as fact by
    # every session and rots the moment a line is inserted above it. W1 (2026-08-21)
    # found the §2 hot-path map citing `server.rs:882-1712` for a handler that is at
    # 1327, nine step offsets pointing at unrelated code, and one Evidence anchor naming
    # the WRONG FILE. Selftest first, per the same-commit rule for a new guard; its
    # cases 1/2/4 are the shapes a `crates/.*:[0-9]+` pattern would have missed entirely.
    skip "claudemd-anchor guard" "guard not exported to the public repo"
    # Every rendered metric TILE must be documented in docs/product/ (CLAUDE.md §16:
    # "the exact semantics AND source of every number displayed"). Earned 2026-08-17: that
    # rule had existed since 2026-08-12 while DASHBOARD.md documented ZERO of the ~17
    # metrics it renders, because §16 only obliges a spec BEFORE a build and nothing ever
    # walked the rendered surface. Two real defects were living in the gap. Selftest first,
    # per the same-commit rule for a new guard.
    skip "metric-docs guard" "guard not exported to the public repo"
    skip "surface-index freshness" "guard not exported to the public repo"
    # ADR-051 is the billing/EE split and has NO design authority; the design system is
    # ADR-053 -> ADR-074. That mix-up recurred EIGHT times (two brief-level, TopNav.tsx,
    # Lollipop.tsx, ADR-074's own supersession line, 2x, 2x the redesign spec)
    # and each correction was followed by another. CLAUDE.md §12: a recurrence needs a
    # gate, not a fifth note. The selftest proves both halves — it BLOCKS an uncorrected
    # design-context cite and ADMITS a billing cite, a correction, and an opt-out.
    area ALWAYS
    skip "ADR-051 miscite guard" "guard not exported to the public repo"
    # B-252: 4088da73 deleted logo-icon-{light,dark}.png and left three references — the
    # apple-touch icon and BOTH PWA icons 404'd in production for months. Next never
    # resolves metadata.icons at build time and a 404 favicon breaks no test, so nothing
    # failed. This asserts every referenced /brand/* asset exists; --selftest proves the
    # scanner is alive (it refuses to pass on an empty scan) and that the asset verifier
    # catches a blank or solid-rectangle icon — the two ways the supplied brand zip failed.
    area WEB
    run "brand icon refs resolve"      python3 scripts/brand/build-brand-assets.py --check-refs
    # The design system's ONLY executable check, and it was wired to nothing until now
    # while carrying two bugs that hid each other: it labelled `:root` (the LIGHT default)
    # as "DARK", then threw on a `[data-theme="light"]` block that has never existed — so
    # it measured light twice, mislabelled, and died before dark. packages/ui/README.md
    # called it "(CI gate)" the whole time. It parses tokens.css at runtime, so it tracks
    # whatever the palette becomes rather than pinning one.
    run "token contrast (WCAG)"        node packages/ui/scripts/contrast-check.mjs
    # ADR-074 §9 listed SEVEN binding engineering constraints and, measured 2026-08-15,
    # ZERO were enforced by anything. The most greppable of them — no blur — was already
    # violated 15x across 8 files under a carve-out written for the ADR it superseded.
    # This gates the three that are a matchable CONSTRUCTION and NAMES the four that are
    # not (per-row shadows, new deps, the CSS delta, the 60fps budget) rather than
    # implying §9 is covered.
    # The retired Chisel mark rendered in FIVE places for a full day AFTER the brand
    # workstream reported done — the assets were correct, the references resolved, every
    # test passed, and the founder found it by looking at the screen. Generating a file
    # is not rendering it, and nothing in the repo knew the difference.
    area ALWAYS
    run "retired logo (ADR-074 §8)"    python3 scripts/ci/check-retired-logo.py
    area WEB
    run "design constraints (§9)"      python3 scripts/ci/check-design-constraints.py
    # R6's REPLACEMENT CONTROL. Consolidation closes instance (a) — the site repo had
    # no CI at all — but it also gives up the one server-side required status check the
    # marketing site ever had: the PUBLIC tracelane/site repo can carry a ruleset, this
    # private monorepo cannot (403, needs GitHub Pro). The founder ruled: replace it with a
    # pre-push gate covering the same surface. This is it.
    #
    # `pnpm lint/typecheck/test` below already reach apps/site (they are --recursive, and
    # apps/site now DEFINES those three scripts — without them consolidation would have
    # gated nothing). This adds the site's own content gates: the four assertions that
    # caught the 2026-07-29 live-site revert, proven discriminating on every run.
    skip "site deploy-gate selftest" "guard not exported to the public repo"
    # The map is generated; a stale map is a lying map. Same reasoning as the guard above:
    # this must live in verify-all (the pre-push hook) because private-repo CI skips the
    # root jobs on a direct push.
    # Selftest FIRST — it proves the generator is deterministic (a flapping --check
    # teaches everyone to ignore it) and that planted drift is actually detected.
    area ALWAYS
    run "claim anchors hold"           python3 scripts/ci/check-claim-anchors.py
    area DOCS RUST WEB
    run "doc cross-doc consistency"    python3 scripts/ci/check-doc-consistency.py
    area DOCS
    run "index parity + links"         python3 scripts/ci/check-index-parity.py
    area ALWAYS
    run "spec anchors"                 python3 scripts/ci/check-spec-anchors.py
    # ADR-062 anchoring honesty over apps/web + apps/docs. It has the best falsification
    # battery in the tree — 12 cases, clause-scoped so a deferral in a NEIGHBOURING clause
    # cannot launder an over-claim — and until 2026-08-15 it was invoked by NOTHING: not
    # verify-all, not a hook, not any ci.yml job. A guard nobody runs is a guard that does
    # not exist, and this one protects the sentence R21 changes the behaviour behind.
    area WEB DOCS
    run "anchoring claims"             python3 scripts/ci/check-anchoring-claims.py
    # The EVENT trigger for docs: a stamped doc whose CITED LINES changed since its stamp.
    # check-spec-anchors proves an anchor RESOLVES (true while the code under it changes
    # completely) and check-review-dates enforces a 180-day full-review CLOCK; neither
    # fires when the code actually moves. Wired only after the 6 docs / 13 anchors it
    # found on its first run were fixed, so it starts GREEN rather than with a baseline.
    area ALWAYS
    skip "doc freshness (cited code)" "guard not exported to the public repo"
    area DOCS
    skip "doc-index freshness" "guard not exported to the public repo"
    # Promotion gate selftest only — the gate itself is NOT run here. Its verdict depends
    # on adversarial-pass currency, which is deliberately allowed to be stale between
    # promotions; failing every push on that would be noise. The selftest proves the two
    # hard blockers still fire.
    area DOCS SCRIPTS
    skip "promotion-gate selftest" "guard not exported to the public repo"
    # Offline banned-link guard (no network here — the merge gate must stay
    # offline/fast). The full liveness+identity pass runs pre-deploy in web.sh.
    area WEB
    run "external-link guard"          python3 scripts/ci/check-external-links.py --static
    # AFT-1 vocabulary: detectors ⊆ taxonomy map, live⟺detector, seeder ⊆ map —
    # the canonical-id vocabulary can never silently drift from the detectors again.
    area RUST WEB SCRIPTS
    run "aft-vocabulary guard"         python3 scripts/ci/check-aft-vocabulary.py
    # Exactly ONE model→provider prefix table (provider_id_for_model); the
    # dispatch + key-lookup + span-attribution must delegate to it. A second table
    # is the cross-provider BYOK-misroute drift surface.
    area CI
    run "action-sha-pin guard"      python3 scripts/ci/check-action-sha-pins.py
    # These three ran in ci.yml's `guards` job and NOWHERE else. With the private
    # repo skipping all 14 jobs on push and the public workflow invalid since
    # 2026-08-04, they were executing on no push path at all. Mirrored here so the
    # pre-push hook covers them regardless of what CI does.
    area INFRA
    run "dockerfile-digest guard"      python3 scripts/ci/check-dockerfile-digest-pins.py
    area DOCS SCRIPTS
    run "docs-site guard"              python3 scripts/ci/check-docs-site.py
    area ALWAYS
    run "tenants-pk-column guard"      bash scripts/ci/check-tenants-pk-column.sh
    # A dangling `needs:` makes GitHub reject the WHOLE workflow — zero jobs, no step
    # to diagnose. That shape hid five days of dead public CI (2026-08-04 → 08-09).
    area CI
    run "workflow job-graph"           python3 scripts/ci/check-workflow-job-graph.py
    # THE META-GATE. Every scripts/** guard invoked above must (a) reject an unknown flag
    # and (b) pass its own --selftest. 20 scripts used to accept `--selftest` silently and
    # exit 0 having proven nothing, so every falsification claim in this repo was
    # unverified. (a) is what makes (b) evidence: a script with no argv parsing returns 0
    # for both, indistinguishable from a passing selftest. ~8s for all 34.
    # The alertable-metric list lives in SIX places (Rust const, checker match, Postgres
    # CHECK, web proxy allowlist, UI meta map, UI dropdown). They drifted: overhead_p99
    # was accepted by the CHECK and the gateway and 422'd by the web proxy, so migration
    # 0017's whole purpose was unreachable and nothing failed.
    # Suppressing a scanner finding is a security DECISION. ~60 suppressions carried a
    # reason but no date of any kind, so every one was permanent by default and the
    # stated reason ("bump in a future sweep") outlived its truth. Same shape as the
    # migration-drift acknowledgements: an override needs a record AND an expiry.
    # Two-trackers-only (CLAUDE.md r9) — prose until now, which is exactly why
    # AUDIT-004 sat "Open (V1.5)" in an unexempted third tracker for ~3 months AFTER
    #  fixed it, on the tamper-evident ledger.
    # R2 endpoints are JURISDICTION-scoped; our bucket is `eu`. The account-default
    # host returns AccessDenied for list AND put, which reads like a bad credential.
    # Third instance of that trap — a false report, a prod config defect, a credential
    # dead end. The propagation path was a doc printing the wrong form.
    # O4 logging policy (.claude/rules/logging.md). At 5,000 rps one 200-byte line per
    # request is ~86 GB/day. A REPEATING condition gets a counter, not a line per
    # occurrence — ingest's LISTEN loop emitted ~300K identical WARNs over 3 weeks.
    area RUST
    run "hot-path logging"             python3 scripts/ci/check-hot-path-logging.py
    # B-256. Three of the four hot-path caches shipped with a TTL SHORTER than the
    # gap between production requests, so none of them ever hit and every request
    # paid the cold path they existed to avoid — 202.3ms measured, against 1.7ms
    # once warm. The same mistake in three modules over months, including one
    # whose doc claims it "mirrors entitlement_cache" while carrying the number
    # entitlement_cache was cured of. Prose did not stop it; this does.
    area RUST
    run "hot-path cache TTL"           python3 scripts/ci/check-hot-path-cache-ttl.py
    area ALWAYS
    run "r2 endpoint jurisdiction"     python3 scripts/ci/check-r2-endpoint-jurisdiction.py
    area DOCS
    skip "tracker discipline" "guard not exported to the public repo"
    # PLT-03/A7. The federation tenant pseudonym is an UNKEYED SHA-256, deferred on
    # the premise that nothing reads the table. This asserts the PREMISE, so the
    # deferral breaks loudly the day a read surface ships — in whatever file ships it.
    # EXE001 has taken CI red TWICE (00a3f089, run 31511826456) — a shebang script
    # committed at mode 644. `ruff check .` cannot catch it here: it asks the
    # filesystem, and WSL2 ext4-on-vhdx answers differently from the CI runner. This
    # reads the mode from `git ls-files -s`, so it gives the same verdict everywhere.
    # The tier-ran assertion is only meaningful if IT can run. Selftest here
    # so the verdict logic is exercised on every local gate, not only in CI.
    area CI
    skip "tier-ran selftest" "guard not exported to the public repo"
    area SCRIPTS
    run "script exec bits"             python3 scripts/ci/check-script-exec-bits.py
    area RUST WEB PY
    skip "federation hash deferral" "guard not exported to the public repo"
    # infra/prod/** is excluded from ci.yml path-filtering; this is the CONDITION on
    # that exclusion — no built-language source may hide under an unchecked path.
    area INFRA
    run "infra-prod no code"           python3 scripts/ci/check-infra-prod-no-code.py
    area ALWAYS
    run "suppression reviews"          python3 scripts/ci/check-suppression-reviews.py
    area RUST WEB
    area RUST WEB CI
    area SCRIPTS
    run "verify-stamp selftest"        bash scripts/ci/check-verify-stamp.sh --selftest
    skip "deploy-provenance selftest" "guard not exported to the public repo"
    # R293. The on-node watchdog carries 48 selftest assertions and NOTHING RAN THEM —
    # it is not under scripts/{ci,hooks,export}, so the meta-gate never saw it, and no
    # `run` line registered it. An unregistered selftest is a claim nobody checks, and
    # this is the file that decides whether prod pages a human. Pure and 0.7s: the block
    # exits before `JSON=$(tlane-status.sh …)`, so it touches no docker, no node, no net.
    skip "watchdog selftest" "guard not exported to the public repo"
    # R306. The class with 40+ recorded instances and, until now, no gate for its most
    # expensive shape: a guard inside a script asserting over that same script, with a
    # pattern its OWN LINE satisfies. The existing hook only sees `pgrep`/`ps|grep` in
    # Bash TOOL CALLS — seven instances landed in scripts/ops/ after it went live.
    run "self-matching assertions"     python3 scripts/ci/check-self-matching-assertions.py
    # This one lives under infra/prod/ rather than scripts, but its
    # selftest is pure (no ClickHouse, no network) and registering it here is what
    # makes it RUN — an unregistered selftest is a claim nobody checks. It proves
    # the daily cutover alert refuses to fire against a time-only table, which is
    # the defect it shipped with for months.
    area INFRA
    run "partition-cutover selftest"   bash infra/prod/partition-cutover-check.sh --selftest
    area ALWAYS
    skip "never-say-again selftest" "guard not exported to the public repo"
    area RUST WEB
    run "alert-metrics single-source"  python3 scripts/ci/check-alert-metrics-single-source.py
    # GWY-41: the API-key scope vocabulary is spelled in the Rust enum, the mint
    # dialog and a Postgres column comment. A scope missing from the UI is a
    # capability no customer can grant; a UI checkbox for a slug Rust refuses is a
    # permission that silently denies. Caught real drift on its first run.
run "plan-write single-source"          python3 scripts/ci/check-plan-write-single-source.py
    run "api-scope single-source"      python3 scripts/ci/check-api-scope-single-source.py
    # GWY-41: a `#[cfg(not(debug_assertions))]` test cannot run under `cargo test`
    # (cfg(test) implies debug_assertions), so it runs ONLY where a job invokes its
    # package with --release. Moving the decoder to `shared` moved the release
    # tenant-isolation guard out of the one job that ran it, and that job stayed
    # green with 168 passing tests and zero of them being that one.
    area RUST WEB CI
    skip "release-only tests covered" "guard not exported to the public repo"
    area SCRIPTS
    # ── time-2: SELFTEST DIFF-GATING IS COMMIT-STAGE ONLY ────────────────────
    # A guard's selftest answers "does this guard still detect its violation?" — an
    # answer that can only change when the guard, or a config the guard READS,
    # changes. At commit time we therefore selftest what the diff touched and
    # existence-check the rest.
    #
    # THE PUSH GATE IS NEVER DIFF-GATED, AND THIS IS THE LOAD-BEARING HALF.
    # Private-repo CI SKIPS its root jobs on a direct push (ci.yml gates them on
    # `github.repository == 'tracelane/tracelane' || event_name != 'push'`), so
    # `.githooks/pre-push` is the ONLY enforcement a pushed commit ever meets. If the
    # push gate honoured the diff, a guard that rotted two commits ago would never be
    # re-checked before the code left this machine — the commit that broke it and the
    # push that ships it are different diffs. So: commit may skip, push may not.
    #
    # THE META-GATE'S OWN SELFTEST IS NEVER DIFF-GATED AND NEVER DELETED. It is now the
    # single point of selftest coverage for all 78 guards, so an unverified meta-gate is
    # an unverified everything. Deleting this line as a "duplicate" removed the only
    # check on the root of trust — caught here, restored, and it stays.
    run "guard-selftest meta-gate selftest" python3 scripts/ci/check-guard-selftests.py --selftest
    # ONE LINE PER INVOCATION, deliberately: `invoked_guards()` matches `run "..." <runner>
    # <script>` on a SINGLE line, so a `\`-continuation makes the script invisible to
    # discovery. Wrapping these two cost the meta-gate its own place in the list (79 -> 78).
    if [[ "$COMMIT_STAGE" -eq 1 ]]; then
        run "guard-selftest meta-gate (commit stage)" python3 scripts/ci/check-guard-selftests.py --changed-only
    else
        run "guard-selftest meta-gate (FULL)" python3 scripts/ci/check-guard-selftests.py
    fi
    # The scoping map is itself a control now: --scoped decides WHICH of the steps in
    # this file run, so a mis-declared `area` is a coverage change nobody would see. Its
    # selftest drives the REAL classifier and asserts BOTH directions — a scripts/ change
    # runs the meta-gate, a docs-only change does not.
    skip "verify-all scoping" "guard not exported to the public repo"
    area RUST
    run "provider-mapping guard"       python3 scripts/ci/check-provider-mapping-single-source.py
    # Migration drift. What runs here is the detector's own proof that it
    # BLOCKS — planted drift, a refused reasonless acknowledgement, and an expired
    # PENDING. Without this the gate could rot to always-pass.
    #
    # THE LIVE HALF HAS NO RUNNER — corrected 2026-08-13. This comment used to say
    # it "runs in the deploy pre-flight (scripts/ops/tlane-migration-drift.sh)".
    # That file has never existed, and no deploy script invokes
    # `audit-migration-drift.py --live`, so nothing compares the catalog to a real
    # database. The selftest below is therefore proof the DETECTOR works, not
    # evidence that drift is being detected — and reading it as the latter is
    # exactly the gap it was written to close, on the seam CLAUDE.md §5 names
    # (migrations 0009+ are un-journaled; a column lands in Neon BEFORE the
    # gateway that reads it deploys).
    #
    # Until it is wired, the live check is manual and needs DB credentials:
    #   psql "$POSTGRES_URL" -Atc "$(python3 scripts/ci/audit-migration-drift.py \
    #        --catalog-sql)" > /tmp/live.tsv
    #   python3 scripts/ci/audit-migration-drift.py --live /tmp/live.tsv
    # Tracked as a row in.
    area WEB INFRA
    run "migration-drift selftest"     python3 scripts/ci/audit-migration-drift.py --selftest
    # No UI/API reads of dead/legacy entitlement columns (tenants.auditEnabled) —
    # the "invisible entitlement-gated UI" class (internal incident review).
    area WEB
    run "legacy-entitlement-column guard" python3 scripts/ci/no-legacy-entitlement-columns.py
fi

# ── TypeScript / Node ─────────────────────────────────────────────────────────
# CI's `web` job builds the audit-verifier workspace pkg before tsc (apps/web tsc
# resolves @tracelanedev/audit-verifier types from its dist). Mirror it.
run "build @tracelanedev/audit-verifier" pnpm --filter @tracelanedev/audit-verifier build
run "pnpm lint (biome)"            pnpm lint
run "pnpm typecheck"               pnpm typecheck
# R128 (2026-08-24). `pnpm test` is `pnpm --recursive run test` across all 8 workspace
# projects — 41.6 s, 20.9% of a WEB-only commit stage (measured). A WEB diff usually
# touches ONE package, and the other seven cannot be affected by it.
#
# FAILS OPEN IN BOTH DIRECTIONS, because the failure mode of a filter is running NOTHING
# and reporting a pass:
#   · no upstream to bound the diff  -> run every package
#   · the filter selects ZERO projects -> run every package, and SAY SO
# `...[ref]` includes DEPENDENTS, so a change in `packages/ui` still tests `apps/web`.
# Verified 2026-08-24 that the filter sees UNCOMMITTED work (it selected apps/web from a
# dirty tree), which is the case that matters at commit stage.
_pnpm_test() {
    local base sel
    [[ "$SCOPED" -eq 1 ]] || { pnpm test; return $?; }
    base="$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
    if [[ -z "$base" ]]; then
        echo "  pnpm test: no upstream to bound the diff — running EVERY package."
        pnpm test; return $?
    fi
    sel="$(pnpm --recursive --filter "...[$base]" exec pwd 2>/dev/null | grep -c '^/' || true)"
    if [[ "${sel:-0}" -eq 0 ]]; then
        echo "  pnpm test: the changed-package filter selected NOTHING — running EVERY"
        echo "             package rather than none. A filter that matches nothing must"
        echo "             never read as a pass."
        pnpm test; return $?
    fi
    echo "  pnpm test: $sel changed package(s) since $base (dependents included)."
    pnpm --recursive --filter "...[$base]" run test
}
run "pnpm test"                    _pnpm_test
# knip: dead files/deps in apps/web (2026-07-23 — the CLAUDE.md-promised
# dead-code gate, previously wired nowhere). Export-level classes are excluded
# here; they're audited opportunistically, not merge-gated.
run "knip (apps/web files+deps)"   bash -c 'cd apps/web && pnpm exec knip --include files,dependencies,devDependencies --no-config-hints'
# Supply-chain (advisory; network) — mirrors ci.yml secret-scan's pnpm audit.
if command -v pnpm >/dev/null 2>&1; then
    # R131 (2026-08-24). `pnpm.overrides` carries EIGHTEEN security floors, and pnpm 10
# stopped reading the `pnpm` field in package.json. The installed binary here is already
# 11.16.0 and warns on every run; we are safe ONLY because `packageManager: pnpm@9.15.0`
# makes corepack delegate to 9.15.0, which does read it, and because CI pins `version: 9`.
# The day that pin moves, every override stops applying on the next lockfile regeneration
# and NOTHING FAILS — no red, no alert, no advisory reappears for months. This compares
# package.json's overrides against the `overrides:` block the LOCKFILE records, which is
# written by the pnpm that actually did the install: the only evidence of what was really
# read. Exact values — a "looks equivalent" range is a different constraint.
run "pnpm overrides applied"       python3 scripts/ci/check-pnpm-overrides-applied.py
run "pnpm overrides selftest"      python3 scripts/ci/check-pnpm-overrides-applied.py --selftest
run "pnpm audit (high)"        pnpm audit --audit-level=high
fi
# Secret scan — mirrors ci.yml `secret-scan`'s gitleaks. This
# was CI-ONLY: a per-push secret hole whenever CI is dark, and verify-all never
# carried it. Secret detection is the one scan where PUSH-TIME matters (a leaked
# credential committed once is leaked forever, esp. ahead of public extraction).
#
# Scans the CURRENT TRACKED snapshot (`git archive HEAD`), NOT `gitleaks dir .`
# of the working tree: the dirty local tree carries gitignored build output
# (apps/web/.open-next), local tool indexes (.codegraph), and local .env backups
# that gitleaks flags but that NEVER get pushed (55 such FPs locally). The
# archive reproduces exactly what CI's pristine checkout sees (committed content
# only) → FP-free and faithful to the gate. ~2s.
if [[ "$EXPLAIN" -eq 1 ]]; then
    # The archive costs seconds and disk; an explain pass only needs the verdict.
    run "gitleaks (tracked snapshot)" true
elif command -v gitleaks >/dev/null 2>&1; then
    _gl_tmp="$(mktemp -d)"
    git archive HEAD | tar -x -C "$_gl_tmp"
    area ALWAYS
    run "gitleaks (tracked snapshot)" gitleaks dir "$_gl_tmp" --no-banner --config .gitleaks.toml
    rm -rf "$_gl_tmp"
else
    skip "gitleaks secret scan" "gitleaks not installed — brew install gitleaks / go install github.com/gitleaks/gitleaks/v8@latest"
fi
# SPANS <-> TRACE_SUMMARIES INTEGRITY. The probe existed, was correct, and had
# ZERO CALLERS from the day it landed — then found 26 real orphan summaries on
# prod the first time anyone ran it (TRAPS §1 CLASS-1, and the cheapest of the
# week to close). verify-all runs its SELFTEST, which plants an orphan in a
# THROWAWAY ClickHouse and requires a red; the REAL prod check runs as a deploy
# proof, because a guard that needs production to prove itself cannot run on
# every push.
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    area RUST INFRA
    run "trace-summary consistency selftest" bash scripts/ci/check-trace-summary-consistency.sh --selftest
else
    skip "trace-summary consistency selftest" "docker unavailable — this guard CANNOT run here; it runs in CI and as a deploy proof"
fi
# REAL-POSTGRES integration. `postgres_tenant_integration.rs` covers the only
# path that writes `api_keys` — and it was `#[ignore]`d with ZERO callers in
# either this file or ci.yml, so it had never run. It would have gone red on the
# first execution: A13 shipped `$9::numeric` bound to an `Option<String>`, which
# tokio-postgres refuses on every call, and `POST /v1/keys` returned 500 for two
# days. TRAPS §1 CLASS-1 — a control that never ran. Prove it bites with
# `scripts/ci/run-postgres-integration.sh --selftest`.
# ── R142/R144: PUSH-ONLY, NOT PER-COMMIT — and NOT NARROWED BY PATH. ──────────
#
# THE WINDOW THIS OPENS, stated in hours because a scheduling change that does not
# say what it costs is a coverage change wearing a disguise: a defect these suites
# would catch now survives from COMMIT until PUSH. Under R141 (one push per work
# block) that is the length of a work block — HOURS, not minutes.
#
# THE THREE DEFECTS THAT MAKE THAT A REAL COST, named so nobody re-litigates this
# cheaply. All three were caught by these suites, in ONE run, on 2026-08-24:
#   B-272  a `WHERE` reading its own `toString(...)` alias — every dataset read 502'd
#   B-273  `CacheRow` declaring FixedString(64) columns as String, so the RowBinary
#          block desynchronised on the first field and every write failed silently
#   B-274  the READ side of B-273, fixed only on the write side, so `read_item`,
#          `list_items` and `all_items` were all broken live on prod
# None is visible to a mock, and none is visible to a string assertion. The bytes on
# the wire are the whole subject.
#
# WHY THIS IS SAFE NOW AND WAS NOT BEFORE: the nightly full gate (R145) runs the
# UNSCOPED gate against main every night and alerts through the watchdog naming the
# failing step. R144(a) required that be OBSERVED red before this moved, and it was —
# planted defect, "preflight refused: ✗ doc freshness (cited code)", delivered via
# SMTP. So the outer bound on any window here is 24h, on a control proven to speak.
#
# GATED ON THE STAGE, NEVER ON PATHS (R144(b)). 31 of 118 gateway files carry a Row
# derive and none of them is in `db/`, so "does this diff touch a row struct" is not a
# question a path list can answer — R124(b). At PUSH these run unconditionally.
if [[ "$COMMIT_STAGE" -eq 1 ]]; then
    skip "api-key mint (real Postgres)" "PUSH-ONLY (R142): 85s, runs unconditionally at push and nightly"
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    area RUST MIGRATIONS
    run "api-key mint (real Postgres)" bash scripts/ci/run-postgres-integration.sh
else
    skip "api-key mint (real Postgres)" "docker unavailable — this guard CANNOT run here; CI runs it with a postgres service"
fi
# A PROOF'S PRINTED VERDICT AND ITS EXIT VERDICT ARE TWO SEPARATE CLAIMS (R105,
# 2026-08-23). `overhead-proof.sh` printed a PASS and exited 1 (deploy ROLLS BACK a healthy
# release); `audit-live-proof.sh` printed `RESULT: ✗` and exited 0, so gateway.sh's
# `|| { rollback; die }` never fired and a deploy with an unverified AUDIT CHAIN printed
# ✅ DEPLOY GREEN. Both directions, one week, and the correct sibling `anchor-live-proof.sh`
# is what made the gap invisible. Static, no docker, milliseconds.
area SCRIPTS INFRA
run "proof exit-verdict agreement" python3 scripts/ci/check-proof-exit-verdicts.py
run "proof exit-verdict selftest"  python3 scripts/ci/check-proof-exit-verdicts.py --selftest

# REAL-CLICKHOUSE integration (founder ruling R97, 2026-08-23). Every one of the
# 49 dataset tests drives a MOCK STORE, so 49 green tests, a clean gate and a
# successful deploy shipped B-272 (alias shadowing killed every read) and B-273
# (a FixedString(64) written as a String killed every write) to production in one
# night. The bytes on the wire are the whole subject and no mock inspects them.
#
# Its first real run found a THIRD instance, live on prod: the read side of
# B-273, which had been fixed only on the write side, so `read_item`,
# `list_items` and `all_items` were all broken on `6e05b0aa` (B-274). Prove it
# bites with `scripts/ci/run-clickhouse-integration.sh --selftest`.
# PUSH-ONLY (R142/R144) — see the window note above the Postgres suite. Same trade,
# same 24h outer bound via the nightly, same refusal to narrow by path.
if [[ "$COMMIT_STAGE" -eq 1 ]]; then
    skip "dataset round trip (real ClickHouse)" "PUSH-ONLY (R142): 100s, runs unconditionally at push and nightly"
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    area RUST
    run "dataset round trip (real ClickHouse)" bash scripts/ci/run-clickhouse-integration.sh
else
    skip "dataset round trip (real ClickHouse)" "docker unavailable — this guard CANNOT run here"
fi
if [[ "$WITH_EVAL_SUITE" -eq 1 ]]; then
    area PY
    run "pnpm eval:run --suite=all" pnpm eval:run --suite=all
else
    # Opt-in, not opt-out. Under `--fast` this was skipped by both callers, so it has
    # never run locally; CI runs it as the "Eval Suite (Merge Gate)" job. Naming it
    # opt-in stops the gate pretending to a coverage it does not have.
    skip "pnpm eval:run --suite=all" "opt in with --with-eval-suite; CI runs it"
fi

# ── Python ────────────────────────────────────────────────────────────────────
# ruff was CI-ONLY (ci.yml `python` job) — dark with CI. Mirror it.
#
# The local ruff MUST be the version ci.yml pins, or this is not a mirror of the
# gate — it is a different tool reporting green while CI reports red. That is not
# hypothetical: local ruff 0.15.15 passed `scripts/ci/check-byok-provider-coverage.py`
# while CI's pinned 0.16.0 failed it with 3× FURB167 (`re.S` -> `re.DOTALL`), and
# the public push went out red. The pin is read FROM ci.yml so there is one source
# of truth and this cannot drift silently again.
if command -v ruff >/dev/null 2>&1; then
    # Single source of truth for the pin moved into the hash-pinned CI
    # requirements file. Read it from there, and FAIL LOUD if it cannot be
    # found — a silent empty pin turns this mirror check into a no-op, which
    # is the CLASS-1 shape the check exists to avoid.
    _ruff_req=scripts/ci/requirements/python-ci.txt
    _ruff_pin=$(grep -oE '^ruff==[0-9]+\.[0-9]+\.[0-9]+' "$_ruff_req" 2>/dev/null | head -1 | cut -d= -f3)
    if [ -z "${_ruff_pin:-}" ]; then
        echo "  ruff pin NOT FOUND in $_ruff_req — cannot mirror CI" >&2
    fi
    _ruff_have=$(ruff --version 2>/dev/null | awk '{print $2}')
    if [[ -n "$_ruff_pin" && -n "$_ruff_have" && "$_ruff_pin" != "$_ruff_have" ]]; then
        skip "ruff" "VERSION MISMATCH: local $_ruff_have, ci.yml pins $_ruff_pin — this check is NOT the CI gate. Run: pip install ruff==$_ruff_pin"
    else
        area PY SCRIPTS
        run "ruff check"               ruff check .
        run "ruff format --check"      ruff format --check .
    fi
else
    skip "ruff" "ruff not installed"
fi
if [[ "${SKIP_PY:-0}" == "1" ]]; then
    skip "pytest" "SKIP_PY=1"
elif command -v pytest >/dev/null 2>&1; then
    area PY
    run "pytest"                   pytest -q
elif python3 -c "import pytest" >/dev/null 2>&1; then
    run "pytest"                   python3 -m pytest -q
else
    skip "pytest" "pytest not installed — install: pip install -e 'evals[dev]' or pip install pytest"
fi

# An explain pass has now printed a verdict per step and executed nothing. It stops
# here: it must never write a .verify-stamp, because that stamp is what lets a commit
# through and nothing was verified.
[[ "$EXPLAIN" -eq 1 ]] && exit 0

# ── summary ───────────────────────────────────────────────────────────────────
echo
echo "═════════════════════════ verify-all summary ═════════════════════════"
for i in "${!NAMES[@]}"; do
    printf "  %-32s %s\n" "${NAMES[$i]}" "${STATUSES[$i]}"
done
echo "═══════════════════════════════════════════════════════════════════════"
# A SKIP is NOT coverage, and "ALL GREEN" must never be printed as if it were.
#
# FOUNDER, 2026-08-14: "a guard that silently disappears on a machine without
# docker is armed only where it is already safe." Both the real-Postgres mint
# integration and the trace-summary consistency selftest need docker; on a host
# without it they skipped and the run still read ALL GREEN — full coverage, from
# a run that had two fewer guards.
#
# This deliberately does NOT turn a missing tool into a RED: a legitimate
# docker-less environment should not be unable to push. It makes the gap LOUD
# instead of silent, which is the honest half — the same distinction as Proof C's
# loud skip in the deploy script.
_skipped=()
for i in "${!NAMES[@]}"; do
    [[ "${STATUSES[$i]}" == "SKIP" ]] && _skipped+=("${NAMES[$i]}")
done
if [[ "$overall" -eq 0 ]]; then
    if (( ${#SCOPED_OUT[@]} > 0 )); then
        # A SCOPED run is a DIFFERENT verdict from a full one, and it must never
        # borrow the full one's words. `ALL GREEN` after skipping 78 of 120 steps
        # is the exact sentence that turns a scheduling optimisation into a lie —
        # so it is unreachable while anything was scoped out, and the exit code
        # carries no claim beyond "what ran, passed".
        echo "SCOPED GREEN — ${#SCOPED_OUT[@]} of ${#NAMES[@]} step(s) DID NOT RUN."
        echo "  Areas touched by the diff: ${CHANGED_BUCKETS[*]}"
        echo "  This is NOT full coverage and must never be reported as ALL GREEN."
        echo "  The full gate runs on push (.githooks/pre-push passes no --scoped)."
        if [[ -n "${VERIFY_ALL_LIST_SCOPED_OUT:-}" ]]; then
            for n in "${SCOPED_OUT[@]}"; do echo "    · $n"; done
        else
            echo "  Set VERIFY_ALL_LIST_SCOPED_OUT=1 to list every step that was skipped."
        fi
        if (( ${#_skipped[@]} > 0 )); then
            echo "  Additionally ${#_skipped[@]} check(s) SKIPPED (missing tool / opt-in):"
            for n in "${_skipped[@]}"; do echo "    · $n"; done
        fi
    elif (( ${#_skipped[@]} > 0 )); then
        echo "GREEN — but ${#_skipped[@]} check(s) DID NOT RUN in this configuration:"
        for n in "${_skipped[@]}"; do echo "    · $n"; done
        echo "  Reasons differ — a missing tool, or an opt-in step deliberately deferred"
        echo "  suite — and the distinction matters, so each line names its own. Either way"
        echo "  this run is NOT full coverage: report it as such, never as ALL GREEN."
    else
        echo "ALL GREEN ✔"
    fi
else
    echo "FAILURES PRESENT ✗ — do not merge"
fi

# ── the STAMP (§1.14 control, 2026-08-10) ─────────────────────────────────────
# SIXTH instance of one reporting defect, and the first was `tail -4` discarding a
# gate's failure reason — same command, same shape, AFTER the rule was written and
# AFTER ci-status.sh shipped:
#
#     bash scripts/verify-all.sh | tail -5 && git commit ...
#
# `&&` reads the exit code of `tail`, which is 0 whatever this script did. The gate
# printed "FAILURES PRESENT ✗" and the commit went through anyway.
#
# A note did not stop it, so this is the control: the REAL exit code is recorded
# here, next to a hash of the tree it was computed over, and `.githooks/pre-commit`
# refuses to commit without a matching exit-0 stamp. Whatever a pipeline reports,
# the recorded status is this script's own `$?`.
#
# The hash is the WORKTREE'S TREE OBJECT, computed by the guard itself (`--tree-hash`)
# so writer and checker share ONE definition and cannot drift. It is invariant across
# `git add` AND across `git commit` — so one verify-all legitimately covers a series of
# commits that split the same verified worktree — and it changes the instant any file
# content changes.
#
# HONEST LIMIT, and it is the right one to state: this constrains the COMMIT PATH,
# not the shell. Nothing here stops a human or an agent misreading a pipeline; it
# stops the misreading from becoming a commit. `--no-verify` bypasses it, which
# CLAUDE.md §1.15 already prohibits outside a production incident.
_stamp_file="$(git rev-parse --show-toplevel 2>/dev/null)/.verify-stamp"
if [[ -n "${_stamp_file#/}" ]] && git rev-parse --git-dir >/dev/null 2>&1; then
    # A SCOPED run still stamps — that is the point of the founder's ruling: iterate and
    # commit locally at 22s, and let the pre-push hook run the full gate before anything
    # leaves the machine. But the stamp RECORDS which it was, so the provenance of a
    # commit is never ambiguous after the fact.
    #
    # Appended to the timestamp field on purpose: `check-verify-stamp.sh:79` reads
    # `read -r rc hash when`, so `when` absorbs the remainder of the line. The decision
    # fields (`rc`, `hash`) keep their positions and the checker is untouched.
    #
    # THE SCOPE FIELD IS A DECISION FIELD NOW, not just provenance — `.githooks/pre-push`
    # skips the full gate when it reads exactly "full", so anything that ran FEWER steps
    # must not be able to spell itself that way. `--commit-stage` is the one that could:
    # it swaps the meta-gate for `--changed-only` (line ~753), so it genuinely covers
    # less while touching neither SCOPED_OUT nor CHANGED_BUCKETS. It stamped "full"
    # until 2026-08-22, which would have let a commit-stage run authorise skipping the
    # pre-push gate — the exact "green for a reason unrelated to the mechanism" shape
    # this stamp exists to prevent.
    _stamp_scope="full"
    (( ${#SCOPED_OUT[@]} > 0 )) && _stamp_scope="scoped:${CHANGED_BUCKETS[*]}"
    (( COMMIT_STAGE == 1 )) && _stamp_scope="commit-stage/${_stamp_scope}"
    _stamp_hash="$(bash scripts/ci/check-verify-stamp.sh --tree-hash 2>/dev/null)"

    # THE STAMP MUST NOT DOWNGRADE ITSELF (2026-08-22). Coverage on a FIXED tree is
    # monotonic: if the full gate passed on these exact bytes, a later scoped or
    # commit-stage pass on the SAME bytes does not make that less true. Without this,
    # the ordering defeats the whole optimisation — you run the full gate, then
    # `.githooks/pre-commit` runs `--commit-stage --scoped`, that overwrites the scope
    # with a weaker value, and `pre-push` dutifully re-runs the full gate it already had.
    #
    # ONLY A PASS MAY BE PRESERVED, and only for an IDENTICAL tree hash. A FAILING run
    # always overwrites: a failure is new information and must never be masked by an
    # older green. That asymmetry is the safety property — this can only ever preserve
    # a stronger TRUE claim, never suppress a false one.
    # STRENGTH, not equality. The first version of this rule only preserved "full",
    # which left a hole that showed up the moment the scoped push path was used for
    # real: you run `--scoped` (16s, stamps `scoped:DOCS`), then `git commit` fires
    # pre-commit, which runs `--commit-stage --scoped` and re-stamps
    # `commit-stage/scoped:DOCS` — a WEAKER run, because commit-stage diff-gates the
    # guard meta-gate. `--push-ready` then refused it and the push ran the full gate
    # anyway. The optimisation was defeated by the ordinary commit flow.
    #
    #   full (3)  >  scoped:… (2)  >  commit-stage/… (1)
    #
    # Same tree + both green => keep the stronger claim. Buckets cannot conflict at
    # equal strength: they are classified from the tree, and the tree hash matched.
    _scope_rank() { case "$1" in full) echo 3 ;; commit-stage/*) echo 1 ;; scoped:*) echo 2 ;; *) echo 0 ;; esac; }
    if [[ "$overall" -eq 0 ]] && [[ -f "$_stamp_file" ]]; then
        read -r _p_rc _p_hash _p_ts _p_scope < "$_stamp_file" 2>/dev/null || true
        if [[ "${_p_rc:-1}" == "0" && "${_p_hash:-}" == "$_stamp_hash" ]]; then
            if [[ "$(_scope_rank "${_p_scope:-}")" -gt "$(_scope_rank "$_stamp_scope")" ]]; then
                _stamp_scope="${_p_scope}"
            fi
        fi
    fi

    printf '%s %s %s %s\n' \
        "$overall" \
        "$_stamp_hash" \
        "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
        "$_stamp_scope" \
        > "$_stamp_file" 2>/dev/null || true
fi

exit "$overall"
