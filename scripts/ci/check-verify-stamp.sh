#!/usr/bin/env bash
# check-verify-stamp — the commit path may only trust verify-all.sh's REAL exit code.
#
# WHY (earned 2026-08-10, the SIXTH instance of one reporting defect — and the first
# instance was `tail -4` discarding a gate's failure reason, i.e. the same command and
# the same shape, AFTER CLAUDE.md §1.14 was written and AFTER ci-status.sh shipped):
#
#     bash scripts/verify-all.sh | tail -5 && git commit -F- <<'MSG' ...
#
# `&&` reads the exit status of `tail`, which is 0 no matter what verify-all did. The
# gate printed "FAILURES PRESENT ✗ — do not merge" and the commit landed anyway.
#
# Four memory notes preceded a fifth instance; that is why ci-status.sh exists rather
# than a sixth note. This is the same lesson applied to the COMMIT path: verify-all.sh
# records its own `$?` next to a hash of the tree it ran on, and this gate refuses any
# commit without a matching exit-0 stamp. Whatever a pipeline claims, the recorded
# status is the gate's own.
#
# THE HASH is the WORKTREE'S TREE OBJECT — the git identity of the file contents on
# disk, computed in a throwaway index so the real one is untouched.
#
# It has to be content identity, not `HEAD + git diff HEAD`, which was the first
# attempt: that representation changes the moment you commit (HEAD moves, the diff
# shrinks) even though the files on disk are identical. One verify-all would then
# cover only the FIRST commit of a series and spuriously block the rest. A tree hash
# is invariant across `git add` and across `git commit`, and changes the instant any
# file content changes — which is exactly the property being asserted: "verify-all
# passed on these bytes."
#
# Computed ONCE here and consumed by verify-all.sh via `--tree-hash`, so the writer
# and the checker cannot drift apart. (That drift is not hypothetical: the same week,
# `caps_write_allowed` carried a comment claiming it delegated to one definition while
# inlining a stale copy of it.)
#
# HONEST LIMIT, stated because it is the right one to state: this constrains the COMMIT
# PATH, not the shell. Nothing here prevents a human or an agent from misreading a
# pipeline; it prevents the misreading from becoming a commit. `--no-verify` bypasses
# it, which CLAUDE.md §1.15 already prohibits outside a production incident.
#
# EXIT: 0 stamp is valid for this tree · 1 missing / failed / stale stamp

set -uo pipefail

tree_hash() {
    local idx; idx="$(mktemp)"
    # read-tree + add -A against a THROWAWAY index: the real index, and therefore
    # whatever the user has staged, is never touched.
    GIT_INDEX_FILE="$idx" git read-tree HEAD 2>/dev/null \
      && GIT_INDEX_FILE="$idx" git add -A 2>/dev/null \
      && GIT_INDEX_FILE="$idx" git write-tree 2>/dev/null
    local rc=$?
    rm -f "$idx"
    return $rc
}

# ARGV IS PARSED STRICTLY, and an unknown flag is an ERROR — not a silent fallthrough
# to the default check. Caught by `check-guard-selftests.py` on this guard's very first
# run: a script that exits 0 for `--any-nonsense-flag` cannot prove anything with
# `--selftest`, because the selftest pass is indistinguishable from "this script
# ignores its arguments". It also made the meta-gate look FLAKY — the verdict flipped
# with the stamp's contents rather than with the code — which is how a real defect
# nearly got written off as transient.
case "${1:-}" in
    "")           : ;;                       # default: check the stamp
    --tree-hash)  tree_hash; exit $? ;;
    --full-gate-current) : ;;                # handled below
    --push-ready) : ;;                       # handled below
    --selftest)   : ;;                       # handled below
    *)            echo "check-verify-stamp: unknown option: $1" >&2; exit 2 ;;
esac

# `check <stamp_file> <expected_tree_hash>` — the whole decision, one function, so the
# selftest drives exactly what the hook drives.
check() {
    local stamp="$1" want="$2" rc hash when
    if [ ! -f "$stamp" ]; then
        echo "✗ no .verify-stamp — verify-all.sh has not run on this tree." >&2
        echo "  Run: bash scripts/verify-all.sh" >&2
        return 1
    fi
    read -r rc hash when < "$stamp"
    if [ "${rc:-1}" != "0" ]; then
        echo "✗ verify-all.sh last exited ${rc:-?} (at ${when:-?}) — it FAILED." >&2
        echo "  A pipeline may have reported success; the gate did not." >&2
        return 1
    fi
    if [ "${hash:-}" != "$want" ]; then
        echo "✗ .verify-stamp is for a DIFFERENT tree (stamped ${when:-?})." >&2
        echo "  The tree changed since verify-all.sh ran. Re-run it:" >&2
        echo "  bash scripts/verify-all.sh" >&2
        return 1
    fi
    return 0
}

# `full_gate_current <stamp_file> <expected_tree_hash>` — "has the FULL gate already
# passed on exactly these bytes?" Exit 0 means a caller may skip re-running it.
#
# WHY THIS EXISTS (2026-08-22): one deploy ran the SAME 101-step suite on the SAME
# unchanged tree three times — pre-commit, pre-push, then scripts/deploy/web.sh. Nothing
# mutates between them, so runs 2 and 3 cannot return information run 1 did not. That was
# most of the wall-clock on a deploy the founder waited hours for.
#
# IT IS DELIBERATELY STRICTER THAN `check`. `check` asks "did the gate pass on this tree"
# and a SCOPED or COMMIT-STAGE run legitimately satisfies it — that is the founder's
# iterate-fast ruling and it stays. This asks the harder question "did the FULL gate
# pass", because the thing being skipped is the full gate. Four ways it must refuse:
#   missing stamp · non-zero exit · a different tree · a run that was not FULL.
# The last one is the load-bearing addition: `--commit-stage` swaps the guard meta-gate
# for `--changed-only`, so it covers less while looking identical from outside. Until
# 2026-08-22 it stamped itself "full"; verify-all.sh now spells it "commit-stage/full"
# and this refuses it. A skip authorised by a weaker run is exactly the defect the stamp
# was built to stop, reintroduced one level up.
full_gate_current() {
    local stamp="$1" want="$2" rc hash ts scope
    [ -f "$stamp" ] || return 1
    read -r rc hash ts scope < "$stamp"
    [ "${rc:-1}" = "0" ]      || return 1
    [ "${hash:-}" = "$want" ] || return 1
    # EXACT match, never a prefix: "commit-stage/full" and "scoped:docs" must both fail,
    # and a `case ... full*` would have passed the first of those.
    [ "${scope:-}" = "full" ] || return 1
    return 0
}

# `push_ready <stamp> <hash>` — may this push reuse the recorded run?
#
# FOUNDER RULING 2026-08-22: "there will be change on marketing page again .. i
# dont want you to run such full test." A CSS change to apps/site was running all
# 101 steps including `cargo test`, `cargo clippy`, `cargo deny`, ruff and pytest
# — none of which can say anything about a stylesheet. That is not rigour, it is
# waste, and a gate whose cost is visibly disproportionate is one people learn to
# bypass (CLAUDE.md §1.15).
#
# THE RULE, and its safety argument, because this is the one place the push gate
# is allowed to be less than total:
#   a FULL run always qualifies;
#   a SCOPED run qualifies ONLY IF every bucket it covered is in {WEB, DOCS}.
#
# Why that subset and no other. `verify-all.sh`'s classifier already fails OPEN in
# every direction that matters: `scripts/verify-all.sh`, `.githooks/*`, `.claude/*`
# and the export files are TRIPWIRES that force a full run, and ANY unclassified
# path forces a full run. So a stamp that says `scoped:WEB DOCS SCRIPTS` is a
# positive assertion that the diff touched nothing outside those trees, and the
# steps a scoped run skipped are precisely the steps that could not have changed.
#
# ── WHY SCRIPTS JOINED, 2026-08-24 (founder ruling R124) ────────────────────
#
# **`{WEB, DOCS}` was never a derived safety boundary. It was the SCOPE OF THE
# REQUEST** — the 2026-08-22 ruling was about iterating on the marketing page
# ("there will be change on marketing page again .. i dont want you to run such
# full test"). Nobody should re-derive a safety rationale for it that never
# existed, which is why this paragraph is here.
#
# The fail-open argument above is SYMMETRIC: `scoped:SCRIPTS` asserts the diff
# touched nothing but `scripts/**` and `bench/**` just as strongly as
# `scoped:WEB` asserts `apps/**`. What is NOT symmetric is the consequence of a
# misfiled `area` declaration, and that is a judgement, not a property.
#
# MEASURED, which is what made the judgement possible: the scope set includes
# `$upstream...HEAD` (`verify-all.sh:169-176`), so ONE `scripts/` edit early in a
# session keeps SCRIPTS in scope for EVERY later push until the push happens.
# That single fact is what made the full 20.4-minute gate feel like the per-commit
# cost. Admitting SCRIPTS takes that session shape from ~8 min per push to 0.
#
# **RUST WAS DELIBERATELY NOT ADMITTED.** A `scoped:RUST` run already pays
# `cargo test` and both container suites, so reuse would save only ~2 minutes —
# bought against the largest blast radius in the tree. Bad trade, and refusing it
# is the point: this list grows on measurement, never on symmetry alone.
#
# AND THE SCOPE WAS COMPUTED FROM THIS EXACT TREE. The hash check below is what
# makes the bucket list trustworthy: it is not a claim about some earlier diff, it
# is the classification of the very bytes being pushed.
#
# Anything else — RUST, CI, INFRA, PY, an unknown bucket, a commit-stage
# run, a failure, a stale hash — still requires the full gate. Fails CLOSED: an
# unrecognised scope string is refused rather than parsed optimistically.
push_ready() {
    local stamp="$1" want="$2" rc hash ts scope
    [ -f "$stamp" ] || return 1
    read -r rc hash ts scope < "$stamp"
    [ "${rc:-1}" = "0" ]      || return 1
    [ "${hash:-}" = "$want" ] || return 1
    [ -n "${scope:-}" ]       || return 1
    [ "$scope" = "full" ] && return 0
    # A commit-stage run covers less (it diff-gates the guard meta-gate), so it
    # never qualifies regardless of its buckets.
    case "$scope" in commit-stage/*) return 1 ;; esac
    case "$scope" in scoped:*) : ;; *) return 1 ;; esac
    local buckets="${scope#scoped:}" b
    [ -n "$buckets" ] || return 1
    for b in $buckets; do
        case "$b" in
            WEB|DOCS|SCRIPTS) : ;;
            *) return 1 ;;
        esac
    done
    return 0
}

if [ "${1:-}" = "--push-ready" ]; then
    push_ready "$(git rev-parse --show-toplevel)/.verify-stamp" "$(tree_hash)"
    exit $?
fi

if [ "${1:-}" = "--full-gate-current" ]; then
    full_gate_current "$(git rev-parse --show-toplevel)/.verify-stamp" "$(tree_hash)"
    exit $?
fi

if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    fails=0
    expect() { # expect <want_rc> <label> <stamp> <hash>
        local want="$1" label="$2"; shift 2
        check "$@" >/dev/null 2>&1; local got=$?
        if [ "$got" -eq "$want" ]; then echo "  ✓ $label (exit $got)"
        else echo "  ✗ $label — expected exit $want, got $got"; fails=$((fails+1)); fi
    }

    expect 1 "a MISSING stamp blocks the commit" "$tmp/none" "abc123"

    # THE CASE THAT HAPPENED: the gate failed, a pipeline reported success anyway.
    printf '1 abc123 2026-08-10T00:00:00Z\n' > "$tmp/failed"
    expect 1 "a FAILING stamp blocks even with a matching tree" "$tmp/failed" "abc123"

    # Verified, then the tree changed — the stamp no longer describes what is committed.
    printf '0 deadbeef 2026-08-10T00:00:00Z\n' > "$tmp/stale"
    expect 1 "a STALE stamp (tree moved on) blocks" "$tmp/stale" "abc123"

    # A malformed/empty stamp must fail CLOSED, not be treated as absent-and-fine.
    : > "$tmp/empty"
    expect 1 "an EMPTY stamp fails closed" "$tmp/empty" "abc123"

    # The only pass.
    printf '0 abc123 2026-08-10T00:00:00Z\n' > "$tmp/ok"
    expect 0 "a matching exit-0 stamp is the ONLY thing that passes" "$tmp/ok" "abc123"

    # ── --full-gate-current: the SKIP decision (2026-08-22) ─────────────────────
    # Every case here is a way the pre-push gate must NOT be skipped. The single pass
    # is last, so a bug that made this function always-true would light up four ✗ first.
    expectf() { # expectf <want_rc> <label> <stamp> <hash>
        local want="$1" label="$2"; shift 2
        full_gate_current "$@" >/dev/null 2>&1; local got=$?
        if [ "$got" -eq "$want" ]; then echo "  ✓ $label (exit $got)"
        else echo "  ✗ $label — expected exit $want, got $got"; fails=$((fails+1)); fi
    }
    expectf 1 "skip REFUSED: no stamp at all" "$tmp/none" "abc123"
    printf '1 abc123 2026-08-22T00:00:00Z full\n' > "$tmp/f_failed"
    expectf 1 "skip REFUSED: the full gate FAILED" "$tmp/f_failed" "abc123"
    printf '0 deadbeef 2026-08-22T00:00:00Z full\n' > "$tmp/f_stale"
    expectf 1 "skip REFUSED: stamp is for a DIFFERENT tree" "$tmp/f_stale" "abc123"
    printf '0 abc123 2026-08-22T00:00:00Z scoped:docs\n' > "$tmp/f_scoped"
    expectf 1 "skip REFUSED: the run was SCOPED, not full" "$tmp/f_scoped" "abc123"
    # THE ONE THAT WOULD HAVE SHIPPED THE BUG: commit-stage runs fewer selftests but
    # used to stamp itself "full". A prefix match would pass this.
    printf '0 abc123 2026-08-22T00:00:00Z commit-stage/full\n' > "$tmp/f_commit"
    expectf 1 "skip REFUSED: COMMIT-STAGE run cannot authorise skipping the full gate" "$tmp/f_commit" "abc123"
    printf '0 abc123 2026-08-22T00:00:00Z commit-stage/scoped:docs\n' > "$tmp/f_cs"
    expectf 1 "skip REFUSED: commit-stage + scoped" "$tmp/f_cs" "abc123"
    : > "$tmp/f_empty"
    expectf 1 "skip REFUSED: an EMPTY stamp fails closed" "$tmp/f_empty" "abc123"
    # The ONLY pass.
    printf '0 abc123 2026-08-22T00:00:00Z full\n' > "$tmp/f_ok"
    expectf 0 "skip ALLOWED only for an exit-0 FULL run on THIS exact tree" "$tmp/f_ok" "abc123"

    # ── --push-ready: the founder-ruled narrowing (2026-08-22) ──────────────
    # Every REFUSAL is listed before the two acceptances, so a bug that made this
    # always-true would light up a wall of ✗ rather than one quiet ✓.
    expectp() { local want="$1" label="$2"; shift 2
        push_ready "$@" >/dev/null 2>&1; local got=$?
        if [ "$got" -eq "$want" ]; then echo "  ✓ $label (exit $got)"
        else echo "  ✗ $label — expected exit $want, got $got"; fails=$((fails+1)); fi; }
    printf '0 abc123 T scoped:RUST\n'      > "$tmp/p_rust";   expectp 1 "push REFUSED: scoped run touched RUST"        "$tmp/p_rust" abc123
    printf '0 abc123 T scoped:WEB RUST\n'  > "$tmp/p_mixed";  expectp 1 "push REFUSED: one bad bucket poisons the set"  "$tmp/p_mixed" abc123
    # R124: SCRIPTS is ALLOWED as of 2026-08-24. RUST is still refused, and the
    # mixed case above pins that ONE bad bucket still poisons the whole set — which
    # is what stops the allowlist quietly widening by accident.
    printf '0 abc123 T scoped:SCRIPTS\n'   > "$tmp/p_scr";    expectp 0 "push ALLOWED: SCRIPTS (R124, 2026-08-24)"       "$tmp/p_scr" abc123
    printf '0 abc123 T scoped:SCRIPTS DOCS\n' > "$tmp/p_sd";  expectp 0 "push ALLOWED: SCRIPTS+DOCS"                     "$tmp/p_sd" abc123
    printf '0 abc123 T scoped:SCRIPTS RUST\n' > "$tmp/p_sr";  expectp 1 "push REFUSED: SCRIPTS+RUST — RUST still bars it" "$tmp/p_sr" abc123
    printf '0 abc123 T scoped:CI\n'        > "$tmp/p_ci";     expectp 1 "push REFUSED: CI is not on the allowlist"       "$tmp/p_ci" abc123
    printf '0 abc123 T scoped:INFRA\n'     > "$tmp/p_inf";    expectp 1 "push REFUSED: INFRA is not on the allowlist"    "$tmp/p_inf" abc123
    printf '0 abc123 T scoped:PY\n'        > "$tmp/p_py";     expectp 1 "push REFUSED: PY is not on the allowlist"       "$tmp/p_py" abc123
    printf '0 abc123 T scoped:PY\n'        > "$tmp/p_py";     expectp 1 "push REFUSED: PY"                              "$tmp/p_py" abc123
    printf '0 abc123 T scoped:INFRA\n'     > "$tmp/p_inf";    expectp 1 "push REFUSED: INFRA"                           "$tmp/p_inf" abc123
    printf '0 abc123 T scoped:CI\n'        > "$tmp/p_ci";     expectp 1 "push REFUSED: CI"                              "$tmp/p_ci" abc123
    printf '0 abc123 T scoped:WEIRD\n'     > "$tmp/p_unk";    expectp 1 "push REFUSED: unknown bucket fails CLOSED"     "$tmp/p_unk" abc123
    printf '0 abc123 T scoped:\n'          > "$tmp/p_empty";  expectp 1 "push REFUSED: empty bucket list"               "$tmp/p_empty" abc123
    printf '0 abc123 T commit-stage/full\n'> "$tmp/p_cs";     expectp 1 "push REFUSED: commit-stage covers less"        "$tmp/p_cs" abc123
    printf '1 abc123 T scoped:WEB\n'       > "$tmp/p_fail";   expectp 1 "push REFUSED: the run FAILED"                  "$tmp/p_fail" abc123
    printf '0 deadbee T scoped:WEB\n'      > "$tmp/p_stale";  expectp 1 "push REFUSED: DIFFERENT tree"                  "$tmp/p_stale" abc123
    expectp 1 "push REFUSED: no stamp"                                                                                   "$tmp/none" abc123
    printf '0 abc123 T scoped:WEB DOCS\n'  > "$tmp/p_ok";     expectp 0 "push ALLOWED: scoped run, WEB+DOCS only"       "$tmp/p_ok" abc123
    printf '0 abc123 T full\n'             > "$tmp/p_full";   expectp 0 "push ALLOWED: a FULL run always qualifies"     "$tmp/p_full" abc123

    if [ "$fails" -eq 0 ]; then echo "verify-stamp selftest PASSED."; exit 0; fi
    echo "verify-stamp selftest FAILED — $fails case(s)."; exit 1
fi

check "$(git rev-parse --show-toplevel)/.verify-stamp" "$(tree_hash)"
