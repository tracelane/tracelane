#!/usr/bin/env bash
# check-verify-stamp — the commit path may only trust verify-all.sh's REAL exit code.
#
# WHY (earned 2026-08-10, the SIXTH instance of one reporting defect — and the first
# instance was `tail -4` discarding a gate's failure reason, i.e. the same command and
# the same shape, AFTER CLAUDE.md §1.14 was written and AFTER ci-status.sh shipped):
#
#     bash scripts/verify-all.sh --fast | tail -5 && git commit -F- <<'MSG' ...
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
    --selftest)   : ;;                       # handled below
    *)            echo "check-verify-stamp: unknown option: $1" >&2; exit 2 ;;
esac

# `check <stamp_file> <expected_tree_hash>` — the whole decision, one function, so the
# selftest drives exactly what the hook drives.
check() {
    local stamp="$1" want="$2" rc hash when
    if [ ! -f "$stamp" ]; then
        echo "✗ no .verify-stamp — verify-all.sh has not run on this tree." >&2
        echo "  Run: bash scripts/verify-all.sh --fast" >&2
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
        echo "  bash scripts/verify-all.sh --fast" >&2
        return 1
    fi
    return 0
}

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

    if [ "$fails" -eq 0 ]; then echo "verify-stamp selftest PASSED."; exit 0; fi
    echo "verify-stamp selftest FAILED — $fails case(s)."; exit 1
fi

check "$(git rev-parse --show-toplevel)/.verify-stamp" "$(tree_hash)"
