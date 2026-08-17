#!/usr/bin/env bash
# scripts/ci/no-llm-in-recovery.sh
#
# CI guard for ADR-037 (deterministic, token-free recovery invariant).
#
# Every recovery / rollback path MUST be free of any LLM / agent / MCP /
# provider dependency, so it works during a provider outage or token-budget
# exhaustion — the very failures it is recovering from (the Bender
# "load-bearing token engine" trap). This script greps the recovery paths for
# any provider / MCP / SLM-judge import and fails CI on a match.
#
# Guarded paths:
#   - crates/**/recovery/                         (any future recovery module)
#   - crates/gateway/src/auto_rollback.rs         (B1 objective-metric rollback)
#   - packages/cli/src/commands/rollback.ts       (tlane rollback)
#
# Run locally:  ./scripts/ci/no-llm-in-recovery.sh
# CI:           wired into .github/workflows/ci.yml job `no-llm-in-recovery`.
# Falsify:      ./scripts/ci/no-llm-in-recovery.sh --selftest
#               (plants a provider/MCP/judge import in each guarded path inside a
#                throwaway tree and proves each one BLOCKS)

set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

usage() {
    cat <<'EOF'
usage: no-llm-in-recovery.sh [--selftest | --help]

  (no args)    run the guard against the recovery paths under ./
               exit 0 = deterministic · 1 = a recovery path imports an LLM/MCP dep
  --selftest   plant the forbidden import in each guarded path and prove it blocks
  -h, --help   this message
EOF
}

# ---------------------------------------------------------------- selftest ---
# Every path this guard reads is relative to $PWD and it shells out to nothing
# but find/sed/grep, so the whole thing falsifies inside a temp dir. Nothing in
# the real tree is written.
selftest() {
    local fails=0 tmp before after rc=0

    before="$(git status --porcelain 2>/dev/null || true)"

    # Case 0 — the baseline negative. A guard that failed on every input would
    # "catch" all the plants below while proving nothing.
    bash "$SELF" >/dev/null 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        echo "SELFTEST ABORT: the guard is already RED against this tree (exit $rc)." >&2
        echo "Fix the tree first — a red baseline makes every planted case vacuous." >&2
        return 1
    fi
    echo "✓ clean case: the real repo tree passes (exit 0)"

    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT

    # A minimal tree shaped like the three guarded paths, all token-free.
    _fresh() {
        rm -rf "${tmp:?}/t"
        mkdir -p "$tmp/t/crates/gateway/src" "$tmp/t/packages/cli/src/commands"
        cat >"$tmp/t/crates/gateway/src/auto_rollback.rs" <<'RS'
use crate::clickhouse::routing_pointer;

pub async fn auto_rollback(deployment: &str) -> anyhow::Result<()> {
    routing_pointer::swap_to_previous(deployment).await
}
RS
        cat >"$tmp/t/packages/cli/src/commands/rollback.ts" <<'TS'
import { readPointer, writePointer } from "../pointer.js";

export async function rollback(id: string) {
  return writePointer(await readPointer(id));
}
TS
    }

    _check() { # label, expected_exit, [expected message substring]
        local got=0 out
        out="$( (cd "$tmp/t" && bash "$SELF") 2>&1 )" || got=$?
        if [[ "$got" -ne "$2" ]]; then
            echo "✗ $1 — expected exit $2, got $got" >&2
            printf '%s\n' "$out" >&2
            fails=$((fails + 1))
            return 0
        fi
        if [[ -n "${3:-}" ]] && ! printf '%s' "$out" | grep -Fq "$3"; then
            echo "✗ $1 — exit $got was right but the message never said '$3'" >&2
            printf '%s\n' "$out" >&2
            fails=$((fails + 1))
            return 0
        fi
        echo "✓ $1 (exit $got)"
    }

    # 1. Deterministic recovery paths must pass, or nothing below discriminates.
    _fresh
    _check "clean case: token-free recovery paths pass" 0 "guard: OK"

    # 2. The ADR-037 violation itself: the rollback path takes a provider dep,
    #    so it dies in exactly the outage it exists to recover from.
    _fresh
    printf 'use crate::providers::openai;\n' >>"$tmp/t/crates/gateway/src/auto_rollback.rs"
    _check "provider import in auto_rollback.rs BLOCKS" 1 "auto_rollback.rs imports a provider"

    # 3. The predictive/SLM-judge layer is the same failure wearing a different
    #    name — a token budget in the recovery path.
    _fresh
    printf 'use crate::predictive::slm_judge::Judge;\n' >>"$tmp/t/crates/gateway/src/auto_rollback.rs"
    _check "slm_judge import in auto_rollback.rs BLOCKS" 1 "violates ADR-037"

    # 4. A recovery/ module that does not exist today. This is the case that
    #    proves the `find crates -type d -name recovery` discovery works — the
    #    guard's forward-looking half, which the live tree cannot exercise.
    _fresh
    mkdir -p "$tmp/t/crates/gateway/src/recovery"
    printf 'use crate::mcp::client::Tool;\n' >"$tmp/t/crates/gateway/src/recovery/pointer.rs"
    _check "MCP import in a NEW crates/**/recovery/ file BLOCKS" 1 "recovery/pointer.rs"

    # 5-6. The TypeScript half: `tlane rollback` must not pull a provider or the
    #      MCP SDK.
    _fresh
    printf 'import OpenAI from "openai";\n' >>"$tmp/t/packages/cli/src/commands/rollback.ts"
    _check "provider SDK import in rollback.ts BLOCKS" 1 "rollback.ts imports a provider/MCP SDK"

    _fresh
    printf 'import { Client } from "@modelcontextprotocol/sdk";\n' \
        >>"$tmp/t/packages/cli/src/commands/rollback.ts"
    _check "MCP SDK import in rollback.ts BLOCKS" 1 "rollback.ts imports a provider/MCP SDK"

    # 7. Discriminating negative: the same import inside a line comment must NOT
    #    fire, or documenting the rule becomes unmergeable.
    _fresh
    printf '// never: use crate::providers::openai; — ADR-037 forbids it\n' \
        >>"$tmp/t/crates/gateway/src/auto_rollback.rs"
    _check "clean case: a COMMENTED-OUT provider import is not a false positive" 0 "guard: OK"

    # 8. Documented fail-OPEN, asserted so it cannot change unnoticed: when
    #    rollback.ts is absent the guard WARNs and still exits 0. That is the
    #    current contract, not an endorsement — if the TS half is ever made
    #    mandatory, this case flips and must be updated deliberately.
    _fresh
    rm -f "$tmp/t/packages/cli/src/commands/rollback.ts"
    _check "missing rollback.ts warns and passes (documented fail-open)" 0 "WARN"

    rm -rf "$tmp"
    trap - EXIT

    # 9. State restored: everything above lived under mktemp, so the real repo
    #    must be byte-identical to how we found it.
    after="$(git status --porcelain 2>/dev/null || true)"
    if [[ "$before" != "$after" ]]; then
        echo "✗ selftest mutated the working tree — git status changed" >&2
        diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") >&2 || true
        fails=$((fails + 1))
    else
        echo "✓ working tree unchanged (git status --porcelain identical)"
    fi

    if [[ "$fails" -ne 0 ]]; then
        echo "selftest FAILED — $fails case(s). This guard is not trustworthy." >&2
        return 1
    fi
    echo "selftest PASSED."
    return 0
}

# ------------------------------------------------------------ arg handling ---
# Default-deny on argv. Silently ignoring an unknown flag is how `--selftest`
# came to "pass" on a guard that had no selftest at all.
if [[ "$#" -gt 1 ]]; then
    echo "ERROR: too many arguments: $*" >&2
    usage >&2
    exit 2
fi
case "${1:-}" in
    "") ;;
    --selftest) selftest; exit $? ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        echo "ERROR: unknown argument '$1'" >&2
        usage >&2
        exit 2
        ;;
esac

violations=0

# Rust recovery paths: forbid importing provider adapters, the MCP crate, or
# the SLM judge / predictive layer. `use ... providers`, `mcp`, `slm_judge`,
# `predictive` in a recovery file means the path can be defeated by an outage.
RUST_PATHS=()
[[ -f crates/gateway/src/auto_rollback.rs ]] && RUST_PATHS+=("crates/gateway/src/auto_rollback.rs")
while IFS= read -r f; do RUST_PATHS+=("$f"); done < <(find crates -type d -name recovery -prune -exec find {} -name '*.rs' \; 2>/dev/null)

RUST_FORBIDDEN='^[[:space:]]*use[[:space:]]+crate::providers|^[[:space:]]*use[[:space:]]+crate::predictive|slm_judge|crate::mcp|tracelane_mcp'

for f in "${RUST_PATHS[@]:-}"; do
    [[ -z "$f" || ! -f "$f" ]] && continue
    # Strip line comments so doc references to these modules don't trip the guard.
    if sed -E 's://.*$::' "$f" | grep -Eq "$RUST_FORBIDDEN"; then
        echo "ERROR: $f imports a provider/MCP/judge module — violates ADR-037 (token-free recovery)." >&2
        sed -E 's://.*$::' "$f" | grep -En "$RUST_FORBIDDEN" >&2 || true
        violations=$((violations + 1))
    fi
done

# TypeScript recovery path: forbid provider SDKs and the MCP SDK.
TS_FILE="packages/cli/src/commands/rollback.ts"
TS_FORBIDDEN='@modelcontextprotocol|from "openai"|from "@anthropic-ai|from "@google|provider-?sdk|slm_judge|llm-judge'
if [[ -f "$TS_FILE" ]]; then
    if sed -E 's://.*$::' "$TS_FILE" | grep -Eq "$TS_FORBIDDEN"; then
        echo "ERROR: $TS_FILE imports a provider/MCP SDK — violates ADR-037 (token-free recovery)." >&2
        sed -E 's://.*$::' "$TS_FILE" | grep -En "$TS_FORBIDDEN" >&2 || true
        violations=$((violations + 1))
    fi
else
    echo "WARN: $TS_FILE not found — tlane rollback missing; skipping its check." >&2
fi

if [[ "$violations" -gt 0 ]]; then
    cat <<'EOF' >&2

A recovery/rollback path took a dependency on an LLM / agent / MCP / provider.
ADR-037 (Bender invariant): recovery must run with every upstream down and a
$0 token budget. Use only deterministic data operations (ClickHouse routing
pointer, R2 partition pointer, binary/LB swap). Remove the offending import.
EOF
    exit 1
fi

echo "no-llm-in-recovery guard: OK (recovery paths are deterministic)."
