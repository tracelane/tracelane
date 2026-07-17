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

set -euo pipefail

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
