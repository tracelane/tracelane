#!/usr/bin/env bash
# scripts/ci/no-raw-ch-query.sh
#
# CI guard: enforce that every ClickHouse read goes through the
# per-tier resource-cap wrappers (ADR-031). Bare `client.query(...)`
# calls outside the allowed wrapper files are a regression — they
# bypass `max_memory_usage` / `max_execution_time` / `max_rows_to_read`
# and let one tenant starve the shared CCX23 node for everyone.
#
# Allowed call sites:
#   * apps/web/lib/clickhouse.ts          — the TS wrapper
#   * crates/gateway/src/clickhouse_query.rs — the Rust wrapper
#   * crates/ingest/src/clickhouse_writer.rs — writes only (no cap semantics)
#   * any file path containing `tests`     — test fixtures are exempt
#
# Patterns checked:
#   * TypeScript:  `getClickHouseClient().query(` or `client.query(`
#                  near a `@clickhouse/client` import
#   * Rust:        `clickhouse::Client::query` or `.query::<` near a
#                  `use clickhouse::` import
#
# Run locally: ./scripts/ci/no-raw-ch-query.sh
# CI:          .github/workflows/ci.yml job `no-raw-ch-query`.

set -euo pipefail

violations=0

# ── TypeScript pass ────────────────────────────────────────────────────────

# Find files that import the ClickHouse client (TS).
while IFS= read -r f; do
    case "$f" in
        apps/web/lib/clickhouse.ts) continue ;;
        *test*|*spec*|*__tests__*|*node_modules*|*.d.ts) continue ;;
    esac
    # Files that import the CH client but call .query() are violations.
    if grep -q '@clickhouse/client' "$f" 2>/dev/null && grep -qE '\.query\s*\(' "$f" 2>/dev/null; then
        echo "VIOLATION (ts): $f imports @clickhouse/client and calls .query() directly" >&2
        echo "  → use apps/web/lib/clickhouse.ts::tenantQuery() (ADR-031)" >&2
        violations=$((violations + 1))
    fi
done < <(find apps -type f \( -name '*.ts' -o -name '*.tsx' \) 2>/dev/null || true)

# ── Rust pass ──────────────────────────────────────────────────────────────

# Find Rust files that import the clickhouse crate and call .query.
# Both `clickhouse_query.rs` (wrapper) and `clickhouse_writer.rs`
# (writes — no caps) are allowed.
while IFS= read -r f; do
    case "$f" in
        crates/gateway/src/clickhouse_query.rs) continue ;;
        crates/ingest/src/clickhouse_writer.rs) continue ;;
        */tests/*|*/test*) continue ;;
        # ── V1.1 sweep allow-list (ADR-031 §"V1 wiring scope") ───────
        # The three pre-existing audit-ledger / prompt-history read
        # paths predate ADR-031 and read from internally-bounded row
        # sets (audit log, prompt history) rather than user-driven
        # dashboard queries. Refactoring them to TenantQuery is V1.1
        # sweep work — tracked in CHANGELOG and ADR-031. Each file
        # has its own "ADR-031 V1.1 sweep" TODO comment near the .query
        # call so the next maintainer sees the upgrade plan.
        crates/gateway/src/audit.rs) continue ;;
        crates/gateway/src/audit_export.rs) continue ;;
        crates/gateway/src/prompt_history.rs) continue ;;
        # ClickHouseEvalGate: single-row tenant-scoped PK lookup against
        # eval_runs, internally bounded like prompt_history. V1.1 sweep
        # routes it through TenantQuery for consistency (ADR-031).
        crates/gateway/src/prompt_router.rs) continue ;;
        # Gateway-proxied trace + SLO reads (Option 1, ). The .query
        # execution lives here, but every SELECT IS wrapped by
        # clickhouse_query::TenantQuery (ADR-031 caps applied) — so this is
        # compliant, not exempt. Allow-listed because the grep matches any
        # `.query` call site regardless of the cap wrapper.
        crates/gateway/src/trace_reads.rs) continue ;;
    esac
    # Match `use clickhouse::` (the crate) + a `.query` call.
    if grep -qE '^use clickhouse(::|;)' "$f" 2>/dev/null && \
       grep -qE '\.query\s*[<\(]' "$f" 2>/dev/null; then
        echo "VIOLATION (rust): $f uses clickhouse crate and calls .query directly" >&2
        echo "  → use crates/gateway/src/clickhouse_query.rs::TenantQuery (ADR-031)" >&2
        violations=$((violations + 1))
    fi
done < <(find crates -type f -name '*.rs' 2>/dev/null || true)

if [[ "$violations" -gt 0 ]]; then
    echo >&2
    echo "no-raw-ch-query guard: $violations violation(s) found." >&2
    echo "Every ClickHouse read MUST go through the per-tier resource-cap" >&2
    echo "wrapper. Writes (clickhouse_writer.rs) and the wrapper files" >&2
    echo "themselves are exempt." >&2
    exit 1
fi

echo "no-raw-ch-query guard: OK"
