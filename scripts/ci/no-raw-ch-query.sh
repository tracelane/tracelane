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
# Falsify it:  ./scripts/ci/no-raw-ch-query.sh --selftest
# CI:          .github/workflows/ci.yml job `no-raw-ch-query`.
#
# Exit codes: 0 = clean · 1 = violation(s) found · 2 = bad usage / selftest failed.
#
# NOTE (pre-existing, deliberately NOT changed here): the scan is relative to
# $PWD (`find apps` / `find crates`), so running it from anywhere but the repo
# root scans nothing and passes. CI and the pre-push hook both run it from the
# root. The selftest depends on that same $PWD-relative behaviour to scan a
# planted temp tree, which is why it is left as-is rather than hardened to $ROOT.

set -euo pipefail

usage() {
    cat <<'EOF'
usage: no-raw-ch-query.sh [--selftest] [-h|--help]

  (no args)   Scan the tree under $PWD (apps/, crates/) for ClickHouse .query()
              calls outside the ADR-031 cap wrappers. Exit 1 on any violation.
  --selftest  Prove the guard BLOCKS: plant a raw .query() call in a temp tree
              and assert it is caught, assert the allow-listed wrapper paths and
              a clean tree still pass. Exit 0 only if every case holds.
EOF
}

mode=scan
while [ $# -gt 0 ]; do
    case "$1" in
        --selftest) mode=selftest ;;
        -h|--help)  usage; exit 0 ;;
        *)
            echo "no-raw-ch-query.sh: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
    shift
done

# Scans $PWD. Returns 0 when clean, 1 when any violation is found.
scan_tree() {
    local violations=0 f

    # ── TypeScript pass ────────────────────────────────────────────────────

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

    # ── Rust pass ──────────────────────────────────────────────────────────

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
            # ── SURFACED 2026-08-13 by widening the trigger; DECLARED, not silent ──
            # These six became visible only when the trigger stopped requiring a
            # direct `use clickhouse::` import. Each was checked rather than waved
            # through: **all six DO filter on `tenant_id`, so there is no isolation
            # leak.** What none of them has is the ADR-031 resource cap — zero use
            # `TenantQuery`, and five carry no `SETTINGS` / `max_execution_time` at
            # all, so an expensive query on an authenticated read route is unbounded.
            #
            # That is a COST/availability gap, not a tenancy gap, and closing it
            # means refactoring six query paths — real work, tracked as **B-225**,
            # not something to smuggle into a guard change. Exempted here WITH the
            # reason and the row so the debt is visible instead of invisible; the
            # row is what removes these lines.
            crates/gateway/src/alerts/checker.rs) continue ;;
            crates/gateway/src/billing/usage.rs) continue ;;
            crates/gateway/src/guardrail/engine.rs) continue ;;
            crates/gateway/src/server.rs) continue ;;
            crates/gateway/src/tool_analytics.rs) continue ;;
            crates/gateway/src/retention_sweep.rs) continue ;;
        esac
        # TRIGGER WIDENED 2026-08-13. It was `^use clickhouse::` + `.query`, and
        # that combination is only how a file looks when it constructs the client
        # ITSELF. The commonest real shape is a client PASSED IN — `fn f(c: &Client)`
        # — which imports nothing from the crate and was therefore invisible.
        #
        # Measured: 21 files under crates/ call `.query(`; only **7** carried the
        # import, and all 7 were already on the allowlist above, so **the effective
        # Rust scan set was ZERO files**. Falsification confirmed it: a planted
        # violation with a direct import is caught, and the identical violation with
        # the client passed in is NOT.
        #
        # `.fetch*::<T>()` is the discriminating signal — it is the clickhouse
        # crate's own execution idiom (`client.query(q).bind(x).fetch_all::<T>()`)
        # and it does NOT match tokio-postgres, whose `.query(sql, &[params])`
        # returns rows directly. So this widens to ClickHouse callers without
        # dragging in every Postgres call site.
        if { grep -qE '^use clickhouse(::|;)' "$f" 2>/dev/null || \
             grep -qE '\.fetch(_all|_one|_optional)?::<' "$f" 2>/dev/null; } && \
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
        return 1
    fi

    echo "no-raw-ch-query guard: OK"
    return 0
}

# ── Selftest ───────────────────────────────────────────────────────────────
#
# Every case runs the REAL scan_tree against a planted temp tree. Nothing under
# the repo is written, so `git status --porcelain` is unchanged afterwards.

TS_IMPORT="import { createClient } from '@clickhouse/client';"
TS_QUERY='const rows = await client.query({ query: "SELECT 1" });'
RS_IMPORT='use clickhouse::Client;'
# NOTE: `.query(` — NOT the turbofish `.query::<Row>(`. The guard's regex is
# `\.query\s*[<\(]`, which does not match `::<` (a pre-existing blind spot in
# the guard, documented not fixed here — this change adds proof, not behaviour).
RS_QUERY='    let r = client.query("SELECT 1").fetch_all::<Row>().await?;'

selftest_failures=0
selftest_tmp=""

# _case <name> <expected_exit> <dir> [expected_substring]
_case() {
    local name="$1" want="$2" dir="$3" needle="${4:-}" rc=0 out
    out="$( cd "$dir" && scan_tree 2>&1 )" || rc=$?
    if [ "$rc" -ne "$want" ]; then
        echo "✗ $name: expected exit $want, got $rc"
        printf '%s\n' "$out" | sed 's/^/      /'
        selftest_failures=$((selftest_failures + 1))
        return 0
    fi
    if [ -n "$needle" ] && ! printf '%s' "$out" | grep -qF "$needle"; then
        echo "✗ $name: exit $rc as expected, but output did not mention '$needle'"
        printf '%s\n' "$out" | sed 's/^/      /'
        selftest_failures=$((selftest_failures + 1))
        return 0
    fi
    echo "✓ $name (exit $rc)"
}

# Lays down a tree that is clean by construction, then the caller adds to it.
_fixture() {
    local d="$1"
    mkdir -p "$d/apps/web/lib" "$d/crates/gateway/src"
    # Imports the CH client but never calls .query() -> not a violation.
    printf '%s\nexport const client = createClient({});\n' "$TS_IMPORT" \
        > "$d/apps/web/lib/config.ts"
    # Uses the clickhouse crate but never calls .query -> not a violation.
    printf '%s\npub fn build() -> Client { Client::default() }\n' "$RS_IMPORT" \
        > "$d/crates/gateway/src/ch_config.rs"
    echo "$d"
}

selftest() {
    local tmp
    selftest_tmp="$(mktemp -d)"   # global: the EXIT trap fires after locals die
    tmp="$selftest_tmp"
    trap 'rm -rf "$selftest_tmp"' EXIT

    echo "no-raw-ch-query.sh --selftest"

    # 1. NEGATIVE CONTROL — a clean tree must pass, or the guard is a wall.
    _fixture "$tmp/clean" >/dev/null
    _case "clean tree passes" 0 "$tmp/clean" "guard: OK"

    # 2. TS violation: imports @clickhouse/client AND calls .query().
    _fixture "$tmp/ts-bad" >/dev/null
    printf '%s\n%s\n' "$TS_IMPORT" "$TS_QUERY" > "$tmp/ts-bad/apps/web/lib/traces.ts"
    _case "planted raw .query() in apps/web/lib/traces.ts BLOCKS" \
        1 "$tmp/ts-bad" "VIOLATION (ts): apps/web/lib/traces.ts"

    # 3. The TS wrapper itself is allow-listed and must NOT be flagged.
    _fixture "$tmp/ts-wrapper" >/dev/null
    printf '%s\n%s\n' "$TS_IMPORT" "$TS_QUERY" > "$tmp/ts-wrapper/apps/web/lib/clickhouse.ts"
    _case "allow-listed apps/web/lib/clickhouse.ts passes" 0 "$tmp/ts-wrapper" "guard: OK"

    # 4. Test fixtures are exempt (same violating content in a *.test.ts).
    _fixture "$tmp/ts-test" >/dev/null
    printf '%s\n%s\n' "$TS_IMPORT" "$TS_QUERY" > "$tmp/ts-test/apps/web/lib/traces.test.ts"
    _case "test file with the same violation is exempt" 0 "$tmp/ts-test" "guard: OK"

    # 5. Rust violation: uses the clickhouse crate AND calls .query.
    _fixture "$tmp/rs-bad" >/dev/null
    printf '%s\npub async fn read() {\n%s\n}\n' "$RS_IMPORT" "$RS_QUERY" \
        > "$tmp/rs-bad/crates/gateway/src/reads.rs"
    _case "planted raw .query in crates/gateway/src/reads.rs BLOCKS" \
        1 "$tmp/rs-bad" "VIOLATION (rust): crates/gateway/src/reads.rs"

    # 6. The Rust cap wrapper itself is allow-listed and must NOT be flagged.
    _fixture "$tmp/rs-wrapper" >/dev/null
    printf '%s\npub async fn read() {\n%s\n}\n' "$RS_IMPORT" "$RS_QUERY" \
        > "$tmp/rs-wrapper/crates/gateway/src/clickhouse_query.rs"
    _case "allow-listed crates/gateway/src/clickhouse_query.rs passes" \
        0 "$tmp/rs-wrapper" "guard: OK"

    # 7. Both surfaces at once -> both reported, exit still 1.
    _fixture "$tmp/both" >/dev/null
    printf '%s\n%s\n' "$TS_IMPORT" "$TS_QUERY" > "$tmp/both/apps/web/lib/traces.ts"
    printf '%s\npub async fn read() {\n%s\n}\n' "$RS_IMPORT" "$RS_QUERY" \
        > "$tmp/both/crates/gateway/src/reads.rs"
    _case "two violations reported together" 1 "$tmp/both" "2 violation(s) found"

    if [ "$selftest_failures" -gt 0 ]; then
        echo
        echo "selftest FAILED — $selftest_failures case(s). The guard is not trustworthy."
        return 2
    fi
    echo
    echo "selftest PASSED."
    return 0
}

if [ "$mode" = selftest ]; then
    selftest
    exit $?
fi

scan_tree
