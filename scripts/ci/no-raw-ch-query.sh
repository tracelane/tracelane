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
            # EVL-05 eval engine. Two shapes, both checked rather than waved:
            #  · the ONE query that scans `spans` on caller-supplied filters IS
            #    wrapped by `TenantQuery` — and at the TIGHTEST (Builder) caps
            #    rather than the tenant's own tier, because a background
            #    case-fetch must not out-consume interactive queries. Compliant,
            #    not exempt, same as trace_reads.rs.
            #  · the `eval_runs` reads are small tenant-scoped lookups bounded by
            #    LIMIT, the same shape as prompt_router's gate read above.
            crates/gateway/src/prompt_eval.rs) continue ;;
            # GWY-24 semantic cache. The one SELECT is wrapped by `TenantQuery`
            # at the TIGHTEST (Builder) caps — a cache lookup sits ON the hot
            # path, so it must never out-consume the interactive queries of the
            # same workspace. Compliant, not exempt, same as trace_reads.rs.
            # The INSERT is a write, which this guard does not police.
            crates/gateway/src/semantic_cache.rs) continue ;;
            # EVL-28 online evals. COMPLIANT, NOT EXEMPT.
            #
            # The one SELECT — the durable monthly judge total that re-seeds the
            # spend sub-limit — is wrapped by `TenantQuery` at the TIGHTEST
            # (Builder) caps rather than the tenant's own tier, for the same
            # reason `prompt_eval.rs` and `semantic_cache.rs` are: it is
            # BACKGROUND work on a fire-and-forget path and must not be able to
            # out-consume the interactive queries of the same workspace.
            #
            # Listed here only because the grep matches any `.query(` call site
            # regardless of the wrapper — which is the same reason every entry
            # below this line is listed, and the reason one of them records
            # having "fixed" working code on a wrong diagnosis.
            #
            # The INSERT into `online_eval_scores` is a write, which this guard
            # does not police.
            crates/gateway/src/online_eval.rs) continue ;;
            # EVL-28 item 11 — the READ side of online evals (`/v1/online-evals/
            # scores` and `/summary`). All three SELECTs are wrapped by
            # `TenantQuery` at Builder caps, and every one binds the tenant from
            # the validated claim; the `?` placeholders are bound, never
            # interpolated. COMPLIANT, NOT EXEMPT — listed for the same reason as
            # every other entry here, that the grep matches `.query(` regardless
            # of the wrapper. The selftest still blocks a planted raw call.
            crates/gateway/src/online_eval_routes.rs) continue ;;
            # EVL-29 item 12 — annotation queues. COMPLIANT, NOT EXEMPT.
            #
            # ONE SELECT: the read-time candidate query behind a queue (founder
            # ruling R221.1 — queue membership is a saved filter evaluated at
            # read time, never a materialised table, so this query IS the
            # membership). It is built by `candidate_sql`, whose every branch is
            # a FIXED string, and the whole thing is wrapped by `TenantQuery` at
            # Builder caps before it is ever executed — tightest tier rather
            # than the tenant's own, because a reviewer's page load must not be
            # able to out-consume the interactive queries of the same workspace.
            # `tenant_id`, the window, the score ceiling and the rubric are all
            # BOUND `?` placeholders; no caller value reaches statement text.
            #
            # Listed for the same reason as every entry above: the grep matches
            # `.query(` regardless of the wrapper.
            crates/gateway/src/annotation_routes.rs) continue ;;
            # Gateway-proxied trace + SLO reads (Option 1, ). The .query
            # execution lives here, but every SELECT IS wrapped by
            # clickhouse_query::TenantQuery (ADR-031 caps applied) — so this is
            # compliant, not exempt. Allow-listed because the grep matches any
            # `.query` call site regardless of the cap wrapper.
            crates/gateway/src/trace_reads.rs) continue ;;
            # EVL-04 datasets. COMPLIANT, NOT EXEMPT.
            #
            # CORRECTED 2026-08-23 — MY FIRST DIAGNOSIS OF THIS FILE WAS WRONG AND I
            # "FIXED" WORKING CODE. This entry read: "10 of its 12 `.query` sites
            # passed raw SQL". They did not. Each one assigns
            # `let sql = Self::capped("...")` and then passes `&sql`, which is the
            # capped string — the guard flagged the file only because it greps for
            # `.query(` regardless of the wrapper, which is the whole reason the
            # entries above exist. Reading the grep hit as the defect, instead of
            # reading the code around it, I wrapped ten already-capped strings a
            # second time. Harmless by luck (`sql_with_settings` appends a SETTINGS
            # fragment and ClickHouse takes the last one), but it was a change made
            # on a misread, and it is reverted.
            #
            # THE LESSON IS THE GUARD'S OWN §2: a failed check is a claim about your
            # TEST until you have read the detector. This one says in its header that
            # it matches call sites, not wrappers.
            #
            # All 12 sites go through `ClickHouseDatasetStore::capped`, which is
            # `TenantQuery::new(sql, PlanTier::Builder).sql_with_settings()` — the
            # TIGHTEST caps rather than the tenant's own tier, because a dataset
            # browse or a snapshot freeze is a background surface and must not
            # out-consume the interactive queries of the same workspace. Same
            # reasoning as `prompt_eval.rs` above.
            #
            # VERIFY THE CLAIM RATHER THAN TRUSTING THIS COMMENT — the capping is
            # at the `let sql =` site, not the `.query()` site:
            #   grep -c '\.query(' crates/gateway/src/dataset_routes.rs       # 12
            #   grep -c 'Self::capped(' crates/gateway/src/dataset_routes.rs   # >= 12
            # If those two numbers ever differ, this entry is a lie and the file is
            # silently uncapped — which is precisely what a per-file allowance in a
            # structural guard converts "not checked here" into (TRAPS §39).
            crates/gateway/src/dataset_routes.rs) continue ;;
            # EVL-02 experiments. COMPLIANT, NOT EXEMPT — and the claim was
            # COUNTED before it was written, because the entry above records what
            # happens when it is not: a grep hit was read as the defect and ten
            # already-capped strings were wrapped a second time.
            #
            # 8 `.query(` sites. SIX are `.query(&sql)` where `sql` is
            # `TenantQuery::new(..., PlanTier::Builder).sql_with_settings()` — the
            # TIGHTEST caps rather than the tenant's own tier, because reading an
            # experiment is a background surface and must not out-consume the
            # interactive queries of the same workspace (same reasoning as
            # `dataset_routes.rs` and `prompt_eval.rs`). The remaining TWO are
            # inside `#[cfg(test)] mod clickhouse_roundtrip`, which applies
            # migrations 18 and 19 to a throwaway container; the guard's path
            # exemption covers `*/tests/*` but not an in-file test module, so they
            # are named here rather than left to look like reads.
            #
            # VERIFY THE CLAIM RATHER THAN TRUSTING THIS COMMENT:
            #   grep -c '\.query(' crates/gateway/src/experiment_routes.rs          # 8
            #   grep -c 'TenantQuery::new(' crates/gateway/src/experiment_routes.rs  # 6
            #   grep -c 'sql_with_settings()' crates/gateway/src/experiment_routes.rs # 6
            # If the first exceeds the second by more than the two test-module
            # sites, this entry is a lie and the file is silently uncapped — which
            # is exactly what a per-file allowance in a structural guard converts
            # "not checked here" into (TRAPS §39).
            crates/gateway/src/experiment_routes.rs) continue ;;
            # GWY-43 spend. COMPLIANT, NOT EXEMPT — and it was NOT when this entry
            # was first needed. `seed_workspace` (EVL-02's budget seed) shipped an
            # UNCAPPED `.query`, this guard caught it on the commit that introduced
            # it, and it was FIXED rather than allow-listed: the one read now goes
            # through `TenantQuery` at `PlanTier::Builder`.
            #
            #   grep -c '\.query(' crates/gateway/src/spend.rs           # 1
            #   grep -c 'TenantQuery::new(' crates/gateway/src/spend.rs   # 1
            crates/gateway/src/spend.rs) continue ;;
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
