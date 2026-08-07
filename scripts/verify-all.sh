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
#   scripts/verify-all.sh --fast     # skip the slow eval suite + bench
#   SKIP_PY=1 scripts/verify-all.sh  # skip Python (e.g. pytest not installed)
#
# Exit code: 0 iff every selected step passed.

set -uo pipefail
cd "$(dirname "$0")/.."

FAST=0
[[ "${1:-}" == "--fast" ]] && FAST=1

# ── result accounting ──────────────────────────────────────────────────────
declare -a NAMES STATUSES
overall=0

run() {
    local name="$1"; shift
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
run "cargo fmt --check"            cargo fmt --check
# --all-targets so test/bench code is linted too (audit finding P2-1: the
# CI gate previously linted only lib+bin targets, hiding test-code lint rot).
run "cargo clippy (all targets)"   cargo clippy --workspace --all-targets -- -D warnings
run "cargo test --all-features"    cargo test --workspace --all-features

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
run "no-raw-ch-query guard"        bash scripts/ci/no-raw-ch-query.sh
run "no-llm-in-recovery guard"     bash scripts/ci/no-llm-in-recovery.sh
if [[ -f scripts/hooks/protect-uncommitted-from-git-restore.sh ]]; then
    run "git-restore guard selftest" bash scripts/hooks/protect-uncommitted-from-git-restore.sh --selftest
fi
if [[ -f scripts/hooks/protect-ponytail-markers.sh ]]; then
    run "ponytail guard selftest"    bash scripts/hooks/protect-ponytail-markers.sh --selftest
fi
if [[ -f scripts/ci/check-guard-parity.py ]] && command -v python3 >/dev/null 2>&1; then
    # it must PASS when they agree and BLOCK when either drifts.
    run "guard-parity selftest" python3 scripts/ci/check-guard-parity.py --selftest
    run "guard-parity"          python3 scripts/ci/check-guard-parity.py
fi
if [[ -f bench/gateway/summary-gate.selftest.mjs ]] && command -v node >/dev/null 2>&1; then
    # The benchmark 2xx gate. Its predecessor was only ever tested for BLOCKING,
    # and shipped unable to PASS any run at all — it read metrics[n].count where
    # k6 puts metrics[n].values.count, on every k6 version. This selftest runs
    # both halves against real captured k6 payloads.
    run "bench 2xx-gate selftest" node bench/gateway/summary-gate.selftest.mjs
fi
if [[ -f scripts/ci/check-tenant-isolation.py ]] && command -v python3 >/dev/null 2>&1; then
    # Selftest first — it plants violations and asserts the guard reports them.
    # A guard nobody has watched fail is assumed decorative.
    run "tenant-isolation selftest" python3 scripts/ci/check-tenant-isolation.py --selftest
    run "tenant-isolation guard"   python3 scripts/ci/check-tenant-isolation.py
fi
# to the marketing site as "35+ providers"). Hand-maintained, they rot silently —
if [[ -f scripts/ci/check-provider-count.py ]] && command -v python3 >/dev/null 2>&1; then
    run "provider-count guard"     python3 scripts/ci/check-provider-count.py
fi
# Together, Fireworks and OpenRouter routed (and counted toward "35") while the
# BYOK allowlist rejected their key upload with 400, so no customer could store
# one. Three hand-maintained lists that must agree — registry, allowlist, dropdown.
if [[ -f scripts/ci/check-byok-provider-coverage.py ]] && command -v python3 >/dev/null 2>&1; then
    run "byok-provider-coverage guard" python3 scripts/ci/check-byok-provider-coverage.py
fi
# Concurrent gateway fan-out budget. /dashboard fired EIGHT gateway subrequests
# in one Promise.all, which resolves at the SLOWEST member — so it sampled the
# wide-area tail eight times and took 6s+ per load while the gateway itself
# answered in 0.9ms on-node. No existing gate could see it: the bench suite
# measures GATEWAY latency (green throughout) and nothing measures latency from
# where a customer stands. Selftest first — a guard nobody has watched fail is
# assumed decorative. (runbooks/RCA-dashboard-fanout-tail-latency.md)
if [[ -f scripts/ci/check-page-fanout.py ]] && command -v python3 >/dev/null 2>&1; then
    run "page-fanout selftest"     python3 scripts/ci/check-page-fanout.py --selftest
    run "page-fanout guard"        python3 scripts/ci/check-page-fanout.py
fi
# Mirrored from ci.yml: these guards were CI-ONLY and therefore enforced
# NOWHERE while the CI workflow was disabled (dark 2026-06-20→). Local gate now
# carries the load-bearing ones so a disabled CI can't silently un-guard them.
run "tenant-id-provenance guard"   bash scripts/ci/check-tenant-id-provenance.sh
run "prod-nats-wiring guard"       bash scripts/ci/check-span-publish-wiring.sh
run "genai-attr-keys guard"        bash scripts/ci/check-genai-attr-keys.sh
run "no-e2e-auth-in-prod guard"    bash scripts/ci/no-e2e-auth-in-prod.sh
if command -v python3 >/dev/null 2>&1; then
    run "span-publish-ordering guard" python3 scripts/ci/check-span-publish-ordering.py
    run "no-internal-refs-in-ui guard" python3 scripts/ci/no-internal-refs-in-ui.py
    run "gateway-fallback guard"       python3 scripts/ci/check-no-localhost-gateway-fallback.py
    run "npm-scope guard"              python3 scripts/ci/check-npm-scope.py
    # Doc classification: every .md/.mdx in the export set carries a tag, and no
    # CONFIDENTIAL/RESTRICTED doc sits inside it. MUST be here, not only in ci.yml:
    # private-repo CI skips the root jobs on a direct push, so this hook is the only
    # place the gate actually runs. Selftest first — it plants an untagged file, a
    # CONFIDENTIAL one and a bogus level, and proves each blocks.
    run "doc-classification selftest"  python3 scripts/ci/check-doc-classification.py --selftest
    run "doc-classification guard"     python3 scripts/ci/check-doc-classification.py
    # The map is generated; a stale map is a lying map. Same reasoning as the guard above:
    # this must live in verify-all (the pre-push hook) because private-repo CI skips the
    # root jobs on a direct push.
    # Selftest FIRST — it proves the generator is deterministic (a flapping --check
    # teaches everyone to ignore it) and that planted drift is actually detected.
    run "claim-anchor selftest"        python3 scripts/ci/check-claim-anchors.py --selftest
    run "claim anchors hold"           python3 scripts/ci/check-claim-anchors.py
    run "doc-consistency selftest"     python3 scripts/ci/check-doc-consistency.py --selftest
    run "doc cross-doc consistency"    python3 scripts/ci/check-doc-consistency.py
    run "doc-index selftest"           python3 scripts/ci/build-doc-index.py --selftest
    run "doc-index freshness"          python3 scripts/ci/build-doc-index.py --check
    # Promotion gate selftest only — the gate itself is NOT run here. Its verdict depends
    # on adversarial-pass currency, which is deliberately allowed to be stale between
    # promotions; failing every push on that would be noise. The selftest proves the two
    # hard blockers still fire.
    run "promotion-gate selftest"      python3 scripts/ci/check-promotion-readiness.py --selftest
    # Offline banned-link guard (no network here — the merge gate must stay
    # offline/fast). The full liveness+identity pass runs pre-deploy in web.sh.
    run "external-link guard"          python3 scripts/ci/check-external-links.py --static
    # AFT-1 vocabulary: detectors ⊆ taxonomy map, live⟺detector, seeder ⊆ map —
    # the canonical-id vocabulary can never silently drift from the detectors again.
    run "aft-vocabulary guard"         python3 scripts/ci/check-aft-vocabulary.py
    # dispatch + key-lookup + span-attribution must delegate to it. A second table
    # is the cross-provider BYOK-misroute drift surface.
    run "action-sha-pin guard"      python3 scripts/ci/check-action-sha-pins.py
    run "provider-mapping guard"       python3 scripts/ci/check-provider-mapping-single-source.py
    # No UI/API reads of dead/legacy entitlement columns (tenants.auditEnabled) —
    # the "invisible entitlement-gated UI" class (internal incident review).
    run "legacy-entitlement-column guard" python3 scripts/ci/no-legacy-entitlement-columns.py
fi

# ── TypeScript / Node ─────────────────────────────────────────────────────────
# CI's `web` job builds the audit-verifier workspace pkg before tsc (apps/web tsc
# resolves @tracelanedev/audit-verifier types from its dist). Mirror it.
run "build @tracelanedev/audit-verifier" pnpm --filter @tracelanedev/audit-verifier build
run "pnpm lint (biome)"            pnpm lint
run "pnpm typecheck"               pnpm typecheck
run "pnpm test"                    pnpm test
# knip: dead files/deps in apps/web (2026-07-23 — the CLAUDE.md-promised
# dead-code gate, previously wired nowhere). Export-level classes are excluded
# here; they're audited opportunistically, not merge-gated.
run "knip (apps/web files+deps)"   bash -c 'cd apps/web && pnpm exec knip --include files,dependencies,devDependencies --no-config-hints'
# Supply-chain (advisory; network) — mirrors ci.yml secret-scan's pnpm audit.
if command -v pnpm >/dev/null 2>&1; then
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
if command -v gitleaks >/dev/null 2>&1; then
    _gl_tmp="$(mktemp -d)"
    git archive HEAD | tar -x -C "$_gl_tmp"
    run "gitleaks (tracked snapshot)" gitleaks dir "$_gl_tmp" --no-banner --config .gitleaks.toml
    rm -rf "$_gl_tmp"
else
    skip "gitleaks secret scan" "gitleaks not installed — brew install gitleaks / go install github.com/gitleaks/gitleaks/v8@latest"
fi
if [[ "$FAST" -eq 0 ]]; then
    run "pnpm eval:run --suite=all" pnpm eval:run --suite=all
else
    skip "pnpm eval:run --suite=all" "--fast"
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
        run "ruff check"               ruff check .
        run "ruff format --check"      ruff format --check .
    fi
else
    skip "ruff" "ruff not installed"
fi
if [[ "${SKIP_PY:-0}" == "1" ]]; then
    skip "pytest" "SKIP_PY=1"
elif command -v pytest >/dev/null 2>&1; then
    run "pytest"                   pytest -q
elif python3 -c "import pytest" >/dev/null 2>&1; then
    run "pytest"                   python3 -m pytest -q
else
    skip "pytest" "pytest not installed — install: pip install -e 'evals[dev]' or pip install pytest"
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo
echo "═════════════════════════ verify-all summary ═════════════════════════"
for i in "${!NAMES[@]}"; do
    printf "  %-32s %s\n" "${NAMES[$i]}" "${STATUSES[$i]}"
done
echo "═══════════════════════════════════════════════════════════════════════"
if [[ "$overall" -eq 0 ]]; then
    echo "ALL GREEN ✔"
else
    echo "FAILURES PRESENT ✗ — do not merge"
fi
exit "$overall"
