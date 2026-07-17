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

# ── CI guard scripts ─────────────────────────────────────────────────────────
run "no-auth-stub guard"           bash scripts/ci/no-auth-stub.sh
run "no-raw-ch-query guard"        bash scripts/ci/no-raw-ch-query.sh
run "no-llm-in-recovery guard"     bash scripts/ci/no-llm-in-recovery.sh
if [[ -f scripts/ci/check-tenant-isolation.py ]] && command -v python3 >/dev/null 2>&1; then
    run "tenant-isolation guard"   python3 scripts/ci/check-tenant-isolation.py
fi
# to the marketing site as "35+ providers"). Hand-maintained, they rot silently —
if [[ -f scripts/ci/check-provider-count.py ]] && command -v python3 >/dev/null 2>&1; then
    run "provider-count guard"     python3 scripts/ci/check-provider-count.py
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
    run "npm-scope guard"              python3 scripts/ci/check-npm-scope.py
    # Offline banned-link guard (no network here — the merge gate must stay
    # offline/fast). The full liveness+identity pass runs pre-deploy in web.sh.
    run "external-link guard"          python3 scripts/ci/check-external-links.py --static
    # AFT-1 vocabulary: detectors ⊆ taxonomy map, live⟺detector, seeder ⊆ map —
    # the canonical-id vocabulary can never silently drift from the detectors again.
    run "aft-vocabulary guard"         python3 scripts/ci/check-aft-vocabulary.py
fi

# ── TypeScript / Node ─────────────────────────────────────────────────────────
# CI's `web` job builds the audit-verifier workspace pkg before tsc (apps/web tsc
# resolves @tracelanedev/audit-verifier types from its dist). Mirror it.
run "build @tracelanedev/audit-verifier" pnpm --filter @tracelanedev/audit-verifier build
run "pnpm lint (biome)"            pnpm lint
run "pnpm typecheck"               pnpm typecheck
run "pnpm test"                    pnpm test
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
if command -v ruff >/dev/null 2>&1; then
    run "ruff check"               ruff check .
    run "ruff format --check"      ruff format --check .
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
