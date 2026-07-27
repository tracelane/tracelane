#!/usr/bin/env bash
# scripts/ci/no-e2e-auth-in-prod.sh
#
# CI guard for (dev-only E2E auth bypass).
#
# The bypass in apps/web/lib/e2e-auth.ts short-circuits WorkOS auth to a fixed
# DISPOSABLE test workspace when `NODE_ENV!==production` AND `TRACELANE_E2E_AUTH=1`.
# The opt-in flag must live ONLY in gitignored config (apps/web/.dev.vars) so a
# production Cloudflare Worker can never see it. This guard fails the merge if
# the flag token `TRACELANE_E2E_AUTH` appears ANYWHERE a prod build can see it:
#   - NOT in wrangler.jsonc
#   - NOT in any committed .env* / .dev.vars.example / next.config / open-next.config
#   - NOT as a CF Worker secret/var reference
#   - NOT in any prod-shipped app source
#
# It is allowed ONLY in:
#   - the bypass source            apps/web/lib/e2e-auth.ts
#   - its tests                    apps/web/lib/e2e-auth.test.ts, apps/web/lib/auth.test.ts
#   - the E2E test HARNESS that drives the bypass (L16 dead-button gate), none of
#     which is bundled into the prod Worker (open-next bundles app/lib/components/
#     middleware, NOT these):
#       apps/web/playwright.config.ts  (test-only; boots `pnpm dev`, NODE_ENV=development)
#       apps/web/e2e/*                 (Playwright specs + fixtures; never shipped)
#       .github/workflows/ci.yml       (the l16-e2e-gate CI job; CI is not a prod build)
#   - this guard                   scripts/ci/no-e2e-auth-in-prod.sh
#   - documentation (*.md)         trackers/docs are never bundled into the Worker
#   - gitignored apps/web/.dev.vars (never tracked → never scanned here)
# The runtime is prod-safe regardless: e2e-auth.ts BOOT-CRASHES a prod build that
# carries the flag AND re-asserts NODE_ENV!==production per call, so these
# test-infra mentions can never activate a bypass in prod.
#
# Run locally:  bash scripts/ci/no-e2e-auth-in-prod.sh
# CI:           wired into .github/workflows/ci.yml job `no-e2e-auth-in-prod`.

set -euo pipefail

TOKEN='TRACELANE_E2E_AUTH'
FAIL=0

# Allowlist: exact tracked paths permitted to mention the token, plus the *.md
# doc class (never shipped to the Worker). Anything else that mentions the token
# is a prod-visible leak and fails the gate (default-deny).
is_allowed() {
	case "$1" in
		apps/web/lib/e2e-auth.ts) return 0 ;;
		apps/web/lib/e2e-auth.test.ts) return 0 ;;
		apps/web/lib/auth.test.ts) return 0 ;;
		# L16 E2E test harness — drives the bypass, never bundled into the Worker.
		apps/web/playwright.config.ts) return 0 ;;
		apps/web/e2e/*) return 0 ;;
		.github/workflows/ci.yml) return 0 ;;
		scripts/ci/no-e2e-auth-in-prod.sh) return 0 ;;
		*.md) return 0 ;;
		*) return 1 ;;
	esac
}

# 1) Hard-deny the dangerous sinks explicitly (clear, targeted error). These are
#    the files a prod build / Worker config actually reads. `git grep --untracked`
#    respects .gitignore, so gitignored apps/web/.dev.vars is never scanned.
SINKS=(
	"apps/web/wrangler.jsonc"
	"apps/web/next.config.ts"
	"apps/web/open-next.config.ts"
)
for f in "${SINKS[@]}"; do
	if [[ -f "$f" ]] && grep -Fq "$TOKEN" "$f"; then
		echo "FAIL: '$TOKEN' must NOT appear in $f — a prod build/Worker reads this." >&2
		FAIL=1
	fi
done

# Any committed env-style config (.env*, .dev.vars* that are TRACKED — e.g. a
# committed .dev.vars.example) is also a hard-deny sink.
while IFS= read -r f; do
	[[ -z "$f" ]] && continue
	if grep -Fq "$TOKEN" "$f"; then
		echo "FAIL: '$TOKEN' must NOT appear in committed env config $f — only in gitignored apps/web/.dev.vars." >&2
		FAIL=1
	fi
done < <(git ls-files -- 'apps/web/.env*' 'apps/web/.dev.vars*' '*.env' '.env*' 2>/dev/null || true)

# 2) Default-deny sweep across all tracked + untracked-non-ignored files.
#    --untracked makes the guard catch a new (not-yet-committed) source file that
#    leaks the token, while still honoring .gitignore (so .dev.vars is skipped).
while IFS= read -r f; do
	[[ -z "$f" ]] && continue
	if ! is_allowed "$f"; then
		echo "FAIL: '$TOKEN' found in $f — not an allowlisted location." >&2
		echo "      The flag belongs ONLY in gitignored apps/web/.dev.vars (+ the bypass source/tests)." >&2
		FAIL=1
	fi
done < <(git grep --untracked -l -F "$TOKEN" -- . 2>/dev/null || true)

# 3) Positive assertion: apps/web/.dev.vars MUST be gitignored so the flag can
#    never be accidentally committed.
if ! git check-ignore -q apps/web/.dev.vars; then
	echo "FAIL: apps/web/.dev.vars is NOT gitignored — the E2E flag could be committed." >&2
	FAIL=1
fi

# 4) Positive assertion: apps/web/e2e/.auth/ (E2E session state) MUST be gitignored.
if ! git check-ignore -q apps/web/e2e/.auth/state.json; then
	echo "FAIL: apps/web/e2e/.auth/ is NOT gitignored — E2E session state could be committed." >&2
	FAIL=1
fi

# 5) The Layer-1 boot-crash in apps/web/lib/e2e-auth.ts is a MODULE-LOAD side
#    effect (it THROWS at import time in a prod build carrying the flag).
#    Declaring `"sideEffects": false` would let a bundler tree-shake that module
#    away when its exports look unused, SILENTLY eliding the boot-crash and
#    leaving only the per-call Layer 2. Block the field where a bundler reads it.
#
for f in apps/web/package.json apps/web/open-next.config.ts; do
	if [[ -f "$f" ]] && grep -Eq '["'\'']?sideEffects["'\'']?[[:space:]]*:' "$f"; then
		echo "FAIL: '$f' declares sideEffects — this can tree-shake the e2e-auth Layer-1 boot-crash (a module-load side effect). Remove it; the safe default is no key (= side-effectful)." >&2
		FAIL=1
	fi
done

if [[ "$FAIL" -ne 0 ]]; then
	echo "no-e2e-auth-in-prod guard: FAILED." >&2
	exit 1
fi

echo "no-e2e-auth-in-prod guard: OK (flag confined to gitignored config + bypass source/tests)."
