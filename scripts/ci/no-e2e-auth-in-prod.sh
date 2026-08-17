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
# Falsify:      bash scripts/ci/no-e2e-auth-in-prod.sh --selftest
#               (builds a throwaway git repo, plants each leak shape, proves each
#                BLOCKS — and proves the three LEGITIMATE homes still pass)

set -euo pipefail

TOKEN='TRACELANE_E2E_AUTH'

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

usage() {
	cat <<'EOF'
usage: no-e2e-auth-in-prod.sh [--selftest | --help]

  (no args)    run the guard against the current repo
               exit 0 = flag confined · 1 = prod-visible leak / missing gitignore
  --selftest   build a throwaway git repo, plant each leak, prove each blocks
  -h, --help   this message
EOF
}

# ---------------------------------------------------------------- selftest ---
# Every check here is git-relative to $PWD (`git grep`, `git ls-files`,
# `git check-ignore`), so the whole guard can be falsified inside a synthetic
# repo under mktemp. Nothing in the real tree is written or staged.
selftest() {
	local fails=0 tmp repo before after rc=0

	before="$(git status --porcelain 2>/dev/null || true)"

	# Case 0 — the baseline negative. Without it, a guard that failed on every
	# input would "catch" all eleven plants below and still be worthless.
	bash "$SELF" >/dev/null 2>&1 || rc=$?
	if [[ "$rc" -ne 0 ]]; then
		echo "SELFTEST ABORT: the guard is already RED against this tree (exit $rc)." >&2
		echo "Fix the tree first — a red baseline makes every planted case vacuous." >&2
		return 1
	fi
	echo "✓ clean case: the real repo tree passes (exit 0)"

	tmp="$(mktemp -d)"
	trap 'rm -rf "$tmp"' EXIT
	repo="$tmp/fixture"

	# A minimal repo shaped like apps/web: the three prod sinks, the allowlisted
	# bypass source, a doc, and a .gitignore that hides the two secret paths.
	_fresh() {
		rm -rf "$repo"
		mkdir -p "$repo/apps/web/lib" "$repo/apps/web/e2e" "$repo/docs"
		printf 'apps/web/.dev.vars\napps/web/e2e/.auth/\n' >"$repo/.gitignore"
		printf '{ "name": "web", "private": true }\n' >"$repo/apps/web/package.json"
		printf '{ "main": "worker.js" }\n' >"$repo/apps/web/wrangler.jsonc"
		printf 'export default {}\n' >"$repo/apps/web/next.config.ts"
		printf 'export default {}\n' >"$repo/apps/web/open-next.config.ts"
		printf 'export const bypassActive = false\n' >"$repo/apps/web/lib/e2e-auth.ts"
		printf 'export const session = null\n' >"$repo/apps/web/lib/session.ts"
		printf '# notes\n' >"$repo/docs/NOTES.md"
		git -C "$repo" init -q -b main
		git -C "$repo" add -A
		git -C "$repo" -c user.email=selftest@example.invalid -c user.name=selftest \
			-c commit.gpgsign=false commit -q --no-verify -m fixture
	}

	_check() { # label, expected_exit, [expected message substring]
		local got=0 out
		out="$( (cd "$repo" && bash "$SELF") 2>&1 )" || got=$?
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

	# 1. An untouched fixture must pass, or nothing below is discriminating.
	_fresh
	_check "clean case: a fixture repo with no leak passes" 0 "guard: OK"

	# 2-3. The hard-deny sinks — files a prod build / Worker actually reads.
	_fresh
	printf '{ "vars": { "%s": "1" } }\n' "$TOKEN" >"$repo/apps/web/wrangler.jsonc"
	_check "flag in wrangler.jsonc BLOCKS" 1 "must NOT appear in apps/web/wrangler.jsonc"

	_fresh
	printf 'export default { env: { %s: "1" } }\n' "$TOKEN" >"$repo/apps/web/next.config.ts"
	_check "flag in next.config.ts BLOCKS" 1 "must NOT appear in apps/web/next.config.ts"

	# 4. A COMMITTED env file — the leak that looks harmless because it is only
	#    an "example".
	_fresh
	printf '%s=1\n' "$TOKEN" >"$repo/apps/web/.dev.vars.example"
	git -C "$repo" add -f apps/web/.dev.vars.example
	_check "flag in a committed .dev.vars.example BLOCKS" 1 "committed env config"

	# 5. Default-deny sweep, TRACKED file: prod app source that is not on the
	#    allowlist.
	_fresh
	printf 'export const session = "%s"\n' "$TOKEN" >"$repo/apps/web/lib/session.ts"
	_check "flag in tracked non-allowlisted app source BLOCKS" 1 "not an allowlisted location"

	# 6. Default-deny sweep, UNTRACKED file: the not-yet-committed new module.
	#    This is what `git grep --untracked` buys, so it gets its own case.
	_fresh
	printf 'export const leak = "%s"\n' "$TOKEN" >"$repo/apps/web/lib/leak.ts"
	_check "flag in an UNTRACKED new source file BLOCKS" 1 "apps/web/lib/leak.ts"

	# 7-9. The three legitimate homes. A guard that also fired here would be
	#      unusable, and the allowlist would be untested.
	_fresh
	printf 'export const bypassActive = process.env.%s === "1"\n' "$TOKEN" \
		>"$repo/apps/web/lib/e2e-auth.ts"
	_check "clean case: flag in the allowlisted bypass source passes" 0 "guard: OK"

	_fresh
	printf 'Set %s=1 in .dev.vars to run the E2E suite.\n' "$TOKEN" >"$repo/docs/NOTES.md"
	_check "clean case: flag mentioned in a *.md doc passes" 0 "guard: OK"

	_fresh
	printf '%s=1\n' "$TOKEN" >"$repo/apps/web/.dev.vars"
	_check "clean case: flag in the GITIGNORED .dev.vars passes" 0 "guard: OK"

	# 10-11. The positive assertions: both secret paths must stay gitignored.
	_fresh
	printf 'apps/web/e2e/.auth/\n' >"$repo/.gitignore"
	_check "un-gitignoring apps/web/.dev.vars BLOCKS" 1 "apps/web/.dev.vars is NOT gitignored"

	_fresh
	printf 'apps/web/.dev.vars\n' >"$repo/.gitignore"
	_check "un-gitignoring apps/web/e2e/.auth/ BLOCKS" 1 "e2e/.auth/ is NOT gitignored"

	# 12. sideEffects would let a bundler tree-shake the Layer-1 boot-crash away.
	_fresh
	printf '{ "name": "web", "sideEffects": false }\n' >"$repo/apps/web/package.json"
	_check "declaring sideEffects in apps/web/package.json BLOCKS" 1 "declares sideEffects"

	rm -rf "$tmp"
	trap - EXIT

	# 13. State restored: everything above lived under mktemp, so the real repo
	#     must be byte-identical to how we found it.
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
--selftest)
	selftest
	exit $?
	;;
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
