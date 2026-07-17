/**
 *
 * Purpose: let an automated *local* E2E run (the dead-button sweep) reach
 * authenticated pages against a dev server without the WorkOS login UI — which
 * cannot pass prod bot-protection headlessly. The bypass resolves to a single
 * FIXED, DISPOSABLE test workspace; it can NEVER resolve to a real tenant and
 * can NEVER activate in a production build.
 *
 * Fail-closed, defense in depth (two layers):
 *   1. BOOT-CRASH at module load: if a production build somehow carries the
 *      opt-in flag, this module THROWS at import time so the Worker crashes
 *      loudly instead of silently bypassing auth.
 *   2. Per-call re-assert: `e2eAuthEnabled()` re-evaluates the environment on
 *      every call (env may be populated per-request on a Worker, after module
 *      load). It THROWS in a prod build that carries the flag, and only ever
 *      returns `true` in a non-prod build with the explicit flag.
 *
 * Activation predicate (BOTH required):
 *   - `process.env.NODE_ENV !== 'production'`  (a prod build can never honor it)
 *   - `process.env.TRACELANE_E2E_AUTH === '1'` (explicit opt-in)
 *
 * The flag lives ONLY in gitignored config (`apps/web/.dev.vars`). It must
 * never appear in `wrangler.jsonc`, a committed `.env*`, or a CF Worker secret
 * — `scripts/ci/no-e2e-auth-in-prod.sh` enforces that at merge time.
 *
 * Callers: `lib/auth.ts` (requireSession / requireGatewayToken) and
 * `middleware.ts`.
 *
 * Postgres layer (a CHECK on `tenants.id`), but NOT at ClickHouse. That gap is
 * inert under today's threat model — the fake gateway token (below) fails gateway
 * auth with a 401 before any ClickHouse write path is reachable, so no bypass
 * span/trace can land. If a future E2E run is ever given a REAL gateway token for
 * the disposable tenant, add a ClickHouse-side guard before pointing it at a
 * shared cluster.
 */

import type { Session } from "@/lib/auth";

/**
 * The single disposable test workspace id the bypass resolves to. Clearly
 * marked (`e2e2e2e2` suffix) so it can never be confused with a real WorkOS
 * organization id / internal tenant UUID. NEVER derived from a request.
 */
export const E2E_TEST_TENANT_ID = "00000000-0000-4000-8000-0000e2e2e2e2";

/** Fixed test user id for the disposable workspace. Never a real user. */
export const E2E_TEST_USER_ID =
	"e2e-test-user-00000000-0000-4000-8000-0000e2e2e2e2";

/** Fixed test email for the disposable workspace. */
export const E2E_TEST_EMAIL = "e2e@tracelane.test";

/**
 * Deliberately-fake gateway bearer for the bypass. The Rust gateway will 401
 * this (it is not a real WorkOS JWT), so trace/SLO reads degrade to the
 * warming/empty state — pages still RENDER, which is exactly what the
 * dead-button sweep needs.
 */
export const E2E_TEST_GATEWAY_TOKEN = "e2e-fake-gateway-token-NOT-A-REAL-JWT";

// Positive allowlist (default-DENY): the bypass is permitted ONLY in an explicit
// dev/test build. Unset / empty / "staging" / a typo'd NODE_ENV is NOT dev — so a
// stray flag in any non-dev env fails CLOSED (boot-crash + bypass off) instead of
// silently activating. Removes the dependency on Next.js inlining NODE_ENV as
function isExplicitDev(): boolean {
	const env = process.env.NODE_ENV;
	return env === "development" || env === "test";
}

function flagSet(): boolean {
	return process.env.TRACELANE_E2E_AUTH === "1";
}

/**
 * Throw if a production build is carrying the E2E flag. Shared by the
 * module-load boot-crash and the per-call check so the loud failure happens at
 * BOTH seams (cold start AND per request, since env may populate late on a
 * Worker).
 */
function assertNotProductionBypass(): void {
	if (!isExplicitDev() && flagSet()) {
		throw new Error(
			`FATAL: TRACELANE_E2E_AUTH is set outside an explicit dev/test build (NODE_ENV=${process.env.NODE_ENV ?? "unset"}). The E2E auth bypass must never be reachable in production. Refusing to start. It belongs only in a local, gitignored apps/web/.dev.vars for \`pnpm dev\`.`,
		);
	}
}

// Layer 1 — BOOT-CRASH at module load. Evaluated the moment this module is
// imported (transitively, the moment lib/auth.ts or middleware.ts loads).
// NOTE: the flag is for `pnpm dev` (NODE_ENV=development) ONLY. `cf:preview` /
// `cf:deploy` serve a production build (NODE_ENV="production"), so they boot-crash
// if the flag is set — by design.
//
// boot-crash IS a module-load side effect. A `sideEffects: false` declaration
// lets a bundler tree-shake a module whose exported bindings look unused, which
// would silently elide this Layer-1 check and leave only the per-call Layer 2.
// `apps/web/package.json` currently has NO `sideEffects` key (the safe default).
assertNotProductionBypass();

/**
 * Whether the dev-only E2E auth bypass is active for this request.
 *
 * Returns `true` ONLY in a non-production build with `TRACELANE_E2E_AUTH=1`.
 * THROWS (fail-closed + loud) if called in a production build that carries the
 * flag. Returns `false` in every other case.
 *
 * @returns `true` iff the bypass should short-circuit auth.
 */
export function e2eAuthEnabled(): boolean {
	// Layer 2 — re-assert per call (env can be populated per-request on a
	// Worker, after module load). If this passes, NOT(non-dev && flag) holds.
	assertNotProductionBypass();
	return isExplicitDev() && flagSet();
}

/**
 * unless the bypass is genuinely active. The mint functions below are exported,
 * so a future caller bug could invoke them WITHOUT first checking
 * {@link e2eAuthEnabled} — this guard makes that fail CLOSED (throw) instead of
 * silently handing back a bypass session/token. Don't trust callers.
 *
 * `e2eAuthEnabled()` itself throws in a prod build that carries the flag and
 * returns `false` in every non-active case, so a single `!e2eAuthEnabled()`
 * check covers both failure modes.
 */
function assertBypassActiveToMint(fn: string): void {
	if (!e2eAuthEnabled()) {
		throw new Error(
			`FATAL: ${fn}() called while the E2E auth bypass is INACTIVE. It mints a disposable test identity and must never run unless e2eAuthEnabled() is true (a non-prod build with TRACELANE_E2E_AUTH=1). Refusing — callers must gate on e2eAuthEnabled().`,
		);
	}
}

/**
 * The fixed test session for the disposable workspace. Only callable when the
 * bypass is active ({@link e2eAuthEnabled} is `true`); throws otherwise. The
 * tenant is the hardcoded disposable id, never derived from a request.
 */
export function e2eTestSession(): Session {
	assertBypassActiveToMint("e2eTestSession");
	return {
		tenantId: E2E_TEST_TENANT_ID,
		userId: E2E_TEST_USER_ID,
		email: E2E_TEST_EMAIL,
		// Disposable test workspace acts as owner (full-access UI paths).
		role: "owner",
	};
}

/**
 * The fixed test gateway credential for the disposable workspace. Only callable
 * when the bypass is active; throws otherwise. Returns a deliberately-fake token
 * (the gateway 401s it) plus the disposable tenant id.
 */
export function e2eTestGatewayToken(): { token: string; tenantId: string } {
	assertBypassActiveToMint("e2eTestGatewayToken");
	return { token: E2E_TEST_GATEWAY_TOKEN, tenantId: E2E_TEST_TENANT_ID };
}
