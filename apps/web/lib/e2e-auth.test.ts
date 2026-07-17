/**
 *
 * Negative cases first per `.claude/rules/testing.md`. The headline gates:
 *   - Gate 1: a production build that carries the flag THROWS at module load
 *     (proves a prod Worker can never honor the bypass).
 *   - Gate 4: when active, the bypass resolves ONLY to the disposable test
 *     workspace id — never a real tenant.
 *
 * Env is driven with `vi.stubEnv` + `vi.resetModules` so each case re-evaluates
 * the module-load boot-crash from a clean slate. No real network, no real auth.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

beforeEach(() => {
	vi.resetModules();
});

afterEach(() => {
	vi.unstubAllEnvs();
	vi.resetModules();
});

describe("boot-crash (Gate 1) — prod build must never honor the bypass", () => {
	it("REJECT: THROWS at module load when NODE_ENV=production AND flag is set", async () => {
		vi.stubEnv("NODE_ENV", "production");
		vi.stubEnv("TRACELANE_E2E_AUTH", "1");
		await expect(import("./e2e-auth")).rejects.toThrow(/production/i);
	});

	it("does NOT throw at load in production when the flag is unset", async () => {
		vi.stubEnv("NODE_ENV", "production");
		vi.stubEnv("TRACELANE_E2E_AUTH", "");
		const mod = await import("./e2e-auth");
		expect(mod.e2eAuthEnabled()).toBe(false);
	});

	it("REJECT: per-call e2eAuthEnabled() THROWS if env flips to prod+flag after load", async () => {
		// Simulates a Worker where request-scoped env is populated AFTER module
		// load: the module loads clean (non-prod), then the prod+flag combo
		// appears at call time. Layer 2 must still fail loudly.
		vi.stubEnv("NODE_ENV", "development");
		vi.stubEnv("TRACELANE_E2E_AUTH", "1");
		const mod = await import("./e2e-auth");
		expect(mod.e2eAuthEnabled()).toBe(true);

		vi.stubEnv("NODE_ENV", "production");
		expect(() => mod.e2eAuthEnabled()).toThrow(/production/i);
	});
});

describe("activation predicate — explicit dev/test build AND flag required", () => {
	it("ACTIVE: non-prod build with the flag enables the bypass", async () => {
		vi.stubEnv("NODE_ENV", "development");
		vi.stubEnv("TRACELANE_E2E_AUTH", "1");
		const mod = await import("./e2e-auth");
		expect(mod.e2eAuthEnabled()).toBe(true);
	});

	it("INACTIVE: non-prod build WITHOUT the flag keeps the bypass off", async () => {
		vi.stubEnv("NODE_ENV", "development");
		vi.stubEnv("TRACELANE_E2E_AUTH", "");
		const mod = await import("./e2e-auth");
		expect(mod.e2eAuthEnabled()).toBe(false);
	});

	it("INACTIVE: a non-'1' flag value does not activate (exact-match only)", async () => {
		vi.stubEnv("NODE_ENV", "development");
		vi.stubEnv("TRACELANE_E2E_AUTH", "true");
		const mod = await import("./e2e-auth");
		expect(mod.e2eAuthEnabled()).toBe(false);
	});

	it("REJECT: a non-dev NODE_ENV ('staging') WITH the flag THROWS at load (positive allowlist, fail-closed)", async () => {
		vi.stubEnv("NODE_ENV", "staging");
		vi.stubEnv("TRACELANE_E2E_AUTH", "1");
		await expect(import("./e2e-auth")).rejects.toThrow(/dev\/test|production/i);
	});

	it("REJECT: an UNSET NODE_ENV WITH the flag THROWS at load (default-deny, not implicit-allow)", async () => {
		vi.stubEnv("NODE_ENV", "");
		vi.stubEnv("TRACELANE_E2E_AUTH", "1");
		await expect(import("./e2e-auth")).rejects.toThrow(/dev\/test|production/i);
	});
});

describe("disposable test workspace (Gate 4) — never a real tenant", () => {
	it("the constant is the clearly-marked disposable UUID", async () => {
		const mod = await import("./e2e-auth");
		expect(mod.E2E_TEST_TENANT_ID).toBe("00000000-0000-4000-8000-0000e2e2e2e2");
	});

	it("the test session resolves ONLY to the disposable tenant", async () => {
		vi.stubEnv("NODE_ENV", "development");
		vi.stubEnv("TRACELANE_E2E_AUTH", "1");
		const mod = await import("./e2e-auth");
		const s = mod.e2eTestSession();
		expect(s.tenantId).toBe(mod.E2E_TEST_TENANT_ID);
		expect(s.userId).toBe(mod.E2E_TEST_USER_ID);
		expect(s.email).toBe(mod.E2E_TEST_EMAIL);
	});

	it("the gateway-token bypass returns a fake token bound to the disposable tenant", async () => {
		vi.stubEnv("NODE_ENV", "development");
		vi.stubEnv("TRACELANE_E2E_AUTH", "1");
		const mod = await import("./e2e-auth");
		const g = mod.e2eTestGatewayToken();
		expect(g.tenantId).toBe(mod.E2E_TEST_TENANT_ID);
		expect(g.token).toBe(mod.E2E_TEST_GATEWAY_TOKEN);
		// A real WorkOS JWT has 3 dot-separated segments; the fake token must not
		// look like one (the gateway 401s it on purpose).
		expect(g.token.split(".").length).toBe(1);
	});
});

describe("mint defense-in-depth — fail closed if callers don't gate", () => {
	it("REJECT: e2eTestSession() THROWS when the bypass is INACTIVE (dev, no flag)", async () => {
		vi.stubEnv("NODE_ENV", "development");
		vi.stubEnv("TRACELANE_E2E_AUTH", "");
		const mod = await import("./e2e-auth");
		expect(mod.e2eAuthEnabled()).toBe(false);
		expect(() => mod.e2eTestSession()).toThrow(/INACTIVE/i);
	});

	it("REJECT: e2eTestGatewayToken() THROWS when the bypass is INACTIVE (dev, no flag)", async () => {
		vi.stubEnv("NODE_ENV", "development");
		vi.stubEnv("TRACELANE_E2E_AUTH", "");
		const mod = await import("./e2e-auth");
		expect(() => mod.e2eTestGatewayToken()).toThrow(/INACTIVE/i);
	});

	it("REJECT: both mint fns THROW if env flips to prod+flag after a clean load", async () => {
		// Module loads clean (dev+flag), then the prod+flag combo appears at call
		// time (Worker request-scoped env). The mint must fail loudly, not bypass.
		vi.stubEnv("NODE_ENV", "development");
		vi.stubEnv("TRACELANE_E2E_AUTH", "1");
		const mod = await import("./e2e-auth");
		expect(mod.e2eTestSession().tenantId).toBe(mod.E2E_TEST_TENANT_ID);

		vi.stubEnv("NODE_ENV", "production");
		expect(() => mod.e2eTestSession()).toThrow(/production/i);
		expect(() => mod.e2eTestGatewayToken()).toThrow(/production/i);
	});
});
