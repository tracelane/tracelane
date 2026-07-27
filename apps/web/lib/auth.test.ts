/**
 * Tests for the auth gate (`requireSession` / `requireGatewayToken`) with the
 *
 * Proves the bypass short-circuits the WorkOS call entirely (Gate 1 / Gate 4 at
 * the real auth seam): when active it resolves the disposable test tenant and
 * NEVER touches `withAuth`; when the flag is unset the real WorkOS path runs.
 *
 * WorkOS (`withAuth`) and `next/navigation` (`redirect`) are mocked — no real
 * network, no real session, per `.claude/rules/testing.md`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Hoisted doubles so the vi.mock factories can reach them.
const h = vi.hoisted(() => ({
	withAuth: vi.fn(),
	redirect: vi.fn((url: string) => {
		throw new Error(`NEXT_REDIRECT:${url}`);
	}),
}));

vi.mock("@workos-inc/authkit-nextjs", () => ({ withAuth: h.withAuth }));
vi.mock("next/navigation", () => ({ redirect: h.redirect }));

beforeEach(() => {
	vi.resetModules();
	h.withAuth.mockReset();
	h.redirect.mockClear();
});

afterEach(() => {
	vi.unstubAllEnvs();
	vi.resetModules();
});

describe("requireSession", () => {
	it("BYPASS: resolves the disposable test tenant WITHOUT calling WorkOS", async () => {
		vi.stubEnv("NODE_ENV", "test"); // !== production
		vi.stubEnv("TRACELANE_E2E_AUTH", "1");
		const { requireSession } = await import("./auth");
		const { E2E_TEST_TENANT_ID, E2E_TEST_USER_ID, E2E_TEST_EMAIL } =
			await import("./e2e-auth");

		const s = await requireSession();

		expect(s.tenantId).toBe(E2E_TEST_TENANT_ID);
		expect(s.userId).toBe(E2E_TEST_USER_ID);
		expect(s.email).toBe(E2E_TEST_EMAIL);
		expect(h.withAuth).not.toHaveBeenCalled();
	});

	it("NO BYPASS: with the flag unset, the real WorkOS path runs", async () => {
		vi.stubEnv("NODE_ENV", "test");
		vi.stubEnv("TRACELANE_E2E_AUTH", "");
		h.withAuth.mockResolvedValue({
			user: { id: "user_real", email: "real@example.com" },
			organizationId: "org_real",
		});
		const { requireSession } = await import("./auth");

		const s = await requireSession();

		expect(h.withAuth).toHaveBeenCalledTimes(1);
		expect(s.tenantId).toBe("org_real");
		expect(s.userId).toBe("user_real");
	});
});

describe("requireGatewayToken", () => {
	it("BYPASS: returns the fake token + disposable tenant WITHOUT calling WorkOS", async () => {
		vi.stubEnv("NODE_ENV", "test");
		vi.stubEnv("TRACELANE_E2E_AUTH", "1");
		const { requireGatewayToken } = await import("./auth");
		const { E2E_TEST_TENANT_ID, E2E_TEST_GATEWAY_TOKEN } = await import(
			"./e2e-auth"
		);

		const r = await requireGatewayToken();

		expect(r.token).toBe(E2E_TEST_GATEWAY_TOKEN);
		expect(r.tenantId).toBe(E2E_TEST_TENANT_ID);
		expect(h.withAuth).not.toHaveBeenCalled();
	});

	it("NO BYPASS: with the flag unset, the real WorkOS token path runs", async () => {
		vi.stubEnv("NODE_ENV", "test");
		vi.stubEnv("TRACELANE_E2E_AUTH", "");
		h.withAuth.mockResolvedValue({
			organizationId: "org_real",
			accessToken: "real.jwt.token",
		});
		const { requireGatewayToken } = await import("./auth");

		const r = await requireGatewayToken();

		expect(h.withAuth).toHaveBeenCalledTimes(1);
		expect(r.token).toBe("real.jwt.token");
		expect(r.tenantId).toBe("org_real");
	});
});
