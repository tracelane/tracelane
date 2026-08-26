/**
 * Tests for the auth gate (`requireSession` / `requireGatewayToken`) with the
 * dev-only E2E bypass wired in.
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

describe("canAdmin (PL-9 — the UI gate must mirror the FIXED gateway gate)", () => {
	// Negative first, per .claude/rules/testing.md. Every one of these returned
	// TRUE before PL-9: the old body denied only a literal "member"/"viewer", so
	// an unrecognised slug, a renamed role, null and undefined all passed —
	// and WorkOS's default org role is `admin`, so the DEFAULT fell through to
	// full access.
	it("DENIES an unrecognised or absent role slug", async () => {
		const { canAdmin } = await import("./auth");
		for (const role of [
			"wat",
			"admin_typo",
			"Admin", // slugs are case-sensitive, matching Role::from_slug
			"Owner",
			"",
			null,
			undefined,
		]) {
			expect(canAdmin(role), `role=${String(role)} must not admin`).toBe(false);
		}
	});

	it("DENIES member and viewer", async () => {
		const { canAdmin } = await import("./auth");
		expect(canAdmin("member")).toBe(false);
		expect(canAdmin("viewer")).toBe(false);
	});

	// The lockout guard: `admin` is WorkOS's built-in org role, so denying it
	// would lock the real org owner out of billing and BYOK.
	it("ALLOWS owner and the WorkOS built-in admin", async () => {
		const { canAdmin } = await import("./auth");
		expect(canAdmin("owner")).toBe(true);
		expect(canAdmin("admin")).toBe(true);
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

	// second instance. `withAuth` THROWS when it must refresh an expired
	// access-token whose verifier cookies have also expired: it writes the new cookie
	// during an RSC render, which Next.js forbids ("Cookies can only be modified in a
	// Server Action or Route Handler"). Unhandled that reached the error boundary on
	// 7 of 11 prod pages. The contract is a REDIRECT, never a throw.
	it("a THROWING withAuth redirects to sign-in instead of propagating", async () => {
		vi.stubEnv("NODE_ENV", "test");
		vi.stubEnv("TRACELANE_E2E_AUTH", "");
		h.withAuth.mockRejectedValue(
			new Error(
				"Cookies can only be modified in a Server Action or Route Handler",
			),
		);
		const { requireGatewayToken } = await import("./auth");

		// `redirect()` is mocked to throw a NEXT_REDIRECT sentinel, so the assertion is
		// that we get THAT and not the cookie error — the whole point of the fix.
		await expect(requireGatewayToken()).rejects.toThrow(/NEXT_REDIRECT/);
		expect(h.redirect).toHaveBeenCalledWith("/sign-in");
	});

	it("does NOT pass ensureSignedIn — its auto-redirect is the un-convertible throw", async () => {
		vi.stubEnv("NODE_ENV", "test");
		vi.stubEnv("TRACELANE_E2E_AUTH", "");
		h.withAuth.mockResolvedValue({
			organizationId: "org_real",
			accessToken: "real.jwt.token",
		});
		const { requireGatewayToken } = await import("./auth");
		await requireGatewayToken();

		const arg = h.withAuth.mock.calls[0]?.[0];
		expect(arg?.ensureSignedIn).toBeUndefined();
	});
});
