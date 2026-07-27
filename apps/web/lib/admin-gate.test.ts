/**
 * Helper-level tests for `requireOrgAdmin` — pins the fail-closed response
 * mapping (501 unconfigured / 502 lookup-failed / 403 non-admin / null
 * proceed) so a future edit to the shared gate cannot silently weaken EVERY
 * gated route at once (security-review note, 2026-07-22). Negative cases
 * first per .claude/rules/testing.md.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	isAdmin: true as boolean | null,
}));

vi.mock("@/lib/workos-org", () => ({
	callerIsOrgAdmin: vi.fn(async () => h.isAdmin),
}));

import { requireOrgAdmin } from "./admin-gate";

const session = { tenantId: "org_SESSION", userId: "user_1" };

describe("requireOrgAdmin", () => {
	beforeEach(() => {
		h.isAdmin = true;
		vi.stubEnv("WORKOS_API_KEY", "sk_test_workos_unit_only");
	});
	afterEach(() => vi.unstubAllEnvs());

	it("REJECT: missing WORKOS_API_KEY → 501 (never an open gate)", async () => {
		vi.unstubAllEnvs();
		vi.stubEnv("WORKOS_API_KEY", "");
		const res = await requireOrgAdmin(session);
		expect(res?.status).toBe(501);
	});

	it("REJECT: WORKOS_API_KEY entirely UNSET → 501 (unset ≠ open)", async () => {
		vi.unstubAllEnvs();
		const prev = process.env.WORKOS_API_KEY;
		// biome-ignore lint/performance/noDelete: unsetting an env var REQUIRES delete — assignment coerces undefined to the string "undefined"
		delete process.env.WORKOS_API_KEY;
		try {
			const res = await requireOrgAdmin(session);
			expect(res?.status).toBe(501);
		} finally {
			if (prev !== undefined) process.env.WORKOS_API_KEY = prev;
		}
	});

	it("REJECT: role lookup failure (null) fails CLOSED → 502", async () => {
		h.isAdmin = null;
		const res = await requireOrgAdmin(session);
		expect(res?.status).toBe(502);
	});

	it("REJECT: non-admin → 403", async () => {
		h.isAdmin = false;
		const res = await requireOrgAdmin(session);
		expect(res?.status).toBe(403);
	});

	it("PROCEED: admin/owner → null", async () => {
		expect(await requireOrgAdmin(session)).toBeNull();
	});
});
