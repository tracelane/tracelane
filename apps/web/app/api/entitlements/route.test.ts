/**
 * Tests for GET /api/entitlements.
 *
 * Focus: tenant scoping. The tenant the handler resolves entitlements for
 * MUST come from the authenticated session, never from the request. The
 * handler signature already ignores the request body (`_req`); these tests
 * lock that in by asserting the DB lookup keys off `session.tenantId` and
 * that a hostile body/query tenant id has no effect.
 */

import { type DbMock, makeDbMock } from "@/lib/__testutils__/db-mock";
import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	db: null as DbMock | null,
	session: { tenantId: "org_SESSION", userId: "user_1", email: "a@b.co" },
}));

vi.mock("@/db", () => ({
	get db() {
		if (!h.db) throw new Error("db mock not initialised");
		return h.db.db;
	},
}));

vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => h.session),
}));

// Capture the eq() args so we can assert WHAT the handler filtered on.
const eqCalls: Array<[unknown, unknown]> = [];
vi.mock("drizzle-orm", async (orig) => {
	const actual = (await orig()) as Record<string, unknown>;
	return {
		...actual,
		eq: (a: unknown, b: unknown) => {
			eqCalls.push([a, b]);
			return { __eq: [a, b] };
		},
	};
});

import { GET } from "./route";

function setDb(results: unknown[]): void {
	h.db = makeDbMock(results);
}

function reqWithBody(body: unknown): NextRequest {
	return {
		json: async () => body,
		headers: new Headers(),
		nextUrl: new URL(
			"http://localhost/api/entitlements?tenant_id=org_ATTACKER",
		),
	} as unknown as NextRequest;
}

describe("GET /api/entitlements — tenant scoping", () => {
	beforeEach(() => {
		eqCalls.length = 0;
		h.session = { tenantId: "org_SESSION", userId: "user_1", email: "a@b.co" };
	});

	it("scopes the tenant lookup to session.tenantId, ignoring a hostile body/query tenant id", async () => {
		// tenant row found, no plan/workspace override rows.
		setDb([
			[{ id: "tenant-db-uuid", plan: "team", auditEnabled: false }],
			[],
			[],
		]);

		const res = await GET(
			reqWithBody({ tenant_id: "org_ATTACKER", plan: "enterprise" }),
		);
		expect(res.status).toBe(200);

		// The FIRST eq() the handler runs is the tenants.workosOrgId filter.
		// Its right-hand value must be the SESSION tenant, never the attacker's.
		const firstFilterValue = eqCalls[0]?.[1];
		expect(firstFilterValue).toBe("org_SESSION");
		expect(eqCalls.some(([, v]) => v === "org_ATTACKER")).toBe(false);

		const json = (await res.json()) as { plan: string };
		// Resolved from the DB row (team), NOT the body-supplied "enterprise".
		expect(json.plan).toBe("team");
	});

	it("FALLBACK: a tenant with no DB row resolves to the builder default", async () => {
		setDb([[]]); // no tenant row → resolver short-circuits (no db id)
		const res = await GET(reqWithBody({}));
		const json = (await res.json()) as { plan: string; byok_cmk: boolean };
		expect(json.plan).toBe("builder");
		expect(json.byok_cmk).toBe(false);
	});
});
