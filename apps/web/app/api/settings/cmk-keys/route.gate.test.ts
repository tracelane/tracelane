/**
 * Role-gate tests for /api/settings/cmk-keys (GET list, POST register).
 *
 * Focus: the admin gate on POST (2026-07-22 audit — any member/viewer could
 * register a rogue CMK into the tenant's encryption trust set). Negative
 * cases first per .claude/rules/testing.md: member → 403 with the DB never
 * touched; role-lookup failure → 502 (fail-closed); WorkOS unconfigured →
 * 501. Listing stays member-readable (fingerprints only, no key material).
 * (`route.test.ts` covers the pure algorithm resolver.)
 */

import { type DbMock, makeDbMock } from "@/lib/__testutils__/db-mock";
import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	db: null as DbMock | null,
	session: { tenantId: "org_SESSION", userId: "user_1", email: "a@b.co" },
	isAdmin: true as boolean | null,
	byokCmk: true as boolean,
	recordAdminAction: vi.fn(async (_entry: unknown) => undefined),
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

vi.mock("@/lib/workos-org", () => ({
	callerIsOrgAdmin: vi.fn(async () => h.isAdmin),
}));

vi.mock("@/lib/entitlements", () => ({
	resolveEntitlements: vi.fn(async () => ({ byok_cmk: h.byokCmk })),
}));

vi.mock("@/lib/admin-audit", () => ({
	recordAdminAction: h.recordAdminAction,
	ipFromRequest: () => null,
}));

import { GET, POST } from "./route";

// Test-only Ed25519 PUBLIC key (no secret material by construction).
const PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEApIUZ7ksPPVlPlb7G6PKmnHXoodE+sU03dcNQ9kHIMf8=
-----END PUBLIC KEY-----`;

function setDb(results: unknown[]): DbMock {
	const m = makeDbMock(results);
	h.db = m;
	return m;
}

function req(body: unknown): NextRequest {
	return {
		json: async () => body,
		headers: new Headers(),
	} as unknown as NextRequest;
}

describe("/api/settings/cmk-keys role gate", () => {
	beforeEach(() => {
		h.isAdmin = true;
		h.byokCmk = true;
		h.recordAdminAction.mockClear();
		vi.stubEnv("WORKOS_API_KEY", "sk_test_workos_unit_only");
	});
	afterEach(() => vi.unstubAllEnvs());

	it("REJECT: a member/viewer POST is 403 and the DB is never touched", async () => {
		h.isAdmin = false;
		const m = setDb([]);
		const res = await POST(req({ alias: "prod", publicKeyPem: PEM }));
		expect(res.status).toBe(403);
		expect(m.cursor()).toBe(0);
		expect(h.recordAdminAction).not.toHaveBeenCalled();
	});

	it("REJECT: role lookup failure fails CLOSED with 502, DB untouched", async () => {
		h.isAdmin = null;
		const m = setDb([]);
		const res = await POST(req({ alias: "prod", publicKeyPem: PEM }));
		expect(res.status).toBe(502);
		expect(m.cursor()).toBe(0);
	});

	it("REJECT: missing WORKOS_API_KEY is 501, never an open gate", async () => {
		vi.unstubAllEnvs();
		vi.stubEnv("WORKOS_API_KEY", "");
		const m = setDb([]);
		const res = await POST(req({ alias: "prod", publicKeyPem: PEM }));
		expect(res.status).toBe(501);
		expect(m.cursor()).toBe(0);
	});

	it("REJECT: an admin WITHOUT byok_cmk is 403 and the DB is never touched", async () => {
		// The role gate answers "may this person do it?"; this answers "did they
		// buy it?". Before 2026-08-30 only the first existed, so a FREE-TIER org
		// admin could register a CMK key against copy selling it as Business+.
		h.byokCmk = false;
		const m = setDb([[{ id: "tenant-db-uuid", plan: "free" }]]);
		const res = await POST(req({ alias: "prod", publicKeyPem: PEM }));
		expect(res.status).toBe(403);
		expect(((await res.json()) as { error: string }).error).toBe(
			"byok_cmk_required",
		);
		expect(h.recordAdminAction).not.toHaveBeenCalled();
	});

	it("HAPPY: an admin registers a key (201)", async () => {
		setDb([
			[{ id: "tenant-db-uuid", plan: "business" }], // entitlement gate lookup
			[{ id: "tenant-db-uuid" }], // upsertTenantId: existing tenant
			[{ id: "cmk-1", fingerprint: "ab".repeat(32) }], // insert returning
		]);
		const res = await POST(req({ alias: "prod", publicKeyPem: PEM }));
		expect(res.status).toBe(201);
		const json = (await res.json()) as { id: string };
		expect(json.id).toBe("cmk-1");
		// ADR-031: the register leaves an audit row.
		expect(h.recordAdminAction).toHaveBeenCalledTimes(1);
	});

	it("GET stays member-readable (fingerprints only, no key material)", async () => {
		h.isAdmin = false;
		setDb([
			[{ id: "tenant-db-uuid" }], // upsertTenantId
			[{ id: "cmk-1", fingerprint: "ab".repeat(32) }], // listing
		]);
		const res = await GET(req({}));
		expect(res.status).toBe(200);
	});
});
