/**
 * Tests for POST /api/settings/cmk-keys/[keyId]/rotate.
 *
 * Focus: a rotate must be tenant-scoped — a key that does not belong to the
 * caller's tenant (cross-tenant or non-existent) must be rejected, and only
 * a valid rotate may invoke the update+insert path. Negative cases first
 * per `.claude/rules/testing.md`.
 *
 * The key-lookup query filters on `(id, tenantId, status='active')`, so a
 * cross-tenant key id resolves to zero rows → 404. We assert both the
 * rejection AND that no write chain runs in that case.
 */

import { type DbMock, makeDbMock } from "@/lib/__testutils__/db-mock";
import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	db: null as DbMock | null,
	session: { tenantId: "org_SESSION", userId: "user_1", email: "a@b.co" },
	isAdmin: true as boolean | null,
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

vi.mock("@/lib/admin-audit", () => ({
	recordAdminAction: vi.fn(async (_entry: unknown) => undefined),
	ipFromRequest: () => null,
}));

import { POST } from "./route";

// Test-only Ed25519 PUBLIC key (no secret material by construction) — the
// rotate route now VALIDATES the replacement PEM, so fixtures must parse.
const VALID_PEM = `-----BEGIN PUBLIC KEY-----
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

const params = (keyId: string) => ({ params: Promise.resolve({ keyId }) });

describe("POST /api/settings/cmk-keys/[keyId]/rotate", () => {
	beforeEach(() => {
		h.session = { tenantId: "org_SESSION", userId: "user_1", email: "a@b.co" };
		h.isAdmin = true;
		vi.stubEnv("WORKOS_API_KEY", "sk_test_workos_unit_only");
	});
	afterEach(() => vi.unstubAllEnvs());

	it("REJECT: a member/viewer rotate is 403 and the DB is never touched (2026-07-22 audit)", async () => {
		h.isAdmin = false;
		const m = setDb([]);
		const res = await POST(req({ publicKeyPem: VALID_PEM }), params("key-1"));
		expect(res.status).toBe(403);
		expect(m.cursor()).toBe(0);
	});

	it("REJECT: role lookup failure fails CLOSED with 502", async () => {
		h.isAdmin = null;
		const m = setDb([]);
		const res = await POST(req({ publicKeyPem: VALID_PEM }), params("key-1"));
		expect(res.status).toBe(502);
		expect(m.cursor()).toBe(0);
	});

	it("REJECT: an unparseable replacement PEM → 422, no rotation write", async () => {
		const m = setDb([
			[{ id: "tenant-db-uuid" }], // tenant lookup
			[
				{
					id: "old-key-uuid",
					alias: "primary",
					algorithm: "rsa-4096",
					purpose: "all",
					status: "active",
				},
			], // active key found
		]);
		const res = await POST(
			req({
				publicKeyPem:
					"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
			}),
			params("old-key-uuid"),
		);
		expect(res.status).toBe(422);
		// Only the two reads ran — no update, no insert.
		expect(m.cursor()).toBe(2);
	});

	it("REJECT: missing publicKeyPem → 422 before any DB write", async () => {
		const m = setDb([]);
		const res = await POST(req({ publicKeyPem: "  " }), params("key-1"));
		expect(res.status).toBe(422);
		// No tenant lookup, no rotate write happened.
		expect(m.cursor()).toBe(0);
	});

	it("REJECT: invalid JSON body → 400", async () => {
		setDb([]);
		const bad = {
			json: async () => {
				throw new Error("bad json");
			},
			headers: new Headers(),
		} as unknown as NextRequest;
		const res = await POST(bad, params("key-1"));
		expect(res.status).toBe(400);
	});

	it("REJECT: cross-tenant / non-existent active key → 404, NO rotation write", async () => {
		// tenant resolves, but the (id, tenant, active) lookup finds nothing —
		// this is exactly the cross-tenant case (key belongs to another org).
		const m = setDb([
			[{ id: "tenant-db-uuid" }], // tenant lookup OK
			[], // active key not found for THIS tenant
		]);
		const res = await POST(
			req({
				publicKeyPem:
					"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
			}),
			params("key-belonging-to-another-tenant"),
		);
		expect(res.status).toBe(404);
		// Only the two reads were consumed — no update/insert chains ran.
		expect(m.cursor()).toBe(2);
	});

	it("REJECT: tenant row missing → 404", async () => {
		setDb([[]]); // no tenant
		const res = await POST(
			req({
				publicKeyPem:
					"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
			}),
			params("key-1"),
		);
		expect(res.status).toBe(404);
	});

	it("HAPPY: valid rotate marks old key rotating + inserts new key once → 201", async () => {
		const newRow = {
			id: "new-key-uuid",
			alias: "primary (rotated)",
			status: "active",
		};
		const m = setDb([
			[{ id: "tenant-db-uuid" }], // tenant lookup
			[
				{
					id: "old-key-uuid",
					alias: "primary",
					algorithm: "rsa-4096",
					purpose: "all",
					status: "active",
				},
			], // active key found
			[newRow], // INSERT new key returning() — insert-first ordering
			[], // UPDATE old key → rotating
		]);

		const res = await POST(
			req({ publicKeyPem: VALID_PEM }),
			params("old-key-uuid"),
		);

		expect(res.status).toBe(201);
		const json = (await res.json()) as { id: string };
		expect(json.id).toBe("new-key-uuid");

		// The update chain AND the insert chain both ran exactly once: the
		// cursor consumed all four scripted results.
		expect(m.cursor()).toBe(4);
		// update() and insert() were each invoked once on the rotation path.
		expect(m.db.update).toHaveBeenCalledTimes(1);
		expect(m.db.insert).toHaveBeenCalledTimes(1);
	});
});
