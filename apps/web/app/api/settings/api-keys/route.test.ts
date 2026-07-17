/**
 * Tests for /api/settings/api-keys (GET list, POST create).
 *
 * Focus: tenant scoping (tenant derived from session, body cannot inject one);
 * than hashing locally, returns the raw key once, and records the audit action
 * with only the non-secret shape; a gateway fault maps to a clean 5xx. Negative
 * cases first per `.claude/rules/testing.md`. The DB, gateway, and admin-audit
 * writes are mocked so this unit stays off Postgres and the network.
 */

import { type DbMock, makeDbMock } from "@/lib/__testutils__/db-mock";
import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Everything the hoisted `vi.mock` factories reference must be created INSIDE
// `vi.hoisted` — including `GatewayError`, since the route's error branch does
// `instanceof GatewayError` and a test throws one.
const h = vi.hoisted(() => {
	class GatewayError extends Error {
		constructor(
			readonly status: number,
			message: string,
		) {
			super(message);
		}
	}
	return {
		db: null as DbMock | null,
		session: { tenantId: "org_SESSION", userId: "user_1", email: "a@b.co" },
		recordAdminAction: vi.fn(async (_entry: unknown) => undefined),
		eqCalls: [] as Array<[unknown, unknown]>,
		GatewayError,
		gatewayPost: vi.fn(async (_path: string, _body: unknown) => ({
			id: "k-new",
			name: "ci",
			keyPrefix: "ABC123",
			createdAt: "2026-07-07T00:00:00Z",
			lastUsedAt: null,
			rawKey: "tlane_MOCKKEYBODYdonotuseinprod0123456789ABCd",
		})),
	};
});
const { recordAdminAction, eqCalls, gatewayPost, GatewayError } = h;

vi.mock("@/db", () => ({
	get db() {
		if (!h.db) throw new Error("db mock not initialised");
		return h.db.db;
	},
}));

vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => h.session),
}));

vi.mock("@/lib/admin-audit", () => ({
	recordAdminAction: h.recordAdminAction,
	ipFromRequest: () => null,
}));

vi.mock("@/lib/gateway", () => ({
	gatewayPost: h.gatewayPost,
	GatewayError: h.GatewayError,
}));

vi.mock("drizzle-orm", async (orig) => {
	const actual = (await orig()) as Record<string, unknown>;
	return {
		...actual,
		eq: (a: unknown, b: unknown) => {
			h.eqCalls.push([a, b]);
			return { __eq: [a, b] };
		},
	};
});

import { GET, POST } from "./route";

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

describe("/api/settings/api-keys", () => {
	beforeEach(() => {
		eqCalls.length = 0;
		recordAdminAction.mockClear();
		gatewayPost.mockClear();
		h.session = { tenantId: "org_SESSION", userId: "user_1", email: "a@b.co" };
	});

	it("GET scopes the listing to the session tenant (existing tenant row)", async () => {
		setDb([
			[{ id: "tenant-db-uuid" }], // upsertTenantId: existing tenant
			[{ id: "k1", name: "ci", keyPrefix: "abc123" }], // listing
		]);
		const res = await GET(req({}));
		expect(res.status).toBe(200);
		// tenant lookup filtered on the SESSION org id.
		expect(eqCalls[0]?.[1]).toBe("org_SESSION");
	});

	it("REJECT: POST with blank name → 422, never calls the gateway", async () => {
		setDb([[{ id: "tenant-db-uuid" }]]);
		const res = await POST(req({ name: "  " }));
		expect(res.status).toBe(422);
		expect(gatewayPost).not.toHaveBeenCalled();
	});

	it("REJECT: a gateway fault maps to 502 and records no audit row", async () => {
		setDb([[{ id: "tenant-db-uuid" }]]);
		gatewayPost.mockRejectedValueOnce(
			new GatewayError(500, "gateway responded 500"),
		);
		const res = await POST(req({ name: "ci" }));
		expect(res.status).toBe(502);
		expect(recordAdminAction).not.toHaveBeenCalled();
	});

	it("HAPPY: POST proxies to the gateway and returns the raw key once (201)", async () => {
		setDb([[{ id: "tenant-db-uuid" }]]);
		const res = await POST(req({ name: "  ci  " }));
		expect(res.status).toBe(201);
		// Minting is delegated to the gateway with the TRIMMED name; the tenant is
		// resolved by the gateway from the JWT, never sent in the body.
		expect(gatewayPost).toHaveBeenCalledWith("/v1/keys", { name: "ci" });
		const json = (await res.json()) as { id: string; rawKey: string };
		expect(json.id).toBe("k-new");
		expect(json.rawKey).toMatch(/^tlane_[0-9A-Za-z]+$/);
		expect(recordAdminAction).toHaveBeenCalledTimes(1);
	});

	it("records the audit action with the safe (non-secret) shape — never the raw key or hash", async () => {
		setDb([[{ id: "tenant-db-uuid" }]]);
		const res = await POST(req({ name: "ci" }));
		expect(res.status).toBe(201);
		expect(recordAdminAction).toHaveBeenCalledTimes(1);
		const entry = recordAdminAction.mock.calls[0]?.[0] as unknown as {
			action: string;
			afterJson: Record<string, unknown>;
		};
		expect(entry.action).toBe("api_key.create");
		// The audit row carries only non-sensitive fields (from the gateway result).
		expect(entry.afterJson).toEqual({ name: "ci", keyPrefix: "ABC123" });
		expect(JSON.stringify(entry.afterJson)).not.toMatch(/tlane_/);
		expect(entry.afterJson).not.toHaveProperty("rawKey");
	});
});
