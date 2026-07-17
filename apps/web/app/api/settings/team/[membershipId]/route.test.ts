/**
 * Tests for member management — DELETE (remove) + PATCH (role change).
 *
 * Every guard is server-side: caller must be owner OF THIS ORG, target must be
 * in-tenant, no self-removal, last-owner protection (a removal/demotion that
 * would leave zero owners → typed 409). Removal additionally revokes the removed
 * member's `tlane_` keys. Negative cases first per `.claude/rules/testing.md`.
 */

import { type DbMock, makeDbMock } from "@/lib/__testutils__/db-mock";
import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	session: { tenantId: "org_SESSION", userId: "user_ADMIN", email: "a@b.co" },
	db: null as DbMock | null,
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

import { DELETE, PATCH } from "./route";

type M = {
	id: string;
	user_id: string;
	organization_id: string;
	role: { slug: string };
};

function ctx(membershipId: string) {
	return { params: Promise.resolve({ membershipId }) };
}
const del = (id: string) =>
	DELETE({ headers: new Headers() } as unknown as NextRequest, ctx(id));
const patch = (id: string, body: unknown) =>
	PATCH({ json: async () => body } as unknown as NextRequest, ctx(id));

const methodOf = (call: unknown[]): string =>
	(call[1] as { method?: string } | undefined)?.method ?? "GET";

/** Stub WorkOS: GET memberships → `members`; DELETE → delOk; PUT (role) → putOk. */
function stub(
	members: M[] | null,
	opts: { delOk?: boolean; putOk?: boolean } = {},
) {
	const { delOk = true, putOk = true } = opts;
	const spy = vi.fn(async (...args: unknown[]) => {
		const url = args[0] as string;
		const method = methodOf(args);
		if (url.includes("organization_memberships") && method === "GET") {
			if (members === null)
				return { ok: false, status: 500 } as unknown as Response;
			return {
				ok: true,
				json: async () => ({ data: members }),
			} as unknown as Response;
		}
		if (method === "DELETE") {
			return { ok: delOk, status: delOk ? 200 : 502 } as unknown as Response;
		}
		// PUT role change
		return { ok: putOk, status: putOk ? 200 : 502 } as unknown as Response;
	});
	vi.stubGlobal("fetch", spy);
	return spy;
}

const admin: M = {
	id: "mem_admin",
	user_id: "user_ADMIN",
	organization_id: "org_SESSION",
	role: { slug: "owner" },
};
const member: M = {
	id: "mem_member",
	user_id: "user_MEMBER",
	organization_id: "org_SESSION",
	role: { slug: "member" },
};

describe("DELETE /api/settings/team/[membershipId] — removal guards", () => {
	beforeEach(() => {
		h.session = {
			tenantId: "org_SESSION",
			userId: "user_ADMIN",
			email: "a@b.co",
		};
		// tenant lookup → update (key-revoke). Both benign for tests that reach it.
		h.db = makeDbMock([[{ id: "tenant-uuid" }], []]);
		process.env.WORKOS_API_KEY = "sk_test_workos_do_not_use";
	});
	afterEach(() => {
		vi.unstubAllGlobals();
		process.env.WORKOS_API_KEY = undefined;
	});

	it("REJECT: WORKOS_API_KEY unset → 501", async () => {
		process.env.WORKOS_API_KEY = "";
		expect((await del("mem_member")).status).toBe(501);
	});

	it("REJECT: membership lookup fails → 502", async () => {
		stub(null);
		expect((await del("mem_member")).status).toBe(502);
	});

	it("REJECT: target not in this org → 404 (tenant isolation, no existence leak)", async () => {
		const spy = stub([admin, member]);
		const res = await del("mem_FROM_ANOTHER_ORG");
		expect(res.status).toBe(404);
		expect(spy.mock.calls.every((c) => methodOf(c) !== "DELETE")).toBe(true);
	});

	it("REJECT: removing yourself → 400", async () => {
		stub([admin, member]);
		expect((await del("mem_admin")).status).toBe(400);
	});

	it("REJECT: caller is not an owner → 403 role_forbidden", async () => {
		h.session = {
			tenantId: "org_SESSION",
			userId: "user_MEMBER",
			email: "m@b.co",
		};
		const spy = stub([admin, member]);
		const res = await del("mem_admin");
		expect(res.status).toBe(403);
		expect(((await res.json()) as { error: string }).error).toBe(
			"role_forbidden",
		);
		expect(spy.mock.calls.every((c) => methodOf(c) !== "DELETE")).toBe(true);
	});

	it("ALLOWS: removing a co-owner when 2 owners exist → 200 (2→1, one owner remains)", async () => {
		const owner2: M = {
			id: "mem_owner2",
			user_id: "user_OWNER2",
			organization_id: "org_SESSION",
			role: { slug: "owner" },
		};
		const spy = stub([admin, owner2]);
		expect((await del("mem_owner2")).status).toBe(200);
		expect(spy.mock.calls.some((c) => methodOf(c) === "DELETE")).toBe(true);
	});

	it("HAPPY: owner removes a member → 200, WorkOS DELETE + key-revoke", async () => {
		const spy = stub([admin, member]);
		const res = await del("mem_member");
		expect(res.status).toBe(200);
		expect(((await res.json()) as { removed: string }).removed).toBe(
			"mem_member",
		);
		const delCall = spy.mock.calls.find((c) => methodOf(c) === "DELETE");
		expect(delCall?.[0]).toContain("organization_memberships/mem_member");
		// The key-revoke consumed both queued db chains (tenant lookup + update).
		expect(h.db?.cursor()).toBe(2);
	});

	it("REJECT: WorkOS DELETE fails → 502 (before any key-revoke)", async () => {
		stub([admin, member], { delOk: false });
		expect((await del("mem_member")).status).toBe(502);
	});
});

describe("PATCH /api/settings/team/[membershipId] — role change", () => {
	beforeEach(() => {
		h.session = {
			tenantId: "org_SESSION",
			userId: "user_ADMIN",
			email: "a@b.co",
		};
		h.db = makeDbMock([]);
		process.env.WORKOS_API_KEY = "sk_test_workos_do_not_use";
	});
	afterEach(() => {
		vi.unstubAllGlobals();
		process.env.WORKOS_API_KEY = undefined;
	});

	it("REJECT: invalid role → 422 (before any WorkOS call)", async () => {
		const spy = stub([admin, member]);
		expect((await patch("mem_member", { role: "superadmin" })).status).toBe(
			422,
		);
		expect(spy).not.toHaveBeenCalled();
	});

	it("REJECT: caller is not an owner → 403 role_forbidden", async () => {
		h.session = {
			tenantId: "org_SESSION",
			userId: "user_MEMBER",
			email: "m@b.co",
		};
		const spy = stub([admin, member]);
		const res = await patch("mem_admin", { role: "viewer" });
		expect(res.status).toBe(403);
		expect(((await res.json()) as { error: string }).error).toBe(
			"role_forbidden",
		);
		expect(spy.mock.calls.every((c) => methodOf(c) !== "PUT")).toBe(true);
	});

	it("REJECT: demoting the last owner → 409 last_owner_protected", async () => {
		// Caller is the ONLY owner and demotes themselves → would leave zero owners.
		const spy = stub([admin, member]);
		const res = await patch("mem_admin", { role: "member" });
		expect(res.status).toBe(409);
		expect(((await res.json()) as { error: string }).error).toBe(
			"last_owner_protected",
		);
		expect(spy.mock.calls.every((c) => methodOf(c) !== "PUT")).toBe(true);
	});

	it("ALLOWS: promoting a member to owner → 200 (owner-grant)", async () => {
		const spy = stub([admin, member]);
		const res = await patch("mem_member", { role: "owner" });
		expect(res.status).toBe(200);
		const put = spy.mock.calls.find((c) => methodOf(c) === "PUT");
		expect(JSON.parse((put?.[1] as { body: string }).body).role_slug).toBe(
			"owner",
		);
	});

	it("ALLOWS: demoting a co-owner when 2 owners exist → 200", async () => {
		const owner2: M = {
			id: "mem_owner2",
			user_id: "user_OWNER2",
			organization_id: "org_SESSION",
			role: { slug: "owner" },
		};
		const spy = stub([admin, owner2]);
		expect((await patch("mem_owner2", { role: "member" })).status).toBe(200);
		expect(spy.mock.calls.some((c) => methodOf(c) === "PUT")).toBe(true);
	});
});
