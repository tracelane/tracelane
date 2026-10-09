/**
 * Tests for DELETE /api/settings/account — the three deletion cases
 * (IDENTITY_TEAM_SPEC §5). tenant_id + user id derive from the session.
 * Negative cases first per `.claude/rules/testing.md`.
 */

import { type DbMock, makeDbMock } from "@/lib/__testutils__/db-mock";
import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	session: { tenantId: "org_S", userId: "user_ME", email: "me@x.co" },
	db: null as DbMock | null,
}));

vi.mock("@workos-inc/authkit-nextjs", () => ({
	withAuth: async () => ({
		user: { id: h.session.userId, email: h.session.email },
		organizationId: h.session.tenantId,
	}),
}));
vi.mock("@/db", () => ({
	get db() {
		if (!h.db) throw new Error("db mock not initialised");
		return h.db.db;
	},
}));
vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => h.session),
	// B-361: the route calls this after archiving; a mock without it throws
	// "not a function" and the route's own catch silently swallows that,
	// which masqueraded as a dropped db call (h.db?.cursor() off by one).
	invalidateOrgArchivedCache: vi.fn(),
}));

// Real lock and cross-route races are proved in owner-race.live.test.ts.
vi.mock("../team/owner-lock", () => ({
	withOwnerMutation: async (_org: string, work: () => Promise<unknown>) =>
		work(),
}));

import { DELETE } from "./route";

type M = {
	id: string;
	user_id: string;
	organization_id: string;
	role: { slug: string };
};
const del = (body: unknown) =>
	DELETE({ json: async () => body } as unknown as NextRequest);
const methodOf = (c: unknown[]): string =>
	(c[1] as { method?: string } | undefined)?.method ?? "GET";

function stub(members: M[]) {
	const spy = vi.fn(async (...args: unknown[]) => {
		const url = args[0] as string;
		if (url.includes("organization_memberships")) {
			return {
				ok: true,
				json: async () => ({ data: members }),
			} as unknown as Response;
		}
		// DELETE user
		return { ok: true, status: 200 } as unknown as Response;
	});
	vi.stubGlobal("fetch", spy);
	return spy;
}

const me = (slug: string): M => ({
	id: "m_me",
	user_id: "user_ME",
	organization_id: "org_S",
	role: { slug },
});
const other: M = {
	id: "m_other",
	user_id: "user_OTHER",
	organization_id: "org_S",
	role: { slug: "member" },
};
const otherOwner: M = {
	id: "m_o2",
	user_id: "user_O2",
	organization_id: "org_S",
	role: { slug: "owner" },
};

beforeEach(() => {
	h.session = { tenantId: "org_S", userId: "user_ME", email: "me@x.co" };
	h.db = makeDbMock([[{ id: "t" }], [], [], []]);
	process.env.WORKOS_API_KEY = "sk_test_workos_do_not_use";
});
afterEach(() => {
	vi.unstubAllGlobals();
	process.env.WORKOS_API_KEY = undefined;
});

it("REJECT: email confirmation mismatch → 422 (before any WorkOS call)", async () => {
	const spy = stub([me("owner")]);
	expect((await del({ confirmEmail: "wrong@x.co" })).status).toBe(422);
	expect(spy).not.toHaveBeenCalled();
});

it("REJECT: last owner WITH other members → 409 last_owner_protected", async () => {
	const spy = stub([me("owner"), other]);
	const res = await del({ confirmEmail: "me@x.co" });
	expect(res.status).toBe(409);
	expect(((await res.json()) as { error: string }).error).toBe(
		"last_owner_protected",
	);
	// No WorkOS user delete was issued.
	expect(spy.mock.calls.every((c) => methodOf(c) !== "DELETE")).toBe(true);
});

it("CASE 1: sole user → org soft-delete + WorkOS user delete, orgDeleted:true", async () => {
	const spy = stub([me("owner")]);
	const res = await del({ confirmEmail: "ME@X.co" }); // case-insensitive confirm
	expect(res.status).toBe(200);
	expect(((await res.json()) as { orgDeleted: boolean }).orgDeleted).toBe(true);
	// Tenant lookup, atomic local erasure, org archive, key revocation.
	expect(h.db?.cursor()).toBe(4);
	expect(h.db?.db.execute).toHaveBeenCalledTimes(1);
	expect(spy.mock.calls.some((c) => methodOf(c) === "DELETE")).toBe(true);
});

it("CASE 3: non-owner member with others → delete self, orgDeleted:false, org kept", async () => {
	h.session = { tenantId: "org_S", userId: "user_ME", email: "me@x.co" };
	const spy = stub([me("member"), otherOwner]);
	const res = await del({ confirmEmail: "me@x.co" });
	expect(res.status).toBe(200);
	expect(((await res.json()) as { orgDeleted: boolean }).orgDeleted).toBe(
		false,
	);
	// Tenant lookup and atomic local erasure; the org lives.
	expect(h.db?.cursor()).toBe(2);
	expect(h.db?.db.execute).toHaveBeenCalledTimes(1);
	expect(spy.mock.calls.some((c) => methodOf(c) === "DELETE")).toBe(true);
});

it("SET-60 REJECT: WorkOS user delete fails → 502 after durable local erasure", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn(async (...args: unknown[]) => {
			const url = args[0] as string;
			if (url.includes("organization_memberships")) {
				return {
					ok: true,
					json: async () => ({ data: [me("member"), otherOwner] }),
				} as unknown as Response;
			}
			return { ok: false, status: 500 } as unknown as Response;
		}),
	);
	const res = await del({ confirmEmail: "me@x.co" });
	expect(res.status).toBe(502);
	expect(h.db?.db.execute).toHaveBeenCalledTimes(1);
});

it("local erasure failure refuses success and keeps the WorkOS identity for retry", async () => {
	const spy = stub([me("member"), otherOwner]);
	vi.spyOn(console, "error").mockImplementation(() => {});
	if (h.db) {
		h.db.db.execute.mockImplementation(() => {
			throw new Error("signups table missing");
		});
	}
	const res = await del({ confirmEmail: "me@x.co" });
	expect(res.status).toBe(503);
	expect(spy.mock.calls.every((c) => methodOf(c) !== "DELETE")).toBe(true);
});
