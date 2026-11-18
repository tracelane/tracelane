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
	ack: true,
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
	requireGatewayToken: vi.fn(async () => ({
		token: "test-human-jwt",
		tenantId: "org_S",
	})),
	requireSession: vi.fn(async () => h.session),
	// B-361: the route calls this after archiving; a mock without it throws
	// "not a function" and the route's own catch silently swallows that,
	// which masqueraded as a dropped db call (h.db?.cursor() off by one).
	invalidateOrgArchivedCache: vi.fn(),
}));

// Real lock and cross-route races are proved in owner-race.live.test.ts.
const lockedScopes = vi.hoisted(() => [] as unknown[]);
vi.mock("../team/owner-lock", () => ({
	withOwnerMutation: async (org: unknown, work: () => Promise<unknown>) => {
		lockedScopes.push(org);
		return work();
	},
}));

import { DELETE } from "./route";

type M = {
	id: string;
	user_id: string;
	organization_id: string;
	role: { slug: string };
	status?: string;
};
const del = (body: unknown) =>
	DELETE({ json: async () => body } as unknown as NextRequest);
const methodOf = (c: unknown[]): string =>
	(c[1] as { method?: string } | undefined)?.method ?? "GET";

function stub(members: M[]) {
	const spy = vi.fn(async (...args: unknown[]) => {
		const url = args[0] as string;
		if (url.endsWith("/v1/keys/invalidate-cache"))
			return Response.json({ invalidated: h.ack });
		if (url.includes("organization_memberships")) {
			return {
				ok: true,
				json: async () => ({
					data: url.includes("user_id=")
						? members.filter((m) => m.user_id === h.session.userId)
						: members,
				}),
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
	status: "active",
});
const other: M = {
	id: "m_other",
	user_id: "user_OTHER",
	organization_id: "org_S",
	role: { slug: "member" },
	status: "active",
};
const otherOwner: M = {
	id: "m_o2",
	user_id: "user_O2",
	organization_id: "org_S",
	role: { slug: "owner" },
	status: "active",
};

beforeEach(() => {
	h.ack = true;
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
	// Tenant lookup, two key sweeps, local erasure, then org archive.
	expect(h.db?.cursor()).toBe(5);
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
	// Tenant lookup, own-key revocation, then local erasure; the org lives.
	expect(h.db?.cursor()).toBe(4);
	expect(h.db?.db.execute).toHaveBeenCalledTimes(1);
	expect(spy.mock.calls.some((c) => methodOf(c) === "DELETE")).toBe(true);
});

it("SET-60 REJECT: WorkOS user delete fails → 502 after durable local erasure", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn(async (...args: unknown[]) => {
			const url = args[0] as string;
			if (url.endsWith("/v1/keys/invalidate-cache"))
				return Response.json({ invalidated: h.ack });
			if (url.includes("organization_memberships")) {
				return {
					ok: true,
					json: async () => ({
						data: url.includes("user_id=")
							? [me("member")]
							: [me("member"), otherOwner],
					}),
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

it("sole_user_archive_failure_must_not_report_deletion", async () => {
	const spy = stub([me("owner")]);
	h.db = makeDbMock([[{ id: "t" }], [], [], [], new Error("archive failed")]);
	vi.spyOn(console, "error").mockImplementation(() => {});
	const res = await del({ confirmEmail: "me@x.co" });
	expect(res.status).toBe(503);
	expect(spy.mock.calls.every((c) => methodOf(c) !== "DELETE")).toBe(true);
});

it.each([{ members: [other] }, { members: [] }])(
	"account_delete_requires_current_membership_before_org_archive ($members)",
	async ({ members }) => {
		const spy = stub(members);
		const res = await del({ confirmEmail: "me@x.co" });
		expect(res.status).toBe(403);
		expect(h.db?.db.update).not.toHaveBeenCalled();
		expect(h.db?.db.execute).not.toHaveBeenCalled();
		expect(spy.mock.calls.every((c) => methodOf(c) !== "DELETE")).toBe(true);
	},
);

it("unconfirmed_account_revocation_keeps_identity_retryable", async () => {
	h.ack = false;
	const spy = stub([me("owner")]);
	const res = await del({ confirmEmail: "me@x.co" });
	expect(res.status).toBe(503);
	expect(spy.mock.calls.every((c) => methodOf(c) !== "DELETE")).toBe(true);
	expect(h.db?.db.execute).not.toHaveBeenCalled();
	expect(h.db?.setCalls.some(([v]) => "archivedAt" in (v as object))).toBe(
		false,
	);
});

it("deletion_requires_confirmable_org", async () => {
	h.session.tenantId = "";
	const spy = stub([me("owner")]);
	const res = await del({ confirmEmail: "me@x.co" });
	expect(res.status).toBe(409);
	expect(await res.json()).toMatchObject({
		error: "organization_selection_required",
	});
	expect(h.db?.cursor()).toBe(0);
	expect(spy.mock.calls.every((c) => methodOf(c) !== "DELETE")).toBe(true);
});
it("truly_orgless_erasure_remains_available", async () => {
	h.session.tenantId = "";
	h.db = makeDbMock([[], [], []]);
	const spy = stub([]);
	const res = await del({ confirmEmail: "me@x.co" });
	expect(res.status).toBe(200);
	expect(h.db?.db.execute).toHaveBeenCalledTimes(1);
	expect(h.db?.db.update).not.toHaveBeenCalled();
	expect(spy.mock.calls.some((c) => methodOf(c) === "DELETE")).toBe(true);
});
it("sole_user_sql_revoke_failure_keeps_identity_and_archive_unchanged", async () => {
	h.db = makeDbMock([[{ id: "t" }], new Error("revoke failed")]);
	const spy = stub([me("owner")]);
	const res = await del({ confirmEmail: "me@x.co" });
	expect(res.status).toBe(503);
	expect(await res.json()).toMatchObject({
		error: "key_revocation_unconfirmed",
	});
	expect(h.db.db.execute).not.toHaveBeenCalled();
	expect(h.db.setCalls.some(([v]) => "archivedAt" in (v as object))).toBe(
		false,
	);
	expect(spy.mock.calls.every((c) => methodOf(c) !== "DELETE")).toBe(true);
});

it("member account deletion refuses success when own-key cache eviction is unconfirmed", async () => {
	h.ack = false;
	const spy = stub([me("member"), otherOwner]);
	const res = await del({ confirmEmail: "me@x.co" });
	expect(res.status).toBe(503);
	expect(h.db?.db.execute).not.toHaveBeenCalled();
	expect(spy.mock.calls.every((c) => methodOf(c) !== "DELETE")).toBe(true);
});

function stubGlobalMemberships(
	opts: {
		failList?: boolean;
		extraSole?: boolean;
		allowGlobal?: boolean;
		changedScope?: boolean;
		duplicateOwner?: boolean;
		pendingPeerOwner?: string;
	} = {},
) {
	const orgs: Record<string, M[]> = {
		org_S: [me("member"), otherOwner],
		org_PROTECTED: [
			{ ...me("owner"), id: "m_protected", organization_id: "org_PROTECTED" },
			{ ...other, id: "m_peer", organization_id: "org_PROTECTED" },
		],
	};
	if (opts.extraSole) orgs.org_PROTECTED = [orgs.org_PROTECTED?.[0] as M];
	if (opts.allowGlobal && orgs.org_PROTECTED?.[1])
		orgs.org_PROTECTED[1].role.slug = "owner";
	if (opts.pendingPeerOwner && orgs.org_PROTECTED?.[1])
		orgs.org_PROTECTED[1] = {
			...orgs.org_PROTECTED[1],
			role: { slug: "owner" },
			status: opts.pendingPeerOwner,
		};
	if (opts.duplicateOwner && orgs.org_PROTECTED?.[0])
		orgs.org_PROTECTED.push(orgs.org_PROTECTED[0]);
	let scopeReads = 0;
	const spy = vi.fn(async (url: string, init?: RequestInit) => {
		if (url.endsWith("/v1/keys/invalidate-cache"))
			return Response.json({ invalidated: true });
		if (url.includes("organization_memberships")) {
			const query = new URL(url).searchParams;
			if (query.has("user_id") && opts.changedScope && ++scopeReads > 1)
				return Response.json({ data: [me("member")] });
			if (query.has("user_id"))
				return opts.failList
					? new Response(null, { status: 503 })
					: Response.json({
							data: Object.values(orgs)
								.flat()
								.filter((m) => m.user_id === "user_ME"),
						});
			return Response.json({
				data: orgs[query.get("organization_id") ?? ""] ?? [],
			});
		}
		return new Response(null, {
			status: init?.method === "DELETE" ? 204 : 200,
		});
	});
	vi.stubGlobal("fetch", spy);
	return spy;
}

it("global_deletion_cannot_bypass_last_owner_by_selecting_another_workspace", async () => {
	const spy = stubGlobalMemberships();
	const response = await del({ confirmEmail: "me@x.co" });
	expect(response.status).toBe(409);
	expect((await response.json()).error).toBe("last_owner_protected");
	expect(spy.mock.calls.some((c) => c[1]?.method === "DELETE")).toBe(false);
	expect(h.db?.db.update).not.toHaveBeenCalled();
	expect(h.db?.db.execute).not.toHaveBeenCalled();
});

it("a_pending_or_inactive_owner_is_not_a_second_owner_for_global_deletion", async () => {
	// Security review of #232, M1: the sole ACTIVE owner of a non-selected workspace
	// must not delete their account because an invited (pending) or deactivated
	// owner is listed with the owner role.
	for (const status of ["pending", "inactive"]) {
		const spy = stubGlobalMemberships({ pendingPeerOwner: status });
		const response = await del({ confirmEmail: "me@x.co" });
		expect(response.status).toBe(409);
		expect((await response.json()).error).toBe("last_owner_protected");
		expect(spy.mock.calls.some((c) => c[1]?.method === "DELETE")).toBe(false);
		vi.unstubAllGlobals();
	}
});

it("global_deletion_fails_closed_when_all_memberships_cannot_be_enumerated", async () => {
	const spy = stubGlobalMemberships({ failList: true });
	expect((await del({ confirmEmail: "me@x.co" })).status).toBe(502);
	expect(spy.mock.calls.some((c) => c[1]?.method === "DELETE")).toBe(false);
	expect(h.db?.db.update).not.toHaveBeenCalled();
});

it("global_deletion_refuses_to_orphan_a_nonselected_sole_user_workspace", async () => {
	const spy = stubGlobalMemberships({ extraSole: true });
	const response = await del({ confirmEmail: "me@x.co" });
	expect(response.status).toBe(409);
	expect((await response.json()).error).toBe("workspace_cleanup_required");
	expect(spy.mock.calls.some((c) => c[1]?.method === "DELETE")).toBe(false);
	expect(h.db?.db.execute).not.toHaveBeenCalled();
});

it("global_deletion_allows_memberships_with_another_owner_in_every_workspace", async () => {
	lockedScopes.length = 0;
	const spy = stubGlobalMemberships({ allowGlobal: true });
	expect((await del({ confirmEmail: "me@x.co" })).status).toBe(200);
	expect(spy.mock.calls.filter((c) => c[1]?.method === "DELETE")).toHaveLength(
		1,
	);
	expect(h.db?.db.execute).toHaveBeenCalledTimes(1);
	// Security review of #232, L1: EVERY workspace of the user is locked, not only the
	// selected one, so a concurrent demotion in a non-selected workspace serialises.
	expect(lockedScopes.at(-1)).toEqual(["org_PROTECTED", "org_S"]);
});

it("changed_membership_scope_after_locking_refuses_all_side_effects", async () => {
	const spy = stubGlobalMemberships({ allowGlobal: true, changedScope: true });
	const response = await del({ confirmEmail: "me@x.co" });
	expect(response.status).toBe(409);
	expect((await response.json()).error).toBe("membership_changed");
	expect(spy.mock.calls.some((c) => c[1]?.method === "DELETE")).toBe(false);
	expect(h.db?.db.update).not.toHaveBeenCalled();
});

it("duplicate_owner_records_cannot_inflate_the_remaining_owner_count", async () => {
	const spy = stubGlobalMemberships({ duplicateOwner: true });
	expect((await del({ confirmEmail: "me@x.co" })).status).toBe(502);
	expect(spy.mock.calls.some((c) => c[1]?.method === "DELETE")).toBe(false);
	expect(h.db?.db.execute).not.toHaveBeenCalled();
});

it("incomplete_paginated_memberships_refuse_global_deletion", async () => {
	const spy = vi.fn(async (raw: string) => {
		const query = new URL(raw).searchParams;
		if (query.has("after")) return new Response(null, { status: 503 });
		return Response.json({
			data: [me("member")],
			list_metadata: { after: "next-page" },
		});
	});
	vi.stubGlobal("fetch", spy);
	expect((await del({ confirmEmail: "me@x.co" })).status).toBe(502);
	expect(spy).toHaveBeenCalledTimes(2);
	expect(h.db?.db.update).not.toHaveBeenCalled();
	expect(h.db?.db.execute).not.toHaveBeenCalled();
});
