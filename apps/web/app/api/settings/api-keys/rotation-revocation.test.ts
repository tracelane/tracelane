import { readFileSync } from "node:fs";
import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	db: null as unknown,
	members: [] as unknown[],
	orgId: "org-test",
}));
vi.mock("@/lib/control-change", () => ({
	recordControlChange: vi.fn(async () => ({ ok: true })),
	recordControlChangeFailed: vi.fn(async () => undefined),
}));

vi.mock("@/db", () => ({
	get db() {
		return h.db;
	},
}));
vi.mock("@workos-inc/authkit-nextjs", () => ({
	withAuth: async () => ({
		user: { id: "owner", email: "owner@example.test" },
		organizationId: h.orgId,
	}),
}));
vi.mock("@/lib/auth", () => ({
	requireGatewayToken: async () => ({
		token: "unit-test-human-jwt",
		tenantId: h.orgId,
	}),
	requireSession: async () => ({
		tenantId: h.orgId,
		userId: "owner",
		email: "owner@example.test",
	}),
	invalidateOrgArchivedCache: vi.fn(),
}));
vi.mock("@/lib/workos-org", () => ({
	callerIsOrgAdmin: async () => true,
	isPrivilegedRole: (role: string) => role === "owner",
	countsAsOwner: (m: { role: { slug: string }; status?: string }) =>
		m.role.slug === "owner" && m.status === "active",
	listMemberships: async (_key: string, org: string) =>
		(h.members as Array<{ organization_id: string }>).filter(
			(m) => m.organization_id === org,
		),
	listUserMemberships: async (_key: string, user: string) =>
		(h.members as Array<{ user_id: string }>).filter((m) => m.user_id === user),
}));
import { DELETE as removeAccount } from "../account/route";
import { DELETE as removeMember } from "../team/[membershipId]/route";
import { DELETE as removeWorkspace } from "../workspace/route";

let pg: PGlite;
let queries: string[] = [];
const tenant = "00000000-0000-0000-0000-000000000001";
beforeEach(async () => {
	h.orgId = "org-test";
	vi.stubEnv("WORKOS_API_KEY", "unit-test-workos-key");
	vi.stubGlobal(
		"fetch",
		vi.fn(async (raw: string) => {
			if (raw.endsWith("/v1/keys/invalidate-cache")) {
				// The real Drizzle write must commit BEFORE gateway acknowledgement.
				const result = await pg.query<{ revoked: boolean }>(
					"SELECT revoked_at <= now() AS revoked FROM api_keys WHERE tenant_id = $1",
					[tenant],
				);
				expect(result.rows[0]?.revoked).toBe(true);
				return Response.json({ invalidated: true });
			}
			return Response.json({});
		}),
	);
	pg = new PGlite();
	h.db = drizzle(pg, { logger: { logQuery: (query) => queries.push(query) } });
	queries = [];
	await pg.exec(`CREATE TABLE tenants (id uuid, workos_org_id text, name text, archived_at timestamptz);
      CREATE TABLE api_keys (tenant_id uuid, minted_by text, revoked_at timestamptz);
      CREATE TABLE users (workos_user_id text, email text, name text, last_login_at timestamptz);
      INSERT INTO tenants VALUES ('${tenant}', 'org-test', 'Test', NULL);
      INSERT INTO api_keys VALUES ('${tenant}', 'member', '2030-01-01T00:00:00Z');
      INSERT INTO api_keys VALUES ('00000000-0000-0000-0000-000000000002', 'member', '2030-01-01T00:00:00Z');`);
	for (const file of ["0063_signups.sql", "0064_account_deletions.sql"]) {
		await pg.exec(
			readFileSync(
				new URL(`../../../../db/migrations/${file}`, import.meta.url),
				"utf8",
			),
		);
	}

	h.members = [
		{
			id: "owner-membership",
			user_id: "owner",
			organization_id: "org-test",
			role: { slug: "owner" },
			status: "active",
		},
		{
			id: "member-membership",
			user_id: "member",
			organization_id: "org-test",
			role: { slug: "member" },
			status: "active",
		},
	];
});
afterEach(async () => {
	await pg.close();
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
});

it.each(["member", "workspace", "account"])(
	"%s removal revokes keys still in rotation grace and leaves other tenants alone",
	async (kind) => {
		const req = new NextRequest("http://localhost/settings", {
			method: "DELETE",
			body: JSON.stringify({
				confirmName: "Test",
				confirmEmail: "owner@example.test",
			}),
		});
		if (kind === "account") h.members = [h.members[0]];
		const res =
			kind === "member"
				? await removeMember(req, {
						params: Promise.resolve({ membershipId: "member-membership" }),
					})
				: kind === "workspace"
					? await removeWorkspace(req)
					: await removeAccount(req);
		expect(res.status).toBe(200);
		const result = await pg.query<{ revoked: boolean }>(
			"SELECT revoked_at <= now() AS revoked FROM api_keys WHERE tenant_id = $1",
			[tenant],
		);
		expect(
			result.rows[0]?.revoked,
			"scheduled keys must be revoked by the real removal handler",
		).toBe(true);
		const other = await pg.query<{ revoked: boolean }>(
			"SELECT revoked_at <= now() AS revoked FROM api_keys WHERE tenant_id <> $1",
			[tenant],
		);
		expect(other.rows[0]?.revoked).toBe(false);
	},
);

// Lock behavior is covered against real Postgres in owner-race.live.test.ts.
vi.mock("../team/owner-lock", () => ({
	withOwnerMutation: async (_org: string, work: () => Promise<unknown>) =>
		work(),
}));

const removalRequest = () =>
	new NextRequest("http://localhost/settings", {
		method: "DELETE",
		body: JSON.stringify({
			confirmName: "Test",
			confirmEmail: "owner@example.test",
		}),
	});

it("a key minted between the first sweep and membership deletion cannot survive removal", async () => {
	let confirmations = 0;
	vi.stubGlobal(
		"fetch",
		vi.fn(async (url: string, init?: RequestInit) => {
			if (url.endsWith("/v1/keys/invalidate-cache")) {
				confirmations++;
				return Response.json({ invalidated: true });
			}
			if (init?.method === "DELETE") {
				expect(confirmations).toBe(1);
				await pg.query("INSERT INTO api_keys VALUES ($1, 'member', NULL)", [
					tenant,
				]);
			}
			return Response.json({});
		}),
	);
	const res = await removeMember(removalRequest(), {
		params: Promise.resolve({ membershipId: "member-membership" }),
	});
	expect(res.status).toBe(200);
	const result = await pg.query<{ active: number }>(
		"SELECT count(*)::int AS active FROM api_keys WHERE tenant_id = $1 AND minted_by = 'member' AND (revoked_at IS NULL OR revoked_at > now())",
		[tenant],
	);
	expect(
		result.rows[0]?.active,
		"concurrently minted member key must be revoked",
	).toBe(0);
	expect(confirmations).toBe(2);
});

it("member account deletion revokes only its own keys in every workspace before self-cache acknowledgement", async () => {
	h.members = [
		{
			id: "me",
			user_id: "owner",
			organization_id: "org-test",
			role: { slug: "member" },
			status: "active",
		},
		{
			id: "other",
			user_id: "other-owner",
			organization_id: "org-test",
			role: { slug: "owner" },
			status: "active",
		},
	];
	await pg.exec(`INSERT INTO api_keys VALUES ('${tenant}', 'owner', NULL);
 INSERT INTO api_keys VALUES ('00000000-0000-0000-0000-000000000002', 'owner', '2030-01-01');`);
	let acknowledged = false;
	vi.stubGlobal(
		"fetch",
		vi.fn(async (url: string, init?: RequestInit) => {
			if (url.endsWith("/v1/keys/invalidate-cache")) {
				expect(JSON.parse(String(init?.body))).toEqual({ own_keys: true });
				const result = await pg.query<{ revoked: boolean }>(
					"SELECT bool_and(revoked_at IS NOT NULL AND revoked_at <= now()) AS revoked FROM api_keys WHERE minted_by = 'owner'",
				);
				expect(result.rows[0]?.revoked).toBe(true);
				acknowledged = true;
			}
			return Response.json({ invalidated: true });
		}),
	);
	const res = await removeAccount(removalRequest());
	expect(res.status).toBe(200);
	const own = await pg.query<{ revoked: boolean }>(
		"SELECT revoked_at IS NOT NULL AND revoked_at <= now() AS revoked FROM api_keys WHERE minted_by = 'owner'",
	);
	expect(
		own.rows.map((r) => r.revoked),
		"all of the deleting user's keys must be revoked",
	).toEqual([true, true]);
	const others = await pg.query<{ active: boolean }>(
		"SELECT revoked_at > now() AS active FROM api_keys WHERE minted_by = 'member'",
	);
	expect(others.rows.map((r) => r.active)).toEqual([true, true]);
	expect(acknowledged).toBe(true);
});

it.each(["member", "workspace", "account"])(
	"%s revocation SQL uses database time even if the web clock is ahead",
	async (kind) => {
		// Inspect actual SQL emitted by Drizzle: no JS timestamp may become a scheduled revoke.
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => Response.json({ invalidated: true })),
		);
		if (kind === "account") h.members = [h.members[0]];
		const res =
			kind === "member"
				? await removeMember(removalRequest(), {
						params: Promise.resolve({ membershipId: "member-membership" }),
					})
				: kind === "workspace"
					? await removeWorkspace(removalRequest())
					: await removeAccount(removalRequest());
		expect(res.status).toBe(200);
		const writes = queries.filter((q) => q.startsWith('update "api_keys"'));
		expect(writes.length).toBeGreaterThan(0);
		for (const query of writes)
			expect(query).toMatch(/set "revoked_at" = now\(\)/);
	},
);

it("account deletion sweeps a mint that committed immediately before the erasure marker", async () => {
	h.members = [h.members[0]];
	const actual = h.db as ReturnType<typeof drizzle>;
	const original = actual.execute.bind(actual);
	h.db = new Proxy(actual, {
		get(target, prop, receiver) {
			if (prop === "execute")
				return async (query: Parameters<typeof original>[0]) => {
					// A mint holding the identity lock immediately before erasure.
					await pg.query("INSERT INTO api_keys VALUES ($1, 'owner', NULL)", [
						tenant,
					]);
					return original(query);
				};
			return Reflect.get(target, prop, receiver);
		},
	});
	vi.stubGlobal(
		"fetch",
		vi.fn(async () => Response.json({ invalidated: true })),
	);
	const res = await removeAccount(removalRequest());
	expect(res.status).toBe(200);
	const result = await pg.query<{ active: number }>(
		"SELECT count(*)::int AS active FROM api_keys WHERE minted_by = 'owner' AND (revoked_at IS NULL OR revoked_at > now())",
	);
	expect(
		result.rows[0]?.active,
		"a mint preceding the erasure marker must be caught by the final sweep",
	).toBe(0);
});

it("archiving_the_other_workspace_allows_global_deletion_with_membership_retained", async () => {
	const second = "00000000-0000-0000-0000-000000000002";
	await pg.query(
		"INSERT INTO tenants VALUES ($1, 'org-second', 'Second', NULL)",
		[second],
	);
	h.members = [
		{
			id: "first",
			user_id: "owner",
			organization_id: "org-test",
			role: { slug: "owner" },
			status: "active",
		},
		{
			id: "second",
			user_id: "owner",
			organization_id: "org-second",
			role: { slug: "owner" },
			status: "active",
		},
		{
			id: "other",
			user_id: "other-owner",
			organization_id: "org-second",
			role: { slug: "owner" },
			status: "active",
		},
	];
	h.orgId = "org-second";
	const blocked = await removeAccount(removalRequest());
	expect(blocked.status).toBe(409);
	expect((await blocked.json()).error).toBe("workspace_cleanup_required");
	h.orgId = "org-test";
	expect((await removeWorkspace(removalRequest())).status).toBe(200);
	// Workspace deletion archives locally; it does not remove WorkOS membership.
	expect(h.members).toHaveLength(3);
	h.orgId = "org-second";
	// An archive marker alone is insufficient: another minter's key in grace
	// still prevents global deletion, even though this user's own sweep would miss it.
	await pg.query(
		"INSERT INTO api_keys VALUES ($1, 'other-minter', '2030-01-01T00:00:00Z')",
		[tenant],
	);
	const unsafe = await removeAccount(removalRequest());
	expect(unsafe.status).toBe(503);
	expect((await unsafe.json()).error).toBe("key_revocation_unconfirmed");
	expect((await pg.query("SELECT * FROM account_deletions")).rows).toHaveLength(
		0,
	);
	await pg.query(
		"UPDATE api_keys SET revoked_at = now() WHERE tenant_id = $1 AND minted_by = 'other-minter'",
		[tenant],
	);
	const deleted = await removeAccount(removalRequest());
	expect(deleted.status).toBe(200);
	expect(await deleted.json()).toEqual({ deleted: true, orgDeleted: false });
});
