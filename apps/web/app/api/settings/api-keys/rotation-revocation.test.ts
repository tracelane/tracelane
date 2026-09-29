import { PGlite } from "@electric-sql/pglite";
import { drizzle } from "drizzle-orm/pglite";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ db: null as unknown, members: [] as unknown[] }));
vi.mock("@/db", () => ({
	get db() {
		return h.db;
	},
}));
vi.mock("@/lib/auth", () => ({
	requireSession: async () => ({
		tenantId: "org-test",
		userId: "owner",
		email: "owner@example.test",
	}),
	invalidateOrgArchivedCache: vi.fn(),
}));
vi.mock("@/lib/workos-org", () => ({
	callerIsOrgAdmin: async () => true,
	isPrivilegedRole: (role: string) => role === "owner",
	listMemberships: async () => h.members,
}));
import { DELETE as removeAccount } from "../account/route";
import { DELETE as removeMember } from "../team/[membershipId]/route";
import { DELETE as removeWorkspace } from "../workspace/route";

let pg: PGlite;
const tenant = "00000000-0000-0000-0000-000000000001";
beforeEach(async () => {
	vi.stubEnv("WORKOS_API_KEY", "unit-test-workos-key");
	vi.stubGlobal(
		"fetch",
		vi.fn(async () => Response.json({})),
	);
	pg = new PGlite();
	h.db = drizzle(pg);
	await pg.exec(`CREATE TABLE tenants (id uuid, workos_org_id text, name text, archived_at timestamptz);
      CREATE TABLE api_keys (tenant_id uuid, minted_by text, revoked_at timestamptz);
      CREATE TABLE users (workos_user_id text, email text, name text);
      INSERT INTO tenants VALUES ('${tenant}', 'org-test', 'Test', NULL);
      INSERT INTO api_keys VALUES ('${tenant}', 'member', '2030-01-01T00:00:00Z');
      INSERT INTO api_keys VALUES ('00000000-0000-0000-0000-000000000002', 'member', '2030-01-01T00:00:00Z');`);
	h.members = [
		{ id: "owner-membership", user_id: "owner", role: { slug: "owner" } },
		{ id: "member-membership", user_id: "member", role: { slug: "member" } },
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
