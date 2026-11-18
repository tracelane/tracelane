/** Account deletion authenticates the identity, including before onboarding. */
import { type DbMock, makeDbMock } from "@/lib/__testutils__/db-mock";
import type { NextRequest } from "next/server";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	session: null as {
		user: { id: string; email: string };
		organizationId?: string;
	} | null,
	db: null as DbMock | null,
}));
vi.mock("@workos-inc/authkit-nextjs", () => ({
	withAuth: async () => h.session,
}));
vi.mock("@/lib/e2e-auth", () => ({ e2eAuthEnabled: () => false }));
vi.mock("@/lib/return-to", () => ({ signInPath: async () => "/sign-in" }));
vi.mock("next/navigation", () => ({
	redirect: (path: string) => {
		throw new Error(`redirect:${path}`);
	},
}));
vi.mock("@/db", () => ({
	get db() {
		return h.db?.db;
	},
}));
vi.mock("../team/owner-lock", () => ({
	withOwnerMutation: vi.fn(async (_org: string, work: () => Promise<unknown>) =>
		work(),
	),
}));

import { withOwnerMutation } from "../team/owner-lock";
import { DELETE } from "./route";
const del = () =>
	DELETE({
		json: async () => ({ confirmEmail: "me@example.test" }),
	} as NextRequest);

beforeEach(() => {
	h.session = { user: { id: "user_new", email: "me@example.test" } };
	h.db = makeDbMock([[], [], []]);
	vi.stubEnv("WORKOS_API_KEY", "sk_test_workos_do_not_use");
	vi.stubGlobal(
		"fetch",
		vi.fn(async () => ({ ok: true, json: async () => ({ data: [] }) })),
	);
});
afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
	vi.unstubAllEnvs();
});

it("authenticated identity without an org can erase itself before onboarding", async () => {
	const result = await del();
	expect(result.status).toBe(200);
	expect(await result.json()).toEqual({ deleted: true, orgDeleted: false });
	expect(h.db?.db.execute).toHaveBeenCalledTimes(1);
	expect(h.db?.db.select).toHaveBeenCalledTimes(2);
	expect(withOwnerMutation).not.toHaveBeenCalled();
	expect(fetch).toHaveBeenCalledTimes(2);
	expect(fetch).toHaveBeenCalledWith(
		"https://api.workos.com/user_management/users/user_new",
		expect.objectContaining({ method: "DELETE" }),
	);
});

it("unauthenticated deletion is refused before any database or WorkOS call", async () => {
	h.session = null;
	const result = await del();
	expect(result.status).toBe(401);
	expect(h.db?.db.execute).not.toHaveBeenCalled();
	expect(fetch).not.toHaveBeenCalled();
});

it("unscoped existing owner must select an organization before deletion", async () => {
	vi.stubGlobal(
		"fetch",
		vi.fn(async (url: string) => ({
			ok: true,
			json: async () => ({
				data: url.includes("user_id=")
					? [
							{
								user_id: "user_new",
								organization_id: "org_existing",
								role: { slug: "owner" },
								status: "active",
							},
						]
					: [
							{
								user_id: "user_new",
								organization_id: "org_existing",
								role: { slug: "owner" },
								status: "active",
							},
							{
								user_id: "other",
								organization_id: "org_existing",
								role: { slug: "member" },
								status: "active",
							},
						],
			}),
		})),
	);
	const result = await del();
	expect(result.status).toBe(409);
	expect((await result.json()).error).toBe("organization_selection_required");
	expect(withOwnerMutation).not.toHaveBeenCalled();
	expect(h.db?.db.execute).not.toHaveBeenCalled();
});

it.each([null, {}])(
	"unverified user membership listing fails closed (%s)",
	async (data) => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => ({ ok: true, json: async () => ({ data }) })),
		);
		expect((await del()).status).toBe(502);
		expect(h.db?.db.execute).not.toHaveBeenCalled();
	},
);

it("orgless identity with historical keys cannot erase without confirmed revocation", async () => {
	h.db = makeDbMock([[{ id: "orphan-key" }]]);
	const result = await del();
	expect(result.status).toBe(409);
	expect(await result.json()).toMatchObject({
		error: "organization_selection_required",
	});
	expect(h.db.db.execute).not.toHaveBeenCalled();
});

it("orgless deletion refuses success if a mint committed before the erasure marker", async () => {
	h.db = makeDbMock([[], [], [{ id: "late-key" }]]);
	const result = await del();
	expect(result.status).toBe(503);
	expect(await result.json()).toMatchObject({
		error: "key_revocation_unconfirmed",
	});
	expect(fetch).toHaveBeenCalledTimes(1);
});
