/**
 * Tests for POST /api/onboarding/organization — workspace provisioning.
 *
 * Focus (the bug this guards): the workspace CREATOR must be provisioned as
 * `admin`, not WorkOS's default `member` — otherwise the owner is 403'd out of
 * the admin-gated rename / member-removal / Admin-Portal surface on their OWN
 * workspace. Also: idempotent across retries, org id from the freshly-created
 * org, never the request body. Negative cases first per `.claude/rules/testing.md`.
 */

import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	auth: {
		user: { id: "user_ME", email: "me@acme.co" },
		organizationId: null as string | null,
	},
}));

// Counter durability and outage paths have their own integration/route tests.
vi.mock("@/lib/rate-limit", () => ({ rateLimit: vi.fn(async () => true) }));

vi.mock("@workos-inc/authkit-nextjs", () => ({
	withAuth: vi.fn(async () => h.auth),
	switchToOrganization: vi.fn(async () => {}),
}));
vi.mock("@/lib/tenant", () => ({
	upsertTenantId: vi.fn(async () => "tenant-uuid"),
	upsertUserMirror: vi.fn(async () => {}),
}));

import { POST } from "./route";

function req(body: unknown): NextRequest {
	return {
		json: async () => body,
		headers: new Headers(),
	} as unknown as NextRequest;
}

const methodOf = (c: unknown[]): string =>
	(c[1] as { method?: string } | undefined)?.method ?? "GET";

/** Stub the WorkOS calls the fresh-provisioning path makes: existing-org lookup
 * (GET memberships), org create (POST /organizations), membership create. */
function stub(
	opts: { priorOrg?: boolean; orgOk?: boolean; memOk?: boolean } = {},
) {
	const { priorOrg = false, orgOk = true, memOk = true } = opts;
	const spy = vi.fn(async (...args: unknown[]) => {
		const url = args[0] as string;
		if (url.includes("organization_memberships") && methodOf(args) !== "POST") {
			return {
				ok: true,
				json: async () => ({
					data: priorOrg
						? [{ organization_id: "org_PRIOR", status: "active" }]
						: [],
				}),
			} as unknown as Response;
		}
		if (url.endsWith("/organizations")) {
			return {
				ok: orgOk,
				status: orgOk ? 201 : 502,
				json: async () => ({ id: "org_NEW" }),
			} as unknown as Response;
		}
		// POST membership
		return {
			ok: memOk,
			status: memOk ? 201 : 502,
			json: async () => ({ id: "mem_NEW" }),
		} as unknown as Response;
	});
	vi.stubGlobal("fetch", spy);
	return spy;
}

describe("POST /api/onboarding/organization — creator provisioned as admin", () => {
	beforeEach(() => {
		h.auth = {
			user: { id: "user_ME", email: "me@acme.co" },
			organizationId: null,
		};
		process.env.WORKOS_API_KEY = "sk_test_workos_do_not_use";
	});
	afterEach(() => {
		vi.unstubAllGlobals();
		process.env.WORKOS_API_KEY = undefined;
	});

	it("HAPPY: fresh signup creates the creator membership with role_slug='admin'", async () => {
		const spy = stub();
		const res = await POST(req({ name: "Acme" }));
		expect(res.status).toBe(201);
		const memCall = spy.mock.calls.find(
			(c) =>
				(c[0] as string).includes("organization_memberships") &&
				methodOf(c) === "POST",
		);
		const body = JSON.parse((memCall?.[1] as { body: string }).body) as {
			user_id: string;
			organization_id: string;
			role_slug: string;
		};
		// THE FIX: the owner must be admin, or they 403 on their own workspace.
		expect(body.role_slug).toBe("admin");
		expect(body.organization_id).toBe("org_NEW");
		expect(body.user_id).toBe("user_ME");
	});

	it("REJECT: no session org and WORKOS_API_KEY unset → 501", async () => {
		process.env.WORKOS_API_KEY = "";
		expect((await POST(req({}))).status).toBe(501);
	});

	it("SHORT-CIRCUIT: session already scoped to an org → no WorkOS calls, created:false", async () => {
		h.auth = {
			user: { id: "user_ME", email: "me@acme.co" },
			organizationId: "org_EXISTING",
		};
		const spy = stub();
		const res = await POST(req({}));
		expect(res.status).toBe(200);
		const json = (await res.json()) as {
			created: boolean;
			organizationId: string;
		};
		expect(json.created).toBe(false);
		expect(json.organizationId).toBe("org_EXISTING");
		expect(spy).not.toHaveBeenCalled();
	});

	it("RETRY-SAFE: an existing membership is reused — no new org/membership created", async () => {
		const spy = stub({ priorOrg: true });
		const res = await POST(req({}));
		expect(res.status).toBe(200);
		const json = (await res.json()) as { organizationId: string };
		expect(json.organizationId).toBe("org_PRIOR");
		const createdOrg = spy.mock.calls.some(
			(c) =>
				(c[0] as string).endsWith("/organizations") && methodOf(c) === "POST",
		);
		expect(createdOrg).toBe(false);
	});

	it("membership_lookup_failure_does_not_create_org", async () => {
		const spy = vi.fn(
			async (..._args: unknown[]) => ({ ok: false, status: 503 }) as Response,
		);
		vi.stubGlobal("fetch", spy);
		const res = await POST(req({ name: "Unexpected" }));
		expect(res.status).toBe(502);
		expect(spy).toHaveBeenCalledTimes(1);
		expect(
			spy.mock.calls.some(
				(call) =>
					(call[0] as string).endsWith("/organizations") &&
					methodOf(call) === "POST",
			),
		).toBe(false);
	});

	it("malformed_membership_lookup_does_not_create_org", async () => {
		const spy = vi.fn(
			async () =>
				({
					ok: true,
					json: async () => ({}),
				}) as Response,
		);
		vi.stubGlobal("fetch", spy);
		const res = await POST(req({ name: "Unexpected" }));
		expect(res.status).toBe(502);
		expect(spy).toHaveBeenCalledTimes(1);
	});

	it("membership_without_org_id_does_not_create_org", async () => {
		const spy = vi.fn(
			async () =>
				({
					ok: true,
					json: async () => ({ data: [{}] }),
				}) as Response,
		);
		vi.stubGlobal("fetch", spy);
		const res = await POST(req({ name: "Unexpected" }));
		expect(res.status).toBe(502);
		expect(spy).toHaveBeenCalledTimes(1);
	});

	it("REJECT: WorkOS membership creation fails → 502", async () => {
		stub({ memOk: false });
		expect((await POST(req({ name: "Acme" }))).status).toBe(502);
	});
});
