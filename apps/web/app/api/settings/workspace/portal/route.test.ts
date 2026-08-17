/**
 * Tests for POST /api/settings/workspace/portal — WorkOS Admin Portal link.
 *
 * The Admin Portal is high-privilege, so the route is admin-gated. Intent is
 * allowlisted, the org derives from the session (never the body), and a missing
 * link fails 502. Negative cases first per testing.md.
 */

import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => ({
		tenantId: "org_SESSION",
		userId: "user_ME",
		email: "e@x.co",
	})),
}));

// SET-24 / 5D-3: the route now reads the tenant's PLAN, not just the caller's role.
const h = vi.hoisted(() => ({
	tenantRow: { id: "t-1", plan: "free" } as
		| { id: string; plan: string }
		| undefined,
	samlSso: false,
}));

vi.mock("@/db", () => ({
	db: {
		select: () => ({
			from: () => ({
				where: () => ({
					limit: async () => (h.tenantRow ? [h.tenantRow] : []),
				}),
			}),
		}),
	},
}));
vi.mock("@/db/schema", () => ({
	tenants: { id: "id", plan: "plan", workosOrgId: "workos_org_id" },
}));
vi.mock("@/lib/entitlements", () => ({
	resolveEntitlements: vi.fn(async () => ({ saml_sso: h.samlSso })),
}));

import { POST } from "./route";

function req(body: unknown): NextRequest {
	return {
		json: async () => body,
		headers: new Headers(),
	} as unknown as NextRequest;
}

const methodOf = (call: unknown[]): string =>
	(call[1] as { method?: string } | undefined)?.method ?? "GET";

/** Stub WorkOS: GET memberships (caller role) → then POST generate_link. */
function stub(opts: {
	callerRole?: string;
	membersOk?: boolean;
	portalOk?: boolean;
	link?: string;
}) {
	const {
		callerRole = "admin",
		membersOk = true,
		portalOk = true,
		link,
	} = opts;
	const spy = vi.fn(async (...args: unknown[]) => {
		const url = args[0] as string;
		if (url.includes("organization_memberships")) {
			if (!membersOk) return { ok: false, status: 500 } as unknown as Response;
			return {
				ok: true,
				json: async () => ({
					data: [
						{
							id: "m",
							user_id: "user_ME",
							organization_id: "org_SESSION",
							role: { slug: callerRole },
						},
					],
				}),
			} as unknown as Response;
		}
		// POST /portal/generate_link
		return {
			ok: portalOk,
			status: portalOk ? 200 : 500,
			json: async () => (link !== undefined ? { link } : {}),
		} as unknown as Response;
	});
	vi.stubGlobal("fetch", spy);
	return spy;
}

describe("POST /api/settings/workspace/portal", () => {
	beforeEach(() => {
		process.env.WORKOS_API_KEY = "sk_test_workos_do_not_use";
		// Default the EXISTING tests to an entitled tenant so they keep asserting
		// what they were written to assert (role, intent, WorkOS failures).
		h.tenantRow = { id: "t-1", plan: "enterprise" };
		h.samlSso = true;
	});
	afterEach(() => {
		vi.unstubAllGlobals();
		process.env.WORKOS_API_KEY = undefined;
	});

	// ── SET-24 / 5D-3 ────────────────────────────────────────────────────────
	// ROLE IS NOT A PLAN. Before 2026-08-10 this route gated on callerIsOrgAdmin
	// ALONE, so any org admin on ANY plan — including Free — could open the WorkOS
	// portal and configure SAML/SCIM. Negative first, per testing.md.
	it("REJECT: admin on a plan WITHOUT saml_sso → 403, and no portal link is minted", async () => {
		h.tenantRow = { id: "t-1", plan: "free" };
		h.samlSso = false;
		const spy = stub({ callerRole: "admin" });
		const res = await POST(req({ intent: "sso" }));
		expect(res.status).toBe(403);
		expect((await res.json()).error).toBe("saml_sso_required");
		// The link is the capability. It must never be generated.
		expect(spy.mock.calls.every((c) => methodOf(c) !== "POST")).toBe(true);
	});

	it("REJECT: SCIM (dsync) is the same paid capability → 403 on an unentitled plan", async () => {
		h.tenantRow = { id: "t-1", plan: "free" };
		h.samlSso = false;
		stub({ callerRole: "admin" });
		expect((await POST(req({ intent: "dsync" }))).status).toBe(403);
	});

	it("REJECT: an UNKNOWN/missing tenant row fails CLOSED → 403, never inherits the capability", async () => {
		h.tenantRow = undefined;
		h.samlSso = false;
		stub({ callerRole: "admin" });
		expect((await POST(req({ intent: "sso" }))).status).toBe(403);
	});

	it("ALLOW: an entitled plan still reaches WorkOS", async () => {
		h.tenantRow = { id: "t-1", plan: "enterprise" };
		h.samlSso = true;
		const spy = stub({
			callerRole: "admin",
			link: "https://portal.workos.com/x",
		});
		expect((await POST(req({ intent: "sso" }))).status).toBe(200);
		expect(spy.mock.calls.some((c) => methodOf(c) === "POST")).toBe(true);
	});

	it("ALLOW: domain_verification is NOT the paid capability — unentitled plans keep it", async () => {
		h.tenantRow = { id: "t-1", plan: "free" };
		h.samlSso = false;
		stub({ callerRole: "admin", link: "https://portal.workos.com/x" });
		expect((await POST(req({ intent: "domain_verification" }))).status).toBe(
			200,
		);
	});

	it("REJECT: WORKOS_API_KEY unset → 501", async () => {
		process.env.WORKOS_API_KEY = "";
		expect((await POST(req({ intent: "sso" }))).status).toBe(501);
	});

	it("REJECT: unknown intent → 422 (before any WorkOS call)", async () => {
		const spy = stub({});
		expect((await POST(req({ intent: "delete_everything" }))).status).toBe(422);
		expect(spy).not.toHaveBeenCalled();
	});

	it("REJECT: caller is not admin/owner → 403 (no portal link minted)", async () => {
		const spy = stub({ callerRole: "member" });
		expect((await POST(req({ intent: "sso" }))).status).toBe(403);
		expect(spy.mock.calls.every((c) => methodOf(c) !== "POST")).toBe(true);
	});

	it("REJECT: role lookup fails → 502 (fail closed)", async () => {
		stub({ membersOk: false });
		expect((await POST(req({ intent: "sso" }))).status).toBe(502);
	});

	it("REJECT: WorkOS failure → 502", async () => {
		stub({ portalOk: false });
		expect((await POST(req({ intent: "sso" }))).status).toBe(502);
	});

	it("REJECT: link missing from WorkOS response → 502", async () => {
		stub({ portalOk: true }); // ok but no link
		expect((await POST(req({ intent: "dsync" }))).status).toBe(502);
	});

	it("HAPPY: admin gets the portal link, org from session not body", async () => {
		const spy = stub({ link: "https://admin.workos.com/xyz" });
		const res = await POST(
			req({ intent: "domain_verification", organization: "org_ATTACKER" }),
		);
		expect(res.status).toBe(200);
		expect(((await res.json()) as { link: string }).link).toBe(
			"https://admin.workos.com/xyz",
		);
		const gen = spy.mock.calls.find((c) =>
			(c[0] as string).includes("/portal/generate_link"),
		);
		const body = JSON.parse((gen?.[1] as unknown as { body: string }).body) as {
			organization: string;
			intent: string;
		};
		expect(body.organization).toBe("org_SESSION"); // never org_ATTACKER
		expect(body.intent).toBe("domain_verification");
	});
});
