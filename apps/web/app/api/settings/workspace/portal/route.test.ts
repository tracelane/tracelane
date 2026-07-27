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
	});
	afterEach(() => {
		vi.unstubAllGlobals();
		process.env.WORKOS_API_KEY = undefined;
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
