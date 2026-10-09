/**
 * PLT-52 — the welcome email is wired to fresh provisioning ONLY, reads the
 * recipient from the WorkOS session, and can never break sign-up.
 */

import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	auth: {
		user: { id: "user_ME", email: "me@acme.co", emailVerified: true },
		organizationId: null as string | null,
	},
	pending: [] as Promise<unknown>[],
	// Membership state across POSTs: false until the first POST creates the org.
	member: false,
}));

vi.mock("@workos-inc/authkit-nextjs", () => ({
	withAuth: vi.fn(async () => h.auth),
	switchToOrganization: vi.fn(async () => {}),
}));
vi.mock("@/lib/tenant", () => ({
	upsertTenantId: vi.fn(async () => "tenant-uuid"),
	upsertUserMirror: vi.fn(async () => {}),
}));
// `after()` needs a request scope; run its callback and keep the promise so the
// test can await it, like the Worker's waitUntil would.
vi.mock("next/server", async (orig) => ({
	...(await orig<typeof import("next/server")>()),
	after: (fn: () => Promise<unknown>) => {
		h.pending.push(fn());
	},
}));

import { resetWelcomeEmailStateForTests } from "@/lib/welcome-email";
import { POST } from "./route";

const req = (body: unknown): NextRequest =>
	({
		json: async () => body,
		headers: new Headers(),
	}) as unknown as NextRequest;

const isResend = (c: unknown[]) =>
	String(c[0]).startsWith("https://api.resend.com");

/** WorkOS + Resend stub. `resend` picks what Resend does. */
function stub(resend: "ok" | 400 | 500 | "throw" = "ok") {
	const spy = vi.fn(async (...args: unknown[]) => {
		const url = String(args[0]);
		const method =
			(args[1] as { method?: string } | undefined)?.method ?? "GET";
		if (url.startsWith("https://api.resend.com")) {
			if (resend === "throw") throw new Error("resend down");
			const ok = resend === "ok";
			return { ok, status: ok ? 200 : resend } as unknown as Response;
		}
		if (url.includes("organization_memberships") && method !== "POST") {
			return {
				ok: true,
				json: async () => ({
					data: h.member
						? [{ organization_id: "org_NEW", status: "active" }]
						: [],
				}),
			} as unknown as Response;
		}
		if (url.endsWith("/organizations")) {
			return {
				ok: true,
				json: async () => ({ id: "org_NEW" }),
			} as unknown as Response;
		}
		h.member = true; // POST membership
		return {
			ok: true,
			json: async () => ({ id: "mem" }),
		} as unknown as Response;
	});
	vi.stubGlobal("fetch", spy);
	return spy;
}

let n = 0;
beforeEach(() => {
	n += 1; // fresh user id per test: the route rate-limits org creation per user
	resetWelcomeEmailStateForTests();
	h.pending = [];
	h.member = false;
	h.auth = {
		user: { id: `user_ME_${n}`, email: "me@acme.co", emailVerified: true },
		organizationId: null,
	};
	process.env.WORKOS_API_KEY = "sk_test_workos_do_not_use";
	process.env.RESEND_API_KEY = "re_test_not_a_real_key";
	process.env.RESEND_FROM = "Tracelane <hello@tracelane.dev>";
	vi.spyOn(console, "warn").mockImplementation(() => {});
	vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
	vi.unstubAllGlobals();
	Reflect.deleteProperty(process.env, "RESEND_API_KEY");
	Reflect.deleteProperty(process.env, "RESEND_FROM");
	Reflect.deleteProperty(process.env, "WORKOS_API_KEY");
});

describe("welcome email — trigger", () => {
	it("fresh provisioning sends ONE email to the SESSION email, ignoring a body email", async () => {
		const spy = stub();
		const res = await POST(req({ name: "Acme", email: "attacker@evil.co" }));
		await Promise.all(h.pending);
		expect(res.status).toBe(201);
		const calls = spy.mock.calls.filter(isResend);
		expect(calls).toHaveLength(1);
		const init = calls[0]?.[1] as {
			body: string;
			headers: Record<string, string>;
		};
		const body = JSON.parse(init.body) as { to: string[]; text: string };
		expect(body.to).toEqual(["me@acme.co"]);
		expect(init.body).not.toContain("attacker@evil.co");
		expect(init.headers["idempotency-key"]).toBe("welcome-org_NEW");
		expect(body.text).toContain("Your workspace is ready.");
		expect(body.text).not.toContain("Acme");
	});

	it("an UNVERIFIED session email gets no mail, and sign-up still succeeds (security review C1)", async () => {
		h.auth.user = {
			id: `user_UNV_${n}`,
			email: "victim@elsewhere.co",
			emailVerified: false,
		};
		const spy = stub();
		const res = await POST(req({ name: "Visit https://evil.example now" }));
		await Promise.all(h.pending);
		expect(res.status).toBe(201);
		expect(spy.mock.calls.filter(isResend)).toHaveLength(0);
	});

	it("session already in an org: no email", async () => {
		h.auth.organizationId = "org_EXISTING";
		const spy = stub();
		expect((await POST(req({}))).status).toBe(200);
		await Promise.all(h.pending);
		expect(spy.mock.calls.filter(isResend)).toHaveLength(0);
	});

	it("retry path (existing membership): no email", async () => {
		h.member = true;
		const spy = stub();
		expect((await POST(req({}))).status).toBe(200);
		await Promise.all(h.pending);
		expect(spy.mock.calls.filter(isResend)).toHaveLength(0);
	});

	it("NOT TWICE: sign-up, then a repeat POST by the now-member, sends one email in total", async () => {
		const spy = stub();
		expect((await POST(req({ name: "Acme" }))).status).toBe(201);
		expect((await POST(req({ name: "Acme" }))).status).toBe(200);
		await Promise.all(h.pending);
		expect(spy.mock.calls.filter(isResend)).toHaveLength(1);
	});

	it("unconfigured: sign-up succeeds, no Resend call", async () => {
		Reflect.deleteProperty(process.env, "RESEND_API_KEY");
		const spy = stub();
		const res = await POST(req({ name: "Acme" }));
		await Promise.all(h.pending);
		expect(res.status).toBe(201);
		expect(spy.mock.calls.filter(isResend)).toHaveLength(0);
	});
});

describe("welcome email — sign-up survives a failing Resend", () => {
	for (const mode of [400, 500, "throw"] as const) {
		it(`Resend ${mode}: still 201 created:true`, async () => {
			const spy = stub(mode);
			const res = await POST(req({ name: "Acme" }));
			await Promise.all(h.pending);
			expect(res.status).toBe(201);
			expect(((await res.json()) as { created: boolean }).created).toBe(true);
			expect(spy.mock.calls.filter(isResend)).toHaveLength(1);
		});
	}
});
