/**
 * Tests for POST /api/settings/team/invite — server-side seat enforcement.
 *
 * Focus: an invite that would push the org past its `seat_cap_max` MUST be
 * rejected with 403 even on a direct POST (the UI disables the button, but
 * the server is the real gate). Seats consumed = accepted memberships + PENDING
 * invitations. Negative cases first per `.claude/rules/testing.md`. tenant_id
 * derives from the session org id.
 */

import { type DbMock, makeDbMock } from "@/lib/__testutils__/db-mock";
import { PLAN_ENTITLEMENTS } from "@/lib/entitlements";
import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	db: null as DbMock | null,
	session: { tenantId: "org_SESSION", userId: "user_1", email: "a@b.co" },
	seatCapMax: 0,
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

// Drive seat_cap_max directly so the seat-gate logic is the unit under test;
// the resolver itself is covered in lib/entitlements.test.ts.
vi.mock("@/lib/entitlements", async (orig) => {
	const actual = (await orig()) as Record<string, unknown>;
	return {
		...actual,
		resolveEntitlements: vi.fn(async () => ({
			...PLAN_ENTITLEMENTS.team,
			seat_cap_max: h.seatCapMax,
		})),
	};
});

import { POST } from "./route";

function setDb(results: unknown[]): void {
	h.db = makeDbMock(results);
}

// Unique IP per call so the module-global per-IP rate limiter never trips
// across tests (rate-limiting is not the unit under test here).
let ipCounter = 0;
function req(body: unknown): NextRequest {
	ipCounter += 1;
	return {
		json: async () => body,
		headers: new Headers({ "x-forwarded-for": `10.0.0.${ipCounter}` }),
	} as unknown as NextRequest;
}

const methodOf = (call: unknown[]): string =>
	(call[1] as { method?: string } | undefined)?.method ?? "GET";

/**
 * Stub the three WorkOS calls the seat gate makes: GET memberships, GET
 * invitations (count), POST invitations (send). `members`/`pending` drive the
 * counts; the invitations GET also returns non-pending states that MUST be
 * ignored by the seat math. `membersOk:false` simulates a failed lookup.
 */
function stubWorkos(opts: {
	members: number;
	pending: number;
	membersOk?: boolean;
	sendOk?: boolean;
}) {
	const { members, pending, membersOk = true, sendOk = true } = opts;
	const spy = vi.fn(async (...args: unknown[]) => {
		const url = args[0] as string;
		if (url.includes("organization_memberships")) {
			if (!membersOk) return { ok: false, status: 500 } as unknown as Response;
			// First entry = the SESSION caller as an owner (so the owner-gate passes);
			// the rest are filler members. Total length = `members` (the seat count).
			const list = [
				{ id: "caller", user_id: "user_1", role: { slug: "owner" } },
				...new Array(Math.max(0, members - 1)).fill({
					id: "m",
					user_id: "other",
					role: { slug: "member" },
				}),
			];
			return {
				ok: true,
				json: async () => ({ data: list }),
			} as unknown as Response;
		}
		if (url.includes("/invitations") && methodOf(args) !== "POST") {
			// GET count — pending seats + non-pending states that must NOT count.
			return {
				ok: true,
				json: async () => ({
					data: [
						...new Array(pending).fill({ state: "pending" }),
						{ state: "accepted" },
						{ state: "expired" },
						{ state: "revoked" },
					],
				}),
			} as unknown as Response;
		}
		// POST send.
		if (!sendOk)
			return {
				ok: false,
				status: 502,
				json: async () => ({}),
			} as unknown as Response;
		return {
			ok: true,
			json: async () => ({
				id: "invitation_123",
				email: "new@member.co",
				state: "pending",
			}),
		} as unknown as Response;
	});
	vi.stubGlobal("fetch", spy);
	return spy;
}

describe("POST /api/settings/team/invite — seat enforcement", () => {
	beforeEach(() => {
		h.session = { tenantId: "org_SESSION", userId: "user_1", email: "a@b.co" };
		process.env.WORKOS_API_KEY = "sk_test_workos_do_not_use";
		setDb([[{ id: "tenant-db-uuid", plan: "team", auditEnabled: false }]]);
	});
	afterEach(() => {
		vi.unstubAllGlobals();
		process.env.WORKOS_API_KEY = undefined;
	});

	it("REJECT: WORKOS_API_KEY unset → 501 (before touching db or session)", async () => {
		process.env.WORKOS_API_KEY = "";
		const res = await POST(req({ email: "x@y.co" }));
		expect(res.status).toBe(501);
	});

	it("REJECT: invalid email → 422", async () => {
		const res = await POST(req({ email: "not-an-email" }));
		expect(res.status).toBe(422);
	});

	it("REJECT: at the seat cap → 403, and the invite POST never runs", async () => {
		h.seatCapMax = 10;
		const spy = stubWorkos({ members: 10, pending: 0 });
		const res = await POST(req({ email: "new@member.co" }));
		expect(res.status).toBe(403);
		const json = (await res.json()) as { error: string; seat_cap_max: number };
		expect(json.error).toBe("seat_limit_reached");
		expect(json.seat_cap_max).toBe(10);
		// Only the two count GETs ran; the invitation POST was never dispatched.
		expect(spy.mock.calls.every((c) => methodOf(c) !== "POST")).toBe(true);
	});

	it("REJECT: PENDING invitations push over the cap → 403 (fix #4)", async () => {
		// 8 accepted + 2 pending = 10 = cap → the next invite is blocked, even
		// though only 8 seats are 'accepted'. Regression for the double-count gap.
		h.seatCapMax = 10;
		const spy = stubWorkos({ members: 8, pending: 2 });
		const res = await POST(req({ email: "new@member.co" }));
		expect(res.status).toBe(403);
		expect(spy.mock.calls.every((c) => methodOf(c) !== "POST")).toBe(true);
	});

	it("REJECT: over the cap (race / stale UI) → 403", async () => {
		h.seatCapMax = 10;
		stubWorkos({ members: 12, pending: 0 });
		const res = await POST(req({ email: "new@member.co" }));
		expect(res.status).toBe(403);
	});

	it("REJECT: a membership lookup fails → 502 (fail closed on the owner gate)", async () => {
		// The owner-gate's membership lookup runs before the seat count, so a
		// WorkOS failure fails closed there first (also 502, different code).
		h.seatCapMax = 10;
		stubWorkos({ members: 3, pending: 0, membersOk: false });
		const res = await POST(req({ email: "new@member.co" }));
		expect(res.status).toBe(502);
		const json = (await res.json()) as { error: string };
		expect(json.error).toBe("could not verify caller role");
	});

	it("HAPPY: under the cap → forwards the invite to WorkOS, 201", async () => {
		h.seatCapMax = 10;
		const spy = stubWorkos({ members: 3, pending: 0 });
		const res = await POST(req({ email: "New@Member.co" }));
		expect(res.status).toBe(201);
		const json = (await res.json()) as { invitationId: string };
		expect(json.invitationId).toBe("invitation_123");
		// The invite carries the SESSION org id, never anything from the body,
		// and the email is normalised to lowercase.
		const inviteCall = spy.mock.calls.find(
			(c) =>
				(c[0] as string).includes("/invitations") && methodOf(c) === "POST",
		);
		const body = JSON.parse((inviteCall?.[1] as { body: string }).body) as {
			organization_id: string;
			email: string;
		};
		expect(body.organization_id).toBe("org_SESSION");
		expect(body.email).toBe("new@member.co");
	});

	it("HAPPY: unlimited (seat_cap_max=0, Enterprise) skips the seat count", async () => {
		h.seatCapMax = 0;
		const spy = stubWorkos({ members: 999, pending: 999 });
		const res = await POST(req({ email: "x@y.co" }));
		expect(res.status).toBe(201);
		// Owner-gate membership GET + the invitation POST — but NO seat-count GET
		// of invitations (unlimited skips it). So no invitations GET was made.
		const invitationGets = spy.mock.calls.filter(
			(c) =>
				(c[0] as string).includes("/invitations") && methodOf(c) !== "POST",
		);
		expect(invitationGets).toHaveLength(0);
		expect(spy.mock.calls.some((c) => methodOf(c) === "POST")).toBe(true);
	});

	it("REJECT: caller is not an owner → 403 role_forbidden (owner-gate)", async () => {
		h.seatCapMax = 10;
		// Session user is present but as a plain member → owner-gate denies.
		vi.stubGlobal(
			"fetch",
			vi.fn(async (url: string) => {
				if (url.includes("organization_memberships")) {
					return {
						ok: true,
						json: async () => ({
							data: [{ id: "c", user_id: "user_1", role: { slug: "member" } }],
						}),
					} as unknown as Response;
				}
				return { ok: true, json: async () => ({}) } as unknown as Response;
			}),
		);
		const res = await POST(req({ email: "new@member.co" }));
		expect(res.status).toBe(403);
		const json = (await res.json()) as { error: string };
		expect(json.error).toBe("role_forbidden");
	});

	it("REJECT: invalid role → 422 (before any WorkOS call)", async () => {
		h.seatCapMax = 10;
		const spy = stubWorkos({ members: 3, pending: 0 });
		const res = await POST(req({ email: "new@member.co", role: "owner" }));
		expect(res.status).toBe(422);
		expect(spy).not.toHaveBeenCalled();
	});
});
