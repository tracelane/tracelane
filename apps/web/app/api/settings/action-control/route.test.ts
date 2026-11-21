/**
 * ACT-20 — GET/PUT /api/settings/action-control. Tier A: tenant from the session only,
 * owner role checked server-side, org resolved to the tenant UUID before any write, fail
 * closed on every lookup. Negative cases first (`.claude/rules/testing.md`).
 */
import { refuseCrossOriginMutation } from "@/lib/csrf";
import { type NextRequest, NextResponse } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	role: "admin" as "admin" | "other" | null,
	sessionRole: "admin" as string | null,
	row: { id: "tenant-uuid-1", actionControl: false } as
		| { id: string; actionControl: boolean }
		| undefined,
	selectThrows: false,
	updateRows: [{ id: "tenant-uuid-1" }] as { id: string }[],
	updateThrows: false,
	rateOk: true,
	rateThrows: false,
	record: { ok: true } as { ok: true } | { ok: false; response: Response },
	sets: [] as unknown[],
	order: [] as string[],
	failure: undefined as unknown,
}));

vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => ({
		tenantId: "org_SESSION",
		userId: "user_ME",
		email: "e@x.co",
		role: h.sessionRole,
	})),
	canAdmin: (r: string | null) => r === "admin" || r === "owner",
}));
vi.mock("@/db", () => ({
	db: {
		select: () => ({
			from: () => ({
				where: () => ({
					limit: async () => {
						if (h.selectThrows) throw new Error("db down");
						return h.row ? [h.row] : [];
					},
				}),
			}),
		}),
		update: () => ({
			set: (v: unknown) => {
				h.sets.push(v);
				return {
					where: () => ({
						returning: async () => {
							h.order.push("update");
							if (h.updateThrows) throw new Error("db down");
							return h.updateRows;
						},
					}),
				};
			},
		}),
	},
}));
vi.mock("@/db/schema", () => ({
	tenants: {
		id: "id",
		actionControl: "action_control",
		workosOrgId: "workos_org_id",
	},
}));
vi.mock("@/lib/workos-org", () => ({
	callerIsOrgAdmin: vi.fn(async () =>
		h.role === null ? null : h.role === "admin",
	),
}));
vi.mock("@/lib/rate-limit", () => ({
	rateLimit: vi.fn(async () => {
		if (h.rateThrows) throw new Error("rate_limit_unavailable");
		return h.rateOk;
	}),
	clientIp: () => "1.2.3.4",
}));
vi.mock("@/lib/control-change", () => ({
	recordControlChange: vi.fn(async () => {
		h.order.push("record");
		return h.record;
	}),
	recordControlChangeFailed: vi.fn(async () => {}),
}));
vi.mock("../team/owner-lock", () => ({
	withOwnerMutation: async (
		_org: string,
		fn: () => Promise<NextResponse>,
		failure?: unknown,
	) => {
		h.failure = failure;
		return fn();
	},
}));

import {
	recordControlChange,
	recordControlChangeFailed,
} from "@/lib/control-change";
import { GET, PUT } from "./route";

const put = (body: unknown) =>
	({
		json: async () => body,
		headers: new Headers(),
	}) as unknown as NextRequest;
const badJson = () =>
	({
		json: async () => {
			throw new SyntaxError("bad");
		},
		headers: new Headers(),
	}) as unknown as NextRequest;

beforeEach(() => {
	vi.stubEnv("WORKOS_API_KEY", "sk_test_x");
	h.role = "admin";
	h.sessionRole = "admin";
	h.row = { id: "tenant-uuid-1", actionControl: false };
	h.selectThrows = false;
	h.updateRows = [{ id: "tenant-uuid-1" }];
	h.updateThrows = false;
	h.rateOk = true;
	h.rateThrows = false;
	h.record = { ok: true };
	h.sets = [];
	h.order = [];
	vi.mocked(recordControlChange).mockClear();
	vi.mocked(recordControlChangeFailed).mockClear();
	vi.spyOn(console, "error").mockImplementation(() => {});
});

describe("PUT — refusals never write", () => {
	it("refuses a non-owner with 403 and touches nothing", async () => {
		h.role = "other";
		const res = await PUT(put({ enabled: true, confirmed: true }));
		expect(res.status).toBe(403);
		expect(await res.json()).toEqual({
			error: "role_forbidden",
			required_role: "owner_or_admin",
		});
		expect(h.sets).toHaveLength(0);
		expect(recordControlChange).not.toHaveBeenCalled();
	});
	it("fails closed 502 when the role cannot be verified", async () => {
		h.role = null;
		const res = await PUT(put({ enabled: true, confirmed: true }));
		expect(res.status).toBe(502);
		expect(h.sets).toHaveLength(0);
	});
	it("refuses an unconfirmed switch with 409 and the OFF warning", async () => {
		h.row = { id: "tenant-uuid-1", actionControl: true };
		const res = await PUT(put({ enabled: false, confirmed: false }));
		expect(res.status).toBe(409);
		const body = await res.json();
		expect(body.error).toBe("confirmation_required");
		expect(body.warning).toMatch(/standard per-tool rules/);
		expect(h.sets).toHaveLength(0);
	});
	it("refuses a malformed body 400", async () => {
		expect((await PUT(badJson())).status).toBe(400);
		expect((await PUT(put({ enabled: "yes", confirmed: true }))).status).toBe(
			400,
		);
		expect((await PUT(put({ enabled: true }))).status).toBe(400);
		expect((await PUT(put(null))).status).toBe(400);
		expect(h.sets).toHaveLength(0);
	});
	it("no write and 404 when the org has no tenant row (no upsert, no fallback)", async () => {
		h.row = undefined;
		const res = await PUT(put({ enabled: true, confirmed: true }));
		expect(res.status).toBe(404);
		expect(h.sets).toHaveLength(0);
		expect(recordControlChange).not.toHaveBeenCalled();
	});
	it("fails closed 503 when the tenant lookup throws", async () => {
		h.selectThrows = true;
		const res = await PUT(put({ enabled: true, confirmed: true }));
		expect(res.status).toBe(503);
		expect(h.sets).toHaveLength(0);
	});
	it("429 when rate limited, 503 when the limiter is down; neither writes", async () => {
		h.rateOk = false;
		expect((await PUT(put({ enabled: true, confirmed: true }))).status).toBe(
			429,
		);
		h.rateOk = true;
		h.rateThrows = true;
		expect((await PUT(put({ enabled: true, confirmed: true }))).status).toBe(
			503,
		);
		expect(h.sets).toHaveLength(0);
	});
	it("does not write when the change history refuses", async () => {
		h.record = {
			ok: false,
			response: NextResponse.json(
				{ error: "control_audit_unavailable" },
				{ status: 503 },
			),
		};
		const res = await PUT(put({ enabled: true, confirmed: true }));
		expect(res.status).toBe(503);
		expect(h.sets).toHaveLength(0);
	});
	it("records a failed change and answers 503 when the write throws", async () => {
		h.updateThrows = true;
		const res = await PUT(put({ enabled: true, confirmed: true }));
		expect(res.status).toBe(503);
		expect(recordControlChangeFailed).toHaveBeenCalledTimes(1);
	});
	it("answers 409 and records a failed change when the value moved underneath", async () => {
		h.updateRows = [];
		const res = await PUT(put({ enabled: true, confirmed: true }));
		expect(res.status).toBe(409);
		expect((await res.json()).error).toBe("changed_elsewhere");
		expect(recordControlChangeFailed).toHaveBeenCalledTimes(1);
	});
});

describe("PUT — configuration", () => {
	it("passes a route-specific lock-failure message, not membership wording", async () => {
		await PUT(put({ enabled: true, confirmed: true }));
		expect(JSON.stringify(h.failure)).not.toMatch(/member/i);
		expect(h.failure).toMatchObject({ error: "write_unavailable" });
	});
	it("501 and no write when WorkOS is not configured", async () => {
		vi.stubEnv("WORKOS_API_KEY", "");
		const res = await PUT(put({ enabled: true, confirmed: true }));
		expect(res.status).toBe(501);
		expect(h.sets).toHaveLength(0);
	});
});

describe("PUT — tenant isolation", () => {
	it("ignores a tenant id smuggled in the body", async () => {
		const res = await PUT(
			put({
				enabled: true,
				confirmed: true,
				tenant_id: "evil-tenant",
				tenantId: "evil-tenant",
				id: "evil-tenant",
			}),
		);
		expect(res.status).toBe(200);
		expect(h.sets).toEqual([{ actionControl: true }]);
		const [, target] = vi.mocked(recordControlChange).mock.calls[0] as [
			string,
			string,
		];
		expect(target).toBe("org_SESSION");
		expect(
			JSON.stringify(vi.mocked(recordControlChange).mock.calls),
		).not.toContain("evil-tenant");
	});
});

describe("PUT — owner changes", () => {
	it("ON: one history entry before one write, with before and after", async () => {
		const res = await PUT(put({ enabled: true, confirmed: true }));
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ enabled: true, changed: true });
		expect(h.sets).toEqual([{ actionControl: true }]);
		expect(recordControlChange).toHaveBeenCalledTimes(1);
		expect(recordControlChange).toHaveBeenCalledWith(
			"workspace.action_control.set",
			"org_SESSION",
			{ action_control: false },
			{ action_control: true },
		);
		expect(h.order).toEqual(["record", "update"]);
	});
	it("OFF: same recording, and the reply repeats the warning", async () => {
		h.row = { id: "tenant-uuid-1", actionControl: true };
		const res = await PUT(put({ enabled: false, confirmed: true }));
		expect(res.status).toBe(200);
		const body = await res.json();
		expect(body).toMatchObject({ enabled: false, changed: true });
		expect(body.warning).toMatch(/standard per-tool rules/);
		expect(h.sets).toEqual([{ actionControl: false }]);
		expect(recordControlChange).toHaveBeenCalledWith(
			"workspace.action_control.set",
			"org_SESSION",
			{ action_control: true },
			{ action_control: false },
		);
	});
	it("is idempotent: ON when already ON writes and records nothing", async () => {
		h.row = { id: "tenant-uuid-1", actionControl: true };
		const res = await PUT(put({ enabled: true, confirmed: false }));
		expect(res.status).toBe(200);
		expect(await res.json()).toMatchObject({ enabled: true, changed: false });
		expect(h.sets).toHaveLength(0);
		expect(recordControlChange).not.toHaveBeenCalled();
	});
	it("states the propagation delay honestly in the reply", async () => {
		const body = await (
			await PUT(put({ enabled: true, confirmed: true }))
		).json();
		expect(body.note).toMatch(/15 minutes/);
	});
});

describe("GET", () => {
	it("returns the state and can_edit for an owner", async () => {
		h.row = { id: "tenant-uuid-1", actionControl: true };
		const res = await GET();
		expect(await res.json()).toMatchObject({ enabled: true, can_edit: true });
	});
	it("a member sees the state but cannot edit", async () => {
		h.sessionRole = "viewer";
		expect(await (await GET()).json()).toMatchObject({
			enabled: false,
			can_edit: false,
		});
	});
	it("fails closed 503 when the read throws, 404 when no tenant row", async () => {
		h.selectThrows = true;
		expect((await GET()).status).toBe(503);
		h.selectThrows = false;
		h.row = undefined;
		expect((await GET()).status).toBe(404);
	});
});

describe("CSRF — the middleware refuses cross-site writes to this route", () => {
	const url = "https://app.tracelane.dev/api/settings/action-control";
	const mutate = (headers: Record<string, string>) =>
		refuseCrossOriginMutation({
			method: "PUT",
			url,
			headers: new Headers(headers),
		});
	it("refuses Sec-Fetch-Site cross-site", () => {
		expect(mutate({ "sec-fetch-site": "cross-site" })).toBe(true);
	});
	it("refuses same-site from another subdomain", () => {
		expect(mutate({ "sec-fetch-site": "same-site" })).toBe(true);
	});
	it("refuses a request with neither header", () => {
		expect(mutate({})).toBe(true);
	});
	it("refuses a foreign Origin", () => {
		expect(mutate({ origin: "https://tracelane.dev" })).toBe(true);
	});
	it("allows same-origin", () => {
		expect(mutate({ "sec-fetch-site": "same-origin" })).toBe(false);
	});
});
