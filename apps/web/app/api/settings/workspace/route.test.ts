/**
 * Tests for PATCH /api/settings/workspace — org rename.
 *
 * Admin-gated (a plain member can't relabel the org for everyone), org id from
 * the session (never the body), name validated 1–255, WorkOS + `tenants.name`
 * mirror. Negative cases first per `.claude/rules/testing.md`.
 */

import { type DbMock, makeDbMock } from "@/lib/__testutils__/db-mock";
import type { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({ db: null as DbMock | null }));

vi.mock("@/db", () => ({
	get db() {
		if (!h.db) throw new Error("db mock not initialised");
		return h.db.db;
	},
}));

vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => ({
		tenantId: "org_SESSION",
		userId: "user_ME",
		email: "e@x.co",
	})),
}));

import { PATCH } from "./route";

function req(body: unknown): NextRequest {
	return {
		json: async () => body,
		headers: new Headers(),
	} as unknown as NextRequest;
}

const methodOf = (call: unknown[]): string =>
	(call[1] as { method?: string } | undefined)?.method ?? "GET";

/** Stub WorkOS: GET memberships (caller role) → then PUT organizations/{id}. */
function stub(opts: {
	callerRole?: string;
	membersOk?: boolean;
	renameOk?: boolean;
}) {
	const { callerRole = "admin", membersOk = true, renameOk = true } = opts;
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
		return {
			ok: renameOk,
			status: renameOk ? 200 : 500,
			json: async () => ({ id: "org_SESSION", name: "whatever" }),
		} as unknown as Response;
	});
	vi.stubGlobal("fetch", spy);
	return spy;
}

describe("PATCH /api/settings/workspace — org rename", () => {
	beforeEach(() => {
		process.env.WORKOS_API_KEY = "sk_test_workos_do_not_use";
		h.db = makeDbMock([[]]); // update chain resolves
	});
	afterEach(() => {
		vi.unstubAllGlobals();
		process.env.WORKOS_API_KEY = undefined;
	});

	it("REJECT: WORKOS_API_KEY unset → 501", async () => {
		process.env.WORKOS_API_KEY = "";
		expect((await PATCH(req({ name: "Acme" }))).status).toBe(501);
	});

	it("REJECT: empty name → 422 (before any WorkOS call)", async () => {
		const spy = stub({});
		expect((await PATCH(req({ name: "   " }))).status).toBe(422);
		expect(spy).not.toHaveBeenCalled();
	});

	it("REJECT: name over 255 chars → 422", async () => {
		expect((await PATCH(req({ name: "x".repeat(256) }))).status).toBe(422);
	});

	it("REJECT: caller is not admin/owner → 403 (no rename)", async () => {
		const spy = stub({ callerRole: "member" });
		expect((await PATCH(req({ name: "Acme" }))).status).toBe(403);
		expect(spy.mock.calls.every((c) => methodOf(c) !== "PUT")).toBe(true);
	});

	it("REJECT: role lookup fails → 502 (fail closed)", async () => {
		stub({ membersOk: false });
		expect((await PATCH(req({ name: "Acme" }))).status).toBe(502);
	});

	it("REJECT: WorkOS rename fails → 502", async () => {
		stub({ renameOk: false });
		expect((await PATCH(req({ name: "Acme" }))).status).toBe(502);
	});

	it("HAPPY: admin renames with the SESSION org + trimmed name → 200", async () => {
		const spy = stub({});
		const res = await PATCH(req({ name: "  Acme, Inc.  " }));
		expect(res.status).toBe(200);
		expect(((await res.json()) as { name: string }).name).toBe("Acme, Inc.");
		const put = spy.mock.calls.find((c) => methodOf(c) === "PUT");
		expect(put?.[0]).toContain("/organizations/org_SESSION");
		const body = JSON.parse((put?.[1] as unknown as { body: string }).body) as {
			name: string;
		};
		expect(body.name).toBe("Acme, Inc.");
	});

	it("HAPPY: a Postgres mirror failure does NOT fail the rename", async () => {
		stub({});
		h.db = makeDbMock([]);
		h.db.db.update = vi.fn(() => {
			throw new Error("pg down");
		}) as unknown as typeof h.db.db.update;
		expect((await PATCH(req({ name: "Acme" }))).status).toBe(200);
	});
});
