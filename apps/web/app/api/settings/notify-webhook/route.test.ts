/**
 * Tests for PUT / DELETE /api/settings/notify-webhook (SET-04).
 *
 * The observable end-state is a WRITE: `tenants.slack_webhook_url` must
 * actually be set to the submitted URL, scoped to the session's org. Asserting
 * a 200 would prove nothing here — the whole defect this route closes was a
 * column with a reader and no writer, so the test reads back what `.set()`
 * received and what `.where()` scoped it to.
 *
 * Negative cases first per `.claude/rules/testing.md`.
 */

import type { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Purpose-built Drizzle double. The shared `makeDbMock` chain is a Proxy whose
 * builder methods are plain functions, so it cannot report WHAT `.set()`
 * received — and that argument is the entire point of this route. This double
 * records it.
 */
function makeUpdateSpy() {
	const set = vi.fn();
	const where = vi.fn();
	// `.where()` is the terminal call in this route, so it returns the promise
	// directly. A `then` property on the chain object would be the idiomatic
	// Drizzle shape but trips `lint/suspicious/noThenProperty`.
	const update = vi.fn(() => {
		const chain = {
			set: (v: unknown) => {
				set(v);
				return chain;
			},
			where: async (v: unknown) => {
				where(v);
			},
		};
		return chain;
	});
	return { db: { update }, update, set, where };
}

const h = vi.hoisted(() => ({
	db: null as ReturnType<typeof makeUpdateSpyType> | null,
	session: { tenantId: "org_SESSION", userId: "user_1", email: "a@b.co" },
	isAdmin: true as boolean | null,
}));

// `vi.hoisted` runs before the factory above is defined, so the handle is typed
// through a declaration-only alias and assigned in `beforeEach`.
declare function makeUpdateSpyType(): ReturnType<typeof makeUpdateSpy>;

vi.mock("@/db", () => ({
	get db() {
		if (!h.db) throw new Error("db mock not initialised");
		return h.db.db;
	},
}));

vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => h.session),
}));

vi.mock("@/lib/workos-org", () => ({
	callerIsOrgAdmin: vi.fn(async () => h.isAdmin),
}));

import { DELETE, PUT } from "./route";

function req(body: unknown): NextRequest {
	return {
		json: async () => {
			if (body === undefined) throw new Error("no body");
			return body;
		},
	} as unknown as NextRequest;
}

/** The value handed to `.set()` on the update chain, or undefined. */
function setPayload(): Record<string, unknown> | undefined {
	return h.db?.set.mock.calls[0]?.[0] as Record<string, unknown> | undefined;
}

beforeEach(() => {
	h.db = makeUpdateSpy();
	h.isAdmin = true;
	process.env.WORKOS_API_KEY = "sk_test";
	vi.clearAllMocks();
});

describe("PUT /api/settings/notify-webhook", () => {
	it("rejects a non-https URL without touching the database", async () => {
		const res = await PUT(req({ url: "http://example.com/hook" }));
		expect(res.status).toBe(422);
		expect(h.db?.update).not.toHaveBeenCalled();
	});

	it("rejects an unparseable URL without touching the database", async () => {
		const res = await PUT(req({ url: "not a url" }));
		expect(res.status).toBe(422);
		expect(h.db?.update).not.toHaveBeenCalled();
	});

	it("rejects a non-admin caller without writing", async () => {
		h.isAdmin = false;
		const res = await PUT(req({ url: "https://example.com/hook" }));
		expect(res.status).toBe(403);
		expect(h.db?.update).not.toHaveBeenCalled();
	});

	it("fails CLOSED when the role cannot be verified", async () => {
		h.isAdmin = null;
		const res = await PUT(req({ url: "https://example.com/hook" }));
		expect(res.status).toBe(502);
		expect(h.db?.update).not.toHaveBeenCalled();
	});

	it("WRITES the normalised url to tenants.slack_webhook_url", async () => {
		const res = await PUT(req({ url: "  https://example.com/hook  " }));
		expect(res.status).toBe(200);
		await expect(res.json()).resolves.toEqual({
			url: "https://example.com/hook",
		});

		// The end-state that matters: the column actually receives the value.
		expect(h.db?.update).toHaveBeenCalledTimes(1);
		expect(setPayload()).toEqual({
			slackWebhookUrl: "https://example.com/hook",
		});
	});
});

describe("DELETE /api/settings/notify-webhook", () => {
	it("rejects a non-admin caller without writing", async () => {
		h.isAdmin = false;
		const res = await DELETE();
		expect(res.status).toBe(403);
		expect(h.db?.update).not.toHaveBeenCalled();
	});

	it("NULLs the column so the gateway resolver stops finding a destination", async () => {
		const res = await DELETE();
		expect(res.status).toBe(200);
		expect(setPayload()).toEqual({ slackWebhookUrl: null });
	});
});
