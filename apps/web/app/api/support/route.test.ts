/**
 * Tests for POST /api/support — the in-product support widget endpoint.
 *
 * Asserts the kind allowlist, message bounds/trim, and that the row is written
 * with the SESSION's WorkOS actor (never a body-supplied identity). db + auth
 * are mocked (off the network / off Postgres).
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

// vi.hoisted: the mock factory is hoisted above these consts, so the fns it
// references must be hoisted too (else "Cannot access before initialization").
const { insert, insertValues, insertReturning } = vi.hoisted(() => {
	// The route now chains `.returning({ id })` so it can mint a ticket ref.
	const insertReturning = vi.fn(async () => [
		{ id: "8f3a21c4-0000-4000-8000-000000000000" },
	]);
	const insertValues = vi.fn(() => ({ returning: insertReturning }));
	const insert = vi.fn(() => ({ values: insertValues }));
	return { insert, insertValues, insertReturning };
});

vi.mock("@/lib/auth", () => ({
	requireSession: vi.fn(async () => ({
		tenantId: "org_A",
		userId: "user_1",
		email: "a@example.com",
	})),
}));
vi.mock("@/db", () => ({ db: { insert } }));
vi.mock("@/db/schema", () => ({ supportRequests: {} }));

import { POST } from "./route";

function req(body: unknown) {
	return { json: async () => body } as never;
}

beforeEach(() => {
	insert.mockClear();
	insertValues.mockClear();
	insertReturning.mockClear();
});

describe("POST /api/support", () => {
	it("persists a valid message with the session actor", async () => {
		const res = await POST(req({ kind: "bug", message: "it broke" }));
		expect(res.status).toBe(201);
		expect(insert).toHaveBeenCalledTimes(1);
		expect(insertValues).toHaveBeenCalledWith({
			workosOrgId: "org_A",
			workosUserId: "user_1",
			email: "a@example.com",
			kind: "bug",
			message: "it broke",
		});
	});

	it("rejects an unknown kind and writes nothing", async () => {
		const res = await POST(req({ kind: "spam", message: "x" }));
		expect(res.status).toBe(400);
		expect(insert).not.toHaveBeenCalled();
	});

	it("rejects an empty or oversized message", async () => {
		expect((await POST(req({ kind: "query", message: "   " }))).status).toBe(
			400,
		);
		expect(
			(await POST(req({ kind: "query", message: "x".repeat(5001) }))).status,
		).toBe(400);
		expect(insert).not.toHaveBeenCalled();
	});

	it("trims the message before persisting", async () => {
		await POST(req({ kind: "feedback", message: "  hi  " }));
		expect(insertValues).toHaveBeenCalledWith(
			expect.objectContaining({ message: "hi" }),
		);
	});

	it("returns a stable ticket ref derived from the row id", async () => {
		const res = await POST(req({ kind: "bug", message: "it broke" }));
		expect(res.status).toBe(201);
		// TL- + first 8 hex of the uuid, upper-cased.
		await expect(res.json()).resolves.toMatchObject({ ref: "TL-8F3A21C4" });
	});

	it("records the broad area as a labeled first line", async () => {
		await POST(req({ kind: "bug", message: "it broke", category: "gateway" }));
		expect(insertValues).toHaveBeenCalledWith(
			expect.objectContaining({ message: "[area: gateway]\nit broke" }),
		);
	});

	it("ignores an unknown area rather than storing it", async () => {
		await POST(
			req({ kind: "bug", message: "it broke", category: "not-a-real-area" }),
		);
		expect(insertValues).toHaveBeenCalledWith(
			expect.objectContaining({ message: "it broke" }),
		);
	});
});
