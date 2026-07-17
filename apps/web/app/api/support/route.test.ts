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
const { insert, insertValues } = vi.hoisted(() => {
	const insertValues = vi.fn(async () => undefined);
	const insert = vi.fn(() => ({ values: insertValues }));
	return { insert, insertValues };
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
});
