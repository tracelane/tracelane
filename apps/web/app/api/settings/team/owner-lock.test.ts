import { PgDialect } from "drizzle-orm/pg-core";
import { NextResponse } from "next/server";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const h = vi.hoisted(() => ({
	locks: [] as string[],
	fail: false,
	end: vi.fn(async () => {}),
}));
vi.mock("@neondatabase/serverless", () => ({
	Pool: class {
		end = h.end;
	},
}));
vi.mock("drizzle-orm/neon-serverless", () => ({
	drizzle: () => ({
		transaction: async (work: (tx: unknown) => Promise<unknown>) =>
			work({
				execute: async (query: Parameters<PgDialect["sqlToQuery"]>[0]) => {
					if (h.fail) throw new Error("lock unavailable");
					h.locks.push(String(new PgDialect().sqlToQuery(query).params[0]));
				},
			}),
	}),
}));
import { withOwnerMutation } from "./owner-lock";
beforeEach(() => {
	h.locks = [];
	h.fail = false;
	vi.stubEnv("DATABASE_URL", "postgres://synthetic-local-only");
});
afterEach(() => vi.unstubAllEnvs());

it("acquires_unique_workspace_locks_in_deterministic_order_before_mutation", async () => {
	const mutation = vi.fn(async () => {
		expect(h.locks).toEqual([
			"tracelane:owners:org_A",
			"tracelane:owners:org_B",
		]);
		return NextResponse.json({ ok: true });
	});
	expect(
		(await withOwnerMutation(["org_B", "org_A", "org_B"], mutation)).status,
	).toBe(200);
	expect(mutation).toHaveBeenCalledOnce();
	expect(h.end).toHaveBeenCalledOnce();
});
it("a_failed_lock_never_invokes_destructive_work", async () => {
	h.fail = true;
	const mutation = vi.fn(async () => NextResponse.json({ ok: true }));
	expect((await withOwnerMutation(["org_A", "org_B"], mutation)).status).toBe(
		503,
	);
	expect(mutation).not.toHaveBeenCalled();
	expect(h.end).toHaveBeenCalledOnce();
});
