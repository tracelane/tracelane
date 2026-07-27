/**
 * Test-only Drizzle mock.
 *
 * Drizzle query builders are chainable and `await`-able at the end
 * (`db.select().from(t).where(...).limit(1)` resolves to a row array;
 * `db.insert(t).values(...).returning()` resolves to the inserted rows).
 *
 * `makeDbMock(results)` returns a `db` double whose every chain resolves to
 * the NEXT queued result, in call order. This lets a test script the exact
 * sequence of DB reads/writes a handler performs without a live Postgres.
 * No network is touched (`.claude/rules/testing.md`).
 *
 * `db.execute(...)` (used by the admin-audit helper) is a separate spy so
 * raw-SQL side effects can be asserted independently of the query builder.
 */

import { vi } from "vitest";

export interface DbMock {
	/** The `db` double to inject via `vi.mock("@/db", ...)`. */
	db: {
		select: ReturnType<typeof vi.fn>;
		insert: ReturnType<typeof vi.fn>;
		update: ReturnType<typeof vi.fn>;
		delete: ReturnType<typeof vi.fn>;
		execute: ReturnType<typeof vi.fn>;
	};
	/** Ordered list of results the next chains resolve to. */
	results: unknown[];
	/** Index of the next result to be consumed (for assertions). */
	cursor: () => number;
}

/**
 * Build a chainable, thenable Drizzle double.
 *
 * @param results Results consumed in order — one per terminal `await` on a
 *   query chain. Each `db.select()/insert()/update()/delete()` chain consumes
 *   exactly one entry when awaited.
 */
export function makeDbMock(results: unknown[]): DbMock {
	let i = 0;
	const cursor = () => i;

	// A single chain object: every builder method returns `this`, and the
	// object is a thenable that resolves to the next queued result the first
	// time it is awaited.
	function makeChain(): unknown {
		let consumed = false;
		const handler: ProxyHandler<Record<string, unknown>> = {
			get(_target, prop) {
				if (prop === "then") {
					// Thenable: resolve to the next queued result exactly once.
					return (
						onFulfilled: (v: unknown) => unknown,
						onRejected?: (e: unknown) => unknown,
					) => {
						try {
							if (consumed) {
								return Promise.resolve(undefined).then(onFulfilled, onRejected);
							}
							consumed = true;
							const value = results[i];
							i += 1;
							if (value instanceof Error) {
								return Promise.reject(value).then(onFulfilled, onRejected);
							}
							return Promise.resolve(value).then(onFulfilled, onRejected);
						} catch (e) {
							return Promise.reject(e).then(onFulfilled, onRejected);
						}
					};
				}
				// Any builder method (from/where/limit/values/returning/set/
				// orderBy/innerJoin/...) returns the same chain.
				return (..._args: unknown[]) => proxy;
			},
		};
		const proxy: unknown = new Proxy({}, handler);
		return proxy;
	}

	// Distinct spies per builder entrypoint so a test can assert e.g. that
	// `update` and `insert` each ran exactly once. They all produce the same
	// shared-cursor chain.
	const db = {
		select: vi.fn(() => makeChain()),
		insert: vi.fn(() => makeChain()),
		update: vi.fn(() => makeChain()),
		delete: vi.fn(() => makeChain()),
		// db.execute resolves to a queued result too (admin-audit insert).
		execute: vi.fn(() => {
			const value = results[i];
			i += 1;
			if (value instanceof Error) return Promise.reject(value);
			return Promise.resolve(value ?? []);
		}),
	};

	return { db, results, cursor };
}
