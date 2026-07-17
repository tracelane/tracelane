/**
 * FT-07 chaos: a slow ClickHouse query must degrade to a partial/stale
 * result within the deadline instead of blocking the dashboard, then deliver
 * the full result via SSE.
 *
 * Negative case first per `.claude/rules/testing.md`: the slow query must NOT
 * resolve the caller past the deadline. The query is injected as a thunk with
 * a deterministic artificial delay — no real ClickHouse.
 */

import { afterEach, describe, expect, it } from "vitest";
import {
	__resetDeadlineCacheForTests,
	queryWithDeadline,
	streamQueryWithDeadline,
} from "./query-deadline";

interface Row {
	id: number;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const slowQuery = (ms: number, rows: Row[]) => async (): Promise<Row[]> => {
	await sleep(ms);
	return rows;
};

async function readSse(stream: ReadableStream<Uint8Array>): Promise<string> {
	const reader = stream.getReader();
	const decoder = new TextDecoder();
	let out = "";
	for (;;) {
		const { value, done } = await reader.read();
		if (done) break;
		out += decoder.decode(value, { stream: true });
	}
	return out;
}

describe("FT-07: slow-query deadline + partial result", () => {
	afterEach(() => __resetDeadlineCacheForTests());

	it("a query slower than the deadline returns stale within budget (cold cache → empty)", async () => {
		const started = Date.now();
		const res = await queryWithDeadline<Row>(slowQuery(2000, [{ id: 1 }]), {
			cacheKey: "slo:test",
			timeoutMs: 200,
		});
		const elapsed = Date.now() - started;

		expect(res.stale).toBe(true);
		expect(res.rows).toEqual([]); // cold cache → empty partial
		expect(elapsed).toBeLessThan(500); // did NOT wait for the 2s query
	});

	it("a fast query returns fresh (stale=false) with its rows", async () => {
		const res = await queryWithDeadline<Row>(slowQuery(5, [{ id: 7 }]), {
			cacheKey: "slo:test",
			timeoutMs: 200,
		});
		expect(res.stale).toBe(false);
		expect(res.rows).toEqual([{ id: 7 }]);
	});

	it("after a warm cache, a subsequent slow query serves the last-known-good rows", async () => {
		// 1st call: fast, warms the cache.
		await queryWithDeadline<Row>(slowQuery(5, [{ id: 42 }]), {
			cacheKey: "slo:warm",
			timeoutMs: 200,
		});
		// 2nd call: slow → must serve the cached rows, flagged stale.
		const res = await queryWithDeadline<Row>(slowQuery(2000, [{ id: 99 }]), {
			cacheKey: "slo:warm",
			timeoutMs: 200,
		});
		expect(res.stale).toBe(true);
		expect(res.rows).toEqual([{ id: 42 }]);
		expect(res.servedAt).toBeGreaterThan(0);
	});

	it("SSE stream emits a partial frame then a full frame within 3s", async () => {
		const started = Date.now();
		const stream = streamQueryWithDeadline<Row>(slowQuery(300, [{ id: 5 }]), {
			cacheKey: "slo:sse",
			timeoutMs: 200,
		});
		const body = await readSse(stream);
		const elapsed = Date.now() - started;

		// Partial first, then full — order matters for progressive paint.
		expect(body.indexOf("event: partial")).toBeGreaterThanOrEqual(0);
		expect(body.indexOf("event: full")).toBeGreaterThan(
			body.indexOf("event: partial"),
		);
		// The full frame carries the fresh rows.
		expect(body).toContain('"rows":[{"id":5}]');
		// FT-07 budget: full result delivered well within 3s.
		expect(elapsed).toBeLessThan(3000);
	});

	it("SSE stream emits an error frame (not full) when the query rejects", async () => {
		const stream = streamQueryWithDeadline<Row>(
			async () => {
				throw new Error("clickhouse timeout");
			},
			{ cacheKey: "slo:err", timeoutMs: 200 },
		);
		const body = await readSse(stream);
		expect(body).toContain("event: partial");
		expect(body).toContain("event: error");
		expect(body).not.toContain("event: full");
	});
});
