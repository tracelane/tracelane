/**
 * FT-07 — dashboard slow-query degradation: timeout → partial result + SSE.
 *
 * A ClickHouse query that exceeds the 500ms p95 budget must not block the
 * user. This module gives every dashboard read two FT-07 guarantees:
 *
 *   1. `queryWithDeadline` races the query against a deadline (default
 *      500ms). If the deadline fires first it returns the last-known-good
 *      result from an in-process cache with `stale: true`, while the real
 *      query keeps running in the background to refresh the cache for next
 *      time. A fast query returns `stale: false` within budget.
 *
 *   2. `streamQueryWithDeadline` serves the same data over Server-Sent
 *      Events: a `partial` frame (the cached/stale rows) is emitted
 *      immediately so the UI paints inside 500ms, then a `full` frame with
 *      the fresh rows when the query completes (FT-07 budget: within 3s).
 *
 * The query is injected as a thunk so callers stay decoupled from the
 * ClickHouse client and FT-07 can exercise the timeout path with a
 * deterministically-slow fake — no real ClickHouse, per `.claude/rules/testing.md`.
 */

/** Result of a deadline-bounded query. */
export interface DeadlineResult<Row> {
	rows: Row[];
	/** True when the deadline fired before the query completed. */
	stale: boolean;
	/** Epoch ms the served rows were produced (0 if never cached). */
	servedAt: number;
}

export interface DeadlineOptions {
	/** Deadline before falling back to the cached result. Default 500ms. */
	timeoutMs?: number;
	/** Identifies the result set for the staleness fallback cache. */
	cacheKey: string;
	/** Injectable clock for deterministic tests. Defaults to `Date.now`. */
	now?: () => number;
}

/** FT-07 default deadline — the dashboard p95 budget. */
export const DEFAULT_DEADLINE_MS = 500;

interface CacheEntry {
	rows: unknown[];
	servedAt: number;
}

/** Process-local fallback cache policy for dashboard and trace streams. */
export const DEADLINE_CACHE_LIMITS = {
	maxEntries: 128,
	maxAgeMs: 5 * 60_000,
} as const;

/** Last-known-good results, oldest insertion first. */
const lastKnownGood = new Map<string, CacheEntry>();

function cachedRows(key: string, now: number): CacheEntry | undefined {
	const entry = lastKnownGood.get(key);
	if (entry && now - entry.servedAt > DEADLINE_CACHE_LIMITS.maxAgeMs) {
		lastKnownGood.delete(key);
		return undefined;
	}
	return entry;
}

function saveRows(key: string, rows: unknown[], servedAt: number): void {
	for (const [candidate, entry] of lastKnownGood) {
		if (servedAt - entry.servedAt > DEADLINE_CACHE_LIMITS.maxAgeMs) {
			lastKnownGood.delete(candidate);
		}
	}
	lastKnownGood.delete(key);
	while (lastKnownGood.size >= DEADLINE_CACHE_LIMITS.maxEntries) {
		const oldest = lastKnownGood.keys().next().value;
		if (oldest === undefined) break;
		lastKnownGood.delete(oldest);
	}
	lastKnownGood.set(key, { rows, servedAt });
}

/** Test-only: clear the staleness cache between cases. */
export function __resetDeadlineCacheForTests(): void {
	lastKnownGood.clear();
}

export function __deadlineCacheStatsForTests(): {
	entries: number;
	rows: number;
} {
	return {
		entries: lastKnownGood.size,
		rows: [...lastKnownGood.values()].reduce(
			(sum, entry) => sum + entry.rows.length,
			0,
		),
	};
}

/**
 * Run `runQuery`, but never block past `timeoutMs`. On timeout, serve the
 * last cached result (or an empty set) flagged `stale: true` and let the
 * query finish in the background to refresh the cache.
 */
export async function queryWithDeadline<Row>(
	runQuery: () => Promise<Row[]>,
	opts: DeadlineOptions,
): Promise<DeadlineResult<Row>> {
	const timeoutMs = opts.timeoutMs ?? DEFAULT_DEADLINE_MS;
	const now = opts.now ?? Date.now;

	let timer: ReturnType<typeof setTimeout> | undefined;
	const deadline = new Promise<"timeout">((resolve) => {
		timer = setTimeout(() => resolve("timeout"), timeoutMs);
	});

	// The live query: refresh the cache on success. We keep a handle so the
	// timeout branch can let it complete in the background.
	const live = runQuery().then((rows) => {
		saveRows(opts.cacheKey, rows, now());
		return rows;
	});

	const winner = await Promise.race([
		live.then(() => "query" as const),
		deadline,
	]);

	if (winner === "query") {
		if (timer) clearTimeout(timer);
		const rows = await live;
		return { rows, stale: false, servedAt: now() };
	}

	// Deadline fired. Serve last-known-good; keep the query alive to warm the
	// cache (swallow its error — the next request surfaces failures).
	void live.catch(() => undefined);
	const cached = cachedRows(opts.cacheKey, now());
	return {
		rows: (cached?.rows as Row[] | undefined) ?? [],
		stale: true,
		servedAt: cached?.servedAt ?? 0,
	};
}

/** A single SSE frame: `event: <name>\ndata: <json>\n\n`. */
function sseFrame(event: string, data: unknown): string {
	return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
}

/**
 * Stream a deadline-bounded query as Server-Sent Events.
 *
 * Frame sequence:
 *   - `partial` — emitted immediately from the staleness cache (rows may be
 *     empty on a cold cache); lets the UI paint inside the 500ms budget.
 *   - `full`    — emitted when the query resolves, with fresh rows.
 *   - `error`   — emitted instead of `full` if the query rejects.
 *
 * The returned `ReadableStream<Uint8Array>` is ready to hand to a
 * `Response` with `Content-Type: text/event-stream`.
 */
export function streamQueryWithDeadline<Row>(
	runQuery: () => Promise<Row[]>,
	opts: DeadlineOptions,
): ReadableStream<Uint8Array> {
	const now = opts.now ?? Date.now;
	const encoder = new TextEncoder();
	const cached = cachedRows(opts.cacheKey, now());

	return new ReadableStream<Uint8Array>({
		start(controller) {
			// Immediate partial frame (cold cache → empty + stale).
			controller.enqueue(
				encoder.encode(
					sseFrame("partial", {
						rows: (cached?.rows as Row[] | undefined) ?? [],
						stale: true,
						servedAt: cached?.servedAt ?? 0,
					}),
				),
			);

			runQuery()
				.then((rows) => {
					saveRows(opts.cacheKey, rows, now());
					controller.enqueue(
						encoder.encode(
							sseFrame("full", { rows, stale: false, servedAt: now() }),
						),
					);
				})
				.catch((err: unknown) => {
					controller.enqueue(
						encoder.encode(
							sseFrame("error", {
								message: err instanceof Error ? err.message : "query failed",
							}),
						),
					);
				})
				.finally(() => controller.close());
		},
	});
}
