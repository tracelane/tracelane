import reference from "@/db/plans.v3.json";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
const h = await vi.hoisted(async () => {
	const { AsyncLocalStorage } = await import("node:async_hooks");
	vi.stubGlobal("AsyncLocalStorage", AsyncLocalStorage);
	return {
		rows: vi.fn(),
		cadence: 600_000,
		entries: new Map<string, { value: unknown; expires: number }>(),
	};
});
vi.mock("@/lib/auth", () => ({ orgArchivedCacheTtlMs: () => h.cadence }));
vi.mock("@/db", () => ({
	db: {
		select: () => ({ from: () => ({ where: () => ({ limit: h.rows }) }) }),
	},
}));
import { getPlaygroundSettings } from "./playground-settings";
beforeEach(() => {
	vi.useFakeTimers();
	h.entries.clear();
	h.rows.mockReset();
	// Exercise Next's real unstable_cache against an in-memory storage adapter.
	vi.stubGlobal("__incrementalCache", {
		generateSimpleCacheKey: async (key: string) => key,
		get: async (key: string) => {
			const row = h.entries.get(key);
			return row
				? { value: row.value, isStale: Date.now() >= row.expires }
				: null;
		},
		set: async (key: string, value: { revalidate: number }) => {
			h.entries.set(key, {
				value,
				expires: Date.now() + value.revalidate * 1000,
			});
		},
	});
});
afterEach(() => {
	vi.useRealTimers();
	vi.unstubAllGlobals();
});

it("reads changed policy values only when the existing cadence expires", async () => {
	const first = {
		max_columns: 2,
		max_messages: 10,
		max_body_bytes: 65536,
		max_tokens_cap: 1024,
		timeout_ms: 20000,
		cost_poll_seconds: 5,
		history_entries: 3,
	};
	h.rows.mockResolvedValue([{ value: first }]);
	expect(await getPlaygroundSettings()).toEqual({
		limits: first,
		defaulted: false,
	});
	expect(await getPlaygroundSettings()).toEqual({
		limits: first,
		defaulted: false,
	});
	expect(h.rows).toHaveBeenCalledTimes(1);

	const next = { ...first, max_columns: 6 };
	h.rows.mockResolvedValue([{ value: next }]);
	vi.advanceTimersByTime(h.cadence + 1);
	expect(await getPlaygroundSettings()).toEqual({
		limits: next,
		defaulted: false,
	});
	expect(h.rows).toHaveBeenCalledTimes(2);
});

it.each([
	undefined,
	{},
	// A zero or negative cap is invalid — every key must be a positive integer.
	{
		max_columns: 0,
		max_messages: 10,
		max_body_bytes: 65536,
		max_tokens_cap: 1024,
		timeout_ms: 20000,
		cost_poll_seconds: 5,
		history_entries: 3,
	},
	// A non-integer cap is invalid too.
	{
		max_columns: 2.5,
		max_messages: 10,
		max_body_bytes: 65536,
		max_tokens_cap: 1024,
		timeout_ms: 20000,
		cost_poll_seconds: 5,
		history_entries: 3,
	},
	// A row missing one of the seven keys is invalid — no partial application
	// of the reviewed default.
	{ max_columns: 4, max_messages: 50 },
])("discloses missing or invalid reference values", async (value) => {
	h.rows.mockResolvedValue(value === undefined ? [] : [{ value }]);
	expect(await getPlaygroundSettings()).toEqual({
		limits: reference.policy.playground_limits,
		defaulted: true,
	});
});

it("caches display fallback during an outage instead of retrying Postgres per page", async () => {
	h.rows.mockRejectedValue(new Error("offline"));
	await getPlaygroundSettings();
	expect((await getPlaygroundSettings()).defaulted).toBe(true);
	expect(h.rows).toHaveBeenCalledTimes(1);
});
