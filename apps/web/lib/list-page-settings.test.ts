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
import { getListPageSettings } from "./list-page-settings";
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
		experiments: 37,
		datasets: 42,
		experiment_datasets: 13,
		session_turns: 15,
		dataset_items: 33,
		trace_conversation_messages: 44,
		span_tool_names_preview: 7,
	};
	h.rows.mockResolvedValue([{ value: first }]);
	expect(await getListPageSettings()).toEqual({
		sizes: first,
		defaulted: false,
	});
	expect(await getListPageSettings()).toEqual({
		sizes: first,
		defaulted: false,
	});
	expect(h.rows).toHaveBeenCalledTimes(1);
	const next = {
		experiments: 9,
		datasets: 8,
		experiment_datasets: 7,
		session_turns: 5,
		dataset_items: 6,
		trace_conversation_messages: 4,
		span_tool_names_preview: 3,
	};
	h.rows.mockResolvedValue([{ value: next }]);
	vi.advanceTimersByTime(h.cadence + 1);
	expect(await getListPageSettings()).toEqual({
		sizes: next,
		defaulted: false,
	});
	expect(h.rows).toHaveBeenCalledTimes(2);
});
it.each([
	undefined,
	{},
	{
		experiments: 0,
		datasets: 4,
		experiment_datasets: 4,
		session_turns: 4,
	},
	{
		experiments: 2.5,
		datasets: 4,
		experiment_datasets: 4,
		session_turns: 4,
	},
	// A row that has every OLD key but is missing the NEW `session_turns`
	// key (the shape a not-yet-reseeded Neon would carry) must also fall
	// back — a partially-migrated row is not a valid reference.
	{ experiments: 25, datasets: 100, experiment_datasets: 100 },
	// …and one carrying `session_turns` but missing `dataset_items` (EVL-31, 2026-09-28).
	{
		experiments: 25,
		datasets: 100,
		experiment_datasets: 100,
		session_turns: 20,
	},
])("discloses missing or invalid reference values", async (value) => {
	h.rows.mockResolvedValue(value === undefined ? [] : [{ value }]);
	expect(await getListPageSettings()).toEqual({
		sizes: reference.policy.web_list_page_sizes,
		defaulted: true,
	});
});
it("caches display fallback during an outage instead of retrying Postgres per page", async () => {
	h.rows.mockRejectedValue(new Error("offline"));
	await getListPageSettings();
	expect((await getListPageSettings()).defaulted).toBe(true);
	expect(h.rows).toHaveBeenCalledTimes(1);
});
