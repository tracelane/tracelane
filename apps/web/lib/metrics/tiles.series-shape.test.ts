/**
 * Item 7 — a custom dashboard "series" tile plots only the ONE metric it was
 * configured for. `fetchSeriesData` used to route `traffic_series` /
 * `llm_calls` / `tokens` / `errors_series` all through `sloTrafficSeries`
 * and return its full three-series result — so a "requests" tile plotted
 * requests+errors+tokens on one linear axis and requests read as ~zero,
 * because tokens is routinely 100-1000x larger. `pickSeries` narrows the
 * result to the tile's own metric; this proves it end to end through
 * `fetchTileData`, the real call site of the bug.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const rows = [
	{
		bucket_hour: "2026-09-01 01:00:00",
		provider: "openai",
		model: "m",
		p50_ms: 10,
		p95_ms: 20,
		p99_ms: 30,
		requests: 5,
		errors: 1,
		error_rate_pct: 20,
		total_input_tokens: 4000,
		total_output_tokens: 1000,
	},
];

vi.mock("./fetch", () => ({
	fetchSloRows: vi.fn(async () => rows),
}));

import { type TileDef, fetchTileData } from "./tiles";

const range = {
	sinceMs: Date.parse("2026-09-01T00:00:00Z"),
	untilMs: Date.parse("2026-09-01T02:00:00Z"),
	bucketMs: 3_600_000,
};

function seriesTile(metricId: string): TileDef {
	return { id: "t1", metricId, shape: "series" };
}

beforeEach(() => {
	vi.clearAllMocks();
});

describe("item 7 — a series tile plots only its own metric", () => {
	it("a 'requests' (llm_calls) tile's chart carries ONLY a requests series", async () => {
		const data = await fetchTileData(seriesTile("llm_calls"), range);
		expect(data.kind).toBe("series");
		if (data.kind !== "series") throw new Error("expected series");
		expect(data.data.series.map((s) => s.id)).toEqual(["requests"]);
	});

	it("a 'traffic_series' tile's chart carries ONLY a requests series", async () => {
		const data = await fetchTileData(seriesTile("traffic_series"), range);
		if (data.kind !== "series") throw new Error("expected series");
		expect(data.data.series.map((s) => s.id)).toEqual(["requests"]);
	});

	it("an 'errors_series' tile's chart carries ONLY an errors series", async () => {
		const data = await fetchTileData(seriesTile("errors_series"), range);
		if (data.kind !== "series") throw new Error("expected series");
		expect(data.data.series.map((s) => s.id)).toEqual(["errors"]);
	});

	it("a 'tokens' tile's chart carries ONLY a tokens series", async () => {
		const data = await fetchTileData(seriesTile("tokens"), range);
		if (data.kind !== "series") throw new Error("expected series");
		expect(data.data.series.map((s) => s.id)).toEqual(["tokens"]);
	});
});
