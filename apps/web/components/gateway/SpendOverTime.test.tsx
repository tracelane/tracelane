import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { type SpendSeries, SpendSeriesView } from "./SpendOverTime";
const data: SpendSeries = {
	granularity: "hour",
	min_history_buckets: 24,
	baseline_buckets: 168,
	history: "ok",
	window: {
		since: "2026-09-30T00:00:00Z",
		until: "2026-09-30T02:00:00Z",
		clamped: false,
	},
	buckets: [
		{
			bucket_start: "2026-09-30T00:00:00Z",
			cost_usd: 10,
			priced_requests: 1,
			unpriced_requests: 2,
			requests: 3,
		},
	],
	spikes: [
		{
			bucket_start: "2026-09-30T00:00:00Z",
			cost_usd: 10,
			baseline_usd: 1,
			ratio: 10,
		},
	],
};
it("shows priced spend, spike baseline and unpriced traffic separately", () => {
	const html = renderToStaticMarkup(
		<SpendSeriesView data={data} onSelect={() => {}} selected={null} />,
	);
	expect(html).toContain("baseline");
	expect(html).toContain("10.0×");
	expect(html).toContain("2 LLM requests had no recorded cost");
});
it("distinguishes no price, insufficient history and no spike", () => {
	const view = (d: SpendSeries) =>
		renderToStaticMarkup(
			<SpendSeriesView data={d} onSelect={() => {}} selected={null} />,
		);
	expect(view({ ...data, buckets: [], spikes: [] })).toContain(
		"No priced spend yet.",
	);
	expect(view({ ...data, history: "insufficient", spikes: [] })).toContain(
		"Not enough history to detect spikes (needs ≥24 hours).",
	);
	expect(view({ ...data, spikes: [] })).toContain("No spike in this window.");
});
