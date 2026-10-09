import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import { type SpendCausesData, SpendCausesView } from "./SpendCauses";
const data: SpendCausesData = {
	by: "user",
	bucket: {
		start: "2026-09-30T00:00:00Z",
		end: "2026-09-30T01:00:00Z",
		cost_usd_series: 11,
		cost_usd_spans: 10,
	},
	available_dimensions: ["model", "key", "provider", "user"],
	rows: [
		{
			dimension: "u",
			cost_usd: 10,
			share_pct: 100,
			requests: 3,
			unpriced_requests: 1,
			traces_href: null,
		},
	],
	unattributed: { unpriced_requests: 1, unlabelled_cost_usd: 0 },
	overlapping_dimensions: false,
};
it("labels unavailable dimensions and avoids invented trace links and user excess", () => {
	const html = renderToStaticMarkup(
		<SpendCausesView data={data} onDimension={() => {}} />,
	);
	expect(html).toContain('disabled=""');
	expect(html).toContain("x-tracelane-environment");
	expect(html).toContain("trace filter not available yet");
	expect(html).not.toContain('href="/traces');
	expect(html).not.toContain("Excess");
	expect(html).toContain("1 LLM requests in this hour had no recorded cost");
	expect(html).toContain("differs from the raw spans by 10.0%");
});
it("overlapping tags disclose non-additive shares", () => {
	const html = renderToStaticMarkup(
		<SpendCausesView
			data={{ ...data, by: "tag", overlapping_dimensions: true }}
			onDimension={() => {}}
		/>,
	);
	expect(html).toContain("Tags can overlap; shares may sum to more than 100%.");
});
it.each([0, 0.0049, -0.0049, 0.1 + 0.2 - 0.3])(
	"ignores absolute rounding noise %s",
	(delta) => {
		const html = renderToStaticMarkup(
			<SpendCausesView
				data={{
					...data,
					bucket: { ...data.bucket, cost_usd_series: 10 + delta },
				}}
				onDimension={() => {}}
			/>,
		);
		expect(html).not.toContain("bg-warn-soft");
	},
);
it.each([
	[0, 0.005],
	[10, 11],
	[10, 9],
])("reports a material difference neutrally (%s, %s)", (raw, series) => {
	const html = renderToStaticMarkup(
		<SpendCausesView
			data={{
				...data,
				bucket: {
					...data.bucket,
					cost_usd_spans: raw,
					cost_usd_series: series,
				},
			}}
			onDimension={() => {}}
		/>,
	);
	expect(html).toContain("bg-warn-soft");
	expect(html).not.toMatch(/redelivery|retention/);
});
